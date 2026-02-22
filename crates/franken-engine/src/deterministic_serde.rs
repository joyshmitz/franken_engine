//! Deterministic serialization module with schema-hash prefix validation.
//!
//! Produces a single canonical byte representation for security-critical
//! objects. Every serialized payload is prefixed with a 32-byte schema hash
//! that binds the encoding format to its schema version.
//!
//! Canonical encoding rules:
//! - Deterministic field ordering (lexicographic for maps, declaration order
//!   for structs).
//! - Length-prefixed byte/string fields (u32 big-endian length prefix).
//! - Minimal integer encoding (u64 big-endian, no overlong forms).
//! - No indefinite-length encodings.
//! - No optional-field omission: absent values serialize as explicit tag.
//!
//! Plan references: Section 10.10 item 3, 9E.2 (deterministic serialization
//! and signature preimage contracts).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Schema hash
// ---------------------------------------------------------------------------

/// Schema identifier: a 32-byte content-addressed hash of the schema
/// definition. Acts as a magic number and version discriminator in all
/// wire and storage formats.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SchemaHash(pub [u8; 32]);

impl SchemaHash {
    /// Derive a schema hash from the schema definition bytes.
    pub fn from_definition(definition: &[u8]) -> Self {
        let hash = ContentHash::compute(definition);
        Self(*hash.as_bytes())
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CanonicalValue — typed values in the canonical encoding
// ---------------------------------------------------------------------------

/// A typed value in the canonical encoding format. All security-critical
/// objects are decomposed into these primitives for deterministic
/// serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalValue {
    /// Unsigned 64-bit integer (big-endian).
    U64(u64),
    /// Signed 64-bit integer (big-endian).
    I64(i64),
    /// Boolean (0x00 = false, 0x01 = true).
    Bool(bool),
    /// Byte string (length-prefixed).
    Bytes(Vec<u8>),
    /// UTF-8 string (length-prefixed).
    String(String),
    /// Ordered sequence of values.
    Array(Vec<CanonicalValue>),
    /// Ordered map with string keys (lexicographic key ordering enforced).
    Map(BTreeMap<String, CanonicalValue>),
    /// Explicit null (distinct from absent field).
    Null,
}

// Tag bytes for each variant to ensure unambiguous decoding.
const TAG_U64: u8 = 0x01;
const TAG_I64: u8 = 0x02;
const TAG_BOOL: u8 = 0x03;
const TAG_BYTES: u8 = 0x04;
const TAG_STRING: u8 = 0x05;
const TAG_ARRAY: u8 = 0x06;
const TAG_MAP: u8 = 0x07;
const TAG_NULL: u8 = 0x08;

// ---------------------------------------------------------------------------
// SerdeError
// ---------------------------------------------------------------------------

/// Errors during deterministic serialization/deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerdeError {
    /// Schema hash mismatch: expected vs actual.
    SchemaMismatch {
        expected: SchemaHash,
        actual: SchemaHash,
    },
    /// Unknown schema hash (not in registry).
    UnknownSchema { schema_hash: SchemaHash },
    /// Input buffer too short.
    BufferTooShort { expected: usize, actual: usize },
    /// Invalid tag byte encountered.
    InvalidTag { tag: u8, offset: usize },
    /// String decoding failed.
    InvalidUtf8 { offset: usize },
    /// Duplicate key in map.
    DuplicateKey { key: String },
    /// Map keys not in lexicographic order.
    NonLexicographicKeys {
        prev_key: String,
        current_key: String,
    },
    /// Recursion limit exceeded (stack overflow protection).
    RecursionLimitExceeded { offset: usize },
    /// Trailing bytes after deserialization.
    TrailingBytes { count: usize },
}

impl fmt::Display for SerdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => {
                write!(f, "schema mismatch: expected {expected}, got {actual}")
            }
            Self::UnknownSchema { schema_hash } => {
                write!(f, "unknown schema: {schema_hash}")
            }
            Self::BufferTooShort { expected, actual } => {
                write!(f, "buffer too short: need {expected}, got {actual}")
            }
            Self::InvalidTag { tag, offset } => {
                write!(f, "invalid tag 0x{tag:02x} at offset {offset}")
            }
            Self::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at offset {offset}"),
            Self::DuplicateKey { key } => write!(f, "duplicate key: {key}"),
            Self::NonLexicographicKeys {
                prev_key,
                current_key,
            } => write!(f, "non-lexicographic keys: {prev_key} > {current_key}"),
            Self::RecursionLimitExceeded { offset } => {
                write!(f, "recursion limit exceeded at offset {offset}")
            }
            Self::TrailingBytes { count } => write!(f, "{count} trailing bytes"),
        }
    }
}

impl std::error::Error for SerdeError {}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Serialize a `CanonicalValue` to deterministic bytes (without schema prefix).
pub fn encode_value(value: &CanonicalValue) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_into(&mut buf, value);
    buf
}

fn encode_into(buf: &mut Vec<u8>, value: &CanonicalValue) {
    match value {
        CanonicalValue::U64(v) => {
            buf.push(TAG_U64);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        CanonicalValue::I64(v) => {
            buf.push(TAG_I64);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        CanonicalValue::Bool(v) => {
            buf.push(TAG_BOOL);
            buf.push(if *v { 0x01 } else { 0x00 });
        }
        CanonicalValue::Bytes(v) => {
            buf.push(TAG_BYTES);
            buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
            buf.extend_from_slice(v);
        }
        CanonicalValue::String(v) => {
            buf.push(TAG_STRING);
            buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
            buf.extend_from_slice(v.as_bytes());
        }
        CanonicalValue::Array(items) => {
            buf.push(TAG_ARRAY);
            buf.extend_from_slice(&(items.len() as u32).to_be_bytes());
            for item in items {
                encode_into(buf, item);
            }
        }
        CanonicalValue::Map(entries) => {
            buf.push(TAG_MAP);
            // BTreeMap guarantees lexicographic ordering.
            buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            for (key, val) in entries {
                buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
                buf.extend_from_slice(key.as_bytes());
                encode_into(buf, val);
            }
        }
        CanonicalValue::Null => {
            buf.push(TAG_NULL);
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Deserialize a `CanonicalValue` from deterministic bytes (without schema prefix).
pub fn decode_value(data: &[u8]) -> Result<CanonicalValue, SerdeError> {
    let (value, consumed) = decode_at(data, 0, 0)?;
    if consumed < data.len() {
        return Err(SerdeError::TrailingBytes {
            count: data.len() - consumed,
        });
    }
    Ok(value)
}

fn decode_at(
    data: &[u8],
    offset: usize,
    depth: usize,
) -> Result<(CanonicalValue, usize), SerdeError> {
    if depth > 128 {
        return Err(SerdeError::RecursionLimitExceeded { offset });
    }

    if offset >= data.len() {
        return Err(SerdeError::BufferTooShort {
            expected: offset + 1,
            actual: data.len(),
        });
    }

    let tag = data[offset];
    let pos = offset + 1;

    match tag {
        TAG_U64 => {
            need_bytes(data, pos, 8)?;
            let v = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
            Ok((CanonicalValue::U64(v), pos + 8))
        }
        TAG_I64 => {
            need_bytes(data, pos, 8)?;
            let v = i64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
            Ok((CanonicalValue::I64(v), pos + 8))
        }
        TAG_BOOL => {
            need_bytes(data, pos, 1)?;
            let v = data[pos] != 0;
            Ok((CanonicalValue::Bool(v), pos + 1))
        }
        TAG_BYTES => {
            need_bytes(data, pos, 4)?;
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let start = pos + 4;
            need_bytes(data, start, len)?;
            let v = data[start..start + len].to_vec();
            Ok((CanonicalValue::Bytes(v), start + len))
        }
        TAG_STRING => {
            need_bytes(data, pos, 4)?;
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let start = pos + 4;
            need_bytes(data, start, len)?;
            let s = std::str::from_utf8(&data[start..start + len])
                .map_err(|_| SerdeError::InvalidUtf8 { offset: start })?;
            Ok((CanonicalValue::String(s.to_string()), start + len))
        }
        TAG_ARRAY => {
            need_bytes(data, pos, 4)?;
            let count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let mut cur = pos + 4;

            // Mitigate OOM: each element requires at least 1 byte (the tag).
            need_bytes(data, cur, count)?;

            let mut items = Vec::with_capacity(std::cmp::min(count, 4096));
            for _ in 0..count {
                let (val, next) = decode_at(data, cur, depth + 1)?;
                items.push(val);
                cur = next;
            }
            Ok((CanonicalValue::Array(items), cur))
        }
        TAG_MAP => {
            need_bytes(data, pos, 4)?;
            let count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let mut cur = pos + 4;
            let mut map = BTreeMap::new();
            let mut prev_key: Option<String> = None;
            for _ in 0..count {
                need_bytes(data, cur, 4)?;
                let key_len = u32::from_be_bytes(data[cur..cur + 4].try_into().unwrap()) as usize;
                cur += 4;
                need_bytes(data, cur, key_len)?;
                let key = std::str::from_utf8(&data[cur..cur + key_len])
                    .map_err(|_| SerdeError::InvalidUtf8 { offset: cur })?
                    .to_string();
                cur += key_len;

                // Enforce lexicographic ordering.
                if let Some(ref prev) = prev_key
                    && key <= *prev
                {
                    if key == *prev {
                        return Err(SerdeError::DuplicateKey { key });
                    }
                    return Err(SerdeError::NonLexicographicKeys {
                        prev_key: prev.clone(),
                        current_key: key,
                    });
                }
                prev_key = Some(key.clone());

                let (val, next) = decode_at(data, cur, depth + 1)?;
                map.insert(key, val);
                cur = next;
            }
            Ok((CanonicalValue::Map(map), cur))
        }
        TAG_NULL => Ok((CanonicalValue::Null, pos)),
        _ => Err(SerdeError::InvalidTag { tag, offset }),
    }
}

fn need_bytes(data: &[u8], offset: usize, count: usize) -> Result<(), SerdeError> {
    if offset + count > data.len() {
        return Err(SerdeError::BufferTooShort {
            expected: offset + count,
            actual: data.len(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema-prefixed encoding
// ---------------------------------------------------------------------------

/// Serialize a value with a 32-byte schema-hash prefix.
pub fn serialize_with_schema(schema: &SchemaHash, value: &CanonicalValue) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(schema.as_bytes());
    encode_into(&mut buf, value);
    buf
}

/// Deserialize a schema-prefixed payload, verifying the schema hash matches.
pub fn deserialize_with_schema(
    expected_schema: &SchemaHash,
    data: &[u8],
) -> Result<CanonicalValue, SerdeError> {
    if data.len() < 32 {
        return Err(SerdeError::BufferTooShort {
            expected: 32,
            actual: data.len(),
        });
    }

    let actual_schema = SchemaHash(data[..32].try_into().unwrap());
    if actual_schema != *expected_schema {
        return Err(SerdeError::SchemaMismatch {
            expected: expected_schema.clone(),
            actual: actual_schema,
        });
    }

    let (value, consumed) = decode_at(data, 32, 0)?;
    if consumed < data.len() {
        return Err(SerdeError::TrailingBytes {
            count: data.len() - consumed,
        });
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// SchemaRegistry
// ---------------------------------------------------------------------------

/// Registry of known schema hashes and their definitions.
///
/// Prevents deserialization of payloads with unknown schemas.
#[derive(Debug, Default)]
pub struct SchemaRegistry {
    schemas: BTreeMap<[u8; 32], SchemaDefinition>,
}

/// A registered schema definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Human-readable name for the schema.
    pub name: String,
    /// Version of the schema.
    pub version: u32,
    /// The schema hash (derived from definition bytes).
    pub schema_hash: SchemaHash,
}

impl SchemaRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schema. Returns the schema hash.
    pub fn register(&mut self, name: &str, version: u32, definition: &[u8]) -> SchemaHash {
        let hash = SchemaHash::from_definition(definition);
        self.schemas.insert(
            hash.0,
            SchemaDefinition {
                name: name.to_string(),
                version,
                schema_hash: hash.clone(),
            },
        );
        hash
    }

    /// Look up a schema by its hash.
    pub fn lookup(&self, hash: &SchemaHash) -> Option<&SchemaDefinition> {
        self.schemas.get(&hash.0)
    }

    /// Check if a schema hash is registered.
    pub fn is_known(&self, hash: &SchemaHash) -> bool {
        self.schemas.contains_key(&hash.0)
    }

    /// Number of registered schemas.
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Deserialize with registry validation: verifies the schema prefix is
    /// known before attempting to decode.
    pub fn deserialize_checked(
        &self,
        data: &[u8],
    ) -> Result<(SchemaDefinition, CanonicalValue), SerdeError> {
        if data.len() < 32 {
            return Err(SerdeError::BufferTooShort {
                expected: 32,
                actual: data.len(),
            });
        }

        let schema_hash = SchemaHash(data[..32].try_into().unwrap());
        let def = self
            .lookup(&schema_hash)
            .ok_or_else(|| SerdeError::UnknownSchema {
                schema_hash: schema_hash.clone(),
            })?
            .clone();

        let (value, consumed) = decode_at(data, 32, 0)?;
        if consumed < data.len() {
            return Err(SerdeError::TrailingBytes {
                count: data.len() - consumed,
            });
        }

        Ok((def, value))
    }
}

// ---------------------------------------------------------------------------
// Content hash for canonical values
// ---------------------------------------------------------------------------

/// Compute the content hash of a canonical value (for use in signatures,
/// evidence chains, etc.).
pub fn canonical_hash(schema: &SchemaHash, value: &CanonicalValue) -> ContentHash {
    let bytes = serialize_with_schema(schema, value);
    ContentHash::compute(&bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_schema() -> SchemaHash {
        SchemaHash::from_definition(b"test-schema-v1")
    }

    // -- Encode/decode round-trip for each value type --

    #[test]
    fn round_trip_u64() {
        let val = CanonicalValue::U64(42);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_u64_max() {
        let val = CanonicalValue::U64(u64::MAX);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_i64() {
        let val = CanonicalValue::I64(-12345);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_bool_true() {
        let val = CanonicalValue::Bool(true);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_bool_false() {
        let val = CanonicalValue::Bool(false);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_bytes() {
        let val = CanonicalValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_empty_bytes() {
        let val = CanonicalValue::Bytes(vec![]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_string() {
        let val = CanonicalValue::String("hello world".to_string());
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_empty_string() {
        let val = CanonicalValue::String(String::new());
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_null() {
        let val = CanonicalValue::Null;
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_array() {
        let val = CanonicalValue::Array(vec![
            CanonicalValue::U64(1),
            CanonicalValue::String("two".to_string()),
            CanonicalValue::Bool(true),
        ]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_empty_array() {
        let val = CanonicalValue::Array(vec![]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_map() {
        let mut map = BTreeMap::new();
        map.insert("alpha".to_string(), CanonicalValue::U64(1));
        map.insert("beta".to_string(), CanonicalValue::String("b".to_string()));
        map.insert("gamma".to_string(), CanonicalValue::Null);
        let val = CanonicalValue::Map(map);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    #[test]
    fn round_trip_nested() {
        let inner_map = BTreeMap::from([
            ("key".to_string(), CanonicalValue::U64(99)),
            ("nested".to_string(), CanonicalValue::Bool(false)),
        ]);
        let val = CanonicalValue::Array(vec![
            CanonicalValue::Map(inner_map),
            CanonicalValue::Bytes(vec![1, 2, 3]),
        ]);
        let bytes = encode_value(&val);
        assert_eq!(decode_value(&bytes).unwrap(), val);
    }

    // -- Determinism --

    #[test]
    fn encoding_is_deterministic() {
        let mut map = BTreeMap::new();
        map.insert("z".to_string(), CanonicalValue::U64(1));
        map.insert("a".to_string(), CanonicalValue::U64(2));
        let val = CanonicalValue::Map(map);
        let bytes1 = encode_value(&val);
        let bytes2 = encode_value(&val);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn map_keys_are_lexicographically_ordered_in_output() {
        let mut map = BTreeMap::new();
        map.insert("zebra".to_string(), CanonicalValue::Null);
        map.insert("apple".to_string(), CanonicalValue::Null);
        map.insert("mango".to_string(), CanonicalValue::Null);
        let bytes = encode_value(&CanonicalValue::Map(map));

        // Decode and verify key order.
        let decoded = decode_value(&bytes).unwrap();
        if let CanonicalValue::Map(m) = decoded {
            let keys: Vec<&String> = m.keys().collect();
            assert_eq!(keys, vec!["apple", "mango", "zebra"]);
        } else {
            panic!("expected map");
        }
    }

    // -- Schema-prefixed round-trip --

    #[test]
    fn schema_prefixed_round_trip() {
        let schema = test_schema();
        let val = CanonicalValue::U64(42);
        let bytes = serialize_with_schema(&schema, &val);
        assert_eq!(bytes.len(), 32 + 1 + 8); // schema + tag + u64
        let decoded = deserialize_with_schema(&schema, &bytes).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn schema_mismatch_rejected() {
        let schema = test_schema();
        let wrong_schema = SchemaHash::from_definition(b"wrong-schema");
        let bytes = serialize_with_schema(&schema, &CanonicalValue::Null);
        assert!(matches!(
            deserialize_with_schema(&wrong_schema, &bytes),
            Err(SerdeError::SchemaMismatch { .. })
        ));
    }

    // -- Schema registry --

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = SchemaRegistry::new();
        let hash = reg.register("TestObject", 1, b"test-schema-def");
        assert!(reg.is_known(&hash));
        let def = reg.lookup(&hash).unwrap();
        assert_eq!(def.name, "TestObject");
        assert_eq!(def.version, 1);
    }

    #[test]
    fn registry_rejects_unknown_schema() {
        let reg = SchemaRegistry::new();
        let schema = test_schema();
        let bytes = serialize_with_schema(&schema, &CanonicalValue::Null);
        assert!(matches!(
            reg.deserialize_checked(&bytes),
            Err(SerdeError::UnknownSchema { .. })
        ));
    }

    #[test]
    fn registry_accepts_known_schema() {
        let mut reg = SchemaRegistry::new();
        let hash = reg.register("TestObj", 1, b"test-schema-v1");
        let bytes = serialize_with_schema(&hash, &CanonicalValue::U64(123));
        let (def, val) = reg.deserialize_checked(&bytes).unwrap();
        assert_eq!(def.name, "TestObj");
        assert_eq!(val, CanonicalValue::U64(123));
    }

    // -- Error cases --

    #[test]
    fn buffer_too_short() {
        assert!(matches!(
            decode_value(&[]),
            Err(SerdeError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn invalid_tag() {
        assert!(matches!(
            decode_value(&[0xFF]),
            Err(SerdeError::InvalidTag { tag: 0xFF, .. })
        ));
    }

    #[test]
    fn truncated_u64() {
        let mut bytes = encode_value(&CanonicalValue::U64(42));
        bytes.truncate(5); // tag + 4 of 8 bytes
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = encode_value(&CanonicalValue::Null);
        bytes.push(0x00);
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::TrailingBytes { count: 1 })
        ));
    }

    #[test]
    fn non_lexicographic_map_rejected() {
        // Manually construct a map with out-of-order keys.
        let mut bytes = vec![TAG_MAP];
        bytes.extend_from_slice(&2u32.to_be_bytes()); // 2 entries

        // Key "z" first (wrong order).
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'z');
        bytes.push(TAG_NULL);

        // Key "a" second.
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::NonLexicographicKeys { .. })
        ));
    }

    #[test]
    fn duplicate_map_key_rejected() {
        let mut bytes = vec![TAG_MAP];
        bytes.extend_from_slice(&2u32.to_be_bytes());

        // Key "a" twice.
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn invalid_utf8_rejected() {
        let mut bytes = vec![TAG_STRING];
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn recursion_limit_exceeded_rejected() {
        // Construct an array nested 129 times to trigger recursion limit (limit is 128).
        let mut bytes = Vec::new();
        for _ in 0..129 {
            bytes.push(TAG_ARRAY);
            bytes.extend_from_slice(&1u32.to_be_bytes());
        }
        bytes.push(TAG_NULL);
        assert!(matches!(
            decode_value(&bytes),
            Err(SerdeError::RecursionLimitExceeded { .. })
        ));
    }

    // -- Content hash --

    #[test]
    fn canonical_hash_is_deterministic() {
        let schema = test_schema();
        let val = CanonicalValue::U64(42);
        let h1 = canonical_hash(&schema, &val);
        let h2 = canonical_hash(&schema, &val);
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_hash_differs_for_different_values() {
        let schema = test_schema();
        let h1 = canonical_hash(&schema, &CanonicalValue::U64(1));
        let h2 = canonical_hash(&schema, &CanonicalValue::U64(2));
        assert_ne!(h1, h2);
    }

    #[test]
    fn canonical_hash_differs_for_different_schemas() {
        let s1 = SchemaHash::from_definition(b"schema-a");
        let s2 = SchemaHash::from_definition(b"schema-b");
        let val = CanonicalValue::U64(42);
        assert_ne!(canonical_hash(&s1, &val), canonical_hash(&s2, &val));
    }

    // -- Serialization of types --

    #[test]
    fn schema_hash_serialization_round_trip() {
        let hash = test_schema();
        let json = serde_json::to_string(&hash).expect("serialize");
        let restored: SchemaHash = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hash, restored);
    }

    #[test]
    fn serde_error_serialization_round_trip() {
        let errors = vec![
            SerdeError::BufferTooShort {
                expected: 10,
                actual: 5,
            },
            SerdeError::InvalidTag {
                tag: 0xFF,
                offset: 0,
            },
            SerdeError::DuplicateKey {
                key: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: SerdeError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn schema_hash_display() {
        let hash = SchemaHash([0u8; 32]);
        assert_eq!(hash.to_string().len(), 64); // 32 bytes * 2 hex chars
    }

    #[test]
    fn error_display() {
        assert!(
            SerdeError::BufferTooShort {
                expected: 10,
                actual: 5
            }
            .to_string()
            .contains("10")
        );

        assert!(
            SerdeError::DuplicateKey {
                key: "x".to_string()
            }
            .to_string()
            .contains("x")
        );
    }

    // -- Minimal encoding --

    #[test]
    fn u64_encoding_is_fixed_size() {
        // All u64 values use exactly 9 bytes (1 tag + 8 data).
        assert_eq!(encode_value(&CanonicalValue::U64(0)).len(), 9);
        assert_eq!(encode_value(&CanonicalValue::U64(u64::MAX)).len(), 9);
    }

    #[test]
    fn string_encoding_includes_length_prefix() {
        let val = CanonicalValue::String("abc".to_string());
        let bytes = encode_value(&val);
        // 1 tag + 4 length + 3 chars = 8
        assert_eq!(bytes.len(), 8);
    }
}
