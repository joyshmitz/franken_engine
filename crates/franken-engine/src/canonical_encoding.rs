//! Strict canonical encoding enforcement for security-critical objects.
//!
//! Rejects non-canonical encodings with hard failure — no silent
//! normalization. When a security-critical object is deserialized, the
//! input bytes are re-serialized and compared byte-for-byte; any
//! mismatch is rejected with structured error detail.
//!
//! Violation classes detected:
//! - Field ordering differences (non-lexicographic map keys).
//! - Duplicate fields.
//! - Non-minimal integer encodings (hypothetical; our format is fixed-width).
//! - Trailing garbage bytes.
//! - BOM / whitespace padding.
//! - Tag byte anomalies (e.g., non-standard bool encoding).
//!
//! Plan references: Section 10.10 item 2, 9E.1 (canonical object identity —
//! "Silent normalization is forbidden for these classes").

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash, SchemaRegistry, SerdeError};
use crate::engine_object_id::ObjectDomain;
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Violation detail
// ---------------------------------------------------------------------------

/// Specific canonicality violation detected during deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalViolation {
    /// Map keys are not in lexicographic order.
    NonLexicographicKeys {
        prev_key: String,
        current_key: String,
    },
    /// Duplicate key in a map.
    DuplicateKey { key: String },
    /// Trailing bytes after the last value.
    TrailingBytes { count: usize },
    /// Boolean value encoded with non-standard byte (not 0x00/0x01).
    NonStandardBoolEncoding { byte: u8, offset: usize },
    /// Leading BOM or whitespace padding before data.
    LeadingPadding { byte_count: usize },
    /// Re-serialization mismatch: the round-tripped bytes differ from
    /// the original input.
    RoundTripMismatch {
        /// Offset of first differing byte.
        first_diff_offset: usize,
        /// Expected byte (from re-serialization).
        expected: u8,
        /// Actual byte (from input).
        actual: u8,
    },
    /// Length mismatch between input and re-serialized output.
    LengthMismatch {
        input_len: usize,
        canonical_len: usize,
    },
    /// Underlying deserialization error.
    DeserializationFailed { detail: String },
    /// Invalid tag byte.
    InvalidTag { tag: u8, offset: usize },
    /// Schema hash mismatch or unknown schema.
    SchemaViolation { detail: String },
}

impl fmt::Display for CanonicalViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLexicographicKeys {
                prev_key,
                current_key,
            } => write!(f, "non-lexicographic keys: '{prev_key}' >= '{current_key}'"),
            Self::DuplicateKey { key } => write!(f, "duplicate key: '{key}'"),
            Self::TrailingBytes { count } => write!(f, "{count} trailing bytes"),
            Self::NonStandardBoolEncoding { byte, offset } => {
                write!(f, "non-standard bool 0x{byte:02x} at offset {offset}")
            }
            Self::LeadingPadding { byte_count } => {
                write!(f, "{byte_count} bytes of leading padding")
            }
            Self::RoundTripMismatch {
                first_diff_offset,
                expected,
                actual,
            } => write!(
                f,
                "round-trip mismatch at offset {first_diff_offset}: \
                 expected 0x{expected:02x}, got 0x{actual:02x}"
            ),
            Self::LengthMismatch {
                input_len,
                canonical_len,
            } => write!(
                f,
                "length mismatch: input {input_len}, canonical {canonical_len}"
            ),
            Self::DeserializationFailed { detail } => {
                write!(f, "deserialization failed: {detail}")
            }
            Self::InvalidTag { tag, offset } => {
                write!(f, "invalid tag 0x{tag:02x} at offset {offset}")
            }
            Self::SchemaViolation { detail } => {
                write!(f, "schema violation: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NonCanonicalError
// ---------------------------------------------------------------------------

/// Error returned when a non-canonical encoding is detected.
///
/// Contains structured detail suitable for audit logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonCanonicalError {
    /// The object class that was being deserialized.
    pub object_class: ObjectDomain,
    /// Content hash of the raw input bytes.
    pub input_hash: [u8; 32],
    /// The specific violation detected.
    pub violation: CanonicalViolation,
    /// Optional trace ID for correlation.
    pub trace_id: String,
}

impl fmt::Display for NonCanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "non-canonical {}: {} [trace={}]",
            self.object_class, self.violation, self.trace_id
        )
    }
}

impl std::error::Error for NonCanonicalError {}

// ---------------------------------------------------------------------------
// CanonicalityCheck trait
// ---------------------------------------------------------------------------

/// Trait that every security-critical object deserializer must implement.
///
/// Provides a uniform canonicality verification interface across all
/// object classes.
pub trait CanonicalityCheck {
    /// The domain of this object class.
    fn domain(&self) -> ObjectDomain;

    /// Verify that the given bytes are in canonical form.
    ///
    /// Returns `Ok(())` if canonical, or a `NonCanonicalError` with
    /// structured detail if not.
    fn check_canonical(&self, bytes: &[u8], trace_id: &str) -> Result<(), NonCanonicalError>;
}

// ---------------------------------------------------------------------------
// CanonicalGuard — the enforcement wrapper
// ---------------------------------------------------------------------------

/// Enforcement wrapper that ensures all deserialized objects pass
/// canonicality checks. Uses the re-serialize-and-compare approach.
#[derive(Debug)]
pub struct CanonicalGuard {
    /// Registered object classes and their schema hashes.
    class_registry: BTreeMap<ObjectDomain, SchemaHash>,
    /// Schema registry for deserialization.
    schema_registry: SchemaRegistry,
    /// Audit events.
    events: Vec<GuardEvent>,
    /// Total rejection count.
    rejection_count: u64,
    /// Total acceptance count.
    acceptance_count: u64,
}

/// Audit event emitted by the guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardEvent {
    pub event_type: GuardEventType,
    pub object_class: ObjectDomain,
    pub trace_id: String,
    pub input_hash: [u8; 32],
}

/// Types of guard events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardEventType {
    /// Object passed canonicality check.
    Accepted,
    /// Object rejected for non-canonical encoding.
    Rejected { violation: CanonicalViolation },
    /// Object class not registered.
    UnregisteredClass,
}

impl fmt::Display for GuardEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected { violation } => write!(f, "rejected: {violation}"),
            Self::UnregisteredClass => write!(f, "unregistered_class"),
        }
    }
}

impl CanonicalGuard {
    /// Create a new guard with an empty class registry.
    pub fn new() -> Self {
        Self {
            class_registry: BTreeMap::new(),
            schema_registry: SchemaRegistry::new(),
            events: Vec::new(),
            rejection_count: 0,
            acceptance_count: 0,
        }
    }

    /// Register a security-critical object class with its schema.
    pub fn register_class(
        &mut self,
        domain: ObjectDomain,
        schema_name: &str,
        schema_version: u32,
        schema_definition: &[u8],
    ) -> SchemaHash {
        let hash = self
            .schema_registry
            .register(schema_name, schema_version, schema_definition);
        self.class_registry.insert(domain, hash.clone());
        hash
    }

    /// Check if an object class is registered.
    pub fn is_class_registered(&self, domain: &ObjectDomain) -> bool {
        self.class_registry.contains_key(domain)
    }

    /// Number of registered classes.
    pub fn registered_class_count(&self) -> usize {
        self.class_registry.len()
    }

    /// Total rejections.
    pub fn rejection_count(&self) -> u64 {
        self.rejection_count
    }

    /// Total acceptances.
    pub fn acceptance_count(&self) -> u64 {
        self.acceptance_count
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<GuardEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counts by type.
    pub fn event_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            let key = match &event.event_type {
                GuardEventType::Accepted => "accepted".to_string(),
                GuardEventType::Rejected { .. } => "rejected".to_string(),
                GuardEventType::UnregisteredClass => "unregistered_class".to_string(),
            };
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    /// Validate raw bytes as a canonical encoding of the given object class.
    ///
    /// This is the main entry point. It:
    /// 1. Checks that the object class is registered.
    /// 2. Performs pre-parse checks (leading padding, BOM).
    /// 3. Deserializes the bytes.
    /// 4. Re-serializes and compares byte-for-byte.
    /// 5. Returns the decoded value on success, or a `NonCanonicalError` on
    ///    failure.
    pub fn validate(
        &mut self,
        domain: ObjectDomain,
        bytes: &[u8],
        trace_id: &str,
    ) -> Result<CanonicalValue, NonCanonicalError> {
        let input_hash = compute_input_hash(bytes);

        // 1. Check class registration.
        let schema_hash = match self.class_registry.get(&domain) {
            Some(h) => h.clone(),
            None => {
                self.emit_event(GuardEvent {
                    event_type: GuardEventType::UnregisteredClass,
                    object_class: domain,
                    trace_id: trace_id.to_string(),
                    input_hash,
                });
                return Err(NonCanonicalError {
                    object_class: domain,
                    input_hash,
                    violation: CanonicalViolation::SchemaViolation {
                        detail: format!("object class {domain} not registered"),
                    },
                    trace_id: trace_id.to_string(),
                });
            }
        };

        // 2. Pre-parse checks.
        if let Some(violation) = check_leading_padding(bytes) {
            self.rejection_count += 1;
            self.emit_event(GuardEvent {
                event_type: GuardEventType::Rejected {
                    violation: violation.clone(),
                },
                object_class: domain,
                trace_id: trace_id.to_string(),
                input_hash,
            });
            return Err(NonCanonicalError {
                object_class: domain,
                input_hash,
                violation,
                trace_id: trace_id.to_string(),
            });
        }

        // 3. Deserialize with schema validation.
        let value = match deterministic_serde::deserialize_with_schema(&schema_hash, bytes) {
            Ok(v) => v,
            Err(e) => {
                let violation = serde_error_to_violation(&e);
                self.rejection_count += 1;
                self.emit_event(GuardEvent {
                    event_type: GuardEventType::Rejected {
                        violation: violation.clone(),
                    },
                    object_class: domain,
                    trace_id: trace_id.to_string(),
                    input_hash,
                });
                return Err(NonCanonicalError {
                    object_class: domain,
                    input_hash,
                    violation,
                    trace_id: trace_id.to_string(),
                });
            }
        };

        // 4. Re-serialize and compare (the core canonicality check).
        let canonical_bytes = deterministic_serde::serialize_with_schema(&schema_hash, &value);
        if let Some(violation) = compare_bytes(bytes, &canonical_bytes) {
            self.rejection_count += 1;
            self.emit_event(GuardEvent {
                event_type: GuardEventType::Rejected {
                    violation: violation.clone(),
                },
                object_class: domain,
                trace_id: trace_id.to_string(),
                input_hash,
            });
            return Err(NonCanonicalError {
                object_class: domain,
                input_hash,
                violation,
                trace_id: trace_id.to_string(),
            });
        }

        // 5. Success.
        self.acceptance_count += 1;
        self.emit_event(GuardEvent {
            event_type: GuardEventType::Accepted,
            object_class: domain,
            trace_id: trace_id.to_string(),
            input_hash,
        });
        Ok(value)
    }

    /// Standalone canonicality check without object class context.
    ///
    /// Checks raw value bytes (no schema prefix) for canonicality by
    /// decoding and re-encoding.
    pub fn is_canonical_raw(bytes: &[u8]) -> Result<(), CanonicalViolation> {
        // Pre-parse checks.
        if let Some(violation) = check_leading_padding(bytes) {
            return Err(violation);
        }

        // Decode.
        let value = match deterministic_serde::decode_value(bytes) {
            Ok(v) => v,
            Err(e) => return Err(serde_error_to_violation(&e)),
        };

        // Re-encode and compare.
        let canonical = deterministic_serde::encode_value(&value);
        if let Some(violation) = compare_bytes(bytes, &canonical) {
            return Err(violation);
        }

        Ok(())
    }

    /// Validate schema-prefixed bytes using the registry.
    ///
    /// Like `validate` but infers the object class from the registered
    /// schemas rather than requiring an explicit domain parameter.
    pub fn validate_from_registry(
        &mut self,
        bytes: &[u8],
        trace_id: &str,
    ) -> Result<(ObjectDomain, CanonicalValue), NonCanonicalError> {
        let input_hash = compute_input_hash(bytes);

        if bytes.len() < 32 {
            let violation = CanonicalViolation::DeserializationFailed {
                detail: "input too short for schema prefix".to_string(),
            };
            return Err(NonCanonicalError {
                object_class: ObjectDomain::PolicyObject, // placeholder
                input_hash,
                violation,
                trace_id: trace_id.to_string(),
            });
        }

        let schema_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let schema_hash = SchemaHash(schema_bytes);

        // Find the domain for this schema.
        let domain = self
            .class_registry
            .iter()
            .find(|(_, sh)| **sh == schema_hash)
            .map(|(d, _)| *d);

        match domain {
            Some(d) => {
                let value = self.validate(d, bytes, trace_id)?;
                Ok((d, value))
            }
            None => Err(NonCanonicalError {
                object_class: ObjectDomain::PolicyObject, // placeholder
                input_hash,
                violation: CanonicalViolation::SchemaViolation {
                    detail: "schema not registered in any object class".to_string(),
                },
                trace_id: trace_id.to_string(),
            }),
        }
    }

    fn emit_event(&mut self, event: GuardEvent) {
        self.events.push(event);
    }
}

impl Default for CanonicalGuard {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pre-parse checks
// ---------------------------------------------------------------------------

/// UTF-8 BOM bytes.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Check for leading padding (BOM, whitespace, null bytes).
fn check_leading_padding(bytes: &[u8]) -> Option<CanonicalViolation> {
    if bytes.is_empty() {
        return None;
    }

    // Check UTF-8 BOM.
    if bytes.len() >= 3 && bytes[..3] == UTF8_BOM {
        return Some(CanonicalViolation::LeadingPadding { byte_count: 3 });
    }

    // Check leading whitespace or null padding.
    let first = bytes[0];
    if first == b' ' || first == b'\t' || first == b'\n' || first == b'\r' || first == 0x00 {
        let padding_len = bytes
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == 0x00)
            .count();
        return Some(CanonicalViolation::LeadingPadding {
            byte_count: padding_len,
        });
    }

    None
}

/// Check for non-standard bool encoding in raw bytes.
///
/// Our canonical bool encoding uses TAG_BOOL (0x03) followed by exactly
/// 0x00 (false) or 0x01 (true). Any other byte after TAG_BOOL is
/// non-canonical.
pub fn check_bool_encoding(bytes: &[u8]) -> Option<CanonicalViolation> {
    const TAG_BOOL: u8 = 0x03;

    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == TAG_BOOL && i + 1 < bytes.len() {
            let val = bytes[i + 1];
            if val != 0x00 && val != 0x01 {
                return Some(CanonicalViolation::NonStandardBoolEncoding {
                    byte: val,
                    offset: i + 1,
                });
            }
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Byte comparison
// ---------------------------------------------------------------------------

/// Compare input bytes against canonical re-serialization.
fn compare_bytes(input: &[u8], canonical: &[u8]) -> Option<CanonicalViolation> {
    if input.len() != canonical.len() {
        return Some(CanonicalViolation::LengthMismatch {
            input_len: input.len(),
            canonical_len: canonical.len(),
        });
    }

    for (i, (a, b)) in input.iter().zip(canonical.iter()).enumerate() {
        if a != b {
            return Some(CanonicalViolation::RoundTripMismatch {
                first_diff_offset: i,
                expected: *b,
                actual: *a,
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Input hashing
// ---------------------------------------------------------------------------

/// Compute a content hash of the raw input for audit logging.
fn compute_input_hash(bytes: &[u8]) -> [u8; 32] {
    *ContentHash::compute(bytes).as_bytes()
}

// ---------------------------------------------------------------------------
// SerdeError → CanonicalViolation mapping
// ---------------------------------------------------------------------------

fn serde_error_to_violation(e: &SerdeError) -> CanonicalViolation {
    match e {
        SerdeError::NonLexicographicKeys {
            prev_key,
            current_key,
        } => CanonicalViolation::NonLexicographicKeys {
            prev_key: prev_key.clone(),
            current_key: current_key.clone(),
        },
        SerdeError::DuplicateKey { key } => CanonicalViolation::DuplicateKey { key: key.clone() },
        SerdeError::TrailingBytes { count } => CanonicalViolation::TrailingBytes { count: *count },
        SerdeError::InvalidTag { tag, offset } => CanonicalViolation::InvalidTag {
            tag: *tag,
            offset: *offset,
        },
        SerdeError::SchemaMismatch { expected, actual } => CanonicalViolation::SchemaViolation {
            detail: format!("expected schema {expected}, got {actual}"),
        },
        SerdeError::UnknownSchema { schema_hash } => CanonicalViolation::SchemaViolation {
            detail: format!("unknown schema {schema_hash}"),
        },
        other => CanonicalViolation::DeserializationFailed {
            detail: other.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// CanonicalityCheck implementations for CanonicalGuard
// ---------------------------------------------------------------------------

impl CanonicalityCheck for CanonicalGuard {
    fn domain(&self) -> ObjectDomain {
        // The guard itself is not a single domain; return a sentinel.
        ObjectDomain::PolicyObject
    }

    fn check_canonical(&self, bytes: &[u8], trace_id: &str) -> Result<(), NonCanonicalError> {
        let input_hash = compute_input_hash(bytes);

        // Pre-parse checks.
        if let Some(violation) = check_leading_padding(bytes) {
            return Err(NonCanonicalError {
                object_class: ObjectDomain::PolicyObject,
                input_hash,
                violation,
                trace_id: trace_id.to_string(),
            });
        }

        // Try to decode and re-encode.
        match deterministic_serde::decode_value(bytes) {
            Ok(value) => {
                let canonical = deterministic_serde::encode_value(&value);
                if let Some(violation) = compare_bytes(bytes, &canonical) {
                    return Err(NonCanonicalError {
                        object_class: ObjectDomain::PolicyObject,
                        input_hash,
                        violation,
                        trace_id: trace_id.to_string(),
                    });
                }
                Ok(())
            }
            Err(e) => Err(NonCanonicalError {
                object_class: ObjectDomain::PolicyObject,
                input_hash,
                violation: serde_error_to_violation(&e),
                trace_id: trace_id.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_serde::{encode_value, serialize_with_schema};

    fn setup_guard() -> (CanonicalGuard, SchemaHash) {
        let mut guard = CanonicalGuard::new();
        let schema = guard.register_class(
            ObjectDomain::PolicyObject,
            "TestPolicy",
            1,
            b"test-policy-schema-v1",
        );
        (guard, schema)
    }

    fn make_canonical_payload(schema: &SchemaHash, value: &CanonicalValue) -> Vec<u8> {
        serialize_with_schema(schema, value)
    }

    // -- Basic acceptance --

    #[test]
    fn canonical_value_accepted() {
        let (mut guard, schema) = setup_guard();
        let value = CanonicalValue::U64(42);
        let bytes = make_canonical_payload(&schema, &value);
        let result = guard.validate(ObjectDomain::PolicyObject, &bytes, "t-001");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), value);
        assert_eq!(guard.acceptance_count(), 1);
        assert_eq!(guard.rejection_count(), 0);
    }

    #[test]
    fn canonical_string_accepted() {
        let (mut guard, schema) = setup_guard();
        let value = CanonicalValue::String("hello".to_string());
        let bytes = make_canonical_payload(&schema, &value);
        assert!(
            guard
                .validate(ObjectDomain::PolicyObject, &bytes, "t-002")
                .is_ok()
        );
    }

    #[test]
    fn canonical_map_accepted() {
        let (mut guard, schema) = setup_guard();
        let value = CanonicalValue::Map(BTreeMap::from([
            ("alpha".to_string(), CanonicalValue::U64(1)),
            ("beta".to_string(), CanonicalValue::Bool(true)),
        ]));
        let bytes = make_canonical_payload(&schema, &value);
        assert!(
            guard
                .validate(ObjectDomain::PolicyObject, &bytes, "t-003")
                .is_ok()
        );
    }

    #[test]
    fn canonical_nested_accepted() {
        let (mut guard, schema) = setup_guard();
        let value = CanonicalValue::Array(vec![
            CanonicalValue::Map(BTreeMap::from([(
                "key".to_string(),
                CanonicalValue::Bytes(vec![1, 2, 3]),
            )])),
            CanonicalValue::Null,
        ]);
        let bytes = make_canonical_payload(&schema, &value);
        assert!(
            guard
                .validate(ObjectDomain::PolicyObject, &bytes, "t-004")
                .is_ok()
        );
    }

    // -- Rejection: trailing bytes --

    #[test]
    fn trailing_bytes_rejected() {
        let (mut guard, schema) = setup_guard();
        let value = CanonicalValue::U64(42);
        let mut bytes = make_canonical_payload(&schema, &value);
        bytes.push(0x00); // trailing garbage
        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-010")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::TrailingBytes { count: 1 }
        ));
        assert_eq!(guard.rejection_count(), 1);
    }

    #[test]
    fn many_trailing_bytes_rejected() {
        let (mut guard, schema) = setup_guard();
        let value = CanonicalValue::Null;
        let mut bytes = make_canonical_payload(&schema, &value);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-011")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::TrailingBytes { count: 4 }
        ));
    }

    // -- Rejection: non-lexicographic keys --

    #[test]
    fn non_lexicographic_map_rejected() {
        let (mut guard, schema) = setup_guard();
        // Manually construct non-canonical map with wrong key order.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.as_bytes()); // schema prefix

        const TAG_MAP: u8 = 0x07;
        const TAG_NULL: u8 = 0x08;

        bytes.push(TAG_MAP);
        bytes.extend_from_slice(&2u32.to_be_bytes()); // 2 entries

        // Key "z" first (wrong order).
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'z');
        bytes.push(TAG_NULL);

        // Key "a" second.
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-020")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::NonLexicographicKeys { .. }
        ));
    }

    // -- Rejection: duplicate keys --

    #[test]
    fn duplicate_key_rejected() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.as_bytes());

        const TAG_MAP: u8 = 0x07;
        const TAG_NULL: u8 = 0x08;

        bytes.push(TAG_MAP);
        bytes.extend_from_slice(&2u32.to_be_bytes());

        // Key "a" twice.
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(TAG_NULL);

        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-021")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::DuplicateKey { .. }
        ));
    }

    // -- Rejection: invalid tag --

    #[test]
    fn invalid_tag_rejected() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.as_bytes());
        bytes.push(0xFF); // invalid tag

        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-030")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::InvalidTag { tag: 0xFF, .. }
        ));
    }

    // -- Rejection: schema mismatch --

    #[test]
    fn schema_mismatch_rejected() {
        let (mut guard, _schema) = setup_guard();
        let wrong_schema = SchemaHash::from_definition(b"wrong-schema");
        let bytes = serialize_with_schema(&wrong_schema, &CanonicalValue::Null);

        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-040")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::SchemaViolation { .. }
        ));
    }

    // -- Rejection: unregistered class --

    #[test]
    fn unregistered_class_rejected() {
        let (mut guard, schema) = setup_guard();
        let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
        let err = guard
            .validate(ObjectDomain::EvidenceRecord, &bytes, "t-050")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::SchemaViolation { .. }
        ));
    }

    // -- Rejection: leading padding --

    #[test]
    fn leading_whitespace_rejected() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = vec![b' ', b' ']; // leading spaces
        bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-060")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::LeadingPadding { byte_count: 2 }
        ));
    }

    #[test]
    fn leading_bom_rejected() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-061")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::LeadingPadding { byte_count: 3 }
        ));
    }

    #[test]
    fn leading_null_bytes_rejected() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = vec![0x00, 0x00, 0x00];
        bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-062")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::LeadingPadding { byte_count: 3 }
        ));
    }

    #[test]
    fn leading_tab_rejected() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = vec![b'\t'];
        bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-063")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::LeadingPadding { byte_count: 1 }
        ));
    }

    // -- Rejection: empty input --

    #[test]
    fn empty_input_rejected() {
        let (mut guard, _schema) = setup_guard();
        let err = guard
            .validate(ObjectDomain::PolicyObject, &[], "t-070")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::DeserializationFailed { .. }
        ));
    }

    // -- Standalone is_canonical_raw --

    #[test]
    fn is_canonical_raw_accepts_valid() {
        let value = CanonicalValue::U64(42);
        let bytes = encode_value(&value);
        assert!(CanonicalGuard::is_canonical_raw(&bytes).is_ok());
    }

    #[test]
    fn is_canonical_raw_rejects_trailing() {
        let value = CanonicalValue::U64(42);
        let mut bytes = encode_value(&value);
        bytes.push(0xFF);
        let err = CanonicalGuard::is_canonical_raw(&bytes).unwrap_err();
        assert!(matches!(err, CanonicalViolation::TrailingBytes { .. }));
    }

    #[test]
    fn is_canonical_raw_rejects_leading_padding() {
        let value = CanonicalValue::U64(42);
        let encoded = encode_value(&value);
        let mut bytes = vec![b' '];
        bytes.extend_from_slice(&encoded);
        let err = CanonicalGuard::is_canonical_raw(&bytes).unwrap_err();
        assert!(matches!(err, CanonicalViolation::LeadingPadding { .. }));
    }

    // -- Round-trip property: canonical encoding is stable --

    #[test]
    fn round_trip_stability() {
        let (mut guard, schema) = setup_guard();
        let values = vec![
            CanonicalValue::U64(0),
            CanonicalValue::U64(u64::MAX),
            CanonicalValue::I64(-1),
            CanonicalValue::Bool(true),
            CanonicalValue::Bool(false),
            CanonicalValue::Bytes(vec![]),
            CanonicalValue::Bytes(vec![0xFF; 256]),
            CanonicalValue::String(String::new()),
            CanonicalValue::String("unicode: \u{1F600}".to_string()),
            CanonicalValue::Array(vec![]),
            CanonicalValue::Map(BTreeMap::new()),
            CanonicalValue::Null,
        ];

        for value in &values {
            let bytes = make_canonical_payload(&schema, value);
            let result = guard.validate(ObjectDomain::PolicyObject, &bytes, "t-round");
            assert!(result.is_ok(), "failed for value: {value:?}");
            let decoded = result.unwrap();
            assert_eq!(&decoded, value);

            // Re-serialize must match exactly.
            let re_serialized = make_canonical_payload(&schema, &decoded);
            assert_eq!(bytes, re_serialized);
        }
    }

    // -- Non-standard bool encoding detection --

    #[test]
    fn non_standard_bool_detected() {
        // 0x03 is TAG_BOOL; value should be 0x00 or 0x01.
        let bytes = [0x03, 0x02]; // bool with value 0x02
        let violation = check_bool_encoding(&bytes);
        assert!(violation.is_some());
        assert!(matches!(
            violation.unwrap(),
            CanonicalViolation::NonStandardBoolEncoding {
                byte: 0x02,
                offset: 1
            }
        ));
    }

    #[test]
    fn standard_bool_accepted() {
        let bytes_false = [0x03, 0x00];
        let bytes_true = [0x03, 0x01];
        assert!(check_bool_encoding(&bytes_false).is_none());
        assert!(check_bool_encoding(&bytes_true).is_none());
    }

    // -- Events and counters --

    #[test]
    fn events_emitted_on_accept() {
        let (mut guard, schema) = setup_guard();
        let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-evt-1")
            .unwrap();
        let events = guard.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].event_type, GuardEventType::Accepted));
        assert_eq!(events[0].trace_id, "t-evt-1");
    }

    #[test]
    fn events_emitted_on_reject() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
        bytes.push(0x00);
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-evt-2")
            .unwrap_err();
        let events = guard.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            GuardEventType::Rejected { .. }
        ));
    }

    #[test]
    fn event_counts() {
        let (mut guard, schema) = setup_guard();

        // One success.
        let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-cnt-1")
            .unwrap();

        // One failure.
        let mut bad = make_canonical_payload(&schema, &CanonicalValue::Null);
        bad.push(0x00);
        guard
            .validate(ObjectDomain::PolicyObject, &bad, "t-cnt-2")
            .unwrap_err();

        let counts = guard.event_counts();
        assert_eq!(counts.get("accepted"), Some(&1));
        assert_eq!(counts.get("rejected"), Some(&1));
    }

    #[test]
    fn drain_events_clears() {
        let (mut guard, schema) = setup_guard();
        let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-drain")
            .unwrap();
        assert_eq!(guard.drain_events().len(), 1);
        assert_eq!(guard.drain_events().len(), 0); // second drain is empty
    }

    // -- Multiple classes --

    #[test]
    fn multiple_classes_registered() {
        let mut guard = CanonicalGuard::new();
        let schema_policy =
            guard.register_class(ObjectDomain::PolicyObject, "Policy", 1, b"policy-schema");
        let schema_evidence = guard.register_class(
            ObjectDomain::EvidenceRecord,
            "Evidence",
            1,
            b"evidence-schema",
        );

        assert_eq!(guard.registered_class_count(), 2);
        assert!(guard.is_class_registered(&ObjectDomain::PolicyObject));
        assert!(guard.is_class_registered(&ObjectDomain::EvidenceRecord));
        assert!(!guard.is_class_registered(&ObjectDomain::Revocation));

        // Both classes accept valid inputs.
        let policy_bytes = make_canonical_payload(&schema_policy, &CanonicalValue::U64(1));
        let evidence_bytes = make_canonical_payload(&schema_evidence, &CanonicalValue::U64(2));

        assert!(
            guard
                .validate(ObjectDomain::PolicyObject, &policy_bytes, "t-multi-1")
                .is_ok()
        );
        assert!(
            guard
                .validate(ObjectDomain::EvidenceRecord, &evidence_bytes, "t-multi-2")
                .is_ok()
        );
    }

    #[test]
    fn cross_class_schema_mismatch_rejected() {
        let mut guard = CanonicalGuard::new();
        let schema_policy =
            guard.register_class(ObjectDomain::PolicyObject, "Policy", 1, b"policy-schema");
        guard.register_class(
            ObjectDomain::EvidenceRecord,
            "Evidence",
            1,
            b"evidence-schema",
        );

        // Policy bytes validated against EvidenceRecord class should fail.
        let policy_bytes = make_canonical_payload(&schema_policy, &CanonicalValue::U64(1));
        let err = guard
            .validate(ObjectDomain::EvidenceRecord, &policy_bytes, "t-cross")
            .unwrap_err();
        assert!(matches!(
            err.violation,
            CanonicalViolation::SchemaViolation { .. }
        ));
    }

    // -- validate_from_registry --

    #[test]
    fn validate_from_registry_finds_class() {
        let mut guard = CanonicalGuard::new();
        let schema = guard.register_class(
            ObjectDomain::Revocation,
            "Revocation",
            1,
            b"revocation-schema",
        );
        let bytes = make_canonical_payload(&schema, &CanonicalValue::Bool(false));
        let (domain, value) = guard.validate_from_registry(&bytes, "t-reg-1").unwrap();
        assert_eq!(domain, ObjectDomain::Revocation);
        assert_eq!(value, CanonicalValue::Bool(false));
    }

    #[test]
    fn validate_from_registry_rejects_unknown() {
        let guard = &mut CanonicalGuard::new();
        let unknown_schema = SchemaHash::from_definition(b"unknown");
        let bytes = make_canonical_payload(&unknown_schema, &CanonicalValue::Null);
        assert!(guard.validate_from_registry(&bytes, "t-reg-2").is_err());
    }

    // -- Error display --

    #[test]
    fn violation_display() {
        let v = CanonicalViolation::TrailingBytes { count: 5 };
        assert!(v.to_string().contains("5"));

        let v = CanonicalViolation::DuplicateKey {
            key: "x".to_string(),
        };
        assert!(v.to_string().contains("x"));

        let v = CanonicalViolation::LeadingPadding { byte_count: 3 };
        assert!(v.to_string().contains("3"));
    }

    #[test]
    fn non_canonical_error_display() {
        let err = NonCanonicalError {
            object_class: ObjectDomain::PolicyObject,
            input_hash: [0u8; 32],
            violation: CanonicalViolation::TrailingBytes { count: 1 },
            trace_id: "trace-abc".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("policy_object"));
        assert!(display.contains("trailing"));
        assert!(display.contains("trace-abc"));
    }

    #[test]
    fn guard_event_type_display() {
        assert_eq!(GuardEventType::Accepted.to_string(), "accepted");
        assert!(
            GuardEventType::UnregisteredClass
                .to_string()
                .contains("unregistered")
        );
    }

    // -- Serialization round-trips --

    #[test]
    fn violation_serialization_round_trip() {
        let violations = vec![
            CanonicalViolation::NonLexicographicKeys {
                prev_key: "z".to_string(),
                current_key: "a".to_string(),
            },
            CanonicalViolation::DuplicateKey {
                key: "k".to_string(),
            },
            CanonicalViolation::TrailingBytes { count: 42 },
            CanonicalViolation::NonStandardBoolEncoding {
                byte: 0x02,
                offset: 10,
            },
            CanonicalViolation::LeadingPadding { byte_count: 3 },
            CanonicalViolation::RoundTripMismatch {
                first_diff_offset: 5,
                expected: 0x01,
                actual: 0x02,
            },
            CanonicalViolation::LengthMismatch {
                input_len: 100,
                canonical_len: 99,
            },
            CanonicalViolation::DeserializationFailed {
                detail: "bad".to_string(),
            },
            CanonicalViolation::InvalidTag {
                tag: 0xFF,
                offset: 0,
            },
            CanonicalViolation::SchemaViolation {
                detail: "mismatch".to_string(),
            },
        ];
        for v in &violations {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: CanonicalViolation = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn non_canonical_error_serialization_round_trip() {
        let err = NonCanonicalError {
            object_class: ObjectDomain::EvidenceRecord,
            input_hash: [0xAB; 32],
            violation: CanonicalViolation::TrailingBytes { count: 1 },
            trace_id: "t-serde".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: NonCanonicalError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    #[test]
    fn guard_event_serialization_round_trip() {
        let event = GuardEvent {
            event_type: GuardEventType::Rejected {
                violation: CanonicalViolation::InvalidTag {
                    tag: 0xFE,
                    offset: 32,
                },
            },
            object_class: ObjectDomain::Revocation,
            trace_id: "t-ser".to_string(),
            input_hash: [0x01; 32],
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: GuardEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Default --

    #[test]
    fn guard_default_is_empty() {
        let guard = CanonicalGuard::default();
        assert_eq!(guard.registered_class_count(), 0);
        assert_eq!(guard.acceptance_count(), 0);
        assert_eq!(guard.rejection_count(), 0);
    }

    // -- Input hash in errors --

    #[test]
    fn error_contains_correct_input_hash() {
        let (mut guard, schema) = setup_guard();
        let mut bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
        bytes.push(0x00); // make non-canonical
        let expected_hash = compute_input_hash(&bytes);
        let err = guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-hash")
            .unwrap_err();
        assert_eq!(err.input_hash, expected_hash);
    }
}
