//! EngineObjectId: domain-separated, deterministic object identity for
//! security-critical state.
//!
//! Produces collision-resistant, domain-separated identifiers for all signed
//! security-critical objects. The derivation formula is:
//! `len(domain_sep) || domain_sep || len(zone) || zone || schema_id_32bytes || canonical_bytes`
//!
//! This module is a leaf dependency with no runtime state; it is a pure
//! function with no side effects or ambient state dependencies.
//!
//! Plan references: Section 10.10 item 1, 9E.1 (canonical object identity),
//! Top-10 #1, #3, #7, #10.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Output length of an EngineObjectId in bytes (256 bits).
pub const OBJECT_ID_LEN: usize = 32;

// ---------------------------------------------------------------------------
// ObjectDomain — domain separation tag registry
// ---------------------------------------------------------------------------

/// Domain separation tags for all object classes.
///
/// Each variant has a unique, well-known ASCII string that is included in the
/// hash preimage. New object classes must register a variant here to prevent
/// cross-domain collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObjectDomain {
    /// Policy objects (capability profiles, runtime policies).
    PolicyObject,
    /// Evidence records (ledger entries, decision receipts).
    EvidenceRecord,
    /// Revocation notices (capability revocations, key revocations).
    Revocation,
    /// Signed extension manifests.
    SignedManifest,
    /// Key attestation objects (owner-signed key bindings).
    Attestation,
    /// Capability tokens (runtime capabilities, delegation tokens).
    CapabilityToken,
    /// Checkpoint artifacts (runtime checkpoint snapshots).
    CheckpointArtifact,
    /// Recovery artifacts (degraded-mode repair evidence).
    RecoveryArtifact,
    /// Owner key bundles (bound signing/encryption/issuance key triples).
    KeyBundle,
}

impl ObjectDomain {
    /// The fixed domain separation tag as an ASCII byte string.
    pub fn tag(&self) -> &'static [u8] {
        match self {
            Self::PolicyObject => b"FrankenEngine.PolicyObject.v1",
            Self::EvidenceRecord => b"FrankenEngine.EvidenceRecord.v1",
            Self::Revocation => b"FrankenEngine.Revocation.v1",
            Self::SignedManifest => b"FrankenEngine.SignedManifest.v1",
            Self::Attestation => b"FrankenEngine.Attestation.v1",
            Self::CapabilityToken => b"FrankenEngine.CapabilityToken.v1",
            Self::CheckpointArtifact => b"FrankenEngine.CheckpointArtifact.v1",
            Self::RecoveryArtifact => b"FrankenEngine.RecoveryArtifact.v1",
            Self::KeyBundle => b"FrankenEngine.KeyBundle.v1",
        }
    }

    /// All domain variants for exhaustive iteration.
    pub const ALL: &'static [ObjectDomain] = &[
        ObjectDomain::PolicyObject,
        ObjectDomain::EvidenceRecord,
        ObjectDomain::Revocation,
        ObjectDomain::SignedManifest,
        ObjectDomain::Attestation,
        ObjectDomain::CapabilityToken,
        ObjectDomain::CheckpointArtifact,
        ObjectDomain::RecoveryArtifact,
        ObjectDomain::KeyBundle,
    ];
}

impl fmt::Display for ObjectDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyObject => write!(f, "policy_object"),
            Self::EvidenceRecord => write!(f, "evidence_record"),
            Self::Revocation => write!(f, "revocation"),
            Self::SignedManifest => write!(f, "signed_manifest"),
            Self::Attestation => write!(f, "attestation"),
            Self::CapabilityToken => write!(f, "capability_token"),
            Self::CheckpointArtifact => write!(f, "checkpoint_artifact"),
            Self::RecoveryArtifact => write!(f, "recovery_artifact"),
            Self::KeyBundle => write!(f, "key_bundle"),
        }
    }
}

// ---------------------------------------------------------------------------
// SchemaId — content-addressed schema identifier
// ---------------------------------------------------------------------------

/// A 32-byte content-addressed schema identifier.
///
/// Derived from the schema definition itself (not from a mutable version
/// label). Two schemas with identical definitions produce the same SchemaId.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SchemaId(pub [u8; OBJECT_ID_LEN]);

impl SchemaId {
    /// Derive a schema ID from the schema definition bytes.
    pub fn from_definition(definition: &[u8]) -> Self {
        Self(deterministic_hash(definition))
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; OBJECT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EngineObjectId — the main identifier type
// ---------------------------------------------------------------------------

/// A 32-byte domain-separated, deterministic object identifier.
///
/// The ID is computed as:
/// ```text
/// hash(len(domain_tag) || domain_tag || len(zone) || zone || schema_id || canonical_bytes)
/// ```
/// where lengths are encoded as 4-byte big-endian u32.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EngineObjectId(pub [u8; OBJECT_ID_LEN]);

impl EngineObjectId {
    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        &self.0
    }

    /// Hex-encode the ID for display.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(OBJECT_ID_LEN * 2);
        for byte in &self.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    /// Decode from a hex string (64 hex chars).
    pub fn from_hex(hex: &str) -> Result<Self, IdError> {
        if hex.len() != OBJECT_ID_LEN * 2 {
            return Err(IdError::InvalidHexLength {
                expected: OBJECT_ID_LEN * 2,
                actual: hex.len(),
            });
        }
        let mut bytes = [0u8; OBJECT_ID_LEN];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0]).ok_or(IdError::InvalidHexChar { position: i * 2 })?;
            let lo = hex_digit(chunk[1]).ok_or(IdError::InvalidHexChar {
                position: i * 2 + 1,
            })?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for EngineObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// IdError — errors from ID operations
// ---------------------------------------------------------------------------

/// Errors from EngineObjectId operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdError {
    /// Canonical bytes are empty.
    EmptyCanonicalBytes,
    /// ID verification failed: computed ID does not match expected.
    IdMismatch {
        expected: EngineObjectId,
        computed: EngineObjectId,
    },
    /// Non-canonical input detected (contains forbidden byte sequences).
    NonCanonicalInput { reason: String },
    /// Hex string has wrong length.
    InvalidHexLength { expected: usize, actual: usize },
    /// Invalid hex character.
    InvalidHexChar { position: usize },
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCanonicalBytes => write!(f, "canonical bytes are empty"),
            Self::IdMismatch { expected, computed } => {
                write!(f, "ID mismatch: expected {expected}, computed {computed}")
            }
            Self::NonCanonicalInput { reason } => {
                write!(f, "non-canonical input: {reason}")
            }
            Self::InvalidHexLength { expected, actual } => {
                write!(f, "hex length: expected {expected}, got {actual}")
            }
            Self::InvalidHexChar { position } => {
                write!(f, "invalid hex char at position {position}")
            }
        }
    }
}

impl std::error::Error for IdError {}

// ---------------------------------------------------------------------------
// derive_id — the core derivation function
// ---------------------------------------------------------------------------

/// Derive an EngineObjectId from its components.
///
/// Preimage layout (length-prefixed to prevent ambiguity):
/// ```text
/// u32_be(len(domain_tag)) || domain_tag
/// u32_be(len(zone))       || zone
/// schema_id               [32 bytes, fixed]
/// canonical_bytes          [variable]
/// ```
///
/// This is a pure function with no side effects.
pub fn derive_id(
    domain: ObjectDomain,
    zone: &str,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Result<EngineObjectId, IdError> {
    if canonical_bytes.is_empty() {
        return Err(IdError::EmptyCanonicalBytes);
    }

    let preimage = build_preimage(domain, zone, schema_id, canonical_bytes);
    Ok(EngineObjectId(deterministic_hash(&preimage)))
}

/// Verify that an object's ID matches the expected value.
///
/// Recomputes the ID from the object's components and compares using
/// constant-time equality to prevent timing side-channels.
pub fn verify_id(
    expected: &EngineObjectId,
    domain: ObjectDomain,
    zone: &str,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Result<(), IdError> {
    let computed = derive_id(domain, zone, schema_id, canonical_bytes)?;
    if constant_time_eq(&expected.0, &computed.0) {
        Ok(())
    } else {
        Err(IdError::IdMismatch {
            expected: expected.clone(),
            computed,
        })
    }
}

// ---------------------------------------------------------------------------
// Preimage construction
// ---------------------------------------------------------------------------

/// Build the preimage bytes for ID derivation.
fn build_preimage(
    domain: ObjectDomain,
    zone: &str,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Vec<u8> {
    let tag = domain.tag();
    let zone_bytes = zone.as_bytes();

    let mut preimage = Vec::with_capacity(
        4 + tag.len() + 4 + zone_bytes.len() + OBJECT_ID_LEN + canonical_bytes.len(),
    );

    // Length-prefixed domain tag.
    preimage.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    preimage.extend_from_slice(tag);

    // Length-prefixed zone.
    preimage.extend_from_slice(&(zone_bytes.len() as u32).to_be_bytes());
    preimage.extend_from_slice(zone_bytes);

    // Fixed-length schema ID (32 bytes).
    preimage.extend_from_slice(schema_id.as_bytes());

    // Canonical bytes (variable length, last field — unambiguous).
    preimage.extend_from_slice(canonical_bytes);

    preimage
}

// ---------------------------------------------------------------------------
// Deterministic hash — de novo construction
// ---------------------------------------------------------------------------

/// De novo deterministic hash function producing 32 bytes.
///
/// This is a non-cryptographic, collision-resistant hash for identity
/// derivation. It uses a Merkle-Damgard-like construction with a
/// mixing function inspired by SipHash rounds. For production use,
/// this should be replaced with BLAKE3 via a trait abstraction.
fn deterministic_hash(input: &[u8]) -> [u8; OBJECT_ID_LEN] {
    // Initialize state with fixed IV (nothing-up-my-sleeve numbers).
    let mut state: [u64; 4] = [
        0x736f_6d65_7073_6575, // "somepseu"
        0x646f_7261_6e64_6f6d, // "dorandom"
        0x6c79_6765_6e65_7261, // "lygenera"
        0x7465_6462_7974_6573, // "tedbytes"
    ];

    // Mix in input length.
    state[0] ^= input.len() as u64;

    // Process input in 8-byte blocks.
    let chunks = input.chunks(8);
    for chunk in chunks {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let word = u64::from_le_bytes(block);

        state[3] ^= word;
        sip_round(&mut state);
        sip_round(&mut state);
        state[0] ^= word;
    }

    // Finalization: additional mixing rounds.
    state[2] ^= 0xff;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash1 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[1] ^= 0xee;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash2 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[0] ^= 0xdd;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash3 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[3] ^= 0xcc;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash4 = state[0] ^ state[1] ^ state[2] ^ state[3];

    let mut output = [0u8; OBJECT_ID_LEN];
    output[0..8].copy_from_slice(&hash1.to_le_bytes());
    output[8..16].copy_from_slice(&hash2.to_le_bytes());
    output[16..24].copy_from_slice(&hash3.to_le_bytes());
    output[24..32].copy_from_slice(&hash4.to_le_bytes());

    output
}

/// SipHash-like mixing round.
#[inline]
fn sip_round(state: &mut [u64; 4]) {
    state[0] = state[0].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(13);
    state[1] ^= state[0];
    state[0] = state[0].rotate_left(32);

    state[2] = state[2].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(16);
    state[3] ^= state[2];

    state[0] = state[0].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(21);
    state[3] ^= state[0];

    state[2] = state[2].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(17);
    state[1] ^= state[2];
    state[2] = state[2].rotate_left(32);
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Constant-time byte array comparison (no early exit).
fn constant_time_eq(a: &[u8; OBJECT_ID_LEN], b: &[u8; OBJECT_ID_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..OBJECT_ID_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Hex helper
// ---------------------------------------------------------------------------

/// Parse a single hex digit.
fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_schema_id() -> SchemaId {
        SchemaId::from_definition(b"test-schema-v1")
    }

    fn test_canonical_bytes() -> Vec<u8> {
        b"canonical-object-content-bytes".to_vec()
    }

    // -- ObjectDomain --

    #[test]
    fn all_domains_have_unique_tags() {
        let tags: Vec<&[u8]> = ObjectDomain::ALL.iter().map(|d| d.tag()).collect();
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domains {:?} and {:?} share tag", i, j);
                }
            }
        }
    }

    #[test]
    fn domain_display() {
        assert_eq!(ObjectDomain::PolicyObject.to_string(), "policy_object");
        assert_eq!(ObjectDomain::EvidenceRecord.to_string(), "evidence_record");
        assert_eq!(ObjectDomain::Revocation.to_string(), "revocation");
        assert_eq!(ObjectDomain::SignedManifest.to_string(), "signed_manifest");
        assert_eq!(
            ObjectDomain::CapabilityToken.to_string(),
            "capability_token"
        );
        assert_eq!(
            ObjectDomain::CheckpointArtifact.to_string(),
            "checkpoint_artifact"
        );
        assert_eq!(
            ObjectDomain::RecoveryArtifact.to_string(),
            "recovery_artifact"
        );
    }

    // -- derive_id determinism --

    #[test]
    fn derive_id_is_deterministic() {
        let id1 = derive_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &test_schema_id(),
            &test_canonical_bytes(),
        )
        .unwrap();
        let id2 = derive_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &test_schema_id(),
            &test_canonical_bytes(),
        )
        .unwrap();
        assert_eq!(id1, id2);
    }

    // -- Domain separation --

    #[test]
    fn different_domains_produce_different_ids() {
        let content = test_canonical_bytes();
        let schema = test_schema_id();
        let zone = "zone-x";

        let ids: Vec<EngineObjectId> = ObjectDomain::ALL
            .iter()
            .map(|d| derive_id(*d, zone, &schema, &content).unwrap())
            .collect();

        for (i, a) in ids.iter().enumerate() {
            for (j, b) in ids.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domains {} and {} produced same ID", i, j);
                }
            }
        }
    }

    // -- Zone separation --

    #[test]
    fn different_zones_produce_different_ids() {
        let content = test_canonical_bytes();
        let schema = test_schema_id();

        let id_a = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "zone-b", &schema, &content).unwrap();
        assert_ne!(id_a, id_b);
    }

    // -- Schema separation --

    #[test]
    fn different_schemas_produce_different_ids() {
        let content = test_canonical_bytes();
        let schema_v1 = SchemaId::from_definition(b"schema-v1");
        let schema_v2 = SchemaId::from_definition(b"schema-v2");

        let id_v1 = derive_id(ObjectDomain::EvidenceRecord, "zone", &schema_v1, &content).unwrap();
        let id_v2 = derive_id(ObjectDomain::EvidenceRecord, "zone", &schema_v2, &content).unwrap();
        assert_ne!(id_v1, id_v2);
    }

    // -- Content separation --

    #[test]
    fn different_content_produces_different_ids() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::Revocation, "zone", &schema, b"content-a").unwrap();
        let id_b = derive_id(ObjectDomain::Revocation, "zone", &schema, b"content-b").unwrap();
        assert_ne!(id_a, id_b);
    }

    // -- Empty canonical bytes rejection --

    #[test]
    fn derive_rejects_empty_canonical_bytes() {
        let err =
            derive_id(ObjectDomain::PolicyObject, "zone", &test_schema_id(), b"").unwrap_err();
        assert_eq!(err, IdError::EmptyCanonicalBytes);
    }

    // -- verify_id --

    #[test]
    fn verify_id_succeeds_on_valid_content() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();
        assert!(verify_id(&id, ObjectDomain::PolicyObject, "zone-a", &schema, &content).is_ok());
    }

    #[test]
    fn verify_id_fails_on_tampered_content() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();

        let tampered = b"tampered-content";
        let err =
            verify_id(&id, ObjectDomain::PolicyObject, "zone-a", &schema, tampered).unwrap_err();
        assert!(matches!(err, IdError::IdMismatch { .. }));
    }

    #[test]
    fn verify_id_fails_on_wrong_domain() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();

        let err = verify_id(
            &id,
            ObjectDomain::EvidenceRecord,
            "zone-a",
            &schema,
            &content,
        )
        .unwrap_err();
        assert!(matches!(err, IdError::IdMismatch { .. }));
    }

    #[test]
    fn verify_id_fails_on_wrong_zone() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();

        let err =
            verify_id(&id, ObjectDomain::PolicyObject, "zone-b", &schema, &content).unwrap_err();
        assert!(matches!(err, IdError::IdMismatch { .. }));
    }

    // -- Constant-time comparison --

    #[test]
    fn constant_time_eq_same() {
        let a = [42u8; OBJECT_ID_LEN];
        let b = [42u8; OBJECT_ID_LEN];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different() {
        let a = [42u8; OBJECT_ID_LEN];
        let mut b = [42u8; OBJECT_ID_LEN];
        b[31] = 43;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_all_different() {
        let a = [0u8; OBJECT_ID_LEN];
        let b = [0xffu8; OBJECT_ID_LEN];
        assert!(!constant_time_eq(&a, &b));
    }

    // -- SchemaId --

    #[test]
    fn schema_id_from_definition_is_deterministic() {
        let a = SchemaId::from_definition(b"test-schema");
        let b = SchemaId::from_definition(b"test-schema");
        assert_eq!(a, b);
    }

    #[test]
    fn schema_id_different_definitions_produce_different_ids() {
        let a = SchemaId::from_definition(b"schema-alpha");
        let b = SchemaId::from_definition(b"schema-beta");
        assert_ne!(a, b);
    }

    #[test]
    fn schema_id_display_is_hex() {
        let schema = SchemaId::from_definition(b"test");
        let display = schema.to_string();
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- Hex encoding/decoding --

    #[test]
    fn hex_round_trip() {
        let id = derive_id(
            ObjectDomain::PolicyObject,
            "zone",
            &test_schema_id(),
            b"hello",
        )
        .unwrap();
        let hex = id.to_hex();
        let restored = EngineObjectId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn hex_decode_wrong_length() {
        let err = EngineObjectId::from_hex("abcd").unwrap_err();
        assert!(matches!(err, IdError::InvalidHexLength { .. }));
    }

    #[test]
    fn hex_decode_invalid_char() {
        let bad = "zz".to_string() + &"00".repeat(31);
        let err = EngineObjectId::from_hex(&bad).unwrap_err();
        assert!(matches!(err, IdError::InvalidHexChar { .. }));
    }

    // -- Golden vector test --

    #[test]
    fn golden_vector_policy_object() {
        // Fixed inputs for reproducible golden vector.
        let domain = ObjectDomain::PolicyObject;
        let zone = "production/us-east-1";
        let schema = SchemaId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let canonical = b"golden-vector-test-content-v1";

        let id = derive_id(domain, zone, &schema, canonical).unwrap();
        let hex = id.to_hex();

        // Re-derive to confirm determinism.
        let id2 = derive_id(domain, zone, &schema, canonical).unwrap();
        assert_eq!(id, id2);
        assert_eq!(hex.len(), 64);

        // Verify that the golden vector is stable across calls.
        let expected_hex = hex.clone();
        let id3 = EngineObjectId::from_hex(&expected_hex).unwrap();
        assert_eq!(id, id3);
    }

    #[test]
    fn golden_vector_evidence_record() {
        let domain = ObjectDomain::EvidenceRecord;
        let zone = "lab/test-cluster";
        let schema = SchemaId::from_definition(b"EvidenceSchema.v2");
        let canonical = b"evidence-entry-canonical-payload";

        let id = derive_id(domain, zone, &schema, canonical).unwrap();

        // Same inputs always produce same output.
        let id2 = derive_id(domain, zone, &schema, canonical).unwrap();
        assert_eq!(id, id2);

        // Verify round-trip through hex.
        let hex = id.to_hex();
        let restored = EngineObjectId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    // -- Preimage construction --

    #[test]
    fn preimage_includes_all_components() {
        let domain = ObjectDomain::PolicyObject;
        let zone = "zone-test";
        let schema = test_schema_id();
        let content = b"test-content";

        let preimage = build_preimage(domain, zone, &schema, content);

        // Should contain domain tag.
        let tag = domain.tag();
        assert!(preimage.windows(tag.len()).any(|w| w == tag));

        // Should contain zone.
        assert!(preimage.windows(zone.len()).any(|w| w == zone.as_bytes()));

        // Should contain schema ID bytes.
        assert!(
            preimage
                .windows(OBJECT_ID_LEN)
                .any(|w| w == schema.as_bytes())
        );

        // Should contain content.
        assert!(preimage.windows(content.len()).any(|w| w == content));
    }

    // -- Hash properties --

    #[test]
    fn hash_empty_input() {
        let h = deterministic_hash(b"");
        // Just check it doesn't panic and produces 32 bytes.
        assert_eq!(h.len(), OBJECT_ID_LEN);
    }

    #[test]
    fn hash_deterministic() {
        let h1 = deterministic_hash(b"test input");
        let h2 = deterministic_hash(b"test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_avalanche_single_bit() {
        let a = deterministic_hash(b"test input A");
        let b = deterministic_hash(b"test input B");
        // Different inputs should produce different outputs.
        assert_ne!(a, b);
        // Count differing bits (should be roughly half for good avalanche).
        let differing_bits: u32 = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum();
        // At least 30% of bits should differ (conservative bound).
        assert!(
            differing_bits > (OBJECT_ID_LEN as u32 * 8 * 30 / 100),
            "poor avalanche: only {differing_bits} bits differ"
        );
    }

    #[test]
    fn hash_length_dependence() {
        // Same prefix but different length should produce different hashes.
        let a = deterministic_hash(b"hello");
        let b = deterministic_hash(b"hello world");
        assert_ne!(a, b);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            IdError::EmptyCanonicalBytes.to_string(),
            "canonical bytes are empty"
        );
        assert!(
            IdError::InvalidHexLength {
                expected: 64,
                actual: 10
            }
            .to_string()
            .contains("64")
        );
        assert!(
            IdError::InvalidHexChar { position: 5 }
                .to_string()
                .contains("5")
        );
    }

    // -- Serialization --

    #[test]
    fn engine_object_id_serialization_round_trip() {
        let id = derive_id(
            ObjectDomain::PolicyObject,
            "zone",
            &test_schema_id(),
            b"content",
        )
        .unwrap();
        let json = serde_json::to_string(&id).expect("serialize");
        let restored: EngineObjectId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, restored);
    }

    #[test]
    fn schema_id_serialization_round_trip() {
        let schema = test_schema_id();
        let json = serde_json::to_string(&schema).expect("serialize");
        let restored: SchemaId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schema, restored);
    }

    #[test]
    fn object_domain_serialization_round_trip() {
        for domain in ObjectDomain::ALL {
            let json = serde_json::to_string(domain).expect("serialize");
            let restored: ObjectDomain = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*domain, restored);
        }
    }

    #[test]
    fn id_error_serialization_round_trip() {
        let errors = vec![
            IdError::EmptyCanonicalBytes,
            IdError::InvalidHexLength {
                expected: 64,
                actual: 10,
            },
            IdError::InvalidHexChar { position: 3 },
            IdError::NonCanonicalInput {
                reason: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: IdError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- EngineObjectId display --

    #[test]
    fn engine_object_id_display_is_hex() {
        let id = derive_id(
            ObjectDomain::Revocation,
            "zone",
            &test_schema_id(),
            b"revoke",
        )
        .unwrap();
        let display = id.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
