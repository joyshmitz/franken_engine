//! Proof schema and signer model for optimizer activation witnesses.
//!
//! Defines the canonical data structures (`OptReceipt`, `RollbackToken`,
//! `InvarianceDigest`) that every adaptive optimization path must produce
//! before activation is permitted.
//!
//! Plan references: Section 10.12 item 1, 9H.1 (proof-carrying adaptive
//! optimizer), 9F.1 (verified adaptive compiler).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for forward/backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub major: u16,
    pub minor: u16,
}

impl SchemaVersion {
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// Whether this version is compatible with `other` (same major version).
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// OptimizationClass — types of optimizations
// ---------------------------------------------------------------------------

/// Classification of optimizer transformation types.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OptimizationClass {
    /// Fused super-instruction combining multiple operations.
    Superinstruction,
    /// Trace specialization based on observed hot paths.
    TraceSpecialization,
    /// Memory layout optimization for data access patterns.
    LayoutSpecialization,
    /// Devirtualized host-call fast path.
    DevirtualizedHostcallFastPath,
}

impl fmt::Display for OptimizationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Superinstruction => write!(f, "superinstruction"),
            Self::TraceSpecialization => write!(f, "trace_specialization"),
            Self::LayoutSpecialization => write!(f, "layout_specialization"),
            Self::DevirtualizedHostcallFastPath => write!(f, "devirtualized_hostcall_fast_path"),
        }
    }
}

// ---------------------------------------------------------------------------
// ActivationStage — lifecycle stages of an optimization
// ---------------------------------------------------------------------------

/// Promotion stage for an optimizer activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActivationStage {
    /// Running in shadow mode (no effect on production traffic).
    Shadow,
    /// Canary deployment to a small fraction of traffic.
    Canary,
    /// Ramping to a larger fraction of traffic.
    Ramp,
    /// Default activation for all traffic.
    Default,
}

impl fmt::Display for ActivationStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shadow => write!(f, "shadow"),
            Self::Canary => write!(f, "canary"),
            Self::Ramp => write!(f, "ramp"),
            Self::Default => write!(f, "default"),
        }
    }
}

// ---------------------------------------------------------------------------
// EquivalenceVerdict
// ---------------------------------------------------------------------------

/// Result of trace-level semantic equivalence checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivalenceVerdict {
    /// Baseline and candidate produce identical observable behavior.
    Equivalent,
    /// Observable behavioral difference detected.
    NonEquivalent { reason: String },
    /// Equivalence could not be determined (e.g. timeout, corpus too small).
    Inconclusive { reason: String },
}

// ---------------------------------------------------------------------------
// TraceComparisonMethodology
// ---------------------------------------------------------------------------

/// Methodology used for comparing baseline and candidate traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceComparisonMethodology {
    /// Deterministic replay with bit-exact output comparison.
    DeterministicReplay,
    /// Symbolic execution with equivalence proof.
    SymbolicEquivalence,
    /// Statistical comparison over a corpus of inputs.
    StatisticalCorpus { corpus_size: u64 },
}

// ---------------------------------------------------------------------------
// InvarianceDigest — equivalence commitment
// ---------------------------------------------------------------------------

/// Cryptographic commitment over the semantic equivalence claim between
/// baseline IR traces and optimized candidate traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvarianceDigest {
    /// Schema version for forward compatibility.
    pub schema_version: SchemaVersion,
    /// Hash of the golden test corpus used for comparison.
    pub golden_corpus_hash: ContentHash,
    /// Methodology used for trace comparison.
    pub trace_comparison_methodology: TraceComparisonMethodology,
    /// Outcome of the equivalence check.
    pub equivalence_verdict: EquivalenceVerdict,
    /// Root hash of the witness chain (Merkle root over individual
    /// trace-comparison witness entries).
    pub witness_chain_root: ContentHash,
}

impl InvarianceDigest {
    /// Compute the content hash of this digest for inclusion in receipts.
    pub fn content_hash(&self) -> ContentHash {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.schema_version.major.to_be_bytes());
        preimage.extend_from_slice(&self.schema_version.minor.to_be_bytes());
        preimage.extend_from_slice(self.golden_corpus_hash.as_bytes());

        let method_tag = match &self.trace_comparison_methodology {
            TraceComparisonMethodology::DeterministicReplay => b"deterministic_replay" as &[u8],
            TraceComparisonMethodology::SymbolicEquivalence => b"symbolic_equivalence",
            TraceComparisonMethodology::StatisticalCorpus { corpus_size } => {
                preimage.extend_from_slice(&corpus_size.to_be_bytes());
                b"statistical_corpus"
            }
        };
        preimage.extend_from_slice(&(method_tag.len() as u32).to_be_bytes());
        preimage.extend_from_slice(method_tag);

        let verdict_tag = match &self.equivalence_verdict {
            EquivalenceVerdict::Equivalent => b"equivalent" as &[u8],
            EquivalenceVerdict::NonEquivalent { reason } => {
                preimage.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                preimage.extend_from_slice(reason.as_bytes());
                b"non_equivalent"
            }
            EquivalenceVerdict::Inconclusive { reason } => {
                preimage.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                preimage.extend_from_slice(reason.as_bytes());
                b"inconclusive"
            }
        };
        preimage.extend_from_slice(&(verdict_tag.len() as u32).to_be_bytes());
        preimage.extend_from_slice(verdict_tag);

        preimage.extend_from_slice(self.witness_chain_root.as_bytes());

        ContentHash::compute(&preimage)
    }
}

// ---------------------------------------------------------------------------
// SignerKeyId — key identity for signatures
// ---------------------------------------------------------------------------

/// Identity of a signing key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignerKeyId {
    /// The key identifier (derived from the public key material).
    pub key_id: EngineObjectId,
    /// Role this key is authorized for.
    pub role: SignerRole,
    /// Security epoch this key is bound to.
    pub bound_epoch: SecurityEpoch,
}

/// Roles that signing keys can hold (split principal model per 10.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SignerRole {
    /// Optimizer subsystem signs receipts.
    OptimizerSubsystem,
    /// Policy plane signs epoch bindings.
    PolicyPlane,
    /// Attestation cell signs TEE-bound variants.
    AttestationCell,
}

impl fmt::Display for SignerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OptimizerSubsystem => write!(f, "optimizer_subsystem"),
            Self::PolicyPlane => write!(f, "policy_plane"),
            Self::AttestationCell => write!(f, "attestation_cell"),
        }
    }
}

// ---------------------------------------------------------------------------
// OptReceipt — optimizer activation receipt
// ---------------------------------------------------------------------------

/// Structured receipt for an optimizer activation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptReceipt {
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Unique optimization identifier.
    pub optimization_id: String,
    /// Class of the optimization.
    pub optimization_class: OptimizationClass,
    /// Content hash of the baseline IR.
    pub baseline_ir_hash: ContentHash,
    /// Content hash of the optimized candidate IR.
    pub candidate_ir_hash: ContentHash,
    /// Hash of the translation witness (proof of correct transformation).
    pub translation_witness_hash: ContentHash,
    /// Invariance digest proving semantic equivalence.
    pub invariance_digest: ContentHash,
    /// Rollback token ID for restoring baseline execution.
    pub rollback_token_id: String,
    /// Replay compatibility metadata (engine version, target arch, etc.).
    pub replay_compatibility: BTreeMap<String, String>,
    /// Security epoch at receipt issuance.
    pub policy_epoch: SecurityEpoch,
    /// Virtual timestamp (deterministic tick count).
    pub timestamp_ticks: u64,
    /// Key used to sign this receipt.
    pub signer_key_id: EngineObjectId,
    /// Correlation ID for audit chain linkage.
    pub correlation_id: String,
    /// Signature over the unsigned view of this receipt.
    pub signature: AuthenticityHash,
}

impl OptReceipt {
    /// Compute the unsigned preimage for signing.
    ///
    /// Uses deterministic field ordering per the 10.10 signature preimage
    /// contract. The `signature` field is excluded from the preimage.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::new();

        // Schema version.
        preimage.extend_from_slice(&self.schema_version.major.to_be_bytes());
        preimage.extend_from_slice(&self.schema_version.minor.to_be_bytes());

        // Optimization identity.
        append_length_prefixed(&mut preimage, self.optimization_id.as_bytes());
        append_length_prefixed(
            &mut preimage,
            self.optimization_class.to_string().as_bytes(),
        );

        // IR hashes.
        preimage.extend_from_slice(self.baseline_ir_hash.as_bytes());
        preimage.extend_from_slice(self.candidate_ir_hash.as_bytes());
        preimage.extend_from_slice(self.translation_witness_hash.as_bytes());
        preimage.extend_from_slice(self.invariance_digest.as_bytes());

        // Rollback token.
        append_length_prefixed(&mut preimage, self.rollback_token_id.as_bytes());

        // Replay compatibility (BTreeMap ensures deterministic ordering).
        preimage.extend_from_slice(&(self.replay_compatibility.len() as u32).to_be_bytes());
        for (k, v) in &self.replay_compatibility {
            append_length_prefixed(&mut preimage, k.as_bytes());
            append_length_prefixed(&mut preimage, v.as_bytes());
        }

        // Epoch and timestamp.
        preimage.extend_from_slice(&self.policy_epoch.as_u64().to_be_bytes());
        preimage.extend_from_slice(&self.timestamp_ticks.to_be_bytes());

        // Signer key.
        preimage.extend_from_slice(self.signer_key_id.as_bytes());

        // Correlation.
        append_length_prefixed(&mut preimage, self.correlation_id.as_bytes());

        preimage
    }

    /// Sign this receipt with the given key material.
    pub fn sign(mut self, key: &[u8]) -> Self {
        let preimage = self.signing_preimage();
        self.signature = AuthenticityHash::compute_keyed(key, &preimage);
        self
    }

    /// Verify the receipt signature against the given key material.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let preimage = self.signing_preimage();
        let expected = AuthenticityHash::compute_keyed(key, &preimage);
        self.signature == expected
    }

    /// Derive the `EngineObjectId` for this receipt.
    pub fn object_id(
        &self,
        zone: &str,
    ) -> Result<EngineObjectId, crate::engine_object_id::IdError> {
        let schema_id = SchemaId::from_definition(b"proof_schema::OptReceipt::v1");
        crate::engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            zone,
            &schema_id,
            &self.signing_preimage(),
        )
    }
}

// ---------------------------------------------------------------------------
// RollbackToken — immutable rollback artifact
// ---------------------------------------------------------------------------

/// Immutable artifact sufficient to deterministically restore baseline
/// execution without re-running validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackToken {
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Unique token identifier.
    pub token_id: String,
    /// Optimization this token can roll back.
    pub optimization_id: String,
    /// Content hash of the baseline execution snapshot.
    pub baseline_snapshot_hash: ContentHash,
    /// Current activation stage at token issuance.
    pub activation_stage: ActivationStage,
    /// Epoch after which this token expires and cannot be used.
    pub expiry_epoch: SecurityEpoch,
    /// Key used to sign this token.
    pub issuer_key_id: EngineObjectId,
    /// Signature over the unsigned view.
    pub issuer_signature: AuthenticityHash,
}

impl RollbackToken {
    /// Compute the unsigned preimage for signing.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::new();

        preimage.extend_from_slice(&self.schema_version.major.to_be_bytes());
        preimage.extend_from_slice(&self.schema_version.minor.to_be_bytes());

        append_length_prefixed(&mut preimage, self.token_id.as_bytes());
        append_length_prefixed(&mut preimage, self.optimization_id.as_bytes());

        preimage.extend_from_slice(self.baseline_snapshot_hash.as_bytes());
        append_length_prefixed(&mut preimage, self.activation_stage.to_string().as_bytes());

        preimage.extend_from_slice(&self.expiry_epoch.as_u64().to_be_bytes());
        preimage.extend_from_slice(self.issuer_key_id.as_bytes());

        preimage
    }

    /// Sign this token with the given key material.
    pub fn sign(mut self, key: &[u8]) -> Self {
        let preimage = self.signing_preimage();
        self.issuer_signature = AuthenticityHash::compute_keyed(key, &preimage);
        self
    }

    /// Verify the token signature.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let preimage = self.signing_preimage();
        let expected = AuthenticityHash::compute_keyed(key, &preimage);
        self.issuer_signature == expected
    }

    /// Check if this token has expired relative to the given epoch.
    pub fn is_expired(&self, current_epoch: SecurityEpoch) -> bool {
        current_epoch > self.expiry_epoch
    }

    /// Derive the `EngineObjectId` for this token.
    pub fn object_id(
        &self,
        zone: &str,
    ) -> Result<EngineObjectId, crate::engine_object_id::IdError> {
        let schema_id = SchemaId::from_definition(b"proof_schema::RollbackToken::v1");
        crate::engine_object_id::derive_id(
            ObjectDomain::RecoveryArtifact,
            zone,
            &schema_id,
            &self.signing_preimage(),
        )
    }
}

// ---------------------------------------------------------------------------
// ProofSchemaError
// ---------------------------------------------------------------------------

/// Errors during proof schema validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSchemaError {
    /// Receipt signature verification failed.
    InvalidSignature { artifact: String },
    /// Schema version is incompatible.
    IncompatibleVersion {
        expected_major: u16,
        actual: SchemaVersion,
    },
    /// Rollback token has expired.
    TokenExpired {
        token_id: String,
        expiry_epoch: u64,
        current_epoch: u64,
    },
    /// Required field is missing or empty.
    MissingField { field: String },
    /// Invariance digest indicates non-equivalence.
    NonEquivalent { reason: String },
    /// Signer role not authorized for this artifact type.
    UnauthorizedSigner { role: SignerRole, artifact: String },
    /// Epoch mismatch between receipt and current epoch.
    EpochMismatch {
        receipt_epoch: u64,
        current_epoch: u64,
    },
}

impl fmt::Display for ProofSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature { artifact } => {
                write!(f, "invalid signature on {artifact}")
            }
            Self::IncompatibleVersion {
                expected_major,
                actual,
            } => write!(
                f,
                "incompatible version: expected major {expected_major}, got {actual}"
            ),
            Self::TokenExpired {
                token_id,
                expiry_epoch,
                current_epoch,
            } => write!(
                f,
                "token {token_id} expired at epoch {expiry_epoch} (current: {current_epoch})"
            ),
            Self::MissingField { field } => write!(f, "missing required field: {field}"),
            Self::NonEquivalent { reason } => write!(f, "non-equivalent: {reason}"),
            Self::UnauthorizedSigner { role, artifact } => {
                write!(f, "role {role} not authorized for {artifact}")
            }
            Self::EpochMismatch {
                receipt_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch mismatch: receipt epoch {receipt_epoch}, current {current_epoch}"
            ),
        }
    }
}

impl std::error::Error for ProofSchemaError {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate an `OptReceipt` against the given key and current epoch.
pub fn validate_receipt(
    receipt: &OptReceipt,
    signing_key: &[u8],
    current_epoch: SecurityEpoch,
) -> Result<(), ProofSchemaError> {
    // Version compatibility.
    if !receipt
        .schema_version
        .is_compatible_with(&SchemaVersion::CURRENT)
    {
        return Err(ProofSchemaError::IncompatibleVersion {
            expected_major: SchemaVersion::CURRENT.major,
            actual: receipt.schema_version,
        });
    }

    // Required fields.
    if receipt.optimization_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "optimization_id".to_string(),
        });
    }
    if receipt.rollback_token_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "rollback_token_id".to_string(),
        });
    }
    if receipt.correlation_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "correlation_id".to_string(),
        });
    }

    // Epoch check.
    if receipt.policy_epoch != current_epoch {
        return Err(ProofSchemaError::EpochMismatch {
            receipt_epoch: receipt.policy_epoch.as_u64(),
            current_epoch: current_epoch.as_u64(),
        });
    }

    // Signature verification.
    if !receipt.verify_signature(signing_key) {
        return Err(ProofSchemaError::InvalidSignature {
            artifact: "OptReceipt".to_string(),
        });
    }

    Ok(())
}

/// Validate a `RollbackToken` against the given key and current epoch.
pub fn validate_rollback_token(
    token: &RollbackToken,
    signing_key: &[u8],
    current_epoch: SecurityEpoch,
) -> Result<(), ProofSchemaError> {
    // Version compatibility.
    if !token
        .schema_version
        .is_compatible_with(&SchemaVersion::CURRENT)
    {
        return Err(ProofSchemaError::IncompatibleVersion {
            expected_major: SchemaVersion::CURRENT.major,
            actual: token.schema_version,
        });
    }

    // Required fields.
    if token.token_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "token_id".to_string(),
        });
    }
    if token.optimization_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "optimization_id".to_string(),
        });
    }

    // Expiry.
    if token.is_expired(current_epoch) {
        return Err(ProofSchemaError::TokenExpired {
            token_id: token.token_id.clone(),
            expiry_epoch: token.expiry_epoch.as_u64(),
            current_epoch: current_epoch.as_u64(),
        });
    }

    // Signature.
    if !token.verify_signature(signing_key) {
        return Err(ProofSchemaError::InvalidSignature {
            artifact: "RollbackToken".to_string(),
        });
    }

    Ok(())
}

/// Check that a signer role is authorized for the given artifact type.
pub fn check_signer_authorization(
    role: SignerRole,
    artifact: &str,
) -> Result<(), ProofSchemaError> {
    let authorized = match artifact {
        "OptReceipt" => role == SignerRole::OptimizerSubsystem,
        "RollbackToken" => {
            role == SignerRole::OptimizerSubsystem || role == SignerRole::PolicyPlane
        }
        "InvarianceDigest" => role == SignerRole::OptimizerSubsystem,
        _ => false,
    };

    if !authorized {
        return Err(ProofSchemaError::UnauthorizedSigner {
            role,
            artifact: artifact.to_string(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Append a length-prefixed byte slice to a preimage buffer.
fn append_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::derive_id;

    const TEST_KEY: &[u8] = b"test-signing-key-material-32bytes!";
    const WRONG_KEY: &[u8] = b"wrong-signing-key-material-xxxxx";

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_signer_key_id() -> EngineObjectId {
        let schema = SchemaId::from_definition(b"test-signer-key");
        derive_id(ObjectDomain::CapabilityToken, "test-zone", &schema, b"key1").expect("derive id")
    }

    fn test_invariance_digest() -> InvarianceDigest {
        InvarianceDigest {
            schema_version: SchemaVersion::CURRENT,
            golden_corpus_hash: ContentHash::compute(b"golden-corpus"),
            trace_comparison_methodology: TraceComparisonMethodology::DeterministicReplay,
            equivalence_verdict: EquivalenceVerdict::Equivalent,
            witness_chain_root: ContentHash::compute(b"witness-chain"),
        }
    }

    fn test_receipt_unsigned() -> OptReceipt {
        let digest = test_invariance_digest();
        OptReceipt {
            schema_version: SchemaVersion::CURRENT,
            optimization_id: "opt-001".to_string(),
            optimization_class: OptimizationClass::Superinstruction,
            baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
            candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
            translation_witness_hash: ContentHash::compute(b"witness"),
            invariance_digest: digest.content_hash(),
            rollback_token_id: "rtk-001".to_string(),
            replay_compatibility: BTreeMap::from([
                ("engine_version".to_string(), "0.1.0".to_string()),
                ("target_arch".to_string(), "x86_64".to_string()),
            ]),
            policy_epoch: test_epoch(),
            timestamp_ticks: 1000,
            signer_key_id: test_signer_key_id(),
            correlation_id: "corr-001".to_string(),
            signature: AuthenticityHash::compute(b"placeholder"),
        }
    }

    fn test_receipt() -> OptReceipt {
        test_receipt_unsigned().sign(TEST_KEY)
    }

    fn test_rollback_unsigned() -> RollbackToken {
        RollbackToken {
            schema_version: SchemaVersion::CURRENT,
            token_id: "rtk-001".to_string(),
            optimization_id: "opt-001".to_string(),
            baseline_snapshot_hash: ContentHash::compute(b"baseline-snapshot"),
            activation_stage: ActivationStage::Shadow,
            expiry_epoch: SecurityEpoch::from_raw(10),
            issuer_key_id: test_signer_key_id(),
            issuer_signature: AuthenticityHash::compute(b"placeholder"),
        }
    }

    fn test_rollback() -> RollbackToken {
        test_rollback_unsigned().sign(TEST_KEY)
    }

    // -- Schema version --

    #[test]
    fn schema_version_compatibility() {
        let v1_0 = SchemaVersion { major: 1, minor: 0 };
        let v1_1 = SchemaVersion { major: 1, minor: 1 };
        let v2_0 = SchemaVersion { major: 2, minor: 0 };

        assert!(v1_0.is_compatible_with(&v1_1));
        assert!(!v1_0.is_compatible_with(&v2_0));
    }

    #[test]
    fn schema_version_display() {
        assert_eq!(SchemaVersion::CURRENT.to_string(), "1.0");
    }

    // -- InvarianceDigest --

    #[test]
    fn invariance_digest_hash_is_deterministic() {
        let d1 = test_invariance_digest();
        let d2 = test_invariance_digest();
        assert_eq!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn invariance_digest_different_verdict_different_hash() {
        let d1 = test_invariance_digest();
        let mut d2 = test_invariance_digest();
        d2.equivalence_verdict = EquivalenceVerdict::NonEquivalent {
            reason: "divergence".to_string(),
        };
        assert_ne!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn invariance_digest_different_methodology_different_hash() {
        let d1 = test_invariance_digest();
        let mut d2 = test_invariance_digest();
        d2.trace_comparison_methodology =
            TraceComparisonMethodology::StatisticalCorpus { corpus_size: 1000 };
        assert_ne!(d1.content_hash(), d2.content_hash());
    }

    // -- OptReceipt signing --

    #[test]
    fn receipt_signing_round_trip() {
        let receipt = test_receipt();
        assert!(receipt.verify_signature(TEST_KEY));
    }

    #[test]
    fn receipt_rejects_wrong_key() {
        let receipt = test_receipt();
        assert!(!receipt.verify_signature(WRONG_KEY));
    }

    #[test]
    fn receipt_signing_is_deterministic() {
        let r1 = test_receipt();
        let r2 = test_receipt();
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn receipt_preimage_changes_with_fields() {
        let r1 = test_receipt();
        let mut r2 = test_receipt_unsigned();
        r2.optimization_id = "opt-002".to_string();
        let r2 = r2.sign(TEST_KEY);
        assert_ne!(r1.signature, r2.signature);
    }

    // -- RollbackToken signing --

    #[test]
    fn rollback_signing_round_trip() {
        let token = test_rollback();
        assert!(token.verify_signature(TEST_KEY));
    }

    #[test]
    fn rollback_rejects_wrong_key() {
        let token = test_rollback();
        assert!(!token.verify_signature(WRONG_KEY));
    }

    #[test]
    fn rollback_signing_is_deterministic() {
        let t1 = test_rollback();
        let t2 = test_rollback();
        assert_eq!(t1.issuer_signature, t2.issuer_signature);
    }

    // -- RollbackToken expiry --

    #[test]
    fn rollback_not_expired_before_expiry_epoch() {
        let token = test_rollback();
        assert!(!token.is_expired(SecurityEpoch::from_raw(5)));
        assert!(!token.is_expired(SecurityEpoch::from_raw(10)));
    }

    #[test]
    fn rollback_expired_after_expiry_epoch() {
        let token = test_rollback();
        assert!(token.is_expired(SecurityEpoch::from_raw(11)));
    }

    // -- Receipt validation --

    #[test]
    fn validate_receipt_success() {
        let receipt = test_receipt();
        assert!(validate_receipt(&receipt, TEST_KEY, test_epoch()).is_ok());
    }

    #[test]
    fn validate_receipt_wrong_key() {
        let receipt = test_receipt();
        assert!(matches!(
            validate_receipt(&receipt, WRONG_KEY, test_epoch()),
            Err(ProofSchemaError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn validate_receipt_wrong_epoch() {
        let receipt = test_receipt();
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, SecurityEpoch::from_raw(99)),
            Err(ProofSchemaError::EpochMismatch { .. })
        ));
    }

    #[test]
    fn validate_receipt_incompatible_version() {
        let mut receipt = test_receipt_unsigned();
        receipt.schema_version = SchemaVersion {
            major: 99,
            minor: 0,
        };
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn validate_receipt_missing_optimization_id() {
        let mut receipt = test_receipt_unsigned();
        receipt.optimization_id = String::new();
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    #[test]
    fn validate_receipt_missing_rollback_token_id() {
        let mut receipt = test_receipt_unsigned();
        receipt.rollback_token_id = String::new();
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    #[test]
    fn validate_receipt_missing_correlation_id() {
        let mut receipt = test_receipt_unsigned();
        receipt.correlation_id = String::new();
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    // -- Token validation --

    #[test]
    fn validate_token_success() {
        let token = test_rollback();
        assert!(validate_rollback_token(&token, TEST_KEY, test_epoch()).is_ok());
    }

    #[test]
    fn validate_token_wrong_key() {
        let token = test_rollback();
        assert!(matches!(
            validate_rollback_token(&token, WRONG_KEY, test_epoch()),
            Err(ProofSchemaError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn validate_token_expired() {
        let token = test_rollback();
        assert!(matches!(
            validate_rollback_token(&token, TEST_KEY, SecurityEpoch::from_raw(11)),
            Err(ProofSchemaError::TokenExpired { .. })
        ));
    }

    #[test]
    fn validate_token_incompatible_version() {
        let mut token = test_rollback_unsigned();
        token.schema_version = SchemaVersion {
            major: 99,
            minor: 0,
        };
        let token = token.sign(TEST_KEY);
        assert!(matches!(
            validate_rollback_token(&token, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn validate_token_missing_token_id() {
        let mut token = test_rollback_unsigned();
        token.token_id = String::new();
        let token = token.sign(TEST_KEY);
        assert!(matches!(
            validate_rollback_token(&token, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    // -- Signer authorization --

    #[test]
    fn optimizer_authorized_for_receipt() {
        assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "OptReceipt").is_ok());
    }

    #[test]
    fn policy_plane_not_authorized_for_receipt() {
        assert!(matches!(
            check_signer_authorization(SignerRole::PolicyPlane, "OptReceipt"),
            Err(ProofSchemaError::UnauthorizedSigner { .. })
        ));
    }

    #[test]
    fn policy_plane_authorized_for_rollback_token() {
        assert!(check_signer_authorization(SignerRole::PolicyPlane, "RollbackToken").is_ok());
    }

    #[test]
    fn attestation_cell_not_authorized_for_receipt() {
        assert!(matches!(
            check_signer_authorization(SignerRole::AttestationCell, "OptReceipt"),
            Err(ProofSchemaError::UnauthorizedSigner { .. })
        ));
    }

    // -- Object IDs --

    #[test]
    fn receipt_object_id_is_deterministic() {
        let r1 = test_receipt();
        let r2 = test_receipt();
        assert_eq!(
            r1.object_id("zone-a").unwrap(),
            r2.object_id("zone-a").unwrap()
        );
    }

    #[test]
    fn receipt_object_id_differs_by_zone() {
        let receipt = test_receipt();
        assert_ne!(
            receipt.object_id("zone-a").unwrap(),
            receipt.object_id("zone-b").unwrap()
        );
    }

    #[test]
    fn rollback_object_id_is_deterministic() {
        let t1 = test_rollback();
        let t2 = test_rollback();
        assert_eq!(
            t1.object_id("zone-a").unwrap(),
            t2.object_id("zone-a").unwrap()
        );
    }

    // -- Serialization --

    #[test]
    fn receipt_serialization_round_trip() {
        let receipt = test_receipt();
        let json = serde_json::to_string(&receipt).expect("serialize");
        let restored: OptReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, restored);
    }

    #[test]
    fn rollback_serialization_round_trip() {
        let token = test_rollback();
        let json = serde_json::to_string(&token).expect("serialize");
        let restored: RollbackToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(token, restored);
    }

    #[test]
    fn invariance_digest_serialization_round_trip() {
        let digest = test_invariance_digest();
        let json = serde_json::to_string(&digest).expect("serialize");
        let restored: InvarianceDigest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(digest, restored);
    }

    #[test]
    fn proof_schema_error_serialization_round_trip() {
        let errors = vec![
            ProofSchemaError::InvalidSignature {
                artifact: "OptReceipt".to_string(),
            },
            ProofSchemaError::TokenExpired {
                token_id: "rtk-1".to_string(),
                expiry_epoch: 10,
                current_epoch: 11,
            },
            ProofSchemaError::MissingField {
                field: "optimization_id".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ProofSchemaError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Error display --

    #[test]
    fn error_display_messages() {
        assert!(
            ProofSchemaError::InvalidSignature {
                artifact: "test".to_string()
            }
            .to_string()
            .contains("test")
        );
        assert!(
            ProofSchemaError::TokenExpired {
                token_id: "rtk-1".to_string(),
                expiry_epoch: 5,
                current_epoch: 6,
            }
            .to_string()
            .contains("rtk-1")
        );
    }

    // -- Display traits --

    #[test]
    fn optimization_class_display() {
        assert_eq!(
            OptimizationClass::Superinstruction.to_string(),
            "superinstruction"
        );
        assert_eq!(
            OptimizationClass::DevirtualizedHostcallFastPath.to_string(),
            "devirtualized_hostcall_fast_path"
        );
    }

    #[test]
    fn activation_stage_display() {
        assert_eq!(ActivationStage::Shadow.to_string(), "shadow");
        assert_eq!(ActivationStage::Default.to_string(), "default");
    }

    #[test]
    fn signer_role_display() {
        assert_eq!(
            SignerRole::OptimizerSubsystem.to_string(),
            "optimizer_subsystem"
        );
    }
}
