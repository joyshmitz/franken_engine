//! PolicyCheckpoint: quorum-signed chain element anchoring the canonical
//! root of enforceable policy state.
//!
//! Each checkpoint contains:
//! - Back-pointer to the previous checkpoint (`prev_checkpoint`).
//! - Monotonically increasing sequence number (`checkpoint_seq`).
//! - Epoch identifier (`epoch_id`).
//! - References to current active policy versions (`policy_heads`).
//! - Quorum of signatures from authorized checkpoint signers.
//! - Content-addressed `checkpoint_id` via EngineObjectId derivation.
//!
//! Invariants:
//! - Genesis checkpoint has `prev_checkpoint = None`, `checkpoint_seq = 0`.
//! - Chain linkage: each checkpoint references the immediately preceding one.
//! - Monotonicity: `checkpoint_seq` is strictly greater than predecessor's.
//! - Immutability: checkpoints are sealed after creation and signing.
//!
//! Plan references: Section 10.10 item 6, 9E.3 (checkpointed policy
//! frontier with rollback/fork protection).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, SignaturePreimage, SigningKey, VerificationKey,
};
use crate::sorted_multisig::{SignerSignature, SortedSignatureArray};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Schema definition for PolicyCheckpoint objects.
const CHECKPOINT_SCHEMA_DEF: &[u8] = b"FrankenEngine.PolicyCheckpoint.v1";

/// Derive the schema hash for checkpoints.
pub fn checkpoint_schema() -> SchemaHash {
    SchemaHash::from_definition(CHECKPOINT_SCHEMA_DEF)
}

/// Derive the schema ID for checkpoints.
pub fn checkpoint_schema_id() -> SchemaId {
    SchemaId::from_definition(CHECKPOINT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// PolicyType / PolicyHead
// ---------------------------------------------------------------------------

/// Type of policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicyType {
    /// Runtime execution policy.
    RuntimeExecution,
    /// Capability lattice policy.
    CapabilityLattice,
    /// Extension trust policy.
    ExtensionTrust,
    /// Evidence retention policy.
    EvidenceRetention,
    /// Revocation governance policy.
    RevocationGovernance,
}

impl fmt::Display for PolicyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeExecution => write!(f, "runtime_execution"),
            Self::CapabilityLattice => write!(f, "capability_lattice"),
            Self::ExtensionTrust => write!(f, "extension_trust"),
            Self::EvidenceRetention => write!(f, "evidence_retention"),
            Self::RevocationGovernance => write!(f, "revocation_governance"),
        }
    }
}

/// A content-addressed reference to an active policy version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyHead {
    /// The type of policy.
    pub policy_type: PolicyType,
    /// Content hash of the policy document.
    pub policy_hash: ContentHash,
    /// Monotonic policy version.
    pub policy_version: u64,
}

// ---------------------------------------------------------------------------
// DeterministicTimestamp
// ---------------------------------------------------------------------------

/// Deterministic timestamp as monotonic tick count.
///
/// Not wall-clock time — a logical tick from a deterministic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeterministicTimestamp(pub u64);

impl fmt::Display for DeterministicTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tick:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// CheckpointError
// ---------------------------------------------------------------------------

/// Errors from checkpoint operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointError {
    /// Genesis checkpoint must have no predecessor.
    GenesisMustHaveNoPredecessor,
    /// Non-genesis checkpoint must have a predecessor.
    MissingPredecessor,
    /// Sequence number is not strictly monotonic.
    NonMonotonicSequence { prev_seq: u64, current_seq: u64 },
    /// Genesis checkpoint must have sequence 0.
    GenesisSequenceNotZero { actual: u64 },
    /// Chain linkage error: prev_checkpoint doesn't match.
    ChainLinkageBroken {
        expected: EngineObjectId,
        actual: EngineObjectId,
    },
    /// Policy heads list is empty.
    EmptyPolicyHeads,
    /// Quorum threshold not met.
    QuorumNotMet { required: usize, provided: usize },
    /// Duplicate policy type in heads.
    DuplicatePolicyType { policy_type: PolicyType },
    /// ID derivation failed.
    IdDerivationFailed { detail: String },
    /// Signature or multi-sig construction error.
    SignatureInvalid { detail: String },
    /// Epoch regression: epoch must not decrease.
    EpochRegression {
        prev_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenesisMustHaveNoPredecessor => {
                write!(f, "genesis checkpoint must have no predecessor")
            }
            Self::MissingPredecessor => {
                write!(f, "non-genesis checkpoint must have a predecessor")
            }
            Self::NonMonotonicSequence {
                prev_seq,
                current_seq,
            } => write!(
                f,
                "non-monotonic sequence: prev={prev_seq}, current={current_seq}"
            ),
            Self::GenesisSequenceNotZero { actual } => {
                write!(f, "genesis sequence must be 0, got {actual}")
            }
            Self::ChainLinkageBroken { expected, actual } => {
                write!(f, "chain linkage: expected {expected}, got {actual}")
            }
            Self::EmptyPolicyHeads => write!(f, "policy heads must not be empty"),
            Self::QuorumNotMet { required, provided } => {
                write!(f, "quorum not met: {provided}/{required}")
            }
            Self::DuplicatePolicyType { policy_type } => {
                write!(f, "duplicate policy type: {policy_type}")
            }
            Self::IdDerivationFailed { detail } => {
                write!(f, "ID derivation failed: {detail}")
            }
            Self::SignatureInvalid { detail } => {
                write!(f, "signature invalid: {detail}")
            }
            Self::EpochRegression {
                prev_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch regression: prev={prev_epoch}, current={current_epoch}"
            ),
        }
    }
}

impl std::error::Error for CheckpointError {}

// ---------------------------------------------------------------------------
// PolicyCheckpoint
// ---------------------------------------------------------------------------

/// A quorum-signed checkpoint anchoring policy state.
///
/// Immutable after creation. The `checkpoint_id` is derived from the
/// unsigned view of all fields via EngineObjectId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckpoint {
    /// Content-addressed checkpoint ID.
    pub checkpoint_id: EngineObjectId,
    /// Back-pointer to the previous checkpoint (None for genesis).
    pub prev_checkpoint: Option<EngineObjectId>,
    /// Strictly monotonic sequence number (0 for genesis).
    pub checkpoint_seq: u64,
    /// The security epoch for this checkpoint.
    pub epoch_id: SecurityEpoch,
    /// Active policy versions (sorted by policy type).
    pub policy_heads: Vec<PolicyHead>,
    /// Quorum signatures (sorted by signer key).
    pub quorum_signatures: SortedSignatureArray,
    /// Creation timestamp (deterministic tick).
    pub created_at: DeterministicTimestamp,
}

impl SignaturePreimage for PolicyCheckpoint {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::CheckpointArtifact
    }

    fn signature_schema(&self) -> &SchemaHash {
        // Return a lazily-computed schema. Since we need a reference,
        // we use a thread-local or compute in-place via a helper.
        // For simplicity, use a leaked Box (safe, small, one-time).
        // Actually, use a function-level static approach is not available
        // without lazy_static. Instead, provide the preimage directly.
        //
        // This is a workaround: we override preimage_bytes() instead.
        unreachable!("use preimage_bytes() directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        build_unsigned_view(
            &self.prev_checkpoint,
            self.checkpoint_seq,
            self.epoch_id,
            &self.policy_heads,
            self.created_at,
        )
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let schema = checkpoint_schema();
        let domain_tag = ObjectDomain::CheckpointArtifact.tag();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// ---------------------------------------------------------------------------
// Unsigned view construction
// ---------------------------------------------------------------------------

fn build_unsigned_view(
    prev_checkpoint: &Option<EngineObjectId>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
    policy_heads: &[PolicyHead],
    created_at: DeterministicTimestamp,
) -> CanonicalValue {
    let mut map = BTreeMap::new();

    // checkpoint_seq
    map.insert(
        "checkpoint_seq".to_string(),
        CanonicalValue::U64(checkpoint_seq),
    );

    // created_at
    map.insert("created_at".to_string(), CanonicalValue::U64(created_at.0));

    // epoch_id
    map.insert(
        "epoch_id".to_string(),
        CanonicalValue::U64(epoch_id.as_u64()),
    );

    // policy_heads (sorted by policy type display name for determinism)
    let heads_array: Vec<CanonicalValue> = policy_heads
        .iter()
        .map(|h| {
            let mut head_map = BTreeMap::new();
            head_map.insert(
                "policy_hash".to_string(),
                CanonicalValue::Bytes(h.policy_hash.as_bytes().to_vec()),
            );
            head_map.insert(
                "policy_type".to_string(),
                CanonicalValue::String(h.policy_type.to_string()),
            );
            head_map.insert(
                "policy_version".to_string(),
                CanonicalValue::U64(h.policy_version),
            );
            CanonicalValue::Map(head_map)
        })
        .collect();
    map.insert(
        "policy_heads".to_string(),
        CanonicalValue::Array(heads_array),
    );

    // prev_checkpoint
    match prev_checkpoint {
        Some(id) => {
            map.insert(
                "prev_checkpoint".to_string(),
                CanonicalValue::Bytes(id.as_bytes().to_vec()),
            );
        }
        None => {
            map.insert("prev_checkpoint".to_string(), CanonicalValue::Null);
        }
    }

    // quorum_signatures sentinel (zeroed in unsigned view)
    map.insert(
        "quorum_signatures".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );

    CanonicalValue::Map(map)
}

// ---------------------------------------------------------------------------
// CheckpointBuilder
// ---------------------------------------------------------------------------

/// Builder for creating PolicyCheckpoint objects.
pub struct CheckpointBuilder {
    prev_checkpoint: Option<EngineObjectId>,
    prev_seq: Option<u64>,
    prev_epoch: Option<SecurityEpoch>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
    policy_heads: Vec<PolicyHead>,
    created_at: DeterministicTimestamp,
    zone: String,
}

impl CheckpointBuilder {
    /// Start building a genesis checkpoint.
    pub fn genesis(
        epoch_id: SecurityEpoch,
        created_at: DeterministicTimestamp,
        zone: &str,
    ) -> Self {
        Self {
            prev_checkpoint: None,
            prev_seq: None,
            prev_epoch: None,
            checkpoint_seq: 0,
            epoch_id,
            policy_heads: Vec::new(),
            created_at,
            zone: zone.to_string(),
        }
    }

    /// Start building a checkpoint that chains to a predecessor.
    pub fn after(
        prev: &PolicyCheckpoint,
        checkpoint_seq: u64,
        epoch_id: SecurityEpoch,
        created_at: DeterministicTimestamp,
        zone: &str,
    ) -> Self {
        Self {
            prev_checkpoint: Some(prev.checkpoint_id.clone()),
            prev_seq: Some(prev.checkpoint_seq),
            prev_epoch: Some(prev.epoch_id),
            checkpoint_seq,
            epoch_id,
            policy_heads: Vec::new(),
            created_at,
            zone: zone.to_string(),
        }
    }

    /// Add a policy head.
    pub fn add_policy_head(mut self, head: PolicyHead) -> Self {
        self.policy_heads.push(head);
        self
    }

    /// Build and sign the checkpoint.
    ///
    /// Each signing key produces a signature on the same preimage.
    pub fn build(
        mut self,
        signing_keys: &[SigningKey],
    ) -> Result<PolicyCheckpoint, CheckpointError> {
        // Validate.
        self.validate()?;

        // Sort policy heads by type for determinism.
        self.policy_heads
            .sort_by(|a, b| a.policy_type.cmp(&b.policy_type));

        // Derive checkpoint_id from unsigned view.
        let unsigned_view = build_unsigned_view(
            &self.prev_checkpoint,
            self.checkpoint_seq,
            self.epoch_id,
            &self.policy_heads,
            self.created_at,
        );
        let canonical_bytes = deterministic_serde::encode_value(&unsigned_view);
        let schema_id = checkpoint_schema_id();

        let checkpoint_id = engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            &self.zone,
            &schema_id,
            &canonical_bytes,
        )
        .map_err(|e| CheckpointError::IdDerivationFailed {
            detail: e.to_string(),
        })?;

        // Compute preimage for signing.
        let schema = checkpoint_schema();
        let domain_tag = ObjectDomain::CheckpointArtifact.tag();
        let value_bytes = deterministic_serde::encode_value(&unsigned_view);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);

        // Sign with each key.
        let mut entries = Vec::with_capacity(signing_keys.len());
        for sk in signing_keys {
            let vk = sk.verification_key();
            let sig = crate::signature_preimage::sign_preimage(sk, &preimage).map_err(|e| {
                CheckpointError::SignatureInvalid {
                    detail: format!("signing failed: {e}"),
                }
            })?;
            entries.push(SignerSignature::new(vk, sig));
        }

        let quorum_signatures = SortedSignatureArray::from_unsorted(entries).map_err(|e| {
            CheckpointError::SignatureInvalid {
                detail: format!("multi-sig construction failed: {e}"),
            }
        })?;

        Ok(PolicyCheckpoint {
            checkpoint_id,
            prev_checkpoint: self.prev_checkpoint,
            checkpoint_seq: self.checkpoint_seq,
            epoch_id: self.epoch_id,
            policy_heads: self.policy_heads,
            quorum_signatures,
            created_at: self.created_at,
        })
    }

    fn validate(&self) -> Result<(), CheckpointError> {
        // Genesis validation.
        if self.prev_checkpoint.is_none() {
            if self.checkpoint_seq != 0 {
                return Err(CheckpointError::GenesisSequenceNotZero {
                    actual: self.checkpoint_seq,
                });
            }
        } else {
            // Non-genesis must have strictly increasing sequence.
            if let Some(prev_seq) = self.prev_seq
                && self.checkpoint_seq <= prev_seq
            {
                return Err(CheckpointError::NonMonotonicSequence {
                    prev_seq,
                    current_seq: self.checkpoint_seq,
                });
            }

            // Epoch must not regress.
            if let Some(prev_epoch) = self.prev_epoch
                && self.epoch_id < prev_epoch
            {
                return Err(CheckpointError::EpochRegression {
                    prev_epoch,
                    current_epoch: self.epoch_id,
                });
            }
        }

        // Must have at least one policy head.
        if self.policy_heads.is_empty() {
            return Err(CheckpointError::EmptyPolicyHeads);
        }

        // No duplicate policy types.
        let mut seen = std::collections::BTreeSet::new();
        for head in &self.policy_heads {
            if !seen.insert(head.policy_type.to_string()) {
                return Err(CheckpointError::DuplicatePolicyType {
                    policy_type: head.policy_type.clone(),
                });
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/// Verify that a checkpoint properly chains to its predecessor.
pub fn verify_chain_linkage(
    prev: &PolicyCheckpoint,
    current: &PolicyCheckpoint,
) -> Result<(), CheckpointError> {
    // Current must reference prev.
    match &current.prev_checkpoint {
        None => return Err(CheckpointError::MissingPredecessor),
        Some(prev_id) => {
            if *prev_id != prev.checkpoint_id {
                return Err(CheckpointError::ChainLinkageBroken {
                    expected: prev.checkpoint_id.clone(),
                    actual: prev_id.clone(),
                });
            }
        }
    }

    // Monotonic sequence.
    if current.checkpoint_seq <= prev.checkpoint_seq {
        return Err(CheckpointError::NonMonotonicSequence {
            prev_seq: prev.checkpoint_seq,
            current_seq: current.checkpoint_seq,
        });
    }

    // Epoch must not regress.
    if current.epoch_id < prev.epoch_id {
        return Err(CheckpointError::EpochRegression {
            prev_epoch: prev.epoch_id,
            current_epoch: current.epoch_id,
        });
    }

    Ok(())
}

/// Verify a checkpoint's quorum against authorized signers.
pub fn verify_checkpoint_quorum(
    checkpoint: &PolicyCheckpoint,
    quorum_threshold: usize,
    authorized_signers: &[VerificationKey],
) -> Result<(), CheckpointError> {
    let preimage = checkpoint.preimage_bytes();

    let result = checkpoint.quorum_signatures.verify_quorum(
        quorum_threshold,
        authorized_signers,
        |vk, sig| crate::signature_preimage::verify_signature(vk, &preimage, sig),
    );

    match result {
        Ok(_) => Ok(()),
        Err(crate::sorted_multisig::MultiSigError::QuorumNotMet {
            required, valid, ..
        }) => Err(CheckpointError::QuorumNotMet {
            required,
            provided: valid,
        }),
        Err(e) => Err(CheckpointError::SignatureInvalid {
            detail: format!("quorum verification error: {e}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Events from checkpoint operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointEvent {
    pub event_type: CheckpointEventType,
    pub checkpoint_seq: u64,
    pub trace_id: String,
}

/// Types of checkpoint events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointEventType {
    /// Genesis checkpoint created.
    GenesisCreated,
    /// Chain checkpoint created.
    ChainCheckpointCreated { prev_seq: u64 },
    /// Quorum verified.
    QuorumVerified { valid: usize, threshold: usize },
    /// Chain linkage verified.
    ChainLinkageVerified,
    /// Epoch transition detected.
    EpochTransition {
        from: SecurityEpoch,
        to: SecurityEpoch,
    },
}

impl fmt::Display for CheckpointEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenesisCreated => write!(f, "genesis_created"),
            Self::ChainCheckpointCreated { prev_seq } => {
                write!(f, "chain_created(prev_seq={prev_seq})")
            }
            Self::QuorumVerified { valid, threshold } => {
                write!(f, "quorum_verified({valid}/{threshold})")
            }
            Self::ChainLinkageVerified => write!(f, "chain_linkage_verified"),
            Self::EpochTransition { from, to } => {
                write!(f, "epoch_transition({from}->{to})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::SigningKey;

    fn make_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn make_policy_head(pt: PolicyType, version: u64) -> PolicyHead {
        let hash_input = format!("{pt}-v{version}");
        PolicyHead {
            policy_type: pt,
            policy_hash: ContentHash::compute(hash_input.as_bytes()),
            policy_version: version,
        }
    }

    fn build_genesis(keys: &[SigningKey]) -> PolicyCheckpoint {
        CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(keys)
        .unwrap()
    }

    // -- Genesis creation --

    #[test]
    fn genesis_checkpoint_created() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);

        assert_eq!(cp.checkpoint_seq, 0);
        assert!(cp.prev_checkpoint.is_none());
        assert_eq!(cp.epoch_id, SecurityEpoch::GENESIS);
        assert_eq!(cp.policy_heads.len(), 1);
        assert_eq!(cp.quorum_signatures.len(), 1);
    }

    #[test]
    fn genesis_id_is_deterministic() {
        let sk = make_sk(1);
        let cp1 = build_genesis(std::slice::from_ref(&sk));
        let cp2 = build_genesis(&[sk]);
        assert_eq!(cp1.checkpoint_id, cp2.checkpoint_id);
    }

    #[test]
    fn genesis_with_multiple_signers() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let sk3 = make_sk(3);
        let cp = build_genesis(&[sk1, sk2, sk3]);
        assert_eq!(cp.quorum_signatures.len(), 3);
    }

    // -- Chain creation --

    #[test]
    fn chain_checkpoint_created() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp1.checkpoint_seq, 1);
        assert_eq!(cp1.prev_checkpoint, Some(genesis.checkpoint_id));
        assert_eq!(cp1.policy_heads[0].policy_version, 2);
    }

    #[test]
    fn three_link_chain() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::after(
            &cp1,
            2,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(300),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp2.checkpoint_seq, 2);
        assert_eq!(cp2.prev_checkpoint, Some(cp1.checkpoint_id));
    }

    // -- Monotonicity enforcement --

    #[test]
    fn non_monotonic_sequence_rejected() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let err = CheckpointBuilder::after(
            &genesis,
            0, // same as genesis
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::NonMonotonicSequence { .. }));
    }

    #[test]
    fn genesis_non_zero_seq_rejected() {
        let sk = make_sk(1);
        let mut builder = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        );
        builder.checkpoint_seq = 5; // wrong
        builder
            .policy_heads
            .push(make_policy_head(PolicyType::RuntimeExecution, 1));

        let err = builder.build(&[sk]).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::GenesisSequenceNotZero { actual: 5 }
        ));
    }

    // -- Empty policy heads --

    #[test]
    fn empty_policy_heads_rejected() {
        let sk = make_sk(1);
        let err = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::EmptyPolicyHeads));
    }

    // -- Duplicate policy types --

    #[test]
    fn duplicate_policy_type_rejected() {
        let sk = make_sk(1);
        let err = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::DuplicatePolicyType { .. }));
    }

    // -- Epoch handling --

    #[test]
    fn epoch_transition_allowed() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::from_raw(1), // epoch transition
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp1.epoch_id, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn epoch_regression_rejected() {
        let sk = make_sk(1);
        // Build genesis at epoch 5.
        let genesis = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(5),
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let err = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::from_raw(3), // regression
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::EpochRegression { .. }));
    }

    // -- Chain linkage verification --

    #[test]
    fn chain_linkage_verified() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
    }

    #[test]
    fn chain_linkage_broken_detected() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        // Build two independent chains from genesis.
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::after(
            &genesis,
            2,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(300),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
        .build(&[sk])
        .unwrap();

        // cp2 chains to genesis, not to cp1.
        let err = verify_chain_linkage(&cp1, &cp2).unwrap_err();
        assert!(matches!(err, CheckpointError::ChainLinkageBroken { .. }));
    }

    // -- Quorum verification --

    #[test]
    fn quorum_verification_succeeds() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let vk1 = sk1.verification_key();
        let vk2 = sk2.verification_key();
        let cp = build_genesis(&[sk1, sk2]);

        assert!(verify_checkpoint_quorum(&cp, 2, &[vk1, vk2]).is_ok());
    }

    #[test]
    fn quorum_verification_threshold_1() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let vk1 = sk1.verification_key();
        let vk2 = sk2.verification_key();
        let cp = build_genesis(&[sk1, sk2]);

        assert!(verify_checkpoint_quorum(&cp, 1, &[vk1, vk2]).is_ok());
    }

    #[test]
    fn quorum_fails_with_wrong_keys() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
        let cp = build_genesis(&[sk1, sk2]);

        let err = verify_checkpoint_quorum(&cp, 2, &[wrong_vk]).unwrap_err();
        assert!(matches!(err, CheckpointError::QuorumNotMet { .. }));
    }

    // -- Multiple policy heads --

    #[test]
    fn multiple_policy_heads() {
        let sk = make_sk(1);
        let cp = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
        .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 1))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp.policy_heads.len(), 3);
        // Should be sorted by policy type.
        assert!(cp.policy_heads[0].policy_type <= cp.policy_heads[1].policy_type);
        assert!(cp.policy_heads[1].policy_type <= cp.policy_heads[2].policy_type);
    }

    // -- Preimage stability --

    #[test]
    fn preimage_is_deterministic() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let p1 = cp.preimage_bytes();
        let p2 = cp.preimage_bytes();
        assert_eq!(p1, p2);
    }

    #[test]
    fn same_inputs_same_preimage() {
        let sk = make_sk(1);
        let cp1 = build_genesis(std::slice::from_ref(&sk));
        let cp2 = build_genesis(&[sk]);
        assert_eq!(cp1.preimage_bytes(), cp2.preimage_bytes());
    }

    // -- Serialization --

    #[test]
    fn checkpoint_serialization_round_trip() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let json = serde_json::to_string(&cp).expect("serialize");
        let restored: PolicyCheckpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cp, restored);
    }

    #[test]
    fn policy_head_serialization_round_trip() {
        let head = make_policy_head(PolicyType::RuntimeExecution, 5);
        let json = serde_json::to_string(&head).expect("serialize");
        let restored: PolicyHead = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(head, restored);
    }

    #[test]
    fn policy_type_serialization_round_trip() {
        let types = vec![
            PolicyType::RuntimeExecution,
            PolicyType::CapabilityLattice,
            PolicyType::ExtensionTrust,
            PolicyType::EvidenceRetention,
            PolicyType::RevocationGovernance,
        ];
        for pt in &types {
            let json = serde_json::to_string(pt).expect("serialize");
            let restored: PolicyType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*pt, restored);
        }
    }

    #[test]
    fn checkpoint_error_serialization_round_trip() {
        let errors = vec![
            CheckpointError::GenesisMustHaveNoPredecessor,
            CheckpointError::MissingPredecessor,
            CheckpointError::EmptyPolicyHeads,
            CheckpointError::GenesisSequenceNotZero { actual: 5 },
            CheckpointError::NonMonotonicSequence {
                prev_seq: 3,
                current_seq: 2,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: CheckpointError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn checkpoint_error_display() {
        let err = CheckpointError::NonMonotonicSequence {
            prev_seq: 5,
            current_seq: 3,
        };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("3"));
    }

    #[test]
    fn policy_type_display() {
        assert_eq!(
            PolicyType::RuntimeExecution.to_string(),
            "runtime_execution"
        );
        assert_eq!(
            PolicyType::CapabilityLattice.to_string(),
            "capability_lattice"
        );
    }

    #[test]
    fn timestamp_display() {
        assert_eq!(DeterministicTimestamp(42).to_string(), "tick:42");
    }

    #[test]
    fn checkpoint_event_type_display() {
        assert_eq!(
            CheckpointEventType::GenesisCreated.to_string(),
            "genesis_created"
        );
        assert!(
            CheckpointEventType::ChainCheckpointCreated { prev_seq: 1 }
                .to_string()
                .contains("1")
        );
    }

    // -- Event serialization --

    #[test]
    fn checkpoint_event_serialization_round_trip() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::GenesisCreated,
            checkpoint_seq: 0,
            trace_id: "t-event".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: CheckpointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }
}
