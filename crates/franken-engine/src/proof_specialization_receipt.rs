//! Specialization receipt schema linking security-proof inputs to activated
//! optimization classes and rollback lineage.
//!
//! Every activated specialization emits a signed receipt that links the proof
//! inputs justifying the optimization, the transformation witness describing
//! code changes, equivalence evidence confirming semantic preservation, and a
//! rollback token enabling deterministic revert to unspecialized code.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//!
//! Plan reference: Section 10.15 item 9I.8 (Security-Proof-Guided
//! Specialization), bd-6qsi.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_object,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RECEIPT_SCHEMA_DEF: &[u8] = b"ProofSpecializationReceipt.v1";
const RECEIPT_ZONE: &str = "proof-specialization-receipt";

/// Fixed-point unit: 1_000_000 = 1.0.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// ReceiptSchemaVersion
// ---------------------------------------------------------------------------

/// Schema version for specialization receipts (major.minor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReceiptSchemaVersion {
    pub major: u32,
    pub minor: u32,
}

impl ReceiptSchemaVersion {
    /// Current schema version.
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// Compatible if same major and reader minor >= receipt minor.
    pub fn is_compatible_with(&self, receipt_version: &Self) -> bool {
        self.major == receipt_version.major && self.minor >= receipt_version.minor
    }
}

impl fmt::Display for ReceiptSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// ProofType — the type of security proof feeding a specialization
// ---------------------------------------------------------------------------

/// The type of security proof that justifies a specialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProofType {
    /// Capability witness from PLAS synthesis (bd-2w9w).
    CapabilityWitness,
    /// IFC flow proof from information flow control (bd-1ovk).
    FlowProof,
    /// Replay motif from deterministic replay infrastructure.
    ReplayMotif,
}

impl fmt::Display for ProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityWitness => f.write_str("capability_witness"),
            Self::FlowProof => f.write_str("flow_proof"),
            Self::ReplayMotif => f.write_str("replay_motif"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProofInput — a single security proof feeding the specialization
// ---------------------------------------------------------------------------

/// A single security-proof input that justifies a specialization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofInput {
    /// Kind of security proof.
    pub proof_type: ProofType,
    /// Content-addressable identifier of the proof artifact.
    pub proof_id: EngineObjectId,
    /// Epoch under which the proof was created.
    pub proof_epoch: SecurityEpoch,
    /// Validity window in ticks. Specialization invalidates after this.
    pub validity_window_ticks: u64,
}

// ---------------------------------------------------------------------------
// OptimizationClass — the kind of optimization activated
// ---------------------------------------------------------------------------

/// Classification of the optimization activated by a specialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OptimizationClass {
    /// Specialization of hostcall dispatch paths.
    HostcallDispatchSpecialization,
    /// Elision of IFC dynamic checks proven static.
    IfcCheckElision,
    /// Fusion of adjacent operations into superinstructions.
    SuperinstructionFusion,
    /// Elimination of provably-dead code paths.
    PathElimination,
}

impl fmt::Display for OptimizationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostcallDispatchSpecialization => f.write_str("hostcall_dispatch_specialization"),
            Self::IfcCheckElision => f.write_str("ifc_check_elision"),
            Self::SuperinstructionFusion => f.write_str("superinstruction_fusion"),
            Self::PathElimination => f.write_str("path_elimination"),
        }
    }
}

// ---------------------------------------------------------------------------
// TransformationWitness — before/after IR transformation evidence
// ---------------------------------------------------------------------------

/// Evidence describing the code transformation applied during specialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformationWitness {
    /// Human-readable description of the transformation.
    pub description: String,
    /// Content hash of the IR before transformation.
    pub before_ir_digest: ContentHash,
    /// Content hash of the IR after transformation.
    pub after_ir_digest: ContentHash,
}

impl TransformationWitness {
    /// Validate the witness has non-empty description and distinct digests.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.description.is_empty() {
            return Err(ReceiptError::EmptyTransformationDescription);
        }
        if self.before_ir_digest == self.after_ir_digest {
            return Err(ReceiptError::IdenticalIrDigests);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EquivalenceEvidence — proof that specialization preserves semantics
// ---------------------------------------------------------------------------

/// Evidence proving semantic equivalence between specialized and unspecialized
/// code paths under the proof constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceEvidence {
    /// Method used to establish equivalence.
    pub method: EquivalenceMethod,
    /// Content hashes of differential test results.
    pub differential_test_hashes: Vec<ContentHash>,
    /// Number of test inputs exercised.
    pub test_count: u64,
    /// Pass rate in millionths (1_000_000 = 100%).
    pub pass_rate_millionths: u64,
}

impl EquivalenceEvidence {
    /// Validate the evidence is well-formed.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.differential_test_hashes.is_empty() {
            return Err(ReceiptError::NoEquivalenceTests);
        }
        if self.test_count == 0 {
            return Err(ReceiptError::ZeroTestCount);
        }
        if self.pass_rate_millionths > MILLIONTHS {
            return Err(ReceiptError::PassRateOutOfRange {
                value: self.pass_rate_millionths,
            });
        }
        // Must be 100% pass rate for equivalence.
        if self.pass_rate_millionths != MILLIONTHS {
            return Err(ReceiptError::InsufficientPassRate {
                required: MILLIONTHS,
                actual: self.pass_rate_millionths,
            });
        }
        Ok(())
    }
}

/// Method used to establish semantic equivalence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EquivalenceMethod {
    /// Differential testing: run both paths on same inputs.
    DifferentialTesting,
    /// Translation validation: formal proof of equivalence.
    TranslationValidation,
    /// Bisimulation proof (behavioral equivalence).
    Bisimulation,
}

impl fmt::Display for EquivalenceMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifferentialTesting => f.write_str("differential_testing"),
            Self::TranslationValidation => f.write_str("translation_validation"),
            Self::Bisimulation => f.write_str("bisimulation"),
        }
    }
}

// ---------------------------------------------------------------------------
// RollbackToken — deterministic rollback to unspecialized code
// ---------------------------------------------------------------------------

/// Artifact enabling deterministic rollback to unspecialized code path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackToken {
    /// Content hash of the unspecialized baseline code.
    pub baseline_hash: ContentHash,
    /// Content hash of the rollback procedure.
    pub rollback_procedure_hash: ContentHash,
    /// Whether rollback has been validated (dry-run tested).
    pub validated: bool,
}

// ---------------------------------------------------------------------------
// PerformanceDelta — measured improvement from specialization
// ---------------------------------------------------------------------------

/// Measured performance improvement from a specialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceDelta {
    /// Latency reduction in millionths (e.g. 500_000 = 50% reduction).
    pub latency_reduction_millionths: u64,
    /// Throughput increase in millionths (e.g. 200_000 = 20% increase).
    pub throughput_increase_millionths: u64,
    /// Number of benchmark samples used.
    pub sample_count: u64,
}

impl PerformanceDelta {
    /// Validate the delta values are within range.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.sample_count == 0 {
            return Err(ReceiptError::ZeroBenchmarkSamples);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReceiptError
// ---------------------------------------------------------------------------

/// Errors from the specialization receipt subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptError {
    /// No proof inputs provided.
    EmptyProofInputs,
    /// Transformation witness description is empty.
    EmptyTransformationDescription,
    /// Before and after IR digests are identical (no transformation occurred).
    IdenticalIrDigests,
    /// No equivalence test results provided.
    NoEquivalenceTests,
    /// Zero test count in equivalence evidence.
    ZeroTestCount,
    /// Pass rate exceeds maximum (> 1_000_000).
    PassRateOutOfRange { value: u64 },
    /// Equivalence pass rate below 100%.
    InsufficientPassRate { required: u64, actual: u64 },
    /// Zero benchmark samples in performance delta.
    ZeroBenchmarkSamples,
    /// Rollback token not validated.
    UnvalidatedRollback,
    /// Epoch mismatch between receipt and proof input.
    EpochMismatch {
        receipt_epoch: u64,
        proof_epoch: u64,
    },
    /// Proof input validity window expired.
    ProofExpired { proof_id: String, window_ticks: u64 },
    /// Receipt ID derivation error.
    IdDerivation(String),
    /// Signature verification failed.
    SignatureInvalid { detail: String },
    /// Content hash integrity failure.
    IntegrityFailure { expected: String, actual: String },
    /// Schema version incompatibility.
    IncompatibleSchema {
        receipt: ReceiptSchemaVersion,
        reader: ReceiptSchemaVersion,
    },
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProofInputs => f.write_str("proof_inputs must not be empty"),
            Self::EmptyTransformationDescription => {
                f.write_str("transformation_witness description is empty")
            }
            Self::IdenticalIrDigests => f.write_str("before and after IR digests are identical"),
            Self::NoEquivalenceTests => {
                f.write_str("equivalence_evidence has no differential test hashes")
            }
            Self::ZeroTestCount => f.write_str("equivalence_evidence test_count is zero"),
            Self::PassRateOutOfRange { value } => {
                write!(
                    f,
                    "pass_rate_millionths {value} exceeds maximum {MILLIONTHS}"
                )
            }
            Self::InsufficientPassRate { required, actual } => {
                write!(f, "pass_rate {actual} below required {required}")
            }
            Self::ZeroBenchmarkSamples => f.write_str("performance_delta sample_count is zero"),
            Self::UnvalidatedRollback => f.write_str("rollback_token has not been validated"),
            Self::EpochMismatch {
                receipt_epoch,
                proof_epoch,
            } => write!(
                f,
                "epoch mismatch: receipt={receipt_epoch}, proof={proof_epoch}"
            ),
            Self::ProofExpired {
                proof_id,
                window_ticks,
            } => write!(f, "proof {proof_id} expired (window={window_ticks})"),
            Self::IdDerivation(msg) => write!(f, "ID derivation error: {msg}"),
            Self::SignatureInvalid { detail } => {
                write!(f, "signature invalid: {detail}")
            }
            Self::IntegrityFailure { expected, actual } => {
                write!(
                    f,
                    "content hash mismatch: expected={expected}, actual={actual}"
                )
            }
            Self::IncompatibleSchema { receipt, reader } => {
                write!(f, "schema incompatible: receipt={receipt}, reader={reader}")
            }
        }
    }
}

impl std::error::Error for ReceiptError {}

// ---------------------------------------------------------------------------
// SpecializationReceipt — the main artifact
// ---------------------------------------------------------------------------

/// A signed, content-addressed specialization receipt linking security-proof
/// inputs to an activated optimization with rollback lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationReceipt {
    /// Content-addressable receipt identifier.
    pub receipt_id: EngineObjectId,
    /// Schema version.
    pub schema_version: ReceiptSchemaVersion,

    // -- Proof inputs --
    /// Security proofs justifying this specialization (non-empty).
    pub proof_inputs: Vec<ProofInput>,

    // -- Optimization --
    /// Class of optimization activated.
    pub optimization_class: OptimizationClass,

    // -- Transformation --
    /// Evidence of the code transformation applied.
    pub transformation_witness: TransformationWitness,

    // -- Equivalence --
    /// Proof that specialization preserves semantics.
    pub equivalence_evidence: EquivalenceEvidence,

    // -- Rollback --
    /// Token for deterministic rollback to unspecialized code.
    pub rollback_token: RollbackToken,

    // -- Validity --
    /// Epoch under which this specialization is valid.
    pub validity_epoch: SecurityEpoch,

    /// Reference to the unspecialized baseline code path.
    pub fallback_path: String,

    // -- Performance --
    /// Measured performance improvement from this specialization.
    pub performance_delta: PerformanceDelta,

    // -- Temporal --
    /// Timestamp in nanoseconds (monotonic).
    pub timestamp_ns: u64,

    // -- Signature --
    /// Signature over canonical receipt bytes.
    pub signature: Signature,

    // -- Metadata --
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

fn receipt_schema() -> &'static SchemaHash {
    use std::sync::LazyLock;
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(RECEIPT_SCHEMA_DEF));
    &HASH
}

fn receipt_schema_id() -> &'static SchemaId {
    use std::sync::LazyLock;
    static SID: LazyLock<SchemaId> =
        LazyLock::new(|| SchemaId::from_definition(RECEIPT_SCHEMA_DEF));
    &SID
}

impl SignaturePreimage for SpecializationReceipt {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        receipt_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(serde_json::to_vec(&copy).unwrap_or_default())
    }
}

impl SpecializationReceipt {
    /// Compute content-addressable identity from canonical bytes.
    pub fn content_hash(&self) -> ContentHash {
        let bytes = self.preimage_bytes();
        ContentHash::compute(&bytes)
    }

    /// Sign this receipt with the given key.
    pub fn sign(
        &mut self,
        key: &SigningKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        self.signature = sign_object(self, key)?;
        Ok(())
    }

    /// Verify the signature on this receipt.
    pub fn verify(
        &self,
        key: &VerificationKey,
    ) -> Result<(), crate::signature_preimage::SignatureError> {
        let preimage = self.preimage_bytes();
        verify_signature(key, &preimage, &self.signature)
    }

    /// Validate all receipt fields for well-formedness.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.proof_inputs.is_empty() {
            return Err(ReceiptError::EmptyProofInputs);
        }
        self.transformation_witness.validate()?;
        self.equivalence_evidence.validate()?;
        self.performance_delta.validate()?;
        if !self.rollback_token.validated {
            return Err(ReceiptError::UnvalidatedRollback);
        }
        if self.fallback_path.is_empty() {
            return Err(ReceiptError::EmptyTransformationDescription);
        }
        Ok(())
    }

    /// Check that all proof inputs are within the receipt's validity epoch.
    pub fn validate_epoch_consistency(&self) -> Result<(), ReceiptError> {
        let receipt_epoch = self.validity_epoch.as_u64();
        for input in &self.proof_inputs {
            if input.proof_epoch.as_u64() != receipt_epoch {
                return Err(ReceiptError::EpochMismatch {
                    receipt_epoch,
                    proof_epoch: input.proof_epoch.as_u64(),
                });
            }
        }
        Ok(())
    }

    /// Derive the receipt_id from canonical bytes.
    pub fn derive_receipt_id(&self) -> Result<EngineObjectId, ReceiptError> {
        let bytes = self.preimage_bytes();
        engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            RECEIPT_ZONE,
            receipt_schema_id(),
            &bytes,
        )
        .map_err(|e| ReceiptError::IdDerivation(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// ReceiptBuilder — fluent construction
// ---------------------------------------------------------------------------

/// Builder for constructing `SpecializationReceipt` instances.
#[derive(Debug)]
pub struct ReceiptBuilder {
    proof_inputs: Vec<ProofInput>,
    optimization_class: OptimizationClass,
    transformation_witness: Option<TransformationWitness>,
    equivalence_evidence: Option<EquivalenceEvidence>,
    rollback_token: Option<RollbackToken>,
    validity_epoch: SecurityEpoch,
    fallback_path: String,
    performance_delta: Option<PerformanceDelta>,
    timestamp_ns: u64,
    metadata: BTreeMap<String, String>,
}

impl ReceiptBuilder {
    /// Create a new builder for the given optimization class.
    pub fn new(optimization_class: OptimizationClass, validity_epoch: SecurityEpoch) -> Self {
        Self {
            proof_inputs: Vec::new(),
            optimization_class,
            transformation_witness: None,
            equivalence_evidence: None,
            rollback_token: None,
            validity_epoch,
            fallback_path: String::new(),
            performance_delta: None,
            timestamp_ns: 0,
            metadata: BTreeMap::new(),
        }
    }

    /// Add a proof input.
    pub fn add_proof_input(mut self, input: ProofInput) -> Self {
        self.proof_inputs.push(input);
        self
    }

    /// Set the transformation witness.
    pub fn transformation_witness(mut self, witness: TransformationWitness) -> Self {
        self.transformation_witness = Some(witness);
        self
    }

    /// Set the equivalence evidence.
    pub fn equivalence_evidence(mut self, evidence: EquivalenceEvidence) -> Self {
        self.equivalence_evidence = Some(evidence);
        self
    }

    /// Set the rollback token.
    pub fn rollback_token(mut self, token: RollbackToken) -> Self {
        self.rollback_token = Some(token);
        self
    }

    /// Set the fallback path.
    pub fn fallback_path(mut self, path: impl Into<String>) -> Self {
        self.fallback_path = path.into();
        self
    }

    /// Set the performance delta.
    pub fn performance_delta(mut self, delta: PerformanceDelta) -> Self {
        self.performance_delta = Some(delta);
        self
    }

    /// Set the timestamp.
    pub fn timestamp_ns(mut self, ts: u64) -> Self {
        self.timestamp_ns = ts;
        self
    }

    /// Add a metadata entry.
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the receipt. Derives receipt_id from content.
    pub fn build(self) -> Result<SpecializationReceipt, ReceiptError> {
        if self.proof_inputs.is_empty() {
            return Err(ReceiptError::EmptyProofInputs);
        }
        let tw = self
            .transformation_witness
            .ok_or(ReceiptError::EmptyTransformationDescription)?;
        tw.validate()?;
        let ee = self
            .equivalence_evidence
            .ok_or(ReceiptError::NoEquivalenceTests)?;
        ee.validate()?;
        let rt = self
            .rollback_token
            .ok_or(ReceiptError::UnvalidatedRollback)?;
        if !rt.validated {
            return Err(ReceiptError::UnvalidatedRollback);
        }
        let pd = self
            .performance_delta
            .ok_or(ReceiptError::ZeroBenchmarkSamples)?;
        pd.validate()?;

        // Build with a placeholder receipt_id, then derive real ID.
        let placeholder_id = EngineObjectId([0u8; 32]);
        let mut receipt = SpecializationReceipt {
            receipt_id: placeholder_id,
            schema_version: ReceiptSchemaVersion::CURRENT,
            proof_inputs: self.proof_inputs,
            optimization_class: self.optimization_class,
            transformation_witness: tw,
            equivalence_evidence: ee,
            rollback_token: rt,
            validity_epoch: self.validity_epoch,
            fallback_path: self.fallback_path,
            performance_delta: pd,
            timestamp_ns: self.timestamp_ns,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
            metadata: self.metadata,
        };
        receipt.receipt_id = receipt.derive_receipt_id()?;
        Ok(receipt)
    }
}

// ---------------------------------------------------------------------------
// ReceiptIndex — aggregation queries
// ---------------------------------------------------------------------------

/// In-memory index supporting receipt aggregation queries.
///
/// Supports "all specializations from a given proof" and
/// "all proofs feeding a given specialization."
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReceiptIndex {
    receipts: Vec<SpecializationReceipt>,
}

impl ReceiptIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }

    /// Insert a receipt. Validates before inserting.
    pub fn insert(&mut self, receipt: SpecializationReceipt) -> Result<(), ReceiptError> {
        receipt.validate()?;
        self.receipts.push(receipt);
        Ok(())
    }

    /// Number of receipts in the index.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// All receipts.
    pub fn all(&self) -> &[SpecializationReceipt] {
        &self.receipts
    }

    /// Find all specializations justified by a given proof ID.
    pub fn specializations_from_proof(
        &self,
        proof_id: &EngineObjectId,
    ) -> Vec<&SpecializationReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.proof_inputs.iter().any(|pi| &pi.proof_id == proof_id))
            .collect()
    }

    /// Find all proof IDs feeding a given specialization (by receipt_id).
    pub fn proofs_for_specialization(&self, receipt_id: &EngineObjectId) -> Vec<&ProofInput> {
        self.receipts
            .iter()
            .find(|r| &r.receipt_id == receipt_id)
            .map(|r| r.proof_inputs.iter().collect())
            .unwrap_or_default()
    }

    /// Find all receipts for a given optimization class.
    pub fn by_optimization_class(&self, class: OptimizationClass) -> Vec<&SpecializationReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.optimization_class == class)
            .collect()
    }

    /// Find all receipts for a given epoch.
    pub fn by_epoch(&self, epoch: SecurityEpoch) -> Vec<&SpecializationReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.validity_epoch == epoch)
            .collect()
    }

    /// Invalidate all receipts whose validity epoch doesn't match the given
    /// current epoch. Returns the invalidated receipt IDs.
    pub fn invalidate_stale(&mut self, current_epoch: SecurityEpoch) -> Vec<EngineObjectId> {
        let mut stale_ids = Vec::new();
        let mut kept = Vec::new();
        for receipt in self.receipts.drain(..) {
            if receipt.validity_epoch != current_epoch {
                stale_ids.push(receipt.receipt_id.clone());
            } else {
                kept.push(receipt);
            }
        }
        self.receipts = kept;
        stale_ids
    }
}

// ---------------------------------------------------------------------------
// ReceiptEvent — structured log events
// ---------------------------------------------------------------------------

/// Structured log event for receipt operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptEvent {
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Component emitting the event.
    pub component: String,
    /// Event kind.
    pub event: ReceiptEventKind,
    /// Receipt ID (if applicable).
    pub receipt_id: Option<String>,
    /// Optimization class (if applicable).
    pub optimization_class: Option<String>,
    /// Outcome.
    pub outcome: String,
}

/// Kinds of receipt events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptEventKind {
    /// Receipt created.
    Created,
    /// Receipt signed.
    Signed,
    /// Receipt validated.
    Validated,
    /// Receipt indexed.
    Indexed,
    /// Receipt invalidated (epoch change).
    Invalidated,
    /// Receipt query performed.
    Queried,
}

impl fmt::Display for ReceiptEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => f.write_str("created"),
            Self::Signed => f.write_str("signed"),
            Self::Validated => f.write_str("validated"),
            Self::Indexed => f.write_str("indexed"),
            Self::Invalidated => f.write_str("invalidated"),
            Self::Queried => f.write_str("queried"),
        }
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Create a valid test proof input for use in tests.
pub fn test_proof_input(proof_type: ProofType, epoch: SecurityEpoch) -> ProofInput {
    let proof_id = engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        "test-proof",
        &SchemaId::from_definition(b"TestProof.v1"),
        &[proof_type as u8, epoch.as_u64() as u8],
    )
    .expect("test proof id derivation");
    ProofInput {
        proof_type,
        proof_id,
        proof_epoch: epoch,
        validity_window_ticks: 1000,
    }
}

/// Create a valid test transformation witness.
pub fn test_transformation_witness() -> TransformationWitness {
    TransformationWitness {
        description: "Specialized hostcall dispatch for extension X".to_string(),
        before_ir_digest: ContentHash::compute(b"before-ir"),
        after_ir_digest: ContentHash::compute(b"after-ir"),
    }
}

/// Create a valid test equivalence evidence.
pub fn test_equivalence_evidence() -> EquivalenceEvidence {
    EquivalenceEvidence {
        method: EquivalenceMethod::DifferentialTesting,
        differential_test_hashes: vec![
            ContentHash::compute(b"diff-test-1"),
            ContentHash::compute(b"diff-test-2"),
        ],
        test_count: 500,
        pass_rate_millionths: MILLIONTHS,
    }
}

/// Create a valid test rollback token.
pub fn test_rollback_token() -> RollbackToken {
    RollbackToken {
        baseline_hash: ContentHash::compute(b"baseline-code"),
        rollback_procedure_hash: ContentHash::compute(b"rollback-proc"),
        validated: true,
    }
}

/// Create a valid test performance delta.
pub fn test_performance_delta() -> PerformanceDelta {
    PerformanceDelta {
        latency_reduction_millionths: 300_000,   // 30% reduction
        throughput_increase_millionths: 250_000, // 25% increase
        sample_count: 1000,
    }
}

/// Build a complete valid test receipt.
pub fn test_receipt(epoch: SecurityEpoch) -> SpecializationReceipt {
    ReceiptBuilder::new(OptimizationClass::HostcallDispatchSpecialization, epoch)
        .add_proof_input(test_proof_input(ProofType::CapabilityWitness, epoch))
        .add_proof_input(test_proof_input(ProofType::FlowProof, epoch))
        .transformation_witness(test_transformation_witness())
        .equivalence_evidence(test_equivalence_evidence())
        .rollback_token(test_rollback_token())
        .fallback_path("modules::hostcall::unspecialized_dispatch")
        .performance_delta(test_performance_delta())
        .timestamp_ns(1_000_000)
        .metadata("test", "true")
        .build()
        .expect("valid test receipt")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes([1u8; 32])
    }

    // -- Serde round-trip tests --

    #[test]
    fn proof_type_serde_roundtrip() {
        for pt in [
            ProofType::CapabilityWitness,
            ProofType::FlowProof,
            ProofType::ReplayMotif,
        ] {
            let json = serde_json::to_string(&pt).unwrap();
            let back: ProofType = serde_json::from_str(&json).unwrap();
            assert_eq!(pt, back);
        }
    }

    #[test]
    fn optimization_class_serde_roundtrip() {
        for oc in [
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClass::IfcCheckElision,
            OptimizationClass::SuperinstructionFusion,
            OptimizationClass::PathElimination,
        ] {
            let json = serde_json::to_string(&oc).unwrap();
            let back: OptimizationClass = serde_json::from_str(&json).unwrap();
            assert_eq!(oc, back);
        }
    }

    #[test]
    fn equivalence_method_serde_roundtrip() {
        for em in [
            EquivalenceMethod::DifferentialTesting,
            EquivalenceMethod::TranslationValidation,
            EquivalenceMethod::Bisimulation,
        ] {
            let json = serde_json::to_string(&em).unwrap();
            let back: EquivalenceMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(em, back);
        }
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let receipt = test_receipt(epoch());
        let json = serde_json::to_string(&receipt).unwrap();
        let back: SpecializationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn receipt_schema_version_display() {
        assert_eq!(ReceiptSchemaVersion::CURRENT.to_string(), "1.0");
    }

    #[test]
    fn receipt_schema_version_compatibility() {
        let v10 = ReceiptSchemaVersion { major: 1, minor: 0 };
        let v11 = ReceiptSchemaVersion { major: 1, minor: 1 };
        let v20 = ReceiptSchemaVersion { major: 2, minor: 0 };
        assert!(v11.is_compatible_with(&v10)); // 1.1 reader can read 1.0
        assert!(!v10.is_compatible_with(&v11)); // 1.0 cannot read 1.1
        assert!(!v20.is_compatible_with(&v10)); // major bump = incompatible
    }

    // -- Validation tests --

    #[test]
    fn validate_rejects_empty_proof_inputs() {
        let mut receipt = test_receipt(epoch());
        receipt.proof_inputs.clear();
        assert_eq!(receipt.validate(), Err(ReceiptError::EmptyProofInputs));
    }

    #[test]
    fn validate_rejects_empty_transformation_description() {
        let mut receipt = test_receipt(epoch());
        receipt.transformation_witness.description.clear();
        assert_eq!(
            receipt.validate(),
            Err(ReceiptError::EmptyTransformationDescription)
        );
    }

    #[test]
    fn validate_rejects_identical_ir_digests() {
        let mut receipt = test_receipt(epoch());
        receipt.transformation_witness.after_ir_digest =
            receipt.transformation_witness.before_ir_digest.clone();
        assert_eq!(receipt.validate(), Err(ReceiptError::IdenticalIrDigests));
    }

    #[test]
    fn validate_rejects_no_equivalence_tests() {
        let mut receipt = test_receipt(epoch());
        receipt
            .equivalence_evidence
            .differential_test_hashes
            .clear();
        assert_eq!(receipt.validate(), Err(ReceiptError::NoEquivalenceTests));
    }

    #[test]
    fn validate_rejects_zero_test_count() {
        let mut receipt = test_receipt(epoch());
        receipt.equivalence_evidence.test_count = 0;
        assert_eq!(receipt.validate(), Err(ReceiptError::ZeroTestCount));
    }

    #[test]
    fn validate_rejects_insufficient_pass_rate() {
        let mut receipt = test_receipt(epoch());
        receipt.equivalence_evidence.pass_rate_millionths = 999_999;
        assert_eq!(
            receipt.validate(),
            Err(ReceiptError::InsufficientPassRate {
                required: MILLIONTHS,
                actual: 999_999,
            })
        );
    }

    #[test]
    fn validate_rejects_pass_rate_out_of_range() {
        let mut receipt = test_receipt(epoch());
        receipt.equivalence_evidence.pass_rate_millionths = MILLIONTHS + 1;
        assert_eq!(
            receipt.validate(),
            Err(ReceiptError::PassRateOutOfRange {
                value: MILLIONTHS + 1,
            })
        );
    }

    #[test]
    fn validate_rejects_unvalidated_rollback() {
        let mut receipt = test_receipt(epoch());
        receipt.rollback_token.validated = false;
        assert_eq!(receipt.validate(), Err(ReceiptError::UnvalidatedRollback));
    }

    #[test]
    fn validate_rejects_zero_benchmark_samples() {
        let mut receipt = test_receipt(epoch());
        receipt.performance_delta.sample_count = 0;
        assert_eq!(receipt.validate(), Err(ReceiptError::ZeroBenchmarkSamples));
    }

    #[test]
    fn validate_passes_for_valid_receipt() {
        let receipt = test_receipt(epoch());
        assert!(receipt.validate().is_ok());
    }

    // -- Epoch consistency tests --

    #[test]
    fn epoch_consistency_passes_for_matching_epochs() {
        let receipt = test_receipt(epoch());
        assert!(receipt.validate_epoch_consistency().is_ok());
    }

    #[test]
    fn epoch_consistency_fails_for_mismatched_proof_epoch() {
        let mut receipt = test_receipt(epoch());
        receipt.proof_inputs[0].proof_epoch = SecurityEpoch::from_raw(99);
        let err = receipt.validate_epoch_consistency().unwrap_err();
        assert_eq!(
            err,
            ReceiptError::EpochMismatch {
                receipt_epoch: 42,
                proof_epoch: 99,
            }
        );
    }

    // -- Content hash and ID tests --

    #[test]
    fn content_hash_is_deterministic() {
        let r1 = test_receipt(epoch());
        let r2 = test_receipt(epoch());
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn receipt_id_is_deterministic() {
        let r1 = test_receipt(epoch());
        let r2 = test_receipt(epoch());
        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn different_optimization_class_yields_different_id() {
        let r1 = test_receipt(epoch());
        let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, epoch())
            .add_proof_input(test_proof_input(ProofType::CapabilityWitness, epoch()))
            .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("modules::path::unspecialized")
            .performance_delta(test_performance_delta())
            .timestamp_ns(1_000_000)
            .build()
            .unwrap();
        assert_ne!(r1.receipt_id, r2.receipt_id);
    }

    // -- Signature tests --

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = signing_key();
        let vk = key.verification_key();
        let mut receipt = test_receipt(epoch());
        receipt.sign(&key).unwrap();
        assert!(receipt.verify(&vk).is_ok());
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let key = signing_key();
        let wrong_vk = SigningKey::from_bytes([2u8; 32]).verification_key();
        let mut receipt = test_receipt(epoch());
        receipt.sign(&key).unwrap();
        assert!(receipt.verify(&wrong_vk).is_err());
    }

    #[test]
    fn verify_fails_after_mutation() {
        let key = signing_key();
        let vk = key.verification_key();
        let mut receipt = test_receipt(epoch());
        receipt.sign(&key).unwrap();
        receipt.timestamp_ns = 999;
        assert!(receipt.verify(&vk).is_err());
    }

    // -- Builder tests --

    #[test]
    fn builder_rejects_empty_proof_inputs() {
        let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("fallback")
            .performance_delta(test_performance_delta())
            .build();
        assert_eq!(result.unwrap_err(), ReceiptError::EmptyProofInputs);
    }

    #[test]
    fn builder_rejects_missing_transformation() {
        let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
            .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("fallback")
            .performance_delta(test_performance_delta())
            .build();
        assert_eq!(
            result.unwrap_err(),
            ReceiptError::EmptyTransformationDescription
        );
    }

    #[test]
    fn builder_rejects_missing_equivalence() {
        let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
            .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
            .transformation_witness(test_transformation_witness())
            .rollback_token(test_rollback_token())
            .fallback_path("fallback")
            .performance_delta(test_performance_delta())
            .build();
        assert_eq!(result.unwrap_err(), ReceiptError::NoEquivalenceTests);
    }

    #[test]
    fn builder_rejects_missing_rollback() {
        let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
            .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .fallback_path("fallback")
            .performance_delta(test_performance_delta())
            .build();
        assert_eq!(result.unwrap_err(), ReceiptError::UnvalidatedRollback);
    }

    #[test]
    fn builder_rejects_missing_perf_delta() {
        let result = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, epoch())
            .add_proof_input(test_proof_input(ProofType::FlowProof, epoch()))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("fallback")
            .build();
        assert_eq!(result.unwrap_err(), ReceiptError::ZeroBenchmarkSamples);
    }

    #[test]
    fn builder_metadata_preserved() {
        let receipt = ReceiptBuilder::new(OptimizationClass::SuperinstructionFusion, epoch())
            .add_proof_input(test_proof_input(ProofType::ReplayMotif, epoch()))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("modules::fusion::baseline")
            .performance_delta(test_performance_delta())
            .metadata("author", "plas")
            .metadata("version", "3")
            .build()
            .unwrap();
        assert_eq!(receipt.metadata.get("author").unwrap(), "plas");
        assert_eq!(receipt.metadata.get("version").unwrap(), "3");
    }

    // -- Index / aggregation tests --

    #[test]
    fn index_insert_and_len() {
        let mut idx = ReceiptIndex::new();
        assert!(idx.is_empty());
        idx.insert(test_receipt(epoch())).unwrap();
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn index_specializations_from_proof() {
        let mut idx = ReceiptIndex::new();
        let receipt = test_receipt(epoch());
        let proof_id = receipt.proof_inputs[0].proof_id.clone();
        idx.insert(receipt).unwrap();

        let found = idx.specializations_from_proof(&proof_id);
        assert_eq!(found.len(), 1);

        let unknown = EngineObjectId([0xFFu8; 32]);
        assert!(idx.specializations_from_proof(&unknown).is_empty());
    }

    #[test]
    fn index_proofs_for_specialization() {
        let mut idx = ReceiptIndex::new();
        let receipt = test_receipt(epoch());
        let rid = receipt.receipt_id.clone();
        idx.insert(receipt).unwrap();

        let proofs = idx.proofs_for_specialization(&rid);
        assert_eq!(proofs.len(), 2); // two proof inputs in test_receipt

        let unknown = EngineObjectId([0xFFu8; 32]);
        assert!(idx.proofs_for_specialization(&unknown).is_empty());
    }

    #[test]
    fn index_by_optimization_class() {
        let mut idx = ReceiptIndex::new();
        idx.insert(test_receipt(epoch())).unwrap(); // HostcallDispatchSpecialization
        let found = idx.by_optimization_class(OptimizationClass::HostcallDispatchSpecialization);
        assert_eq!(found.len(), 1);
        let empty = idx.by_optimization_class(OptimizationClass::PathElimination);
        assert!(empty.is_empty());
    }

    #[test]
    fn index_by_epoch() {
        let mut idx = ReceiptIndex::new();
        let e42 = SecurityEpoch::from_raw(42);
        let e99 = SecurityEpoch::from_raw(99);
        idx.insert(test_receipt(e42)).unwrap();
        assert_eq!(idx.by_epoch(e42).len(), 1);
        assert!(idx.by_epoch(e99).is_empty());
    }

    #[test]
    fn index_invalidate_stale_removes_wrong_epoch() {
        let mut idx = ReceiptIndex::new();
        let e42 = SecurityEpoch::from_raw(42);
        let e43 = SecurityEpoch::from_raw(43);
        idx.insert(test_receipt(e42)).unwrap();
        let stale = idx.invalidate_stale(e43);
        assert_eq!(stale.len(), 1);
        assert!(idx.is_empty());
    }

    #[test]
    fn index_invalidate_stale_keeps_matching_epoch() {
        let mut idx = ReceiptIndex::new();
        let e42 = SecurityEpoch::from_raw(42);
        idx.insert(test_receipt(e42)).unwrap();
        let stale = idx.invalidate_stale(e42);
        assert!(stale.is_empty());
        assert_eq!(idx.len(), 1);
    }

    // -- Determinism tests --

    #[test]
    fn receipt_deterministic_100_times() {
        let first = test_receipt(epoch());
        for _ in 0..100 {
            let r = test_receipt(epoch());
            assert_eq!(r.receipt_id, first.receipt_id);
            assert_eq!(r.content_hash(), first.content_hash());
        }
    }

    #[test]
    fn receipt_event_serde_roundtrip() {
        let event = ReceiptEvent {
            trace_id: "tr-1".to_string(),
            component: "proof_specialization_receipt".to_string(),
            event: ReceiptEventKind::Created,
            receipt_id: Some("rid-1".to_string()),
            optimization_class: Some("hostcall_dispatch_specialization".to_string()),
            outcome: "success".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ReceiptEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn receipt_event_kind_display() {
        assert_eq!(ReceiptEventKind::Created.to_string(), "created");
        assert_eq!(ReceiptEventKind::Invalidated.to_string(), "invalidated");
    }

    // -- Display tests --

    #[test]
    fn proof_type_display() {
        assert_eq!(
            ProofType::CapabilityWitness.to_string(),
            "capability_witness"
        );
        assert_eq!(ProofType::FlowProof.to_string(), "flow_proof");
        assert_eq!(ProofType::ReplayMotif.to_string(), "replay_motif");
    }

    #[test]
    fn optimization_class_display() {
        assert_eq!(
            OptimizationClass::HostcallDispatchSpecialization.to_string(),
            "hostcall_dispatch_specialization"
        );
        assert_eq!(
            OptimizationClass::IfcCheckElision.to_string(),
            "ifc_check_elision"
        );
        assert_eq!(
            OptimizationClass::SuperinstructionFusion.to_string(),
            "superinstruction_fusion"
        );
        assert_eq!(
            OptimizationClass::PathElimination.to_string(),
            "path_elimination"
        );
    }

    #[test]
    fn equivalence_method_display() {
        assert_eq!(
            EquivalenceMethod::DifferentialTesting.to_string(),
            "differential_testing"
        );
        assert_eq!(
            EquivalenceMethod::TranslationValidation.to_string(),
            "translation_validation"
        );
        assert_eq!(EquivalenceMethod::Bisimulation.to_string(), "bisimulation");
    }

    #[test]
    fn receipt_error_display_coverage() {
        let errors = [
            ReceiptError::EmptyProofInputs,
            ReceiptError::EmptyTransformationDescription,
            ReceiptError::IdenticalIrDigests,
            ReceiptError::NoEquivalenceTests,
            ReceiptError::ZeroTestCount,
            ReceiptError::PassRateOutOfRange { value: 2_000_000 },
            ReceiptError::InsufficientPassRate {
                required: MILLIONTHS,
                actual: 500_000,
            },
            ReceiptError::ZeroBenchmarkSamples,
            ReceiptError::UnvalidatedRollback,
            ReceiptError::EpochMismatch {
                receipt_epoch: 1,
                proof_epoch: 2,
            },
            ReceiptError::ProofExpired {
                proof_id: "p1".to_string(),
                window_ticks: 100,
            },
            ReceiptError::IdDerivation("test".to_string()),
            ReceiptError::SignatureInvalid {
                detail: "bad".to_string(),
            },
            ReceiptError::IntegrityFailure {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
            ReceiptError::IncompatibleSchema {
                receipt: ReceiptSchemaVersion { major: 2, minor: 0 },
                reader: ReceiptSchemaVersion { major: 1, minor: 0 },
            },
        ];
        for err in &errors {
            let s = err.to_string();
            assert!(!s.is_empty(), "display for {err:?} should not be empty");
        }
    }

    // -- Multiple proof types in single receipt --

    #[test]
    fn receipt_with_all_proof_types() {
        let e = epoch();
        let receipt = ReceiptBuilder::new(OptimizationClass::IfcCheckElision, e)
            .add_proof_input(test_proof_input(ProofType::CapabilityWitness, e))
            .add_proof_input(test_proof_input(ProofType::FlowProof, e))
            .add_proof_input(test_proof_input(ProofType::ReplayMotif, e))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("modules::ifc::unspecialized_check")
            .performance_delta(test_performance_delta())
            .build()
            .unwrap();
        assert_eq!(receipt.proof_inputs.len(), 3);
    }

    // -- Multiple receipts from same proof --

    #[test]
    fn multiple_receipts_from_same_proof() {
        let e = epoch();
        let pi = test_proof_input(ProofType::CapabilityWitness, e);
        let mut idx = ReceiptIndex::new();

        // Two receipts with different optimization classes share a proof input.
        let r1 = ReceiptBuilder::new(OptimizationClass::HostcallDispatchSpecialization, e)
            .add_proof_input(pi.clone())
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("fallback_a")
            .performance_delta(test_performance_delta())
            .build()
            .unwrap();
        let r2 = ReceiptBuilder::new(OptimizationClass::PathElimination, e)
            .add_proof_input(pi.clone())
            .transformation_witness(TransformationWitness {
                description: "Eliminate dead path".to_string(),
                before_ir_digest: ContentHash::compute(b"before-path"),
                after_ir_digest: ContentHash::compute(b"after-path"),
            })
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("fallback_b")
            .performance_delta(test_performance_delta())
            .build()
            .unwrap();

        idx.insert(r1).unwrap();
        idx.insert(r2).unwrap();

        let found = idx.specializations_from_proof(&pi.proof_id);
        assert_eq!(found.len(), 2);
    }

    // -- Machine-readable JSON output --

    #[test]
    fn receipt_json_has_stable_keys() {
        let receipt = test_receipt(epoch());
        let json = serde_json::to_string(&receipt).unwrap();
        for key in [
            "receipt_id",
            "schema_version",
            "proof_inputs",
            "optimization_class",
            "transformation_witness",
            "equivalence_evidence",
            "rollback_token",
            "validity_epoch",
            "fallback_path",
            "performance_delta",
            "timestamp_ns",
            "signature",
        ] {
            assert!(json.contains(key), "JSON missing key: {key}");
        }
    }

    #[test]
    fn receipt_index_serde_roundtrip() {
        let mut idx = ReceiptIndex::new();
        idx.insert(test_receipt(epoch())).unwrap();
        let json = serde_json::to_string(&idx).unwrap();
        let back: ReceiptIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    // -- Edge: single proof input receipt --

    #[test]
    fn receipt_with_single_proof_input() {
        let e = epoch();
        let receipt = ReceiptBuilder::new(OptimizationClass::SuperinstructionFusion, e)
            .add_proof_input(test_proof_input(ProofType::ReplayMotif, e))
            .transformation_witness(test_transformation_witness())
            .equivalence_evidence(test_equivalence_evidence())
            .rollback_token(test_rollback_token())
            .fallback_path("modules::fusion::baseline")
            .performance_delta(test_performance_delta())
            .build()
            .unwrap();
        assert_eq!(receipt.proof_inputs.len(), 1);
        receipt.validate().unwrap();
    }

    // -- ReceiptError serde --

    #[test]
    fn receipt_error_serde_roundtrip() {
        let err = ReceiptError::EpochMismatch {
            receipt_epoch: 42,
            proof_epoch: 99,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: ReceiptError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // -- Enrichment: std::error --

    #[test]
    fn receipt_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ReceiptError::EmptyProofInputs),
            Box::new(ReceiptError::EmptyTransformationDescription),
            Box::new(ReceiptError::IdenticalIrDigests),
            Box::new(ReceiptError::NoEquivalenceTests),
            Box::new(ReceiptError::ZeroTestCount),
            Box::new(ReceiptError::PassRateOutOfRange { value: 2_000_000 }),
            Box::new(ReceiptError::ZeroBenchmarkSamples),
            Box::new(ReceiptError::UnvalidatedRollback),
            Box::new(ReceiptError::IdDerivation("bad id".into())),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            9,
            "all 9 tested variants produce distinct messages"
        );
    }

    #[test]
    fn proof_type_ord() {
        assert!(ProofType::CapabilityWitness < ProofType::FlowProof);
        assert!(ProofType::FlowProof < ProofType::ReplayMotif);
    }

    #[test]
    fn optimization_class_ord() {
        assert!(
            OptimizationClass::HostcallDispatchSpecialization < OptimizationClass::IfcCheckElision
        );
        assert!(OptimizationClass::IfcCheckElision < OptimizationClass::SuperinstructionFusion);
        assert!(OptimizationClass::SuperinstructionFusion < OptimizationClass::PathElimination);
    }

    #[test]
    fn equivalence_method_ord() {
        assert!(EquivalenceMethod::DifferentialTesting < EquivalenceMethod::TranslationValidation);
        assert!(EquivalenceMethod::TranslationValidation < EquivalenceMethod::Bisimulation);
    }
}
