//! PLAS capability witness artifact schema.
//!
//! A capability witness is a signed, content-addressed artifact that records
//! the minimal authority envelope an extension needs to operate, the proof
//! obligations justifying each included capability, statistical confidence
//! bounds on the envelope's completeness, and deterministic replay/rollback
//! linkage.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: 10.15 item 1, 9I.5.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEmitter, EvidenceEntry,
    EvidenceEntryBuilder, InMemoryLedger, Witness as EvidenceWitness,
};
use crate::hash_tiers::ContentHash;
use crate::mmr_proof::{
    MerkleMountainRange, MmrProof, ProofError as MmrProofError, verify_consistency,
    verify_inclusion,
};
use crate::policy_theorem_compiler::Capability;
use crate::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceLedgerInput, GovernanceRationale, ScorecardSnapshot,
};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};
use crate::storage_adapter::{
    BatchPutEntry, EventContext, MigrationReceipt, StorageAdapter, StorageError, StoreKind,
    StoreQuery,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WITNESS_SCHEMA_DEF: &[u8] = b"CapabilityWitness.v1";
const WITNESS_THEOREM_SCHEMA_DEF: &[u8] = b"CapabilityWitnessPromotionTheorem.v1";
const WITNESS_ZONE: &str = "capability-witness";
const WITNESS_THEOREM_COMPONENT: &str = "capability_witness_theorem_gate";
const WITNESS_THEOREM_RESULT_ZONE: &str = "capability-witness-theorem-result";
const WITNESS_THEOREM_REPORT_SCHEMA_DEF: &[u8] = b"CapabilityWitnessPromotionTheoremReport.v1";
const WITNESS_THEOREM_REPORT_ZONE: &str = "capability-witness-theorem-report";
const WITNESS_PUBLICATION_SCHEMA_DEF: &[u8] = b"CapabilityWitnessPublication.v1";
const WITNESS_PUBLICATION_ZONE: &str = "capability-witness-publication";

// ---------------------------------------------------------------------------
// WitnessSchemaVersion
// ---------------------------------------------------------------------------

/// Schema version for the capability witness format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WitnessSchemaVersion {
    pub major: u32,
    pub minor: u32,
}

impl WitnessSchemaVersion {
    /// Current schema version.
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// Compatible if same major and reader minor >= witness minor.
    pub fn is_compatible_with(&self, witness_version: &Self) -> bool {
        self.major == witness_version.major && self.minor >= witness_version.minor
    }
}

impl fmt::Display for WitnessSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// LifecycleState
// ---------------------------------------------------------------------------

/// Lifecycle state of a capability witness.
///
/// ```text
/// draft -> validated -> promoted -> active -> {superseded | revoked}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LifecycleState {
    /// Synthesizer has emitted a candidate witness.
    Draft,
    /// Validation checks passed (fields well-formed, confidence acceptable).
    Validated,
    /// Policy theorem checks passed (monotonic safety, merge legality, etc.).
    Promoted,
    /// Shadow validation completed; witness is actively enforced.
    Active,
    /// A newer witness version has been activated for the same extension.
    Superseded,
    /// Emergency revocation (compromise detected, witness proven unsound, epoch change).
    Revoked,
}

impl LifecycleState {
    /// Whether the witness is in a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Superseded | Self::Revoked)
    }

    /// Whether the witness is actively enforced.
    pub fn is_active(self) -> bool {
        self == Self::Active
    }

    /// Valid successor states from this state.
    pub fn valid_transitions(self) -> &'static [LifecycleState] {
        match self {
            Self::Draft => &[Self::Validated],
            Self::Validated => &[Self::Promoted],
            Self::Promoted => &[Self::Active],
            Self::Active => &[Self::Superseded, Self::Revoked],
            Self::Superseded | Self::Revoked => &[],
        }
    }

    /// Check if transitioning to `target` is valid.
    pub fn can_transition_to(self, target: Self) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => f.write_str("draft"),
            Self::Validated => f.write_str("validated"),
            Self::Promoted => f.write_str("promoted"),
            Self::Active => f.write_str("active"),
            Self::Superseded => f.write_str("superseded"),
            Self::Revoked => f.write_str("revoked"),
        }
    }
}

// ---------------------------------------------------------------------------
// WitnessError
// ---------------------------------------------------------------------------

/// Errors from the capability witness subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessError {
    /// Required capability set is empty.
    EmptyRequiredSet,
    /// Proof obligations missing for one or more required capabilities.
    MissingProofObligation { capability: String },
    /// Confidence interval out of valid range.
    InvalidConfidence { reason: String },
    /// Invalid lifecycle state transition.
    InvalidTransition {
        from: LifecycleState,
        to: LifecycleState,
    },
    /// Schema version incompatibility.
    IncompatibleSchema {
        witness: WitnessSchemaVersion,
        reader: WitnessSchemaVersion,
    },
    /// Signature verification failed.
    SignatureInvalid { detail: String },
    /// Content hash mismatch.
    IntegrityFailure { expected: String, actual: String },
    /// ID derivation error.
    IdDerivation(String),
    /// Rollback token references unknown witness.
    InvalidRollbackToken { reason: String },
    /// Epoch mismatch.
    EpochMismatch {
        witness_epoch: u64,
        current_epoch: u64,
    },
    /// Promotion to `promoted` requires all theorem checks.
    MissingPromotionTheoremProofs { missing_checks: Vec<String> },
    /// One or more theorem checks failed.
    PromotionTheoremFailed { failed_checks: Vec<String> },
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRequiredSet => f.write_str("required capability set is empty"),
            Self::MissingProofObligation { capability } => {
                write!(f, "missing proof obligation for capability: {capability}")
            }
            Self::InvalidConfidence { reason } => {
                write!(f, "invalid confidence interval: {reason}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid lifecycle transition: {from} -> {to}")
            }
            Self::IncompatibleSchema { witness, reader } => {
                write!(f, "incompatible schema: witness={witness}, reader={reader}")
            }
            Self::SignatureInvalid { detail } => write!(f, "signature invalid: {detail}"),
            Self::IntegrityFailure { expected, actual } => {
                write!(f, "integrity failure: expected={expected}, actual={actual}")
            }
            Self::IdDerivation(s) => write!(f, "id derivation: {s}"),
            Self::InvalidRollbackToken { reason } => {
                write!(f, "invalid rollback token: {reason}")
            }
            Self::EpochMismatch {
                witness_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch mismatch: witness={witness_epoch}, current={current_epoch}"
            ),
            Self::MissingPromotionTheoremProofs { missing_checks } => write!(
                f,
                "missing promotion theorem proofs: {}",
                missing_checks.join(",")
            ),
            Self::PromotionTheoremFailed { failed_checks } => {
                write!(
                    f,
                    "promotion theorem checks failed: {}",
                    failed_checks.join(",")
                )
            }
        }
    }
}

impl std::error::Error for WitnessError {}

// ---------------------------------------------------------------------------
// ConfidenceInterval — Wilson score bounds
// ---------------------------------------------------------------------------

/// Statistical confidence bounds on the completeness of the required
/// capability set.  Uses Wilson score interval at 95% coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Lower bound (millionths; 950_000 = 0.95).
    pub lower_millionths: i64,
    /// Upper bound (millionths).
    pub upper_millionths: i64,
    /// Number of ablation trials run.
    pub n_trials: u32,
    /// Number of trials where capability removal broke behavior.
    pub n_successes: u32,
}

impl ConfidenceInterval {
    /// Create a new confidence interval from ablation trial results.
    ///
    /// Computes Wilson score interval at ~95% coverage (z ≈ 1.96).
    pub fn from_trials(n_trials: u32, n_successes: u32) -> Self {
        if n_trials == 0 {
            return Self {
                lower_millionths: 0,
                upper_millionths: 0,
                n_trials: 0,
                n_successes: 0,
            };
        }

        // Wilson score interval in fixed-point millionths.
        // z = 1.96 ≈ 196/100.  z^2 ≈ 38416/10000.
        let n = n_trials as i64;
        let s = n_successes as i64;
        let p_hat = s * 1_000_000 / n;

        // z^2/n in millionths: (3_841_600 / n)
        let z2_over_n = 3_841_600 / n;

        // center = (p_hat + z^2/(2n)) / (1 + z^2/n)
        let center_num = p_hat + z2_over_n / 2;
        let denom = 1_000_000 + z2_over_n;

        // discriminant in millionths^2
        let var_term = p_hat * (1_000_000 - p_hat) / n;
        let correction = z2_over_n * 1_000_000 / 4 / n;
        // Approximate sqrt via integer math: we want sqrt(var_term + correction)
        // scaled appropriately.
        let disc = var_term + correction;
        let disc_sqrt = isqrt_millionths(disc);

        // z * sqrt(disc) / denom, where z = 1_960_000 millionths
        let margin = 1_960_000 * disc_sqrt / denom;

        let lower = (center_num * 1_000_000 / denom).saturating_sub(margin);
        let upper = (center_num * 1_000_000 / denom).saturating_add(margin);

        Self {
            lower_millionths: lower.clamp(0, 1_000_000),
            upper_millionths: upper.clamp(0, 1_000_000),
            n_trials,
            n_successes,
        }
    }

    /// Whether the interval meets the minimum coverage threshold (millionths).
    pub fn meets_threshold(&self, threshold_millionths: i64) -> bool {
        self.lower_millionths >= threshold_millionths
    }

    /// Coverage probability at the point estimate (p_hat in millionths).
    pub fn point_estimate_millionths(&self) -> i64 {
        if self.n_trials == 0 {
            return 0;
        }
        self.n_successes as i64 * 1_000_000 / self.n_trials as i64
    }
}

/// Integer square root for fixed-point millionths arithmetic.
fn isqrt_millionths(val: i64) -> i64 {
    if val <= 0 {
        return 0;
    }
    let mut x = val;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + val / x) / 2;
    }
    x
}

// ---------------------------------------------------------------------------
// RollbackToken
// ---------------------------------------------------------------------------

/// Deterministic rollback artifact for reverting to a previous witness version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackToken {
    /// Content hash of the previous active witness (for lookup).
    pub previous_witness_hash: ContentHash,
    /// Witness ID of the previous version (for direct retrieval).
    pub previous_witness_id: Option<EngineObjectId>,
    /// Epoch at which the rollback token was created.
    pub created_epoch: SecurityEpoch,
    /// Sequence number for ordering rollback history.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// ProofObligation — justification for including a capability
// ---------------------------------------------------------------------------

/// Category of evidence justifying a capability's inclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProofKind {
    /// Static analysis evidence (code inspection, type analysis).
    StaticAnalysis,
    /// Dynamic ablation evidence (capability removed, behavior broke).
    DynamicAblation,
    /// Policy theorem check (monotonicity, non-interference, etc.).
    PolicyTheoremCheck,
    /// Manual attestation by a trusted operator.
    OperatorAttestation,
    /// Imported from a prior validated witness.
    InheritedFromPredecessor,
}

impl fmt::Display for ProofKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticAnalysis => f.write_str("static-analysis"),
            Self::DynamicAblation => f.write_str("dynamic-ablation"),
            Self::PolicyTheoremCheck => f.write_str("policy-theorem-check"),
            Self::OperatorAttestation => f.write_str("operator-attestation"),
            Self::InheritedFromPredecessor => f.write_str("inherited"),
        }
    }
}

/// A proof obligation justifying the inclusion of a specific capability
/// in the required set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofObligation {
    /// The capability this proof justifies.
    pub capability: Capability,
    /// Kind of proof evidence.
    pub kind: ProofKind,
    /// Reference to the proof artifact (EngineObjectId of the evidence).
    pub proof_artifact_id: EngineObjectId,
    /// Human-readable description of the justification.
    pub justification: String,
    /// Content hash of the proof artifact.
    pub artifact_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// DenialRecord — justification for excluding a capability
// ---------------------------------------------------------------------------

/// A record explaining why a capability was explicitly denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenialRecord {
    /// The denied capability.
    pub capability: Capability,
    /// Reason for denial.
    pub reason: String,
    /// Optional reference to evidence supporting the denial.
    pub evidence_id: Option<EngineObjectId>,
}

// ---------------------------------------------------------------------------
// Promotion theorem checks
// ---------------------------------------------------------------------------

/// Capability evidence set contributed by one theorem input source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCapabilitySet {
    /// Stable identifier for the source artifact.
    pub source_id: String,
    /// Capabilities justified by this source.
    pub capabilities: BTreeSet<Capability>,
}

/// Optional deterministic extension theorem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomTheoremExtension {
    /// Unique theorem name (used in deterministic metadata keys).
    pub name: String,
    /// Capabilities that must be present in the promoted witness.
    pub required_capabilities: BTreeSet<Capability>,
    /// Capabilities that must not be present in the promoted witness.
    pub forbidden_capabilities: BTreeSet<Capability>,
}

/// Theorem kinds evaluated before witness promotion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PromotionTheoremKind {
    MergeLegality,
    AttenuationLegality,
    NonInterference,
    Custom(String),
}

impl PromotionTheoremKind {
    fn metadata_key(&self) -> String {
        match self {
            Self::MergeLegality => "merge_legality".to_string(),
            Self::AttenuationLegality => "attenuation_legality".to_string(),
            Self::NonInterference => "non_interference".to_string(),
            Self::Custom(name) => {
                let mut sanitized = String::with_capacity(name.len());
                for ch in name.chars() {
                    if ch.is_ascii_alphanumeric() {
                        sanitized.push(ch.to_ascii_lowercase());
                    } else {
                        sanitized.push('_');
                    }
                }
                sanitized
            }
        }
    }
}

impl fmt::Display for PromotionTheoremKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MergeLegality => f.write_str("merge-legality"),
            Self::AttenuationLegality => f.write_str("attenuation-legality"),
            Self::NonInterference => f.write_str("non-interference"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// Deterministic theorem-check input bundle for witness promotion gating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionTheoremInput {
    /// Capability evidence sets from static analysis / ablation / replay.
    pub source_capability_sets: Vec<SourceCapabilitySet>,
    /// Manifest-declared envelope (promotion must attenuate to this set).
    pub manifest_capabilities: BTreeSet<Capability>,
    /// Capability implication lattice:
    /// `capability -> implied prerequisite capabilities`.
    #[serde(default)]
    pub capability_lattice: BTreeMap<Capability, BTreeSet<Capability>>,
    /// Required dependency edges: required_capability -> dependencies.
    pub non_interference_dependencies: BTreeMap<Capability, BTreeSet<Capability>>,
    /// Optional custom theorem checks.
    pub custom_extensions: Vec<CustomTheoremExtension>,
}

/// Result of one theorem check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionTheoremResult {
    pub theorem: PromotionTheoremKind,
    pub passed: bool,
    pub detail: String,
    pub counterexample: Option<String>,
    pub proof_artifact_id: EngineObjectId,
    pub artifact_hash: ContentHash,
}

/// Complete theorem-check report for one witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionTheoremReport {
    pub results: Vec<PromotionTheoremResult>,
    pub all_passed: bool,
    pub report_artifact_id: EngineObjectId,
    pub report_artifact_hash: ContentHash,
}

/// Structured log event for theorem checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionTheoremLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

impl PromotionTheoremReport {
    pub fn structured_events(
        &self,
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
    ) -> Vec<PromotionTheoremLogEvent> {
        let mut events = Vec::with_capacity(self.results.len() + 1);
        for result in &self.results {
            let theorem_key = result.theorem.metadata_key();
            events.push(PromotionTheoremLogEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: policy_id.to_string(),
                component: WITNESS_THEOREM_COMPONENT.to_string(),
                event: format!("theorem_check_{theorem_key}"),
                outcome: if result.passed {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                },
                error_code: if result.passed {
                    None
                } else {
                    Some(format!("promotion_theorem_{theorem_key}_failed"))
                },
            });
        }
        events.push(PromotionTheoremLogEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: WITNESS_THEOREM_COMPONENT.to_string(),
            event: "promotion_theorem_gate".to_string(),
            outcome: if self.all_passed {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_code: if self.all_passed {
                None
            } else {
                Some("promotion_theorem_gate_failed".to_string())
            },
        });
        events
    }
}

// ---------------------------------------------------------------------------
// CapabilityWitness — the main artifact
// ---------------------------------------------------------------------------

/// A signed, content-addressed PLAS capability witness artifact.
///
/// Records the minimal authority envelope an extension demonstrably needs,
/// including proof obligations for each capability and statistical confidence
/// bounds on envelope completeness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityWitness {
    /// Unique witness identifier (content-addressed).
    pub witness_id: EngineObjectId,
    /// Schema version.
    pub schema_version: WitnessSchemaVersion,
    /// Extension this witness applies to.
    pub extension_id: EngineObjectId,
    /// Synthesized policy version.
    pub policy_id: EngineObjectId,
    /// Current lifecycle state.
    pub lifecycle_state: LifecycleState,

    // -- Authority envelope --
    /// Minimal set of capabilities the extension demonstrably needs.
    pub required_capabilities: BTreeSet<Capability>,
    /// Capabilities explicitly excluded with justification.
    pub denied_capabilities: BTreeSet<Capability>,

    // -- Proof obligations --
    /// Proof artifacts justifying each required capability.
    pub proof_obligations: Vec<ProofObligation>,
    /// Denial records for each denied capability.
    pub denial_records: Vec<DenialRecord>,

    // -- Confidence --
    /// Statistical confidence on envelope completeness.
    pub confidence: ConfidenceInterval,

    // -- Determinism & replay --
    /// PRNG seed used during synthesis (for deterministic replay).
    pub replay_seed: u64,
    /// Hash of the synthesis transcript.
    pub transcript_hash: ContentHash,
    /// Rollback token for reverting to previous witness version.
    pub rollback_token: Option<RollbackToken>,

    // -- Signatures --
    /// Synthesizer's signature over the unsigned witness bytes.
    pub synthesizer_signature: Vec<u8>,
    /// Promotion signatures (sorted by key for determinism).
    pub promotion_signatures: Vec<Vec<u8>>,

    // -- Temporal --
    /// Epoch under which this witness was synthesized.
    pub epoch: SecurityEpoch,
    /// Synthesis timestamp (nanoseconds, monotonic).
    pub timestamp_ns: u64,

    // -- Content hash --
    /// Content hash of the canonical unsigned witness bytes.
    pub content_hash: ContentHash,

    // -- Metadata --
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

impl CapabilityWitness {
    /// Canonical bytes for signing/hashing (excludes signatures and content_hash).
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.schema_version.major.to_be_bytes());
        buf.extend_from_slice(&self.schema_version.minor.to_be_bytes());
        buf.extend_from_slice(self.extension_id.as_bytes());
        buf.extend_from_slice(self.policy_id.as_bytes());
        buf.push(self.lifecycle_state as u8);

        for cap in &self.required_capabilities {
            buf.extend_from_slice(cap.as_str().as_bytes());
            buf.push(0); // separator
        }
        buf.push(0xff); // section separator

        for cap in &self.denied_capabilities {
            buf.extend_from_slice(cap.as_str().as_bytes());
            buf.push(0);
        }
        buf.push(0xff);

        for po in &self.proof_obligations {
            buf.extend_from_slice(po.capability.as_str().as_bytes());
            buf.push(po.kind as u8);
            buf.extend_from_slice(po.proof_artifact_id.as_bytes());
            buf.extend_from_slice(po.artifact_hash.as_bytes());
        }
        buf.push(0xff);

        buf.extend_from_slice(&self.confidence.lower_millionths.to_be_bytes());
        buf.extend_from_slice(&self.confidence.upper_millionths.to_be_bytes());
        buf.extend_from_slice(&self.confidence.n_trials.to_be_bytes());
        buf.extend_from_slice(&self.confidence.n_successes.to_be_bytes());

        buf.extend_from_slice(&self.replay_seed.to_be_bytes());
        buf.extend_from_slice(self.transcript_hash.as_bytes());

        if let Some(ref rt) = self.rollback_token {
            buf.push(1);
            buf.extend_from_slice(rt.previous_witness_hash.as_bytes());
            buf.extend_from_slice(&rt.sequence.to_be_bytes());
        } else {
            buf.push(0);
        }

        buf.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());

        for (k, v) in &self.metadata {
            buf.extend_from_slice(k.as_bytes());
            buf.push(0);
            buf.extend_from_slice(v.as_bytes());
            buf.push(0);
        }

        buf
    }

    /// Canonical unsigned bytes for synthesis-bound signatures/integrity checks.
    pub fn synthesis_unsigned_bytes(&self) -> Vec<u8> {
        let mut synthesis_view = self.clone();
        synthesis_view.lifecycle_state = LifecycleState::Draft;
        // Strip metadata added during theorem evaluation
        synthesis_view
            .metadata
            .retain(|k, _| !k.starts_with("promotion_theorem."));
        // Strip proof obligations added during theorem evaluation
        synthesis_view
            .proof_obligations
            .retain(|po| po.kind != ProofKind::PolicyTheoremCheck);
        synthesis_view.unsigned_bytes()
    }

    /// Transition to a new lifecycle state.
    pub fn transition_to(&mut self, target: LifecycleState) -> Result<(), WitnessError> {
        if !self.lifecycle_state.can_transition_to(target) {
            return Err(WitnessError::InvalidTransition {
                from: self.lifecycle_state,
                to: target,
            });
        }
        if target == LifecycleState::Promoted {
            self.verify_promotion_theorem_gate()?;
        }
        self.lifecycle_state = target;
        Ok(())
    }

    fn expand_capability_lattice(
        capabilities: &BTreeSet<Capability>,
        capability_lattice: &BTreeMap<Capability, BTreeSet<Capability>>,
    ) -> BTreeSet<Capability> {
        let mut expanded = capabilities.clone();
        let mut queue: Vec<Capability> = capabilities.iter().cloned().collect();
        while let Some(capability) = queue.pop() {
            if let Some(implied) = capability_lattice.get(&capability) {
                for implied_capability in implied {
                    if expanded.insert(implied_capability.clone()) {
                        queue.push(implied_capability.clone());
                    }
                }
            }
        }
        expanded
    }

    fn dependency_transitive_closure(
        root: &Capability,
        dependencies: &BTreeMap<Capability, BTreeSet<Capability>>,
    ) -> BTreeSet<Capability> {
        let mut closure = BTreeSet::new();
        let mut queue = vec![root.clone()];
        while let Some(current) = queue.pop() {
            if let Some(next_hops) = dependencies.get(&current) {
                for next in next_hops {
                    if closure.insert(next.clone()) {
                        queue.push(next.clone());
                    }
                }
            }
        }
        closure
    }

    /// Evaluate deterministic theorem checks required for witness promotion.
    pub fn evaluate_promotion_theorems(
        &self,
        input: &PromotionTheoremInput,
    ) -> Result<PromotionTheoremReport, WitnessError> {
        let mut results = Vec::new();

        let mut source_union = BTreeSet::new();
        for source in &input.source_capability_sets {
            source_union.extend(source.capabilities.iter().cloned());
        }
        let source_union_lattice =
            Self::expand_capability_lattice(&source_union, &input.capability_lattice);

        let merge_excess = self
            .required_capabilities
            .difference(&source_union_lattice)
            .map(|cap| cap.as_str().to_string())
            .collect::<Vec<_>>();
        let merge_passed = merge_excess.is_empty();
        let merge_detail = if merge_passed {
            format!(
                "required envelope justified by {} source capability sets",
                input.source_capability_sets.len()
            )
        } else {
            format!(
                "required capabilities without source evidence: {}",
                merge_excess.join(",")
            )
        };
        results.push(
            self.build_theorem_result(
                PromotionTheoremKind::MergeLegality,
                merge_passed,
                merge_detail,
                (!merge_excess.is_empty())
                    .then(|| format!("required_minus_sources={}", merge_excess.join(","))),
            )?,
        );

        let manifest_lattice = Self::expand_capability_lattice(
            &input.manifest_capabilities,
            &input.capability_lattice,
        );
        let manifest_excess = self
            .required_capabilities
            .difference(&manifest_lattice)
            .map(|cap| cap.as_str().to_string())
            .collect::<Vec<_>>();
        let attenuation_passed = manifest_excess.is_empty();
        let attenuation_detail = if attenuation_passed {
            "required envelope attenuates to manifest capability envelope".to_string()
        } else {
            format!(
                "required capabilities exceed manifest envelope: {}",
                manifest_excess.join(",")
            )
        };
        results.push(
            self.build_theorem_result(
                PromotionTheoremKind::AttenuationLegality,
                attenuation_passed,
                attenuation_detail,
                (!manifest_excess.is_empty())
                    .then(|| format!("required_minus_manifest={}", manifest_excess.join(","))),
            )?,
        );

        let mut interfering_edges = Vec::new();
        for required in &self.required_capabilities {
            let dependencies =
                Self::dependency_transitive_closure(required, &input.non_interference_dependencies);
            for denied in dependencies.intersection(&self.denied_capabilities) {
                interfering_edges.push(format!("{required}->{denied}"));
            }
        }
        interfering_edges.sort();
        let non_interference_passed = interfering_edges.is_empty();
        let non_interference_detail = if non_interference_passed {
            "no denied capability dependencies found for retained capabilities".to_string()
        } else {
            format!(
                "denied capability dependencies detected: {}",
                interfering_edges.join(",")
            )
        };
        results.push(
            self.build_theorem_result(
                PromotionTheoremKind::NonInterference,
                non_interference_passed,
                non_interference_detail,
                (!interfering_edges.is_empty())
                    .then(|| format!("interfering_edges={}", interfering_edges.join(","))),
            )?,
        );

        let mut extensions = input.custom_extensions.clone();
        extensions.sort_by(|left, right| left.name.cmp(&right.name));
        for extension in extensions {
            let missing = extension
                .required_capabilities
                .difference(&self.required_capabilities)
                .map(|cap| cap.as_str().to_string())
                .collect::<Vec<_>>();
            let forbidden = extension
                .forbidden_capabilities
                .intersection(&self.required_capabilities)
                .map(|cap| cap.as_str().to_string())
                .collect::<Vec<_>>();
            let passed = missing.is_empty() && forbidden.is_empty();
            let detail = if passed {
                format!("custom theorem '{}' satisfied", extension.name)
            } else {
                format!(
                    "custom theorem '{}' failed (missing: [{}], forbidden: [{}])",
                    extension.name,
                    missing.join(","),
                    forbidden.join(",")
                )
            };
            let counterexample = if passed {
                None
            } else {
                Some(format!(
                    "missing=[{}];forbidden=[{}]",
                    missing.join(","),
                    forbidden.join(",")
                ))
            };
            results.push(self.build_theorem_result(
                PromotionTheoremKind::Custom(extension.name),
                passed,
                detail,
                counterexample,
            )?);
        }

        results.sort_by(|left, right| left.theorem.cmp(&right.theorem));
        let all_passed = results.iter().all(|result| result.passed);

        let report_artifact_hash = {
            let canonical = Self::theorem_report_canonical_bytes(self, &results, all_passed);
            ContentHash::compute(&canonical)
        };
        let report_artifact_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            WITNESS_THEOREM_REPORT_ZONE,
            &SchemaId::from_definition(WITNESS_THEOREM_REPORT_SCHEMA_DEF),
            report_artifact_hash.as_bytes(),
        )
        .map_err(|err| WitnessError::IdDerivation(err.to_string()))?;

        Ok(PromotionTheoremReport {
            results,
            all_passed,
            report_artifact_id,
            report_artifact_hash,
        })
    }

    /// Persist theorem-check outcomes into metadata and theorem proof obligations.
    pub fn apply_promotion_theorem_report(&mut self, report: &PromotionTheoremReport) {
        self.metadata.insert(
            "promotion_theorem.report_artifact_id".to_string(),
            report.report_artifact_id.to_string(),
        );
        self.metadata.insert(
            "promotion_theorem.report_artifact_hash".to_string(),
            report.report_artifact_hash.to_hex(),
        );
        self.metadata.insert(
            "promotion_theorem.all_passed".to_string(),
            if report.all_passed { "true" } else { "false" }.to_string(),
        );

        for result in &report.results {
            let key = format!("promotion_theorem.{}", result.theorem.metadata_key());
            self.metadata.insert(
                key.clone(),
                if result.passed { "pass" } else { "fail" }.to_string(),
            );
            self.metadata.insert(
                format!("{key}.artifact_id"),
                result.proof_artifact_id.to_string(),
            );
            self.metadata.insert(
                format!("{key}.artifact_hash"),
                result.artifact_hash.to_hex(),
            );
            self.metadata
                .insert(format!("{key}.detail"), result.detail.clone());
            if let Some(counterexample) = &result.counterexample {
                self.metadata
                    .insert(format!("{key}.counterexample"), counterexample.clone());
            }
        }

        if !report.all_passed {
            return;
        }

        let required = self
            .required_capabilities
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for capability in required {
            let theorem_already_covered = self.proof_obligations.iter().any(|proof| {
                proof.kind == ProofKind::PolicyTheoremCheck && proof.capability == capability
            });
            if theorem_already_covered {
                continue;
            }

            self.proof_obligations.push(ProofObligation {
                capability,
                kind: ProofKind::PolicyTheoremCheck,
                proof_artifact_id: report.report_artifact_id.clone(),
                justification: format!(
                    "{}: promotion theorem report passed",
                    WITNESS_THEOREM_COMPONENT
                ),
                artifact_hash: report.report_artifact_hash.clone(),
            });
        }
    }

    fn build_theorem_result(
        &self,
        theorem: PromotionTheoremKind,
        passed: bool,
        detail: String,
        counterexample: Option<String>,
    ) -> Result<PromotionTheoremResult, WitnessError> {
        let artifact_hash = ContentHash::compute(&Self::theorem_result_canonical_bytes(
            self,
            &theorem,
            passed,
            &detail,
            counterexample.as_deref(),
        ));
        let proof_artifact_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            WITNESS_THEOREM_RESULT_ZONE,
            &SchemaId::from_definition(WITNESS_THEOREM_SCHEMA_DEF),
            artifact_hash.as_bytes(),
        )
        .map_err(|err| WitnessError::IdDerivation(err.to_string()))?;

        Ok(PromotionTheoremResult {
            theorem,
            passed,
            detail,
            counterexample,
            proof_artifact_id,
            artifact_hash,
        })
    }

    fn theorem_result_canonical_bytes(
        witness: &CapabilityWitness,
        theorem: &PromotionTheoremKind,
        passed: bool,
        detail: &str,
        counterexample: Option<&str>,
    ) -> Vec<u8> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(witness.witness_id.as_bytes());
        canonical.extend_from_slice(witness.extension_id.as_bytes());
        canonical.extend_from_slice(witness.policy_id.as_bytes());
        canonical.extend_from_slice(witness.content_hash.as_bytes());
        canonical.extend_from_slice(theorem.to_string().as_bytes());
        canonical.push(0xff);
        canonical.push(u8::from(passed));
        canonical.extend_from_slice(detail.as_bytes());
        canonical.push(0xfe);
        if let Some(counterexample) = counterexample {
            canonical.extend_from_slice(counterexample.as_bytes());
        }
        canonical
    }

    fn theorem_report_canonical_bytes(
        witness: &CapabilityWitness,
        results: &[PromotionTheoremResult],
        all_passed: bool,
    ) -> Vec<u8> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(witness.witness_id.as_bytes());
        canonical.extend_from_slice(witness.content_hash.as_bytes());
        canonical.push(u8::from(all_passed));
        for result in results {
            canonical.extend_from_slice(result.theorem.to_string().as_bytes());
            canonical.push(0xff);
            canonical.push(u8::from(result.passed));
            canonical.extend_from_slice(result.proof_artifact_id.as_bytes());
            canonical.extend_from_slice(result.artifact_hash.as_bytes());
            canonical.push(0xfe);
        }
        canonical
    }

    fn verify_promotion_theorem_gate(&self) -> Result<(), WitnessError> {
        let required = [
            PromotionTheoremKind::MergeLegality,
            PromotionTheoremKind::AttenuationLegality,
            PromotionTheoremKind::NonInterference,
        ];

        let mut missing_checks = Vec::new();
        let mut failed_checks = Vec::new();
        for theorem in required {
            let key = format!("promotion_theorem.{}", theorem.metadata_key());
            match self.metadata.get(&key).map(String::as_str) {
                Some("pass") => {}
                Some(_) => failed_checks.push(theorem.to_string()),
                None => missing_checks.push(theorem.to_string()),
            }
        }

        if !missing_checks.is_empty() {
            missing_checks.sort();
            return Err(WitnessError::MissingPromotionTheoremProofs { missing_checks });
        }
        if !failed_checks.is_empty() {
            failed_checks.sort();
            return Err(WitnessError::PromotionTheoremFailed { failed_checks });
        }

        let mut missing_capability_proofs = Vec::new();
        for capability in &self.required_capabilities {
            let has_theorem_proof = self.proof_obligations.iter().any(|proof| {
                proof.kind == ProofKind::PolicyTheoremCheck && proof.capability == *capability
            });
            if !has_theorem_proof {
                missing_capability_proofs.push(capability.as_str().to_string());
            }
        }
        if !missing_capability_proofs.is_empty() {
            missing_capability_proofs.sort();
            return Err(WitnessError::MissingPromotionTheoremProofs {
                missing_checks: missing_capability_proofs,
            });
        }

        Ok(())
    }

    /// Verify the synthesizer signature.
    pub fn verify_synthesizer_signature(
        &self,
        verification_key: &crate::signature_preimage::VerificationKey,
    ) -> Result<(), WitnessError> {
        if self.synthesizer_signature.len() != 64 {
            return Err(WitnessError::SignatureInvalid {
                detail: "signature length is not 64 bytes".to_string(),
            });
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.synthesizer_signature);
        let sig = Signature::from_bytes(sig_bytes);
        let unsigned = self.synthesis_unsigned_bytes();
        verify_signature(verification_key, &unsigned, &sig).map_err(|e| {
            WitnessError::SignatureInvalid {
                detail: e.to_string(),
            }
        })
    }

    /// Verify content hash integrity.
    pub fn verify_integrity(&self) -> Result<(), WitnessError> {
        let computed = ContentHash::compute(&self.synthesis_unsigned_bytes());
        if computed == self.content_hash {
            Ok(())
        } else {
            Err(WitnessError::IntegrityFailure {
                expected: self.content_hash.to_hex(),
                actual: computed.to_hex(),
            })
        }
    }

    /// Check that every required capability has at least one proof obligation.
    pub fn verify_proof_coverage(&self) -> Result<(), WitnessError> {
        let covered: BTreeSet<&Capability> = self
            .proof_obligations
            .iter()
            .map(|po| &po.capability)
            .collect();
        for cap in &self.required_capabilities {
            if !covered.contains(cap) {
                return Err(WitnessError::MissingProofObligation {
                    capability: cap.as_str().to_string(),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WitnessBuilder — ergonomic construction
// ---------------------------------------------------------------------------

/// Builder for constructing `CapabilityWitness` artifacts.
pub struct WitnessBuilder {
    extension_id: EngineObjectId,
    policy_id: EngineObjectId,
    required: BTreeSet<Capability>,
    denied: BTreeSet<Capability>,
    proofs: Vec<ProofObligation>,
    denials: Vec<DenialRecord>,
    confidence: Option<ConfidenceInterval>,
    replay_seed: u64,
    transcript_hash: ContentHash,
    rollback_token: Option<RollbackToken>,
    epoch: SecurityEpoch,
    timestamp_ns: u64,
    signing_key: SigningKey,
    metadata: BTreeMap<String, String>,
}

impl WitnessBuilder {
    /// Create a new builder.
    pub fn new(
        extension_id: EngineObjectId,
        policy_id: EngineObjectId,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            extension_id,
            policy_id,
            required: BTreeSet::new(),
            denied: BTreeSet::new(),
            proofs: Vec::new(),
            denials: Vec::new(),
            confidence: None,
            replay_seed: 0,
            transcript_hash: ContentHash::compute(b""),
            rollback_token: None,
            epoch,
            timestamp_ns,
            signing_key,
            metadata: BTreeMap::new(),
        }
    }

    /// Add a required capability.
    pub fn require(mut self, cap: Capability) -> Self {
        self.required.insert(cap);
        self
    }

    /// Add multiple required capabilities.
    pub fn require_all(mut self, caps: impl IntoIterator<Item = Capability>) -> Self {
        self.required.extend(caps);
        self
    }

    /// Add a denied capability with reason.
    pub fn deny(mut self, cap: Capability, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        self.denied.insert(cap.clone());
        self.denials.push(DenialRecord {
            capability: cap,
            reason,
            evidence_id: None,
        });
        self
    }

    /// Add a proof obligation.
    pub fn proof(mut self, obligation: ProofObligation) -> Self {
        self.proofs.push(obligation);
        self
    }

    /// Set the confidence interval.
    pub fn confidence(mut self, ci: ConfidenceInterval) -> Self {
        self.confidence = Some(ci);
        self
    }

    /// Set the replay seed.
    pub fn replay_seed(mut self, seed: u64) -> Self {
        self.replay_seed = seed;
        self
    }

    /// Set the transcript hash.
    pub fn transcript_hash(mut self, hash: ContentHash) -> Self {
        self.transcript_hash = hash;
        self
    }

    /// Set the rollback token.
    pub fn rollback(mut self, token: RollbackToken) -> Self {
        self.rollback_token = Some(token);
        self
    }

    /// Add metadata.
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the witness, computing content hash, deriving ID, and signing.
    pub fn build(self) -> Result<CapabilityWitness, WitnessError> {
        if self.required.is_empty() {
            return Err(WitnessError::EmptyRequiredSet);
        }

        let confidence = self.confidence.unwrap_or(ConfidenceInterval {
            lower_millionths: 0,
            upper_millionths: 0,
            n_trials: 0,
            n_successes: 0,
        });

        // Build an unsigned witness first (with placeholder ID, sig, content_hash).
        let schema_id = SchemaId::from_definition(WITNESS_SCHEMA_DEF);
        let placeholder_id = engine_object_id::derive_id(
            ObjectDomain::Attestation,
            WITNESS_ZONE,
            &schema_id,
            b"placeholder",
        )
        .map_err(|e| WitnessError::IdDerivation(e.to_string()))?;

        let mut witness = CapabilityWitness {
            witness_id: placeholder_id,
            schema_version: WitnessSchemaVersion::CURRENT,
            extension_id: self.extension_id,
            policy_id: self.policy_id,
            lifecycle_state: LifecycleState::Draft,
            required_capabilities: self.required,
            denied_capabilities: self.denied,
            proof_obligations: self.proofs,
            denial_records: self.denials,
            confidence,
            replay_seed: self.replay_seed,
            transcript_hash: self.transcript_hash,
            rollback_token: self.rollback_token,
            synthesizer_signature: Vec::new(),
            promotion_signatures: Vec::new(),
            epoch: self.epoch,
            timestamp_ns: self.timestamp_ns,
            content_hash: ContentHash::compute(b""),
            metadata: self.metadata,
        };

        // Compute content hash from unsigned bytes.
        let unsigned = witness.unsigned_bytes();
        witness.content_hash = ContentHash::compute(&unsigned);

        // Derive deterministic witness ID.
        let mut canonical = Vec::new();
        canonical.extend_from_slice(witness.extension_id.as_bytes());
        canonical.extend_from_slice(witness.policy_id.as_bytes());
        canonical.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        canonical.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        canonical.extend_from_slice(witness.content_hash.as_bytes());

        witness.witness_id = engine_object_id::derive_id(
            ObjectDomain::Attestation,
            WITNESS_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| WitnessError::IdDerivation(e.to_string()))?;

        // Sign.
        let sig = sign_preimage(&self.signing_key, &unsigned).map_err(|e| {
            WitnessError::SignatureInvalid {
                detail: format!("signing: {e}"),
            }
        })?;
        witness.synthesizer_signature = sig.to_bytes().to_vec();

        Ok(witness)
    }
}

// ---------------------------------------------------------------------------
// WitnessValidator — validation logic
// ---------------------------------------------------------------------------

/// Validates capability witness artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessValidator {
    /// Supported schema version.
    pub supported_version: WitnessSchemaVersion,
    /// Minimum confidence lower bound (millionths).
    pub min_confidence_millionths: i64,
}

impl WitnessValidator {
    /// Create a validator with default settings.
    pub fn new() -> Self {
        Self {
            supported_version: WitnessSchemaVersion::CURRENT,
            min_confidence_millionths: 900_000, // 0.90
        }
    }

    /// Full validation of a witness artifact.
    pub fn validate(&self, witness: &CapabilityWitness) -> Vec<WitnessError> {
        let mut errors = Vec::new();

        // Schema compatibility.
        if !self
            .supported_version
            .is_compatible_with(&witness.schema_version)
        {
            errors.push(WitnessError::IncompatibleSchema {
                witness: witness.schema_version,
                reader: self.supported_version,
            });
        }

        // Required set non-empty.
        if witness.required_capabilities.is_empty() {
            errors.push(WitnessError::EmptyRequiredSet);
        }

        // Proof coverage.
        if let Err(e) = witness.verify_proof_coverage() {
            errors.push(e);
        }

        // Integrity.
        if let Err(e) = witness.verify_integrity() {
            errors.push(e);
        }

        // Confidence threshold.
        if !witness
            .confidence
            .meets_threshold(self.min_confidence_millionths)
            && witness.confidence.n_trials > 0
        {
            errors.push(WitnessError::InvalidConfidence {
                reason: format!(
                    "lower bound {} < required {}",
                    witness.confidence.lower_millionths, self.min_confidence_millionths
                ),
            });
        }

        errors
    }
}

impl Default for WitnessValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// WitnessStore — in-memory store for witness lifecycle management
// ---------------------------------------------------------------------------

/// In-memory store for capability witnesses, keyed by witness_id.
///
/// Uses `Vec` storage with linear scan to avoid serde issues with
/// `BTreeMap<EngineObjectId, _>` keys in JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WitnessStore {
    witnesses: Vec<CapabilityWitness>,
    /// Active witness ID per extension (extension_id, witness_id).
    active_pairs: Vec<(EngineObjectId, EngineObjectId)>,
}

impl WitnessStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a witness into the store.
    pub fn insert(&mut self, witness: CapabilityWitness) {
        let wid = witness.witness_id.clone();
        if witness.lifecycle_state == LifecycleState::Active {
            let ext_id = witness.extension_id.clone();
            // Update or insert the active pair.
            if let Some(pair) = self.active_pairs.iter_mut().find(|(e, _)| *e == ext_id) {
                pair.1 = wid.clone();
            } else {
                self.active_pairs.push((ext_id, wid.clone()));
            }
        }
        // Replace existing witness with same ID, or append.
        if let Some(existing) = self.witnesses.iter_mut().find(|w| w.witness_id == wid) {
            *existing = witness;
        } else {
            self.witnesses.push(witness);
        }
    }

    /// Get a witness by ID.
    pub fn get(&self, witness_id: &EngineObjectId) -> Option<&CapabilityWitness> {
        self.witnesses.iter().find(|w| w.witness_id == *witness_id)
    }

    fn get_mut(&mut self, witness_id: &EngineObjectId) -> Option<&mut CapabilityWitness> {
        self.witnesses
            .iter_mut()
            .find(|w| w.witness_id == *witness_id)
    }

    /// Get the active witness for an extension.
    pub fn active_for_extension(
        &self,
        extension_id: &EngineObjectId,
    ) -> Option<&CapabilityWitness> {
        self.active_pairs
            .iter()
            .find(|(e, _)| *e == *extension_id)
            .and_then(|(_, wid)| self.get(wid))
    }

    /// Transition a witness to a new lifecycle state.
    pub fn transition(
        &mut self,
        witness_id: &EngineObjectId,
        target: LifecycleState,
    ) -> Result<(), WitnessError> {
        let witness = self
            .get_mut(witness_id)
            .ok_or_else(|| WitnessError::IdDerivation("witness not found".to_string()))?;

        let old_state = witness.lifecycle_state;
        let ext_id = witness.extension_id.clone();
        witness.transition_to(target)?;

        // Track active witness per extension.
        if target == LifecycleState::Active {
            // Find any previously active witness for this extension.
            let prev_wid = self
                .active_pairs
                .iter_mut()
                .find(|(e, _)| *e == ext_id)
                .map(|pair| {
                    let old = pair.1.clone();
                    pair.1 = witness_id.clone();
                    old
                });
            if prev_wid.is_none() {
                self.active_pairs.push((ext_id.clone(), witness_id.clone()));
            }
            // Supersede the previous active witness.
            if let Some(prev_wid) = prev_wid
                && prev_wid != *witness_id
                && let Some(prev) = self.get_mut(&prev_wid)
                && prev.lifecycle_state == LifecycleState::Active
            {
                prev.lifecycle_state = LifecycleState::Superseded;
            }
        } else if old_state == LifecycleState::Active {
            // Removing from active (revoked).
            let current_active = self
                .active_pairs
                .iter()
                .find(|(e, _)| *e == ext_id)
                .map(|(_, w)| w.clone());
            if current_active.as_ref() == Some(witness_id) {
                self.active_pairs.retain(|(e, _)| *e != ext_id);
            }
        }

        Ok(())
    }

    /// Number of witnesses in the store.
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    /// All witnesses.
    pub fn iter(&self) -> impl Iterator<Item = (&EngineObjectId, &CapabilityWitness)> {
        self.witnesses.iter().map(|w| (&w.witness_id, w))
    }

    /// Witnesses by lifecycle state.
    pub fn by_state(&self, state: LifecycleState) -> Vec<&CapabilityWitness> {
        self.witnesses
            .iter()
            .filter(|w| w.lifecycle_state == state)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// WitnessIndexStore — storage-adapter backed witness/index persistence
// ---------------------------------------------------------------------------

const WITNESS_INDEX_SCHEMA_VERSION: u32 = 1;
const TABLE_WITNESSES: &str = "witnesses";
const TABLE_WITNESS_BY_ID: &str = "witness_by_id";
const TABLE_WITNESS_BY_CAPABILITY: &str = "witness_by_capability";
const TABLE_WITNESS_BY_EXTENSION: &str = "witness_by_extension";
const TABLE_WITNESS_ESCROW_RECEIPTS: &str = "witness_escrow_receipts";

/// Persisted witness record for `StoreKind::PlasWitness`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessIndexRecord {
    pub witness_id: EngineObjectId,
    pub extension_id: EngineObjectId,
    pub policy_id: EngineObjectId,
    pub epoch: SecurityEpoch,
    pub lifecycle_state: LifecycleState,
    pub promotion_timestamp_ns: u64,
    pub content_hash: ContentHash,
    pub witness: CapabilityWitness,
}

impl WitnessIndexRecord {
    fn cursor_key(&self) -> String {
        format!(
            "{:020}:{}:{}",
            self.promotion_timestamp_ns,
            self.content_hash.to_hex(),
            hex::encode(self.witness_id.as_bytes())
        )
    }
}

/// Canonical receipt record for replay joins with witness state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEscrowReceiptRecord {
    pub receipt_id: String,
    pub extension_id: EngineObjectId,
    pub capability: Option<Capability>,
    pub decision_kind: String,
    pub outcome: String,
    pub timestamp_ns: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub error_code: Option<String>,
}

impl CapabilityEscrowReceiptRecord {
    fn sort_key(&self) -> String {
        format!("{:020}:{}", self.timestamp_ns, self.receipt_id)
    }
}

/// Deterministic query selector for witness retrieval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessIndexQuery {
    pub extension_id: Option<EngineObjectId>,
    pub policy_id: Option<EngineObjectId>,
    pub epoch: Option<SecurityEpoch>,
    pub lifecycle_state: Option<LifecycleState>,
    pub capability: Option<Capability>,
    pub start_timestamp_ns: Option<u64>,
    pub end_timestamp_ns: Option<u64>,
    pub include_revoked: bool,
    pub cursor: Option<String>,
    pub limit: usize,
}

impl Default for WitnessIndexQuery {
    fn default() -> Self {
        Self {
            extension_id: None,
            policy_id: None,
            epoch: None,
            lifecycle_state: None,
            capability: None,
            start_timestamp_ns: None,
            end_timestamp_ns: None,
            include_revoked: true,
            cursor: None,
            limit: 128,
        }
    }
}

/// Page of deterministically ordered witness records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessIndexPage {
    pub records: Vec<WitnessIndexRecord>,
    pub next_cursor: Option<String>,
}

/// Replay join query for witness state + escrow receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReplayJoinQuery {
    pub extension_id: EngineObjectId,
    pub start_timestamp_ns: Option<u64>,
    pub end_timestamp_ns: Option<u64>,
    pub include_revoked: bool,
}

/// Replay join output row for one witness window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReplayJoinRow {
    pub witness: WitnessIndexRecord,
    pub receipts: Vec<CapabilityEscrowReceiptRecord>,
}

/// Structured event emitted by witness index operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessIndexEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Error taxonomy for witness/index persistence and replay joins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessIndexError {
    Storage(StorageError),
    Serialization { operation: String, detail: String },
    CorruptRecord { key: String, detail: String },
    InvalidInput { detail: String },
}

impl WitnessIndexError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Storage(_) => "FE-WITIDX-0001",
            Self::Serialization { .. } => "FE-WITIDX-0002",
            Self::CorruptRecord { .. } => "FE-WITIDX-0003",
            Self::InvalidInput { .. } => "FE-WITIDX-0004",
        }
    }
}

impl fmt::Display for WitnessIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::Serialization { operation, detail } => {
                write!(f, "serialization error during {operation}: {detail}")
            }
            Self::CorruptRecord { key, detail } => {
                write!(f, "corrupt record `{key}`: {detail}")
            }
            Self::InvalidInput { detail } => write!(f, "invalid input: {detail}"),
        }
    }
}

impl std::error::Error for WitnessIndexError {}

impl From<StorageError> for WitnessIndexError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

/// Typed PLAS witness/index store backed by the storage-adapter contract.
#[derive(Debug)]
pub struct WitnessIndexStore<A: StorageAdapter> {
    adapter: A,
    events: Vec<WitnessIndexEvent>,
}

impl<A: StorageAdapter> WitnessIndexStore<A> {
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            events: Vec::new(),
        }
    }

    pub fn into_inner(self) -> A {
        self.adapter
    }

    pub fn events(&self) -> &[WitnessIndexEvent] {
        &self.events
    }

    pub fn adapter_mut(&mut self) -> &mut A {
        &mut self.adapter
    }

    pub fn ensure_schema_version(&self) -> Result<(), WitnessIndexError> {
        self.adapter
            .ensure_schema_version(WITNESS_INDEX_SCHEMA_VERSION)
            .map_err(WitnessIndexError::from)
    }

    pub fn migrate_schema(
        &mut self,
        target_version: u32,
        context: &EventContext,
    ) -> Result<MigrationReceipt, WitnessIndexError> {
        let result = self
            .adapter
            .migrate_to(target_version)
            .map_err(WitnessIndexError::from);
        self.emit_event(
            context,
            "migrate_schema",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Persist a witness plus deterministic index rows.
    pub fn index_witness(
        &mut self,
        witness: &CapabilityWitness,
        promotion_timestamp_ns: u64,
        context: &EventContext,
    ) -> Result<WitnessIndexRecord, WitnessIndexError> {
        let result = (|| {
            witness
                .verify_integrity()
                .map_err(|err| WitnessIndexError::InvalidInput {
                    detail: format!("witness integrity verification failed: {err}"),
                })?;

            let record = WitnessIndexRecord {
                witness_id: witness.witness_id.clone(),
                extension_id: witness.extension_id.clone(),
                policy_id: witness.policy_id.clone(),
                epoch: witness.epoch,
                lifecycle_state: witness.lifecycle_state,
                promotion_timestamp_ns,
                content_hash: witness.content_hash.clone(),
                witness: witness.clone(),
            };

            let record_key = witness_record_key(&record);
            let mut entries = Vec::new();

            let mut witness_metadata = witness_index_table_metadata(TABLE_WITNESSES);
            witness_metadata.insert(
                "witness_id".to_string(),
                hex::encode(record.witness_id.as_bytes()),
            );
            witness_metadata.insert(
                "extension_id".to_string(),
                hex::encode(record.extension_id.as_bytes()),
            );
            witness_metadata.insert(
                "policy_id".to_string(),
                hex::encode(record.policy_id.as_bytes()),
            );
            witness_metadata.insert("epoch".to_string(), record.epoch.as_u64().to_string());
            witness_metadata.insert(
                "lifecycle_state".to_string(),
                record.lifecycle_state.to_string(),
            );
            witness_metadata.insert(
                "promotion_timestamp_ns".to_string(),
                record.promotion_timestamp_ns.to_string(),
            );
            witness_metadata.insert("content_hash".to_string(), record.content_hash.to_hex());
            let witness_value =
                serde_json::to_vec(&record).map_err(|err| WitnessIndexError::Serialization {
                    operation: "serialize witness index record".to_string(),
                    detail: err.to_string(),
                })?;
            entries.push(BatchPutEntry {
                key: record_key.clone(),
                value: witness_value,
                metadata: witness_metadata,
            });

            entries.push(BatchPutEntry {
                key: witness_by_id_key(&record.witness_id),
                value: record_key.as_bytes().to_vec(),
                metadata: witness_index_table_metadata(TABLE_WITNESS_BY_ID),
            });
            entries.push(BatchPutEntry {
                key: witness_by_extension_key(&record),
                value: record_key.as_bytes().to_vec(),
                metadata: witness_index_table_metadata(TABLE_WITNESS_BY_EXTENSION),
            });

            for capability in &record.witness.required_capabilities {
                entries.push(BatchPutEntry {
                    key: witness_by_capability_key(capability, &record),
                    value: record_key.as_bytes().to_vec(),
                    metadata: witness_index_table_metadata(TABLE_WITNESS_BY_CAPABILITY),
                });
            }

            self.adapter
                .put_batch(StoreKind::PlasWitness, entries, context)
                .map_err(WitnessIndexError::from)?;

            Ok(record)
        })();

        self.emit_event(
            context,
            "index_witness",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Persist an escrow/grant/deny receipt for replay-join queries.
    pub fn index_escrow_receipt(
        &mut self,
        receipt: CapabilityEscrowReceiptRecord,
        context: &EventContext,
    ) -> Result<(), WitnessIndexError> {
        let result = (|| {
            if receipt.receipt_id.trim().is_empty() {
                return Err(WitnessIndexError::InvalidInput {
                    detail: "receipt_id cannot be empty".to_string(),
                });
            }
            if receipt.decision_kind.trim().is_empty() {
                return Err(WitnessIndexError::InvalidInput {
                    detail: "decision_kind cannot be empty".to_string(),
                });
            }
            if receipt.outcome.trim().is_empty() {
                return Err(WitnessIndexError::InvalidInput {
                    detail: "outcome cannot be empty".to_string(),
                });
            }

            let key = escrow_receipt_key(
                &receipt.extension_id,
                receipt.timestamp_ns,
                &receipt.receipt_id,
            );
            let mut metadata = witness_index_table_metadata(TABLE_WITNESS_ESCROW_RECEIPTS);
            metadata.insert(
                "extension_id".to_string(),
                hex::encode(receipt.extension_id.as_bytes()),
            );
            metadata.insert("decision_kind".to_string(), receipt.decision_kind.clone());
            metadata.insert("outcome".to_string(), receipt.outcome.clone());
            metadata.insert("timestamp_ns".to_string(), receipt.timestamp_ns.to_string());
            if let Some(capability) = &receipt.capability {
                metadata.insert("capability".to_string(), capability.as_str().to_string());
            }

            let value =
                serde_json::to_vec(&receipt).map_err(|err| WitnessIndexError::Serialization {
                    operation: "serialize escrow receipt record".to_string(),
                    detail: err.to_string(),
                })?;
            self.adapter
                .put(StoreKind::PlasWitness, key, value, metadata, context)
                .map_err(WitnessIndexError::from)?;
            Ok(())
        })();

        self.emit_event(
            context,
            "index_escrow_receipt",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Lookup one witness by content-addressed witness id.
    pub fn witness_by_id(
        &mut self,
        witness_id: &EngineObjectId,
        context: &EventContext,
    ) -> Result<Option<WitnessIndexRecord>, WitnessIndexError> {
        let result = (|| {
            let Some(pointer) = self.adapter.get(
                StoreKind::PlasWitness,
                &witness_by_id_key(witness_id),
                context,
            )?
            else {
                return Ok(None);
            };
            let pointed_key = String::from_utf8(pointer.value).map_err(|err| {
                WitnessIndexError::CorruptRecord {
                    key: pointer.key,
                    detail: err.to_string(),
                }
            })?;
            self.read_witness_record(&pointed_key, context)
        })();

        self.emit_event(
            context,
            "witness_by_id",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Deterministic witness retrieval with cursor pagination.
    pub fn query_witnesses(
        &mut self,
        query: &WitnessIndexQuery,
        context: &EventContext,
    ) -> Result<WitnessIndexPage, WitnessIndexError> {
        let result = (|| {
            if query.limit == 0 {
                return Err(WitnessIndexError::InvalidInput {
                    detail: "query limit cannot be zero".to_string(),
                });
            }
            let mut keyed = self.collect_filtered_witnesses(query, context)?;
            keyed.sort_by(|(a, _), (b, _)| a.cmp(b));
            if let Some(cursor) = &query.cursor {
                keyed.retain(|(key, _)| key > cursor);
            }

            let has_more = keyed.len() > query.limit;
            keyed.truncate(query.limit);
            let next_cursor = if has_more {
                keyed.last().map(|(key, _)| key.clone())
            } else {
                None
            };
            let records = keyed.into_iter().map(|(_, record)| record).collect();
            Ok(WitnessIndexPage {
                records,
                next_cursor,
            })
        })();

        self.emit_event(
            context,
            "query_witnesses",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Deterministic replay join between witness state windows and escrow receipts.
    pub fn replay_join(
        &mut self,
        query: &WitnessReplayJoinQuery,
        context: &EventContext,
    ) -> Result<Vec<WitnessReplayJoinRow>, WitnessIndexError> {
        let result = (|| {
            let mut witness_query = WitnessIndexQuery {
                extension_id: Some(query.extension_id.clone()),
                include_revoked: query.include_revoked,
                limit: usize::MAX,
                ..WitnessIndexQuery::default()
            };
            // Ignore cursor for full replay windows.
            witness_query.cursor = None;
            let mut witnesses: Vec<WitnessIndexRecord> = self
                .collect_filtered_witnesses(&witness_query, context)?
                .into_iter()
                .map(|(_, record)| record)
                .collect();
            witnesses.sort_by_key(|a| a.cursor_key());

            let start_ns = query.start_timestamp_ns.unwrap_or(0);
            let end_ns = query.end_timestamp_ns.unwrap_or(u64::MAX);
            if start_ns > end_ns {
                return Err(WitnessIndexError::InvalidInput {
                    detail: "start_timestamp_ns cannot exceed end_timestamp_ns".to_string(),
                });
            }

            let mut receipts = self.escrow_receipts_for_extension(&query.extension_id, context)?;
            receipts.retain(|receipt| {
                receipt.timestamp_ns >= start_ns && receipt.timestamp_ns <= end_ns
            });
            receipts.sort_by_key(|a| a.sort_key());

            let mut rows = Vec::new();
            for (idx, witness) in witnesses.iter().enumerate() {
                let window_start = witness.promotion_timestamp_ns;
                let window_end = witnesses
                    .get(idx + 1)
                    .map(|next| next.promotion_timestamp_ns)
                    .unwrap_or(u64::MAX);

                let effective_start = window_start.max(start_ns);
                let effective_end_exclusive = window_end.min(end_ns.saturating_add(1));
                if effective_start >= effective_end_exclusive {
                    continue;
                }

                let mut window_receipts = Vec::new();
                for receipt in &receipts {
                    if receipt.timestamp_ns >= effective_start
                        && receipt.timestamp_ns < effective_end_exclusive
                    {
                        window_receipts.push(receipt.clone());
                    }
                }
                rows.push(WitnessReplayJoinRow {
                    witness: witness.clone(),
                    receipts: window_receipts,
                });
            }
            rows.sort_by_key(|a| a.witness.cursor_key());
            Ok(rows)
        })();

        self.emit_event(
            context,
            "replay_join",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    /// Deterministic snapshot hash for conformance checks.
    pub fn deterministic_snapshot_hash(
        &mut self,
        extension_id: &EngineObjectId,
        context: &EventContext,
    ) -> Result<String, WitnessIndexError> {
        let query = WitnessIndexQuery {
            extension_id: Some(extension_id.clone()),
            include_revoked: true,
            limit: usize::MAX,
            ..WitnessIndexQuery::default()
        };
        let mut witnesses: Vec<WitnessIndexRecord> = self
            .collect_filtered_witnesses(&query, context)?
            .into_iter()
            .map(|(_, record)| record)
            .collect();
        witnesses.sort_by_key(|a| a.cursor_key());
        let mut receipts = self.escrow_receipts_for_extension(extension_id, context)?;
        receipts.sort_by_key(|a| a.sort_key());

        let payload = serde_json::to_vec(&(witnesses, receipts)).map_err(|err| {
            WitnessIndexError::Serialization {
                operation: "serialize witness snapshot hash payload".to_string(),
                detail: err.to_string(),
            }
        })?;
        Ok(ContentHash::compute(&payload).to_hex())
    }

    fn collect_filtered_witnesses(
        &mut self,
        query: &WitnessIndexQuery,
        context: &EventContext,
    ) -> Result<Vec<(String, WitnessIndexRecord)>, WitnessIndexError> {
        let mut records = if let Some(capability) = &query.capability {
            self.load_witnesses_from_pointer_prefix(
                &witness_by_capability_prefix(capability),
                context,
            )?
        } else if let Some(extension_id) = &query.extension_id {
            self.load_witnesses_from_pointer_prefix(
                &witness_by_extension_prefix(extension_id),
                context,
            )?
        } else {
            self.load_witnesses_from_table(context)?
        };

        records.retain(|record| witness_matches_query(record, query));

        // Deduplicate by witness id in case index rows overlap.
        let mut dedup = BTreeMap::<Vec<u8>, WitnessIndexRecord>::new();
        for record in records {
            dedup.insert(record.witness_id.as_bytes().to_vec(), record);
        }

        let out = dedup
            .into_values()
            .map(|record| (record.cursor_key(), record))
            .collect();
        Ok(out)
    }

    fn load_witnesses_from_table(
        &mut self,
        context: &EventContext,
    ) -> Result<Vec<WitnessIndexRecord>, WitnessIndexError> {
        let rows = self.adapter.query(
            StoreKind::PlasWitness,
            &StoreQuery {
                key_prefix: Some(format!("{TABLE_WITNESSES}/")),
                metadata_filters: BTreeMap::new(),
                limit: None,
            },
            context,
        )?;

        let mut records = Vec::new();
        for row in rows {
            let decoded: WitnessIndexRecord =
                serde_json::from_slice(&row.value).map_err(|err| {
                    WitnessIndexError::CorruptRecord {
                        key: row.key,
                        detail: err.to_string(),
                    }
                })?;
            records.push(decoded);
        }
        Ok(records)
    }

    fn load_witnesses_from_pointer_prefix(
        &mut self,
        prefix: &str,
        context: &EventContext,
    ) -> Result<Vec<WitnessIndexRecord>, WitnessIndexError> {
        let pointers = self.adapter.query(
            StoreKind::PlasWitness,
            &StoreQuery {
                key_prefix: Some(prefix.to_string()),
                metadata_filters: BTreeMap::new(),
                limit: None,
            },
            context,
        )?;

        let mut records = Vec::new();
        for pointer in pointers {
            let pointed_key = String::from_utf8(pointer.value).map_err(|err| {
                WitnessIndexError::CorruptRecord {
                    key: pointer.key,
                    detail: err.to_string(),
                }
            })?;
            if let Some(record) = self.read_witness_record(&pointed_key, context)? {
                records.push(record);
            }
        }
        Ok(records)
    }

    fn read_witness_record(
        &mut self,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<WitnessIndexRecord>, WitnessIndexError> {
        let Some(record) = self.adapter.get(StoreKind::PlasWitness, key, context)? else {
            return Ok(None);
        };
        let decoded: WitnessIndexRecord = serde_json::from_slice(&record.value).map_err(|err| {
            WitnessIndexError::CorruptRecord {
                key: record.key,
                detail: err.to_string(),
            }
        })?;
        Ok(Some(decoded))
    }

    fn escrow_receipts_for_extension(
        &mut self,
        extension_id: &EngineObjectId,
        context: &EventContext,
    ) -> Result<Vec<CapabilityEscrowReceiptRecord>, WitnessIndexError> {
        let rows = self.adapter.query(
            StoreKind::PlasWitness,
            &StoreQuery {
                key_prefix: Some(escrow_receipt_prefix(extension_id)),
                metadata_filters: BTreeMap::new(),
                limit: None,
            },
            context,
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let decoded: CapabilityEscrowReceiptRecord = serde_json::from_slice(&row.value)
                .map_err(|err| WitnessIndexError::CorruptRecord {
                    key: row.key,
                    detail: err.to_string(),
                })?;
            receipts.push(decoded);
        }
        Ok(receipts)
    }

    fn emit_event(
        &mut self,
        context: &EventContext,
        event: &str,
        outcome: &str,
        error: Option<&WitnessIndexError>,
    ) {
        self.events.push(WitnessIndexEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "capability_witness_index".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error.map(|err| err.code().to_string()),
        });
    }
}

fn witness_matches_query(record: &WitnessIndexRecord, query: &WitnessIndexQuery) -> bool {
    if let Some(extension_id) = &query.extension_id
        && record.extension_id != *extension_id
    {
        return false;
    }
    if let Some(policy_id) = &query.policy_id
        && record.policy_id != *policy_id
    {
        return false;
    }
    if let Some(epoch) = query.epoch
        && record.epoch != epoch
    {
        return false;
    }
    if let Some(lifecycle_state) = query.lifecycle_state
        && record.lifecycle_state != lifecycle_state
    {
        return false;
    }
    if !query.include_revoked && record.lifecycle_state == LifecycleState::Revoked {
        return false;
    }
    if let Some(capability) = &query.capability
        && !record.witness.required_capabilities.contains(capability)
    {
        return false;
    }
    if let Some(start_timestamp_ns) = query.start_timestamp_ns
        && record.promotion_timestamp_ns < start_timestamp_ns
    {
        return false;
    }
    if let Some(end_timestamp_ns) = query.end_timestamp_ns
        && record.promotion_timestamp_ns > end_timestamp_ns
    {
        return false;
    }
    true
}

fn witness_index_table_metadata(table: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("table".to_string(), table.to_string());
    metadata
}

fn object_id_segment(object_id: &EngineObjectId) -> String {
    hex::encode(object_id.as_bytes())
}

fn capability_segment(capability: &Capability) -> String {
    hex::encode(capability.as_str().as_bytes())
}

fn witness_record_key(record: &WitnessIndexRecord) -> String {
    format!(
        "{TABLE_WITNESSES}/{}/{:020}/{:020}/{}",
        object_id_segment(&record.extension_id),
        record.epoch.as_u64(),
        record.promotion_timestamp_ns,
        record.content_hash.to_hex()
    )
}

fn witness_by_id_key(witness_id: &EngineObjectId) -> String {
    format!("{TABLE_WITNESS_BY_ID}/{}", object_id_segment(witness_id))
}

fn witness_by_extension_prefix(extension_id: &EngineObjectId) -> String {
    format!(
        "{TABLE_WITNESS_BY_EXTENSION}/{}/",
        object_id_segment(extension_id)
    )
}

fn witness_by_extension_key(record: &WitnessIndexRecord) -> String {
    format!(
        "{}{:020}/{}/{}",
        witness_by_extension_prefix(&record.extension_id),
        record.promotion_timestamp_ns,
        record.content_hash.to_hex(),
        object_id_segment(&record.witness_id)
    )
}

fn witness_by_capability_prefix(capability: &Capability) -> String {
    format!(
        "{TABLE_WITNESS_BY_CAPABILITY}/{}/",
        capability_segment(capability)
    )
}

fn witness_by_capability_key(capability: &Capability, record: &WitnessIndexRecord) -> String {
    format!(
        "{}/{}/{:020}/{}/{}",
        witness_by_capability_prefix(capability).trim_end_matches('/'),
        object_id_segment(&record.extension_id),
        record.promotion_timestamp_ns,
        record.content_hash.to_hex(),
        object_id_segment(&record.witness_id)
    )
}

fn escrow_receipt_prefix(extension_id: &EngineObjectId) -> String {
    format!(
        "{TABLE_WITNESS_ESCROW_RECEIPTS}/{}/",
        object_id_segment(extension_id)
    )
}

fn escrow_receipt_key(
    extension_id: &EngineObjectId,
    timestamp_ns: u64,
    receipt_id: &str,
) -> String {
    format!(
        "{}{:020}/{}",
        escrow_receipt_prefix(extension_id),
        timestamp_ns,
        receipt_id
    )
}

// ---------------------------------------------------------------------------
// Witness publication pipeline
// ---------------------------------------------------------------------------

/// Kind of transparency-log entry emitted by witness publication flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PublicationEntryKind {
    /// A witness was published after promotion.
    Publish,
    /// A previously published witness was revoked.
    Revoke,
}

impl PublicationEntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Revoke => "revoke",
        }
    }
}

impl fmt::Display for PublicationEntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Append-only log entry for witness publication transparency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationLogEntry {
    pub sequence: u64,
    pub kind: PublicationEntryKind,
    pub witness_id: EngineObjectId,
    pub extension_id: EngineObjectId,
    pub policy_id: EngineObjectId,
    pub witness_epoch: SecurityEpoch,
    pub witness_content_hash: ContentHash,
    pub timestamp_ns: u64,
    pub revocation_reason: Option<String>,
    pub predecessor_leaf_hash: ContentHash,
    pub leaf_hash: ContentHash,
}

/// Parameters for [`PublicationLogEntry::canonical_bytes`] and
/// [`PublicationLogEntry::compute_leaf_hash`].
struct PublicationLeafInput<'a> {
    sequence: u64,
    kind: PublicationEntryKind,
    witness_id: &'a EngineObjectId,
    extension_id: &'a EngineObjectId,
    policy_id: &'a EngineObjectId,
    witness_epoch: SecurityEpoch,
    witness_content_hash: &'a ContentHash,
    timestamp_ns: u64,
    revocation_reason: Option<&'a str>,
    predecessor_leaf_hash: &'a ContentHash,
}

impl PublicationLogEntry {
    fn canonical_bytes(input: &PublicationLeafInput<'_>) -> Vec<u8> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&input.sequence.to_be_bytes());
        canonical.extend_from_slice(input.kind.as_str().as_bytes());
        canonical.push(0xff);
        canonical.extend_from_slice(input.witness_id.as_bytes());
        canonical.extend_from_slice(input.extension_id.as_bytes());
        canonical.extend_from_slice(input.policy_id.as_bytes());
        canonical.extend_from_slice(&input.witness_epoch.as_u64().to_be_bytes());
        canonical.extend_from_slice(input.witness_content_hash.as_bytes());
        canonical.extend_from_slice(&input.timestamp_ns.to_be_bytes());
        if let Some(reason) = input.revocation_reason {
            canonical.extend_from_slice(reason.as_bytes());
        }
        canonical.push(0xff);
        canonical.extend_from_slice(input.predecessor_leaf_hash.as_bytes());
        canonical
    }

    fn compute_leaf_hash(input: &PublicationLeafInput<'_>) -> ContentHash {
        let canonical = Self::canonical_bytes(input);
        ContentHash::compute(&canonical)
    }

    fn verify_leaf_hash(&self) -> bool {
        let expected = Self::compute_leaf_hash(&PublicationLeafInput {
            sequence: self.sequence,
            kind: self.kind,
            witness_id: &self.witness_id,
            extension_id: &self.extension_id,
            policy_id: &self.policy_id,
            witness_epoch: self.witness_epoch,
            witness_content_hash: &self.witness_content_hash,
            timestamp_ns: self.timestamp_ns,
            revocation_reason: self.revocation_reason.as_deref(),
            predecessor_leaf_hash: &self.predecessor_leaf_hash,
        });
        expected == self.leaf_hash
    }
}

/// Signed tree-head snapshot for the witness transparency log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessTreeHead {
    pub checkpoint_seq: u64,
    pub log_length: u64,
    pub mmr_root: ContentHash,
    pub timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub head_hash: ContentHash,
    pub signature: Vec<u8>,
}

impl WitnessTreeHead {
    fn preimage(
        checkpoint_seq: u64,
        log_length: u64,
        mmr_root: &ContentHash,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Vec<u8> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"capability_witness_tree_head|");
        preimage.extend_from_slice(&checkpoint_seq.to_be_bytes());
        preimage.push(0xff);
        preimage.extend_from_slice(&log_length.to_be_bytes());
        preimage.push(0xff);
        preimage.extend_from_slice(mmr_root.as_bytes());
        preimage.push(0xff);
        preimage.extend_from_slice(&timestamp_ns.to_be_bytes());
        preimage.push(0xff);
        preimage.extend_from_slice(&epoch.as_u64().to_be_bytes());
        preimage
    }

    fn verify_signature(
        &self,
        verification_key: &VerificationKey,
    ) -> Result<(), WitnessPublicationError> {
        if self.signature.len() != 64 {
            return Err(WitnessPublicationError::TreeHeadSignatureInvalid {
                detail: "signature length is not 64 bytes".to_string(),
            });
        }
        let preimage = Self::preimage(
            self.checkpoint_seq,
            self.log_length,
            &self.mmr_root,
            self.timestamp_ns,
            self.epoch,
        );
        let expected_hash = ContentHash::compute(&preimage);
        if expected_hash != self.head_hash {
            return Err(WitnessPublicationError::TreeHeadHashMismatch {
                expected: expected_hash.to_hex(),
                actual: self.head_hash.to_hex(),
            });
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(bytes);
        verify_signature(verification_key, &preimage, &sig).map_err(|e| {
            WitnessPublicationError::TreeHeadSignatureInvalid {
                detail: e.to_string(),
            }
        })
    }
}

/// Consistency proof edge from one signed tree-head to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProofLink {
    pub from_head: WitnessTreeHead,
    pub to_head: WitnessTreeHead,
    pub proof: MmrProof,
}

/// Transparency proof bundle for a single publish/revoke entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyProofBundle {
    pub log_entry: PublicationLogEntry,
    pub inclusion_proof: MmrProof,
    pub tree_head: WitnessTreeHead,
    pub consistency_chain: Vec<ConsistencyProofLink>,
}

/// Published capability witness plus transparency/verifier artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedWitnessArtifact {
    /// Content-addressed publication identifier.
    pub publication_id: EngineObjectId,
    /// Original witness payload.
    pub witness: CapabilityWitness,
    /// Publication proof bundle.
    pub publication_proof: TransparencyProofBundle,
    /// Revocation proof bundle, present if revoked.
    pub revocation_proof: Option<TransparencyProofBundle>,
    /// Signature bundle copied from witness for independent verifiers.
    pub signature_bundle: Vec<Vec<u8>>,
    /// Hash over publication artifact fields.
    pub published_hash: ContentHash,
}

impl PublishedWitnessArtifact {
    pub fn is_revoked(&self) -> bool {
        self.revocation_proof.is_some()
    }
}

/// Query filter for published witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPublicationQuery {
    pub extension_id: Option<EngineObjectId>,
    pub policy_id: Option<EngineObjectId>,
    pub epoch: Option<SecurityEpoch>,
    pub content_hash: Option<ContentHash>,
    pub include_revoked: bool,
}

impl WitnessPublicationQuery {
    pub fn all() -> Self {
        Self {
            extension_id: None,
            policy_id: None,
            epoch: None,
            content_hash: None,
            include_revoked: true,
        }
    }
}

/// Configuration for witness publication pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPublicationConfig {
    /// Emit signed checkpoints every N log entries.
    pub checkpoint_interval: u64,
    /// Policy identifier used for governance/evidence event attribution.
    pub policy_id: String,
    /// Optional governance ledger integration.
    pub governance_ledger_config: Option<GovernanceLedgerConfig>,
}

impl Default for WitnessPublicationConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 8,
            policy_id: "capability-witness-policy".to_string(),
            governance_ledger_config: None,
        }
    }
}

/// Structured event emitted by witness publication pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPublicationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub timestamp_ns: u64,
}

/// Errors returned by witness publication pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessPublicationError {
    InvalidConfig { reason: String },
    WitnessNotPromoted { state: LifecycleState },
    DuplicatePublication { witness_id: EngineObjectId },
    PublicationNotFound { publication_id: EngineObjectId },
    WitnessNotPublished { witness_id: EngineObjectId },
    AlreadyRevoked { witness_id: EngineObjectId },
    EmptyRevocationReason,
    IdDerivation(String),
    InclusionProofFailed { detail: String },
    ConsistencyProofFailed { detail: String },
    TreeHeadSignatureInvalid { detail: String },
    TreeHeadHashMismatch { expected: String, actual: String },
    LogEntryHashMismatch,
    WitnessVerificationFailed { detail: String },
    GovernanceLedger { detail: String },
    EvidenceLedger { detail: String },
}

impl WitnessPublicationError {
    fn from_mmr(err: MmrProofError, for_consistency: bool) -> Self {
        if for_consistency {
            Self::ConsistencyProofFailed {
                detail: err.to_string(),
            }
        } else {
            Self::InclusionProofFailed {
                detail: err.to_string(),
            }
        }
    }
}

impl fmt::Display for WitnessPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { reason } => write!(f, "invalid publication config: {reason}"),
            Self::WitnessNotPromoted { state } => {
                write!(
                    f,
                    "witness must be promoted/active before publication, got {state}"
                )
            }
            Self::DuplicatePublication { witness_id } => {
                write!(f, "witness already published: {witness_id}")
            }
            Self::PublicationNotFound { publication_id } => {
                write!(f, "publication not found: {publication_id}")
            }
            Self::WitnessNotPublished { witness_id } => {
                write!(f, "witness not published: {witness_id}")
            }
            Self::AlreadyRevoked { witness_id } => {
                write!(f, "witness already revoked: {witness_id}")
            }
            Self::EmptyRevocationReason => write!(f, "revocation reason must not be empty"),
            Self::IdDerivation(detail) => write!(f, "id derivation failed: {detail}"),
            Self::InclusionProofFailed { detail } => {
                write!(f, "inclusion proof failed: {detail}")
            }
            Self::ConsistencyProofFailed { detail } => {
                write!(f, "consistency proof failed: {detail}")
            }
            Self::TreeHeadSignatureInvalid { detail } => {
                write!(f, "tree-head signature invalid: {detail}")
            }
            Self::TreeHeadHashMismatch { expected, actual } => {
                write!(
                    f,
                    "tree-head hash mismatch: expected={expected} actual={actual}"
                )
            }
            Self::LogEntryHashMismatch => write!(f, "log entry hash mismatch"),
            Self::WitnessVerificationFailed { detail } => {
                write!(f, "witness verification failed: {detail}")
            }
            Self::GovernanceLedger { detail } => write!(f, "governance ledger: {detail}"),
            Self::EvidenceLedger { detail } => write!(f, "evidence ledger: {detail}"),
        }
    }
}

impl std::error::Error for WitnessPublicationError {}

/// Signed witness publication engine with append-only transparency proofs.
#[derive(Debug)]
pub struct WitnessPublicationPipeline {
    config: WitnessPublicationConfig,
    current_epoch: SecurityEpoch,
    head_signing_key: SigningKey,
    log_entries: Vec<PublicationLogEntry>,
    mmr: MerkleMountainRange,
    checkpoints: Vec<WitnessTreeHead>,
    publications: Vec<PublishedWitnessArtifact>,
    evidence_ledger: InMemoryLedger,
    governance_ledger: Option<GovernanceAuditLedger>,
    events: Vec<WitnessPublicationEvent>,
}

impl WitnessPublicationPipeline {
    /// Create a new publication pipeline.
    pub fn new(
        current_epoch: SecurityEpoch,
        head_signing_key: SigningKey,
        config: WitnessPublicationConfig,
    ) -> Result<Self, WitnessPublicationError> {
        if config.checkpoint_interval == 0 {
            return Err(WitnessPublicationError::InvalidConfig {
                reason: "checkpoint_interval must be >= 1".to_string(),
            });
        }
        if config.policy_id.trim().is_empty() {
            return Err(WitnessPublicationError::InvalidConfig {
                reason: "policy_id must not be empty".to_string(),
            });
        }
        let governance_ledger = if let Some(cfg) = config.governance_ledger_config.clone() {
            Some(GovernanceAuditLedger::new(cfg).map_err(|e| {
                WitnessPublicationError::GovernanceLedger {
                    detail: e.to_string(),
                }
            })?)
        } else {
            None
        };

        Ok(Self {
            config,
            current_epoch,
            head_signing_key,
            log_entries: Vec::new(),
            mmr: MerkleMountainRange::new(current_epoch.as_u64()),
            checkpoints: Vec::new(),
            publications: Vec::new(),
            evidence_ledger: InMemoryLedger::new(),
            governance_ledger,
            events: Vec::new(),
        })
    }

    pub fn publications(&self) -> &[PublishedWitnessArtifact] {
        &self.publications
    }

    pub fn checkpoints(&self) -> &[WitnessTreeHead] {
        &self.checkpoints
    }

    pub fn log_entries(&self) -> &[PublicationLogEntry] {
        &self.log_entries
    }

    pub fn events(&self) -> &[WitnessPublicationEvent] {
        &self.events
    }

    pub fn evidence_entries(&self) -> &[EvidenceEntry] {
        self.evidence_ledger.entries()
    }

    pub fn governance_ledger(&self) -> Option<&GovernanceAuditLedger> {
        self.governance_ledger.as_ref()
    }

    /// Publish a promoted witness into the transparency log.
    pub fn publish_witness(
        &mut self,
        witness: CapabilityWitness,
        timestamp_ns: u64,
    ) -> Result<EngineObjectId, WitnessPublicationError> {
        if !matches!(
            witness.lifecycle_state,
            LifecycleState::Promoted | LifecycleState::Active
        ) {
            return Err(WitnessPublicationError::WitnessNotPromoted {
                state: witness.lifecycle_state,
            });
        }
        if self
            .publications
            .iter()
            .any(|p| p.witness.witness_id == witness.witness_id)
        {
            return Err(WitnessPublicationError::DuplicatePublication {
                witness_id: witness.witness_id.clone(),
            });
        }

        let publication_proof =
            self.append_log_entry(&witness, PublicationEntryKind::Publish, None, timestamp_ns)?;
        let publication_id = self.derive_publication_id(&witness, &publication_proof)?;
        let mut signature_bundle = Vec::new();
        signature_bundle.push(witness.synthesizer_signature.clone());
        signature_bundle.extend(witness.promotion_signatures.clone());

        let mut artifact = PublishedWitnessArtifact {
            publication_id: publication_id.clone(),
            witness,
            publication_proof,
            revocation_proof: None,
            signature_bundle,
            published_hash: ContentHash::compute(b"pending"),
        };
        artifact.published_hash = Self::compute_published_hash(&artifact);

        self.emit_evidence_entry(&artifact, &artifact.publication_proof, "publish")?;
        self.emit_governance_entry(&artifact, &artifact.publication_proof, "publish")?;
        self.events.push(WitnessPublicationEvent {
            trace_id: format!("trace:{}", artifact.publication_id),
            decision_id: format!("publish:{}", artifact.witness.witness_id),
            policy_id: self.config.policy_id.clone(),
            component: "capability_witness_publication".to_string(),
            event: "publish_witness".to_string(),
            outcome: "success".to_string(),
            error_code: None,
            timestamp_ns,
        });

        self.publications.push(artifact);
        Ok(publication_id)
    }

    /// Append a signed revocation entry for a previously published witness.
    pub fn revoke_witness(
        &mut self,
        witness_id: &EngineObjectId,
        reason: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<(), WitnessPublicationError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(WitnessPublicationError::EmptyRevocationReason);
        }

        let idx = self
            .publications
            .iter()
            .position(|p| p.witness.witness_id == *witness_id)
            .ok_or_else(|| WitnessPublicationError::WitnessNotPublished {
                witness_id: witness_id.clone(),
            })?;
        if self.publications[idx].revocation_proof.is_some() {
            return Err(WitnessPublicationError::AlreadyRevoked {
                witness_id: witness_id.clone(),
            });
        }

        let witness = self.publications[idx].witness.clone();
        let revocation_proof = self.append_log_entry(
            &witness,
            PublicationEntryKind::Revoke,
            Some(reason),
            timestamp_ns,
        )?;
        self.publications[idx].revocation_proof = Some(revocation_proof.clone());
        self.publications[idx].published_hash =
            Self::compute_published_hash(&self.publications[idx]);

        let updated = self.publications[idx].clone();
        self.emit_evidence_entry(&updated, &revocation_proof, "revoke")?;
        self.emit_governance_entry(&updated, &revocation_proof, "revoke")?;
        self.events.push(WitnessPublicationEvent {
            trace_id: format!("trace:{}", updated.publication_id),
            decision_id: format!("revoke:{}", updated.witness.witness_id),
            policy_id: self.config.policy_id.clone(),
            component: "capability_witness_publication".to_string(),
            event: "revoke_witness".to_string(),
            outcome: "success".to_string(),
            error_code: None,
            timestamp_ns,
        });
        Ok(())
    }

    /// Query publication records by extension/policy/epoch/content hash.
    pub fn query(&self, query: &WitnessPublicationQuery) -> Vec<&PublishedWitnessArtifact> {
        self.publications
            .iter()
            .filter(|artifact| {
                query
                    .extension_id
                    .as_ref()
                    .is_none_or(|id| artifact.witness.extension_id == *id)
            })
            .filter(|artifact| {
                query
                    .policy_id
                    .as_ref()
                    .is_none_or(|id| artifact.witness.policy_id == *id)
            })
            .filter(|artifact| {
                query
                    .epoch
                    .is_none_or(|epoch| artifact.witness.epoch == epoch)
            })
            .filter(|artifact| {
                query.content_hash.as_ref().is_none_or(|hash| {
                    artifact.witness.content_hash == *hash || artifact.published_hash == *hash
                })
            })
            .filter(|artifact| query.include_revoked || !artifact.is_revoked())
            .collect()
    }

    /// Verify a publication artifact, including inclusion and consistency proofs.
    pub fn verify_publication(
        &self,
        publication_id: &EngineObjectId,
        witness_verification_key: &VerificationKey,
        tree_head_verification_key: &VerificationKey,
    ) -> Result<(), WitnessPublicationError> {
        let artifact = self
            .publications
            .iter()
            .find(|p| p.publication_id == *publication_id)
            .ok_or_else(|| WitnessPublicationError::PublicationNotFound {
                publication_id: publication_id.clone(),
            })?;
        Self::verify_artifact(
            artifact,
            witness_verification_key,
            tree_head_verification_key,
        )
    }

    /// Verify a publication artifact without pipeline state.
    pub fn verify_artifact(
        artifact: &PublishedWitnessArtifact,
        witness_verification_key: &VerificationKey,
        tree_head_verification_key: &VerificationKey,
    ) -> Result<(), WitnessPublicationError> {
        Self::verify_witness_synthesis_binding(&artifact.witness, witness_verification_key)?;

        Self::verify_proof_bundle(&artifact.publication_proof, tree_head_verification_key)?;
        if let Some(ref revocation_bundle) = artifact.revocation_proof {
            if revocation_bundle.log_entry.kind != PublicationEntryKind::Revoke {
                return Err(WitnessPublicationError::WitnessVerificationFailed {
                    detail: "revocation bundle does not contain revoke entry".to_string(),
                });
            }
            if revocation_bundle.log_entry.witness_id != artifact.witness.witness_id {
                return Err(WitnessPublicationError::WitnessVerificationFailed {
                    detail: "revocation witness_id mismatch".to_string(),
                });
            }
            Self::verify_proof_bundle(revocation_bundle, tree_head_verification_key)?;
        }
        Ok(())
    }

    fn verify_witness_synthesis_binding(
        witness: &CapabilityWitness,
        witness_verification_key: &VerificationKey,
    ) -> Result<(), WitnessPublicationError> {
        // Witnesses are synthesized/signed in Draft state and may transition
        // afterward; verify against the canonical synthesis view.
        let unsigned = witness.synthesis_unsigned_bytes();

        let computed = ContentHash::compute(&unsigned);
        if computed != witness.content_hash {
            return Err(WitnessPublicationError::WitnessVerificationFailed {
                detail: format!(
                    "content hash mismatch against synthesis view: expected={}, actual={}",
                    witness.content_hash.to_hex(),
                    computed.to_hex()
                ),
            });
        }

        if witness.synthesizer_signature.len() != 64 {
            return Err(WitnessPublicationError::WitnessVerificationFailed {
                detail: "synthesizer signature length is not 64 bytes".to_string(),
            });
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&witness.synthesizer_signature);
        let sig = Signature::from_bytes(sig_bytes);
        verify_signature(witness_verification_key, &unsigned, &sig).map_err(|e| {
            WitnessPublicationError::WitnessVerificationFailed {
                detail: e.to_string(),
            }
        })?;
        Ok(())
    }

    fn verify_proof_bundle(
        bundle: &TransparencyProofBundle,
        tree_head_verification_key: &VerificationKey,
    ) -> Result<(), WitnessPublicationError> {
        if !bundle.log_entry.verify_leaf_hash() {
            return Err(WitnessPublicationError::LogEntryHashMismatch);
        }
        verify_inclusion(
            &bundle.log_entry.leaf_hash,
            bundle.log_entry.sequence,
            &bundle.inclusion_proof,
        )
        .map_err(|e| WitnessPublicationError::from_mmr(e, false))?;
        if bundle.inclusion_proof.root_hash != bundle.tree_head.mmr_root {
            return Err(WitnessPublicationError::InclusionProofFailed {
                detail: "inclusion root does not match tree head".to_string(),
            });
        }
        bundle
            .tree_head
            .verify_signature(tree_head_verification_key)?;

        for link in &bundle.consistency_chain {
            link.from_head
                .verify_signature(tree_head_verification_key)?;
            link.to_head.verify_signature(tree_head_verification_key)?;
            if link.proof.marker_index != link.from_head.log_length {
                return Err(WitnessPublicationError::ConsistencyProofFailed {
                    detail: "consistency proof marker does not match from_head length".to_string(),
                });
            }
            if link.proof.root_hash != link.to_head.mmr_root {
                return Err(WitnessPublicationError::ConsistencyProofFailed {
                    detail: "consistency proof root does not match to_head root".to_string(),
                });
            }
            verify_consistency(&link.from_head.mmr_root, &link.proof)
                .map_err(|e| WitnessPublicationError::from_mmr(e, true))?;
        }
        Ok(())
    }

    fn append_log_entry(
        &mut self,
        witness: &CapabilityWitness,
        kind: PublicationEntryKind,
        revocation_reason: Option<String>,
        timestamp_ns: u64,
    ) -> Result<TransparencyProofBundle, WitnessPublicationError> {
        let sequence = self.log_entries.len() as u64;
        let predecessor_leaf_hash = self
            .log_entries
            .last()
            .map(|e| e.leaf_hash.clone())
            .unwrap_or(ContentHash([0u8; 32]));
        let leaf_hash = PublicationLogEntry::compute_leaf_hash(&PublicationLeafInput {
            sequence,
            kind,
            witness_id: &witness.witness_id,
            extension_id: &witness.extension_id,
            policy_id: &witness.policy_id,
            witness_epoch: witness.epoch,
            witness_content_hash: &witness.content_hash,
            timestamp_ns,
            revocation_reason: revocation_reason.as_deref(),
            predecessor_leaf_hash: &predecessor_leaf_hash,
        });
        let entry = PublicationLogEntry {
            sequence,
            kind,
            witness_id: witness.witness_id.clone(),
            extension_id: witness.extension_id.clone(),
            policy_id: witness.policy_id.clone(),
            witness_epoch: witness.epoch,
            witness_content_hash: witness.content_hash.clone(),
            timestamp_ns,
            revocation_reason,
            predecessor_leaf_hash,
            leaf_hash: leaf_hash.clone(),
        };
        self.log_entries.push(entry.clone());
        self.mmr.append(leaf_hash);

        let inclusion_proof = self
            .mmr
            .inclusion_proof(sequence)
            .map_err(|e| WitnessPublicationError::from_mmr(e, false))?;
        let tree_head = self.create_tree_head(timestamp_ns)?;
        let consistency_chain = self.build_consistency_chain(&tree_head)?;

        if (self.log_entries.len() as u64).is_multiple_of(self.config.checkpoint_interval) {
            self.checkpoints.push(tree_head.clone());
        }

        Ok(TransparencyProofBundle {
            log_entry: entry,
            inclusion_proof,
            tree_head,
            consistency_chain,
        })
    }

    fn create_tree_head(
        &self,
        timestamp_ns: u64,
    ) -> Result<WitnessTreeHead, WitnessPublicationError> {
        let mmr_root = self
            .mmr
            .root_hash()
            .map_err(|e| WitnessPublicationError::from_mmr(e, false))?;
        let checkpoint_seq = self.checkpoints.len() as u64 + 1;
        let log_length = self.log_entries.len() as u64;
        let preimage = WitnessTreeHead::preimage(
            checkpoint_seq,
            log_length,
            &mmr_root,
            timestamp_ns,
            self.current_epoch,
        );
        let head_hash = ContentHash::compute(&preimage);
        let sig = sign_preimage(&self.head_signing_key, &preimage).map_err(|e| {
            WitnessPublicationError::TreeHeadSignatureInvalid {
                detail: e.to_string(),
            }
        })?;
        Ok(WitnessTreeHead {
            checkpoint_seq,
            log_length,
            mmr_root,
            timestamp_ns,
            epoch: self.current_epoch,
            head_hash,
            signature: sig.to_bytes().to_vec(),
        })
    }

    fn build_consistency_chain(
        &self,
        to_head: &WitnessTreeHead,
    ) -> Result<Vec<ConsistencyProofLink>, WitnessPublicationError> {
        let Some(from_head) = self.checkpoints.last() else {
            return Ok(Vec::new());
        };
        if from_head.log_length == 0 || from_head.log_length >= to_head.log_length {
            return Ok(Vec::new());
        }
        let proof = self
            .mmr
            .consistency_proof(from_head.log_length)
            .map_err(|e| WitnessPublicationError::from_mmr(e, true))?;
        Ok(vec![ConsistencyProofLink {
            from_head: from_head.clone(),
            to_head: to_head.clone(),
            proof,
        }])
    }

    fn derive_publication_id(
        &self,
        witness: &CapabilityWitness,
        bundle: &TransparencyProofBundle,
    ) -> Result<EngineObjectId, WitnessPublicationError> {
        let schema_id = SchemaId::from_definition(WITNESS_PUBLICATION_SCHEMA_DEF);
        let mut canonical = Vec::new();
        canonical.extend_from_slice(witness.witness_id.as_bytes());
        canonical.extend_from_slice(witness.content_hash.as_bytes());
        canonical.extend_from_slice(bundle.log_entry.leaf_hash.as_bytes());
        canonical.extend_from_slice(bundle.tree_head.mmr_root.as_bytes());
        canonical.extend_from_slice(&bundle.tree_head.log_length.to_be_bytes());
        engine_object_id::derive_id(
            ObjectDomain::Attestation,
            WITNESS_PUBLICATION_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| WitnessPublicationError::IdDerivation(e.to_string()))
    }

    fn compute_published_hash(artifact: &PublishedWitnessArtifact) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(artifact.publication_id.as_bytes());
        canonical.extend_from_slice(artifact.witness.witness_id.as_bytes());
        canonical.extend_from_slice(artifact.witness.content_hash.as_bytes());
        canonical.extend_from_slice(artifact.publication_proof.log_entry.leaf_hash.as_bytes());
        canonical.extend_from_slice(artifact.publication_proof.tree_head.mmr_root.as_bytes());
        if let Some(ref revocation) = artifact.revocation_proof {
            canonical.extend_from_slice(revocation.log_entry.leaf_hash.as_bytes());
            canonical.extend_from_slice(revocation.tree_head.mmr_root.as_bytes());
        }
        ContentHash::compute(&canonical)
    }

    fn emit_evidence_entry(
        &mut self,
        artifact: &PublishedWitnessArtifact,
        bundle: &TransparencyProofBundle,
        action: &str,
    ) -> Result<(), WitnessPublicationError> {
        let chosen_loss = if action == "revoke" { 5_000 } else { 50_000 };
        let alt_loss = if action == "revoke" { 200_000 } else { 100_000 };
        let decision_id = format!("{action}:{}", artifact.publication_id);
        let mut builder = EvidenceEntryBuilder::new(
            format!("trace:{}", artifact.publication_id),
            decision_id,
            self.config.policy_id.clone(),
            artifact.witness.epoch,
            DecisionType::CapabilityDecision,
        )
        .timestamp_ns(bundle.tree_head.timestamp_ns)
        .candidate(CandidateAction::new(action, chosen_loss))
        .candidate(CandidateAction::new("hold", alt_loss))
        .chosen(ChosenAction {
            action_name: action.to_string(),
            expected_loss_millionths: chosen_loss,
            rationale: format!("witness {action} action selected"),
        })
        .witness(EvidenceWitness {
            witness_id: artifact.witness.witness_id.to_string(),
            witness_type: "capability_witness".to_string(),
            value: artifact.witness.content_hash.to_hex(),
        })
        .meta("publication_id", artifact.publication_id.to_string())
        .meta("entry_kind", bundle.log_entry.kind.as_str())
        .meta("leaf_hash", bundle.log_entry.leaf_hash.to_hex())
        .meta("mmr_root", bundle.tree_head.mmr_root.to_hex())
        .meta(
            "inclusion_proof_stream_length",
            bundle.inclusion_proof.stream_length.to_string(),
        );

        if let Some(reason) = bundle.log_entry.revocation_reason.as_ref() {
            builder = builder.meta("revocation_reason", reason);
        }

        let entry = builder
            .build()
            .map_err(|e| WitnessPublicationError::EvidenceLedger {
                detail: e.to_string(),
            })?;
        self.evidence_ledger
            .emit(entry)
            .map_err(|e| WitnessPublicationError::EvidenceLedger {
                detail: e.to_string(),
            })
    }

    fn emit_governance_entry(
        &mut self,
        artifact: &PublishedWitnessArtifact,
        bundle: &TransparencyProofBundle,
        action: &str,
    ) -> Result<(), WitnessPublicationError> {
        let Some(ref mut ledger) = self.governance_ledger else {
            return Ok(());
        };
        let decision_type = match action {
            "revoke" => GovernanceDecisionType::Kill,
            _ => GovernanceDecisionType::Promote,
        };
        let confidence = artifact
            .witness
            .confidence
            .lower_millionths
            .clamp(0, 1_000_000) as u64;
        let risk = if action == "revoke" { 1_000_000 } else { 0 };
        let rationale = GovernanceRationale::for_automatic_decision(
            format!("capability witness {action}"),
            confidence,
            risk,
            vec![format!(
                "inclusion proof root {}",
                bundle.tree_head.mmr_root.to_hex()
            )],
            Vec::new(),
        );
        ledger
            .append(GovernanceLedgerInput {
                decision_id: format!("witness-{action}-seq-{}", bundle.log_entry.sequence),
                moonshot_id: format!("witness:{}", artifact.witness.extension_id),
                decision_type,
                actor: GovernanceActor::System("capability_witness_publication".to_string()),
                rationale,
                scorecard_snapshot: ScorecardSnapshot {
                    ev_millionths: 0,
                    confidence_millionths: confidence,
                    risk_of_harm_millionths: risk,
                    implementation_friction_millionths: 0,
                    cross_initiative_interference_millionths: 0,
                    operational_burden_millionths: 0,
                },
                artifact_references: vec![
                    artifact.publication_id.to_string(),
                    artifact.witness.witness_id.to_string(),
                    bundle.log_entry.leaf_hash.to_hex(),
                    bundle.tree_head.mmr_root.to_hex(),
                ],
                timestamp_ns: bundle.tree_head.timestamp_ns,
                moonshot_started_at_ns: None,
            })
            .map_err(|e| WitnessPublicationError::GovernanceLedger {
                detail: e.to_string(),
            })?;
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::SigningKey;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_signing_key() -> SigningKey {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        SigningKey::from_bytes(key)
    }

    fn test_extension_id() -> EngineObjectId {
        engine_object_id::derive_id(
            ObjectDomain::Attestation,
            "test-ext",
            &SchemaId::from_definition(b"TestExtension.v1"),
            b"ext-001",
        )
        .unwrap()
    }

    fn test_policy_id() -> EngineObjectId {
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test-policy",
            &SchemaId::from_definition(b"TestPolicy.v1"),
            b"policy-001",
        )
        .unwrap()
    }

    fn test_proof_artifact_id() -> EngineObjectId {
        engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            "test-proof",
            &SchemaId::from_definition(b"TestProof.v1"),
            b"proof-001",
        )
        .unwrap()
    }

    fn make_proof(cap: &Capability) -> ProofObligation {
        ProofObligation {
            capability: cap.clone(),
            kind: ProofKind::DynamicAblation,
            proof_artifact_id: test_proof_artifact_id(),
            justification: format!("Ablation test: removing {} breaks behavior", cap),
            artifact_hash: ContentHash::compute(format!("proof-for-{}", cap).as_bytes()),
        }
    }

    fn promotion_theorem_input_for(witness: &CapabilityWitness) -> PromotionTheoremInput {
        PromotionTheoremInput {
            source_capability_sets: vec![SourceCapabilitySet {
                source_id: "ablation-evidence".to_string(),
                capabilities: witness.required_capabilities.clone(),
            }],
            manifest_capabilities: witness.required_capabilities.clone(),
            capability_lattice: BTreeMap::new(),
            non_interference_dependencies: BTreeMap::new(),
            custom_extensions: Vec::new(),
        }
    }

    fn apply_passing_promotion_theorems(witness: &mut CapabilityWitness) {
        let report = witness
            .evaluate_promotion_theorems(&promotion_theorem_input_for(witness))
            .expect("theorem check report");
        assert!(report.all_passed, "expected passing theorem report");
        witness.apply_promotion_theorem_report(&report);
        rebind_witness(witness, &test_signing_key());
    }

    fn rebind_witness(witness: &mut CapabilityWitness, signing_key: &SigningKey) {
        let unsigned = witness.synthesis_unsigned_bytes();
        witness.content_hash = ContentHash::compute(&unsigned);

        let mut canonical = Vec::new();
        canonical.extend_from_slice(witness.extension_id.as_bytes());
        canonical.extend_from_slice(witness.policy_id.as_bytes());
        canonical.extend_from_slice(&witness.epoch.as_u64().to_be_bytes());
        canonical.extend_from_slice(&witness.timestamp_ns.to_be_bytes());
        canonical.extend_from_slice(witness.content_hash.as_bytes());
        witness.witness_id = engine_object_id::derive_id(
            ObjectDomain::Attestation,
            WITNESS_ZONE,
            &SchemaId::from_definition(WITNESS_SCHEMA_DEF),
            &canonical,
        )
        .expect("derive witness id after mutation");

        let signature = sign_preimage(signing_key, &unsigned).expect("sign witness after mutation");
        witness.synthesizer_signature = signature.to_bytes().to_vec();
    }

    fn build_test_witness() -> CapabilityWitness {
        let cap_read = Capability::new("read-data");
        let cap_write = Capability::new("write-data");
        let cap_admin = Capability::new("admin-access");

        let mut witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(100),
            5000,
            test_signing_key(),
        )
        .require(cap_read.clone())
        .require(cap_write.clone())
        .deny(cap_admin, "Extension does not require admin access")
        .proof(make_proof(&cap_read))
        .proof(make_proof(&cap_write))
        .confidence(ConfidenceInterval::from_trials(200, 195))
        .replay_seed(42)
        .transcript_hash(ContentHash::compute(b"synthesis-transcript"))
        .meta("synthesizer", "plas-v1")
        .build()
        .unwrap();
        apply_passing_promotion_theorems(&mut witness);
        witness
    }

    // -----------------------------------------------------------------------
    // WitnessSchemaVersion tests
    // -----------------------------------------------------------------------

    #[test]
    fn schema_version_current() {
        let v = WitnessSchemaVersion::CURRENT;
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
    }

    #[test]
    fn schema_version_compatible_same() {
        let v = WitnessSchemaVersion::CURRENT;
        assert!(v.is_compatible_with(&v));
    }

    #[test]
    fn schema_version_compatible_higher_minor() {
        let reader = WitnessSchemaVersion { major: 1, minor: 1 };
        let witness = WitnessSchemaVersion { major: 1, minor: 0 };
        assert!(reader.is_compatible_with(&witness));
    }

    #[test]
    fn schema_version_incompatible_lower_minor() {
        let reader = WitnessSchemaVersion { major: 1, minor: 0 };
        let witness = WitnessSchemaVersion { major: 1, minor: 1 };
        assert!(!reader.is_compatible_with(&witness));
    }

    #[test]
    fn schema_version_incompatible_different_major() {
        let reader = WitnessSchemaVersion { major: 2, minor: 0 };
        let witness = WitnessSchemaVersion { major: 1, minor: 0 };
        assert!(!reader.is_compatible_with(&witness));
    }

    #[test]
    fn schema_version_display() {
        let v = WitnessSchemaVersion { major: 1, minor: 2 };
        assert_eq!(v.to_string(), "1.2");
    }

    // -----------------------------------------------------------------------
    // LifecycleState tests
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_display() {
        assert_eq!(LifecycleState::Draft.to_string(), "draft");
        assert_eq!(LifecycleState::Validated.to_string(), "validated");
        assert_eq!(LifecycleState::Promoted.to_string(), "promoted");
        assert_eq!(LifecycleState::Active.to_string(), "active");
        assert_eq!(LifecycleState::Superseded.to_string(), "superseded");
        assert_eq!(LifecycleState::Revoked.to_string(), "revoked");
    }

    #[test]
    fn lifecycle_terminal_states() {
        assert!(!LifecycleState::Draft.is_terminal());
        assert!(!LifecycleState::Active.is_terminal());
        assert!(LifecycleState::Superseded.is_terminal());
        assert!(LifecycleState::Revoked.is_terminal());
    }

    #[test]
    fn lifecycle_active_states() {
        assert!(!LifecycleState::Draft.is_active());
        assert!(LifecycleState::Active.is_active());
        assert!(!LifecycleState::Revoked.is_active());
    }

    #[test]
    fn lifecycle_valid_transitions() {
        assert!(LifecycleState::Draft.can_transition_to(LifecycleState::Validated));
        assert!(!LifecycleState::Draft.can_transition_to(LifecycleState::Active));
        assert!(LifecycleState::Validated.can_transition_to(LifecycleState::Promoted));
        assert!(LifecycleState::Promoted.can_transition_to(LifecycleState::Active));
        assert!(LifecycleState::Active.can_transition_to(LifecycleState::Superseded));
        assert!(LifecycleState::Active.can_transition_to(LifecycleState::Revoked));
        assert!(!LifecycleState::Superseded.can_transition_to(LifecycleState::Active));
        assert!(!LifecycleState::Revoked.can_transition_to(LifecycleState::Active));
    }

    #[test]
    fn lifecycle_full_happy_path() {
        let mut witness = build_test_witness();
        assert_eq!(witness.lifecycle_state, LifecycleState::Draft);

        witness.transition_to(LifecycleState::Validated).unwrap();
        witness.transition_to(LifecycleState::Promoted).unwrap();
        witness.transition_to(LifecycleState::Active).unwrap();
        witness.transition_to(LifecycleState::Superseded).unwrap();

        assert!(witness.lifecycle_state.is_terminal());
    }

    #[test]
    fn lifecycle_invalid_transition_errors() {
        let mut witness = build_test_witness();
        let err = witness.transition_to(LifecycleState::Active).unwrap_err();
        assert!(matches!(err, WitnessError::InvalidTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // Promotion theorem tests
    // -----------------------------------------------------------------------

    #[test]
    fn promotion_requires_theorem_report_before_promoted() {
        let cap = Capability::new("read");
        let mut witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();

        witness.transition_to(LifecycleState::Validated).unwrap();
        let err = witness.transition_to(LifecycleState::Promoted).unwrap_err();
        assert!(matches!(
            err,
            WitnessError::MissingPromotionTheoremProofs { .. }
        ));
    }

    #[test]
    fn promotion_theorem_report_enables_promoted_transition() {
        let cap = Capability::new("read");
        let mut witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
        witness.transition_to(LifecycleState::Validated).unwrap();

        let input = PromotionTheoremInput {
            source_capability_sets: vec![SourceCapabilitySet {
                source_id: "static-analysis".to_string(),
                capabilities: witness.required_capabilities.clone(),
            }],
            manifest_capabilities: witness.required_capabilities.clone(),
            capability_lattice: BTreeMap::new(),
            non_interference_dependencies: BTreeMap::new(),
            custom_extensions: Vec::new(),
        };
        let report = witness.evaluate_promotion_theorems(&input).unwrap();
        assert!(report.all_passed);
        witness.apply_promotion_theorem_report(&report);
        witness.transition_to(LifecycleState::Promoted).unwrap();
        assert_eq!(witness.lifecycle_state, LifecycleState::Promoted);
        assert_eq!(
            witness.metadata.get("promotion_theorem.merge_legality"),
            Some(&"pass".to_string())
        );
        assert!(witness.proof_obligations.iter().any(|proof| {
            proof.kind == ProofKind::PolicyTheoremCheck && proof.capability == cap
        }));
    }

    #[test]
    fn promotion_theorem_merge_legality_detects_unjustified_capability() {
        let cap_read = Capability::new("read");
        let cap_write = Capability::new("write");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap_read.clone())
        .require(cap_write.clone())
        .proof(make_proof(&cap_read))
        .proof(make_proof(&cap_write))
        .build()
        .unwrap();

        let input = PromotionTheoremInput {
            source_capability_sets: vec![SourceCapabilitySet {
                source_id: "dynamic-ablation".to_string(),
                capabilities: BTreeSet::from([cap_read.clone()]),
            }],
            manifest_capabilities: BTreeSet::from([cap_read, cap_write.clone()]),
            capability_lattice: BTreeMap::new(),
            non_interference_dependencies: BTreeMap::new(),
            custom_extensions: Vec::new(),
        };
        let report = witness.evaluate_promotion_theorems(&input).unwrap();
        assert!(!report.all_passed);
        let merge = report
            .results
            .iter()
            .find(|result| result.theorem == PromotionTheoremKind::MergeLegality)
            .unwrap();
        assert!(!merge.passed);
        assert!(
            merge
                .counterexample
                .as_deref()
                .is_some_and(|counterexample| counterexample.contains("write"))
        );
    }

    #[test]
    fn promotion_theorem_merge_legality_accepts_lattice_implied_capability() {
        let cap_read = Capability::new("read");
        let cap_write = Capability::new("write");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap_read.clone())
        .proof(make_proof(&cap_read))
        .build()
        .unwrap();

        let input = PromotionTheoremInput {
            source_capability_sets: vec![SourceCapabilitySet {
                source_id: "static-analysis".to_string(),
                capabilities: BTreeSet::from([cap_write.clone()]),
            }],
            manifest_capabilities: BTreeSet::from([cap_write]),
            capability_lattice: BTreeMap::from([(
                Capability::new("write"),
                BTreeSet::from([cap_read]),
            )]),
            non_interference_dependencies: BTreeMap::new(),
            custom_extensions: Vec::new(),
        };
        let report = witness.evaluate_promotion_theorems(&input).unwrap();
        let merge = report
            .results
            .iter()
            .find(|result| result.theorem == PromotionTheoremKind::MergeLegality)
            .unwrap();
        assert!(merge.passed);
    }

    #[test]
    fn promotion_theorem_non_interference_uses_transitive_dependencies() {
        let cap_read = Capability::new("read");
        let cap_internal = Capability::new("internal-hop");
        let cap_denied = Capability::new("denied-network");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap_read.clone())
        .deny(cap_denied.clone(), "forbidden capability")
        .proof(make_proof(&cap_read))
        .build()
        .unwrap();

        let input = PromotionTheoremInput {
            source_capability_sets: vec![SourceCapabilitySet {
                source_id: "static-analysis".to_string(),
                capabilities: BTreeSet::from([cap_read.clone()]),
            }],
            manifest_capabilities: BTreeSet::from([cap_read.clone()]),
            capability_lattice: BTreeMap::new(),
            non_interference_dependencies: BTreeMap::from([
                (cap_read.clone(), BTreeSet::from([cap_internal.clone()])),
                (cap_internal, BTreeSet::from([cap_denied])),
            ]),
            custom_extensions: Vec::new(),
        };
        let report = witness.evaluate_promotion_theorems(&input).unwrap();
        let non_interference = report
            .results
            .iter()
            .find(|result| result.theorem == PromotionTheoremKind::NonInterference)
            .unwrap();
        assert!(!non_interference.passed);
        assert!(
            non_interference
                .counterexample
                .as_deref()
                .is_some_and(|counterexample| counterexample.contains("read->denied-network"))
        );
    }

    #[test]
    fn promotion_theorem_custom_extension_is_supported() {
        let cap_read = Capability::new("read");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap_read.clone())
        .proof(make_proof(&cap_read))
        .build()
        .unwrap();

        let input = PromotionTheoremInput {
            source_capability_sets: vec![SourceCapabilitySet {
                source_id: "static-analysis".to_string(),
                capabilities: BTreeSet::from([cap_read.clone()]),
            }],
            manifest_capabilities: BTreeSet::from([cap_read]),
            capability_lattice: BTreeMap::new(),
            non_interference_dependencies: BTreeMap::new(),
            custom_extensions: vec![CustomTheoremExtension {
                name: "deny-network".to_string(),
                required_capabilities: BTreeSet::new(),
                forbidden_capabilities: BTreeSet::from([Capability::new("network")]),
            }],
        };
        let report = witness.evaluate_promotion_theorems(&input).unwrap();
        let custom = report
            .results
            .iter()
            .find(|result| {
                result.theorem == PromotionTheoremKind::Custom("deny-network".to_string())
            })
            .unwrap();
        assert!(custom.passed);
    }

    #[test]
    fn promotion_theorem_report_emits_structured_events() {
        let cap = Capability::new("read");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
        let report = witness
            .evaluate_promotion_theorems(&promotion_theorem_input_for(&witness))
            .unwrap();
        let events = report.structured_events("trace-a", "decision-a", "policy-a");
        assert_eq!(events.len(), report.results.len() + 1);
        assert!(events.iter().all(|event| event.trace_id == "trace-a"
            && event.decision_id == "decision-a"
            && event.policy_id == "policy-a"
            && !event.component.is_empty()
            && !event.event.is_empty()));
    }

    // -----------------------------------------------------------------------
    // WitnessError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_all_variants() {
        let variants: Vec<WitnessError> = vec![
            WitnessError::EmptyRequiredSet,
            WitnessError::MissingProofObligation {
                capability: "x".to_string(),
            },
            WitnessError::InvalidConfidence {
                reason: "low".to_string(),
            },
            WitnessError::InvalidTransition {
                from: LifecycleState::Draft,
                to: LifecycleState::Active,
            },
            WitnessError::IncompatibleSchema {
                witness: WitnessSchemaVersion { major: 2, minor: 0 },
                reader: WitnessSchemaVersion { major: 1, minor: 0 },
            },
            WitnessError::SignatureInvalid {
                detail: "bad".to_string(),
            },
            WitnessError::IntegrityFailure {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
            WitnessError::IdDerivation("id".to_string()),
            WitnessError::InvalidRollbackToken {
                reason: "unknown".to_string(),
            },
            WitnessError::EpochMismatch {
                witness_epoch: 1,
                current_epoch: 2,
            },
            WitnessError::MissingPromotionTheoremProofs {
                missing_checks: vec!["merge-legality".to_string()],
            },
            WitnessError::PromotionTheoremFailed {
                failed_checks: vec!["non-interference".to_string()],
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // ConfidenceInterval tests
    // -----------------------------------------------------------------------

    #[test]
    fn confidence_from_zero_trials() {
        let ci = ConfidenceInterval::from_trials(0, 0);
        assert_eq!(ci.n_trials, 0);
        assert_eq!(ci.point_estimate_millionths(), 0);
    }

    #[test]
    fn confidence_from_perfect_trials() {
        let ci = ConfidenceInterval::from_trials(100, 100);
        // Wilson interval with integer arithmetic: both bounds converge near the
        // center of the Wilson formula. For p=1.0 the center is
        //   (p_hat + z²/2n) / (1 + z²/n) ≈ 0.9815
        // and margin from z²/(4n²) is tiny, so lower ≈ upper ≈ 981_xxx.
        assert!(
            ci.lower_millionths > 950_000,
            "lower > 0.95: {}",
            ci.lower_millionths
        );
        assert!(
            ci.upper_millionths > 950_000,
            "upper > 0.95: {}",
            ci.upper_millionths
        );
        assert!(ci.upper_millionths >= ci.lower_millionths);
        assert_eq!(ci.point_estimate_millionths(), 1_000_000);
    }

    #[test]
    fn confidence_from_mixed_trials() {
        let ci = ConfidenceInterval::from_trials(100, 95);
        assert!(ci.lower_millionths > 0);
        assert!(ci.upper_millionths <= 1_000_000);
        assert!(ci.lower_millionths < ci.upper_millionths);
        assert_eq!(ci.point_estimate_millionths(), 950_000);
    }

    #[test]
    fn confidence_meets_threshold() {
        let ci = ConfidenceInterval::from_trials(100, 100);
        assert!(ci.meets_threshold(900_000));
    }

    #[test]
    fn confidence_below_threshold() {
        let ci = ConfidenceInterval::from_trials(10, 5);
        assert!(!ci.meets_threshold(900_000));
    }

    #[test]
    fn confidence_serde_roundtrip() {
        let ci = ConfidenceInterval::from_trials(50, 48);
        let json = serde_json::to_string(&ci).unwrap();
        let restored: ConfidenceInterval = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, restored);
    }

    // -----------------------------------------------------------------------
    // ProofObligation / ProofKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn proof_kind_display() {
        assert_eq!(ProofKind::StaticAnalysis.to_string(), "static-analysis");
        assert_eq!(ProofKind::DynamicAblation.to_string(), "dynamic-ablation");
        assert_eq!(
            ProofKind::PolicyTheoremCheck.to_string(),
            "policy-theorem-check"
        );
        assert_eq!(
            ProofKind::OperatorAttestation.to_string(),
            "operator-attestation"
        );
        assert_eq!(ProofKind::InheritedFromPredecessor.to_string(), "inherited");
    }

    #[test]
    fn proof_obligation_serde_roundtrip() {
        let cap = Capability::new("test-cap");
        let po = make_proof(&cap);
        let json = serde_json::to_string(&po).unwrap();
        let restored: ProofObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(po.capability, restored.capability);
        assert_eq!(po.kind, restored.kind);
    }

    // -----------------------------------------------------------------------
    // WitnessBuilder tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_minimal_witness() {
        let cap = Capability::new("read");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();

        assert_eq!(witness.lifecycle_state, LifecycleState::Draft);
        assert_eq!(witness.required_capabilities.len(), 1);
        assert_eq!(witness.schema_version, WitnessSchemaVersion::CURRENT);
        assert!(!witness.synthesizer_signature.is_empty());
    }

    #[test]
    fn build_empty_required_set_fails() {
        let err = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .build()
        .unwrap_err();

        assert!(matches!(err, WitnessError::EmptyRequiredSet));
    }

    #[test]
    fn build_full_witness() {
        let witness = build_test_witness();
        assert_eq!(witness.required_capabilities.len(), 2);
        assert_eq!(witness.denied_capabilities.len(), 1);
        assert!(witness.proof_obligations.len() >= 2);
        assert!(
            witness
                .proof_obligations
                .iter()
                .any(|proof| proof.kind == ProofKind::PolicyTheoremCheck)
        );
        assert_eq!(witness.denial_records.len(), 1);
        assert!(witness.confidence.n_trials > 0);
        assert_eq!(witness.replay_seed, 42);
        assert_eq!(
            witness.metadata.get("synthesizer"),
            Some(&"plas-v1".to_string())
        );
    }

    #[test]
    fn build_deterministic_id() {
        let w1 = build_test_witness();
        let w2 = build_test_witness();
        assert_eq!(w1.witness_id, w2.witness_id);
        assert_eq!(w1.content_hash, w2.content_hash);
    }

    #[test]
    fn build_with_rollback_token() {
        let cap = Capability::new("read");
        let token = RollbackToken {
            previous_witness_hash: ContentHash::compute(b"prev-witness"),
            previous_witness_id: None,
            created_epoch: SecurityEpoch::from_raw(99),
            sequence: 1,
        };

        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(100),
            5000,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .rollback(token.clone())
        .build()
        .unwrap();

        assert_eq!(witness.rollback_token.as_ref().unwrap().sequence, 1);
    }

    // -----------------------------------------------------------------------
    // Integrity & signature verification
    // -----------------------------------------------------------------------

    #[test]
    fn verify_integrity_passes_for_valid_witness() {
        let witness = build_test_witness();
        assert!(witness.verify_integrity().is_ok());
    }

    #[test]
    fn verify_integrity_detects_tampering() {
        let mut witness = build_test_witness();
        witness.replay_seed = 999;
        let err = witness.verify_integrity().unwrap_err();
        assert!(matches!(err, WitnessError::IntegrityFailure { .. }));
    }

    #[test]
    fn verify_signature_passes() {
        let witness = build_test_witness();
        let vk = test_signing_key().verification_key();
        assert!(witness.verify_synthesizer_signature(&vk).is_ok());
    }

    #[test]
    fn verify_signature_fails_wrong_key() {
        let witness = build_test_witness();
        let wrong_key = SigningKey::from_bytes([99u8; 32]).verification_key();
        let err = witness
            .verify_synthesizer_signature(&wrong_key)
            .unwrap_err();
        assert!(matches!(err, WitnessError::SignatureInvalid { .. }));
    }

    #[test]
    fn verify_signature_fails_bad_length() {
        let mut witness = build_test_witness();
        witness.synthesizer_signature = vec![0u8; 10]; // Wrong length.
        let vk = test_signing_key().verification_key();
        let err = witness.verify_synthesizer_signature(&vk).unwrap_err();
        assert!(matches!(err, WitnessError::SignatureInvalid { .. }));
    }

    // -----------------------------------------------------------------------
    // Proof coverage
    // -----------------------------------------------------------------------

    #[test]
    fn verify_proof_coverage_passes() {
        let witness = build_test_witness();
        assert!(witness.verify_proof_coverage().is_ok());
    }

    #[test]
    fn verify_proof_coverage_detects_missing() {
        let cap_a = Capability::new("a");
        let cap_b = Capability::new("b");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap_a.clone())
        .require(cap_b)
        .proof(make_proof(&cap_a)) // Only proof for 'a', not 'b'.
        .build()
        .unwrap();

        let err = witness.verify_proof_coverage().unwrap_err();
        assert!(matches!(err, WitnessError::MissingProofObligation { .. }));
    }

    // -----------------------------------------------------------------------
    // WitnessValidator
    // -----------------------------------------------------------------------

    #[test]
    fn validator_default() {
        let v = WitnessValidator::default();
        assert_eq!(v.supported_version, WitnessSchemaVersion::CURRENT);
        assert_eq!(v.min_confidence_millionths, 900_000);
    }

    #[test]
    fn validate_good_witness() {
        let witness = build_test_witness();
        let validator = WitnessValidator::new();
        let errors = validator.validate(&witness);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn validate_detects_incompatible_schema() {
        let mut witness = build_test_witness();
        witness.schema_version = WitnessSchemaVersion {
            major: 99,
            minor: 0,
        };
        let validator = WitnessValidator::new();
        let errors = validator.validate(&witness);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, WitnessError::IncompatibleSchema { .. }))
        );
    }

    #[test]
    fn validate_detects_low_confidence() {
        let cap = Capability::new("read");
        let witness = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .confidence(ConfidenceInterval::from_trials(10, 5)) // ~50%
        .build()
        .unwrap();

        let validator = WitnessValidator::new();
        let errors = validator.validate(&witness);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, WitnessError::InvalidConfidence { .. }))
        );
    }

    #[test]
    fn validator_serde_roundtrip() {
        let v = WitnessValidator::new();
        let json = serde_json::to_string(&v).unwrap();
        let restored: WitnessValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(v.supported_version, restored.supported_version);
    }

    // -----------------------------------------------------------------------
    // WitnessStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn store_starts_empty() {
        let store = WitnessStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn store_insert_and_get() {
        let mut store = WitnessStore::new();
        let witness = build_test_witness();
        let wid = witness.witness_id.clone();
        store.insert(witness);
        assert_eq!(store.len(), 1);
        assert!(store.get(&wid).is_some());
    }

    #[test]
    fn store_lifecycle_transitions() {
        let mut store = WitnessStore::new();
        let witness = build_test_witness();
        let wid = witness.witness_id.clone();
        let ext_id = witness.extension_id.clone();
        store.insert(witness);

        store.transition(&wid, LifecycleState::Validated).unwrap();
        store.transition(&wid, LifecycleState::Promoted).unwrap();
        store.transition(&wid, LifecycleState::Active).unwrap();

        assert!(store.active_for_extension(&ext_id).is_some());
        assert_eq!(
            store.get(&wid).unwrap().lifecycle_state,
            LifecycleState::Active
        );
    }

    #[test]
    fn store_supersedes_old_active() {
        let mut store = WitnessStore::new();

        // Insert and activate first witness.
        let w1 = build_test_witness();
        let w1_id = w1.witness_id.clone();
        let ext_id = w1.extension_id.clone();
        store.insert(w1);
        store.transition(&w1_id, LifecycleState::Validated).unwrap();
        store.transition(&w1_id, LifecycleState::Promoted).unwrap();
        store.transition(&w1_id, LifecycleState::Active).unwrap();

        // Build second witness for same extension (different timestamp).
        let cap = Capability::new("read-data");
        let w2 = WitnessBuilder::new(
            ext_id.clone(),
            test_policy_id(),
            SecurityEpoch::from_raw(101),
            6000,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .build()
        .unwrap();
        let mut w2 = w2;
        apply_passing_promotion_theorems(&mut w2);
        let w2_id = w2.witness_id.clone();
        store.insert(w2);
        store.transition(&w2_id, LifecycleState::Validated).unwrap();
        store.transition(&w2_id, LifecycleState::Promoted).unwrap();
        store.transition(&w2_id, LifecycleState::Active).unwrap();

        // w1 should be superseded.
        assert_eq!(
            store.get(&w1_id).unwrap().lifecycle_state,
            LifecycleState::Superseded
        );
        // w2 is the active one.
        assert_eq!(
            store.active_for_extension(&ext_id).unwrap().witness_id,
            w2_id
        );
    }

    #[test]
    fn store_revoke_removes_active() {
        let mut store = WitnessStore::new();
        let witness = build_test_witness();
        let wid = witness.witness_id.clone();
        let ext_id = witness.extension_id.clone();
        store.insert(witness);
        store.transition(&wid, LifecycleState::Validated).unwrap();
        store.transition(&wid, LifecycleState::Promoted).unwrap();
        store.transition(&wid, LifecycleState::Active).unwrap();
        store.transition(&wid, LifecycleState::Revoked).unwrap();

        assert!(store.active_for_extension(&ext_id).is_none());
    }

    #[test]
    fn store_by_state() {
        let mut store = WitnessStore::new();
        let witness = build_test_witness();
        store.insert(witness);
        assert_eq!(store.by_state(LifecycleState::Draft).len(), 1);
        assert_eq!(store.by_state(LifecycleState::Active).len(), 0);
    }

    #[test]
    fn store_invalid_transition_errors() {
        let mut store = WitnessStore::new();
        let witness = build_test_witness();
        let wid = witness.witness_id.clone();
        store.insert(witness);

        let err = store.transition(&wid, LifecycleState::Active).unwrap_err();
        assert!(matches!(err, WitnessError::InvalidTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // Witness publication pipeline tests
    // -----------------------------------------------------------------------

    fn test_extension_id_seeded(seed: u64) -> EngineObjectId {
        engine_object_id::derive_id(
            ObjectDomain::Attestation,
            "test-ext-seeded",
            &SchemaId::from_definition(b"TestExtension.v1"),
            &seed.to_be_bytes(),
        )
        .unwrap()
    }

    fn build_promoted_witness(seed: u64) -> CapabilityWitness {
        let cap_name = format!("read-{seed}");
        let cap = Capability::new(&cap_name);
        let mut witness = WitnessBuilder::new(
            test_extension_id_seeded(seed),
            test_policy_id(),
            SecurityEpoch::from_raw(10 + seed),
            10_000 + seed,
            test_signing_key(),
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .confidence(ConfidenceInterval::from_trials(120, 118))
        .replay_seed(seed)
        .transcript_hash(ContentHash::compute(
            format!("transcript-{seed}").as_bytes(),
        ))
        .build()
        .unwrap();
        apply_passing_promotion_theorems(&mut witness);
        witness.transition_to(LifecycleState::Validated).unwrap();
        witness.transition_to(LifecycleState::Promoted).unwrap();
        witness
    }

    fn publication_config_with_governance() -> WitnessPublicationConfig {
        WitnessPublicationConfig {
            checkpoint_interval: 1,
            policy_id: "witness-publication-policy".to_string(),
            governance_ledger_config: Some(GovernanceLedgerConfig {
                checkpoint_interval: 2,
                signer_key: b"witness-governance-signing-key".to_vec(),
                policy_id: "witness-governance".to_string(),
            }),
        }
    }

    #[test]
    fn publication_pipeline_publish_emits_artifact_and_ledgers() {
        let head_signing_key = SigningKey::from_bytes([17u8; 32]);
        let mut pipeline = WitnessPublicationPipeline::new(
            SecurityEpoch::from_raw(500),
            head_signing_key.clone(),
            publication_config_with_governance(),
        )
        .unwrap();

        let witness = build_promoted_witness(1);
        let publication_id = pipeline.publish_witness(witness.clone(), 90_000).unwrap();

        assert_eq!(pipeline.publications().len(), 1);
        let artifact = &pipeline.publications()[0];
        assert_eq!(artifact.publication_id, publication_id);
        assert_eq!(
            artifact.publication_proof.log_entry.kind,
            PublicationEntryKind::Publish
        );
        assert!(artifact.publication_proof.log_entry.verify_leaf_hash());
        assert_eq!(pipeline.evidence_entries().len(), 1);
        assert_eq!(pipeline.governance_ledger().unwrap().entries().len(), 1);

        WitnessPublicationPipeline::verify_artifact(
            artifact,
            &test_signing_key().verification_key(),
            &head_signing_key.verification_key(),
        )
        .unwrap();
    }

    #[test]
    fn publication_pipeline_second_publish_has_consistency_chain() {
        let head_signing_key = SigningKey::from_bytes([21u8; 32]);
        let mut pipeline = WitnessPublicationPipeline::new(
            SecurityEpoch::from_raw(600),
            head_signing_key.clone(),
            WitnessPublicationConfig {
                checkpoint_interval: 1,
                policy_id: "witness-publication-policy".to_string(),
                governance_ledger_config: None,
            },
        )
        .unwrap();

        let first = build_promoted_witness(10);
        let second = build_promoted_witness(11);
        pipeline.publish_witness(first, 100).unwrap();
        let pub2 = pipeline.publish_witness(second, 200).unwrap();

        let second_artifact = pipeline
            .publications()
            .iter()
            .find(|artifact| artifact.publication_id == pub2)
            .unwrap();
        assert!(
            !second_artifact
                .publication_proof
                .consistency_chain
                .is_empty()
        );

        WitnessPublicationPipeline::verify_artifact(
            second_artifact,
            &test_signing_key().verification_key(),
            &head_signing_key.verification_key(),
        )
        .unwrap();
    }

    #[test]
    fn publication_pipeline_revocation_appends_signed_entry() {
        let head_signing_key = SigningKey::from_bytes([33u8; 32]);
        let mut pipeline = WitnessPublicationPipeline::new(
            SecurityEpoch::from_raw(700),
            head_signing_key.clone(),
            publication_config_with_governance(),
        )
        .unwrap();

        let witness = build_promoted_witness(20);
        let witness_id = witness.witness_id.clone();
        pipeline.publish_witness(witness.clone(), 1_000).unwrap();
        pipeline
            .revoke_witness(&witness_id, "compromise detected", 2_000)
            .unwrap();

        let artifact = pipeline
            .publications()
            .iter()
            .find(|artifact| artifact.witness.witness_id == witness_id)
            .unwrap();
        assert!(artifact.is_revoked());
        let revocation = artifact.revocation_proof.as_ref().unwrap();
        assert_eq!(revocation.log_entry.kind, PublicationEntryKind::Revoke);
        assert_eq!(
            revocation.log_entry.revocation_reason.as_deref(),
            Some("compromise detected")
        );
        assert_eq!(pipeline.governance_ledger().unwrap().entries().len(), 2);
        assert_eq!(pipeline.evidence_entries().len(), 2);

        WitnessPublicationPipeline::verify_artifact(
            artifact,
            &test_signing_key().verification_key(),
            &head_signing_key.verification_key(),
        )
        .unwrap();
    }

    #[test]
    fn publication_pipeline_query_filters() {
        let head_signing_key = SigningKey::from_bytes([44u8; 32]);
        let mut pipeline = WitnessPublicationPipeline::new(
            SecurityEpoch::from_raw(800),
            head_signing_key,
            WitnessPublicationConfig {
                checkpoint_interval: 2,
                policy_id: "query-policy".to_string(),
                governance_ledger_config: None,
            },
        )
        .unwrap();

        let w1 = build_promoted_witness(31);
        let w2 = build_promoted_witness(32);
        let w1_ext = w1.extension_id.clone();
        let w2_hash = w2.content_hash.clone();
        pipeline.publish_witness(w1, 10).unwrap();
        pipeline.publish_witness(w2, 20).unwrap();

        let by_ext = pipeline.query(&WitnessPublicationQuery {
            extension_id: Some(w1_ext),
            policy_id: None,
            epoch: None,
            content_hash: None,
            include_revoked: true,
        });
        assert_eq!(by_ext.len(), 1);

        let by_hash = pipeline.query(&WitnessPublicationQuery {
            extension_id: None,
            policy_id: None,
            epoch: None,
            content_hash: Some(w2_hash),
            include_revoked: true,
        });
        assert_eq!(by_hash.len(), 1);
    }

    #[test]
    fn publication_pipeline_detects_tampered_inclusion_root() {
        let head_signing_key = SigningKey::from_bytes([55u8; 32]);
        let mut pipeline = WitnessPublicationPipeline::new(
            SecurityEpoch::from_raw(900),
            head_signing_key.clone(),
            WitnessPublicationConfig {
                checkpoint_interval: 1,
                policy_id: "verify-policy".to_string(),
                governance_ledger_config: None,
            },
        )
        .unwrap();

        let witness = build_promoted_witness(40);
        pipeline.publish_witness(witness, 30).unwrap();

        let mut artifact = pipeline.publications()[0].clone();
        artifact.publication_proof.inclusion_proof.root_hash = ContentHash([0xabu8; 32]);

        let err = WitnessPublicationPipeline::verify_artifact(
            &artifact,
            &test_signing_key().verification_key(),
            &head_signing_key.verification_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WitnessPublicationError::InclusionProofFailed { .. }
                | WitnessPublicationError::ConsistencyProofFailed { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn witness_serde_roundtrip() {
        let witness = build_test_witness();
        let json = serde_json::to_string(&witness).unwrap();
        let restored: CapabilityWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness.witness_id, restored.witness_id);
        assert_eq!(witness.content_hash, restored.content_hash);
        assert_eq!(
            witness.required_capabilities,
            restored.required_capabilities
        );
    }

    #[test]
    fn rollback_token_serde_roundtrip() {
        let token = RollbackToken {
            previous_witness_hash: ContentHash::compute(b"prev"),
            previous_witness_id: Some(test_extension_id()),
            created_epoch: SecurityEpoch::from_raw(99),
            sequence: 5,
        };
        let json = serde_json::to_string(&token).unwrap();
        let restored: RollbackToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, restored);
    }

    #[test]
    fn denial_record_serde_roundtrip() {
        let dr = DenialRecord {
            capability: Capability::new("admin"),
            reason: "not needed".to_string(),
            evidence_id: None,
        };
        let json = serde_json::to_string(&dr).unwrap();
        let restored: DenialRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(dr, restored);
    }

    #[test]
    fn store_serde_roundtrip() {
        let mut store = WitnessStore::new();
        store.insert(build_test_witness());
        let json = serde_json::to_string(&store).unwrap();
        let restored: WitnessStore = serde_json::from_str(&json).unwrap();
        assert_eq!(store.len(), restored.len());
    }

    // -----------------------------------------------------------------------
    // Unsigned bytes determinism
    // -----------------------------------------------------------------------

    #[test]
    fn unsigned_bytes_deterministic() {
        let w1 = build_test_witness();
        let w2 = build_test_witness();
        assert_eq!(w1.unsigned_bytes(), w2.unsigned_bytes());
    }

    // -----------------------------------------------------------------------
    // isqrt_millionths
    // -----------------------------------------------------------------------

    #[test]
    fn isqrt_zero() {
        assert_eq!(isqrt_millionths(0), 0);
    }

    #[test]
    fn isqrt_negative() {
        assert_eq!(isqrt_millionths(-5), 0);
    }

    #[test]
    fn isqrt_perfect_square() {
        assert_eq!(isqrt_millionths(1_000_000), 1000);
    }

    #[test]
    fn isqrt_large_value() {
        let result = isqrt_millionths(4_000_000);
        assert_eq!(result, 2000);
    }

    // -- Enrichment: serde roundtrips for leaf types --

    #[test]
    fn lifecycle_state_serde_roundtrip() {
        let variants = [
            LifecycleState::Draft,
            LifecycleState::Validated,
            LifecycleState::Promoted,
            LifecycleState::Active,
            LifecycleState::Superseded,
            LifecycleState::Revoked,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: LifecycleState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn proof_kind_serde_roundtrip() {
        let variants = [
            ProofKind::StaticAnalysis,
            ProofKind::DynamicAblation,
            ProofKind::PolicyTheoremCheck,
            ProofKind::OperatorAttestation,
            ProofKind::InheritedFromPredecessor,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: ProofKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn promotion_theorem_kind_serde_roundtrip() {
        let variants = vec![
            PromotionTheoremKind::MergeLegality,
            PromotionTheoremKind::AttenuationLegality,
            PromotionTheoremKind::NonInterference,
            PromotionTheoremKind::Custom("my_theorem".to_string()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: PromotionTheoremKind =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn witness_schema_version_serde_roundtrip() {
        let v = WitnessSchemaVersion::CURRENT;
        let json = serde_json::to_string(&v).expect("serialize");
        let restored: WitnessSchemaVersion =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, restored);
    }

    #[test]
    fn confidence_interval_serde_roundtrip() {
        let ci = ConfidenceInterval::from_trials(100, 90);
        let json = serde_json::to_string(&ci).expect("serialize");
        let restored: ConfidenceInterval = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ci, restored);
    }

    #[test]
    fn witness_error_serde_roundtrip() {
        let errors: Vec<WitnessError> = vec![
            WitnessError::EmptyRequiredSet,
            WitnessError::MissingProofObligation {
                capability: "cap_a".to_string(),
            },
            WitnessError::InvalidConfidence {
                reason: "too low".to_string(),
            },
            WitnessError::InvalidTransition {
                from: LifecycleState::Draft,
                to: LifecycleState::Active,
            },
            WitnessError::IncompatibleSchema {
                witness: WitnessSchemaVersion { major: 1, minor: 0 },
                reader: WitnessSchemaVersion { major: 2, minor: 0 },
            },
            WitnessError::SignatureInvalid {
                detail: "bad".to_string(),
            },
            WitnessError::IntegrityFailure {
                expected: "aaa".to_string(),
                actual: "bbb".to_string(),
            },
            WitnessError::IdDerivation("failed".to_string()),
            WitnessError::InvalidRollbackToken {
                reason: "unknown".to_string(),
            },
            WitnessError::EpochMismatch {
                witness_epoch: 1,
                current_epoch: 2,
            },
            WitnessError::MissingPromotionTheoremProofs {
                missing_checks: vec!["merge".to_string()],
            },
            WitnessError::PromotionTheoremFailed {
                failed_checks: vec!["attenuation".to_string()],
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: WitnessError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn publication_entry_kind_serde_roundtrip() {
        let variants = [PublicationEntryKind::Publish, PublicationEntryKind::Revoke];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: PublicationEntryKind =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn witness_publication_error_serde_roundtrip() {
        let errors: Vec<WitnessPublicationError> = vec![
            WitnessPublicationError::InvalidConfig {
                reason: "bad".to_string(),
            },
            WitnessPublicationError::WitnessNotPromoted {
                state: LifecycleState::Draft,
            },
            WitnessPublicationError::DuplicatePublication {
                witness_id: EngineObjectId([1; 32]),
            },
            WitnessPublicationError::EmptyRevocationReason,
            WitnessPublicationError::IdDerivation("err".to_string()),
            WitnessPublicationError::InclusionProofFailed {
                detail: "miss".to_string(),
            },
            WitnessPublicationError::LogEntryHashMismatch,
            WitnessPublicationError::GovernanceLedger {
                detail: "ledger err".to_string(),
            },
            WitnessPublicationError::EvidenceLedger {
                detail: "evidence err".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: WitnessPublicationError =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn witness_index_error_serde_roundtrip() {
        let errors: Vec<WitnessIndexError> = vec![
            WitnessIndexError::Serialization {
                operation: "write".to_string(),
                detail: "fail".to_string(),
            },
            WitnessIndexError::CorruptRecord {
                key: "k1".to_string(),
                detail: "bad".to_string(),
            },
            WitnessIndexError::InvalidInput {
                detail: "empty".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: WitnessIndexError =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn source_capability_set_serde_roundtrip() {
        let scs = SourceCapabilitySet {
            source_id: "src-1".to_string(),
            capabilities: BTreeSet::from([Capability::new("cap_a")]),
        };
        let json = serde_json::to_string(&scs).expect("serialize");
        let restored: SourceCapabilitySet =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(scs, restored);
    }

    #[test]
    fn lifecycle_state_ordering() {
        assert!(LifecycleState::Draft < LifecycleState::Validated);
        assert!(LifecycleState::Validated < LifecycleState::Promoted);
        assert!(LifecycleState::Promoted < LifecycleState::Active);
        assert!(LifecycleState::Active < LifecycleState::Superseded);
        assert!(LifecycleState::Superseded < LifecycleState::Revoked);
    }

    #[test]
    fn witness_publication_config_serde_roundtrip() {
        let config = WitnessPublicationConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: WitnessPublicationConfig =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn witness_publication_event_serde_roundtrip() {
        let event = WitnessPublicationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "witness_publication".to_string(),
            event: "test".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            timestamp_ns: 12345,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: WitnessPublicationEvent =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn publication_entry_kind_display_content() {
        assert_eq!(PublicationEntryKind::Publish.to_string(), "publish");
        assert_eq!(PublicationEntryKind::Revoke.to_string(), "revoke");
    }

    #[test]
    fn witness_index_error_display_content() {
        let s = WitnessIndexError::Serialization {
            operation: "write".to_string(),
            detail: "broken".to_string(),
        }
        .to_string();
        assert!(s.contains("write"));
        assert!(s.contains("broken"));

        let s = WitnessIndexError::CorruptRecord {
            key: "k1".to_string(),
            detail: "bad crc".to_string(),
        }
        .to_string();
        assert!(s.contains("k1"));

        let s = WitnessIndexError::InvalidInput {
            detail: "empty".to_string(),
        }
        .to_string();
        assert!(s.contains("empty"));
    }

    #[test]
    fn promotion_theorem_kind_display_content() {
        assert_eq!(
            PromotionTheoremKind::MergeLegality.to_string(),
            "merge-legality"
        );
        assert_eq!(
            PromotionTheoremKind::AttenuationLegality.to_string(),
            "attenuation-legality"
        );
        assert_eq!(
            PromotionTheoremKind::NonInterference.to_string(),
            "non-interference"
        );
        assert!(
            PromotionTheoremKind::Custom("my_thm".to_string())
                .to_string()
                .contains("my_thm")
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn witness_index_record_serde_roundtrip() {
        let key = test_signing_key();
        let cap = Capability::new("cap:fs");
        let w = WitnessBuilder::new(
            test_extension_id(),
            test_policy_id(),
            SecurityEpoch::from_raw(1),
            1000,
            key,
        )
        .require(cap.clone())
        .proof(make_proof(&cap))
        .confidence(ConfidenceInterval::from_trials(100, 95))
        .replay_seed(42)
        .transcript_hash(ContentHash::compute(b"tx"))
        .build()
        .unwrap();
        let rec = WitnessIndexRecord {
            witness_id: w.witness_id.clone(),
            extension_id: w.extension_id.clone(),
            policy_id: w.policy_id.clone(),
            epoch: w.epoch,
            lifecycle_state: w.lifecycle_state,
            promotion_timestamp_ns: w.timestamp_ns,
            content_hash: w.content_hash.clone(),
            witness: w,
        };
        let json = serde_json::to_string(&rec).unwrap();
        let restored: WitnessIndexRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, restored);
    }

    #[test]
    fn capability_escrow_receipt_record_serde_roundtrip() {
        let rec = CapabilityEscrowReceiptRecord {
            receipt_id: "r-1".to_string(),
            extension_id: test_extension_id(),
            capability: Some(Capability::new("cap:net")),
            decision_kind: "grant".to_string(),
            outcome: "approved".to_string(),
            timestamp_ns: 1000,
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&rec).unwrap();
        let restored: CapabilityEscrowReceiptRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, restored);
    }

    #[test]
    fn witness_index_query_serde_roundtrip() {
        let q = WitnessIndexQuery {
            extension_id: Some(test_extension_id()),
            policy_id: None,
            epoch: Some(SecurityEpoch::from_raw(1)),
            lifecycle_state: Some(LifecycleState::Active),
            capability: None,
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            include_revoked: false,
            cursor: None,
            limit: 10,
        };
        let json = serde_json::to_string(&q).unwrap();
        let restored: WitnessIndexQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, restored);
    }

    #[test]
    fn witness_index_event_serde_roundtrip() {
        let ev = WitnessIndexEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "witness_index".to_string(),
            event: "indexed".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: WitnessIndexEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn witness_publication_query_serde_roundtrip() {
        let q = WitnessPublicationQuery {
            extension_id: Some(test_extension_id()),
            policy_id: None,
            epoch: Some(SecurityEpoch::from_raw(2)),
            content_hash: Some(ContentHash::compute(b"hash")),
            include_revoked: true,
        };
        let json = serde_json::to_string(&q).unwrap();
        let restored: WitnessPublicationQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, restored);
    }

    #[test]
    fn custom_theorem_extension_serde_roundtrip() {
        let ext = CustomTheoremExtension {
            name: "isolation_check".to_string(),
            required_capabilities: {
                let mut s = BTreeSet::new();
                s.insert(Capability::new("cap:fs"));
                s
            },
            forbidden_capabilities: BTreeSet::new(),
        };
        let json = serde_json::to_string(&ext).unwrap();
        let restored: CustomTheoremExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(ext, restored);
    }

    #[test]
    fn promotion_theorem_log_event_serde_roundtrip() {
        let ev = PromotionTheoremLogEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "promotion".to_string(),
            event: "evaluated".to_string(),
            outcome: "passed".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: PromotionTheoremLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: default value assertions
    // -----------------------------------------------------------------------

    #[test]
    fn witness_index_query_default_values() {
        let q = WitnessIndexQuery::default();
        assert!(q.extension_id.is_none());
        assert!(q.policy_id.is_none());
        assert!(q.epoch.is_none());
        assert!(q.lifecycle_state.is_none());
        assert!(q.capability.is_none());
        assert!(q.start_timestamp_ns.is_none());
        assert!(q.end_timestamp_ns.is_none());
        assert!(q.include_revoked);
        assert!(q.cursor.is_none());
        assert_eq!(q.limit, 128);
    }

    #[test]
    fn witness_publication_config_default_values() {
        let c = WitnessPublicationConfig::default();
        assert_eq!(c.checkpoint_interval, 8);
        assert_eq!(c.policy_id, "capability-witness-policy");
        assert!(c.governance_ledger_config.is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn proof_kind_ordering() {
        assert!(ProofKind::StaticAnalysis < ProofKind::InheritedFromPredecessor);
    }

    #[test]
    fn publication_entry_kind_ordering() {
        assert!(PublicationEntryKind::Publish < PublicationEntryKind::Revoke);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display completeness
    // -----------------------------------------------------------------------

    #[test]
    fn witness_publication_error_display_all_variants() {
        let variants: Vec<WitnessPublicationError> = vec![
            WitnessPublicationError::InvalidConfig {
                reason: "bad".to_string(),
            },
            WitnessPublicationError::WitnessNotPromoted {
                state: LifecycleState::Draft,
            },
            WitnessPublicationError::DuplicatePublication {
                witness_id: test_extension_id(),
            },
            WitnessPublicationError::PublicationNotFound {
                publication_id: test_extension_id(),
            },
            WitnessPublicationError::WitnessNotPublished {
                witness_id: test_extension_id(),
            },
            WitnessPublicationError::AlreadyRevoked {
                witness_id: test_extension_id(),
            },
            WitnessPublicationError::EmptyRevocationReason,
            WitnessPublicationError::IdDerivation("id err".to_string()),
            WitnessPublicationError::InclusionProofFailed {
                detail: "bad".to_string(),
            },
            WitnessPublicationError::ConsistencyProofFailed {
                detail: "bad".to_string(),
            },
            WitnessPublicationError::TreeHeadSignatureInvalid {
                detail: "bad".to_string(),
            },
            WitnessPublicationError::TreeHeadHashMismatch {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
            WitnessPublicationError::LogEntryHashMismatch,
            WitnessPublicationError::WitnessVerificationFailed {
                detail: "bad".to_string(),
            },
            WitnessPublicationError::GovernanceLedger {
                detail: "bad".to_string(),
            },
            WitnessPublicationError::EvidenceLedger {
                detail: "bad".to_string(),
            },
        ];
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty(), "Display should not be empty for {v:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: WitnessPublicationQuery::all
    // -----------------------------------------------------------------------

    #[test]
    fn witness_publication_query_all_includes_revoked() {
        let q = WitnessPublicationQuery::all();
        assert!(q.extension_id.is_none());
        assert!(q.policy_id.is_none());
        assert!(q.epoch.is_none());
        assert!(q.content_hash.is_none());
        assert!(q.include_revoked);
    }

    // -----------------------------------------------------------------------
    // Enrichment: publication_entry_kind as_str
    // -----------------------------------------------------------------------

    #[test]
    fn publication_entry_kind_as_str_values() {
        assert_eq!(PublicationEntryKind::Publish.as_str(), "publish");
        assert_eq!(PublicationEntryKind::Revoke.as_str(), "revoke");
    }

    // -----------------------------------------------------------------------
    // Enrichment: WitnessIndexError code all variants
    // -----------------------------------------------------------------------

    #[test]
    fn witness_index_error_code_all_variants() {
        let errors: Vec<WitnessIndexError> = vec![
            WitnessIndexError::Storage(StorageError::NotFound {
                store: StoreKind::PlasWitness,
                key: "k".to_string(),
            }),
            WitnessIndexError::Serialization {
                operation: "w".to_string(),
                detail: "e".to_string(),
            },
            WitnessIndexError::CorruptRecord {
                key: "k".to_string(),
                detail: "d".to_string(),
            },
            WitnessIndexError::InvalidInput {
                detail: "d".to_string(),
            },
        ];
        let codes: Vec<&str> = errors.iter().map(|e| e.code()).collect();
        // All codes should be unique
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(codes.len(), unique.len());
    }
}
