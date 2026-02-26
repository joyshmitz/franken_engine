//! Proof-to-specialization linkage engine for IR3/IR4 artifacts.
//!
//! Bridges the compiler-policy decision engine with IR3 (ExecIR) and IR4
//! (WitnessIR) artifacts. Manages the lifecycle of specialization linkages:
//! create from proof decisions, attach to IR3 modules, invalidate on epoch
//! change with deterministic rollback, and record consumption in IR4 witnesses.
//!
//! Plan reference: Section 10.2 item 6 (proof-to-specialization linkage),
//! bd-161.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::ir_contract::{
    Ir3Module, Ir4Module, SpecializationLinkage, WitnessEvent, WitnessEventKind,
};
use crate::proof_specialization_receipt::{OptimizationClass, ProofType};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema definition for canonical hashing.
#[cfg(test)]
const SCHEMA_DEF: &[u8] = b"ProofSpecializationLinkage.v1";

// ---------------------------------------------------------------------------
// Linkage identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a specialization linkage record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LinkageId(pub String);

impl LinkageId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LinkageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// ProofInputRef — a reference to a security proof
// ---------------------------------------------------------------------------

/// A reference to a security proof that justifies a specialization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofInputRef {
    /// Content-addressable proof identifier.
    pub proof_id: String,
    /// Type of security proof.
    pub proof_type: ProofType,
    /// Security epoch during which this proof was produced.
    pub proof_epoch: SecurityEpoch,
    /// Validity window in logical ticks (0 = unlimited).
    pub validity_window_ticks: u64,
}

// ---------------------------------------------------------------------------
// PerformanceDelta — observed performance change
// ---------------------------------------------------------------------------

/// Performance delta observed from a specialization.
/// Fixed-point millionths: 1_000_000 = 1.0x (no change).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PerformanceDelta {
    /// Speedup factor in millionths (e.g. 1_500_000 = 1.5x speedup).
    pub speedup_millionths: u64,
    /// Instruction count ratio in millionths (e.g. 800_000 = 0.8x instructions).
    pub instruction_ratio_millionths: u64,
}

impl PerformanceDelta {
    pub const NEUTRAL: Self = Self {
        speedup_millionths: 1_000_000,
        instruction_ratio_millionths: 1_000_000,
    };
}

impl Default for PerformanceDelta {
    fn default() -> Self {
        Self::NEUTRAL
    }
}

// ---------------------------------------------------------------------------
// RollbackState — what to revert to when invalidated
// ---------------------------------------------------------------------------

/// State needed to revert a specialization to its unspecialized baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackState {
    /// Content hash of the unspecialized IR3 module.
    pub baseline_ir3_hash: ContentHash,
    /// Monotonic epoch at which the specialization was activated.
    pub activation_epoch: SecurityEpoch,
    /// Activation timestamp in logical ticks.
    pub activation_tick: u64,
}

// ---------------------------------------------------------------------------
// LinkageRecord — full linkage between proofs and specialization
// ---------------------------------------------------------------------------

/// A full record linking security proofs to an IR3 specialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageRecord {
    /// Unique linkage identifier.
    pub id: LinkageId,
    /// Which security proofs justify this specialization.
    pub proof_inputs: Vec<ProofInputRef>,
    /// Classification of the optimization.
    pub optimization_class: OptimizationClass,
    /// Security epoch during which this linkage is valid.
    pub validity_epoch: SecurityEpoch,
    /// Content hash of the specialized IR3 module.
    pub specialized_ir3_hash: ContentHash,
    /// Rollback state for reverting to unspecialized baseline.
    pub rollback: RollbackState,
    /// Whether this linkage is currently active.
    pub active: bool,
    /// Observed performance delta (populated after first execution).
    pub performance_delta: Option<PerformanceDelta>,
    /// How many times this specialization has been executed.
    pub execution_count: u64,
}

impl LinkageRecord {
    /// Check if all proof inputs are still valid at the given epoch.
    pub fn proofs_valid_at(&self, epoch: SecurityEpoch) -> bool {
        self.proof_inputs.iter().all(|p| p.proof_epoch <= epoch)
    }

    /// Convert to the IR3 `SpecializationLinkage` format.
    pub fn to_ir3_linkage(&self) -> SpecializationLinkage {
        SpecializationLinkage {
            proof_input_ids: self
                .proof_inputs
                .iter()
                .map(|p| p.proof_id.clone())
                .collect(),
            optimization_class: self.optimization_class.to_string(),
            validity_epoch: self.validity_epoch.as_u64(),
            rollback_token: self.rollback.baseline_ir3_hash.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// InvalidationCause — why a specialization was invalidated
// ---------------------------------------------------------------------------

/// Reason a specialization linkage was invalidated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationCause {
    /// Security epoch changed, proofs expired.
    EpochChange {
        old_epoch: SecurityEpoch,
        new_epoch: SecurityEpoch,
    },
    /// Proof was explicitly revoked.
    ProofRevoked { proof_id: String },
    /// Policy change invalidated the optimization class.
    PolicyChange { reason: String },
    /// Operator-initiated manual invalidation.
    ManualInvalidation { operator_id: String },
}

impl fmt::Display for InvalidationCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochChange {
                old_epoch,
                new_epoch,
            } => write!(f, "epoch_change({old_epoch}->{new_epoch})"),
            Self::ProofRevoked { proof_id } => write!(f, "proof_revoked({proof_id})"),
            Self::PolicyChange { reason } => write!(f, "policy_change({reason})"),
            Self::ManualInvalidation { operator_id } => {
                write!(f, "manual_invalidation({operator_id})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LinkageEvent — audit log entry
// ---------------------------------------------------------------------------

/// Structured audit event for specialization linkage operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// LinkageError
// ---------------------------------------------------------------------------

/// Error type for linkage operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageError {
    /// Linkage ID already exists.
    DuplicateLinkage { id: String },
    /// Linkage not found.
    LinkageNotFound { id: String },
    /// Linkage is already inactive.
    AlreadyInactive { id: String },
    /// No proof inputs provided.
    EmptyProofInputs,
    /// Epoch mismatch: linkage epoch does not match current.
    EpochMismatch {
        linkage_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    /// IR3 module already has a specialization attached.
    Ir3AlreadySpecialized,
}

impl fmt::Display for LinkageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateLinkage { id } => write!(f, "duplicate linkage: {id}"),
            Self::LinkageNotFound { id } => write!(f, "linkage not found: {id}"),
            Self::AlreadyInactive { id } => write!(f, "linkage already inactive: {id}"),
            Self::EmptyProofInputs => write!(f, "no proof inputs provided"),
            Self::EpochMismatch {
                linkage_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch mismatch: linkage={linkage_epoch}, current={current_epoch}"
            ),
            Self::Ir3AlreadySpecialized => write!(f, "IR3 module already has specialization"),
        }
    }
}

impl std::error::Error for LinkageError {}

/// Stable error code for each error variant.
pub fn error_code(err: &LinkageError) -> &'static str {
    match err {
        LinkageError::DuplicateLinkage { .. } => "LINKAGE_DUPLICATE",
        LinkageError::LinkageNotFound { .. } => "LINKAGE_NOT_FOUND",
        LinkageError::AlreadyInactive { .. } => "LINKAGE_ALREADY_INACTIVE",
        LinkageError::EmptyProofInputs => "LINKAGE_EMPTY_PROOF_INPUTS",
        LinkageError::EpochMismatch { .. } => "LINKAGE_EPOCH_MISMATCH",
        LinkageError::Ir3AlreadySpecialized => "LINKAGE_IR3_ALREADY_SPECIALIZED",
    }
}

// ---------------------------------------------------------------------------
// ExecutionRecord — what happened during a specialized execution
// ---------------------------------------------------------------------------

/// Record of a specialized execution for consumption tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// Which linkage was active.
    pub linkage_id: LinkageId,
    /// IR4 content hash of the execution witness.
    pub witness_hash: ContentHash,
    /// Observed performance delta.
    pub performance_delta: PerformanceDelta,
    /// Number of instructions executed.
    pub instructions_executed: u64,
    /// Duration in logical ticks.
    pub duration_ticks: u64,
}

// ---------------------------------------------------------------------------
// LinkageEngine — the main coordinator
// ---------------------------------------------------------------------------

/// Engine managing proof-to-specialization linkages for IR3/IR4 artifacts.
///
/// Maintains the registry of active and invalidated linkages, provides
/// operations for attaching specializations to IR3 modules, recording
/// consumption in IR4 witnesses, and deterministic invalidation on epoch
/// change.
pub struct LinkageEngine {
    /// Policy identifier for audit trail.
    policy_id: String,
    /// Current security epoch.
    current_epoch: SecurityEpoch,
    /// Active and inactive linkage records.
    linkages: BTreeMap<LinkageId, LinkageRecord>,
    /// Invalidation log (append-only).
    invalidations: Vec<(LinkageId, InvalidationCause)>,
    /// Structured audit events.
    events: Vec<LinkageEvent>,
}

impl LinkageEngine {
    /// Create a new linkage engine.
    pub fn new(policy_id: impl Into<String>, epoch: SecurityEpoch) -> Self {
        Self {
            policy_id: policy_id.into(),
            current_epoch: epoch,
            linkages: BTreeMap::new(),
            invalidations: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    pub fn linkages(&self) -> &BTreeMap<LinkageId, LinkageRecord> {
        &self.linkages
    }

    pub fn invalidations(&self) -> &[(LinkageId, InvalidationCause)] {
        &self.invalidations
    }

    pub fn events(&self) -> &[LinkageEvent] {
        &self.events
    }

    // -----------------------------------------------------------------------
    // Register a new linkage
    // -----------------------------------------------------------------------

    /// Register a new proof-to-specialization linkage.
    pub fn register(&mut self, record: LinkageRecord, trace_id: &str) -> Result<(), LinkageError> {
        if record.proof_inputs.is_empty() {
            self.emit_event(
                trace_id,
                "register",
                "rejected",
                Some("LINKAGE_EMPTY_PROOF_INPUTS"),
            );
            return Err(LinkageError::EmptyProofInputs);
        }

        if self.linkages.contains_key(&record.id) {
            self.emit_event(trace_id, "register", "rejected", Some("LINKAGE_DUPLICATE"));
            return Err(LinkageError::DuplicateLinkage {
                id: record.id.0.clone(),
            });
        }

        let id = record.id.clone();
        self.linkages.insert(id, record);
        self.emit_event(trace_id, "register", "ok", None);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Attach specialization to IR3
    // -----------------------------------------------------------------------

    /// Attach a specialization linkage to an IR3 module.
    ///
    /// Returns an error if the IR3 module already has a specialization or the
    /// linkage is not found / not active.
    pub fn attach_to_ir3(
        &mut self,
        linkage_id: &LinkageId,
        ir3: &mut Ir3Module,
        trace_id: &str,
    ) -> Result<(), LinkageError> {
        if ir3.specialization.is_some() {
            self.emit_event(
                trace_id,
                "attach_to_ir3",
                "rejected",
                Some("LINKAGE_IR3_ALREADY_SPECIALIZED"),
            );
            return Err(LinkageError::Ir3AlreadySpecialized);
        }

        let record =
            self.linkages
                .get(linkage_id)
                .ok_or_else(|| LinkageError::LinkageNotFound {
                    id: linkage_id.0.clone(),
                })?;

        if !record.active {
            self.emit_event(
                trace_id,
                "attach_to_ir3",
                "rejected",
                Some("LINKAGE_ALREADY_INACTIVE"),
            );
            return Err(LinkageError::AlreadyInactive {
                id: linkage_id.0.clone(),
            });
        }

        if record.validity_epoch != self.current_epoch {
            let linkage_epoch = record.validity_epoch;
            let current_epoch = self.current_epoch;
            self.emit_event(
                trace_id,
                "attach_to_ir3",
                "rejected",
                Some("LINKAGE_EPOCH_MISMATCH"),
            );
            return Err(LinkageError::EpochMismatch {
                linkage_epoch,
                current_epoch,
            });
        }

        ir3.specialization = Some(record.to_ir3_linkage());
        self.emit_event(trace_id, "attach_to_ir3", "ok", None);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Record execution in IR4
    // -----------------------------------------------------------------------

    /// Record that a specialization was used in an execution, updating IR4
    /// witness and internal counters.
    pub fn record_execution(
        &mut self,
        linkage_id: &LinkageId,
        ir4: &mut Ir4Module,
        performance: PerformanceDelta,
        trace_id: &str,
    ) -> Result<ExecutionRecord, LinkageError> {
        let record =
            self.linkages
                .get_mut(linkage_id)
                .ok_or_else(|| LinkageError::LinkageNotFound {
                    id: linkage_id.0.clone(),
                })?;

        record.execution_count += 1;
        record.performance_delta = Some(performance);

        // Add to IR4 active specialization IDs
        if !ir4.active_specialization_ids.contains(&linkage_id.0) {
            ir4.active_specialization_ids.push(linkage_id.0.clone());
        }

        let exec_record = ExecutionRecord {
            linkage_id: linkage_id.clone(),
            witness_hash: ir4.content_hash(),
            performance_delta: performance,
            instructions_executed: ir4.instructions_executed,
            duration_ticks: ir4.duration_ticks,
        };

        self.emit_event(trace_id, "record_execution", "ok", None);
        Ok(exec_record)
    }

    // -----------------------------------------------------------------------
    // Invalidation on epoch change
    // -----------------------------------------------------------------------

    /// Invalidate all specializations whose validity epoch does not match
    /// the new epoch. Returns the list of invalidated linkage IDs with their
    /// rollback hashes.
    pub fn on_epoch_change(
        &mut self,
        new_epoch: SecurityEpoch,
        trace_id: &str,
    ) -> Vec<(LinkageId, ContentHash)> {
        let old_epoch = self.current_epoch;
        self.current_epoch = new_epoch;

        let mut rollbacks = Vec::new();

        // Collect IDs to invalidate first (deterministic BTreeMap order).
        let to_invalidate: Vec<LinkageId> = self
            .linkages
            .iter()
            .filter(|(_, r)| r.active && r.validity_epoch != new_epoch)
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_invalidate {
            if let Some(record) = self.linkages.get_mut(&id) {
                record.active = false;
                let baseline_hash = record.rollback.baseline_ir3_hash.clone();
                rollbacks.push((id.clone(), baseline_hash));
                self.invalidations.push((
                    id,
                    InvalidationCause::EpochChange {
                        old_epoch,
                        new_epoch,
                    },
                ));
            }
        }

        self.emit_event(trace_id, "on_epoch_change", "ok", None);
        rollbacks
    }

    // -----------------------------------------------------------------------
    // Invalidate a single linkage by proof revocation
    // -----------------------------------------------------------------------

    /// Invalidate a linkage because one of its proofs was revoked.
    pub fn invalidate_by_proof(
        &mut self,
        proof_id: &str,
        trace_id: &str,
    ) -> Vec<(LinkageId, ContentHash)> {
        let mut rollbacks = Vec::new();

        let to_invalidate: Vec<LinkageId> = self
            .linkages
            .iter()
            .filter(|(_, r)| r.active && r.proof_inputs.iter().any(|p| p.proof_id == proof_id))
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_invalidate {
            if let Some(record) = self.linkages.get_mut(&id) {
                record.active = false;
                let baseline_hash = record.rollback.baseline_ir3_hash.clone();
                rollbacks.push((id.clone(), baseline_hash));
                self.invalidations.push((
                    id,
                    InvalidationCause::ProofRevoked {
                        proof_id: proof_id.to_string(),
                    },
                ));
            }
        }

        if !rollbacks.is_empty() {
            self.emit_event(trace_id, "invalidate_by_proof", "ok", None);
        }
        rollbacks
    }

    // -----------------------------------------------------------------------
    // Manual invalidation
    // -----------------------------------------------------------------------

    /// Manually invalidate a specific linkage.
    pub fn invalidate_manual(
        &mut self,
        linkage_id: &LinkageId,
        operator_id: &str,
        trace_id: &str,
    ) -> Result<ContentHash, LinkageError> {
        let record =
            self.linkages
                .get_mut(linkage_id)
                .ok_or_else(|| LinkageError::LinkageNotFound {
                    id: linkage_id.0.clone(),
                })?;

        if !record.active {
            return Err(LinkageError::AlreadyInactive {
                id: linkage_id.0.clone(),
            });
        }

        record.active = false;
        let baseline_hash = record.rollback.baseline_ir3_hash.clone();
        self.invalidations.push((
            linkage_id.clone(),
            InvalidationCause::ManualInvalidation {
                operator_id: operator_id.to_string(),
            },
        ));
        self.emit_event(trace_id, "invalidate_manual", "ok", None);
        Ok(baseline_hash)
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    /// Get all active linkage records.
    pub fn active_linkages(&self) -> Vec<&LinkageRecord> {
        self.linkages.values().filter(|r| r.active).collect()
    }

    /// Get a specific linkage record.
    pub fn get(&self, id: &LinkageId) -> Option<&LinkageRecord> {
        self.linkages.get(id)
    }

    /// Total number of registered linkages (active + inactive).
    pub fn total_count(&self) -> usize {
        self.linkages.len()
    }

    /// Number of active linkages.
    pub fn active_count(&self) -> usize {
        self.linkages.values().filter(|r| r.active).count()
    }

    /// Number of invalidated linkages.
    pub fn inactive_count(&self) -> usize {
        self.linkages.values().filter(|r| !r.active).count()
    }

    /// Build a rollback plan: for each active linkage, return (linkage_id,
    /// baseline_ir3_hash) so the caller can revert to unspecialized code.
    pub fn rollback_plan(&self) -> Vec<(LinkageId, ContentHash)> {
        self.linkages
            .iter()
            .filter(|(_, r)| r.active)
            .map(|(id, r)| (id.clone(), r.rollback.baseline_ir3_hash.clone()))
            .collect()
    }

    /// Collect proof inputs consumed by all active linkages.
    pub fn consumed_proof_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .linkages
            .values()
            .filter(|r| r.active)
            .flat_map(|r| r.proof_inputs.iter().map(|p| p.proof_id.clone()))
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Produce IR4 witness events for all active specializations at a given
    /// logical tick.
    pub fn produce_witness_events(&self, base_seq: u64, tick: u64) -> Vec<WitnessEvent> {
        self.linkages
            .values()
            .filter(|r| r.active)
            .enumerate()
            .map(|(i, _r)| WitnessEvent {
                seq: base_seq + i as u64,
                kind: WitnessEventKind::CapabilityChecked,
                instruction_index: 0,
                payload_hash: ContentHash::compute(b"specialization-active"),
                timestamp_tick: tick,
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn emit_event(&mut self, trace_id: &str, event: &str, outcome: &str, error_code: Option<&str>) {
        self.events.push(LinkageEvent {
            trace_id: trace_id.to_string(),
            decision_id: String::new(),
            policy_id: self.policy_id.clone(),
            component: "proof_specialization_linkage".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(String::from),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;

    // Helpers
    fn test_epoch(val: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(val)
    }

    fn test_hash(data: &[u8]) -> ContentHash {
        ContentHash::compute(data)
    }

    fn make_proof_input(id: &str, epoch: u64) -> ProofInputRef {
        ProofInputRef {
            proof_id: id.to_string(),
            proof_type: ProofType::CapabilityWitness,
            proof_epoch: test_epoch(epoch),
            validity_window_ticks: 1000,
        }
    }

    fn make_linkage(id: &str, epoch: u64, proof_ids: &[&str]) -> LinkageRecord {
        let baseline = test_hash(format!("baseline-{id}").as_bytes());
        let specialized = test_hash(format!("specialized-{id}").as_bytes());
        LinkageRecord {
            id: LinkageId::new(id),
            proof_inputs: proof_ids
                .iter()
                .map(|pid| make_proof_input(pid, epoch))
                .collect(),
            optimization_class: OptimizationClass::HostcallDispatchSpecialization,
            validity_epoch: test_epoch(epoch),
            specialized_ir3_hash: specialized,
            rollback: RollbackState {
                baseline_ir3_hash: baseline,
                activation_epoch: test_epoch(epoch),
                activation_tick: 100,
            },
            active: true,
            performance_delta: None,
            execution_count: 0,
        }
    }

    fn make_engine(epoch: u64) -> LinkageEngine {
        LinkageEngine::new("test-policy", test_epoch(epoch))
    }

    fn make_ir3() -> Ir3Module {
        Ir3Module::new(test_hash(b"source"), "test-source")
    }

    fn make_ir4() -> Ir4Module {
        Ir4Module::new(test_hash(b"ir3-exec"), "test-witness")
    }

    // -----------------------------------------------------------------------
    // LinkageId
    // -----------------------------------------------------------------------

    #[test]
    fn linkage_id_display() {
        let id = LinkageId::new("link-1");
        assert_eq!(id.to_string(), "link-1");
        assert_eq!(id.as_str(), "link-1");
    }

    #[test]
    fn linkage_id_serde_roundtrip() {
        let id = LinkageId::new("link-42");
        let json = serde_json::to_string(&id).unwrap();
        let back: LinkageId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // -----------------------------------------------------------------------
    // ProofInputRef
    // -----------------------------------------------------------------------

    #[test]
    fn proof_input_ref_serde_roundtrip() {
        let input = make_proof_input("proof-1", 5);
        let json = serde_json::to_string(&input).unwrap();
        let back: ProofInputRef = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    // -----------------------------------------------------------------------
    // PerformanceDelta
    // -----------------------------------------------------------------------

    #[test]
    fn performance_delta_neutral() {
        let d = PerformanceDelta::NEUTRAL;
        assert_eq!(d.speedup_millionths, 1_000_000);
        assert_eq!(d.instruction_ratio_millionths, 1_000_000);
    }

    #[test]
    fn performance_delta_default_is_neutral() {
        assert_eq!(PerformanceDelta::default(), PerformanceDelta::NEUTRAL);
    }

    #[test]
    fn performance_delta_serde_roundtrip() {
        let d = PerformanceDelta {
            speedup_millionths: 1_500_000,
            instruction_ratio_millionths: 800_000,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // -----------------------------------------------------------------------
    // RollbackState
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_state_serde_roundtrip() {
        let rs = RollbackState {
            baseline_ir3_hash: test_hash(b"baseline"),
            activation_epoch: test_epoch(3),
            activation_tick: 42,
        };
        let json = serde_json::to_string(&rs).unwrap();
        let back: RollbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(rs, back);
    }

    // -----------------------------------------------------------------------
    // LinkageRecord
    // -----------------------------------------------------------------------

    #[test]
    fn linkage_record_to_ir3_linkage() {
        let record = make_linkage("link-1", 5, &["proof-a", "proof-b"]);
        let ir3_linkage = record.to_ir3_linkage();
        assert_eq!(ir3_linkage.proof_input_ids, vec!["proof-a", "proof-b"]);
        assert_eq!(
            ir3_linkage.optimization_class,
            OptimizationClass::HostcallDispatchSpecialization.to_string()
        );
        assert_eq!(ir3_linkage.validity_epoch, 5);
        assert_eq!(
            ir3_linkage.rollback_token,
            record.rollback.baseline_ir3_hash
        );
    }

    #[test]
    fn linkage_record_proofs_valid_at() {
        let record = make_linkage("link-1", 5, &["proof-a"]);
        assert!(record.proofs_valid_at(test_epoch(5)));
        assert!(record.proofs_valid_at(test_epoch(10)));
        // Proof was made at epoch 5, so epoch 3 should fail
        assert!(!record.proofs_valid_at(test_epoch(3)));
    }

    #[test]
    fn linkage_record_serde_roundtrip() {
        let record = make_linkage("link-1", 5, &["proof-a", "proof-b"]);
        let json = serde_json::to_string(&record).unwrap();
        let back: LinkageRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // -----------------------------------------------------------------------
    // InvalidationCause
    // -----------------------------------------------------------------------

    #[test]
    fn invalidation_cause_display() {
        let epoch = InvalidationCause::EpochChange {
            old_epoch: test_epoch(1),
            new_epoch: test_epoch(2),
        };
        assert!(epoch.to_string().contains("epoch_change"));

        let revoked = InvalidationCause::ProofRevoked {
            proof_id: "p1".to_string(),
        };
        assert!(revoked.to_string().contains("proof_revoked(p1)"));

        let policy = InvalidationCause::PolicyChange {
            reason: "new-policy".to_string(),
        };
        assert!(policy.to_string().contains("policy_change"));

        let manual = InvalidationCause::ManualInvalidation {
            operator_id: "op-1".to_string(),
        };
        assert!(manual.to_string().contains("manual_invalidation"));
    }

    #[test]
    fn invalidation_cause_serde_roundtrip() {
        let cause = InvalidationCause::EpochChange {
            old_epoch: test_epoch(1),
            new_epoch: test_epoch(2),
        };
        let json = serde_json::to_string(&cause).unwrap();
        let back: InvalidationCause = serde_json::from_str(&json).unwrap();
        assert_eq!(cause, back);
    }

    // -----------------------------------------------------------------------
    // Error codes
    // -----------------------------------------------------------------------

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            error_code(&LinkageError::DuplicateLinkage {
                id: "x".to_string()
            }),
            "LINKAGE_DUPLICATE"
        );
        assert_eq!(
            error_code(&LinkageError::LinkageNotFound {
                id: "x".to_string()
            }),
            "LINKAGE_NOT_FOUND"
        );
        assert_eq!(
            error_code(&LinkageError::AlreadyInactive {
                id: "x".to_string()
            }),
            "LINKAGE_ALREADY_INACTIVE"
        );
        assert_eq!(
            error_code(&LinkageError::EmptyProofInputs),
            "LINKAGE_EMPTY_PROOF_INPUTS"
        );
        assert_eq!(
            error_code(&LinkageError::EpochMismatch {
                linkage_epoch: test_epoch(1),
                current_epoch: test_epoch(2),
            }),
            "LINKAGE_EPOCH_MISMATCH"
        );
        assert_eq!(
            error_code(&LinkageError::Ir3AlreadySpecialized),
            "LINKAGE_IR3_ALREADY_SPECIALIZED"
        );
    }

    #[test]
    fn error_display() {
        let err = LinkageError::DuplicateLinkage {
            id: "x".to_string(),
        };
        assert!(err.to_string().contains("duplicate linkage"));
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    #[test]
    fn register_linkage() {
        let mut engine = make_engine(5);
        let record = make_linkage("link-1", 5, &["proof-a"]);
        engine.register(record, "t1").unwrap();
        assert_eq!(engine.total_count(), 1);
        assert_eq!(engine.active_count(), 1);
    }

    #[test]
    fn register_duplicate_rejected() {
        let mut engine = make_engine(5);
        let r1 = make_linkage("link-1", 5, &["proof-a"]);
        let r2 = make_linkage("link-1", 5, &["proof-b"]);
        engine.register(r1, "t1").unwrap();
        let err = engine.register(r2, "t2").unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_DUPLICATE");
    }

    #[test]
    fn register_empty_proofs_rejected() {
        let mut engine = make_engine(5);
        let mut record = make_linkage("link-1", 5, &["proof-a"]);
        record.proof_inputs.clear();
        let err = engine.register(record, "t1").unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_EMPTY_PROOF_INPUTS");
    }

    // -----------------------------------------------------------------------
    // Attach to IR3
    // -----------------------------------------------------------------------

    #[test]
    fn attach_to_ir3_module() {
        let mut engine = make_engine(5);
        let record = make_linkage("link-1", 5, &["proof-a"]);
        engine.register(record, "t1").unwrap();

        let mut ir3 = make_ir3();
        assert!(ir3.specialization.is_none());

        let lid = LinkageId::new("link-1");
        engine.attach_to_ir3(&lid, &mut ir3, "t2").unwrap();
        assert!(ir3.specialization.is_some());
        let spec = ir3.specialization.unwrap();
        assert_eq!(spec.proof_input_ids, vec!["proof-a"]);
        assert_eq!(spec.validity_epoch, 5);
    }

    #[test]
    fn attach_to_already_specialized_ir3_rejected() {
        let mut engine = make_engine(5);
        let r1 = make_linkage("link-1", 5, &["proof-a"]);
        let r2 = make_linkage("link-2", 5, &["proof-b"]);
        engine.register(r1, "t1").unwrap();
        engine.register(r2, "t1").unwrap();

        let mut ir3 = make_ir3();
        let lid1 = LinkageId::new("link-1");
        let lid2 = LinkageId::new("link-2");
        engine.attach_to_ir3(&lid1, &mut ir3, "t2").unwrap();

        let err = engine.attach_to_ir3(&lid2, &mut ir3, "t3").unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_IR3_ALREADY_SPECIALIZED");
    }

    #[test]
    fn attach_inactive_linkage_rejected() {
        let mut engine = make_engine(5);
        let mut record = make_linkage("link-1", 5, &["proof-a"]);
        record.active = false;
        engine.register(record, "t1").unwrap();

        let mut ir3 = make_ir3();
        let lid = LinkageId::new("link-1");
        let err = engine.attach_to_ir3(&lid, &mut ir3, "t2").unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_ALREADY_INACTIVE");
    }

    #[test]
    fn attach_epoch_mismatch_rejected() {
        let mut engine = make_engine(5);
        let record = make_linkage("link-1", 3, &["proof-a"]); // epoch 3, engine at 5
        engine.register(record, "t1").unwrap();

        let mut ir3 = make_ir3();
        let lid = LinkageId::new("link-1");
        let err = engine.attach_to_ir3(&lid, &mut ir3, "t2").unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_EPOCH_MISMATCH");
    }

    #[test]
    fn attach_nonexistent_linkage_rejected() {
        let mut engine = make_engine(5);
        let mut ir3 = make_ir3();
        let lid = LinkageId::new("link-999");
        let err = engine.attach_to_ir3(&lid, &mut ir3, "t1").unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_NOT_FOUND");
    }

    // -----------------------------------------------------------------------
    // Record execution in IR4
    // -----------------------------------------------------------------------

    #[test]
    fn record_execution_updates_ir4() {
        let mut engine = make_engine(5);
        let record = make_linkage("link-1", 5, &["proof-a"]);
        engine.register(record, "t1").unwrap();

        let mut ir4 = make_ir4();
        ir4.instructions_executed = 100;
        ir4.duration_ticks = 50;

        let lid = LinkageId::new("link-1");
        let perf = PerformanceDelta {
            speedup_millionths: 1_200_000,
            instruction_ratio_millionths: 900_000,
        };
        let exec = engine.record_execution(&lid, &mut ir4, perf, "t2").unwrap();

        assert_eq!(exec.linkage_id, lid);
        assert_eq!(exec.instructions_executed, 100);
        assert_eq!(exec.duration_ticks, 50);
        assert_eq!(exec.performance_delta.speedup_millionths, 1_200_000);

        // IR4 updated
        assert!(
            ir4.active_specialization_ids
                .contains(&"link-1".to_string())
        );

        // Engine updated
        let stored = engine.get(&lid).unwrap();
        assert_eq!(stored.execution_count, 1);
        assert_eq!(
            stored.performance_delta.unwrap().speedup_millionths,
            1_200_000
        );
    }

    #[test]
    fn record_execution_nonexistent_rejected() {
        let mut engine = make_engine(5);
        let mut ir4 = make_ir4();
        let lid = LinkageId::new("link-999");
        let err = engine
            .record_execution(&lid, &mut ir4, PerformanceDelta::NEUTRAL, "t1")
            .unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_NOT_FOUND");
    }

    #[test]
    fn record_execution_idempotent_ir4_ids() {
        let mut engine = make_engine(5);
        let record = make_linkage("link-1", 5, &["proof-a"]);
        engine.register(record, "t1").unwrap();

        let mut ir4 = make_ir4();
        let lid = LinkageId::new("link-1");
        engine
            .record_execution(&lid, &mut ir4, PerformanceDelta::NEUTRAL, "t2")
            .unwrap();
        engine
            .record_execution(&lid, &mut ir4, PerformanceDelta::NEUTRAL, "t3")
            .unwrap();

        // Should only appear once in IR4
        assert_eq!(
            ir4.active_specialization_ids
                .iter()
                .filter(|id| *id == "link-1")
                .count(),
            1
        );
        // But execution count should be 2
        assert_eq!(engine.get(&lid).unwrap().execution_count, 2);
    }

    // -----------------------------------------------------------------------
    // Epoch change invalidation
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_change_invalidates_old_epoch_linkages() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-old", 5, &["proof-a"]), "t1")
            .unwrap();

        let rollbacks = engine.on_epoch_change(test_epoch(6), "t2");
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].0, LinkageId::new("link-old"));

        assert_eq!(engine.active_count(), 0);
        assert_eq!(engine.inactive_count(), 1);
        assert_eq!(engine.current_epoch(), test_epoch(6));
    }

    #[test]
    fn epoch_change_preserves_matching_epoch_linkages() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();

        // Register one at epoch 6 too
        let mut r2 = make_linkage("link-2", 6, &["proof-b"]);
        r2.validity_epoch = test_epoch(6);
        engine.register(r2, "t1").unwrap();

        let rollbacks = engine.on_epoch_change(test_epoch(6), "t2");
        assert_eq!(rollbacks.len(), 1); // Only link-1 invalidated
        assert_eq!(rollbacks[0].0, LinkageId::new("link-1"));

        assert_eq!(engine.active_count(), 1);
        assert!(engine.get(&LinkageId::new("link-2")).unwrap().active);
    }

    #[test]
    fn epoch_change_returns_rollback_hashes() {
        let mut engine = make_engine(5);
        let record = make_linkage("link-1", 5, &["proof-a"]);
        let expected_baseline = record.rollback.baseline_ir3_hash.clone();
        engine.register(record, "t1").unwrap();

        let rollbacks = engine.on_epoch_change(test_epoch(6), "t2");
        assert_eq!(rollbacks[0].1, expected_baseline);
    }

    #[test]
    fn epoch_change_logs_invalidation_cause() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();
        engine.on_epoch_change(test_epoch(6), "t2");

        assert_eq!(engine.invalidations().len(), 1);
        match &engine.invalidations()[0].1 {
            InvalidationCause::EpochChange {
                old_epoch,
                new_epoch,
            } => {
                assert_eq!(*old_epoch, test_epoch(5));
                assert_eq!(*new_epoch, test_epoch(6));
            }
            other => panic!("expected EpochChange, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Proof revocation invalidation
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_by_proof_deactivates_matching() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a", "proof-b"]), "t1")
            .unwrap();
        engine
            .register(make_linkage("link-2", 5, &["proof-c"]), "t1")
            .unwrap();

        let rollbacks = engine.invalidate_by_proof("proof-a", "t2");
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].0, LinkageId::new("link-1"));

        assert!(!engine.get(&LinkageId::new("link-1")).unwrap().active);
        assert!(engine.get(&LinkageId::new("link-2")).unwrap().active);
    }

    #[test]
    fn invalidate_by_proof_no_match_returns_empty() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();

        let rollbacks = engine.invalidate_by_proof("proof-zzz", "t2");
        assert!(rollbacks.is_empty());
        assert!(engine.get(&LinkageId::new("link-1")).unwrap().active);
    }

    // -----------------------------------------------------------------------
    // Manual invalidation
    // -----------------------------------------------------------------------

    #[test]
    fn manual_invalidation() {
        let mut engine = make_engine(5);
        let record = make_linkage("link-1", 5, &["proof-a"]);
        let expected_baseline = record.rollback.baseline_ir3_hash.clone();
        engine.register(record, "t1").unwrap();

        let lid = LinkageId::new("link-1");
        let baseline = engine.invalidate_manual(&lid, "operator-1", "t2").unwrap();
        assert_eq!(baseline, expected_baseline);
        assert!(!engine.get(&lid).unwrap().active);
    }

    #[test]
    fn manual_invalidation_already_inactive() {
        let mut engine = make_engine(5);
        let mut record = make_linkage("link-1", 5, &["proof-a"]);
        record.active = false;
        engine.register(record, "t1").unwrap();

        let lid = LinkageId::new("link-1");
        let err = engine
            .invalidate_manual(&lid, "operator-1", "t2")
            .unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_ALREADY_INACTIVE");
    }

    #[test]
    fn manual_invalidation_not_found() {
        let mut engine = make_engine(5);
        let lid = LinkageId::new("link-999");
        let err = engine
            .invalidate_manual(&lid, "operator-1", "t1")
            .unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_NOT_FOUND");
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    #[test]
    fn consumed_proof_ids_deduped() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a", "proof-b"]), "t1")
            .unwrap();
        engine
            .register(make_linkage("link-2", 5, &["proof-a", "proof-c"]), "t1")
            .unwrap();

        let ids = engine.consumed_proof_ids();
        assert_eq!(ids, vec!["proof-a", "proof-b", "proof-c"]);
    }

    #[test]
    fn rollback_plan_returns_active_only() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();
        let mut inactive = make_linkage("link-2", 5, &["proof-b"]);
        inactive.active = false;
        engine.register(inactive, "t1").unwrap();

        let plan = engine.rollback_plan();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0, LinkageId::new("link-1"));
    }

    #[test]
    fn active_linkages_returns_only_active() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();
        let mut inactive = make_linkage("link-2", 5, &["proof-b"]);
        inactive.active = false;
        engine.register(inactive, "t1").unwrap();

        let active = engine.active_linkages();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, LinkageId::new("link-1"));
    }

    // -----------------------------------------------------------------------
    // Witness event production
    // -----------------------------------------------------------------------

    #[test]
    fn produce_witness_events_for_active() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();
        engine
            .register(make_linkage("link-2", 5, &["proof-b"]), "t1")
            .unwrap();

        let events = engine.produce_witness_events(100, 42);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 100);
        assert_eq!(events[1].seq, 101);
        assert_eq!(events[0].timestamp_tick, 42);
    }

    #[test]
    fn produce_witness_events_excludes_inactive() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();
        let mut inactive = make_linkage("link-2", 5, &["proof-b"]);
        inactive.active = false;
        engine.register(inactive, "t1").unwrap();

        let events = engine.produce_witness_events(0, 0);
        assert_eq!(events.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Event logging
    // -----------------------------------------------------------------------

    #[test]
    fn events_are_recorded() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-1", 5, &["proof-a"]), "t1")
            .unwrap();

        assert!(!engine.events().is_empty());
        assert_eq!(engine.events()[0].event, "register");
        assert_eq!(engine.events()[0].outcome, "ok");
        assert_eq!(engine.events()[0].component, "proof_specialization_linkage");
    }

    #[test]
    fn error_events_carry_error_code() {
        let mut engine = make_engine(5);
        let mut record = make_linkage("link-1", 5, &["proof-a"]);
        record.proof_inputs.clear();
        let _ = engine.register(record, "t1");

        let last = engine.events().last().unwrap();
        assert_eq!(last.outcome, "rejected");
        assert_eq!(
            last.error_code.as_deref(),
            Some("LINKAGE_EMPTY_PROOF_INPUTS")
        );
    }

    // -----------------------------------------------------------------------
    // Execution record serde
    // -----------------------------------------------------------------------

    #[test]
    fn execution_record_serde_roundtrip() {
        let er = ExecutionRecord {
            linkage_id: LinkageId::new("link-1"),
            witness_hash: test_hash(b"witness"),
            performance_delta: PerformanceDelta {
                speedup_millionths: 1_300_000,
                instruction_ratio_millionths: 700_000,
            },
            instructions_executed: 500,
            duration_ticks: 200,
        };
        let json = serde_json::to_string(&er).unwrap();
        let back: ExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(er, back);
    }

    // -----------------------------------------------------------------------
    // Full lifecycle: create → attach → execute → epoch change → rollback
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle() {
        let mut engine = make_engine(5);

        // 1. Register
        let record = make_linkage("link-1", 5, &["proof-a", "proof-b"]);
        let expected_baseline = record.rollback.baseline_ir3_hash.clone();
        engine.register(record, "t1").unwrap();
        assert_eq!(engine.active_count(), 1);

        // 2. Attach to IR3
        let mut ir3 = make_ir3();
        let lid = LinkageId::new("link-1");
        engine.attach_to_ir3(&lid, &mut ir3, "t2").unwrap();
        assert!(ir3.specialization.is_some());

        // 3. Record execution in IR4
        let mut ir4 = make_ir4();
        ir4.instructions_executed = 1000;
        ir4.duration_ticks = 500;
        let perf = PerformanceDelta {
            speedup_millionths: 1_500_000,
            instruction_ratio_millionths: 750_000,
        };
        let exec = engine.record_execution(&lid, &mut ir4, perf, "t3").unwrap();
        assert_eq!(exec.instructions_executed, 1000);
        assert!(
            ir4.active_specialization_ids
                .contains(&"link-1".to_string())
        );

        // 4. Epoch change → invalidate
        let rollbacks = engine.on_epoch_change(test_epoch(6), "t4");
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].0, LinkageId::new("link-1"));
        assert_eq!(rollbacks[0].1, expected_baseline);
        assert_eq!(engine.active_count(), 0);
        assert_eq!(engine.inactive_count(), 1);

        // 5. Cannot attach invalidated linkage
        let mut ir3_2 = make_ir3();
        let err = engine.attach_to_ir3(&lid, &mut ir3_2, "t5").unwrap_err();
        assert_eq!(error_code(&err), "LINKAGE_ALREADY_INACTIVE");
    }

    // -----------------------------------------------------------------------
    // Multiple specializations lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_specializations_partial_invalidation() {
        let mut engine = make_engine(5);
        engine
            .register(make_linkage("link-epoch5", 5, &["proof-a"]), "t1")
            .unwrap();

        let mut r2 = make_linkage("link-epoch6", 6, &["proof-b"]);
        r2.validity_epoch = test_epoch(6);
        engine.register(r2, "t1").unwrap();

        // Advance to epoch 6
        let rollbacks = engine.on_epoch_change(test_epoch(6), "t2");
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].0, LinkageId::new("link-epoch5"));

        // link-epoch6 should still be active
        assert!(engine.get(&LinkageId::new("link-epoch6")).unwrap().active);
        assert!(!engine.get(&LinkageId::new("link-epoch5")).unwrap().active);
    }

    // -----------------------------------------------------------------------
    // Deterministic BTreeMap ordering
    // -----------------------------------------------------------------------

    #[test]
    fn invalidation_order_is_deterministic() {
        let mut engine = make_engine(5);
        // Insert in non-alphabetical order
        engine
            .register(make_linkage("link-c", 5, &["proof-c"]), "t1")
            .unwrap();
        engine
            .register(make_linkage("link-a", 5, &["proof-a"]), "t1")
            .unwrap();
        engine
            .register(make_linkage("link-b", 5, &["proof-b"]), "t1")
            .unwrap();

        let rollbacks = engine.on_epoch_change(test_epoch(6), "t2");
        // BTreeMap order: a, b, c
        assert_eq!(rollbacks[0].0, LinkageId::new("link-a"));
        assert_eq!(rollbacks[1].0, LinkageId::new("link-b"));
        assert_eq!(rollbacks[2].0, LinkageId::new("link-c"));
    }

    // -----------------------------------------------------------------------
    // LinkageEvent serde
    // -----------------------------------------------------------------------

    #[test]
    fn linkage_event_serde_roundtrip() {
        let event = LinkageEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "proof_specialization_linkage".to_string(),
            event: "register".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: LinkageEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // -----------------------------------------------------------------------
    // Schema hash stability
    // -----------------------------------------------------------------------

    #[test]
    fn schema_hash_is_stable() {
        let hash = ContentHash::compute(SCHEMA_DEF);
        let hash2 = ContentHash::compute(SCHEMA_DEF);
        assert_eq!(hash, hash2);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn invalidation_cause_display_all_distinct() {
        let variants = vec![
            InvalidationCause::EpochChange {
                old_epoch: SecurityEpoch::from_raw(1),
                new_epoch: SecurityEpoch::from_raw(2),
            },
            InvalidationCause::ProofRevoked {
                proof_id: "p1".into(),
            },
            InvalidationCause::PolicyChange {
                reason: "update".into(),
            },
            InvalidationCause::ManualInvalidation {
                operator_id: "admin".into(),
            },
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn linkage_error_serde_roundtrip() {
        let variants = vec![
            LinkageError::DuplicateLinkage { id: "l1".into() },
            LinkageError::LinkageNotFound { id: "l2".into() },
            LinkageError::AlreadyInactive { id: "l3".into() },
            LinkageError::EmptyProofInputs,
            LinkageError::EpochMismatch {
                linkage_epoch: SecurityEpoch::from_raw(5),
                current_epoch: SecurityEpoch::from_raw(3),
            },
            LinkageError::Ir3AlreadySpecialized,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LinkageError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn linkage_error_display_all_distinct() {
        let variants = vec![
            LinkageError::DuplicateLinkage { id: "l1".into() },
            LinkageError::LinkageNotFound { id: "l2".into() },
            LinkageError::AlreadyInactive { id: "l3".into() },
            LinkageError::EmptyProofInputs,
            LinkageError::EpochMismatch {
                linkage_epoch: SecurityEpoch::from_raw(5),
                current_epoch: SecurityEpoch::from_raw(3),
            },
            LinkageError::Ir3AlreadySpecialized,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn performance_delta_default_equals_neutral() {
        let d = PerformanceDelta::default();
        assert_eq!(d, PerformanceDelta::NEUTRAL);
        assert_eq!(d.speedup_millionths, 1_000_000);
        assert_eq!(d.instruction_ratio_millionths, 1_000_000);
    }

    #[test]
    fn linkage_record_proofs_valid_at_epoch() {
        let linkage = make_linkage("link-1", 5, &["proof-a"]);
        assert!(linkage.proofs_valid_at(test_epoch(5)));
        assert!(linkage.proofs_valid_at(test_epoch(10)));
    }

    #[test]
    fn linkage_record_to_ir3_linkage_fields() {
        let linkage = make_linkage("link-1", 5, &["proof-a", "proof-b"]);
        let ir3 = linkage.to_ir3_linkage();
        assert_eq!(ir3.proof_input_ids.len(), 2);
        assert_eq!(ir3.proof_input_ids[0], "proof-a");
        assert_eq!(ir3.proof_input_ids[1], "proof-b");
    }
}
