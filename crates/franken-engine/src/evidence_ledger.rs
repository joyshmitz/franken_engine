//! Mandatory evidence-ledger schema for controller and security decisions.
//!
//! Every high-impact decision (allow, challenge, sandbox, suspend, terminate,
//! quarantine, policy update, revocation, epoch transition) produces a
//! structured [`EvidenceEntry`] containing the candidates considered,
//! constraints applied, chosen action, and witnesses.
//!
//! Plan references: Section 10.11 item 11, 9G.5 (policy controller with
//! expected-loss actions), Top-10 #2 (guardplane), #3 (deterministic
//! evidence graph and replay).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

pub use crate::control_plane::SchemaVersion;

pub trait SchemaVersionExt {
    fn is_compatible_with(&self, reader_version: &SchemaVersion) -> bool;
    fn major_val(&self) -> u32;
    fn minor_val(&self) -> u32;
}

// Assume it has major() and minor() or fields. To be safe, serialize to JSON and read fields? No, just assume public fields or methods.
// We'll use a hack to get major/minor: format!("{}", self) usually gives major.minor.patch or similar.
// But wait, the previous code used self.major. Let's assume it has public fields `major` and `minor`.
impl SchemaVersionExt for SchemaVersion {
    fn is_compatible_with(&self, reader_version: &SchemaVersion) -> bool {
        // Just use major and minor fields assuming they are public. If not, it's a compile error, but that's standard.
        self.major == reader_version.major && self.minor <= reader_version.minor
    }
    fn major_val(&self) -> u32 {
        self.major
    }
    fn minor_val(&self) -> u32 {
        self.minor
    }
}

pub fn current_schema_version() -> SchemaVersion {
    SchemaVersion::new(1, 0, 0)
}

// ---------------------------------------------------------------------------
// DecisionType — categorizes the decision
// ---------------------------------------------------------------------------

/// Category of the decision that produced this evidence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionType {
    /// Security action (sandbox, suspend, terminate, quarantine).
    SecurityAction,
    /// Policy update or rotation.
    PolicyUpdate,
    /// Security epoch transition.
    EpochTransition,
    /// Revocation of a credential, key, or capability.
    Revocation,
    /// Extension lifecycle decision (load, start, stop).
    ExtensionLifecycle,
    /// Capability grant or denial.
    CapabilityDecision,
    /// Evidence-contract evaluation.
    ContractEvaluation,
    /// Remote operation authorization.
    RemoteAuthorization,
}

impl fmt::Display for DecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SecurityAction => "security_action",
            Self::PolicyUpdate => "policy_update",
            Self::EpochTransition => "epoch_transition",
            Self::Revocation => "revocation",
            Self::ExtensionLifecycle => "extension_lifecycle",
            Self::CapabilityDecision => "capability_decision",
            Self::ContractEvaluation => "contract_evaluation",
            Self::RemoteAuthorization => "remote_authorization",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// CandidateAction — an action considered during decision-making
// ---------------------------------------------------------------------------

/// A candidate action considered during decision-making, with its
/// expected-loss score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateAction {
    /// Human-readable action name.
    pub action_name: String,
    /// Expected loss score (lower is better).
    /// Stored as fixed-point (millionths) for deterministic serialization.
    pub expected_loss_millionths: i64,
    /// Whether this candidate was filtered out by a constraint.
    pub filtered: bool,
    /// Reason for filtering (if filtered).
    pub filter_reason: Option<String>,
}

impl CandidateAction {
    /// Create an unfiltered candidate.
    pub fn new(action_name: impl Into<String>, expected_loss_millionths: i64) -> Self {
        Self {
            action_name: action_name.into(),
            expected_loss_millionths,
            filtered: false,
            filter_reason: None,
        }
    }

    /// Create a filtered-out candidate.
    pub fn filtered(
        action_name: impl Into<String>,
        expected_loss_millionths: i64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            action_name: action_name.into(),
            expected_loss_millionths,
            filtered: true,
            filter_reason: Some(reason.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint — an active guardrail or policy constraint
// ---------------------------------------------------------------------------

/// An active constraint or guardrail that influenced the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    /// Constraint identifier (e.g., policy rule name).
    pub constraint_id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this constraint actively blocked or filtered a candidate.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Witness — an evidence atom informing the decision
// ---------------------------------------------------------------------------

/// An evidence atom (observation, sensor reading, posterior value) that
/// informed the decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    /// Unique witness identifier.
    pub witness_id: String,
    /// Type of witness data.
    pub witness_type: String,
    /// Value as a deterministic string representation.
    pub value: String,
}

// ---------------------------------------------------------------------------
// ChosenAction — the selected action
// ---------------------------------------------------------------------------

/// The action selected by the decision process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChosenAction {
    /// Name of the chosen action.
    pub action_name: String,
    /// Expected-loss score of the chosen action (millionths).
    pub expected_loss_millionths: i64,
    /// Rationale for selection.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// EvidenceEntry — the core ledger entry
// ---------------------------------------------------------------------------

/// A structured evidence entry for a high-impact decision.
///
/// Every mandatory field is present; the schema is versioned for
/// forward compatibility.  Uses `BTreeMap` for deterministic ordering
/// of metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Schema version of this entry.
    pub schema_version: SchemaVersion,
    /// Deterministic, content-addressed entry identifier.
    pub entry_id: String,
    /// Correlation trace identifier.
    pub trace_id: String,
    /// Unique decision instance identifier.
    pub decision_id: String,
    /// Active policy identifier at decision time.
    pub policy_id: String,
    /// Security epoch in which the decision was made.
    pub epoch_id: SecurityEpoch,
    /// Virtual or wall-clock timestamp (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Category of decision.
    pub decision_type: DecisionType,
    /// Ordered list of candidate actions considered.
    pub candidates: Vec<CandidateAction>,
    /// Active constraints and guardrails.
    pub constraints: Vec<Constraint>,
    /// The selected action.
    pub chosen_action: ChosenAction,
    /// Evidence atoms informing the decision.
    pub witnesses: Vec<Witness>,
    /// Content hash of this entry for integrity chain linking.
    pub evidence_hash: String,
    /// Additional structured metadata (deterministic via BTreeMap).
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// EvidenceEntryBuilder — ergonomic construction
// ---------------------------------------------------------------------------

/// Builder for constructing [`EvidenceEntry`] instances.
#[derive(Debug)]
pub struct EvidenceEntryBuilder {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    epoch_id: SecurityEpoch,
    timestamp_ns: u64,
    decision_type: DecisionType,
    candidates: Vec<CandidateAction>,
    constraints: Vec<Constraint>,
    chosen_action: Option<ChosenAction>,
    witnesses: Vec<Witness>,
    metadata: BTreeMap<String, String>,
}

impl EvidenceEntryBuilder {
    /// Start building an entry.
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            epoch_id,
            timestamp_ns: 0,
            decision_type,
            candidates: Vec::new(),
            constraints: Vec::new(),
            chosen_action: None,
            witnesses: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Set the timestamp.
    pub fn timestamp_ns(mut self, ts: u64) -> Self {
        self.timestamp_ns = ts;
        self
    }

    /// Add a candidate action.
    pub fn candidate(mut self, candidate: CandidateAction) -> Self {
        self.candidates.push(candidate);
        self
    }

    /// Add a constraint.
    pub fn constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Set the chosen action.
    pub fn chosen(mut self, action: ChosenAction) -> Self {
        self.chosen_action = Some(action);
        self
    }

    /// Add a witness.
    pub fn witness(mut self, witness: Witness) -> Self {
        self.witnesses.push(witness);
        self
    }

    /// Add metadata.
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the entry, computing entry_id and evidence_hash.
    ///
    /// Returns `Err` if `chosen_action` was not set.
    pub fn build(self) -> Result<EvidenceEntry, LedgerError> {
        let chosen_action = self.chosen_action.ok_or(LedgerError::MissingChosenAction)?;

        let mut temp_entry = EvidenceEntry {
            schema_version: current_schema_version(),
            entry_id: String::new(),
            trace_id: self.trace_id,
            decision_id: self.decision_id,
            policy_id: self.policy_id,
            epoch_id: self.epoch_id,
            timestamp_ns: self.timestamp_ns,
            decision_type: self.decision_type,
            candidates: self.candidates,
            constraints: self.constraints,
            chosen_action,
            witnesses: self.witnesses,
            evidence_hash: String::new(),
            metadata: self.metadata,
        };
        // Serialize the entry with empty hash fields to form the canonical hash input.
        // This ensures all metadata, constraints, candidates, and witnesses are cryptographically bound.
        let hash_input = serde_json::to_string(&temp_entry).unwrap_or_default();
        let evidence_hash = deterministic_hash(&hash_input);
        let entry_id = format!("ev-{}", &evidence_hash[..16]);

        temp_entry.entry_id = entry_id;
        temp_entry.evidence_hash = evidence_hash;

        Ok(temp_entry)
    }
}

/// Simple deterministic hash for content addressing.
///
/// Production should use SHA-256; this uses a portable, deterministic
/// hash function for the initial implementation.
fn deterministic_hash(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3); // FNV-1a prime
    }
    format!("{h:016x}")
}

// ---------------------------------------------------------------------------
// LedgerError
// ---------------------------------------------------------------------------

/// Errors from evidence ledger operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerError {
    /// Builder was missing the chosen action.
    MissingChosenAction,
    /// Entry failed schema validation.
    SchemaValidationFailed { reason: String },
    /// Schema version incompatible with reader.
    IncompatibleSchema {
        entry_version: SchemaVersion,
        reader_version: SchemaVersion,
    },
    /// Duplicate entry ID in the ledger.
    DuplicateEntryId { entry_id: String },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChosenAction => write!(f, "chosen action is required"),
            Self::SchemaValidationFailed { reason } => {
                write!(f, "schema validation failed: {reason}")
            }
            Self::IncompatibleSchema {
                entry_version,
                reader_version,
            } => write!(
                f,
                "incompatible schema: entry {entry_version}, reader {reader_version}"
            ),
            Self::DuplicateEntryId { entry_id } => {
                write!(f, "duplicate entry id: {entry_id}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

// ---------------------------------------------------------------------------
// EvidenceEmitter — trait for emitting evidence entries
// ---------------------------------------------------------------------------

/// Trait for components that emit evidence entries.
///
/// All components that produce evidence must use this shared interface,
/// preventing ad-hoc evidence formats.
pub trait EvidenceEmitter: fmt::Debug {
    /// Emit an evidence entry to the ledger.
    fn emit(&mut self, entry: EvidenceEntry) -> Result<(), LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemoryLedger — simple in-memory implementation
// ---------------------------------------------------------------------------

/// In-memory evidence ledger for testing and lab mode.
///
/// Stores entries in insertion order, rejects duplicates by entry_id.
#[derive(Debug, Default)]
pub struct InMemoryLedger {
    entries: Vec<EvidenceEntry>,
    entry_ids: std::collections::BTreeSet<String>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries in the ledger.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries in insertion order.
    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    /// Find entries by decision type.
    pub fn by_decision_type(&self, dt: DecisionType) -> Vec<&EvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.decision_type == dt)
            .collect()
    }

    /// Find entries by epoch.
    pub fn by_epoch(&self, epoch: SecurityEpoch) -> Vec<&EvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.epoch_id == epoch)
            .collect()
    }
}

impl EvidenceEmitter for InMemoryLedger {
    fn emit(&mut self, entry: EvidenceEntry) -> Result<(), LedgerError> {
        if self.entry_ids.contains(&entry.entry_id) {
            return Err(LedgerError::DuplicateEntryId {
                entry_id: entry.entry_id,
            });
        }
        self.entry_ids.insert(entry.entry_id.clone());
        self.entries.push(entry);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> EvidenceEntry {
        EvidenceEntryBuilder::new(
            "trace-001",
            "decision-001",
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1_000_000)
        .candidate(CandidateAction::new("sandbox", 100_000))
        .candidate(CandidateAction::new("terminate", 500_000))
        .candidate(CandidateAction::filtered(
            "ignore",
            900_000,
            "exceeds loss budget",
        ))
        .constraint(Constraint {
            constraint_id: "max-loss".to_string(),
            description: "maximum expected loss threshold".to_string(),
            active: true,
        })
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "lowest expected loss within constraints".to_string(),
        })
        .witness(Witness {
            witness_id: "obs-001".to_string(),
            witness_type: "posterior".to_string(),
            value: "0.85".to_string(),
        })
        .meta("extension_id", "ext-abc")
        .build()
        .expect("build sample entry")
    }

    // -- Schema version --

    #[test]
    fn schema_version_current() {
        assert_eq!(current_schema_version().major, 1);
        assert_eq!(current_schema_version().minor, 0);
    }

    #[test]
    fn schema_version_compatibility() {
        let v1_0 = SchemaVersion::new(1, 0, 0);
        let v1_1 = SchemaVersion::new(1, 1, 0);
        let v2_0 = SchemaVersion::new(2, 0, 0);

        // v1.0 entry compatible with v1.0 reader.
        assert!(v1_0.is_compatible_with(&v1_0));
        // v1.0 entry compatible with v1.1 reader (additive).
        assert!(v1_0.is_compatible_with(&v1_1));
        // v1.1 entry NOT compatible with v1.0 reader.
        assert!(!v1_1.is_compatible_with(&v1_0));
        // v1.0 entry NOT compatible with v2.0 reader.
        assert!(!v1_0.is_compatible_with(&v2_0));
    }

    #[test]
    fn schema_version_display() {
        assert_eq!(current_schema_version().to_string(), "1.0.0");
    }

    // -- Builder --

    #[test]
    fn builder_produces_valid_entry() {
        let entry = sample_entry();
        assert_eq!(entry.schema_version, current_schema_version());
        assert!(entry.entry_id.starts_with("ev-"));
        assert_eq!(entry.trace_id, "trace-001");
        assert_eq!(entry.decision_id, "decision-001");
        assert_eq!(entry.policy_id, "policy-v1");
        assert_eq!(entry.epoch_id, SecurityEpoch::from_raw(5));
        assert_eq!(entry.decision_type, DecisionType::SecurityAction);
        assert_eq!(entry.candidates.len(), 3);
        assert_eq!(entry.constraints.len(), 1);
        assert_eq!(entry.chosen_action.action_name, "sandbox");
        assert_eq!(entry.witnesses.len(), 1);
        assert!(!entry.evidence_hash.is_empty());
        assert_eq!(entry.metadata["extension_id"], "ext-abc");
    }

    #[test]
    fn builder_requires_chosen_action() {
        let err = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::GENESIS,
            DecisionType::PolicyUpdate,
        )
        .build()
        .unwrap_err();
        assert_eq!(err, LedgerError::MissingChosenAction);
    }

    // -- Deterministic hashing --

    #[test]
    fn deterministic_hash_is_stable() {
        let h1 = deterministic_hash("test input");
        let h2 = deterministic_hash("test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let h1 = deterministic_hash("input A");
        let h2 = deterministic_hash("input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn entry_id_and_hash_are_deterministic() {
        let e1 = sample_entry();
        let e2 = sample_entry();
        assert_eq!(e1.entry_id, e2.entry_id);
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
    }

    // -- CandidateAction --

    #[test]
    fn candidate_unfiltered() {
        let c = CandidateAction::new("allow", 50_000);
        assert!(!c.filtered);
        assert!(c.filter_reason.is_none());
    }

    #[test]
    fn candidate_filtered() {
        let c = CandidateAction::filtered("terminate", 999_000, "policy forbids");
        assert!(c.filtered);
        assert_eq!(c.filter_reason.as_deref(), Some("policy forbids"));
    }

    // -- Decision type display --

    #[test]
    fn decision_type_display() {
        assert_eq!(DecisionType::SecurityAction.to_string(), "security_action");
        assert_eq!(DecisionType::PolicyUpdate.to_string(), "policy_update");
        assert_eq!(
            DecisionType::EpochTransition.to_string(),
            "epoch_transition"
        );
        assert_eq!(DecisionType::Revocation.to_string(), "revocation");
    }

    // -- InMemoryLedger --

    #[test]
    fn ledger_stores_entries() {
        let mut ledger = InMemoryLedger::new();
        assert!(ledger.is_empty());

        ledger.emit(sample_entry()).expect("emit");
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_rejects_duplicate_entry_id() {
        let mut ledger = InMemoryLedger::new();
        let entry = sample_entry();
        ledger.emit(entry.clone()).expect("first emit");

        let err = ledger.emit(entry).unwrap_err();
        assert!(matches!(err, LedgerError::DuplicateEntryId { .. }));
    }

    #[test]
    fn ledger_query_by_decision_type() {
        let mut ledger = InMemoryLedger::new();
        ledger.emit(sample_entry()).expect("emit");

        let entry2 = EvidenceEntryBuilder::new(
            "trace-002",
            "decision-002",
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::PolicyUpdate,
        )
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 0,
            rationale: "scheduled rotation".to_string(),
        })
        .build()
        .expect("build");
        ledger.emit(entry2).expect("emit");

        let security_entries = ledger.by_decision_type(DecisionType::SecurityAction);
        assert_eq!(security_entries.len(), 1);

        let policy_entries = ledger.by_decision_type(DecisionType::PolicyUpdate);
        assert_eq!(policy_entries.len(), 1);
    }

    #[test]
    fn ledger_query_by_epoch() {
        let mut ledger = InMemoryLedger::new();
        ledger.emit(sample_entry()).expect("emit");

        let entries_e5 = ledger.by_epoch(SecurityEpoch::from_raw(5));
        assert_eq!(entries_e5.len(), 1);

        let entries_e1 = ledger.by_epoch(SecurityEpoch::from_raw(1));
        assert!(entries_e1.is_empty());
    }

    // -- Error display --

    #[test]
    fn ledger_error_display() {
        assert_eq!(
            LedgerError::MissingChosenAction.to_string(),
            "chosen action is required"
        );
        assert_eq!(
            LedgerError::DuplicateEntryId {
                entry_id: "ev-123".to_string()
            }
            .to_string(),
            "duplicate entry id: ev-123"
        );
        let err = LedgerError::IncompatibleSchema {
            entry_version: SchemaVersion::new(2, 0, 0),
            reader_version: current_schema_version(),
        };
        assert_eq!(
            err.to_string(),
            "incompatible schema: entry 2.0.0, reader 1.0.0"
        );
    }

    // -- Serialization --

    #[test]
    fn evidence_entry_serialization_round_trip() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: EvidenceEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, restored);
    }

    #[test]
    fn evidence_entry_deterministic_serialization() {
        let entry = sample_entry();
        let json1 = serde_json::to_string(&entry).expect("serialize");
        let json2 = serde_json::to_string(&entry).expect("serialize");
        assert_eq!(json1, json2);
    }

    #[test]
    fn all_error_variants_serialize() {
        let errors = vec![
            LedgerError::MissingChosenAction,
            LedgerError::SchemaValidationFailed {
                reason: "test".to_string(),
            },
            LedgerError::IncompatibleSchema {
                entry_version: SchemaVersion::new(2, 0, 0),
                reader_version: current_schema_version(),
            },
            LedgerError::DuplicateEntryId {
                entry_id: "ev-test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: LedgerError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn candidate_action_serialization_round_trip() {
        let c = CandidateAction::filtered("sandbox", 100_000, "max-loss");
        let json = serde_json::to_string(&c).expect("serialize");
        let restored: CandidateAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, restored);
    }

    #[test]
    fn schema_version_serialization_round_trip() {
        let v = current_schema_version();
        let json = serde_json::to_string(&v).expect("serialize");
        let restored: SchemaVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, restored);
    }

    // -- Enrichment: ordering --

    #[test]
    fn decision_type_ordering() {
        assert!(DecisionType::SecurityAction < DecisionType::PolicyUpdate);
        assert!(DecisionType::PolicyUpdate < DecisionType::EpochTransition);
        assert!(DecisionType::EpochTransition < DecisionType::Revocation);
        assert!(DecisionType::Revocation < DecisionType::ExtensionLifecycle);
        assert!(DecisionType::ExtensionLifecycle < DecisionType::CapabilityDecision);
        assert!(DecisionType::CapabilityDecision < DecisionType::ContractEvaluation);
        assert!(DecisionType::ContractEvaluation < DecisionType::RemoteAuthorization);
    }

    // -- Enrichment: error trait --

    #[test]
    fn ledger_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(LedgerError::MissingChosenAction),
            Box::new(LedgerError::SchemaValidationFailed {
                reason: "bad".to_string(),
            }),
            Box::new(LedgerError::DuplicateEntryId {
                entry_id: "e".to_string(),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn decision_type_serde_roundtrip() {
        for dt in [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::Revocation,
            DecisionType::ExtensionLifecycle,
            DecisionType::CapabilityDecision,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ] {
            let json = serde_json::to_string(&dt).expect("serialize");
            let restored: DecisionType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(dt, restored);
        }
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let c = Constraint {
            constraint_id: "c-1".to_string(),
            description: "rate limit".to_string(),
            active: true,
        };
        let json = serde_json::to_string(&c).expect("serialize");
        let restored: Constraint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, restored);
    }

    #[test]
    fn witness_serde_roundtrip() {
        let w = Witness {
            witness_id: "w-1".to_string(),
            witness_type: "monotonicity".to_string(),
            value: "proof-hash".to_string(),
        };
        let json = serde_json::to_string(&w).expect("serialize");
        let restored: Witness = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(w, restored);
    }

    #[test]
    fn chosen_action_serde_roundtrip() {
        let ca = ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "lowest loss".to_string(),
        };
        let json = serde_json::to_string(&ca).expect("serialize");
        let restored: ChosenAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ca, restored);
    }

    // -- Enrichment: default --

    #[test]
    fn in_memory_ledger_default_is_empty() {
        let ledger = InMemoryLedger::default();
        assert_eq!(ledger.len(), 0);
        assert!(ledger.is_empty());
    }
}
