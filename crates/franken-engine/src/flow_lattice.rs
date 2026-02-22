//! IFC flow-lattice semantics for IR2 (CapabilityIR).
//!
//! Defines label classes, clearance classes, declassification obligations,
//! and lattice operations for information flow control in IR2 nodes.
//! Labels combine via join/meet operations; flows are legal when
//! `source_label <= sink_clearance` in the lattice ordering.
//!
//! ## Label Hierarchy
//!
//! `Public < Internal < Confidential < Secret < TopSecret`
//!
//! ## Clearance Hierarchy
//!
//! `OpenSink < RestrictedSink < AuditedSink < SealedSink < NeverSink`
//!
//! Plan reference: Section 10.2 item 4, 9I.7, bd-1fm.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ifc_artifacts::Label;

// ---------------------------------------------------------------------------
// Clearance — sink authorization level
// ---------------------------------------------------------------------------

/// Sink clearance level: determines what data sensitivity a sink may receive.
///
/// Ordered: `OpenSink < RestrictedSink < AuditedSink < SealedSink < NeverSink`.
/// NeverSink cannot receive any labeled data without declassification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Clearance {
    /// Can receive any data (e.g., stdout with redaction).
    OpenSink,
    /// Can receive up to Internal (e.g., metrics export).
    RestrictedSink,
    /// Can receive up to Confidential with audit trail.
    AuditedSink,
    /// Can receive up to Secret with explicit declassification.
    SealedSink,
    /// Cannot receive any labeled data.
    NeverSink,
}

impl Clearance {
    /// Numeric level for lattice ordering.
    pub fn level(&self) -> u32 {
        match self {
            Self::OpenSink => 0,
            Self::RestrictedSink => 1,
            Self::AuditedSink => 2,
            Self::SealedSink => 3,
            Self::NeverSink => 4,
        }
    }

    /// Maximum label level this clearance can receive without declassification.
    pub fn max_label_level(&self) -> u32 {
        match self {
            Self::OpenSink => 4, // Can receive everything
            Self::RestrictedSink => 1,
            Self::AuditedSink => 2,
            Self::SealedSink => 3,
            Self::NeverSink => 0, // Only Public (level 0), but even that requires audit
        }
    }

    /// Meet (greatest lower bound) for clearance narrowing.
    pub fn meet(&self, other: &Self) -> Self {
        if self.level() <= other.level() {
            self.clone()
        } else {
            other.clone()
        }
    }

    /// Join (least upper bound) for clearance widening.
    pub fn join(&self, other: &Self) -> Self {
        if self.level() >= other.level() {
            self.clone()
        } else {
            other.clone()
        }
    }
}

impl fmt::Display for Clearance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenSink => f.write_str("open_sink"),
            Self::RestrictedSink => f.write_str("restricted_sink"),
            Self::AuditedSink => f.write_str("audited_sink"),
            Self::SealedSink => f.write_str("sealed_sink"),
            Self::NeverSink => f.write_str("never_sink"),
        }
    }
}

// ---------------------------------------------------------------------------
// LabelClass — data sensitivity category
// ---------------------------------------------------------------------------

/// Data sensitivity category extending the base Label with TopSecret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LabelClass {
    /// Public data — no restrictions.
    Public,
    /// Internal engine state — limited access.
    Internal,
    /// User/session data — restricted.
    Confidential,
    /// Credentials/API keys — highly restricted.
    Secret,
    /// Key material/signing keys — maximum sensitivity.
    TopSecret,
}

impl LabelClass {
    /// Numeric level for lattice ordering.
    pub fn level(&self) -> u32 {
        match self {
            Self::Public => 0,
            Self::Internal => 1,
            Self::Confidential => 2,
            Self::Secret => 3,
            Self::TopSecret => 4,
        }
    }

    /// Join (least upper bound).
    pub fn join(&self, other: &Self) -> Self {
        if self.level() >= other.level() {
            self.clone()
        } else {
            other.clone()
        }
    }

    /// Meet (greatest lower bound).
    pub fn meet(&self, other: &Self) -> Self {
        if self.level() <= other.level() {
            self.clone()
        } else {
            other.clone()
        }
    }

    /// Whether this label can flow to the given clearance without declassification.
    pub fn can_flow_to(&self, clearance: &Clearance) -> bool {
        self.level() <= clearance.max_label_level()
    }

    /// Convert to the existing Label type used in ifc_artifacts.
    pub fn to_label(&self) -> Label {
        match self {
            Self::Public => Label::Public,
            Self::Internal => Label::Internal,
            Self::Confidential => Label::Confidential,
            Self::Secret => Label::Secret,
            Self::TopSecret => Label::TopSecret,
        }
    }

    /// Convert from the existing Label type.
    pub fn from_label(label: &Label) -> Self {
        match label {
            Label::Public => Self::Public,
            Label::Internal => Self::Internal,
            Label::Confidential => Self::Confidential,
            Label::Secret => Self::Secret,
            Label::TopSecret => Self::TopSecret,
            Label::Custom { level, .. } => match level {
                0 => Self::Public,
                1 => Self::Internal,
                2 => Self::Confidential,
                3 => Self::Secret,
                _ => Self::TopSecret,
            },
        }
    }
}

impl fmt::Display for LabelClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("public"),
            Self::Internal => f.write_str("internal"),
            Self::Confidential => f.write_str("confidential"),
            Self::Secret => f.write_str("secret"),
            Self::TopSecret => f.write_str("top_secret"),
        }
    }
}

// ---------------------------------------------------------------------------
// DataSource — where labels originate
// ---------------------------------------------------------------------------

/// Source of data that determines the initial label assignment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DataSource {
    /// Literal value in source code.
    Literal,
    /// Environment variable read.
    EnvironmentVariable,
    /// File read from credential path.
    CredentialFileRead,
    /// File read from non-credential path.
    GeneralFileRead,
    /// Crypto key material access.
    KeyMaterial,
    /// Policy-protected host artifact.
    PolicyProtectedArtifact,
    /// Hostcall return value.
    HostcallReturn { clearance: Clearance },
    /// Computed from other values (taint propagation).
    Computed { input_labels: Vec<LabelClass> },
    /// Declassified by explicit receipt.
    Declassified { original: LabelClass },
}

/// Label assignment rules: which label a data source receives by default.
pub fn assign_label(source: &DataSource) -> LabelClass {
    match source {
        DataSource::Literal => LabelClass::Public,
        DataSource::EnvironmentVariable => LabelClass::Secret,
        DataSource::CredentialFileRead => LabelClass::Secret,
        DataSource::GeneralFileRead => LabelClass::Internal,
        DataSource::KeyMaterial => LabelClass::TopSecret,
        DataSource::PolicyProtectedArtifact => LabelClass::Confidential,
        DataSource::HostcallReturn { clearance } => match clearance {
            Clearance::OpenSink => LabelClass::Public,
            Clearance::RestrictedSink => LabelClass::Internal,
            Clearance::AuditedSink => LabelClass::Confidential,
            Clearance::SealedSink => LabelClass::Secret,
            Clearance::NeverSink => LabelClass::TopSecret,
        },
        DataSource::Computed { input_labels } => {
            // Join all input labels: the result is as sensitive as the most sensitive input
            input_labels
                .iter()
                .fold(LabelClass::Public, |acc, l| acc.join(l))
        }
        DataSource::Declassified { original: _ } => {
            // Declassified data drops to Public by the declassification receipt
            LabelClass::Public
        }
    }
}

// ---------------------------------------------------------------------------
// SinkKind — classification of data destinations
// ---------------------------------------------------------------------------

/// Kind of data sink for clearance assignment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    /// Network egress (raw socket/HTTP).
    NetworkEgress,
    /// Subprocess/IPC boundary.
    SubprocessIpc,
    /// Persistence/export channel.
    PersistenceExport,
    /// Explicit declassification endpoint.
    DeclassificationEndpoint,
    /// Stdout logging with redaction.
    LoggingRedacted,
    /// Metrics export channel.
    MetricsExport,
}

/// Default clearance assignment for sink kinds.
pub fn sink_clearance(sink: &SinkKind) -> Clearance {
    match sink {
        SinkKind::NetworkEgress => Clearance::NeverSink,
        SinkKind::SubprocessIpc => Clearance::NeverSink,
        SinkKind::PersistenceExport => Clearance::SealedSink,
        SinkKind::DeclassificationEndpoint => Clearance::SealedSink,
        SinkKind::LoggingRedacted => Clearance::OpenSink,
        SinkKind::MetricsExport => Clearance::RestrictedSink,
    }
}

// ---------------------------------------------------------------------------
// DeclassificationObligation — required for cross-label flows
// ---------------------------------------------------------------------------

/// An obligation that must be fulfilled for a cross-label flow to be permitted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeclassificationObligation {
    /// Unique obligation identifier.
    pub obligation_id: String,
    /// Source label being declassified from.
    pub source_label: LabelClass,
    /// Target clearance being declassified to.
    pub target_clearance: Clearance,
    /// Decision contract ID that must approve this declassification.
    pub decision_contract_id: String,
    /// Whether the obligation requires operator approval.
    pub requires_operator_approval: bool,
    /// Maximum number of times this declassification can be used (0 = unlimited).
    pub max_uses: u64,
    /// Current use count.
    pub use_count: u64,
}

impl DeclassificationObligation {
    /// Check if this obligation has remaining uses.
    pub fn has_remaining_uses(&self) -> bool {
        self.max_uses == 0 || self.use_count < self.max_uses
    }

    /// Record a use of this obligation.
    pub fn record_use(&mut self) -> Result<(), FlowLatticeError> {
        if !self.has_remaining_uses() {
            return Err(FlowLatticeError::ObligationExhausted {
                obligation_id: self.obligation_id.clone(),
            });
        }
        self.use_count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FlowCheckResult — outcome of a flow legality check
// ---------------------------------------------------------------------------

/// Result of checking whether a flow is legal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowCheckResult {
    /// Flow is legal by lattice ordering.
    LegalByLattice,
    /// Flow requires declassification via the specified obligation.
    RequiresDeclassification { obligation_id: String },
    /// Flow is blocked: no lattice path and no declassification route.
    Blocked { source: LabelClass, sink: Clearance },
}

impl FlowCheckResult {
    pub fn is_legal(&self) -> bool {
        matches!(self, Self::LegalByLattice)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

// ---------------------------------------------------------------------------
// FlowLatticeError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowLatticeError {
    ObligationExhausted { obligation_id: String },
    ObligationNotFound { obligation_id: String },
    DuplicateObligation { obligation_id: String },
    FlowBlocked { detail: String },
}

impl fmt::Display for FlowLatticeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObligationExhausted { obligation_id } => {
                write!(f, "declassification obligation exhausted: {obligation_id}")
            }
            Self::ObligationNotFound { obligation_id } => {
                write!(f, "declassification obligation not found: {obligation_id}")
            }
            Self::DuplicateObligation { obligation_id } => {
                write!(f, "duplicate obligation: {obligation_id}")
            }
            Self::FlowBlocked { detail } => write!(f, "flow blocked: {detail}"),
        }
    }
}

impl std::error::Error for FlowLatticeError {}

// ---------------------------------------------------------------------------
// FlowLatticeEvent — structured log events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowLatticeEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Ir2FlowLattice — the flow lattice engine for IR2
// ---------------------------------------------------------------------------

/// Flow lattice engine for IR2 information flow control.
///
/// Evaluates flow legality, manages declassification obligations,
/// and enforces the label-clearance lattice.
pub struct Ir2FlowLattice {
    obligations: BTreeMap<String, DeclassificationObligation>,
    events: Vec<FlowLatticeEvent>,
    policy_id: String,
}

impl Ir2FlowLattice {
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            obligations: BTreeMap::new(),
            events: Vec::new(),
            policy_id: policy_id.into(),
        }
    }

    pub fn events(&self) -> &[FlowLatticeEvent] {
        &self.events
    }

    pub fn obligations(&self) -> &BTreeMap<String, DeclassificationObligation> {
        &self.obligations
    }

    /// Register a declassification obligation.
    pub fn register_obligation(
        &mut self,
        obligation: DeclassificationObligation,
    ) -> Result<(), FlowLatticeError> {
        if self.obligations.contains_key(&obligation.obligation_id) {
            return Err(FlowLatticeError::DuplicateObligation {
                obligation_id: obligation.obligation_id.clone(),
            });
        }
        self.obligations
            .insert(obligation.obligation_id.clone(), obligation);
        Ok(())
    }

    /// Check whether a flow from `source` to `sink` is legal.
    ///
    /// Returns the flow check result: legal by lattice, requires declassification,
    /// or blocked.
    pub fn check_flow(
        &mut self,
        source: &LabelClass,
        sink: &Clearance,
        trace_id: &str,
    ) -> FlowCheckResult {
        // 1. Check lattice legality
        if source.can_flow_to(sink) {
            self.emit_event(trace_id, "check_flow", "legal_by_lattice", None);
            return FlowCheckResult::LegalByLattice;
        }

        // 2. Check for declassification route
        let matching_obligation = self
            .obligations
            .iter()
            .find(|(_, obligation)| {
                obligation.source_label == *source
                    && obligation.target_clearance == *sink
                    && obligation.has_remaining_uses()
            })
            .map(|(id, _)| id.clone());

        if let Some(obligation_id) = matching_obligation {
            self.emit_event(trace_id, "check_flow", "requires_declassification", None);
            return FlowCheckResult::RequiresDeclassification { obligation_id };
        }

        // 3. Blocked
        self.emit_event(trace_id, "check_flow", "blocked", Some("FLOW_BLOCKED"));
        FlowCheckResult::Blocked {
            source: source.clone(),
            sink: sink.clone(),
        }
    }

    /// Exercise a declassification obligation.
    pub fn use_declassification(
        &mut self,
        obligation_id: &str,
        trace_id: &str,
    ) -> Result<(), FlowLatticeError> {
        let obligation = self.obligations.get_mut(obligation_id).ok_or_else(|| {
            FlowLatticeError::ObligationNotFound {
                obligation_id: obligation_id.to_string(),
            }
        })?;

        obligation.record_use()?;
        self.emit_event(trace_id, "use_declassification", "ok", None);
        Ok(())
    }

    /// Propagate labels through a computation: join all input labels.
    pub fn propagate_labels(&self, inputs: &[LabelClass]) -> LabelClass {
        inputs.iter().fold(LabelClass::Public, |acc, l| acc.join(l))
    }

    /// Assign a label to a data source.
    pub fn assign_source_label(&self, source: &DataSource) -> LabelClass {
        assign_label(source)
    }

    /// Get the clearance for a sink kind.
    pub fn assign_sink_clearance(&self, sink: &SinkKind) -> Clearance {
        sink_clearance(sink)
    }

    fn emit_event(&mut self, trace_id: &str, event: &str, outcome: &str, error_code: Option<&str>) {
        self.events.push(FlowLatticeEvent {
            trace_id: trace_id.to_string(),
            decision_id: String::new(),
            policy_id: self.policy_id.clone(),
            component: "flow_lattice".to_string(),
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

    // -----------------------------------------------------------------------
    // LabelClass lattice operations
    // -----------------------------------------------------------------------

    #[test]
    fn label_class_ordering() {
        assert!(LabelClass::Public.level() < LabelClass::Internal.level());
        assert!(LabelClass::Internal.level() < LabelClass::Confidential.level());
        assert!(LabelClass::Confidential.level() < LabelClass::Secret.level());
        assert!(LabelClass::Secret.level() < LabelClass::TopSecret.level());
    }

    #[test]
    fn label_join_returns_higher() {
        assert_eq!(
            LabelClass::Public.join(&LabelClass::Secret),
            LabelClass::Secret
        );
        assert_eq!(
            LabelClass::Secret.join(&LabelClass::Public),
            LabelClass::Secret
        );
        assert_eq!(
            LabelClass::Internal.join(&LabelClass::Confidential),
            LabelClass::Confidential
        );
        assert_eq!(
            LabelClass::TopSecret.join(&LabelClass::Public),
            LabelClass::TopSecret
        );
    }

    #[test]
    fn label_meet_returns_lower() {
        assert_eq!(
            LabelClass::Public.meet(&LabelClass::Secret),
            LabelClass::Public
        );
        assert_eq!(
            LabelClass::Secret.meet(&LabelClass::Public),
            LabelClass::Public
        );
        assert_eq!(
            LabelClass::TopSecret.meet(&LabelClass::Confidential),
            LabelClass::Confidential
        );
    }

    #[test]
    fn label_join_idempotent() {
        for label in [
            LabelClass::Public,
            LabelClass::Internal,
            LabelClass::Confidential,
            LabelClass::Secret,
            LabelClass::TopSecret,
        ] {
            assert_eq!(label.join(&label), label);
        }
    }

    #[test]
    fn label_meet_idempotent() {
        for label in [
            LabelClass::Public,
            LabelClass::Internal,
            LabelClass::Confidential,
            LabelClass::Secret,
            LabelClass::TopSecret,
        ] {
            assert_eq!(label.meet(&label), label);
        }
    }

    #[test]
    fn label_join_commutative() {
        let pairs = [
            (LabelClass::Public, LabelClass::Secret),
            (LabelClass::Internal, LabelClass::TopSecret),
            (LabelClass::Confidential, LabelClass::Internal),
        ];
        for (a, b) in &pairs {
            assert_eq!(a.join(b), b.join(a));
        }
    }

    #[test]
    fn label_meet_commutative() {
        let pairs = [
            (LabelClass::Public, LabelClass::Secret),
            (LabelClass::Internal, LabelClass::TopSecret),
            (LabelClass::Confidential, LabelClass::Internal),
        ];
        for (a, b) in &pairs {
            assert_eq!(a.meet(b), b.meet(a));
        }
    }

    #[test]
    fn label_join_associative() {
        let a = LabelClass::Public;
        let b = LabelClass::Confidential;
        let c = LabelClass::Secret;
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn label_meet_associative() {
        let a = LabelClass::TopSecret;
        let b = LabelClass::Confidential;
        let c = LabelClass::Internal;
        assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
    }

    // -----------------------------------------------------------------------
    // Clearance lattice operations
    // -----------------------------------------------------------------------

    #[test]
    fn clearance_ordering() {
        assert!(Clearance::OpenSink.level() < Clearance::RestrictedSink.level());
        assert!(Clearance::RestrictedSink.level() < Clearance::AuditedSink.level());
        assert!(Clearance::AuditedSink.level() < Clearance::SealedSink.level());
        assert!(Clearance::SealedSink.level() < Clearance::NeverSink.level());
    }

    #[test]
    fn clearance_meet_returns_lower() {
        assert_eq!(
            Clearance::NeverSink.meet(&Clearance::AuditedSink),
            Clearance::AuditedSink
        );
        assert_eq!(
            Clearance::OpenSink.meet(&Clearance::SealedSink),
            Clearance::OpenSink
        );
    }

    #[test]
    fn clearance_join_returns_higher() {
        assert_eq!(
            Clearance::OpenSink.join(&Clearance::SealedSink),
            Clearance::SealedSink
        );
        assert_eq!(
            Clearance::NeverSink.join(&Clearance::RestrictedSink),
            Clearance::NeverSink
        );
    }

    #[test]
    fn clearance_idempotent() {
        for c in [
            Clearance::OpenSink,
            Clearance::RestrictedSink,
            Clearance::AuditedSink,
            Clearance::SealedSink,
            Clearance::NeverSink,
        ] {
            assert_eq!(c.join(&c), c);
            assert_eq!(c.meet(&c), c);
        }
    }

    // -----------------------------------------------------------------------
    // Flow legality: label -> clearance
    // -----------------------------------------------------------------------

    #[test]
    fn public_can_flow_to_any_sink() {
        let public = LabelClass::Public;
        assert!(public.can_flow_to(&Clearance::OpenSink));
        assert!(public.can_flow_to(&Clearance::RestrictedSink));
        assert!(public.can_flow_to(&Clearance::NeverSink));
    }

    #[test]
    fn secret_cannot_flow_to_restricted_sink() {
        let secret = LabelClass::Secret;
        assert!(!secret.can_flow_to(&Clearance::RestrictedSink));
        assert!(!secret.can_flow_to(&Clearance::NeverSink));
    }

    #[test]
    fn secret_can_flow_to_sealed_sink() {
        let secret = LabelClass::Secret;
        assert!(secret.can_flow_to(&Clearance::SealedSink));
        assert!(secret.can_flow_to(&Clearance::OpenSink));
    }

    #[test]
    fn top_secret_can_only_flow_to_open_sink() {
        let top_secret = LabelClass::TopSecret;
        assert!(top_secret.can_flow_to(&Clearance::OpenSink));
        assert!(!top_secret.can_flow_to(&Clearance::RestrictedSink));
        assert!(!top_secret.can_flow_to(&Clearance::AuditedSink));
        assert!(!top_secret.can_flow_to(&Clearance::SealedSink));
        assert!(!top_secret.can_flow_to(&Clearance::NeverSink));
    }

    #[test]
    fn internal_fits_restricted_sink() {
        let internal = LabelClass::Internal;
        assert!(internal.can_flow_to(&Clearance::RestrictedSink));
        assert!(!internal.can_flow_to(&Clearance::NeverSink));
    }

    // -----------------------------------------------------------------------
    // Label assignment
    // -----------------------------------------------------------------------

    #[test]
    fn literal_assigns_public() {
        assert_eq!(assign_label(&DataSource::Literal), LabelClass::Public);
    }

    #[test]
    fn env_var_assigns_secret() {
        assert_eq!(
            assign_label(&DataSource::EnvironmentVariable),
            LabelClass::Secret
        );
    }

    #[test]
    fn credential_file_assigns_secret() {
        assert_eq!(
            assign_label(&DataSource::CredentialFileRead),
            LabelClass::Secret
        );
    }

    #[test]
    fn general_file_assigns_internal() {
        assert_eq!(
            assign_label(&DataSource::GeneralFileRead),
            LabelClass::Internal
        );
    }

    #[test]
    fn key_material_assigns_top_secret() {
        assert_eq!(
            assign_label(&DataSource::KeyMaterial),
            LabelClass::TopSecret
        );
    }

    #[test]
    fn policy_artifact_assigns_confidential() {
        assert_eq!(
            assign_label(&DataSource::PolicyProtectedArtifact),
            LabelClass::Confidential
        );
    }

    #[test]
    fn computed_joins_inputs() {
        let source = DataSource::Computed {
            input_labels: vec![LabelClass::Public, LabelClass::Secret, LabelClass::Internal],
        };
        assert_eq!(assign_label(&source), LabelClass::Secret);
    }

    #[test]
    fn computed_empty_inputs_is_public() {
        let source = DataSource::Computed {
            input_labels: vec![],
        };
        assert_eq!(assign_label(&source), LabelClass::Public);
    }

    #[test]
    fn declassified_drops_to_public() {
        let source = DataSource::Declassified {
            original: LabelClass::TopSecret,
        };
        assert_eq!(assign_label(&source), LabelClass::Public);
    }

    #[test]
    fn hostcall_return_label_by_clearance() {
        assert_eq!(
            assign_label(&DataSource::HostcallReturn {
                clearance: Clearance::OpenSink
            }),
            LabelClass::Public
        );
        assert_eq!(
            assign_label(&DataSource::HostcallReturn {
                clearance: Clearance::SealedSink
            }),
            LabelClass::Secret
        );
        assert_eq!(
            assign_label(&DataSource::HostcallReturn {
                clearance: Clearance::NeverSink
            }),
            LabelClass::TopSecret
        );
    }

    // -----------------------------------------------------------------------
    // Sink clearance assignment
    // -----------------------------------------------------------------------

    #[test]
    fn network_egress_is_never_sink() {
        assert_eq!(
            sink_clearance(&SinkKind::NetworkEgress),
            Clearance::NeverSink
        );
    }

    #[test]
    fn subprocess_ipc_is_never_sink() {
        assert_eq!(
            sink_clearance(&SinkKind::SubprocessIpc),
            Clearance::NeverSink
        );
    }

    #[test]
    fn logging_redacted_is_open_sink() {
        assert_eq!(
            sink_clearance(&SinkKind::LoggingRedacted),
            Clearance::OpenSink
        );
    }

    #[test]
    fn metrics_export_is_restricted() {
        assert_eq!(
            sink_clearance(&SinkKind::MetricsExport),
            Clearance::RestrictedSink
        );
    }

    // -----------------------------------------------------------------------
    // Ir2FlowLattice: flow checking
    // -----------------------------------------------------------------------

    #[test]
    fn legal_flow_by_lattice() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        let result = lattice.check_flow(&LabelClass::Public, &Clearance::RestrictedSink, "t1");
        assert_eq!(result, FlowCheckResult::LegalByLattice);
    }

    #[test]
    fn blocked_flow_without_declassification() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        let result = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t1");
        assert!(result.is_blocked());
    }

    #[test]
    fn flow_requires_declassification() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        lattice
            .register_obligation(DeclassificationObligation {
                obligation_id: "declass-1".to_string(),
                source_label: LabelClass::Secret,
                target_clearance: Clearance::NeverSink,
                decision_contract_id: "contract-1".to_string(),
                requires_operator_approval: false,
                max_uses: 0,
                use_count: 0,
            })
            .unwrap();

        let result = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t1");
        assert_eq!(
            result,
            FlowCheckResult::RequiresDeclassification {
                obligation_id: "declass-1".to_string()
            }
        );
    }

    #[test]
    fn exhausted_obligation_blocks_flow() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        lattice
            .register_obligation(DeclassificationObligation {
                obligation_id: "declass-1".to_string(),
                source_label: LabelClass::Secret,
                target_clearance: Clearance::NeverSink,
                decision_contract_id: "contract-1".to_string(),
                requires_operator_approval: false,
                max_uses: 1,
                use_count: 1, // already used
            })
            .unwrap();

        let result = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t1");
        assert!(result.is_blocked());
    }

    // -----------------------------------------------------------------------
    // Declassification obligations
    // -----------------------------------------------------------------------

    #[test]
    fn register_and_use_obligation() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        lattice
            .register_obligation(DeclassificationObligation {
                obligation_id: "d1".to_string(),
                source_label: LabelClass::Secret,
                target_clearance: Clearance::NeverSink,
                decision_contract_id: "c1".to_string(),
                requires_operator_approval: true,
                max_uses: 3,
                use_count: 0,
            })
            .unwrap();

        lattice.use_declassification("d1", "t1").unwrap();
        lattice.use_declassification("d1", "t2").unwrap();
        lattice.use_declassification("d1", "t3").unwrap();

        // Fourth use should fail
        let err = lattice.use_declassification("d1", "t4").unwrap_err();
        assert_eq!(
            err,
            FlowLatticeError::ObligationExhausted {
                obligation_id: "d1".to_string()
            }
        );
    }

    #[test]
    fn unlimited_obligation() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        lattice
            .register_obligation(DeclassificationObligation {
                obligation_id: "d1".to_string(),
                source_label: LabelClass::Secret,
                target_clearance: Clearance::NeverSink,
                decision_contract_id: "c1".to_string(),
                requires_operator_approval: false,
                max_uses: 0, // unlimited
                use_count: 0,
            })
            .unwrap();

        for i in 0..100 {
            lattice
                .use_declassification("d1", &format!("t{i}"))
                .unwrap();
        }
    }

    #[test]
    fn duplicate_obligation_rejected() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        let ob = DeclassificationObligation {
            obligation_id: "d1".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "c1".to_string(),
            requires_operator_approval: false,
            max_uses: 0,
            use_count: 0,
        };
        lattice.register_obligation(ob.clone()).unwrap();
        let err = lattice.register_obligation(ob).unwrap_err();
        assert_eq!(
            err,
            FlowLatticeError::DuplicateObligation {
                obligation_id: "d1".to_string()
            }
        );
    }

    #[test]
    fn unknown_obligation_not_found() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        let err = lattice
            .use_declassification("nonexistent", "t1")
            .unwrap_err();
        assert_eq!(
            err,
            FlowLatticeError::ObligationNotFound {
                obligation_id: "nonexistent".to_string()
            }
        );
    }

    // -----------------------------------------------------------------------
    // Label propagation
    // -----------------------------------------------------------------------

    #[test]
    fn propagate_empty_is_public() {
        let lattice = Ir2FlowLattice::new("test-policy");
        assert_eq!(lattice.propagate_labels(&[]), LabelClass::Public);
    }

    #[test]
    fn propagate_single_preserves_label() {
        let lattice = Ir2FlowLattice::new("test-policy");
        assert_eq!(
            lattice.propagate_labels(&[LabelClass::Secret]),
            LabelClass::Secret
        );
    }

    #[test]
    fn propagate_joins_all() {
        let lattice = Ir2FlowLattice::new("test-policy");
        let result = lattice.propagate_labels(&[
            LabelClass::Public,
            LabelClass::Internal,
            LabelClass::Secret,
            LabelClass::Confidential,
        ]);
        assert_eq!(result, LabelClass::Secret);
    }

    // -----------------------------------------------------------------------
    // Label/Clearance display
    // -----------------------------------------------------------------------

    #[test]
    fn label_class_display() {
        assert_eq!(format!("{}", LabelClass::Public), "public");
        assert_eq!(format!("{}", LabelClass::TopSecret), "top_secret");
    }

    #[test]
    fn clearance_display() {
        assert_eq!(format!("{}", Clearance::NeverSink), "never_sink");
        assert_eq!(format!("{}", Clearance::OpenSink), "open_sink");
    }

    // -----------------------------------------------------------------------
    // LabelClass <-> Label conversion
    // -----------------------------------------------------------------------

    #[test]
    fn label_class_to_label_roundtrip() {
        for class in [
            LabelClass::Public,
            LabelClass::Internal,
            LabelClass::Confidential,
            LabelClass::Secret,
        ] {
            let label = class.to_label();
            let back = LabelClass::from_label(&label);
            assert_eq!(class, back);
        }
    }

    #[test]
    fn top_secret_converts_to_native_label() {
        let label = LabelClass::TopSecret.to_label();
        assert_eq!(label, Label::TopSecret);
    }

    // -----------------------------------------------------------------------
    // Event logging
    // -----------------------------------------------------------------------

    #[test]
    fn events_are_recorded() {
        let mut lattice = Ir2FlowLattice::new("test-policy");
        lattice.check_flow(&LabelClass::Public, &Clearance::OpenSink, "t1");
        lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t2");

        assert_eq!(lattice.events().len(), 2);
        assert_eq!(lattice.events()[0].outcome, "legal_by_lattice");
        assert_eq!(lattice.events()[1].outcome, "blocked");
        assert_eq!(
            lattice.events()[1].error_code.as_deref(),
            Some("FLOW_BLOCKED")
        );
    }

    #[test]
    fn event_fields_populated() {
        let mut lattice = Ir2FlowLattice::new("my-policy");
        lattice.check_flow(&LabelClass::Public, &Clearance::OpenSink, "trace-1");

        let event = &lattice.events()[0];
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.policy_id, "my-policy");
        assert_eq!(event.component, "flow_lattice");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn label_class_serde_roundtrip() {
        for label in [
            LabelClass::Public,
            LabelClass::Internal,
            LabelClass::Confidential,
            LabelClass::Secret,
            LabelClass::TopSecret,
        ] {
            let json = serde_json::to_string(&label).unwrap();
            let decoded: LabelClass = serde_json::from_str(&json).unwrap();
            assert_eq!(label, decoded);
        }
    }

    #[test]
    fn clearance_serde_roundtrip() {
        for clearance in [
            Clearance::OpenSink,
            Clearance::RestrictedSink,
            Clearance::AuditedSink,
            Clearance::SealedSink,
            Clearance::NeverSink,
        ] {
            let json = serde_json::to_string(&clearance).unwrap();
            let decoded: Clearance = serde_json::from_str(&json).unwrap();
            assert_eq!(clearance, decoded);
        }
    }

    #[test]
    fn obligation_serde_roundtrip() {
        let ob = DeclassificationObligation {
            obligation_id: "d1".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "c1".to_string(),
            requires_operator_approval: true,
            max_uses: 5,
            use_count: 2,
        };
        let json = serde_json::to_string(&ob).unwrap();
        let decoded: DeclassificationObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(ob, decoded);
    }

    #[test]
    fn flow_check_result_serde_roundtrip() {
        let results = vec![
            FlowCheckResult::LegalByLattice,
            FlowCheckResult::RequiresDeclassification {
                obligation_id: "d1".to_string(),
            },
            FlowCheckResult::Blocked {
                source: LabelClass::Secret,
                sink: Clearance::NeverSink,
            },
        ];
        for r in &results {
            let json = serde_json::to_string(r).unwrap();
            let decoded: FlowCheckResult = serde_json::from_str(&json).unwrap();
            assert_eq!(r, &decoded);
        }
    }

    // -----------------------------------------------------------------------
    // Error display coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_display() {
        let errors = [
            FlowLatticeError::ObligationExhausted {
                obligation_id: "d1".to_string(),
            },
            FlowLatticeError::ObligationNotFound {
                obligation_id: "d2".to_string(),
            },
            FlowLatticeError::DuplicateObligation {
                obligation_id: "d3".to_string(),
            },
            FlowLatticeError::FlowBlocked {
                detail: "secret->never".to_string(),
            },
        ];
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Exfiltration scenario (from enrichment)
    // -----------------------------------------------------------------------

    #[test]
    fn exfiltration_scenario_blocked() {
        let mut lattice = Ir2FlowLattice::new("test-policy");

        // let api_key = env.get("API_KEY"); -> Secret
        let api_key_label = lattice.assign_source_label(&DataSource::EnvironmentVariable);
        assert_eq!(api_key_label, LabelClass::Secret);

        // let prefix = "Bearer "; -> Public
        let prefix_label = lattice.assign_source_label(&DataSource::Literal);
        assert_eq!(prefix_label, LabelClass::Public);

        // let header = prefix + api_key; -> join(Public, Secret) = Secret
        let header_label = lattice.propagate_labels(&[prefix_label, api_key_label]);
        assert_eq!(header_label, LabelClass::Secret);

        // http.send(url, { auth: header }); -> network egress (NeverSink)
        let sink = lattice.assign_sink_clearance(&SinkKind::NetworkEgress);
        assert_eq!(sink, Clearance::NeverSink);

        // BLOCKED: Secret cannot flow to NeverSink
        let result = lattice.check_flow(&header_label, &sink, "t1");
        assert!(result.is_blocked());
    }

    #[test]
    fn declassified_exfiltration_allowed() {
        let mut lattice = Ir2FlowLattice::new("test-policy");

        lattice
            .register_obligation(DeclassificationObligation {
                obligation_id: "auth-api".to_string(),
                source_label: LabelClass::Secret,
                target_clearance: Clearance::NeverSink,
                decision_contract_id: "api-auth-contract".to_string(),
                requires_operator_approval: false,
                max_uses: 0,
                use_count: 0,
            })
            .unwrap();

        let result = lattice.check_flow(&LabelClass::Secret, &Clearance::NeverSink, "t1");
        assert_eq!(
            result,
            FlowCheckResult::RequiresDeclassification {
                obligation_id: "auth-api".to_string()
            }
        );

        // Exercise the declassification
        lattice.use_declassification("auth-api", "t2").unwrap();
    }
}
