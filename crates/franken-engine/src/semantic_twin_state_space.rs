//! [FRX-19.1] Semantic twin state-space + causal graph specification.
//!
//! This module binds four artifacts into one deterministic contract:
//! - Versioned twin-state dictionary mapped to runtime/FRIR signals.
//! - Deterministic transition graph for decision/fallback lifecycle states.
//! - Structural causal graph + recommended adjustment set for treatment/outcome effects.
//! - Assumptions registry with falsification hooks that compile into `AssumptionLedger`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assumptions_ledger::{
    Assumption, AssumptionCategory, AssumptionLedger, AssumptionOrigin, AssumptionStatus,
    DemotionPolicy, FalsificationMonitor, MonitorKind, MonitorOp, ViolationSeverity,
};
use crate::structural_causal_model::{ScmError, StructuralCausalModel, build_lane_decision_dag};

/// Stable schema identifier for semantic twin specifications.
pub const SEMANTIC_TWIN_SCHEMA_VERSION: &str = "franken-engine.semantic-twin-state-space.v1";
/// Stable component key for structured logs emitted by this subsystem.
pub const SEMANTIC_TWIN_COMPONENT: &str = "semantic_twin_state_space";

/// Semantic domain of a twin-state variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwinStateDomain {
    Workload,
    Risk,
    Policy,
    Lane,
    Outcome,
    Regime,
    Resource,
    Replay,
    Calibration,
}

/// Source surface that produces a twin-state signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwinSignalSource {
    RuntimeDecisionCore,
    RuntimeDecisionTheory,
    CausalReplay,
    FrirIr2,
    FrirIr3,
    ObservabilityChannel,
    EvidenceLedger,
    OperatorInput,
    EnvironmentTelemetry,
}

/// High-level deterministic lifecycle phase in the semantic twin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwinPhase {
    ObserveWorkload,
    UpdateRiskBelief,
    SelectLane,
    ExecuteLane,
    RecordOutcome,
    EvaluateFallback,
    SafeMode,
}

/// Deterministic trigger that moves the twin from one phase to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwinTransitionTrigger {
    ObservationCommitted,
    PosteriorUpdated,
    DecisionCommitted,
    ExecutionCompleted,
    OutcomeRecorded,
    GuardrailTriggered,
    OperatorOverride,
    ReplayCounterfactual,
}

/// Versioned state-variable dictionary entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinStateVariableSpec {
    pub id: String,
    pub label: String,
    pub domain: TwinStateDomain,
    pub source: TwinSignalSource,
    pub observable: bool,
    /// Unit semantic for values (e.g. "millionths", "count", "ticks").
    pub unit: String,
    pub description: String,
}

/// Deterministic transition contract entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinTransitionSpec {
    pub id: String,
    pub from_phase: TwinPhase,
    pub to_phase: TwinPhase,
    pub trigger: TwinTransitionTrigger,
    /// Total order for transitions with the same `(from_phase, trigger)`.
    pub deterministic_priority: u16,
    /// Required assumptions that must remain active for this transition.
    pub guard_assumptions: Vec<String>,
    pub description: String,
}

/// Measurement contract for one twin-state variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinMeasurementContract {
    pub variable_id: String,
    pub required: bool,
    pub min_value_millionths: Option<i64>,
    pub max_value_millionths: Option<i64>,
    pub max_staleness_ticks: u64,
    pub evidence_component: String,
}

/// Registry entry describing one identifiability assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinAssumptionSpec {
    pub id: String,
    pub category: AssumptionCategory,
    pub origin: AssumptionOrigin,
    pub violation_severity: ViolationSeverity,
    pub description: String,
    pub dependencies: BTreeSet<String>,
    /// Deterministic hash of the logical predicate this assumption encodes.
    pub predicate_hash: String,
}

/// Falsification hook mapping one monitored variable to an assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinFalsificationHook {
    pub monitor_id: String,
    pub assumption_id: String,
    pub variable_id: String,
    pub kind: MonitorKind,
    pub op: MonitorOp,
    pub threshold_millionths: i64,
    pub trigger_count: u32,
}

/// One concrete twin-state observation snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinStateSnapshot {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub epoch: u64,
    pub tick: u64,
    /// Variable id -> value.
    pub values_millionths: BTreeMap<String, i64>,
}

impl TwinStateSnapshot {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch: u64,
        tick: u64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            epoch,
            tick,
            values_millionths: BTreeMap::new(),
        }
    }

    pub fn upsert_value(&mut self, variable_id: impl Into<String>, value_millionths: i64) {
        self.values_millionths
            .insert(variable_id.into(), value_millionths);
    }

    pub fn deterministic_digest(&self) -> String {
        let payload = serde_json::to_vec(self).expect("twin snapshot serialization should succeed");
        let digest = Sha256::digest(payload);
        format!("sha256:{}", hex::encode(digest))
    }
}

/// Validation and construction errors for semantic twin specs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TwinSpecError {
    Scm(String),
    InvalidSchemaVersion(String),
    DuplicateVariable(String),
    UnknownVariable(String),
    DuplicateTransition(String),
    DuplicateTransitionPriority {
        from_phase: TwinPhase,
        trigger: TwinTransitionTrigger,
        deterministic_priority: u16,
    },
    UnknownAssumption(String),
    DuplicateAssumption(String),
    DuplicateMonitor(String),
    InvalidMonitorTriggerCount {
        monitor_id: String,
    },
    InvalidMeasurementRange {
        variable_id: String,
    },
    MissingTreatmentVariable(String),
    MissingOutcomeVariable(String),
    MissingRequiredVariable {
        variable_id: String,
    },
    MissingSnapshotValue {
        variable_id: String,
    },
    OutOfRangeSnapshotValue {
        variable_id: String,
        value: i64,
        min: Option<i64>,
        max: Option<i64>,
    },
}

impl fmt::Display for TwinSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scm(message) => write!(f, "scm error: {message}"),
            Self::InvalidSchemaVersion(version) => {
                write!(f, "invalid semantic twin schema version: {version}")
            }
            Self::DuplicateVariable(id) => write!(f, "duplicate variable id: {id}"),
            Self::UnknownVariable(id) => write!(f, "unknown variable id: {id}"),
            Self::DuplicateTransition(id) => write!(f, "duplicate transition id: {id}"),
            Self::DuplicateTransitionPriority {
                from_phase,
                trigger,
                deterministic_priority,
            } => write!(
                f,
                "duplicate transition priority for {from_phase:?}/{trigger:?}: {deterministic_priority}"
            ),
            Self::UnknownAssumption(id) => write!(f, "unknown assumption id: {id}"),
            Self::DuplicateAssumption(id) => write!(f, "duplicate assumption id: {id}"),
            Self::DuplicateMonitor(id) => write!(f, "duplicate monitor id: {id}"),
            Self::InvalidMonitorTriggerCount { monitor_id } => {
                write!(f, "invalid trigger_count for monitor {monitor_id}")
            }
            Self::InvalidMeasurementRange { variable_id } => {
                write!(f, "invalid measurement range for variable {variable_id}")
            }
            Self::MissingTreatmentVariable(id) => write!(f, "missing treatment variable {id}"),
            Self::MissingOutcomeVariable(id) => write!(f, "missing outcome variable {id}"),
            Self::MissingRequiredVariable { variable_id } => {
                write!(f, "missing required variable contract for {variable_id}")
            }
            Self::MissingSnapshotValue { variable_id } => {
                write!(f, "missing required snapshot value for {variable_id}")
            }
            Self::OutOfRangeSnapshotValue {
                variable_id,
                value,
                min,
                max,
            } => write!(
                f,
                "snapshot value out of range for {variable_id}: value={value} min={min:?} max={max:?}"
            ),
        }
    }
}

impl std::error::Error for TwinSpecError {}

impl From<ScmError> for TwinSpecError {
    fn from(value: ScmError) -> Self {
        Self::Scm(value.to_string())
    }
}

/// Complete semantic twin specification for FRX-19.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinSpecification {
    pub schema_version: String,
    pub component: String,
    pub states: Vec<TwinPhase>,
    pub treatment_variable: String,
    pub outcome_variable: String,
    pub variables: Vec<TwinStateVariableSpec>,
    pub transitions: Vec<TwinTransitionSpec>,
    pub measurement_contracts: Vec<TwinMeasurementContract>,
    pub assumptions: Vec<TwinAssumptionSpec>,
    pub falsification_hooks: Vec<TwinFalsificationHook>,
    pub causal_model: StructuralCausalModel,
    pub recommended_adjustment_set: BTreeSet<String>,
}

impl SemanticTwinSpecification {
    /// Build the canonical lane-decision semantic twin.
    pub fn lane_decision_default() -> Result<Self, TwinSpecError> {
        let mut causal_model = build_lane_decision_dag()?;
        causal_model.classify_confounders("lane_choice", "latency_outcome")?;
        let backdoor = causal_model.backdoor_criterion("lane_choice", "latency_outcome")?;
        causal_model.compute_intervention_surfaces("lane_choice", "latency_outcome")?;

        let mut assumptions = Vec::new();
        assumptions.push(assumption(
            "assumption_regime_observable",
            AssumptionCategory::Structural,
            AssumptionOrigin::Runtime,
            ViolationSeverity::Critical,
            "Operating regime signal is observable for confounder adjustment.",
            &["regime"],
        ));
        assumptions.push(assumption(
            "assumption_confounder_adjustment_set_valid",
            AssumptionCategory::Statistical,
            AssumptionOrigin::Runtime,
            ViolationSeverity::Warning,
            "Backdoor adjustment set remains measurable and non-empty.",
            &["regime", "lane_choice", "latency_outcome"],
        ));
        assumptions.push(assumption(
            "assumption_latency_measurement_fresh",
            AssumptionCategory::Resource,
            AssumptionOrigin::Runtime,
            ViolationSeverity::Warning,
            "Latency signal remains fresh and bounded by SLO envelope.",
            &["latency_outcome"],
        ));
        assumptions.push(assumption(
            "assumption_nondeterminism_log_complete",
            AssumptionCategory::Safety,
            AssumptionOrigin::Runtime,
            ViolationSeverity::Critical,
            "Causal replay nondeterminism transcript remains complete.",
            &["nondeterminism_log_completeness"],
        ));
        assumptions.push(assumption(
            "assumption_policy_weights_bounded",
            AssumptionCategory::Structural,
            AssumptionOrigin::PolicyInherited,
            ViolationSeverity::Warning,
            "Loss matrix weights remain within deterministic bounded range.",
            &["loss_matrix_weight"],
        ));
        assumptions.push(assumption(
            "assumption_workload_measurement_fresh",
            AssumptionCategory::Resource,
            AssumptionOrigin::Runtime,
            ViolationSeverity::Advisory,
            "Workload complexity telemetry is available for every routed decision.",
            &["workload_complexity"],
        ));

        let spec = Self {
            schema_version: SEMANTIC_TWIN_SCHEMA_VERSION.to_string(),
            component: SEMANTIC_TWIN_COMPONENT.to_string(),
            states: vec![
                TwinPhase::ObserveWorkload,
                TwinPhase::UpdateRiskBelief,
                TwinPhase::SelectLane,
                TwinPhase::ExecuteLane,
                TwinPhase::RecordOutcome,
                TwinPhase::EvaluateFallback,
                TwinPhase::SafeMode,
            ],
            treatment_variable: "lane_choice".to_string(),
            outcome_variable: "latency_outcome".to_string(),
            variables: vec![
                variable(
                    "workload_complexity",
                    "Workload Complexity",
                    TwinStateDomain::Workload,
                    TwinSignalSource::RuntimeDecisionTheory,
                    true,
                    "millionths",
                    "Normalized workload complexity score.",
                ),
                variable(
                    "component_count",
                    "Component Count",
                    TwinStateDomain::Workload,
                    TwinSignalSource::FrirIr2,
                    true,
                    "count",
                    "Component count in the executable workload graph.",
                ),
                variable(
                    "effect_depth",
                    "Effect Depth",
                    TwinStateDomain::Workload,
                    TwinSignalSource::FrirIr3,
                    true,
                    "count",
                    "Maximum effect-chain depth in the current workload.",
                ),
                variable(
                    "environment_load",
                    "Environment Load",
                    TwinStateDomain::Resource,
                    TwinSignalSource::EnvironmentTelemetry,
                    true,
                    "millionths",
                    "Host environment pressure metric.",
                ),
                variable(
                    "regime",
                    "Operating Regime",
                    TwinStateDomain::Regime,
                    TwinSignalSource::RuntimeDecisionTheory,
                    true,
                    "enum_millionths",
                    "Runtime regime label encoded as deterministic integer domain.",
                ),
                variable(
                    "risk_belief",
                    "Risk Belief Posterior",
                    TwinStateDomain::Risk,
                    TwinSignalSource::RuntimeDecisionCore,
                    true,
                    "millionths",
                    "Posterior belief over risk state.",
                ),
                variable(
                    "loss_matrix_weight",
                    "Loss Matrix Weight",
                    TwinStateDomain::Policy,
                    TwinSignalSource::RuntimeDecisionCore,
                    true,
                    "millionths",
                    "Effective decision-theoretic loss amplification.",
                ),
                variable(
                    "lane_choice",
                    "Lane Choice",
                    TwinStateDomain::Lane,
                    TwinSignalSource::RuntimeDecisionCore,
                    true,
                    "enum_millionths",
                    "Selected execution lane.",
                ),
                variable(
                    "calibration_quality",
                    "Calibration Quality",
                    TwinStateDomain::Calibration,
                    TwinSignalSource::ObservabilityChannel,
                    true,
                    "millionths",
                    "Conformal/e-process calibration quality indicator.",
                ),
                variable(
                    "latency_outcome",
                    "Latency Outcome",
                    TwinStateDomain::Outcome,
                    TwinSignalSource::EvidenceLedger,
                    true,
                    "millionths",
                    "Observed latency outcome normalized to millionths.",
                ),
                variable(
                    "correctness_outcome",
                    "Correctness Outcome",
                    TwinStateDomain::Outcome,
                    TwinSignalSource::EvidenceLedger,
                    true,
                    "millionths",
                    "Observed correctness outcome normalized to millionths.",
                ),
                variable(
                    "nondeterminism_log_completeness",
                    "Nondeterminism Log Completeness",
                    TwinStateDomain::Replay,
                    TwinSignalSource::CausalReplay,
                    true,
                    "millionths",
                    "Fraction of required nondeterminism events captured for replay.",
                ),
                variable(
                    "replay_fidelity_margin",
                    "Replay Fidelity Margin",
                    TwinStateDomain::Replay,
                    TwinSignalSource::CausalReplay,
                    true,
                    "millionths",
                    "Difference between live and replayed outcome distributions.",
                ),
            ],
            transitions: vec![
                transition(
                    "transition_observe_to_risk",
                    TwinPhase::ObserveWorkload,
                    TwinPhase::UpdateRiskBelief,
                    TwinTransitionTrigger::ObservationCommitted,
                    10,
                    &["assumption_workload_measurement_fresh"],
                    "Promote fresh workload telemetry into posterior update stage.",
                ),
                transition(
                    "transition_risk_to_select",
                    TwinPhase::UpdateRiskBelief,
                    TwinPhase::SelectLane,
                    TwinTransitionTrigger::PosteriorUpdated,
                    20,
                    &[
                        "assumption_regime_observable",
                        "assumption_policy_weights_bounded",
                    ],
                    "Route once posterior + policy context are available.",
                ),
                transition(
                    "transition_select_to_execute",
                    TwinPhase::SelectLane,
                    TwinPhase::ExecuteLane,
                    TwinTransitionTrigger::DecisionCommitted,
                    30,
                    &["assumption_confounder_adjustment_set_valid"],
                    "Apply decision with causal identifiability assumptions active.",
                ),
                transition(
                    "transition_execute_to_record",
                    TwinPhase::ExecuteLane,
                    TwinPhase::RecordOutcome,
                    TwinTransitionTrigger::ExecutionCompleted,
                    40,
                    &["assumption_nondeterminism_log_complete"],
                    "Persist deterministic execution and replay witness material.",
                ),
                transition(
                    "transition_record_to_fallback_eval",
                    TwinPhase::RecordOutcome,
                    TwinPhase::EvaluateFallback,
                    TwinTransitionTrigger::OutcomeRecorded,
                    50,
                    &["assumption_latency_measurement_fresh"],
                    "Assess whether fallback should be triggered by recorded outcomes.",
                ),
                transition(
                    "transition_fallback_to_safe_mode",
                    TwinPhase::EvaluateFallback,
                    TwinPhase::SafeMode,
                    TwinTransitionTrigger::GuardrailTriggered,
                    60,
                    &[],
                    "Fail closed into deterministic safe mode on guardrail trigger.",
                ),
                transition(
                    "transition_safe_mode_to_select",
                    TwinPhase::SafeMode,
                    TwinPhase::SelectLane,
                    TwinTransitionTrigger::OperatorOverride,
                    70,
                    &["assumption_regime_observable"],
                    "Allow explicit operator return from safe mode into routed execution.",
                ),
            ],
            measurement_contracts: vec![
                measurement_contract(
                    "workload_complexity",
                    true,
                    Some(0),
                    Some(1_000_000),
                    1,
                    "runtime_decision_theory",
                ),
                measurement_contract(
                    "risk_belief",
                    true,
                    Some(0),
                    Some(1_000_000),
                    1,
                    "runtime_decision_core",
                ),
                measurement_contract(
                    "loss_matrix_weight",
                    true,
                    Some(0),
                    Some(2_000_000),
                    10,
                    "runtime_decision_core",
                ),
                measurement_contract(
                    "latency_outcome",
                    true,
                    Some(0),
                    Some(2_000_000),
                    5,
                    "evidence_ledger",
                ),
                measurement_contract(
                    "nondeterminism_log_completeness",
                    true,
                    Some(0),
                    Some(1_000_000),
                    1,
                    "causal_replay",
                ),
                measurement_contract(
                    "replay_fidelity_margin",
                    false,
                    Some(0),
                    Some(1_000_000),
                    100,
                    "causal_replay",
                ),
            ],
            assumptions,
            falsification_hooks: vec![
                falsification_hook(
                    "monitor_workload_complexity_presence",
                    "assumption_workload_measurement_fresh",
                    "workload_complexity",
                    MonitorKind::Invariant,
                    MonitorOp::Ge,
                    0,
                    1,
                ),
                falsification_hook(
                    "monitor_loss_matrix_bound",
                    "assumption_policy_weights_bounded",
                    "loss_matrix_weight",
                    MonitorKind::Threshold,
                    MonitorOp::Le,
                    1_000_000,
                    1,
                ),
                falsification_hook(
                    "monitor_latency_slo_envelope",
                    "assumption_latency_measurement_fresh",
                    "latency_outcome",
                    MonitorKind::Threshold,
                    MonitorOp::Le,
                    250_000,
                    2,
                ),
                falsification_hook(
                    "monitor_replay_completeness",
                    "assumption_nondeterminism_log_complete",
                    "nondeterminism_log_completeness",
                    MonitorKind::Invariant,
                    MonitorOp::Ge,
                    1_000_000,
                    1,
                ),
                falsification_hook(
                    "monitor_regime_observable",
                    "assumption_regime_observable",
                    "regime",
                    MonitorKind::Invariant,
                    MonitorOp::Ge,
                    0,
                    1,
                ),
                falsification_hook(
                    "monitor_adjustment_validity",
                    "assumption_confounder_adjustment_set_valid",
                    "risk_belief",
                    MonitorKind::Coverage,
                    MonitorOp::Le,
                    1_000_000,
                    1,
                ),
            ],
            causal_model,
            recommended_adjustment_set: backdoor.adjustment_set,
        };

        spec.validate()?;
        Ok(spec)
    }

    /// Deterministic digest for reproducibility and witness linkage.
    pub fn deterministic_digest(&self) -> String {
        let payload = serde_json::to_vec(self).expect("semantic twin serialization should succeed");
        let digest = Sha256::digest(payload);
        format!("sha256:{}", hex::encode(digest))
    }

    /// Materialize assumptions + monitors into an executable ledger.
    pub fn to_assumption_ledger(
        &self,
        decision_id: &str,
        epoch: u64,
    ) -> Result<AssumptionLedger, TwinSpecError> {
        self.validate()?;

        let mut ledger = AssumptionLedger::new(DemotionPolicy::default());
        for assumption in &self.assumptions {
            ledger
                .record_assumption(Assumption {
                    id: assumption.id.clone(),
                    category: assumption.category,
                    origin: assumption.origin,
                    status: AssumptionStatus::Active,
                    description: assumption.description.clone(),
                    decision_id: decision_id.to_string(),
                    epoch,
                    dependencies: assumption.dependencies.clone(),
                    violation_severity: assumption.violation_severity,
                    predicate_hash: assumption.predicate_hash.clone(),
                })
                .map_err(|error| TwinSpecError::Scm(error.to_string()))?;
        }

        for hook in &self.falsification_hooks {
            ledger
                .register_monitor(FalsificationMonitor {
                    monitor_id: hook.monitor_id.clone(),
                    assumption_id: hook.assumption_id.clone(),
                    kind: hook.kind,
                    variable: hook.variable_id.clone(),
                    threshold_millionths: hook.threshold_millionths,
                    op: hook.op,
                    trigger_count: hook.trigger_count,
                    current_violations: 0,
                    triggered: false,
                })
                .map_err(|error| TwinSpecError::Scm(error.to_string()))?;
        }

        Ok(ledger)
    }

    /// Validate one state snapshot against required variable contracts.
    pub fn validate_snapshot(&self, snapshot: &TwinStateSnapshot) -> Result<(), TwinSpecError> {
        self.validate()?;
        let contracts = self
            .measurement_contracts
            .iter()
            .map(|contract| (contract.variable_id.as_str(), contract))
            .collect::<BTreeMap<_, _>>();

        for contract in &self.measurement_contracts {
            if contract.required
                && !snapshot
                    .values_millionths
                    .contains_key(&contract.variable_id)
            {
                return Err(TwinSpecError::MissingSnapshotValue {
                    variable_id: contract.variable_id.clone(),
                });
            }
        }

        for (variable_id, value) in &snapshot.values_millionths {
            let Some(contract) = contracts.get(variable_id.as_str()) else {
                return Err(TwinSpecError::UnknownVariable(variable_id.clone()));
            };
            let min = contract.min_value_millionths;
            let max = contract.max_value_millionths;
            if min.is_some_and(|lower| *value < lower) || max.is_some_and(|upper| *value > upper) {
                return Err(TwinSpecError::OutOfRangeSnapshotValue {
                    variable_id: variable_id.clone(),
                    value: *value,
                    min,
                    max,
                });
            }
        }

        Ok(())
    }

    /// Strong structural validation for deterministic twin behavior.
    pub fn validate(&self) -> Result<(), TwinSpecError> {
        if self.schema_version != SEMANTIC_TWIN_SCHEMA_VERSION {
            return Err(TwinSpecError::InvalidSchemaVersion(
                self.schema_version.clone(),
            ));
        }

        let mut variable_ids = BTreeSet::new();
        for variable in &self.variables {
            if !variable_ids.insert(variable.id.clone()) {
                return Err(TwinSpecError::DuplicateVariable(variable.id.clone()));
            }
        }

        if !variable_ids.contains(&self.treatment_variable) {
            return Err(TwinSpecError::MissingTreatmentVariable(
                self.treatment_variable.clone(),
            ));
        }
        if !variable_ids.contains(&self.outcome_variable) {
            return Err(TwinSpecError::MissingOutcomeVariable(
                self.outcome_variable.clone(),
            ));
        }

        let known_states = self.states.iter().copied().collect::<BTreeSet<_>>();
        let mut transition_ids = BTreeSet::new();
        let mut transition_priority_keys = BTreeSet::new();
        for transition in &self.transitions {
            if !transition_ids.insert(transition.id.clone()) {
                return Err(TwinSpecError::DuplicateTransition(transition.id.clone()));
            }
            if !known_states.contains(&transition.from_phase)
                || !known_states.contains(&transition.to_phase)
            {
                return Err(TwinSpecError::Scm(format!(
                    "transition {} references unknown state",
                    transition.id
                )));
            }
            let key = (
                transition.from_phase,
                transition.trigger,
                transition.deterministic_priority,
            );
            if !transition_priority_keys.insert(key) {
                return Err(TwinSpecError::DuplicateTransitionPriority {
                    from_phase: transition.from_phase,
                    trigger: transition.trigger,
                    deterministic_priority: transition.deterministic_priority,
                });
            }
        }

        for contract in &self.measurement_contracts {
            if !variable_ids.contains(&contract.variable_id) {
                return Err(TwinSpecError::UnknownVariable(contract.variable_id.clone()));
            }
            if let (Some(min), Some(max)) =
                (contract.min_value_millionths, contract.max_value_millionths)
                && min > max
            {
                return Err(TwinSpecError::InvalidMeasurementRange {
                    variable_id: contract.variable_id.clone(),
                });
            }
        }

        let required_ids = self
            .measurement_contracts
            .iter()
            .filter(|contract| contract.required)
            .map(|contract| contract.variable_id.clone())
            .collect::<BTreeSet<_>>();
        for required_id in &required_ids {
            if !variable_ids.contains(required_id) {
                return Err(TwinSpecError::MissingRequiredVariable {
                    variable_id: required_id.clone(),
                });
            }
        }

        let mut assumption_ids = BTreeSet::new();
        for assumption in &self.assumptions {
            if !assumption_ids.insert(assumption.id.clone()) {
                return Err(TwinSpecError::DuplicateAssumption(assumption.id.clone()));
            }
            for dependency in &assumption.dependencies {
                if !variable_ids.contains(dependency) {
                    return Err(TwinSpecError::UnknownVariable(dependency.clone()));
                }
            }
        }

        let mut monitor_ids = BTreeSet::new();
        for hook in &self.falsification_hooks {
            if !monitor_ids.insert(hook.monitor_id.clone()) {
                return Err(TwinSpecError::DuplicateMonitor(hook.monitor_id.clone()));
            }
            if hook.trigger_count == 0 {
                return Err(TwinSpecError::InvalidMonitorTriggerCount {
                    monitor_id: hook.monitor_id.clone(),
                });
            }
            if !assumption_ids.contains(&hook.assumption_id) {
                return Err(TwinSpecError::UnknownAssumption(hook.assumption_id.clone()));
            }
            if !variable_ids.contains(&hook.variable_id) {
                return Err(TwinSpecError::UnknownVariable(hook.variable_id.clone()));
            }
        }

        for transition in &self.transitions {
            for assumption_id in &transition.guard_assumptions {
                if !assumption_ids.contains(assumption_id) {
                    return Err(TwinSpecError::UnknownAssumption(assumption_id.clone()));
                }
            }
        }

        if self.causal_model.node(&self.treatment_variable).is_none() {
            return Err(TwinSpecError::MissingTreatmentVariable(
                self.treatment_variable.clone(),
            ));
        }
        if self.causal_model.node(&self.outcome_variable).is_none() {
            return Err(TwinSpecError::MissingOutcomeVariable(
                self.outcome_variable.clone(),
            ));
        }
        for adjusted in &self.recommended_adjustment_set {
            if !variable_ids.contains(adjusted) {
                return Err(TwinSpecError::UnknownVariable(adjusted.clone()));
            }
            if self.causal_model.node(adjusted).is_none() {
                return Err(TwinSpecError::Scm(format!(
                    "adjustment variable missing in causal model: {adjusted}"
                )));
            }
        }

        Ok(())
    }
}

fn variable(
    id: &str,
    label: &str,
    domain: TwinStateDomain,
    source: TwinSignalSource,
    observable: bool,
    unit: &str,
    description: &str,
) -> TwinStateVariableSpec {
    TwinStateVariableSpec {
        id: id.to_string(),
        label: label.to_string(),
        domain,
        source,
        observable,
        unit: unit.to_string(),
        description: description.to_string(),
    }
}

fn transition(
    id: &str,
    from_phase: TwinPhase,
    to_phase: TwinPhase,
    trigger: TwinTransitionTrigger,
    deterministic_priority: u16,
    guard_assumptions: &[&str],
    description: &str,
) -> TwinTransitionSpec {
    TwinTransitionSpec {
        id: id.to_string(),
        from_phase,
        to_phase,
        trigger,
        deterministic_priority,
        guard_assumptions: guard_assumptions
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        description: description.to_string(),
    }
}

fn measurement_contract(
    variable_id: &str,
    required: bool,
    min_value_millionths: Option<i64>,
    max_value_millionths: Option<i64>,
    max_staleness_ticks: u64,
    evidence_component: &str,
) -> TwinMeasurementContract {
    TwinMeasurementContract {
        variable_id: variable_id.to_string(),
        required,
        min_value_millionths,
        max_value_millionths,
        max_staleness_ticks,
        evidence_component: evidence_component.to_string(),
    }
}

fn assumption(
    id: &str,
    category: AssumptionCategory,
    origin: AssumptionOrigin,
    violation_severity: ViolationSeverity,
    description: &str,
    dependencies: &[&str],
) -> TwinAssumptionSpec {
    let dep_set = dependencies
        .iter()
        .map(|dependency| (*dependency).to_string())
        .collect::<BTreeSet<_>>();
    TwinAssumptionSpec {
        id: id.to_string(),
        category,
        origin,
        violation_severity,
        description: description.to_string(),
        dependencies: dep_set.clone(),
        predicate_hash: predicate_hash(id, &dep_set),
    }
}

fn falsification_hook(
    monitor_id: &str,
    assumption_id: &str,
    variable_id: &str,
    kind: MonitorKind,
    op: MonitorOp,
    threshold_millionths: i64,
    trigger_count: u32,
) -> TwinFalsificationHook {
    TwinFalsificationHook {
        monitor_id: monitor_id.to_string(),
        assumption_id: assumption_id.to_string(),
        variable_id: variable_id.to_string(),
        kind,
        op,
        threshold_millionths,
        trigger_count,
    }
}

fn predicate_hash(assumption_id: &str, dependencies: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(assumption_id.as_bytes());
    for dependency in dependencies {
        hasher.update(dependency.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{
        SEMANTIC_TWIN_SCHEMA_VERSION, SemanticTwinSpecification, TwinMeasurementContract,
        TwinSpecError, TwinStateSnapshot,
    };

    #[test]
    fn default_spec_is_valid_and_identified() {
        let spec = SemanticTwinSpecification::lane_decision_default().expect("build default spec");
        spec.validate().expect("default spec should validate");
        assert_eq!(spec.schema_version, SEMANTIC_TWIN_SCHEMA_VERSION);
        assert!(spec.recommended_adjustment_set.contains("regime"));
        assert!(!spec.transitions.is_empty());
        assert!(!spec.assumptions.is_empty());
    }

    #[test]
    fn deterministic_digest_is_stable() {
        let left = SemanticTwinSpecification::lane_decision_default().expect("left");
        let right = SemanticTwinSpecification::lane_decision_default().expect("right");
        assert_eq!(left.deterministic_digest(), right.deterministic_digest());
    }

    #[test]
    fn invalid_measurement_range_is_rejected() {
        let mut spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
        spec.measurement_contracts.push(TwinMeasurementContract {
            variable_id: "risk_belief".to_string(),
            required: false,
            min_value_millionths: Some(2),
            max_value_millionths: Some(1),
            max_staleness_ticks: 1,
            evidence_component: "test".to_string(),
        });

        let err = spec.validate().expect_err("should fail");
        assert!(matches!(err, TwinSpecError::InvalidMeasurementRange { .. }));
    }

    #[test]
    fn ledger_contains_assumptions_and_falsification_triggers_demotion() {
        let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
        let mut ledger = spec
            .to_assumption_ledger("decision-semantic-twin", 9)
            .expect("ledger");

        assert_eq!(ledger.assumption_count(), spec.assumptions.len());
        assert_eq!(ledger.monitors().len(), spec.falsification_hooks.len());

        // Force `assumption_nondeterminism_log_complete` to violate:
        // monitor requires nondeterminism_log_completeness >= 1_000_000.
        let actions = ledger.observe("nondeterminism_log_completeness", 900_000, 9, 1);
        assert_eq!(actions.len(), 1);
        assert_eq!(ledger.violated_count(), 1);
    }

    #[test]
    fn snapshot_validation_enforces_required_values_and_bounds() {
        let spec = SemanticTwinSpecification::lane_decision_default().expect("spec");
        let mut snapshot =
            TwinStateSnapshot::new("trace-semantic", "decision-semantic", "policy-v1", 7, 3);
        snapshot.upsert_value("workload_complexity", 500_000);
        snapshot.upsert_value("risk_belief", 400_000);
        snapshot.upsert_value("loss_matrix_weight", 900_000);
        snapshot.upsert_value("latency_outcome", 200_000);
        snapshot.upsert_value("nondeterminism_log_completeness", 1_000_000);
        spec.validate_snapshot(&snapshot)
            .expect("required values should satisfy contracts");

        snapshot.upsert_value("latency_outcome", 3_000_000);
        let err = spec
            .validate_snapshot(&snapshot)
            .expect_err("must fail out-of-range");
        assert!(matches!(err, TwinSpecError::OutOfRangeSnapshotValue { .. }));
    }

    #[test]
    fn snapshot_digest_changes_with_value_updates() {
        let mut snapshot = TwinStateSnapshot::new("trace", "decision", "policy", 1, 1);
        snapshot.upsert_value("risk_belief", 100_000);
        let first = snapshot.deterministic_digest();
        snapshot.upsert_value("risk_belief", 200_000);
        let second = snapshot.deterministic_digest();
        assert_ne!(first, second);
    }
}
