//! [FRX-19.1] Semantic Twin State Space and Causal Graph Specification
//!
//! This module defines an executable semantic twin for lane/router decisions:
//! - versioned twin state variable dictionary with concrete runtime/FRIR signal bindings
//! - deterministic transition contract over twin variables
//! - causal adjustment strategies for key decision-outcome effects
//! - identifiability assumptions wired to falsification monitors via assumptions ledger

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assumptions_ledger::{
    Assumption, AssumptionCategory, AssumptionLedger, AssumptionOrigin, AssumptionStatus,
    DemotionAction, DemotionPolicy, FalsificationMonitor, LedgerError, MonitorKind, MonitorOp,
    ViolationSeverity,
};
use crate::structural_causal_model::{
    BackdoorResult, ScmError, StructuralCausalModel, VariableDomain, build_lane_decision_dag,
};

/// Semantic twin state dictionary schema.
pub const SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION: &str =
    "franken-engine.semantic-twin.state-space.v1";
/// Causal adjustment strategy schema.
pub const SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION: &str =
    "franken-engine.semantic-twin.causal-adjustment.v1";
/// Structured log schema for semantic twin monitor events.
pub const SEMANTIC_TWIN_LOG_SCHEMA_VERSION: &str = "franken-engine.semantic-twin.log-event.v1";
/// Stable component identifier for semantic twin events.
pub const SEMANTIC_TWIN_COMPONENT: &str = "semantic_twin_state_space";

/// Runtime/FRIR namespace for a mapped telemetry signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalNamespace {
    Frir,
    RuntimeDecisionCore,
    RuntimeObservability,
    PolicyController,
    AssumptionsLedger,
}

impl SignalNamespace {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frir => "frir",
            Self::RuntimeDecisionCore => "runtime_decision_core",
            Self::RuntimeObservability => "runtime_observability",
            Self::PolicyController => "policy_controller",
            Self::AssumptionsLedger => "assumptions_ledger",
        }
    }
}

/// Concrete telemetry binding for a semantic twin variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryContractRef {
    pub namespace: SignalNamespace,
    pub signal_key: String,
    pub units: String,
    pub deterministic: bool,
    pub required: bool,
}

impl TelemetryContractRef {
    pub fn validate(&self) -> Result<(), SemanticTwinError> {
        if self.signal_key.trim().is_empty() {
            return Err(SemanticTwinError::MissingTelemetrySignalKey {
                namespace: self.namespace.as_str().to_string(),
            });
        }
        if self.units.trim().is_empty() {
            return Err(SemanticTwinError::MissingTelemetryUnits {
                signal_key: self.signal_key.clone(),
            });
        }
        Ok(())
    }
}

/// One variable in the semantic twin state dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinStateVariable {
    pub id: String,
    pub label: String,
    pub description: String,
    pub domain: VariableDomain,
    pub observable: bool,
    pub telemetry: TelemetryContractRef,
}

/// Guard condition for deterministic transition activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionGuard {
    pub variable: String,
    pub op: MonitorOp,
    pub threshold_millionths: i64,
}

/// Deterministic transition relation between semantic twin variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinStateTransition {
    pub transition_id: String,
    pub source_variable: String,
    pub target_variable: String,
    pub trigger_event: String,
    pub telemetry_contract: String,
    #[serde(default)]
    pub guard: Option<TransitionGuard>,
}

/// Adjustment strategy for a specific treatment→outcome causal effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalAdjustmentStrategy {
    pub effect_id: String,
    pub treatment: String,
    pub outcome: String,
    pub identified: bool,
    pub adjustment_set: BTreeSet<String>,
    pub blocked_confounding_paths: Vec<Vec<String>>,
    pub strategy_note: String,
}

/// Explicit identifiability assumption mapped to telemetry + monitor contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifiabilityAssumption {
    pub assumption_id: String,
    pub description: String,
    pub category: AssumptionCategory,
    pub origin: AssumptionOrigin,
    pub decision_effect_id: String,
    pub telemetry_contract: String,
    pub monitor_kind: MonitorKind,
    pub monitor_variable: String,
    pub monitor_op: MonitorOp,
    pub monitor_threshold_millionths: i64,
    pub trigger_count: u32,
    pub violation_severity: ViolationSeverity,
}

/// [FRX-19.1] executable semantic twin specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinSpecification {
    pub schema_version: String,
    pub causal_adjustment_schema_version: String,
    pub state_variables: Vec<TwinStateVariable>,
    pub transitions: Vec<TwinStateTransition>,
    pub adjustment_strategies: Vec<CausalAdjustmentStrategy>,
    pub assumptions: Vec<IdentifiabilityAssumption>,
    pub causal_model: StructuralCausalModel,
}

/// Structured semantic twin monitor event with stable fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinLogEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub variable: String,
    pub observed_value_millionths: i64,
    pub assumption_id: Option<String>,
    pub monitor_id: Option<String>,
    pub action: Option<String>,
}

/// Outcome of observing one semantic twin telemetry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinObservationResult {
    pub actions: Vec<DemotionAction>,
    pub events: Vec<SemanticTwinLogEvent>,
}

/// Runtime wrapper that enforces semantic twin assumptions via monitors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinRuntime {
    specification: SemanticTwinSpecification,
    ledger: AssumptionLedger,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    tick: u64,
}

/// Semantic twin failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticTwinError {
    Scm(ScmError),
    Ledger(LedgerError),
    DuplicateVariable(String),
    MissingTelemetrySignalKey {
        namespace: String,
    },
    MissingTelemetryUnits {
        signal_key: String,
    },
    TransitionMissingVariable {
        transition_id: String,
        variable: String,
    },
    AdjustmentNotIdentified {
        effect_id: String,
    },
    AdjustmentMismatch {
        effect_id: String,
        expected: BTreeSet<String>,
        actual: BTreeSet<String>,
    },
    AssumptionMissingVariable {
        assumption_id: String,
        variable: String,
    },
    AssumptionMissingEffect {
        assumption_id: String,
        effect_id: String,
    },
    InvalidAssumptionTriggerCount {
        assumption_id: String,
    },
}

impl std::fmt::Display for SemanticTwinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scm(err) => write!(f, "scm error: {err}"),
            Self::Ledger(err) => write!(f, "assumptions ledger error: {err}"),
            Self::DuplicateVariable(id) => write!(f, "duplicate semantic twin variable: {id}"),
            Self::MissingTelemetrySignalKey { namespace } => {
                write!(f, "missing telemetry signal key for namespace {namespace}")
            }
            Self::MissingTelemetryUnits { signal_key } => {
                write!(f, "missing telemetry units for signal {signal_key}")
            }
            Self::TransitionMissingVariable {
                transition_id,
                variable,
            } => write!(
                f,
                "transition {transition_id} references unknown variable {variable}"
            ),
            Self::AdjustmentNotIdentified { effect_id } => {
                write!(f, "causal effect {effect_id} is not identified")
            }
            Self::AdjustmentMismatch {
                effect_id,
                expected,
                actual,
            } => write!(
                f,
                "adjustment mismatch for {effect_id}: expected {:?}, actual {:?}",
                expected, actual
            ),
            Self::AssumptionMissingVariable {
                assumption_id,
                variable,
            } => write!(
                f,
                "assumption {assumption_id} references unknown monitor variable {variable}"
            ),
            Self::AssumptionMissingEffect {
                assumption_id,
                effect_id,
            } => write!(
                f,
                "assumption {assumption_id} references unknown effect {effect_id}"
            ),
            Self::InvalidAssumptionTriggerCount { assumption_id } => {
                write!(f, "assumption {assumption_id} has trigger_count=0")
            }
        }
    }
}

impl std::error::Error for SemanticTwinError {}

impl From<ScmError> for SemanticTwinError {
    fn from(value: ScmError) -> Self {
        Self::Scm(value)
    }
}

impl From<LedgerError> for SemanticTwinError {
    fn from(value: LedgerError) -> Self {
        Self::Ledger(value)
    }
}

impl SemanticTwinSpecification {
    /// Build canonical [FRX-19.1] semantic twin specification.
    pub fn frx_19_1_default() -> Result<Self, SemanticTwinError> {
        let causal_model = build_lane_decision_dag()?;

        let state_variables = default_state_variables();
        let transitions = default_transitions(&causal_model);

        let adjustment_strategies = vec![
            adjustment_strategy(
                &causal_model,
                "effect_lane_choice_to_latency",
                "lane_choice",
                "latency_outcome",
                "Backdoor adjustment blocks regime/workload/load confounding before estimating lane latency effect.",
            )?,
            adjustment_strategy(
                &causal_model,
                "effect_lane_choice_to_correctness",
                "lane_choice",
                "correctness_outcome",
                "Backdoor adjustment blocks regime/workload confounding before estimating lane correctness effect.",
            )?,
        ];

        let assumptions = vec![
            IdentifiabilityAssumption {
                assumption_id: "asm-regime-observability".to_string(),
                description: "Regime labels are observed and linked to each routing decision".to_string(),
                category: AssumptionCategory::Structural,
                origin: AssumptionOrigin::Runtime,
                decision_effect_id: "effect_lane_choice_to_latency".to_string(),
                telemetry_contract: "runtime_observability.regime_observed_millionths"
                    .to_string(),
                monitor_kind: MonitorKind::Invariant,
                monitor_variable: "regime_observed_millionths".to_string(),
                monitor_op: MonitorOp::Ge,
                monitor_threshold_millionths: 1_000_000,
                trigger_count: 1,
                violation_severity: ViolationSeverity::Critical,
            },
            IdentifiabilityAssumption {
                assumption_id: "asm-latency-conounder-stability".to_string(),
                description:
                    "Environment load drift remains bounded for latency-effect identifiability"
                        .to_string(),
                category: AssumptionCategory::Statistical,
                origin: AssumptionOrigin::Inferred,
                decision_effect_id: "effect_lane_choice_to_latency".to_string(),
                telemetry_contract: "runtime_observability.environment_load_drift_millionths"
                    .to_string(),
                monitor_kind: MonitorKind::Drift,
                monitor_variable: "environment_load_drift_millionths".to_string(),
                monitor_op: MonitorOp::Le,
                monitor_threshold_millionths: 150_000,
                trigger_count: 2,
                violation_severity: ViolationSeverity::Warning,
            },
            IdentifiabilityAssumption {
                assumption_id: "asm-risk-calibration-error".to_string(),
                description:
                    "Risk posterior calibration error remains below configured bound for correctness attribution"
                        .to_string(),
                category: AssumptionCategory::Statistical,
                origin: AssumptionOrigin::Runtime,
                decision_effect_id: "effect_lane_choice_to_correctness".to_string(),
                telemetry_contract: "runtime_decision_core.risk_calibration_error_millionths"
                    .to_string(),
                monitor_kind: MonitorKind::Coverage,
                monitor_variable: "risk_calibration_error_millionths".to_string(),
                monitor_op: MonitorOp::Le,
                monitor_threshold_millionths: 120_000,
                trigger_count: 1,
                violation_severity: ViolationSeverity::Critical,
            },
            IdentifiabilityAssumption {
                assumption_id: "asm-frir-witness-linkage".to_string(),
                description: "FRIR witness linkage is present for each twin state transition"
                    .to_string(),
                category: AssumptionCategory::Behavioral,
                origin: AssumptionOrigin::CompileTime,
                decision_effect_id: "effect_lane_choice_to_correctness".to_string(),
                telemetry_contract: "frir_schema.witness_linkage_ratio_millionths".to_string(),
                monitor_kind: MonitorKind::Invariant,
                monitor_variable: "frir_witness_linkage_millionths".to_string(),
                monitor_op: MonitorOp::Ge,
                monitor_threshold_millionths: 1_000_000,
                trigger_count: 1,
                violation_severity: ViolationSeverity::Fatal,
            },
        ];

        let spec = Self {
            schema_version: SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION.to_string(),
            causal_adjustment_schema_version: SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION
                .to_string(),
            state_variables,
            transitions,
            adjustment_strategies,
            assumptions,
            causal_model,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validate semantic twin dictionary, transitions, adjustment strategy, and assumptions.
    pub fn validate(&self) -> Result<(), SemanticTwinError> {
        let mut variable_index = BTreeMap::new();
        for variable in &self.state_variables {
            if variable_index.insert(variable.id.clone(), true).is_some() {
                return Err(SemanticTwinError::DuplicateVariable(variable.id.clone()));
            }
            variable.telemetry.validate()?;
        }

        for transition in &self.transitions {
            if !variable_index.contains_key(&transition.source_variable) {
                return Err(SemanticTwinError::TransitionMissingVariable {
                    transition_id: transition.transition_id.clone(),
                    variable: transition.source_variable.clone(),
                });
            }
            if !variable_index.contains_key(&transition.target_variable) {
                return Err(SemanticTwinError::TransitionMissingVariable {
                    transition_id: transition.transition_id.clone(),
                    variable: transition.target_variable.clone(),
                });
            }
            if let Some(guard) = &transition.guard
                && !variable_index.contains_key(&guard.variable)
            {
                return Err(SemanticTwinError::TransitionMissingVariable {
                    transition_id: transition.transition_id.clone(),
                    variable: guard.variable.clone(),
                });
            }
        }

        let mut effect_ids = BTreeMap::new();
        for strategy in &self.adjustment_strategies {
            effect_ids.insert(strategy.effect_id.clone(), true);

            if !strategy.identified {
                return Err(SemanticTwinError::AdjustmentNotIdentified {
                    effect_id: strategy.effect_id.clone(),
                });
            }

            let check = self
                .causal_model
                .backdoor_criterion(&strategy.treatment, &strategy.outcome)?;
            if !check.identified {
                return Err(SemanticTwinError::AdjustmentNotIdentified {
                    effect_id: strategy.effect_id.clone(),
                });
            }
            if check.adjustment_set != strategy.adjustment_set {
                return Err(SemanticTwinError::AdjustmentMismatch {
                    effect_id: strategy.effect_id.clone(),
                    expected: strategy.adjustment_set.clone(),
                    actual: check.adjustment_set,
                });
            }
        }

        for assumption in &self.assumptions {
            if !effect_ids.contains_key(&assumption.decision_effect_id) {
                return Err(SemanticTwinError::AssumptionMissingEffect {
                    assumption_id: assumption.assumption_id.clone(),
                    effect_id: assumption.decision_effect_id.clone(),
                });
            }
            if !variable_index.contains_key(&assumption.monitor_variable) {
                return Err(SemanticTwinError::AssumptionMissingVariable {
                    assumption_id: assumption.assumption_id.clone(),
                    variable: assumption.monitor_variable.clone(),
                });
            }
            if assumption.trigger_count == 0 {
                return Err(SemanticTwinError::InvalidAssumptionTriggerCount {
                    assumption_id: assumption.assumption_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Build assumptions ledger and register falsification monitors from this spec.
    pub fn build_assumption_ledger(
        &self,
        decision_id: &str,
        epoch: u64,
        demotion_policy: DemotionPolicy,
    ) -> Result<AssumptionLedger, SemanticTwinError> {
        let mut ledger = AssumptionLedger::new(demotion_policy);

        for assumption in &self.assumptions {
            let mut dependencies = BTreeSet::new();
            dependencies.insert(assumption.decision_effect_id.clone());
            dependencies.insert(assumption.monitor_variable.clone());

            let assumption_row = Assumption {
                id: assumption.assumption_id.clone(),
                category: assumption.category,
                origin: assumption.origin,
                status: AssumptionStatus::Active,
                description: assumption.description.clone(),
                decision_id: decision_id.to_string(),
                epoch,
                dependencies,
                violation_severity: assumption.violation_severity,
                predicate_hash: predicate_hash(
                    assumption.assumption_id.as_str(),
                    assumption.monitor_variable.as_str(),
                    assumption.monitor_threshold_millionths,
                ),
            };
            ledger.record_assumption(assumption_row)?;

            ledger.register_monitor(FalsificationMonitor {
                monitor_id: format!("monitor-{}", assumption.assumption_id),
                assumption_id: assumption.assumption_id.clone(),
                kind: assumption.monitor_kind,
                variable: assumption.monitor_variable.clone(),
                threshold_millionths: assumption.monitor_threshold_millionths,
                op: assumption.monitor_op,
                trigger_count: assumption.trigger_count,
                current_violations: 0,
                triggered: false,
            })?;
        }

        Ok(ledger)
    }
}

impl SemanticTwinRuntime {
    /// Create runtime semantic twin monitor execution context.
    pub fn new(
        specification: SemanticTwinSpecification,
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch: u64,
        demotion_policy: DemotionPolicy,
    ) -> Result<Self, SemanticTwinError> {
        specification.validate()?;
        let decision_id = decision_id.into();
        let ledger =
            specification.build_assumption_ledger(decision_id.as_str(), epoch, demotion_policy)?;
        Ok(Self {
            specification,
            ledger,
            trace_id: trace_id.into(),
            decision_id,
            policy_id: policy_id.into(),
            tick: 0,
        })
    }

    /// Observe one variable value and run falsification monitors deterministically.
    pub fn observe(
        &mut self,
        variable: &str,
        value_millionths: i64,
        epoch: u64,
    ) -> SemanticTwinObservationResult {
        let history_before = self.ledger.falsification_history().len();
        self.tick = self.tick.saturating_add(1);

        let actions = self
            .ledger
            .observe(variable, value_millionths, epoch, self.tick);
        let new_evidence = &self.ledger.falsification_history()[history_before..];

        let mut events = Vec::new();
        if new_evidence.is_empty() {
            events.push(SemanticTwinLogEvent {
                schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
                trace_id: self.trace_id.clone(),
                decision_id: self.decision_id.clone(),
                policy_id: self.policy_id.clone(),
                component: SEMANTIC_TWIN_COMPONENT.to_string(),
                event: "assumption_monitor_evaluate".to_string(),
                outcome: "ok".to_string(),
                error_code: None,
                variable: variable.to_string(),
                observed_value_millionths: value_millionths,
                assumption_id: None,
                monitor_id: None,
                action: None,
            });
        } else {
            for (index, evidence) in new_evidence.iter().enumerate() {
                events.push(SemanticTwinLogEvent {
                    schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
                    trace_id: self.trace_id.clone(),
                    decision_id: self.decision_id.clone(),
                    policy_id: self.policy_id.clone(),
                    component: SEMANTIC_TWIN_COMPONENT.to_string(),
                    event: "assumption_falsified".to_string(),
                    outcome: "falsified".to_string(),
                    error_code: Some("FE-SEMANTIC-TWIN-0001".to_string()),
                    variable: variable.to_string(),
                    observed_value_millionths: value_millionths,
                    assumption_id: Some(evidence.assumption_id.clone()),
                    monitor_id: Some(evidence.monitor_id.clone()),
                    action: actions.get(index).map(action_label),
                });
            }
        }

        SemanticTwinObservationResult { actions, events }
    }

    /// Access current semantic twin specification.
    pub fn specification(&self) -> &SemanticTwinSpecification {
        &self.specification
    }

    /// Access assumptions ledger state.
    pub fn ledger(&self) -> &AssumptionLedger {
        &self.ledger
    }
}

fn adjustment_strategy(
    causal_model: &StructuralCausalModel,
    effect_id: &str,
    treatment: &str,
    outcome: &str,
    strategy_note: &str,
) -> Result<CausalAdjustmentStrategy, SemanticTwinError> {
    let BackdoorResult {
        identified,
        adjustment_set,
        confounding_paths,
        ..
    } = causal_model.backdoor_criterion(treatment, outcome)?;

    Ok(CausalAdjustmentStrategy {
        effect_id: effect_id.to_string(),
        treatment: treatment.to_string(),
        outcome: outcome.to_string(),
        identified,
        adjustment_set,
        blocked_confounding_paths: confounding_paths,
        strategy_note: strategy_note.to_string(),
    })
}

fn default_state_variables() -> Vec<TwinStateVariable> {
    vec![
        state_variable(
            "workload_complexity",
            "Workload complexity score",
            "Deterministic complexity score extracted from FRIR workload profile.",
            VariableDomain::WorkloadCharacteristic,
            true,
            SignalNamespace::Frir,
            "workload.profile.complexity_millionths",
            "millionths",
        ),
        state_variable(
            "component_count",
            "Component count",
            "Count of component units in FRIR graph for the current route payload.",
            VariableDomain::WorkloadCharacteristic,
            true,
            SignalNamespace::Frir,
            "workload.profile.component_count_millionths",
            "millionths",
        ),
        state_variable(
            "effect_depth",
            "Effect depth",
            "Maximum deterministic effect-chain depth from FRIR normalization.",
            VariableDomain::WorkloadCharacteristic,
            true,
            SignalNamespace::Frir,
            "workload.profile.effect_depth_millionths",
            "millionths",
        ),
        state_variable(
            "environment_load",
            "Environment load",
            "Runtime observability aggregate load score for attribution windows.",
            VariableDomain::EnvironmentFactor,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.load_millionths",
            "millionths",
        ),
        state_variable(
            "regime",
            "Operating regime",
            "Regime detector output used as confounder adjustment signal.",
            VariableDomain::Regime,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.regime_millionths",
            "millionths",
        ),
        state_variable(
            "risk_belief",
            "Risk belief posterior",
            "Posterior risk belief driving expected-loss lane selection.",
            VariableDomain::RiskBelief,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.risk_belief_millionths",
            "millionths",
        ),
        state_variable(
            "loss_matrix_weight",
            "Loss matrix weight",
            "Policy controller risk/cost weight active for routing decision.",
            VariableDomain::PolicySetting,
            true,
            SignalNamespace::PolicyController,
            "policy.loss_weight_millionths",
            "millionths",
        ),
        state_variable(
            "lane_choice",
            "Lane choice",
            "Selected execution lane encoded as deterministic lane score.",
            VariableDomain::LaneChoice,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.selected_lane_millionths",
            "millionths",
        ),
        state_variable(
            "calibration_quality",
            "Calibration quality",
            "Calibration confidence quality emitted by decision core.",
            VariableDomain::CalibrationMetric,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.calibration_quality_millionths",
            "millionths",
        ),
        state_variable(
            "latency_outcome",
            "Latency outcome",
            "Observed end-to-end latency outcome for attributed request window.",
            VariableDomain::ObservedOutcome,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.latency_outcome_millionths",
            "millionths",
        ),
        state_variable(
            "correctness_outcome",
            "Correctness outcome",
            "Observed correctness/compliance score for attributed request window.",
            VariableDomain::ObservedOutcome,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.correctness_outcome_millionths",
            "millionths",
        ),
        state_variable(
            "regime_observed_millionths",
            "Regime observability ratio",
            "Coverage ratio indicating regime labels are recorded for decisions.",
            VariableDomain::Regime,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.regime_observed_millionths",
            "millionths",
        ),
        state_variable(
            "environment_load_drift_millionths",
            "Environment load drift",
            "Windowed drift score for environment load stability assumption.",
            VariableDomain::EnvironmentFactor,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.environment_load_drift_millionths",
            "millionths",
        ),
        state_variable(
            "risk_calibration_error_millionths",
            "Risk calibration error",
            "Calibration error used for identifiability of correctness effects.",
            VariableDomain::CalibrationMetric,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.risk_calibration_error_millionths",
            "millionths",
        ),
        state_variable(
            "frir_witness_linkage_millionths",
            "FRIR witness linkage ratio",
            "Coverage ratio for FRIR witness linkage between transitions and decisions.",
            VariableDomain::PolicySetting,
            true,
            SignalNamespace::Frir,
            "frir_schema.witness_linkage_ratio_millionths",
            "millionths",
        ),
    ]
}

fn state_variable(
    id: &str,
    label: &str,
    description: &str,
    domain: VariableDomain,
    observable: bool,
    namespace: SignalNamespace,
    signal_key: &str,
    units: &str,
) -> TwinStateVariable {
    TwinStateVariable {
        id: id.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        domain,
        observable,
        telemetry: TelemetryContractRef {
            namespace,
            signal_key: signal_key.to_string(),
            units: units.to_string(),
            deterministic: true,
            required: true,
        },
    }
}

fn default_transitions(causal_model: &StructuralCausalModel) -> Vec<TwinStateTransition> {
    causal_model
        .edges()
        .iter()
        .map(|edge| TwinStateTransition {
            transition_id: format!("transition-{}-to-{}", edge.source, edge.target),
            source_variable: edge.source.clone(),
            target_variable: edge.target.clone(),
            trigger_event: transition_trigger(edge.source.as_str(), edge.target.as_str()),
            telemetry_contract: transition_contract(edge.source.as_str(), edge.target.as_str()),
            guard: transition_guard(edge.source.as_str(), edge.target.as_str()),
        })
        .collect()
}

fn transition_trigger(source: &str, target: &str) -> String {
    match (source, target) {
        ("workload_complexity", "risk_belief")
        | ("component_count", "risk_belief")
        | ("effect_depth", "risk_belief") => "frir_workload_profile_emitted".to_string(),
        ("environment_load", "risk_belief") | ("environment_load", "latency_outcome") => {
            "runtime_load_window_sampled".to_string()
        }
        ("regime", "loss_matrix_weight") | ("regime", "lane_choice") => {
            "regime_detector_updated".to_string()
        }
        ("risk_belief", "lane_choice") => "risk_posterior_updated".to_string(),
        ("loss_matrix_weight", "lane_choice") => "policy_loss_matrix_reloaded".to_string(),
        ("lane_choice", "calibration_quality")
        | ("lane_choice", "latency_outcome")
        | ("lane_choice", "correctness_outcome") => "router_action_selected".to_string(),
        ("calibration_quality", "correctness_outcome") => "calibration_ledger_updated".to_string(),
        _ => "semantic_twin_transition_observed".to_string(),
    }
}

fn transition_contract(source: &str, target: &str) -> String {
    format!("{}->{}", source, target)
}

fn transition_guard(source: &str, target: &str) -> Option<TransitionGuard> {
    match (source, target) {
        ("risk_belief", "lane_choice") => Some(TransitionGuard {
            variable: "risk_belief".to_string(),
            op: MonitorOp::Ge,
            threshold_millionths: 400_000,
        }),
        ("regime", "lane_choice") => Some(TransitionGuard {
            variable: "regime_observed_millionths".to_string(),
            op: MonitorOp::Ge,
            threshold_millionths: 1_000_000,
        }),
        ("loss_matrix_weight", "lane_choice") => Some(TransitionGuard {
            variable: "loss_matrix_weight".to_string(),
            op: MonitorOp::Ge,
            threshold_millionths: 50_000,
        }),
        _ => None,
    }
}

fn predicate_hash(assumption_id: &str, variable: &str, threshold_millionths: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(assumption_id.as_bytes());
    hasher.update(b":");
    hasher.update(variable.as_bytes());
    hasher.update(b":");
    hasher.update(threshold_millionths.to_string().as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn action_label(action: &DemotionAction) -> String {
    match action {
        DemotionAction::EnterSafeMode { .. } => "enter_safe_mode".to_string(),
        DemotionAction::DemoteLane { .. } => "demote_lane".to_string(),
        DemotionAction::SuspendAdaptive { .. } => "suspend_adaptive".to_string(),
        DemotionAction::EscalateToOperator { .. } => "escalate_to_operator".to_string(),
        DemotionAction::NoAction => "no_action".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frx_19_1_default_spec_validates() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.validate().expect("spec validates");
        assert_eq!(
            spec.schema_version,
            SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION
        );
        assert!(spec.state_variables.len() >= 10);
        assert!(spec.transitions.len() >= 10);
    }

    #[test]
    fn adjustment_strategies_are_identified_with_non_empty_adjustment_set() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        for strategy in &spec.adjustment_strategies {
            assert!(
                strategy.identified,
                "effect {} should be identified",
                strategy.effect_id
            );
            assert!(
                !strategy.adjustment_set.is_empty() || strategy.blocked_confounding_paths.is_empty(),
                "effect {} must either expose an adjustment set or have no confounding paths",
                strategy.effect_id
            );
        }
    }

    #[test]
    fn assumption_ledger_is_built_with_monitor_contracts() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let ledger = spec
            .build_assumption_ledger("decision-1", 9, DemotionPolicy::default())
            .expect("ledger");
        assert_eq!(ledger.assumption_count(), spec.assumptions.len());
        assert_eq!(ledger.monitors().len(), spec.assumptions.len());
        assert_eq!(ledger.active_count(), spec.assumptions.len());
    }

    #[test]
    fn runtime_observe_emits_ok_event_when_assumptions_hold() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let mut runtime = SemanticTwinRuntime::new(
            spec,
            "trace-semantic-twin",
            "decision-semantic-twin",
            "policy-semantic-twin",
            5,
            DemotionPolicy::default(),
        )
        .expect("runtime");

        let result = runtime.observe("risk_calibration_error_millionths", 80_000, 5);
        assert!(result.actions.is_empty());
        assert_eq!(result.events.len(), 1);
        assert_eq!(
            result.events[0].schema_version,
            SEMANTIC_TWIN_LOG_SCHEMA_VERSION
        );
        assert_eq!(result.events[0].event, "assumption_monitor_evaluate");
        assert_eq!(result.events[0].outcome, "ok");
    }

    #[test]
    fn runtime_observe_emits_falsification_event_and_action() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let mut runtime = SemanticTwinRuntime::new(
            spec,
            "trace-semantic-twin",
            "decision-semantic-twin",
            "policy-semantic-twin",
            5,
            DemotionPolicy::default(),
        )
        .expect("runtime");

        // This variable maps to warning-level assumption with trigger_count=2.
        let first = runtime.observe("environment_load_drift_millionths", 200_000, 5);
        assert!(first.actions.is_empty());

        let second = runtime.observe("environment_load_drift_millionths", 220_000, 5);
        assert_eq!(second.actions.len(), 1);
        assert!(matches!(
            second.actions[0],
            DemotionAction::SuspendAdaptive { .. }
        ));
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].event, "assumption_falsified");
        assert_eq!(second.events[0].outcome, "falsified");
        assert_eq!(
            second.events[0].error_code.as_deref(),
            Some("FE-SEMANTIC-TWIN-0001")
        );
        assert!(second.events[0].assumption_id.is_some());
        assert!(second.events[0].monitor_id.is_some());
    }

    #[test]
    fn validate_rejects_assumption_missing_effect() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.assumptions[0].decision_effect_id = "unknown-effect".to_string();
        let err = spec.validate().expect_err("must fail");
        assert!(matches!(
            err,
            SemanticTwinError::AssumptionMissingEffect { .. }
        ));
    }

    #[test]
    fn validate_rejects_adjustment_set_mismatch() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.adjustment_strategies[0].adjustment_set.clear();
        let err = spec.validate().expect_err("must fail");
        assert!(matches!(err, SemanticTwinError::AdjustmentMismatch { .. }));
    }
}
