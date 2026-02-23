//! End-to-end integration seam: parse → lower → execute → assess → decide → record → contain.
//!
//! The `ExecutionOrchestrator` accepts an extension package and drives it
//! through the full FrankenEngine pipeline:
//!
//! 1. **Parse** source via `CanonicalEs2020Parser`
//! 2. **Lower** IR0 → IR3 via `lowering_pipeline`
//! 3. **Execute** IR3 via `LaneRouter`
//! 4. **Assess risk** via `BayesianPosteriorUpdater`
//! 5. **Decide action** via `ExpectedLossSelector`
//! 6. **Record evidence** via `EvidenceLedger`
//! 7. **Execute containment** via `ContainmentExecutor`
//! 8. **Close cell** via `ExecutionCell` quiescent protocol

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ast::ParseGoal;
use crate::baseline_interpreter::{
    ExecutionResult, InterpreterError, LaneChoice, LaneReason, LaneRouter, RoutedResult,
};
use crate::bayesian_posterior::{
    BayesianPosteriorUpdater, Evidence, Posterior, RiskState, UpdateResult,
};
use crate::containment_executor::{
    ContainmentContext, ContainmentError, ContainmentExecutor, ContainmentReceipt, SandboxPolicy,
};
use crate::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use crate::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEmitter, EvidenceEntry,
    EvidenceEntryBuilder, InMemoryLedger, LedgerError, Witness,
};
use crate::execution_cell::{CellError, CellEvent, CellKind, ExecutionCell};
use crate::expected_loss_selector::{
    ActionDecision, ContainmentAction, ExpectedLossSelector, LossMatrix,
};
use crate::ir_contract::{Ir0Module, Ir3Module};
use crate::lowering_pipeline::{
    LoweringContext, LoweringEvent, LoweringPipelineError, PassWitness, lower_ir0_to_ir3,
};
use crate::parser::{CanonicalEs2020Parser, Es2020Parser, ParseError};
use crate::region_lifecycle::{CancelReason, DrainDeadline, FinalizeResult};
use crate::saga_orchestrator::{
    SagaError, SagaOrchestrator, SagaType, eviction_saga_steps, quarantine_saga_steps,
    revocation_saga_steps,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// LossMatrixPreset
// ---------------------------------------------------------------------------

/// Preset selection for the loss matrix used in action selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LossMatrixPreset {
    Balanced,
    Conservative,
    Permissive,
}

impl LossMatrixPreset {
    fn to_loss_matrix(self) -> LossMatrix {
        match self {
            Self::Balanced => LossMatrix::balanced(),
            Self::Conservative => LossMatrix::conservative(),
            Self::Permissive => LossMatrix::permissive(),
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorConfig
// ---------------------------------------------------------------------------

/// Configuration for the execution orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Which loss matrix preset to use.
    pub loss_matrix_preset: LossMatrixPreset,
    /// Force a specific interpreter lane.
    pub force_lane: Option<LaneChoice>,
    /// Max drain ticks for cell close.
    pub drain_deadline_ticks: u64,
    /// Saga concurrency limit.
    pub max_concurrent_sagas: usize,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Parse goal (Script or Module).
    pub parse_goal: ParseGoal,
    /// Prefix for generated trace IDs.
    pub trace_id_prefix: String,
    /// Policy ID for decision context.
    pub policy_id: String,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            loss_matrix_preset: LossMatrixPreset::Balanced,
            force_lane: None,
            drain_deadline_ticks: 10_000,
            max_concurrent_sagas: 4,
            epoch: SecurityEpoch::from_raw(1),
            parse_goal: ParseGoal::Script,
            trace_id_prefix: "orch".to_string(),
            policy_id: "default-policy".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionPackage
// ---------------------------------------------------------------------------

/// An extension package submitted for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionPackage {
    /// Unique extension identifier.
    pub extension_id: String,
    /// JavaScript source code.
    pub source: String,
    /// Declared capabilities.
    pub capabilities: Vec<String>,
    /// Extension version.
    pub version: String,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// OrchestratorResult
// ---------------------------------------------------------------------------

/// Complete result of an orchestrated execution pipeline.
#[derive(Debug)]
pub struct OrchestratorResult {
    // Identity
    pub extension_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub source_label: String,

    // Lowering
    pub lowering_events: Vec<LoweringEvent>,
    pub lowering_witnesses: Vec<PassWitness>,

    // Execution
    pub lane: LaneChoice,
    pub lane_reason: LaneReason,
    pub execution_value: String,
    pub instructions_executed: u64,

    // Risk
    pub posterior: Posterior,
    pub risk_state: RiskState,

    // Action
    pub containment_action: ContainmentAction,
    pub expected_loss_millionths: i64,
    pub action_decision: ActionDecision,

    // Evidence
    pub evidence_entries: Vec<EvidenceEntry>,

    // Containment
    pub containment_receipt: Option<ContainmentReceipt>,
    pub saga_id: Option<String>,

    // Cell
    pub cell_events: Vec<CellEvent>,
    pub finalize_result: Option<FinalizeResult>,

    // Epoch
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// OrchestratorError
// ---------------------------------------------------------------------------

/// Errors produced by the orchestrator pipeline.
#[derive(Debug)]
pub enum OrchestratorError {
    Parse(ParseError),
    Lowering(LoweringPipelineError),
    Interpreter(InterpreterError),
    Ledger(LedgerError),
    Saga(SagaError),
    Cell(CellError),
    Containment(ContainmentError),
    EmptySource,
    EmptyExtensionId,
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse: {e}"),
            Self::Lowering(e) => write!(f, "lowering: {e}"),
            Self::Interpreter(e) => write!(f, "interpreter: {e}"),
            Self::Ledger(e) => write!(f, "ledger: {e}"),
            Self::Saga(e) => write!(f, "saga: {e}"),
            Self::Cell(e) => write!(f, "cell: {e}"),
            Self::Containment(e) => write!(f, "containment: {e}"),
            Self::EmptySource => f.write_str("extension source is empty"),
            Self::EmptyExtensionId => f.write_str("extension_id is empty"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl From<ParseError> for OrchestratorError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<LoweringPipelineError> for OrchestratorError {
    fn from(e: LoweringPipelineError) -> Self {
        Self::Lowering(e)
    }
}

impl From<InterpreterError> for OrchestratorError {
    fn from(e: InterpreterError) -> Self {
        Self::Interpreter(e)
    }
}

impl From<LedgerError> for OrchestratorError {
    fn from(e: LedgerError) -> Self {
        Self::Ledger(e)
    }
}

impl From<SagaError> for OrchestratorError {
    fn from(e: SagaError) -> Self {
        Self::Saga(e)
    }
}

impl From<CellError> for OrchestratorError {
    fn from(e: CellError) -> Self {
        Self::Cell(e)
    }
}

impl From<ContainmentError> for OrchestratorError {
    fn from(e: ContainmentError) -> Self {
        Self::Containment(e)
    }
}

// ---------------------------------------------------------------------------
// ExecutionOrchestrator
// ---------------------------------------------------------------------------

/// Integration seam that wires together the full FrankenEngine pipeline.
pub struct ExecutionOrchestrator {
    config: OrchestratorConfig,
    parser: CanonicalEs2020Parser,
    lane_router: LaneRouter,
    posterior_updater: BayesianPosteriorUpdater,
    loss_selector: ExpectedLossSelector,
    ledger: InMemoryLedger,
    saga_orchestrator: SagaOrchestrator,
    containment_executor: ContainmentExecutor,
    execution_counter: u64,
}

impl ExecutionOrchestrator {
    /// Create a new orchestrator with the given configuration.
    pub fn new(config: OrchestratorConfig) -> Self {
        let loss_matrix = config.loss_matrix_preset.to_loss_matrix();
        let prior = Posterior::default_prior();
        Self {
            parser: CanonicalEs2020Parser,
            lane_router: LaneRouter::new(),
            posterior_updater: BayesianPosteriorUpdater::new(prior, "orchestrator"),
            loss_selector: ExpectedLossSelector::new(loss_matrix),
            ledger: InMemoryLedger::new(),
            saga_orchestrator: SagaOrchestrator::new(config.epoch, config.max_concurrent_sagas),
            containment_executor: ContainmentExecutor::new(),
            execution_counter: 0,
            config,
        }
    }

    /// Create an orchestrator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(OrchestratorConfig::default())
    }

    /// Access the evidence ledger.
    pub fn ledger(&self) -> &InMemoryLedger {
        &self.ledger
    }

    /// Access the saga orchestrator.
    pub fn saga_orchestrator(&self) -> &SagaOrchestrator {
        &self.saga_orchestrator
    }

    /// Number of executions completed.
    pub fn execution_count(&self) -> u64 {
        self.execution_counter
    }

    /// Execute an extension package through the full pipeline.
    pub fn execute(
        &mut self,
        package: &ExtensionPackage,
    ) -> Result<OrchestratorResult, OrchestratorError> {
        // Step 0: Validate.
        Self::validate_package(package)?;

        // Step 1: Generate identifiers.
        let trace_id = self.next_trace_id();
        let decision_id = self.next_decision_id();
        let source_label = format!("ext:{}", package.extension_id);

        // Step 2: Create execution cell.
        let mut cell = ExecutionCell::with_context(
            &trace_id,
            CellKind::Extension,
            &trace_id,
            &decision_id,
            &self.config.policy_id,
        );

        // Step 3: Register extension in containment executor.
        self.containment_executor.register(&package.extension_id);

        // Step 4: Parse source.
        let syntax_tree = self
            .parser
            .parse(package.source.as_str(), self.config.parse_goal)?;

        // Step 5: Lower IR0 → IR3.
        let ir0 = Ir0Module::from_syntax_tree(syntax_tree, &source_label);
        let lowering_ctx = LoweringContext::new(&trace_id, &decision_id, &self.config.policy_id);
        let lowering_output = lower_ir0_to_ir3(&ir0, &lowering_ctx)?;
        let lowering_events = lowering_output.events.clone();
        let lowering_witnesses = lowering_output.witnesses.clone();

        // Step 6: Execute IR3.
        let routed = self.phase_execute(&lowering_output.ir3, &trace_id)?;
        let lane = routed.lane;
        let lane_reason = routed.reason;
        let exec_result = routed.result;
        let execution_value = format!("{}", exec_result.value);
        let instructions_executed = exec_result.instructions_executed;

        // Step 7: Assess risk.
        let evidence = Self::build_evidence(package, &exec_result, self.config.epoch);
        let update_result = self.posterior_updater.update(&evidence);
        let posterior = update_result.posterior.clone();
        let risk_state = posterior.map_estimate();

        // Step 8: Decide action.
        let action_decision = self.loss_selector.select(&posterior);
        let containment_action = action_decision.action;
        let expected_loss_millionths = action_decision.expected_loss_millionths;

        // Step 9: Record evidence.
        let entry = self.phase_record_evidence(
            &trace_id,
            &decision_id,
            package,
            &action_decision,
            &exec_result,
            &update_result,
        )?;
        let evidence_entries = vec![entry];

        // Step 10: Containment + saga (if action > Allow).
        let (containment_receipt, saga_id) =
            self.phase_execute_containment(containment_action, package, &trace_id, &decision_id)?;

        // Step 11: Close execution cell.
        let cancel_reason = if containment_action.severity() >= 4 {
            CancelReason::Quarantine
        } else {
            CancelReason::OperatorShutdown
        };
        let deadline = DrainDeadline {
            max_ticks: self.config.drain_deadline_ticks,
        };
        let trace_seed = self.execution_counter.wrapping_add(1000);
        let mut cx = MockCx::new(trace_id_from_seed(trace_seed), MockBudget::new(10_000));
        let finalize_result = cell.close(&mut cx, cancel_reason, deadline).ok();

        // Step 12: Drain cell events and assemble result.
        let cell_events = cell.drain_events();

        self.execution_counter += 1;

        Ok(OrchestratorResult {
            extension_id: package.extension_id.clone(),
            trace_id,
            decision_id,
            source_label,
            lowering_events,
            lowering_witnesses,
            lane,
            lane_reason,
            execution_value,
            instructions_executed,
            posterior,
            risk_state,
            containment_action,
            expected_loss_millionths,
            action_decision,
            evidence_entries,
            containment_receipt,
            saga_id,
            cell_events,
            finalize_result,
            epoch: self.config.epoch,
        })
    }

    // -- Private helpers -----------------------------------------------------

    fn validate_package(package: &ExtensionPackage) -> Result<(), OrchestratorError> {
        if package.source.trim().is_empty() {
            return Err(OrchestratorError::EmptySource);
        }
        if package.extension_id.trim().is_empty() {
            return Err(OrchestratorError::EmptyExtensionId);
        }
        Ok(())
    }

    fn phase_execute(
        &self,
        ir3: &Ir3Module,
        trace_id: &str,
    ) -> Result<RoutedResult, OrchestratorError> {
        self.lane_router
            .execute(ir3, trace_id, self.config.force_lane)
            .map_err(OrchestratorError::Interpreter)
    }

    fn phase_record_evidence(
        &mut self,
        trace_id: &str,
        decision_id: &str,
        package: &ExtensionPackage,
        decision: &ActionDecision,
        exec: &ExecutionResult,
        update: &UpdateResult,
    ) -> Result<EvidenceEntry, OrchestratorError> {
        let mut builder = EvidenceEntryBuilder::new(
            trace_id,
            decision_id,
            &self.config.policy_id,
            self.config.epoch,
            DecisionType::SecurityAction,
        );

        builder = builder.timestamp_ns(0);

        // Add all containment actions as candidates.
        for action in &ContainmentAction::ALL {
            builder = builder.candidate(CandidateAction::new(format!("{action:?}"), 0));
        }

        // Record chosen action.
        builder = builder.chosen(ChosenAction {
            action_name: format!("{:?}", decision.action),
            expected_loss_millionths: decision.expected_loss_millionths,
            rationale: format!(
                "risk_state={:?}, posterior_benign={}",
                update.posterior.map_estimate(),
                update.posterior.p_benign
            ),
        });

        // Record witnesses.
        builder = builder.witness(Witness {
            witness_id: format!("{trace_id}:posterior"),
            witness_type: "bayesian_posterior".to_string(),
            value: format!(
                "benign={} anomalous={} malicious={} unknown={}",
                update.posterior.p_benign,
                update.posterior.p_anomalous,
                update.posterior.p_malicious,
                update.posterior.p_unknown
            ),
        });

        builder = builder.witness(Witness {
            witness_id: format!("{trace_id}:execution"),
            witness_type: "execution_telemetry".to_string(),
            value: format!(
                "instructions={} hostcalls={} value={}",
                exec.instructions_executed,
                exec.hostcall_decisions.len(),
                exec.value
            ),
        });

        // Metadata.
        builder = builder.meta("extension_id".to_string(), package.extension_id.clone());
        builder = builder.meta("extension_version".to_string(), package.version.clone());
        builder = builder.meta(
            "capabilities_count".to_string(),
            package.capabilities.len().to_string(),
        );

        let entry = builder.build()?;
        self.ledger.emit(entry.clone())?;
        Ok(entry)
    }

    fn phase_execute_containment(
        &mut self,
        action: ContainmentAction,
        package: &ExtensionPackage,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<(Option<ContainmentReceipt>, Option<String>), OrchestratorError> {
        if action == ContainmentAction::Allow
            || action == ContainmentAction::Challenge
            || action == ContainmentAction::Sandbox
        {
            return Ok((None, None));
        }

        // Execute containment.
        let context = ContainmentContext {
            decision_id: decision_id.to_string(),
            timestamp_ns: 0,
            epoch: self.config.epoch,
            evidence_refs: vec![trace_id.to_string()],
            grace_period_ns: 0,
            challenge_timeout_ns: 0,
            sandbox_policy: SandboxPolicy::default(),
        };

        let receipt = self
            .containment_executor
            .execute(action, &package.extension_id, &context)?;

        // Create saga if applicable.
        let saga_id = if let Some(saga_type) = Self::action_to_saga_type(action) {
            let steps = match saga_type {
                SagaType::Quarantine => quarantine_saga_steps(&package.extension_id),
                SagaType::Eviction => eviction_saga_steps(&package.extension_id),
                SagaType::Revocation => revocation_saga_steps(&package.extension_id),
                SagaType::Publish => unreachable!("action_to_saga_type never returns Publish"),
            };
            let saga_id_str = format!("{trace_id}:saga");
            let id =
                self.saga_orchestrator
                    .create_saga(&saga_id_str, saga_type, steps, trace_id, 0)?;
            Some(id.to_string())
        } else {
            None
        };

        Ok((Some(receipt), saga_id))
    }

    fn next_trace_id(&self) -> String {
        format!("{}:{}", self.config.trace_id_prefix, self.execution_counter)
    }

    fn next_decision_id(&self) -> String {
        format!(
            "{}:decision:{}",
            self.config.trace_id_prefix, self.execution_counter
        )
    }

    fn build_evidence(
        package: &ExtensionPackage,
        exec: &ExecutionResult,
        epoch: SecurityEpoch,
    ) -> Evidence {
        let hostcall_count = exec.hostcall_decisions.len() as u64;
        let hostcall_rate_millionths = hostcall_count.saturating_mul(1_000_000);

        let distinct_capabilities = package.capabilities.len() as u32;

        let resource_score_millionths =
            (exec.instructions_executed.saturating_mul(5)).min(1_000_000);

        let denied = exec
            .hostcall_decisions
            .iter()
            .filter(|d| !d.allowed)
            .count() as u64;
        let denial_rate_millionths = denied
            .saturating_mul(1_000_000)
            .checked_div(hostcall_count)
            .unwrap_or(0);

        Evidence {
            extension_id: package.extension_id.clone(),
            hostcall_rate_millionths: hostcall_rate_millionths as i64,
            distinct_capabilities,
            resource_score_millionths: resource_score_millionths as i64,
            timing_anomaly_millionths: 0,
            denial_rate_millionths: denial_rate_millionths as i64,
            epoch,
        }
    }

    fn action_to_saga_type(action: ContainmentAction) -> Option<SagaType> {
        match action {
            ContainmentAction::Quarantine => Some(SagaType::Quarantine),
            ContainmentAction::Terminate => Some(SagaType::Eviction),
            ContainmentAction::Suspend => Some(SagaType::Revocation),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_package() -> ExtensionPackage {
        ExtensionPackage {
            extension_id: "test-ext-1".to_string(),
            source: "42".to_string(),
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn end_to_end_simple_source() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch
            .execute(&simple_package())
            .expect("execute should succeed");

        assert_eq!(result.extension_id, "test-ext-1");
        assert!(!result.trace_id.is_empty());
        assert!(!result.decision_id.is_empty());
        assert!(result.posterior.is_valid());
        assert!(!result.evidence_entries.is_empty());
        assert_eq!(result.epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn empty_source_returns_error() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = ExtensionPackage {
            extension_id: "ext-1".to_string(),
            source: "".to_string(),
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let err = orch.execute(&pkg).expect_err("empty source should fail");
        assert!(matches!(err, OrchestratorError::EmptySource));
    }

    #[test]
    fn empty_extension_id_returns_error() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = ExtensionPackage {
            extension_id: "".to_string(),
            source: "42".to_string(),
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let err = orch.execute(&pkg).expect_err("empty id should fail");
        assert!(matches!(err, OrchestratorError::EmptyExtensionId));
    }

    #[test]
    fn multiple_executions_accumulate_evidence() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        for _ in 0..3 {
            orch.execute(&simple_package()).expect("execute");
        }
        assert_eq!(orch.execution_count(), 3);
        assert!(orch.ledger().len() >= 3);
    }
}
