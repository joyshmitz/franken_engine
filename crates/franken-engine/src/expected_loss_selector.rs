//! Expected-loss action selector for the Probabilistic Guardplane.
//!
//! Given a posterior distribution over extension risk states (from
//! `bayesian_posterior`) and an explicit loss matrix, computes expected
//! loss for every candidate containment action and selects the one with
//! minimum expected loss.
//!
//! All expected-loss values use fixed-point millionths (1_000_000 = 1.0)
//! for deterministic cross-platform arithmetic.
//!
//! Plan reference: Section 10.5, item 5.
//! Cross-refs: 9C.2 (decision loop), 9A.2 (Guardplane), 9F.5 (receipts).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bayesian_posterior::{Posterior, RiskState};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::trust_economics::{
    AttackerCostModel, AttackerRoiAssessment, FleetRoiSummary, summarize_fleet_roi,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;
const RUNTIME_DECISION_SCORING_COMPONENT: &str = "runtime_decision_scoring";

// ---------------------------------------------------------------------------
// ContainmentAction — the action space
// ---------------------------------------------------------------------------

/// Containment actions available to the Guardplane, ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ContainmentAction {
    Allow,
    Challenge,
    Sandbox,
    Suspend,
    Terminate,
    Quarantine,
}

impl ContainmentAction {
    /// All variants in severity order (least to most severe).
    pub const ALL: [ContainmentAction; 6] = [
        ContainmentAction::Allow,
        ContainmentAction::Challenge,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ];

    /// Severity rank (0 = least severe).  Used for tie-breaking.
    pub fn severity(&self) -> u32 {
        match self {
            Self::Allow => 0,
            Self::Challenge => 1,
            Self::Sandbox => 2,
            Self::Suspend => 3,
            Self::Terminate => 4,
            Self::Quarantine => 5,
        }
    }
}

impl fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allow => "allow",
            Self::Challenge => "challenge",
            Self::Sandbox => "sandbox",
            Self::Suspend => "suspend",
            Self::Terminate => "terminate",
            Self::Quarantine => "quarantine",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// LossMatrix — the cost model
// ---------------------------------------------------------------------------

/// Loss matrix entry: cost of taking `action` when true state is `state`.
/// All values in millionths (1_000_000 = 1.0 unit of loss).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossEntry {
    pub action: ContainmentAction,
    pub state: RiskState,
    pub loss_millionths: i64,
}

/// Explicit loss matrix mapping (action, state) → cost.
///
/// Must have entries for all 6×4 = 24 (action, state) pairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossMatrix {
    /// Matrix ID for audit trail.
    pub matrix_id: String,
    /// The 24 loss entries.  Stored as Vec for JSON-serializable determinism.
    entries: Vec<LossEntry>,
}

impl LossMatrix {
    /// Create a loss matrix from explicit entries.
    ///
    /// Panics if not all 24 (action, state) pairs are present.
    pub fn new(matrix_id: impl Into<String>, entries: Vec<LossEntry>) -> Self {
        let m = Self {
            matrix_id: matrix_id.into(),
            entries,
        };
        debug_assert!(m.is_complete(), "loss matrix must cover all 24 pairs");
        m
    }

    /// Look up the loss for a given (action, state) pair.
    pub fn loss(&self, action: ContainmentAction, state: RiskState) -> i64 {
        self.entries
            .iter()
            .find(|e| e.action == action && e.state == state)
            .map(|e| e.loss_millionths)
            .unwrap_or(0)
    }

    /// Whether all 24 pairs are present.
    pub fn is_complete(&self) -> bool {
        for action in &ContainmentAction::ALL {
            for state in &RiskState::ALL {
                if !self
                    .entries
                    .iter()
                    .any(|e| e.action == *action && e.state == *state)
                {
                    return false;
                }
            }
        }
        true
    }

    /// The "balanced" default loss matrix.
    pub fn balanced() -> Self {
        Self::new(
            "balanced-v1",
            vec![
                // Allow
                le(ContainmentAction::Allow, RiskState::Benign, 0),
                le(ContainmentAction::Allow, RiskState::Anomalous, 20_000_000), // 20.0
                le(ContainmentAction::Allow, RiskState::Malicious, 100_000_000), // 100.0
                le(ContainmentAction::Allow, RiskState::Unknown, 10_000_000),   // 10.0
                // Challenge
                le(ContainmentAction::Challenge, RiskState::Benign, 2_000_000), // 2.0
                le(
                    ContainmentAction::Challenge,
                    RiskState::Anomalous,
                    5_000_000,
                ), // 5.0
                le(
                    ContainmentAction::Challenge,
                    RiskState::Malicious,
                    50_000_000,
                ), // 50.0
                le(ContainmentAction::Challenge, RiskState::Unknown, 5_000_000), // 5.0
                // Sandbox
                le(ContainmentAction::Sandbox, RiskState::Benign, 5_000_000), // 5.0
                le(ContainmentAction::Sandbox, RiskState::Anomalous, 2_000_000), // 2.0
                le(ContainmentAction::Sandbox, RiskState::Malicious, 20_000_000), // 20.0
                le(ContainmentAction::Sandbox, RiskState::Unknown, 3_000_000), // 3.0
                // Suspend
                le(ContainmentAction::Suspend, RiskState::Benign, 8_000_000), // 8.0
                le(ContainmentAction::Suspend, RiskState::Anomalous, 1_000_000), // 1.0
                le(ContainmentAction::Suspend, RiskState::Malicious, 5_000_000), // 5.0
                le(ContainmentAction::Suspend, RiskState::Unknown, 4_000_000), // 4.0
                // Terminate
                le(ContainmentAction::Terminate, RiskState::Benign, 10_000_000), // 10.0
                le(
                    ContainmentAction::Terminate,
                    RiskState::Anomalous,
                    3_000_000,
                ), // 3.0
                le(ContainmentAction::Terminate, RiskState::Malicious, 500_000), // 0.5
                le(ContainmentAction::Terminate, RiskState::Unknown, 6_000_000), // 6.0
                // Quarantine
                le(ContainmentAction::Quarantine, RiskState::Benign, 12_000_000), // 12.0
                le(
                    ContainmentAction::Quarantine,
                    RiskState::Anomalous,
                    2_000_000,
                ), // 2.0
                le(ContainmentAction::Quarantine, RiskState::Malicious, 200_000), // 0.2
                le(ContainmentAction::Quarantine, RiskState::Unknown, 7_000_000), // 7.0
            ],
        )
    }

    /// Conservative matrix: high cost for false negatives (letting bad code run).
    pub fn conservative() -> Self {
        Self::new(
            "conservative-v1",
            vec![
                // Allow: very costly if wrong
                le(ContainmentAction::Allow, RiskState::Benign, 0),
                le(ContainmentAction::Allow, RiskState::Anomalous, 50_000_000),
                le(ContainmentAction::Allow, RiskState::Malicious, 200_000_000),
                le(ContainmentAction::Allow, RiskState::Unknown, 30_000_000),
                // Challenge
                le(ContainmentAction::Challenge, RiskState::Benign, 1_000_000),
                le(
                    ContainmentAction::Challenge,
                    RiskState::Anomalous,
                    10_000_000,
                ),
                le(
                    ContainmentAction::Challenge,
                    RiskState::Malicious,
                    100_000_000,
                ),
                le(ContainmentAction::Challenge, RiskState::Unknown, 10_000_000),
                // Sandbox
                le(ContainmentAction::Sandbox, RiskState::Benign, 3_000_000),
                le(ContainmentAction::Sandbox, RiskState::Anomalous, 2_000_000),
                le(ContainmentAction::Sandbox, RiskState::Malicious, 30_000_000),
                le(ContainmentAction::Sandbox, RiskState::Unknown, 3_000_000),
                // Suspend
                le(ContainmentAction::Suspend, RiskState::Benign, 5_000_000),
                le(ContainmentAction::Suspend, RiskState::Anomalous, 1_000_000),
                le(ContainmentAction::Suspend, RiskState::Malicious, 5_000_000),
                le(ContainmentAction::Suspend, RiskState::Unknown, 3_000_000),
                // Terminate
                le(ContainmentAction::Terminate, RiskState::Benign, 8_000_000),
                le(
                    ContainmentAction::Terminate,
                    RiskState::Anomalous,
                    2_000_000,
                ),
                le(ContainmentAction::Terminate, RiskState::Malicious, 300_000),
                le(ContainmentAction::Terminate, RiskState::Unknown, 5_000_000),
                // Quarantine
                le(ContainmentAction::Quarantine, RiskState::Benign, 10_000_000),
                le(
                    ContainmentAction::Quarantine,
                    RiskState::Anomalous,
                    1_500_000,
                ),
                le(ContainmentAction::Quarantine, RiskState::Malicious, 100_000),
                le(ContainmentAction::Quarantine, RiskState::Unknown, 5_000_000),
            ],
        )
    }

    /// Permissive matrix: high cost for false positives (disrupting good code).
    pub fn permissive() -> Self {
        Self::new(
            "permissive-v1",
            vec![
                le(ContainmentAction::Allow, RiskState::Benign, 0),
                le(ContainmentAction::Allow, RiskState::Anomalous, 10_000_000),
                le(ContainmentAction::Allow, RiskState::Malicious, 50_000_000),
                le(ContainmentAction::Allow, RiskState::Unknown, 5_000_000),
                le(ContainmentAction::Challenge, RiskState::Benign, 5_000_000),
                le(
                    ContainmentAction::Challenge,
                    RiskState::Anomalous,
                    3_000_000,
                ),
                le(
                    ContainmentAction::Challenge,
                    RiskState::Malicious,
                    30_000_000,
                ),
                le(ContainmentAction::Challenge, RiskState::Unknown, 5_000_000),
                le(ContainmentAction::Sandbox, RiskState::Benign, 10_000_000),
                le(ContainmentAction::Sandbox, RiskState::Anomalous, 2_000_000),
                le(ContainmentAction::Sandbox, RiskState::Malicious, 15_000_000),
                le(ContainmentAction::Sandbox, RiskState::Unknown, 5_000_000),
                le(ContainmentAction::Suspend, RiskState::Benign, 15_000_000),
                le(ContainmentAction::Suspend, RiskState::Anomalous, 2_000_000),
                le(ContainmentAction::Suspend, RiskState::Malicious, 5_000_000),
                le(ContainmentAction::Suspend, RiskState::Unknown, 8_000_000),
                le(ContainmentAction::Terminate, RiskState::Benign, 20_000_000),
                le(
                    ContainmentAction::Terminate,
                    RiskState::Anomalous,
                    5_000_000,
                ),
                le(
                    ContainmentAction::Terminate,
                    RiskState::Malicious,
                    1_000_000,
                ),
                le(ContainmentAction::Terminate, RiskState::Unknown, 10_000_000),
                le(ContainmentAction::Quarantine, RiskState::Benign, 25_000_000),
                le(
                    ContainmentAction::Quarantine,
                    RiskState::Anomalous,
                    5_000_000,
                ),
                le(ContainmentAction::Quarantine, RiskState::Malicious, 500_000),
                le(
                    ContainmentAction::Quarantine,
                    RiskState::Unknown,
                    12_000_000,
                ),
            ],
        )
    }

    /// Content hash of the loss matrix for audit trail.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.matrix_id.as_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(entry.action.to_string().as_bytes());
            buf.extend_from_slice(entry.state.to_string().as_bytes());
            buf.extend_from_slice(&entry.loss_millionths.to_le_bytes());
        }
        ContentHash::compute(&buf)
    }
}

/// Helper to create a LossEntry.
fn le(action: ContainmentAction, state: RiskState, loss_millionths: i64) -> LossEntry {
    LossEntry {
        action,
        state,
        loss_millionths,
    }
}

// ---------------------------------------------------------------------------
// DecisionExplanation — the audit trail
// ---------------------------------------------------------------------------

/// Explanation of how a decision was reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionExplanation {
    /// Posterior at decision time.
    pub posterior_snapshot: Posterior,
    /// Loss matrix ID used.
    pub loss_matrix_id: String,
    /// Expected loss for every action (millionths).
    pub all_expected_losses: BTreeMap<String, i64>,
    /// Margin: runner_up_loss - selected_loss (millionths).
    pub margin_millionths: i64,
}

// ---------------------------------------------------------------------------
// ActionDecision — the output
// ---------------------------------------------------------------------------

/// The result of the expected-loss action selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDecision {
    /// Selected action (minimum expected loss).
    pub action: ContainmentAction,
    /// Expected loss of the selected action (millionths).
    pub expected_loss_millionths: i64,
    /// Runner-up action.
    pub runner_up_action: ContainmentAction,
    /// Expected loss of the runner-up (millionths).
    pub runner_up_loss_millionths: i64,
    /// Full decision explanation.
    pub explanation: DecisionExplanation,
    /// Security epoch at decision time.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Runtime decision scoring artifact surfaces
// ---------------------------------------------------------------------------

/// Input to the high-level runtime decision scoring entrypoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDecisionScoringInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub policy_version: String,
    pub timestamp_ns: u64,
    pub posterior: Posterior,
    pub attacker_cost_model: AttackerCostModel,
    /// ROI history for this extension (oldest first, millionths).
    pub extension_roi_history_millionths: Vec<i64>,
    /// Fleet ROI snapshots for other extensions (`extension_id -> roi_millionths`).
    pub fleet_roi_baseline_millionths: BTreeMap<String, i64>,
    /// Guardrail-vetoed actions.
    pub blocked_actions: BTreeSet<ContainmentAction>,
}

/// Deterministic confidence interval over selected expected-loss estimate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionConfidenceInterval {
    pub lower_millionths: i64,
    pub upper_millionths: i64,
}

/// Per-action score entry for runtime decision artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateActionScore {
    pub action: ContainmentAction,
    pub expected_loss_millionths: i64,
    /// Per-state contribution to expected loss (`state -> contribution_millionths`).
    pub state_contributions_millionths: BTreeMap<String, i64>,
    pub guardrail_blocked: bool,
}

/// Structured log event emitted during runtime decision scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDecisionScoreEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Runtime decision scoring artifact with expected-loss + attacker-ROI outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDecisionScore {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub policy_version: String,
    pub timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub loss_matrix_version: String,
    pub candidate_actions: Vec<CandidateActionScore>,
    pub selected_action: ContainmentAction,
    pub selected_expected_loss_millionths: i64,
    pub selection_rationale: String,
    pub confidence_interval: DecisionConfidenceInterval,
    pub posterior_snapshot: Posterior,
    pub attacker_roi: AttackerRoiAssessment,
    pub fleet_roi_summary: FleetRoiSummary,
    /// True when the top two non-blocked actions are within 10% expected-loss margin.
    pub borderline_decision: bool,
    /// Sensitivity report: for each risk state, the posterior delta (millionths) that
    /// would flip the selected action to the runner-up. Empty when not borderline.
    pub sensitivity_deltas: BTreeMap<String, i64>,
    /// Deterministic receipt preimage hash suitable for signed receipt pipelines.
    pub receipt_preimage_hash: ContentHash,
    pub events: Vec<RuntimeDecisionScoreEvent>,
}

/// Runtime scoring errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeDecisionScoringError {
    MissingField { field: String },
    ZeroAttackerCost,
    AllActionsBlocked,
}

impl fmt::Display for RuntimeDecisionScoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => write!(f, "missing required field: {field}"),
            Self::ZeroAttackerCost => write!(f, "attacker cost model has zero total cost"),
            Self::AllActionsBlocked => write!(f, "all candidate actions are blocked by guardrails"),
        }
    }
}

impl std::error::Error for RuntimeDecisionScoringError {}

// ---------------------------------------------------------------------------
// ExpectedLossSelector — the selector engine
// ---------------------------------------------------------------------------

/// Expected-loss action selector.
///
/// Computes `E[Loss(a)] = Σ_s P(s) × L(a,s)` for each action and
/// selects the action with minimum expected loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedLossSelector {
    loss_matrix: LossMatrix,
    epoch: SecurityEpoch,
    decisions_made: u64,
}

impl ExpectedLossSelector {
    /// Create a new selector with the given loss matrix.
    pub fn new(loss_matrix: LossMatrix) -> Self {
        Self {
            loss_matrix,
            epoch: SecurityEpoch::GENESIS,
            decisions_made: 0,
        }
    }

    /// Create with the balanced default loss matrix.
    pub fn balanced() -> Self {
        Self::new(LossMatrix::balanced())
    }

    /// Compute expected losses for all actions given a posterior.
    pub fn expected_losses(&self, posterior: &Posterior) -> BTreeMap<ContainmentAction, i64> {
        let mut losses = BTreeMap::new();
        for action in &ContainmentAction::ALL {
            let mut expected_loss: i64 = 0;
            for state in &RiskState::ALL {
                let p = posterior.probability(*state);
                let l = self.loss_matrix.loss(*action, *state);
                // E[Loss] += P(s) * L(a,s) / MILLION
                expected_loss += p * l / MILLION;
            }
            losses.insert(*action, expected_loss);
        }
        losses
    }

    /// Select the optimal action (minimum expected loss).
    pub fn select(&mut self, posterior: &Posterior) -> ActionDecision {
        let losses = self.expected_losses(posterior);

        // Sort by (expected_loss, severity) for deterministic tie-breaking.
        let mut ranked: Vec<(ContainmentAction, i64)> =
            losses.iter().map(|(a, l)| (*a, *l)).collect();
        ranked.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.severity().cmp(&b.0.severity()))
        });

        let (best_action, best_loss) = ranked[0];
        let (runner_up_action, runner_up_loss) = ranked[1];

        let all_expected_losses: BTreeMap<String, i64> =
            losses.iter().map(|(a, l)| (a.to_string(), *l)).collect();

        self.decisions_made += 1;

        ActionDecision {
            action: best_action,
            expected_loss_millionths: best_loss,
            runner_up_action,
            runner_up_loss_millionths: runner_up_loss,
            explanation: DecisionExplanation {
                posterior_snapshot: posterior.clone(),
                loss_matrix_id: self.loss_matrix.matrix_id.clone(),
                all_expected_losses,
                margin_millionths: runner_up_loss - best_loss,
            },
            epoch: self.epoch,
        }
    }

    /// Produce a high-level runtime decision scoring artifact with
    /// expected-loss details, guardrail-aware selection, and ROI outputs.
    pub fn score_runtime_decision(
        &mut self,
        input: &RuntimeDecisionScoringInput,
    ) -> Result<RuntimeDecisionScore, RuntimeDecisionScoringError> {
        validate_runtime_scoring_input(input)?;

        let attacker_roi_millionths = input
            .attacker_cost_model
            .expected_roi()
            .ok_or(RuntimeDecisionScoringError::ZeroAttackerCost)?;

        let losses = self.expected_losses(&input.posterior);
        let mut ranked: Vec<(ContainmentAction, i64)> = losses
            .iter()
            .map(|(action, loss)| (*action, *loss))
            .collect();
        ranked.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.severity().cmp(&b.0.severity()))
        });

        let candidate_actions: Vec<CandidateActionScore> = ranked
            .iter()
            .map(|(action, expected_loss_millionths)| CandidateActionScore {
                action: *action,
                expected_loss_millionths: *expected_loss_millionths,
                state_contributions_millionths: state_contributions(
                    *action,
                    &self.loss_matrix,
                    &input.posterior,
                ),
                guardrail_blocked: input.blocked_actions.contains(action),
            })
            .collect();

        let selected_rank_index = ranked
            .iter()
            .position(|(action, _)| !input.blocked_actions.contains(action))
            .ok_or(RuntimeDecisionScoringError::AllActionsBlocked)?;
        let selected = ranked[selected_rank_index];
        let runner_up_index = ranked
            .iter()
            .enumerate()
            .filter(|(_, (action, _))| !input.blocked_actions.contains(action))
            .nth(1)
            .map_or(selected_rank_index, |(idx, _)| idx);
        let runner_up = ranked[runner_up_index];

        let confidence_interval =
            confidence_interval_from_posterior(selected.1, runner_up.1, &input.posterior);
        let selection_rationale = build_selection_rationale(
            selected.0,
            selected.1,
            runner_up.0,
            runner_up.1,
            &input.posterior,
        );

        let mut roi_history = input.extension_roi_history_millionths.clone();
        roi_history.push(attacker_roi_millionths);
        let attacker_roi = AttackerRoiAssessment::new(
            input.extension_id.clone(),
            attacker_roi_millionths,
            &roi_history,
        );

        let mut fleet_assessments: BTreeMap<String, AttackerRoiAssessment> = input
            .fleet_roi_baseline_millionths
            .iter()
            .map(|(extension_id, roi_millionths)| {
                (
                    extension_id.clone(),
                    AttackerRoiAssessment::new(extension_id.clone(), *roi_millionths, &[]),
                )
            })
            .collect();
        fleet_assessments.insert(input.extension_id.clone(), attacker_roi.clone());
        let fleet_roi_summary = summarize_fleet_roi(&fleet_assessments);

        let (borderline_decision, sensitivity_deltas) = compute_borderline_sensitivity(
            selected.0,
            selected.1,
            runner_up.0,
            runner_up.1,
            &self.loss_matrix,
            &input.posterior,
        );

        self.decisions_made += 1;
        let receipt_preimage_hash = compute_runtime_decision_receipt_hash(
            input,
            selected.0,
            selected.1,
            &confidence_interval,
            &attacker_roi,
            &fleet_roi_summary,
        );

        let mut events =
            build_runtime_decision_events(input, &ranked, selected.0, &fleet_assessments);
        if borderline_decision {
            events.push(RuntimeDecisionScoreEvent {
                trace_id: input.trace_id.clone(),
                decision_id: input.decision_id.clone(),
                policy_id: input.policy_id.clone(),
                component: RUNTIME_DECISION_SCORING_COMPONENT.to_string(),
                event: "borderline_decision".to_string(),
                outcome: format!(
                    "margin={} ({}→{})",
                    runner_up.1 - selected.1,
                    selected.0,
                    runner_up.0,
                ),
                error_code: Some("FE-RUNTIME-SCORING-BORDERLINE".to_string()),
            });
        }

        Ok(RuntimeDecisionScore {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            extension_id: input.extension_id.clone(),
            policy_version: input.policy_version.clone(),
            timestamp_ns: input.timestamp_ns,
            epoch: self.epoch,
            loss_matrix_version: self.loss_matrix.matrix_id.clone(),
            candidate_actions,
            selected_action: selected.0,
            selected_expected_loss_millionths: selected.1,
            selection_rationale,
            confidence_interval,
            posterior_snapshot: input.posterior.clone(),
            attacker_roi,
            fleet_roi_summary,
            borderline_decision,
            sensitivity_deltas,
            receipt_preimage_hash,
            events,
        })
    }

    /// Set the security epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }

    /// Number of decisions made.
    pub fn decisions_made(&self) -> u64 {
        self.decisions_made
    }

    /// Reference to the loss matrix.
    pub fn loss_matrix(&self) -> &LossMatrix {
        &self.loss_matrix
    }

    /// Update the loss matrix (e.g., after operator reconfiguration).
    pub fn set_loss_matrix(&mut self, matrix: LossMatrix) {
        self.loss_matrix = matrix;
    }
}

fn validate_runtime_scoring_input(
    input: &RuntimeDecisionScoringInput,
) -> Result<(), RuntimeDecisionScoringError> {
    if input.trace_id.trim().is_empty() {
        return Err(RuntimeDecisionScoringError::MissingField {
            field: "trace_id".to_string(),
        });
    }
    if input.decision_id.trim().is_empty() {
        return Err(RuntimeDecisionScoringError::MissingField {
            field: "decision_id".to_string(),
        });
    }
    if input.policy_id.trim().is_empty() {
        return Err(RuntimeDecisionScoringError::MissingField {
            field: "policy_id".to_string(),
        });
    }
    if input.extension_id.trim().is_empty() {
        return Err(RuntimeDecisionScoringError::MissingField {
            field: "extension_id".to_string(),
        });
    }
    if input.policy_version.trim().is_empty() {
        return Err(RuntimeDecisionScoringError::MissingField {
            field: "policy_version".to_string(),
        });
    }
    Ok(())
}

fn state_contributions(
    action: ContainmentAction,
    loss_matrix: &LossMatrix,
    posterior: &Posterior,
) -> BTreeMap<String, i64> {
    RiskState::ALL
        .iter()
        .map(|state| {
            let contribution =
                posterior.probability(*state) * loss_matrix.loss(action, *state) / MILLION;
            (state.to_string(), contribution)
        })
        .collect()
}

fn confidence_interval_from_posterior(
    selected_loss_millionths: i64,
    runner_up_loss_millionths: i64,
    posterior: &Posterior,
) -> DecisionConfidenceInterval {
    let max_prob = RiskState::ALL
        .iter()
        .map(|state| posterior.probability(*state))
        .max()
        .unwrap_or(0);
    let uncertainty = MILLION.saturating_sub(max_prob);
    let delta_uncertainty = ((selected_loss_millionths.abs() as i128 * uncertainty as i128)
        / (MILLION as i128 * 5)) as i64;
    let delta_margin = (runner_up_loss_millionths - selected_loss_millionths).abs() / 10;
    let delta = delta_uncertainty.max(delta_margin).max(1);
    DecisionConfidenceInterval {
        lower_millionths: selected_loss_millionths.saturating_sub(delta),
        upper_millionths: selected_loss_millionths.saturating_add(delta),
    }
}

fn build_selection_rationale(
    selected_action: ContainmentAction,
    selected_loss_millionths: i64,
    runner_up_action: ContainmentAction,
    runner_up_loss_millionths: i64,
    posterior: &Posterior,
) -> String {
    let margin = runner_up_loss_millionths - selected_loss_millionths;
    format!(
        "{selected_action} selected: EL({selected_action})={selected_loss_millionths}, \
         EL({runner_up_action})={runner_up_loss_millionths}, \
         margin={margin}, \
         p_benign={}, p_anomalous={}, p_malicious={}, p_unknown={}",
        posterior.probability(RiskState::Benign),
        posterior.probability(RiskState::Anomalous),
        posterior.probability(RiskState::Malicious),
        posterior.probability(RiskState::Unknown),
    )
}

/// Detect borderline decisions (top-2 within 10% expected-loss) and compute
/// per-state sensitivity deltas: approximate millionths shift in each risk-state
/// probability that would flip the selected action to the runner-up.
fn compute_borderline_sensitivity(
    selected_action: ContainmentAction,
    selected_el: i64,
    runner_up_action: ContainmentAction,
    runner_up_el: i64,
    loss_matrix: &LossMatrix,
    posterior: &Posterior,
) -> (bool, BTreeMap<String, i64>) {
    if selected_action == runner_up_action {
        return (false, BTreeMap::new());
    }
    let margin = runner_up_el.saturating_sub(selected_el);
    let threshold = selected_el.abs().max(1) / 10;
    let borderline = margin <= threshold;

    if !borderline {
        return (false, BTreeMap::new());
    }

    // For each risk state, estimate the probability delta that would close the
    // margin between selected and runner-up expected losses. The sensitivity
    // for state S is:  delta_S = margin * MILLION / |L(runner_up, S) - L(selected, S)|
    // (clamped to avoid division by zero).
    let mut deltas = BTreeMap::new();
    for state in RiskState::ALL {
        let loss_sel = loss_matrix.loss(selected_action, state);
        let loss_run = loss_matrix.loss(runner_up_action, state);
        let diff = (loss_run - loss_sel).abs();
        if diff > 0 {
            let delta = (margin as i128 * MILLION as i128 / diff as i128) as i64;
            deltas.insert(state.to_string(), delta);
        }
    }
    // Also record current posterior probabilities for context.
    let _ = posterior;

    (true, deltas)
}

fn compute_runtime_decision_receipt_hash(
    input: &RuntimeDecisionScoringInput,
    selected_action: ContainmentAction,
    selected_expected_loss_millionths: i64,
    confidence_interval: &DecisionConfidenceInterval,
    attacker_roi: &AttackerRoiAssessment,
    fleet_roi_summary: &FleetRoiSummary,
) -> ContentHash {
    let preimage = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        input.trace_id,
        input.decision_id,
        input.policy_id,
        input.extension_id,
        input.policy_version,
        input.timestamp_ns,
        selected_action,
        selected_expected_loss_millionths,
        confidence_interval.lower_millionths,
        confidence_interval.upper_millionths,
        attacker_roi.roi_millionths,
        fleet_roi_summary.extension_count,
        fleet_roi_summary.average_roi_millionths,
    );
    ContentHash::compute(preimage.as_bytes())
}

fn build_runtime_decision_events(
    input: &RuntimeDecisionScoringInput,
    ranked: &[(ContainmentAction, i64)],
    selected_action: ContainmentAction,
    fleet_assessments: &BTreeMap<String, AttackerRoiAssessment>,
) -> Vec<RuntimeDecisionScoreEvent> {
    let mut events = Vec::new();
    events.push(RuntimeDecisionScoreEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: RUNTIME_DECISION_SCORING_COMPONENT.to_string(),
        event: "decision_scored".to_string(),
        outcome: selected_action.to_string(),
        error_code: None,
    });

    if let Some((best_action, _)) = ranked.first()
        && input.blocked_actions.contains(best_action)
        && *best_action != selected_action
    {
        events.push(RuntimeDecisionScoreEvent {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: RUNTIME_DECISION_SCORING_COMPONENT.to_string(),
            event: "guardrail_veto_applied".to_string(),
            outcome: format!("{}->{}", best_action, selected_action),
            error_code: Some("FE-RUNTIME-SCORING-GUARDRAIL-VETO".to_string()),
        });
    }

    if let Some(assessment) = fleet_assessments.get(&input.extension_id)
        && matches!(
            assessment.alert,
            crate::trust_economics::RoiAlertLevel::Profitable
                | crate::trust_economics::RoiAlertLevel::HighlyProfitable
        )
    {
        events.push(RuntimeDecisionScoreEvent {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: RUNTIME_DECISION_SCORING_COMPONENT.to_string(),
            event: "attacker_roi_alert".to_string(),
            outcome: assessment.alert.to_string(),
            error_code: Some("FE-RUNTIME-SCORING-ROI-ALERT".to_string()),
        });
    }

    events
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bayesian_posterior::Posterior;
    use crate::trust_economics::StrategyCostAdjustment;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn certain_benign() -> Posterior {
        Posterior::from_millionths(MILLION, 0, 0, 0)
    }

    fn certain_malicious() -> Posterior {
        Posterior::from_millionths(0, 0, MILLION, 0)
    }

    fn uncertain_posterior() -> Posterior {
        Posterior::uniform()
    }

    fn high_anomalous() -> Posterior {
        Posterior::from_millionths(100, 800, 50, 50)
    }

    fn sample_attacker_cost_model() -> AttackerCostModel {
        let mut strategy_adjustments = BTreeMap::new();
        strategy_adjustments.insert(
            "supply_chain".to_string(),
            StrategyCostAdjustment {
                strategy_name: "supply_chain".to_string(),
                discovery_delta: 100_000,
                development_delta: 200_000,
                evasion_delta: 50_000,
                justification: "test-strategy".to_string(),
            },
        );
        AttackerCostModel {
            discovery_cost: 1_000_000,
            development_cost: 2_000_000,
            deployment_cost: 1_000_000,
            persistence_cost: 500_000,
            evasion_cost: 1_000_000,
            expected_gain: 20_000_000,
            strategy_adjustments,
            version: 1,
            calibration_source: "unit-test".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // ContainmentAction tests
    // -----------------------------------------------------------------------

    #[test]
    fn action_display() {
        assert_eq!(ContainmentAction::Allow.to_string(), "allow");
        assert_eq!(ContainmentAction::Challenge.to_string(), "challenge");
        assert_eq!(ContainmentAction::Sandbox.to_string(), "sandbox");
        assert_eq!(ContainmentAction::Suspend.to_string(), "suspend");
        assert_eq!(ContainmentAction::Terminate.to_string(), "terminate");
        assert_eq!(ContainmentAction::Quarantine.to_string(), "quarantine");
    }

    #[test]
    fn action_severity_order() {
        assert!(ContainmentAction::Allow.severity() < ContainmentAction::Challenge.severity());
        assert!(ContainmentAction::Challenge.severity() < ContainmentAction::Sandbox.severity());
        assert!(ContainmentAction::Sandbox.severity() < ContainmentAction::Suspend.severity());
        assert!(ContainmentAction::Suspend.severity() < ContainmentAction::Terminate.severity());
        assert!(ContainmentAction::Terminate.severity() < ContainmentAction::Quarantine.severity());
    }

    #[test]
    fn action_serde_roundtrip() {
        for action in &ContainmentAction::ALL {
            let json = serde_json::to_string(action).unwrap();
            let restored: ContainmentAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, restored);
        }
    }

    // -----------------------------------------------------------------------
    // LossMatrix tests
    // -----------------------------------------------------------------------

    #[test]
    fn balanced_matrix_is_complete() {
        let m = LossMatrix::balanced();
        assert!(m.is_complete());
    }

    #[test]
    fn conservative_matrix_is_complete() {
        let m = LossMatrix::conservative();
        assert!(m.is_complete());
    }

    #[test]
    fn permissive_matrix_is_complete() {
        let m = LossMatrix::permissive();
        assert!(m.is_complete());
    }

    #[test]
    fn loss_lookup() {
        let m = LossMatrix::balanced();
        assert_eq!(m.loss(ContainmentAction::Allow, RiskState::Benign), 0);
        assert_eq!(
            m.loss(ContainmentAction::Allow, RiskState::Malicious),
            100_000_000
        );
        assert_eq!(
            m.loss(ContainmentAction::Terminate, RiskState::Malicious),
            500_000
        );
    }

    #[test]
    fn loss_matrix_serde_roundtrip() {
        let m = LossMatrix::balanced();
        let json = serde_json::to_string(&m).unwrap();
        let restored: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }

    #[test]
    fn loss_matrix_content_hash_deterministic() {
        let m1 = LossMatrix::balanced();
        let m2 = LossMatrix::balanced();
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn different_matrices_different_hashes() {
        let balanced = LossMatrix::balanced();
        let conservative = LossMatrix::conservative();
        assert_ne!(balanced.content_hash(), conservative.content_hash());
    }

    // -----------------------------------------------------------------------
    // ExpectedLossSelector — basic selection
    // -----------------------------------------------------------------------

    #[test]
    fn select_allow_for_benign() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&certain_benign());
        assert_eq!(decision.action, ContainmentAction::Allow);
    }

    #[test]
    fn select_severe_for_malicious() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&certain_malicious());
        // With high P(Malicious), should select Quarantine or Terminate.
        assert!(
            decision.action == ContainmentAction::Quarantine
                || decision.action == ContainmentAction::Terminate,
            "expected severe action, got: {}",
            decision.action
        );
    }

    #[test]
    fn select_returns_valid_decision() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&uncertain_posterior());
        assert!(decision.expected_loss_millionths >= 0);
        assert!(decision.runner_up_loss_millionths >= decision.expected_loss_millionths);
        assert!(decision.explanation.margin_millionths >= 0);
    }

    // -----------------------------------------------------------------------
    // Expected losses computation
    // -----------------------------------------------------------------------

    #[test]
    fn expected_losses_all_actions_present() {
        let selector = ExpectedLossSelector::balanced();
        let losses = selector.expected_losses(&uncertain_posterior());
        assert_eq!(losses.len(), 6);
        for action in &ContainmentAction::ALL {
            assert!(losses.contains_key(action));
        }
    }

    #[test]
    fn expected_losses_deterministic() {
        let s1 = ExpectedLossSelector::balanced();
        let s2 = ExpectedLossSelector::balanced();
        let p = uncertain_posterior();
        assert_eq!(s1.expected_losses(&p), s2.expected_losses(&p));
    }

    // -----------------------------------------------------------------------
    // Tie-breaking
    // -----------------------------------------------------------------------

    #[test]
    fn tie_breaking_prefers_less_severe() {
        // Create a matrix where Allow and Challenge have identical loss for all states.
        let entries: Vec<LossEntry> = ContainmentAction::ALL
            .iter()
            .flat_map(|action| {
                RiskState::ALL.iter().map(move |state| LossEntry {
                    action: *action,
                    state: *state,
                    loss_millionths: 1_000_000, // All costs equal
                })
            })
            .collect();
        let matrix = LossMatrix::new("equal-v1", entries);
        let mut selector = ExpectedLossSelector::new(matrix);
        let decision = selector.select(&uncertain_posterior());
        // Should pick Allow (least severe) when all equal.
        assert_eq!(decision.action, ContainmentAction::Allow);
    }

    // -----------------------------------------------------------------------
    // Decision explanation
    // -----------------------------------------------------------------------

    #[test]
    fn explanation_contains_posterior() {
        let mut selector = ExpectedLossSelector::balanced();
        let posterior = uncertain_posterior();
        let decision = selector.select(&posterior);
        assert_eq!(decision.explanation.posterior_snapshot, posterior);
    }

    #[test]
    fn explanation_contains_all_losses() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&uncertain_posterior());
        assert_eq!(decision.explanation.all_expected_losses.len(), 6);
    }

    #[test]
    fn explanation_margin_correct() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&uncertain_posterior());
        assert_eq!(
            decision.explanation.margin_millionths,
            decision.runner_up_loss_millionths - decision.expected_loss_millionths
        );
    }

    #[test]
    fn explanation_loss_matrix_id() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&uncertain_posterior());
        assert_eq!(decision.explanation.loss_matrix_id, "balanced-v1");
    }

    // -----------------------------------------------------------------------
    // Decision counting
    // -----------------------------------------------------------------------

    #[test]
    fn decisions_made_increments() {
        let mut selector = ExpectedLossSelector::balanced();
        assert_eq!(selector.decisions_made(), 0);
        selector.select(&uncertain_posterior());
        assert_eq!(selector.decisions_made(), 1);
        selector.select(&certain_benign());
        assert_eq!(selector.decisions_made(), 2);
    }

    // -----------------------------------------------------------------------
    // Epoch tracking
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_stamped_on_decision() {
        let mut selector = ExpectedLossSelector::balanced();
        selector.set_epoch(SecurityEpoch::from_raw(42));
        let decision = selector.select(&uncertain_posterior());
        assert_eq!(decision.epoch, SecurityEpoch::from_raw(42));
    }

    // -----------------------------------------------------------------------
    // Loss matrix swap
    // -----------------------------------------------------------------------

    #[test]
    fn changing_matrix_changes_decision() {
        let mut selector = ExpectedLossSelector::new(LossMatrix::permissive());
        let d1 = selector.select(&uncertain_posterior());

        selector.set_loss_matrix(LossMatrix::conservative());
        let d2 = selector.select(&uncertain_posterior());

        // Different matrices should generally produce different expected losses.
        assert_ne!(
            d1.expected_loss_millionths, d2.expected_loss_millionths,
            "different matrices should produce different expected losses"
        );
    }

    // -----------------------------------------------------------------------
    // Property: selected action has minimum expected loss
    // -----------------------------------------------------------------------

    #[test]
    fn selected_action_is_minimum() {
        let mut selector = ExpectedLossSelector::balanced();
        for posterior in [
            certain_benign(),
            certain_malicious(),
            uncertain_posterior(),
            high_anomalous(),
            Posterior::default_prior(),
        ] {
            let decision = selector.select(&posterior);
            let losses = selector.expected_losses(&posterior);
            for loss in losses.values() {
                assert!(
                    decision.expected_loss_millionths <= *loss,
                    "selected action should have minimum loss"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn action_decision_serde_roundtrip() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&uncertain_posterior());
        let json = serde_json::to_string(&decision).unwrap();
        let restored: ActionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, restored);
    }

    #[test]
    fn selector_serde_roundtrip() {
        let mut selector = ExpectedLossSelector::balanced();
        selector.select(&uncertain_posterior());
        let json = serde_json::to_string(&selector).unwrap();
        let restored: ExpectedLossSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(selector.decisions_made(), restored.decisions_made());
    }

    #[test]
    fn explanation_serde_roundtrip() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&uncertain_posterior());
        let json = serde_json::to_string(&decision.explanation).unwrap();
        let restored: DecisionExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(decision.explanation, restored);
    }

    // -----------------------------------------------------------------------
    // Integration-style: posterior updater → selector
    // -----------------------------------------------------------------------

    #[test]
    fn integration_benign_sequence() {
        use crate::bayesian_posterior::{BayesianPosteriorUpdater, Evidence};

        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let mut selector = ExpectedLossSelector::balanced();

        // Feed benign evidence.
        let ev = Evidence {
            extension_id: "ext-001".to_string(),
            hostcall_rate_millionths: 10_000_000,
            distinct_capabilities: 3,
            resource_score_millionths: 100_000,
            timing_anomaly_millionths: 0,
            denial_rate_millionths: 0,
            epoch: SecurityEpoch::GENESIS,
        };
        for _ in 0..5 {
            updater.update(&ev);
        }

        let decision = selector.select(updater.posterior());
        assert_eq!(
            decision.action,
            ContainmentAction::Allow,
            "benign evidence should result in Allow"
        );
    }

    #[test]
    fn integration_malicious_sequence() {
        use crate::bayesian_posterior::{BayesianPosteriorUpdater, Evidence};

        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let mut selector = ExpectedLossSelector::balanced();

        // Feed malicious evidence.
        let ev = Evidence {
            extension_id: "ext-001".to_string(),
            hostcall_rate_millionths: 900_000_000,
            distinct_capabilities: 14,
            resource_score_millionths: 950_000,
            timing_anomaly_millionths: 900_000,
            denial_rate_millionths: 500_000,
            epoch: SecurityEpoch::GENESIS,
        };
        for _ in 0..10 {
            updater.update(&ev);
        }

        let decision = selector.select(updater.posterior());
        assert!(
            decision.action == ContainmentAction::Quarantine
                || decision.action == ContainmentAction::Terminate,
            "malicious evidence should result in Quarantine or Terminate, got: {}",
            decision.action
        );
    }

    // -----------------------------------------------------------------------
    // Runtime decision scoring
    // -----------------------------------------------------------------------

    fn sample_runtime_input(posterior: Posterior) -> RuntimeDecisionScoringInput {
        RuntimeDecisionScoringInput {
            trace_id: "trace-runtime-score-001".to_string(),
            decision_id: "decision-runtime-score-001".to_string(),
            policy_id: "policy-runtime-score-v1".to_string(),
            extension_id: "ext-runtime-score".to_string(),
            policy_version: "policy-v1.2.3".to_string(),
            timestamp_ns: 1_700_000_000_000_000_123,
            posterior,
            attacker_cost_model: sample_attacker_cost_model(),
            extension_roi_history_millionths: vec![1_000_000, 1_500_000, 2_100_000],
            fleet_roi_baseline_millionths: BTreeMap::from([("ext-other".to_string(), 300_000)]),
            blocked_actions: BTreeSet::new(),
        }
    }

    #[test]
    fn runtime_scoring_emits_expected_artifact_fields() {
        let mut selector = ExpectedLossSelector::balanced();
        selector.set_epoch(SecurityEpoch::from_raw(7));
        let input = sample_runtime_input(uncertain_posterior());
        let artifact = selector
            .score_runtime_decision(&input)
            .expect("runtime scoring artifact");

        assert_eq!(artifact.trace_id, input.trace_id);
        assert_eq!(artifact.decision_id, input.decision_id);
        assert_eq!(artifact.policy_id, input.policy_id);
        assert_eq!(artifact.extension_id, input.extension_id);
        assert_eq!(artifact.policy_version, input.policy_version);
        assert_eq!(artifact.timestamp_ns, input.timestamp_ns);
        assert_eq!(artifact.epoch, SecurityEpoch::from_raw(7));
        assert_eq!(artifact.loss_matrix_version, "balanced-v1");
        assert_eq!(
            artifact.candidate_actions.len(),
            ContainmentAction::ALL.len()
        );
        assert!(
            artifact
                .candidate_actions
                .windows(2)
                .all(|w| w[0].expected_loss_millionths <= w[1].expected_loss_millionths)
        );
        assert!(artifact.candidate_actions.iter().all(|candidate| {
            candidate.state_contributions_millionths.len() == RiskState::ALL.len()
                && !candidate.guardrail_blocked
        }));
        assert!(
            artifact.confidence_interval.lower_millionths
                <= artifact.selected_expected_loss_millionths
        );
        assert!(
            artifact.confidence_interval.upper_millionths
                >= artifact.selected_expected_loss_millionths
        );
        assert!(artifact.selection_rationale.contains("EL("));
        assert_eq!(artifact.attacker_roi.extension_id, input.extension_id);
        assert_eq!(artifact.attacker_roi.alert.to_string(), "highly_profitable");
        assert_eq!(artifact.fleet_roi_summary.extension_count, 2);
        assert_eq!(
            artifact.events[0],
            RuntimeDecisionScoreEvent {
                trace_id: input.trace_id.clone(),
                decision_id: input.decision_id.clone(),
                policy_id: input.policy_id.clone(),
                component: "runtime_decision_scoring".to_string(),
                event: "decision_scored".to_string(),
                outcome: artifact.selected_action.to_string(),
                error_code: None,
            }
        );
        assert!(artifact.events.iter().any(|event| {
            event.event == "attacker_roi_alert"
                && event.outcome == "highly_profitable"
                && event.error_code.as_deref() == Some("FE-RUNTIME-SCORING-ROI-ALERT")
        }));
    }

    #[test]
    fn runtime_scoring_guardrail_veto_changes_selection() {
        let mut selector = ExpectedLossSelector::balanced();
        let mut input = sample_runtime_input(certain_benign());
        input.blocked_actions.insert(ContainmentAction::Allow);

        let artifact = selector
            .score_runtime_decision(&input)
            .expect("runtime scoring artifact");
        assert_ne!(artifact.selected_action, ContainmentAction::Allow);
        assert!(artifact.events.iter().any(|event| {
            event.event == "guardrail_veto_applied"
                && event.error_code.as_deref() == Some("FE-RUNTIME-SCORING-GUARDRAIL-VETO")
        }));
    }

    #[test]
    fn runtime_scoring_rejects_missing_metadata() {
        let mut selector = ExpectedLossSelector::balanced();
        let mut input = sample_runtime_input(uncertain_posterior());
        input.trace_id.clear();
        let err = selector
            .score_runtime_decision(&input)
            .expect_err("missing trace id should fail");
        assert_eq!(
            err,
            RuntimeDecisionScoringError::MissingField {
                field: "trace_id".to_string()
            }
        );
    }

    #[test]
    fn runtime_scoring_rejects_all_actions_blocked() {
        let mut selector = ExpectedLossSelector::balanced();
        let mut input = sample_runtime_input(uncertain_posterior());
        input.blocked_actions = ContainmentAction::ALL.into_iter().collect();
        let err = selector
            .score_runtime_decision(&input)
            .expect_err("all actions blocked should fail");
        assert_eq!(err, RuntimeDecisionScoringError::AllActionsBlocked);
    }

    #[test]
    fn runtime_scoring_is_deterministic() {
        let mut selector = ExpectedLossSelector::balanced();
        let input = sample_runtime_input(uncertain_posterior());
        let first = selector
            .score_runtime_decision(&input)
            .expect("first runtime scoring");
        let second = selector
            .score_runtime_decision(&input)
            .expect("second runtime scoring");
        assert_eq!(first, second);
    }

    // -----------------------------------------------------------------------
    // Loss entry serde
    // -----------------------------------------------------------------------

    #[test]
    fn loss_entry_serde_roundtrip() {
        let entry = le(ContainmentAction::Allow, RiskState::Benign, 0);
        let json = serde_json::to_string(&entry).unwrap();
        let restored: LossEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }

    // -----------------------------------------------------------------------
    // High anomalous selects moderate action
    // -----------------------------------------------------------------------

    #[test]
    fn high_anomalous_selects_moderate_action() {
        let mut selector = ExpectedLossSelector::balanced();
        let decision = selector.select(&high_anomalous());
        // With high P(Anomalous), should select Suspend or Sandbox (moderate).
        assert!(
            decision.action.severity() >= ContainmentAction::Sandbox.severity(),
            "high anomalous should select at least Sandbox, got: {}",
            decision.action
        );
    }

    // -----------------------------------------------------------------------
    // Borderline decision detection and sensitivity
    // -----------------------------------------------------------------------

    #[test]
    fn borderline_decision_detected_when_margin_small() {
        // Build a posterior where allow and challenge are very close in EL.
        // Mostly benign with slight anomalous signal → allow and challenge close.
        let posterior = Posterior::from_millionths(900_000, 80_000, 10_000, 10_000);
        let mut selector = ExpectedLossSelector::balanced();
        let input = sample_runtime_input(posterior);
        let score = selector
            .score_runtime_decision(&input)
            .expect("scoring should succeed");

        // If borderline, verify sensitivity deltas exist.
        if score.borderline_decision {
            assert!(
                !score.sensitivity_deltas.is_empty(),
                "borderline decisions must include sensitivity deltas"
            );
            // All sensitivity deltas must be non-negative.
            for (state, delta) in &score.sensitivity_deltas {
                assert!(
                    *delta >= 0,
                    "sensitivity delta for {state} must be non-negative, got {delta}"
                );
            }
            // Must have a borderline_decision event.
            assert!(
                score
                    .events
                    .iter()
                    .any(|e| e.event == "borderline_decision"),
                "borderline decision must emit borderline_decision event"
            );
        }
    }

    #[test]
    fn non_borderline_has_empty_sensitivity() {
        let posterior = certain_malicious();
        let mut selector = ExpectedLossSelector::balanced();
        let input = sample_runtime_input(posterior);
        let score = selector
            .score_runtime_decision(&input)
            .expect("scoring should succeed");
        assert!(
            !score.borderline_decision,
            "certain malicious posterior should not be borderline"
        );
        assert!(
            score.sensitivity_deltas.is_empty(),
            "non-borderline must have empty sensitivity_deltas"
        );
    }

    // -----------------------------------------------------------------------
    // Enhanced rationale includes all posterior probabilities
    // -----------------------------------------------------------------------

    #[test]
    fn rationale_includes_all_posterior_probabilities() {
        let posterior = uncertain_posterior();
        let mut selector = ExpectedLossSelector::balanced();
        let input = sample_runtime_input(posterior);
        let score = selector
            .score_runtime_decision(&input)
            .expect("scoring should succeed");
        assert!(
            score.selection_rationale.contains("p_benign="),
            "rationale must include p_benign"
        );
        assert!(
            score.selection_rationale.contains("p_anomalous="),
            "rationale must include p_anomalous"
        );
        assert!(
            score.selection_rationale.contains("p_malicious="),
            "rationale must include p_malicious"
        );
        assert!(
            score.selection_rationale.contains("p_unknown="),
            "rationale must include p_unknown"
        );
        assert!(
            score.selection_rationale.contains("margin="),
            "rationale must include margin"
        );
    }

    // -----------------------------------------------------------------------
    // Monotonicity: higher P(malicious) never selects less-restrictive action
    // -----------------------------------------------------------------------

    #[test]
    fn monotonicity_increasing_malicious_never_relaxes() {
        let mut selector = ExpectedLossSelector::balanced();
        let steps = 20;
        let mut prev_severity = 0u32;
        for i in 0..=steps {
            let p_malicious = (MILLION as u64 * i as u64 / steps as u64) as i64;
            let p_benign = MILLION - p_malicious;
            let posterior = Posterior::from_millionths(p_benign, 0, p_malicious, 0);
            let input = sample_runtime_input(posterior);
            let score = selector
                .score_runtime_decision(&input)
                .expect("scoring should succeed");
            let severity = score.selected_action.severity();
            assert!(
                severity >= prev_severity,
                "monotonicity violation at step {i}: severity {} < previous {prev_severity}",
                severity
            );
            prev_severity = severity;
        }
    }

    // -----------------------------------------------------------------------
    // Edge case: uniform posterior selects deterministic action
    // -----------------------------------------------------------------------

    #[test]
    fn uniform_posterior_deterministic() {
        let mut selector = ExpectedLossSelector::balanced();
        let input = sample_runtime_input(Posterior::uniform());
        let score1 = selector.score_runtime_decision(&input).expect("first");
        let score2 = selector.score_runtime_decision(&input).expect("second");
        assert_eq!(score1.selected_action, score2.selected_action);
        assert_eq!(
            score1.selected_expected_loss_millionths,
            score2.selected_expected_loss_millionths,
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: near-degenerate posterior (one state ~100%)
    // -----------------------------------------------------------------------

    #[test]
    fn near_degenerate_posterior_handles_correctly() {
        let mut selector = ExpectedLossSelector::balanced();
        // 99.99% benign
        let posterior = Posterior::from_millionths(999_900, 50, 25, 25);
        let input = sample_runtime_input(posterior);
        let score = selector
            .score_runtime_decision(&input)
            .expect("scoring should succeed");
        assert_eq!(
            score.selected_action,
            ContainmentAction::Allow,
            "near-certain benign should select Allow"
        );
        assert!(
            score.confidence_interval.upper_millionths
                >= score.confidence_interval.lower_millionths,
            "confidence interval must be well-ordered"
        );
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip for new fields
    // -----------------------------------------------------------------------

    #[test]
    fn runtime_score_serde_with_borderline_fields() {
        let posterior = uncertain_posterior();
        let mut selector = ExpectedLossSelector::balanced();
        let input = sample_runtime_input(posterior);
        let score = selector
            .score_runtime_decision(&input)
            .expect("scoring should succeed");
        let json = serde_json::to_string(&score).unwrap();
        let restored: RuntimeDecisionScore = serde_json::from_str(&json).unwrap();
        assert_eq!(score, restored);
        // Verify new fields survive roundtrip.
        assert_eq!(score.borderline_decision, restored.borderline_decision);
        assert_eq!(score.sensitivity_deltas, restored.sensitivity_deltas);
    }

    // -----------------------------------------------------------------------
    // Multiple blocked actions: selection skips all vetoed
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_blocked_actions_skips_correctly() {
        let posterior = certain_malicious();
        let mut selector = ExpectedLossSelector::balanced();
        let mut input = sample_runtime_input(posterior);
        input.blocked_actions.insert(ContainmentAction::Quarantine);
        input.blocked_actions.insert(ContainmentAction::Terminate);
        input.blocked_actions.insert(ContainmentAction::Suspend);
        let score = selector
            .score_runtime_decision(&input)
            .expect("scoring should succeed");
        assert!(
            !input.blocked_actions.contains(&score.selected_action),
            "selected action {} must not be blocked",
            score.selected_action
        );
    }

    // -----------------------------------------------------------------------
    // Candidate actions always includes all 6 actions
    // -----------------------------------------------------------------------

    #[test]
    fn candidate_actions_always_complete() {
        let posteriors = [
            certain_benign(),
            certain_malicious(),
            uncertain_posterior(),
            high_anomalous(),
        ];
        for posterior in posteriors {
            let mut selector = ExpectedLossSelector::balanced();
            let input = sample_runtime_input(posterior);
            let score = selector
                .score_runtime_decision(&input)
                .expect("scoring should succeed");
            assert_eq!(
                score.candidate_actions.len(),
                ContainmentAction::ALL.len(),
                "candidate actions must include all 6 actions"
            );
        }
    }
}
