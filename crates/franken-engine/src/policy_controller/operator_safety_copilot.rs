//! Operator-facing safety copilot surfaces for policy-controller decisions.
//!
//! This module focuses on deterministic recommendation ranking, confidence
//! bands, rollback command generation, confirmation workflow, and audit-friendly
//! interaction contracts used by operator UI surfaces.
//!
//! Plan reference: Section 10.12 item 19 (`bd-1ddd`).

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

const COPILOT_COMPONENT: &str = "operator_safety_copilot";
const MILLION: i64 = 1_000_000;
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Reversibility classification for an operator recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationReversibility {
    Reversible,
    LimitedWindow,
    Irreversible,
}

/// Time sensitivity for recommended actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSensitivity {
    Immediate,
    NearTerm,
    Routine,
}

/// Operator role for access-control checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Viewer,
    Operator,
    Administrator,
}

/// Direction for a decision-boundary trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryTriggerDirection {
    AtOrAbove,
    AtOrBelow,
}

/// Severity class for fleet incidents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Extension trust level for fleet-health surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionTrustLevel {
    High,
    Guarded,
    Watch,
    Quarantined,
}

/// Candidate recommendation generated from runtime decision scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecommendationCandidate {
    pub action_type: String,
    pub target_extension: String,
    pub expected_loss_reduction_millionths: i64,
    pub confidence_millionths: i64,
    pub side_effects: Vec<String>,
    pub collateral_extensions: u32,
    pub estimated_action_latency_ms: u64,
    pub reversibility: RecommendationReversibility,
    pub time_sensitivity: TimeSensitivity,
    pub rollback_window_ms: Option<u64>,
    pub snapshot_id: Option<String>,
}

/// Confidence interval for one metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceBand {
    pub metric: String,
    pub point_millionths: i64,
    pub lower_millionths: i64,
    pub upper_millionths: i64,
    pub confidence_level_bps: u16,
}

impl ConfidenceBand {
    fn validate(&self) -> Result<(), CopilotError> {
        validate_non_empty("confidence_band.metric", &self.metric)?;
        validate_probability("confidence_band.point_millionths", self.point_millionths)?;
        validate_probability("confidence_band.lower_millionths", self.lower_millionths)?;
        validate_probability("confidence_band.upper_millionths", self.upper_millionths)?;
        if self.lower_millionths > self.point_millionths
            || self.point_millionths > self.upper_millionths
        {
            return Err(CopilotError::InvalidConfidenceBand {
                metric: self.metric.clone(),
            });
        }
        if self.confidence_level_bps == 0 || self.confidence_level_bps > 10_000 {
            return Err(CopilotError::InvalidConfidenceBand {
                metric: self.metric.clone(),
            });
        }
        Ok(())
    }
}

/// Evidence strength summary shown to operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStrength {
    pub evidence_atoms: u32,
    pub observation_window_seconds: u64,
}

/// Proximity hint for a decision boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBoundaryHint {
    pub metric: String,
    pub current_millionths: i64,
    pub threshold_millionths: i64,
    pub additional_evidence_needed: u32,
    pub evidence_type: String,
    pub trigger_direction: BoundaryTriggerDirection,
}

impl DecisionBoundaryHint {
    fn validate(&self) -> Result<(), CopilotError> {
        validate_non_empty("decision_boundary.metric", &self.metric)?;
        validate_probability(
            "decision_boundary.current_millionths",
            self.current_millionths,
        )?;
        validate_probability(
            "decision_boundary.threshold_millionths",
            self.threshold_millionths,
        )?;
        validate_non_empty("decision_boundary.evidence_type", &self.evidence_type)?;
        if self.additional_evidence_needed == 0 {
            return Err(CopilotError::InvalidDecisionBoundaryHint {
                metric: self.metric.clone(),
            });
        }
        Ok(())
    }
}

/// Drill-down pointers associated with timeline events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineDrilldownPointers {
    pub evidence_pointer: Option<String>,
    pub decision_receipt_pointer: Option<String>,
    pub replay_pointer: Option<String>,
    pub counterfactual_pointer: Option<String>,
}

/// One event in the incident timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTimelineEvent {
    pub timestamp_ns: u64,
    pub event_id: String,
    pub event_type: String,
    pub detail: String,
    pub outcome: String,
    pub error_code: Option<String>,
    #[serde(default)]
    pub drilldown: TimelineDrilldownPointers,
}

/// Input envelope for building an operator safety copilot surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSafetyCopilotInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub no_action_expected_loss_millionths: i64,
    pub recommendations: Vec<ActionRecommendationCandidate>,
    pub confidence_bands: Vec<ConfidenceBand>,
    pub evidence_strength: EvidenceStrength,
    pub decision_boundary_hints: Vec<DecisionBoundaryHint>,
    pub timeline: Vec<IncidentTimelineEvent>,
}

/// Deterministic rollback command emitted for every recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackCommand {
    pub command: String,
    pub safety_summary: String,
}

/// Ranked recommendation for operator presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedRecommendation {
    pub rank: u32,
    pub action_type: String,
    pub target_extension: String,
    pub expected_loss_reduction_millionths: i64,
    pub confidence_millionths: i64,
    pub side_effects: Vec<String>,
    pub collateral_extensions: u32,
    pub estimated_action_latency_ms: u64,
    pub reversibility: RecommendationReversibility,
    pub time_sensitivity: TimeSensitivity,
    pub rollback_window_ms: Option<u64>,
    pub rollback_command: RollbackCommand,
    pub explanation: String,
}

/// Structured event emitted by copilot-surface operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopilotStructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Deterministic output for operator safety copilot surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSafetyCopilotSurface {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub read_only: bool,
    pub recommended_action: RankedRecommendation,
    pub alternatives: Vec<RankedRecommendation>,
    pub no_action_expected_loss_millionths: i64,
    pub confidence_bands: Vec<ConfidenceBand>,
    pub evidence_strength: EvidenceStrength,
    pub decision_boundary_hints: Vec<DecisionBoundaryHint>,
    pub timeline: Vec<IncidentTimelineEvent>,
    pub logs: Vec<CopilotStructuredLogEvent>,
}

/// Operator identity attached to action interactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub operator_id: String,
    pub role: OperatorRole,
}

/// Operator interaction audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAuditEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub operator_id: String,
    pub operator_role: OperatorRole,
    pub event: String,
    pub outcome: String,
    pub context: String,
    pub timestamp_ns: u64,
    pub error_code: Option<String>,
}

/// Impact summary shown before action confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionImpactSummary {
    pub dependent_extensions_affected: u32,
    pub estimated_latency_ms: u64,
    pub reversible: bool,
    pub rollback_window_ms_remaining: Option<u64>,
}

/// Selection state for the action-confirmation workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSelectionReview {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub selected_rank: u32,
    pub selected_recommendation: RankedRecommendation,
    pub impact_summary: ActionImpactSummary,
    pub selected_by: OperatorIdentity,
    pub selected_at_ns: u64,
    pub audit_event: OperatorAuditEvent,
}

/// Receipt proving an action execution decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionExecutionReceipt {
    pub receipt_id: String,
    pub signature: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub incident_id: String,
    pub action_type: String,
    pub target_extension: String,
    pub operator_id: String,
    pub confirmed_at_ns: u64,
    pub rollback_command: String,
}

/// Final action-confirmation output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedActionExecution {
    pub execution_command: String,
    pub rollback_command: RollbackCommand,
    pub receipt: ActionExecutionReceipt,
    pub audit_event: OperatorAuditEvent,
    pub log_event: CopilotStructuredLogEvent,
}

/// Input for deterministic rollback receipt generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReceiptInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action_receipt_id: String,
    pub rollback_decision_id: String,
    pub evidence_pointer: String,
    pub restoration_verification: String,
    pub executed_at_ns: u64,
}

/// Receipt proving rollback execution and verification linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackExecutionReceipt {
    pub receipt_id: String,
    pub signature: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action_receipt_id: String,
    pub rollback_decision_id: String,
    pub evidence_pointer: String,
    pub restoration_verification: String,
    pub executed_at_ns: u64,
}

/// Per-extension detail card used in dashboard surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionTrustCard {
    pub extension_id: String,
    pub trust_level: ExtensionTrustLevel,
    pub recent_evidence_atoms: u32,
    pub recent_decision_ids: Vec<String>,
    pub current_recommendation: Option<String>,
}

/// Active incident summary for fleet dashboards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveIncidentSummary {
    pub incident_id: String,
    pub extension_id: String,
    pub severity: IncidentSeverity,
    pub started_at_ns: u64,
    pub status: String,
}

/// Recent containment action outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentActionOutcome {
    pub incident_id: String,
    pub action_type: String,
    pub outcome: String,
    pub latency_ms: u64,
}

/// Distribution row for trust-level aggregates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustLevelDistributionEntry {
    pub trust_level: ExtensionTrustLevel,
    pub extensions: u32,
}

/// Fleet health aggregate view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHealthOverview {
    pub trust_level_distribution: Vec<TrustLevelDistributionEntry>,
    pub active_incidents: Vec<ActiveIncidentSummary>,
    pub active_incidents_count: u32,
    pub highest_severity: IncidentSeverity,
    pub attacker_roi_trend_millionths: Vec<i64>,
    pub recent_containment_actions: Vec<ContainmentActionOutcome>,
    pub extension_details: Vec<ExtensionTrustCard>,
}

/// Raw detection counts for policy effectiveness views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryDetectionCount {
    pub category: String,
    pub detected_events: u64,
    pub total_events: u64,
}

/// Detection-rate row (fixed-point millionths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryDetectionRate {
    pub category: String,
    pub detected_events: u64,
    pub total_events: u64,
    pub rate_millionths: i64,
}

/// Calibration point for reliability tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationPoint {
    pub timestamp_ns: u64,
    pub expected_millionths: i64,
    pub observed_millionths: i64,
}

/// Input envelope for policy-effectiveness surface computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEffectivenessInput {
    pub detection_counts: Vec<CategoryDetectionCount>,
    pub false_positive_rate_trend_millionths: Vec<i64>,
    pub containment_latencies_ms: Vec<u64>,
    pub calibration_history: Vec<CalibrationPoint>,
}

/// Policy-effectiveness dashboard view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEffectivenessView {
    pub detection_rate_by_category: Vec<CategoryDetectionRate>,
    pub false_positive_rate_trend_millionths: Vec<i64>,
    pub containment_latency_p50_ms: u64,
    pub containment_latency_p95_ms: u64,
    pub calibration_history: Vec<CalibrationPoint>,
}

/// Copilot-surface construction and interaction errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CopilotError {
    MissingRecommendations,
    InvalidProbability {
        field: String,
        value: i64,
    },
    InvalidField {
        field: String,
    },
    InvalidConfidenceBand {
        metric: String,
    },
    InvalidDecisionBoundaryHint {
        metric: String,
    },
    MissingSnapshotForRollback {
        action_type: String,
        target_extension: String,
    },
    InvalidRollbackWindow {
        action_type: String,
        target_extension: String,
    },
    UnauthorizedRole {
        role: OperatorRole,
        action: String,
    },
    RecommendationRankOutOfRange {
        requested_rank: u32,
        available: u32,
    },
    OperatorMismatch {
        selected_by: String,
        confirmed_by: String,
    },
    MissingConfirmationToken,
}

impl fmt::Display for CopilotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRecommendations => f.write_str("copilot input is missing recommendations"),
            Self::InvalidProbability { field, value } => {
                write!(
                    f,
                    "invalid probability for {field}: {value} (expected 0..=1_000_000)"
                )
            }
            Self::InvalidField { field } => write!(f, "invalid or empty field `{field}`"),
            Self::InvalidConfidenceBand { metric } => {
                write!(f, "invalid confidence band bounds for metric `{metric}`")
            }
            Self::InvalidDecisionBoundaryHint { metric } => {
                write!(f, "invalid decision boundary hint for metric `{metric}`")
            }
            Self::MissingSnapshotForRollback {
                action_type,
                target_extension,
            } => write!(
                f,
                "missing snapshot_id for rollback action `{action_type}` on extension `{target_extension}`"
            ),
            Self::InvalidRollbackWindow {
                action_type,
                target_extension,
            } => write!(
                f,
                "limited-window rollback requires rollback_window_ms for action `{action_type}` on extension `{target_extension}`"
            ),
            Self::UnauthorizedRole { role, action } => {
                write!(f, "role `{role:?}` is not authorized to `{action}`")
            }
            Self::RecommendationRankOutOfRange {
                requested_rank,
                available,
            } => write!(
                f,
                "requested recommendation rank {requested_rank} out of range (available={available})"
            ),
            Self::OperatorMismatch {
                selected_by,
                confirmed_by,
            } => write!(
                f,
                "operator mismatch between selection `{selected_by}` and confirmation `{confirmed_by}`"
            ),
            Self::MissingConfirmationToken => {
                f.write_str("confirmation token is required for action execution")
            }
        }
    }
}

impl Error for CopilotError {}

/// Build the deterministic operator safety copilot surface.
pub fn build_operator_safety_copilot_surface(
    input: &OperatorSafetyCopilotInput,
) -> Result<OperatorSafetyCopilotSurface, CopilotError> {
    validate_input(input)?;

    let mut ranked = input.recommendations.clone();
    ranked.sort_by(recommendation_sort);

    let ranked_recommendations = ranked
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let rank = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            let rollback = build_rollback_command(
                &input.trace_id,
                &input.decision_id,
                &input.policy_id,
                candidate,
            );
            RankedRecommendation {
                rank,
                action_type: candidate.action_type.clone(),
                target_extension: candidate.target_extension.clone(),
                expected_loss_reduction_millionths: candidate.expected_loss_reduction_millionths,
                confidence_millionths: candidate.confidence_millionths,
                side_effects: candidate.side_effects.clone(),
                collateral_extensions: candidate.collateral_extensions,
                estimated_action_latency_ms: candidate.estimated_action_latency_ms,
                reversibility: candidate.reversibility,
                time_sensitivity: candidate.time_sensitivity,
                rollback_window_ms: candidate.rollback_window_ms,
                rollback_command: rollback,
                explanation: recommendation_explanation(candidate),
            }
        })
        .collect::<Vec<_>>();

    let mut timeline = input.timeline.clone();
    timeline.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then_with(|| left.event_id.cmp(&right.event_id))
            .then_with(|| left.event_type.cmp(&right.event_type))
    });

    let mut bands = input.confidence_bands.clone();
    bands.sort_by(|left, right| left.metric.cmp(&right.metric));

    let mut boundary_hints = input.decision_boundary_hints.clone();
    boundary_hints.sort_by(|left, right| {
        left.metric
            .cmp(&right.metric)
            .then_with(|| left.threshold_millionths.cmp(&right.threshold_millionths))
            .then_with(|| left.current_millionths.cmp(&right.current_millionths))
            .then_with(|| left.evidence_type.cmp(&right.evidence_type))
    });

    let recommended_action = ranked_recommendations[0].clone();
    let alternatives = ranked_recommendations[1..].to_vec();
    let logs = vec![CopilotStructuredLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: COPILOT_COMPONENT.to_string(),
        event: "copilot_surface_built".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }];

    Ok(OperatorSafetyCopilotSurface {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        incident_id: input.incident_id.clone(),
        read_only: true,
        recommended_action,
        alternatives,
        no_action_expected_loss_millionths: input.no_action_expected_loss_millionths,
        confidence_bands: bands,
        evidence_strength: input.evidence_strength.clone(),
        decision_boundary_hints: boundary_hints,
        timeline,
        logs,
    })
}

/// Step (a)+(b): select a recommendation and review deterministic impact summary.
pub fn select_recommendation_for_review(
    surface: &OperatorSafetyCopilotSurface,
    identity: &OperatorIdentity,
    requested_rank: u32,
    selected_at_ns: u64,
) -> Result<ActionSelectionReview, CopilotError> {
    validate_operator_identity(identity)?;
    if !role_can_execute_actions(identity.role) {
        return Err(CopilotError::UnauthorizedRole {
            role: identity.role,
            action: "select_recommendation".to_string(),
        });
    }

    let selected_recommendation = recommendation_by_rank(surface, requested_rank)?;
    let impact_summary = ActionImpactSummary {
        dependent_extensions_affected: selected_recommendation.collateral_extensions,
        estimated_latency_ms: selected_recommendation.estimated_action_latency_ms,
        reversible: selected_recommendation.reversibility
            != RecommendationReversibility::Irreversible,
        rollback_window_ms_remaining: selected_recommendation.rollback_window_ms,
    };

    let context = format!(
        "rank={} action={} target={} collateral={} latency_ms={}",
        selected_recommendation.rank,
        selected_recommendation.action_type,
        selected_recommendation.target_extension,
        impact_summary.dependent_extensions_affected,
        impact_summary.estimated_latency_ms
    );

    let audit_event = OperatorAuditEvent {
        trace_id: surface.trace_id.clone(),
        decision_id: surface.decision_id.clone(),
        policy_id: surface.policy_id.clone(),
        operator_id: identity.operator_id.clone(),
        operator_role: identity.role,
        event: "copilot_action_selected".to_string(),
        outcome: "pending_confirmation".to_string(),
        context,
        timestamp_ns: selected_at_ns,
        error_code: None,
    };

    Ok(ActionSelectionReview {
        trace_id: surface.trace_id.clone(),
        decision_id: surface.decision_id.clone(),
        policy_id: surface.policy_id.clone(),
        incident_id: surface.incident_id.clone(),
        selected_rank: selected_recommendation.rank,
        selected_recommendation,
        impact_summary,
        selected_by: identity.clone(),
        selected_at_ns,
        audit_event,
    })
}

/// Step (c): confirm action execution with operator identity and token.
pub fn confirm_selected_recommendation(
    review: &ActionSelectionReview,
    identity: &OperatorIdentity,
    confirmation_token: &str,
    confirmed_at_ns: u64,
) -> Result<ConfirmedActionExecution, CopilotError> {
    validate_operator_identity(identity)?;
    if !role_can_execute_actions(identity.role) {
        return Err(CopilotError::UnauthorizedRole {
            role: identity.role,
            action: "confirm_recommendation".to_string(),
        });
    }
    if identity.operator_id != review.selected_by.operator_id {
        return Err(CopilotError::OperatorMismatch {
            selected_by: review.selected_by.operator_id.clone(),
            confirmed_by: identity.operator_id.clone(),
        });
    }
    if confirmation_token.trim().is_empty() {
        return Err(CopilotError::MissingConfirmationToken);
    }

    let confirmation_token_hash = deterministic_signature(&[confirmation_token.trim()]);
    let execution_command = build_execute_command(review, identity, &confirmation_token_hash);

    let signature = deterministic_signature(&[
        &review.trace_id,
        &review.decision_id,
        &review.policy_id,
        &review.incident_id,
        &review.selected_recommendation.action_type,
        &review.selected_recommendation.target_extension,
        &identity.operator_id,
        &confirmed_at_ns.to_string(),
        &confirmation_token_hash,
    ]);
    let receipt_id = format!("action-receipt-{signature}");

    let receipt = ActionExecutionReceipt {
        receipt_id,
        signature,
        trace_id: review.trace_id.clone(),
        decision_id: review.decision_id.clone(),
        policy_id: review.policy_id.clone(),
        incident_id: review.incident_id.clone(),
        action_type: review.selected_recommendation.action_type.clone(),
        target_extension: review.selected_recommendation.target_extension.clone(),
        operator_id: identity.operator_id.clone(),
        confirmed_at_ns,
        rollback_command: review
            .selected_recommendation
            .rollback_command
            .command
            .clone(),
    };

    let audit_event = OperatorAuditEvent {
        trace_id: review.trace_id.clone(),
        decision_id: review.decision_id.clone(),
        policy_id: review.policy_id.clone(),
        operator_id: identity.operator_id.clone(),
        operator_role: identity.role,
        event: "copilot_action_confirmed".to_string(),
        outcome: "executed".to_string(),
        context: format!(
            "rank={} action={} target={} token_hash={}",
            review.selected_rank,
            review.selected_recommendation.action_type,
            review.selected_recommendation.target_extension,
            confirmation_token_hash
        ),
        timestamp_ns: confirmed_at_ns,
        error_code: None,
    };

    let log_event = CopilotStructuredLogEvent {
        trace_id: review.trace_id.clone(),
        decision_id: review.decision_id.clone(),
        policy_id: review.policy_id.clone(),
        component: COPILOT_COMPONENT.to_string(),
        event: "copilot_action_confirmed".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };

    Ok(ConfirmedActionExecution {
        execution_command,
        rollback_command: review.selected_recommendation.rollback_command.clone(),
        receipt,
        audit_event,
        log_event,
    })
}

/// Build a deterministic rollback receipt linking rollback decision and evidence.
pub fn build_rollback_execution_receipt(
    input: &RollbackReceiptInput,
) -> Result<RollbackExecutionReceipt, CopilotError> {
    validate_non_empty("rollback.trace_id", &input.trace_id)?;
    validate_non_empty("rollback.decision_id", &input.decision_id)?;
    validate_non_empty("rollback.policy_id", &input.policy_id)?;
    validate_non_empty("rollback.action_receipt_id", &input.action_receipt_id)?;
    validate_non_empty("rollback.rollback_decision_id", &input.rollback_decision_id)?;
    validate_non_empty("rollback.evidence_pointer", &input.evidence_pointer)?;
    validate_non_empty(
        "rollback.restoration_verification",
        &input.restoration_verification,
    )?;

    let signature = deterministic_signature(&[
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
        &input.action_receipt_id,
        &input.rollback_decision_id,
        &input.evidence_pointer,
        &input.restoration_verification,
        &input.executed_at_ns.to_string(),
    ]);
    let receipt_id = format!("rollback-receipt-{signature}");

    Ok(RollbackExecutionReceipt {
        receipt_id,
        signature,
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        action_receipt_id: input.action_receipt_id.clone(),
        rollback_decision_id: input.rollback_decision_id.clone(),
        evidence_pointer: input.evidence_pointer.clone(),
        restoration_verification: input.restoration_verification.clone(),
        executed_at_ns: input.executed_at_ns,
    })
}

/// Build deterministic fleet-health aggregates for dashboard surfaces.
pub fn build_fleet_health_overview(
    extension_cards: &[ExtensionTrustCard],
    active_incidents: &[ActiveIncidentSummary],
    attacker_roi_trend_millionths: &[i64],
    recent_containment_actions: &[ContainmentActionOutcome],
) -> FleetHealthOverview {
    let mut high = 0u32;
    let mut guarded = 0u32;
    let mut watch = 0u32;
    let mut quarantined = 0u32;

    for card in extension_cards {
        match card.trust_level {
            ExtensionTrustLevel::High => high += 1,
            ExtensionTrustLevel::Guarded => guarded += 1,
            ExtensionTrustLevel::Watch => watch += 1,
            ExtensionTrustLevel::Quarantined => quarantined += 1,
        }
    }

    let trust_level_distribution = vec![
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::High,
            extensions: high,
        },
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::Guarded,
            extensions: guarded,
        },
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::Watch,
            extensions: watch,
        },
        TrustLevelDistributionEntry {
            trust_level: ExtensionTrustLevel::Quarantined,
            extensions: quarantined,
        },
    ];

    let mut incidents = active_incidents.to_vec();
    incidents.sort_by(|left, right| {
        left.started_at_ns
            .cmp(&right.started_at_ns)
            .then_with(|| left.incident_id.cmp(&right.incident_id))
            .then_with(|| left.extension_id.cmp(&right.extension_id))
    });
    let highest_severity = incidents
        .iter()
        .map(|incident| incident.severity)
        .max()
        .unwrap_or(IncidentSeverity::Low);

    let mut extension_details = extension_cards.to_vec();
    extension_details.sort_by(|left, right| {
        left.extension_id
            .cmp(&right.extension_id)
            .then_with(|| left.trust_level.cmp(&right.trust_level))
    });

    let mut containment = recent_containment_actions.to_vec();
    containment.sort_by(|left, right| {
        left.incident_id
            .cmp(&right.incident_id)
            .then_with(|| left.action_type.cmp(&right.action_type))
            .then_with(|| left.outcome.cmp(&right.outcome))
            .then_with(|| left.latency_ms.cmp(&right.latency_ms))
    });

    let active_incidents_count = u32::try_from(incidents.len()).unwrap_or(u32::MAX);

    FleetHealthOverview {
        trust_level_distribution,
        active_incidents: incidents,
        active_incidents_count,
        highest_severity,
        attacker_roi_trend_millionths: attacker_roi_trend_millionths.to_vec(),
        recent_containment_actions: containment,
        extension_details,
    }
}

/// Build deterministic policy-effectiveness metrics for dashboard surfaces.
pub fn build_policy_effectiveness_view(
    input: &PolicyEffectivenessInput,
) -> Result<PolicyEffectivenessView, CopilotError> {
    for value in &input.false_positive_rate_trend_millionths {
        validate_probability("policy.false_positive_rate_trend", *value)?;
    }

    let mut detection_rate_by_category = input
        .detection_counts
        .iter()
        .map(|entry| {
            validate_non_empty("policy.detection.category", &entry.category)?;
            let rate_millionths = if entry.total_events == 0 {
                0
            } else {
                let numerator = u128::from(entry.detected_events) * u128::from(MILLION as u64);
                let denominator = u128::from(entry.total_events);
                let ratio = numerator / denominator;
                match i64::try_from(ratio) {
                    Ok(value) => value,
                    Err(_) => MILLION,
                }
            };
            Ok(CategoryDetectionRate {
                category: entry.category.clone(),
                detected_events: entry.detected_events,
                total_events: entry.total_events,
                rate_millionths,
            })
        })
        .collect::<Result<Vec<_>, CopilotError>>()?;
    detection_rate_by_category.sort_by(|left, right| left.category.cmp(&right.category));

    let mut calibration_history = input.calibration_history.clone();
    for point in &calibration_history {
        validate_probability(
            "policy.calibration.expected_millionths",
            point.expected_millionths,
        )?;
        validate_probability(
            "policy.calibration.observed_millionths",
            point.observed_millionths,
        )?;
    }
    calibration_history.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then_with(|| left.expected_millionths.cmp(&right.expected_millionths))
            .then_with(|| left.observed_millionths.cmp(&right.observed_millionths))
    });

    let mut latencies = input.containment_latencies_ms.clone();
    latencies.sort_unstable();
    let containment_latency_p50_ms = percentile_ms(&latencies, 5_000);
    let containment_latency_p95_ms = percentile_ms(&latencies, 9_500);

    Ok(PolicyEffectivenessView {
        detection_rate_by_category,
        false_positive_rate_trend_millionths: input.false_positive_rate_trend_millionths.clone(),
        containment_latency_p50_ms,
        containment_latency_p95_ms,
        calibration_history,
    })
}

/// Render a deterministic text summary for CLI/TUI fallback output.
pub fn render_copilot_summary(surface: &OperatorSafetyCopilotSurface) -> String {
    let mut lines = Vec::new();
    lines.push(format!("trace_id: {}", surface.trace_id));
    lines.push(format!("decision_id: {}", surface.decision_id));
    lines.push(format!("policy_id: {}", surface.policy_id));
    lines.push(format!("incident_id: {}", surface.incident_id));
    lines.push(format!("read_only: {}", surface.read_only));
    lines.push(format!(
        "recommended_action: {} {}",
        surface.recommended_action.action_type, surface.recommended_action.target_extension
    ));
    lines.push(format!(
        "recommended_el_reduction: {}",
        format_millionths(
            surface
                .recommended_action
                .expected_loss_reduction_millionths
        )
    ));
    lines.push(format!(
        "recommended_confidence: {}",
        format_millionths(surface.recommended_action.confidence_millionths)
    ));
    lines.push(format!(
        "no_action_expected_loss: {}",
        format_millionths(surface.no_action_expected_loss_millionths)
    ));
    lines.push(format!(
        "evidence_strength: {} atoms / {}s",
        surface.evidence_strength.evidence_atoms,
        surface.evidence_strength.observation_window_seconds
    ));

    for hint in &surface.decision_boundary_hints {
        lines.push(format!(
            "decision_boundary:{} current={} threshold={} direction={:?} additional_evidence={}({})",
            hint.metric,
            format_millionths(hint.current_millionths),
            format_millionths(hint.threshold_millionths),
            hint.trigger_direction,
            hint.additional_evidence_needed,
            hint.evidence_type
        ));
    }

    for (idx, alternative) in surface.alternatives.iter().enumerate() {
        lines.push(format!(
            "alternative_{}: {} {} (el_reduction={}, confidence={}, collateral={}, latency_ms={})",
            idx + 1,
            alternative.action_type,
            alternative.target_extension,
            format_millionths(alternative.expected_loss_reduction_millionths),
            format_millionths(alternative.confidence_millionths),
            alternative.collateral_extensions,
            alternative.estimated_action_latency_ms,
        ));
    }
    for band in &surface.confidence_bands {
        lines.push(format!(
            "confidence_band:{}={} [{}..{}] @{}bps",
            band.metric,
            format_millionths(band.point_millionths),
            format_millionths(band.lower_millionths),
            format_millionths(band.upper_millionths),
            band.confidence_level_bps
        ));
    }
    lines.join("\n")
}

fn validate_input(input: &OperatorSafetyCopilotInput) -> Result<(), CopilotError> {
    validate_non_empty("trace_id", &input.trace_id)?;
    validate_non_empty("decision_id", &input.decision_id)?;
    validate_non_empty("policy_id", &input.policy_id)?;
    validate_non_empty("incident_id", &input.incident_id)?;

    if input.recommendations.is_empty() {
        return Err(CopilotError::MissingRecommendations);
    }

    if input.no_action_expected_loss_millionths < 0 {
        return Err(CopilotError::InvalidField {
            field: "no_action_expected_loss_millionths".to_string(),
        });
    }

    for candidate in &input.recommendations {
        validate_non_empty("recommendation.action_type", &candidate.action_type)?;
        validate_non_empty(
            "recommendation.target_extension",
            &candidate.target_extension,
        )?;
        validate_probability(
            "recommendation.confidence_millionths",
            candidate.confidence_millionths,
        )?;
        if candidate.expected_loss_reduction_millionths < 0 {
            return Err(CopilotError::InvalidField {
                field: "recommendation.expected_loss_reduction_millionths".to_string(),
            });
        }
        match candidate.reversibility {
            RecommendationReversibility::Reversible => {
                if candidate
                    .snapshot_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(CopilotError::MissingSnapshotForRollback {
                        action_type: candidate.action_type.clone(),
                        target_extension: candidate.target_extension.clone(),
                    });
                }
            }
            RecommendationReversibility::LimitedWindow => {
                if candidate
                    .snapshot_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(CopilotError::MissingSnapshotForRollback {
                        action_type: candidate.action_type.clone(),
                        target_extension: candidate.target_extension.clone(),
                    });
                }
                if candidate.rollback_window_ms.unwrap_or(0) == 0 {
                    return Err(CopilotError::InvalidRollbackWindow {
                        action_type: candidate.action_type.clone(),
                        target_extension: candidate.target_extension.clone(),
                    });
                }
            }
            RecommendationReversibility::Irreversible => {}
        }
    }

    for band in &input.confidence_bands {
        band.validate()?;
    }

    for hint in &input.decision_boundary_hints {
        hint.validate()?;
    }

    for event in &input.timeline {
        validate_non_empty("timeline.event_id", &event.event_id)?;
        validate_non_empty("timeline.event_type", &event.event_type)?;
        validate_non_empty("timeline.detail", &event.detail)?;
        validate_non_empty("timeline.outcome", &event.outcome)?;
    }

    Ok(())
}

fn validate_operator_identity(identity: &OperatorIdentity) -> Result<(), CopilotError> {
    validate_non_empty("operator.operator_id", &identity.operator_id)
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), CopilotError> {
    if value.trim().is_empty() {
        return Err(CopilotError::InvalidField {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn validate_probability(field: &str, value: i64) -> Result<(), CopilotError> {
    if !(0..=MILLION).contains(&value) {
        return Err(CopilotError::InvalidProbability {
            field: field.to_string(),
            value,
        });
    }
    Ok(())
}

fn role_can_execute_actions(role: OperatorRole) -> bool {
    matches!(role, OperatorRole::Operator | OperatorRole::Administrator)
}

fn recommendation_by_rank(
    surface: &OperatorSafetyCopilotSurface,
    requested_rank: u32,
) -> Result<RankedRecommendation, CopilotError> {
    if requested_rank == 1 {
        return Ok(surface.recommended_action.clone());
    }

    let available = u32::try_from(surface.alternatives.len() + 1).unwrap_or(u32::MAX);

    let idx_u32 = requested_rank.saturating_sub(2);
    let idx = match usize::try_from(idx_u32) {
        Ok(value) => value,
        Err(_) => {
            return Err(CopilotError::RecommendationRankOutOfRange {
                requested_rank,
                available,
            });
        }
    };

    surface
        .alternatives
        .get(idx)
        .cloned()
        .ok_or(CopilotError::RecommendationRankOutOfRange {
            requested_rank,
            available,
        })
}

fn recommendation_sort(
    left: &ActionRecommendationCandidate,
    right: &ActionRecommendationCandidate,
) -> Ordering {
    right
        .expected_loss_reduction_millionths
        .cmp(&left.expected_loss_reduction_millionths)
        .then_with(|| right.confidence_millionths.cmp(&left.confidence_millionths))
        .then_with(|| left.action_type.cmp(&right.action_type))
        .then_with(|| left.target_extension.cmp(&right.target_extension))
}

fn build_rollback_command(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    candidate: &ActionRecommendationCandidate,
) -> RollbackCommand {
    let action_token = canonical_action_token(&candidate.action_type);
    let extension = candidate.target_extension.trim();
    match candidate.reversibility {
        RecommendationReversibility::Reversible => {
            let snapshot = candidate.snapshot_id.as_deref().unwrap_or("unknown");
            RollbackCommand {
                command: format!(
                    "rollback {action_token} --extension {extension} --snapshot-id {snapshot} --trace-id {trace_id} --decision-id {decision_id} --policy-id {policy_id} --verify"
                ),
                safety_summary: format!(
                    "snapshot={snapshot}; dependent_extensions={}; estimated_latency_ms={}",
                    candidate.collateral_extensions, candidate.estimated_action_latency_ms
                ),
            }
        }
        RecommendationReversibility::LimitedWindow => {
            let snapshot = candidate.snapshot_id.as_deref().unwrap_or("unknown");
            let window_ms = candidate.rollback_window_ms.unwrap_or(0);
            RollbackCommand {
                command: format!(
                    "rollback {action_token} --extension {extension} --snapshot-id {snapshot} --trace-id {trace_id} --decision-id {decision_id} --policy-id {policy_id} --window-ms {window_ms} --verify"
                ),
                safety_summary: format!(
                    "snapshot={snapshot}; dependent_extensions={}; estimated_latency_ms={}; window_ms_remaining={window_ms}",
                    candidate.collateral_extensions, candidate.estimated_action_latency_ms,
                ),
            }
        }
        RecommendationReversibility::Irreversible => RollbackCommand {
            command: format!(
                "rollback mark-irreversible --action {action_token} --extension {extension} --trace-id {trace_id} --decision-id {decision_id} --policy-id {policy_id} --acknowledge"
            ),
            safety_summary: format!(
                "irreversible action; dependent_extensions={}; estimated_latency_ms={}",
                candidate.collateral_extensions, candidate.estimated_action_latency_ms
            ),
        },
    }
}

fn build_execute_command(
    review: &ActionSelectionReview,
    identity: &OperatorIdentity,
    confirmation_token_hash: &str,
) -> String {
    let action_token = canonical_action_token(&review.selected_recommendation.action_type);
    format!(
        "execute {action_token} --extension {} --incident-id {} --trace-id {} --decision-id {} --policy-id {} --confirmed-by {} --confirmation-token-hash {}",
        review.selected_recommendation.target_extension,
        review.incident_id,
        review.trace_id,
        review.decision_id,
        review.policy_id,
        identity.operator_id,
        confirmation_token_hash
    )
}

fn deterministic_signature(parts: &[&str]) -> String {
    let mut hash = FNV_OFFSET_BASIS;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

fn canonical_action_token(action: &str) -> String {
    let mut out = String::new();
    let mut previous_was_dash = false;
    for ch in action.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_was_dash = false;
        } else if !previous_was_dash {
            out.push('-');
            previous_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unknown-action".to_string()
    } else {
        out
    }
}

fn recommendation_explanation(candidate: &ActionRecommendationCandidate) -> String {
    format!(
        "Recommended: {} {} because expected loss reduction={} and confidence={}",
        candidate.action_type,
        candidate.target_extension,
        format_millionths(candidate.expected_loss_reduction_millionths),
        format_millionths(candidate.confidence_millionths)
    )
}

fn percentile_ms(sorted_values: &[u64], percentile_bps: u16) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let n_minus_one = sorted_values.len() - 1;
    let rank = (n_minus_one as u128 * u128::from(percentile_bps)).div_ceil(10_000);
    let index = match usize::try_from(rank) {
        Ok(value) => value,
        Err(_) => sorted_values.len() - 1,
    };
    sorted_values[index]
}

fn format_millionths(value: i64) -> String {
    let sign = if value < 0 { "-" } else { "" };
    let abs = value.abs();
    let whole = abs / MILLION;
    let fractional = abs % MILLION;
    format!("{sign}{whole}.{fractional:06}")
}
