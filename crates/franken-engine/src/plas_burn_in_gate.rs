//! Deterministic burn-in promotion gate for PLAS synthesized policies.
//!
//! Enforces shadow success-rate, false-deny envelope, and rollback-proof
//! artifact checks before allowing auto-enforcement promotion.
//!
//! Plan reference: Section 10.15 item 13 (`bd-24ie`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_witness::RollbackToken;
use crate::hash_tiers::ContentHash;

const PLAS_BURN_IN_COMPONENT: &str = "plas_burn_in_gate";

/// Extension risk class used to select default threshold strictness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRiskClass {
    Low,
    Standard,
    High,
}

impl ExtensionRiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Standard => "standard",
            Self::High => "high",
        }
    }
}

impl fmt::Display for ExtensionRiskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Burn-in thresholds that must be satisfied for promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInThresholds {
    /// Minimum shadow success rate (millionths).
    pub min_shadow_success_millionths: u64,
    /// Maximum false-deny rate (millionths).
    pub max_false_deny_millionths: u64,
    /// Minimum shadow burn-in duration in nanoseconds.
    pub min_shadow_duration_ns: u64,
    /// Minimum number of shadow observations before gate evaluation.
    pub min_shadow_observations: u64,
}

impl BurnInThresholds {
    /// Default strictness by extension risk class.
    pub fn for_risk_class(risk_class: ExtensionRiskClass) -> Self {
        match risk_class {
            ExtensionRiskClass::Low => Self {
                min_shadow_success_millionths: 992_000,
                max_false_deny_millionths: 8_000,
                min_shadow_duration_ns: 60_000_000_000,
                min_shadow_observations: 100,
            },
            ExtensionRiskClass::Standard => Self {
                min_shadow_success_millionths: 995_000,
                max_false_deny_millionths: 5_000,
                min_shadow_duration_ns: 180_000_000_000,
                min_shadow_observations: 250,
            },
            ExtensionRiskClass::High => Self {
                min_shadow_success_millionths: 998_000,
                max_false_deny_millionths: 2_000,
                min_shadow_duration_ns: 300_000_000_000,
                min_shadow_observations: 500,
            },
        }
    }

    fn validate(&self) -> Result<(), BurnInError> {
        if self.min_shadow_success_millionths > 1_000_000 {
            return Err(BurnInError::InvalidConfig {
                detail: "min_shadow_success_millionths must be <= 1_000_000".to_string(),
            });
        }
        if self.max_false_deny_millionths > 1_000_000 {
            return Err(BurnInError::InvalidConfig {
                detail: "max_false_deny_millionths must be <= 1_000_000".to_string(),
            });
        }
        if self.min_shadow_duration_ns == 0 {
            return Err(BurnInError::InvalidConfig {
                detail: "min_shadow_duration_ns must be > 0".to_string(),
            });
        }
        if self.min_shadow_observations == 0 {
            return Err(BurnInError::InvalidConfig {
                detail: "min_shadow_observations must be > 0".to_string(),
            });
        }
        Ok(())
    }
}

/// Shadow-mode lifecycle for a synthesized policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnInLifecycleState {
    ShadowStart,
    ShadowEvaluation,
    PromotionGate,
    AutoEnforcement,
    Rejection,
}

impl BurnInLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShadowStart => "shadow_start",
            Self::ShadowEvaluation => "shadow_evaluation",
            Self::PromotionGate => "promotion_gate",
            Self::AutoEnforcement => "auto_enforcement",
            Self::Rejection => "rejection",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::AutoEnforcement | Self::Rejection)
    }
}

impl fmt::Display for BurnInLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure taxonomy for burn-in decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnInFailureCode {
    EarlyTerminationFalseDeny,
    InsufficientShadowDuration,
    InsufficientShadowObservations,
    ShadowSuccessRateBelowThreshold,
    FalseDenyEnvelopeExceeded,
    RollbackProofArtifactsMissing,
}

impl BurnInFailureCode {
    pub fn error_code(self) -> &'static str {
        match self {
            Self::EarlyTerminationFalseDeny => "early_termination_false_deny",
            Self::InsufficientShadowDuration => "insufficient_shadow_duration",
            Self::InsufficientShadowObservations => "insufficient_shadow_observations",
            Self::ShadowSuccessRateBelowThreshold => "shadow_success_rate_below_threshold",
            Self::FalseDenyEnvelopeExceeded => "false_deny_envelope_exceeded",
            Self::RollbackProofArtifactsMissing => "rollback_proof_artifacts_missing",
        }
    }
}

impl fmt::Display for BurnInFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error_code())
    }
}

/// Rollback artifacts required for safe fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RollbackProofArtifacts {
    /// Whether the rollback command has been exercised successfully.
    pub rollback_command_tested: bool,
    /// Reference to a previous policy snapshot artifact.
    pub previous_policy_snapshot_ref: Option<String>,
    /// Whether the transition receipt is signed and verified.
    pub transition_receipt_signed: bool,
    /// Reference to transition receipt artifact.
    pub transition_receipt_ref: Option<String>,
    /// Deterministic rollback token linking to prior witness version.
    pub rollback_token: Option<RollbackToken>,
}

impl RollbackProofArtifacts {
    fn normalize(&mut self) {
        self.previous_policy_snapshot_ref = self
            .previous_policy_snapshot_ref
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.transition_receipt_ref = self
            .transition_receipt_ref
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
    }

    pub fn is_complete(&self) -> bool {
        self.rollback_command_tested
            && self.transition_receipt_signed
            && self.previous_policy_snapshot_ref.is_some()
            && self.transition_receipt_ref.is_some()
            && self.rollback_token.is_some()
    }
}

/// One shadow observation used in burn-in evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowObservation {
    pub observation_id: String,
    pub timestamp_ns: u64,
    pub success: bool,
    pub false_deny: bool,
}

impl ShadowObservation {
    fn normalize(&mut self) {
        self.observation_id = self.observation_id.trim().to_string();
    }

    fn validate(&self) -> Result<(), BurnInError> {
        if self.observation_id.is_empty() {
            return Err(BurnInError::InvalidObservation {
                detail: "observation_id must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Aggregated shadow metrics used by promotion decision logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInMetrics {
    pub started_at_ns: u64,
    pub latest_timestamp_ns: u64,
    pub total_observations: u64,
    pub successful_observations: u64,
    pub false_denies: u64,
}

impl BurnInMetrics {
    fn new(started_at_ns: u64) -> Self {
        Self {
            started_at_ns,
            latest_timestamp_ns: started_at_ns,
            total_observations: 0,
            successful_observations: 0,
            false_denies: 0,
        }
    }

    pub fn elapsed_ns(&self) -> u64 {
        self.latest_timestamp_ns.saturating_sub(self.started_at_ns)
    }

    pub fn shadow_success_rate_millionths(&self) -> u64 {
        if self.total_observations == 0 {
            return 0;
        }
        self.successful_observations
            .saturating_mul(1_000_000)
            .saturating_div(self.total_observations)
    }

    pub fn false_deny_rate_millionths(&self) -> u64 {
        if self.total_observations == 0 {
            return 0;
        }
        self.false_denies
            .saturating_mul(1_000_000)
            .saturating_div(self.total_observations)
    }
}

/// Configuration for a burn-in session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInSessionConfig {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub risk_class: ExtensionRiskClass,
    pub thresholds: BurnInThresholds,
    pub shadow_start_timestamp_ns: u64,
}

impl BurnInSessionConfig {
    fn normalize(&mut self) {
        self.trace_id = self.trace_id.trim().to_string();
        self.decision_id = self.decision_id.trim().to_string();
        self.policy_id = self.policy_id.trim().to_string();
        self.extension_id = self.extension_id.trim().to_string();
    }

    fn validate(&self) -> Result<(), BurnInError> {
        if self.trace_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.extension_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "extension_id must not be empty".to_string(),
            });
        }
        self.thresholds.validate()?;
        Ok(())
    }
}

/// Structured log event with stable keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub lifecycle_state: BurnInLifecycleState,
}

/// Deterministic decision artifact produced on promotion-gate or early termination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInDecisionArtifact {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub risk_class: ExtensionRiskClass,
    pub lifecycle_state: BurnInLifecycleState,
    pub outcome: String,
    pub failure_codes: Vec<BurnInFailureCode>,
    pub metrics: BurnInMetrics,
    pub thresholds: BurnInThresholds,
    pub rollback_artifacts_verified: bool,
    pub diagnostic_report: Option<String>,
    pub decision_hash: ContentHash,
}

/// Snapshot for PLAS benchmark/governance scorecards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInScorecardMetrics {
    pub shadow_success_rate_millionths: u64,
    pub false_deny_rate_millionths: u64,
    pub rollback_artifacts_verified: bool,
    pub lifecycle_state: BurnInLifecycleState,
}

/// Burn-in gate errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BurnInError {
    InvalidConfig {
        detail: String,
    },
    InvalidObservation {
        detail: String,
    },
    InvalidTransition {
        from: BurnInLifecycleState,
        to: BurnInLifecycleState,
    },
    NonMonotonicTimestamp {
        previous_ns: u64,
        observed_ns: u64,
    },
}

impl fmt::Display for BurnInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { detail } => write!(f, "invalid burn-in config: {detail}"),
            Self::InvalidObservation { detail } => {
                write!(f, "invalid burn-in observation: {detail}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid burn-in lifecycle transition: {from} -> {to}")
            }
            Self::NonMonotonicTimestamp {
                previous_ns,
                observed_ns,
            } => {
                write!(
                    f,
                    "non-monotonic timestamp: previous={previous_ns}, observed={observed_ns}"
                )
            }
        }
    }
}

impl std::error::Error for BurnInError {}

/// Stateful deterministic burn-in evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInSession {
    config: BurnInSessionConfig,
    rollback_artifacts: RollbackProofArtifacts,
    lifecycle_state: BurnInLifecycleState,
    metrics: BurnInMetrics,
    logs: Vec<BurnInLogEvent>,
    decision_artifact: Option<BurnInDecisionArtifact>,
}

impl BurnInSession {
    /// Create a new burn-in session at `shadow_start`.
    pub fn new(
        mut config: BurnInSessionConfig,
        mut rollback_artifacts: RollbackProofArtifacts,
    ) -> Result<Self, BurnInError> {
        config.normalize();
        config.validate()?;
        rollback_artifacts.normalize();

        let initial_state = BurnInLifecycleState::ShadowStart;
        let mut session = Self {
            metrics: BurnInMetrics::new(config.shadow_start_timestamp_ns),
            config,
            rollback_artifacts,
            lifecycle_state: initial_state,
            logs: Vec::new(),
            decision_artifact: None,
        };
        session.push_log("shadow_start", "pass", None, initial_state);
        Ok(session)
    }

    /// Transition from `shadow_start` to `shadow_evaluation`.
    pub fn begin_shadow_evaluation(&mut self) -> Result<(), BurnInError> {
        self.transition_to(BurnInLifecycleState::ShadowEvaluation)?;
        self.push_log(
            "shadow_evaluation",
            "pass",
            None,
            BurnInLifecycleState::ShadowEvaluation,
        );
        Ok(())
    }

    /// Record one shadow observation.
    ///
    /// Returns a decision artifact when early termination triggers.
    pub fn record_shadow_observation(
        &mut self,
        mut observation: ShadowObservation,
    ) -> Result<Option<BurnInDecisionArtifact>, BurnInError> {
        if self.lifecycle_state != BurnInLifecycleState::ShadowEvaluation {
            return Err(BurnInError::InvalidTransition {
                from: self.lifecycle_state,
                to: BurnInLifecycleState::ShadowEvaluation,
            });
        }

        observation.normalize();
        observation.validate()?;

        if observation.timestamp_ns < self.metrics.latest_timestamp_ns {
            return Err(BurnInError::NonMonotonicTimestamp {
                previous_ns: self.metrics.latest_timestamp_ns,
                observed_ns: observation.timestamp_ns,
            });
        }

        self.metrics.latest_timestamp_ns = observation.timestamp_ns;
        self.metrics.total_observations = self.metrics.total_observations.saturating_add(1);
        if observation.success {
            self.metrics.successful_observations =
                self.metrics.successful_observations.saturating_add(1);
        }
        if observation.false_deny {
            self.metrics.false_denies = self.metrics.false_denies.saturating_add(1);
        }

        self.push_log(
            "shadow_observation_recorded",
            "pass",
            None,
            BurnInLifecycleState::ShadowEvaluation,
        );

        if self.metrics.false_deny_rate_millionths()
            > self.config.thresholds.max_false_deny_millionths
        {
            self.transition_to(BurnInLifecycleState::Rejection)?;
            let failure_codes = vec![BurnInFailureCode::EarlyTerminationFalseDeny];
            let artifact = self.build_decision_artifact(
                BurnInLifecycleState::Rejection,
                &failure_codes,
                Some(
                    "false-deny envelope exceeded during shadow evaluation; early termination"
                        .to_string(),
                ),
            );
            self.decision_artifact = Some(artifact.clone());
            self.push_log(
                "shadow_evaluation",
                "fail",
                Some(BurnInFailureCode::EarlyTerminationFalseDeny),
                BurnInLifecycleState::Rejection,
            );
            return Ok(Some(artifact));
        }

        Ok(None)
    }

    /// Execute the promotion gate and transition to terminal state.
    pub fn evaluate_promotion_gate(
        &mut self,
        evaluation_timestamp_ns: u64,
    ) -> Result<BurnInDecisionArtifact, BurnInError> {
        if self.lifecycle_state != BurnInLifecycleState::ShadowEvaluation {
            return Err(BurnInError::InvalidTransition {
                from: self.lifecycle_state,
                to: BurnInLifecycleState::PromotionGate,
            });
        }
        if evaluation_timestamp_ns < self.metrics.latest_timestamp_ns {
            return Err(BurnInError::NonMonotonicTimestamp {
                previous_ns: self.metrics.latest_timestamp_ns,
                observed_ns: evaluation_timestamp_ns,
            });
        }

        self.metrics.latest_timestamp_ns = evaluation_timestamp_ns;
        self.transition_to(BurnInLifecycleState::PromotionGate)?;

        let mut failure_codes = Vec::new();
        if self.metrics.elapsed_ns() < self.config.thresholds.min_shadow_duration_ns {
            failure_codes.push(BurnInFailureCode::InsufficientShadowDuration);
        }
        if self.metrics.total_observations < self.config.thresholds.min_shadow_observations {
            failure_codes.push(BurnInFailureCode::InsufficientShadowObservations);
        }
        if self.metrics.shadow_success_rate_millionths()
            < self.config.thresholds.min_shadow_success_millionths
        {
            failure_codes.push(BurnInFailureCode::ShadowSuccessRateBelowThreshold);
        }
        if self.metrics.false_deny_rate_millionths()
            > self.config.thresholds.max_false_deny_millionths
        {
            failure_codes.push(BurnInFailureCode::FalseDenyEnvelopeExceeded);
        }
        if !self.rollback_artifacts.is_complete() {
            failure_codes.push(BurnInFailureCode::RollbackProofArtifactsMissing);
        }
        failure_codes.sort();
        failure_codes.dedup();

        let final_state = if failure_codes.is_empty() {
            BurnInLifecycleState::AutoEnforcement
        } else {
            BurnInLifecycleState::Rejection
        };
        self.transition_to(final_state)?;

        let artifact = self.build_decision_artifact(final_state, &failure_codes, None);
        self.decision_artifact = Some(artifact.clone());

        self.push_log(
            "promotion_gate",
            if failure_codes.is_empty() {
                "pass"
            } else {
                "fail"
            },
            failure_codes.first().copied(),
            final_state,
        );

        Ok(artifact)
    }

    pub fn lifecycle_state(&self) -> BurnInLifecycleState {
        self.lifecycle_state
    }

    pub fn metrics(&self) -> &BurnInMetrics {
        &self.metrics
    }

    pub fn logs(&self) -> &[BurnInLogEvent] {
        &self.logs
    }

    pub fn decision_artifact(&self) -> Option<&BurnInDecisionArtifact> {
        self.decision_artifact.as_ref()
    }

    pub fn scorecard_metrics(&self) -> BurnInScorecardMetrics {
        BurnInScorecardMetrics {
            shadow_success_rate_millionths: self.metrics.shadow_success_rate_millionths(),
            false_deny_rate_millionths: self.metrics.false_deny_rate_millionths(),
            rollback_artifacts_verified: self.rollback_artifacts.is_complete(),
            lifecycle_state: self.lifecycle_state,
        }
    }

    fn transition_to(&mut self, to: BurnInLifecycleState) -> Result<(), BurnInError> {
        let from = self.lifecycle_state;
        let valid = matches!(
            (from, to),
            (
                BurnInLifecycleState::ShadowStart,
                BurnInLifecycleState::ShadowEvaluation
            ) | (
                BurnInLifecycleState::ShadowEvaluation,
                BurnInLifecycleState::PromotionGate
            ) | (
                BurnInLifecycleState::ShadowEvaluation,
                BurnInLifecycleState::Rejection
            ) | (
                BurnInLifecycleState::PromotionGate,
                BurnInLifecycleState::AutoEnforcement
            ) | (
                BurnInLifecycleState::PromotionGate,
                BurnInLifecycleState::Rejection
            )
        );
        if !valid {
            return Err(BurnInError::InvalidTransition { from, to });
        }
        self.lifecycle_state = to;
        Ok(())
    }

    fn build_decision_artifact(
        &self,
        lifecycle_state: BurnInLifecycleState,
        failure_codes: &[BurnInFailureCode],
        diagnostic_report: Option<String>,
    ) -> BurnInDecisionArtifact {
        let outcome = if failure_codes.is_empty() {
            "pass".to_string()
        } else {
            "fail".to_string()
        };

        let mut unsigned = Vec::new();
        unsigned.extend_from_slice(self.config.trace_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(self.config.decision_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(self.config.policy_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(self.config.extension_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(lifecycle_state.as_str().as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(outcome.as_bytes());
        unsigned.push(b'|');
        for code in failure_codes {
            unsigned.extend_from_slice(code.error_code().as_bytes());
            unsigned.push(b',');
        }
        unsigned.push(b'|');
        unsigned.extend_from_slice(&self.metrics.total_observations.to_be_bytes());
        unsigned.extend_from_slice(&self.metrics.successful_observations.to_be_bytes());
        unsigned.extend_from_slice(&self.metrics.false_denies.to_be_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(&self.metrics.shadow_success_rate_millionths().to_be_bytes());
        unsigned.extend_from_slice(&self.metrics.false_deny_rate_millionths().to_be_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(
            &self
                .config
                .thresholds
                .min_shadow_success_millionths
                .to_be_bytes(),
        );
        unsigned.extend_from_slice(
            &self
                .config
                .thresholds
                .max_false_deny_millionths
                .to_be_bytes(),
        );
        unsigned.extend_from_slice(&self.config.thresholds.min_shadow_duration_ns.to_be_bytes());
        unsigned.extend_from_slice(&self.config.thresholds.min_shadow_observations.to_be_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(if self.rollback_artifacts.is_complete() {
            b"rollback_complete"
        } else {
            b"rollback_incomplete"
        });
        if let Some(report) = &diagnostic_report {
            unsigned.push(b'|');
            unsigned.extend_from_slice(report.as_bytes());
        }

        BurnInDecisionArtifact {
            trace_id: self.config.trace_id.clone(),
            decision_id: self.config.decision_id.clone(),
            policy_id: self.config.policy_id.clone(),
            extension_id: self.config.extension_id.clone(),
            risk_class: self.config.risk_class,
            lifecycle_state,
            outcome,
            failure_codes: failure_codes.to_vec(),
            metrics: self.metrics.clone(),
            thresholds: self.config.thresholds.clone(),
            rollback_artifacts_verified: self.rollback_artifacts.is_complete(),
            diagnostic_report,
            decision_hash: ContentHash::compute(&unsigned),
        }
    }

    fn push_log(
        &mut self,
        event: &str,
        outcome: &str,
        error_code: Option<BurnInFailureCode>,
        lifecycle_state: BurnInLifecycleState,
    ) {
        self.logs.push(BurnInLogEvent {
            trace_id: self.config.trace_id.clone(),
            decision_id: self.config.decision_id.clone(),
            policy_id: self.config.policy_id.clone(),
            component: PLAS_BURN_IN_COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|code| code.error_code().to_string()),
            lifecycle_state,
        });
    }
}
