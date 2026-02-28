//! Catastrophic-tail adversarial tournament and release-gate integration.
//!
//! Operationalizes catastrophic-tail adversarial evaluation as a release blocker,
//! computing tail-risk metrics (CVaR, EVT-style e-value alarms) per release candidate
//! and producing signed gate decisions referencing tournament evidence.
//!
//! Plan reference: FRX-18.4

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::adversarial_coevolution_harness::TournamentResult;
use crate::hash_tiers::ContentHash;
use crate::runtime_decision_theory::{DemotionReason, LaneAction, LaneId};
use crate::security_epoch::SecurityEpoch;

// ── Constants ────────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for tail-tournament gate artifacts.
pub const TAIL_GATE_SCHEMA_VERSION: &str = "franken-engine.catastrophic-tail-tournament-gate.v1";

/// Maximum number of threat classes.
const MAX_THREAT_CLASSES: usize = 64;

/// Maximum number of campaigns per evaluation.
const MAX_CAMPAIGNS: usize = 128;

/// Maximum number of round outcomes retained for tail analysis.
const MAX_TAIL_OBSERVATIONS: usize = 100_000;

/// Default CVaR alpha (95th percentile of losses, millionths).
const DEFAULT_CVAR_ALPHA_MILLIONTHS: i64 = 950_000;

/// Default tail budget (maximum acceptable CVaR, millionths).
const DEFAULT_TAIL_BUDGET_MILLIONTHS: i64 = 500_000;

/// Default e-value threshold for alarm (millionths).
const DEFAULT_E_VALUE_ALARM_MILLIONTHS: i64 = 20_000_000; // 20x

/// Default minimum rounds per campaign for valid tail statistics.
const DEFAULT_MIN_ROUNDS: u64 = 100;

// ── Threat Class ────────────────────────────────────────────────────────

/// A high-impact threat class for tail-risk evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatClass {
    /// Unique identifier.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Category of threat.
    pub category: ThreatCategory,
    /// Impact weight (millionths). Higher = more impact on gate decisions.
    pub impact_weight_millionths: i64,
    /// Related exploit classes from adversarial harness.
    pub related_exploits: BTreeSet<String>,
}

impl fmt::Display for ThreatClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "threat({}, {}, weight={})",
            self.id, self.category, self.impact_weight_millionths
        )
    }
}

/// Category of threat class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// Capability escalation threats.
    CapabilityEscalation,
    /// Resource exhaustion / DoS.
    ResourceExhaustion,
    /// Information leakage.
    InformationLeakage,
    /// Policy bypass / evasion.
    PolicyBypass,
    /// Supply chain / provenance.
    SupplyChain,
    /// Timing / side-channel.
    TimingChannel,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityEscalation => write!(f, "capability-escalation"),
            Self::ResourceExhaustion => write!(f, "resource-exhaustion"),
            Self::InformationLeakage => write!(f, "information-leakage"),
            Self::PolicyBypass => write!(f, "policy-bypass"),
            Self::SupplyChain => write!(f, "supply-chain"),
            Self::TimingChannel => write!(f, "timing-channel"),
        }
    }
}

// ── Campaign ────────────────────────────────────────────────────────────

/// A worst-case tournament campaign run for a specific threat class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campaign {
    /// Campaign identifier.
    pub campaign_id: String,
    /// Threat class this campaign targets.
    pub threat_class_id: String,
    /// Tournament result from the adversarial harness.
    pub tournament_result: TournamentResult,
    /// Attacker payoff observations used for tail analysis.
    pub attacker_payoffs: Vec<i64>,
}

impl Campaign {
    /// Number of rounds in this campaign.
    pub fn round_count(&self) -> u64 {
        self.tournament_result.rounds_played
    }
}

// ── Tail Risk Metrics ───────────────────────────────────────────────────

/// Tail-risk metrics computed from tournament campaigns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskMetrics {
    /// Threat class ID these metrics apply to.
    pub threat_class_id: String,
    /// Number of observations used.
    pub observation_count: u64,
    /// Value-at-Risk at alpha quantile (millionths).
    pub var_millionths: i64,
    /// Conditional Value-at-Risk (expected tail loss, millionths).
    pub cvar_millionths: i64,
    /// CVaR alpha quantile used (millionths).
    pub alpha_millionths: i64,
    /// E-value alarm statistic (millionths). Above threshold = alarm.
    pub e_value_millionths: i64,
    /// Whether the e-value alarm is active.
    pub alarm_active: bool,
    /// Maximum single-round attacker payoff observed (millionths).
    pub max_payoff_millionths: i64,
    /// Worst exploit class observed, if any.
    pub worst_exploit: Option<String>,
}

impl TailRiskMetrics {
    /// Whether CVaR exceeds the budget.
    pub fn exceeds_budget(&self, budget: i64) -> bool {
        self.cvar_millionths > budget
    }
}

impl fmt::Display for TailRiskMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tail-risk({}, cvar={}, e-value={}, alarm={})",
            self.threat_class_id, self.cvar_millionths, self.e_value_millionths, self.alarm_active
        )
    }
}

// ── Gate Decision ───────────────────────────────────────────────────────

/// Gate decision for a release candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecision {
    /// Decision ID.
    pub decision_id: String,
    /// Release candidate identifier.
    pub release_candidate_id: String,
    /// Verdict.
    pub verdict: GateVerdict,
    /// Epoch of evaluation.
    pub epoch: SecurityEpoch,
    /// Per-threat-class risk metrics.
    pub risk_metrics: Vec<TailRiskMetrics>,
    /// Aggregate tail risk (weighted CVaR across threat classes, millionths).
    pub aggregate_cvar_millionths: i64,
    /// Aggregate e-value alarm (any active = true).
    pub any_alarm_active: bool,
    /// Campaigns evaluated.
    pub campaigns_evaluated: u64,
    /// Total rounds across all campaigns.
    pub total_rounds: u64,
    /// Rollback playbook if tail budget exceeded.
    pub rollback_playbook: Option<RollbackPlaybook>,
    /// Rationale for the decision.
    pub rationale: String,
    /// Artifact hash.
    pub artifact_hash: ContentHash,
}

impl GateDecision {
    /// Whether the release candidate passes the gate.
    pub fn is_pass(&self) -> bool {
        self.verdict == GateVerdict::Pass
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gate({}, {}, cvar={}, campaigns={})",
            self.release_candidate_id,
            self.verdict,
            self.aggregate_cvar_millionths,
            self.campaigns_evaluated
        )
    }
}

/// Verdict of a gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Release candidate passes — tail risk within budget.
    Pass,
    /// Release candidate fails — tail budget exceeded.
    Fail,
    /// Insufficient data — need more campaigns.
    Inconclusive,
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

// ── Rollback Playbook ───────────────────────────────────────────────────

/// Deterministic rollback playbook for failed release candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlaybook {
    /// Playbook identifier.
    pub playbook_id: String,
    /// Lane action to apply for rollback.
    pub rollback_action: LaneAction,
    /// Threat classes that triggered rollback.
    pub triggering_threats: Vec<String>,
    /// Recommended mitigation steps (ordered).
    pub mitigation_steps: Vec<MitigationStep>,
    /// Evidence hash linking to the gate decision.
    pub evidence_hash: ContentHash,
}

impl fmt::Display for RollbackPlaybook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "playbook({}, triggers={}, steps={})",
            self.playbook_id,
            self.triggering_threats.len(),
            self.mitigation_steps.len()
        )
    }
}

/// A step in a rollback mitigation playbook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationStep {
    /// Step number (1-indexed).
    pub step: u32,
    /// Description of the mitigation.
    pub description: String,
    /// Whether this step is automated or manual.
    pub automated: bool,
    /// Lane action for this step, if applicable.
    pub action: Option<LaneAction>,
}

// ── Risk Ledger ─────────────────────────────────────────────────────────

/// Per-release-candidate risk ledger tracking tail-risk history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskLedgerEntry {
    /// Epoch of the entry.
    pub epoch: SecurityEpoch,
    /// Threat class ID.
    pub threat_class_id: String,
    /// CVaR at this evaluation.
    pub cvar_millionths: i64,
    /// E-value at this evaluation.
    pub e_value_millionths: i64,
    /// Whether the tail budget was exceeded.
    pub budget_exceeded: bool,
}

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the catastrophic-tail tournament gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailGateConfig {
    /// Epoch for evaluation.
    pub epoch: SecurityEpoch,
    /// CVaR alpha (quantile, millionths). 950_000 = 95th percentile.
    pub cvar_alpha_millionths: i64,
    /// Maximum acceptable CVaR (tail budget, millionths).
    pub tail_budget_millionths: i64,
    /// E-value threshold for alarm (millionths).
    pub e_value_alarm_threshold_millionths: i64,
    /// Minimum rounds per campaign.
    pub min_rounds_per_campaign: u64,
    /// Whether to generate rollback playbooks for failed candidates.
    pub generate_rollback_playbook: bool,
    /// Lane for rollback routing.
    pub rollback_lane: LaneId,
    /// Whether to record per-campaign risk ledger entries.
    pub record_risk_ledger: bool,
}

impl Default for TailGateConfig {
    fn default() -> Self {
        Self {
            epoch: SecurityEpoch::from_raw(1),
            cvar_alpha_millionths: DEFAULT_CVAR_ALPHA_MILLIONTHS,
            tail_budget_millionths: DEFAULT_TAIL_BUDGET_MILLIONTHS,
            e_value_alarm_threshold_millionths: DEFAULT_E_VALUE_ALARM_MILLIONTHS,
            min_rounds_per_campaign: DEFAULT_MIN_ROUNDS,
            generate_rollback_playbook: true,
            rollback_lane: LaneId("safe".to_string()),
            record_risk_ledger: true,
        }
    }
}

// ── Error ───────────────────────────────────────────────────────────────

/// Errors from the tail-tournament gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TailGateError {
    /// No threat classes defined.
    NoThreatClasses,
    /// Too many threat classes.
    TooManyThreatClasses { count: usize, max: usize },
    /// No campaigns provided.
    NoCampaigns,
    /// Too many campaigns.
    TooManyCampaigns { count: usize, max: usize },
    /// Campaign references unknown threat class.
    UnknownThreatClass {
        campaign_id: String,
        threat_class_id: String,
    },
    /// Duplicate threat class ID.
    DuplicateThreatClass { id: String },
    /// Insufficient rounds in campaign.
    InsufficientRounds {
        campaign_id: String,
        rounds: u64,
        required: u64,
    },
    /// Invalid configuration.
    InvalidConfig { detail: String },
    /// Too many observations for tail analysis.
    TooManyObservations { count: usize, max: usize },
}

impl fmt::Display for TailGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoThreatClasses => write!(f, "no threat classes defined"),
            Self::TooManyThreatClasses { count, max } => {
                write!(f, "too many threat classes: {} exceeds max {}", count, max)
            }
            Self::NoCampaigns => write!(f, "no campaigns provided"),
            Self::TooManyCampaigns { count, max } => {
                write!(f, "too many campaigns: {} exceeds max {}", count, max)
            }
            Self::UnknownThreatClass {
                campaign_id,
                threat_class_id,
            } => {
                write!(
                    f,
                    "campaign {} references unknown threat class {}",
                    campaign_id, threat_class_id
                )
            }
            Self::DuplicateThreatClass { id } => {
                write!(f, "duplicate threat class: {}", id)
            }
            Self::InsufficientRounds {
                campaign_id,
                rounds,
                required,
            } => {
                write!(
                    f,
                    "campaign {} has {} rounds, need at least {}",
                    campaign_id, rounds, required
                )
            }
            Self::InvalidConfig { detail } => write!(f, "invalid config: {}", detail),
            Self::TooManyObservations { count, max } => {
                write!(f, "too many observations: {} exceeds max {}", count, max)
            }
        }
    }
}

impl std::error::Error for TailGateError {}

// ── Main Gate ───────────────────────────────────────────────────────────

/// Catastrophic-tail adversarial tournament gate.
///
/// Evaluates release candidates by running worst-case tournament campaigns
/// and computing tail-risk metrics against budget thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatastrophicTailTournamentGate {
    config: TailGateConfig,
    threat_classes: BTreeMap<String, ThreatClass>,
    risk_ledger: Vec<RiskLedgerEntry>,
    evaluation_count: u64,
}

impl CatastrophicTailTournamentGate {
    /// Create a new gate with threat class definitions.
    pub fn new(
        config: TailGateConfig,
        threat_classes: Vec<ThreatClass>,
    ) -> Result<Self, TailGateError> {
        if threat_classes.is_empty() {
            return Err(TailGateError::NoThreatClasses);
        }
        if threat_classes.len() > MAX_THREAT_CLASSES {
            return Err(TailGateError::TooManyThreatClasses {
                count: threat_classes.len(),
                max: MAX_THREAT_CLASSES,
            });
        }

        let mut map = BTreeMap::new();
        for tc in threat_classes {
            if map.contains_key(&tc.id) {
                return Err(TailGateError::DuplicateThreatClass { id: tc.id });
            }
            map.insert(tc.id.clone(), tc);
        }

        if config.cvar_alpha_millionths <= 0 || config.cvar_alpha_millionths > MILLION {
            return Err(TailGateError::InvalidConfig {
                detail: format!(
                    "cvar_alpha_millionths {} out of range (0, {}]",
                    config.cvar_alpha_millionths, MILLION
                ),
            });
        }

        if config.tail_budget_millionths < 0 {
            return Err(TailGateError::InvalidConfig {
                detail: format!(
                    "tail_budget_millionths {} must be non-negative",
                    config.tail_budget_millionths
                ),
            });
        }

        Ok(Self {
            config,
            threat_classes: map,
            risk_ledger: Vec::new(),
            evaluation_count: 0,
        })
    }

    /// Access the configuration.
    pub fn config(&self) -> &TailGateConfig {
        &self.config
    }

    /// Number of evaluations performed.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Number of threat classes.
    pub fn threat_class_count(&self) -> usize {
        self.threat_classes.len()
    }

    /// Access the risk ledger.
    pub fn risk_ledger(&self) -> &[RiskLedgerEntry] {
        &self.risk_ledger
    }

    /// Evaluate a release candidate against tournament campaigns.
    pub fn evaluate(
        &mut self,
        release_candidate_id: &str,
        campaigns: &[Campaign],
    ) -> Result<GateDecision, TailGateError> {
        if campaigns.is_empty() {
            return Err(TailGateError::NoCampaigns);
        }
        if campaigns.len() > MAX_CAMPAIGNS {
            return Err(TailGateError::TooManyCampaigns {
                count: campaigns.len(),
                max: MAX_CAMPAIGNS,
            });
        }

        // Validate campaigns.
        for campaign in campaigns {
            if !self.threat_classes.contains_key(&campaign.threat_class_id) {
                return Err(TailGateError::UnknownThreatClass {
                    campaign_id: campaign.campaign_id.clone(),
                    threat_class_id: campaign.threat_class_id.clone(),
                });
            }
            if campaign.round_count() < self.config.min_rounds_per_campaign {
                return Err(TailGateError::InsufficientRounds {
                    campaign_id: campaign.campaign_id.clone(),
                    rounds: campaign.round_count(),
                    required: self.config.min_rounds_per_campaign,
                });
            }
            if campaign.attacker_payoffs.len() > MAX_TAIL_OBSERVATIONS {
                return Err(TailGateError::TooManyObservations {
                    count: campaign.attacker_payoffs.len(),
                    max: MAX_TAIL_OBSERVATIONS,
                });
            }
        }

        self.evaluation_count += 1;

        // Group campaigns by threat class.
        let mut by_threat: BTreeMap<String, Vec<&Campaign>> = BTreeMap::new();
        for campaign in campaigns {
            by_threat
                .entry(campaign.threat_class_id.clone())
                .or_default()
                .push(campaign);
        }

        // Compute tail-risk metrics per threat class.
        let mut risk_metrics = Vec::new();
        let mut total_rounds: u64 = 0;

        for (threat_id, threat_campaigns) in &by_threat {
            let mut all_payoffs: Vec<i64> = Vec::new();
            let mut worst_exploit: Option<String> = None;
            let mut max_payoff: i64 = 0;

            for campaign in threat_campaigns {
                all_payoffs.extend_from_slice(&campaign.attacker_payoffs);
                total_rounds += campaign.round_count();

                // Check for exploits in tournament result.
                if let Some(trajectory) = &campaign.tournament_result.trajectory {
                    for round in &trajectory.rounds {
                        if round.attacker_payoff_millionths > max_payoff {
                            max_payoff = round.attacker_payoff_millionths;
                        }
                        if let Some(exploit) = &round.exploit_discovered {
                            let exploit_str = format!("{}", exploit);
                            worst_exploit = Some(exploit_str);
                        }
                    }
                }

                // Also check payoffs directly.
                for &p in &campaign.attacker_payoffs {
                    if p > max_payoff {
                        max_payoff = p;
                    }
                }
            }

            let metrics =
                self.compute_tail_metrics(threat_id, &all_payoffs, max_payoff, worst_exploit);
            risk_metrics.push(metrics);
        }

        // Compute aggregate weighted CVaR.
        let aggregate_cvar = self.compute_aggregate_cvar(&risk_metrics);
        let any_alarm = risk_metrics.iter().any(|m| m.alarm_active);

        // Determine verdict.
        let verdict = if risk_metrics.iter().any(|m| m.observation_count == 0) {
            GateVerdict::Inconclusive
        } else if aggregate_cvar > self.config.tail_budget_millionths || any_alarm {
            GateVerdict::Fail
        } else {
            GateVerdict::Pass
        };

        // Build rationale.
        let rationale = match verdict {
            GateVerdict::Pass => format!(
                "Aggregate CVaR {} within budget {}, no alarms",
                aggregate_cvar, self.config.tail_budget_millionths
            ),
            GateVerdict::Fail => {
                let mut reasons = Vec::new();
                if aggregate_cvar > self.config.tail_budget_millionths {
                    reasons.push(format!(
                        "aggregate CVaR {} exceeds budget {}",
                        aggregate_cvar, self.config.tail_budget_millionths
                    ));
                }
                if any_alarm {
                    let alarming: Vec<_> = risk_metrics
                        .iter()
                        .filter(|m| m.alarm_active)
                        .map(|m| m.threat_class_id.clone())
                        .collect();
                    reasons.push(format!("e-value alarms in: {}", alarming.join(", ")));
                }
                reasons.join("; ")
            }
            GateVerdict::Inconclusive => "insufficient data for some threat classes".to_string(),
        };

        // Generate rollback playbook if failed.
        let rollback_playbook =
            if verdict == GateVerdict::Fail && self.config.generate_rollback_playbook {
                Some(self.generate_rollback_playbook(release_candidate_id, &risk_metrics))
            } else {
                None
            };

        // Record risk ledger entries.
        if self.config.record_risk_ledger {
            for m in &risk_metrics {
                self.risk_ledger.push(RiskLedgerEntry {
                    epoch: self.config.epoch,
                    threat_class_id: m.threat_class_id.clone(),
                    cvar_millionths: m.cvar_millionths,
                    e_value_millionths: m.e_value_millionths,
                    budget_exceeded: m.exceeds_budget(self.config.tail_budget_millionths),
                });
            }
        }

        // Compute artifact hash.
        let mut hash_buf = Vec::new();
        hash_buf.extend_from_slice(TAIL_GATE_SCHEMA_VERSION.as_bytes());
        hash_buf.extend_from_slice(release_candidate_id.as_bytes());
        hash_buf.extend_from_slice(&self.config.epoch.as_u64().to_le_bytes());
        hash_buf.extend_from_slice(&aggregate_cvar.to_le_bytes());
        hash_buf.extend_from_slice(&(campaigns.len() as u64).to_le_bytes());
        for m in &risk_metrics {
            hash_buf.extend_from_slice(m.threat_class_id.as_bytes());
            hash_buf.extend_from_slice(&m.cvar_millionths.to_le_bytes());
        }

        let decision_id = format!(
            "gate-{}-{}-{}",
            release_candidate_id,
            self.config.epoch.as_u64(),
            self.evaluation_count
        );

        Ok(GateDecision {
            decision_id,
            release_candidate_id: release_candidate_id.to_string(),
            verdict,
            epoch: self.config.epoch,
            risk_metrics,
            aggregate_cvar_millionths: aggregate_cvar,
            any_alarm_active: any_alarm,
            campaigns_evaluated: campaigns.len() as u64,
            total_rounds,
            rollback_playbook,
            rationale,
            artifact_hash: ContentHash::compute(&hash_buf),
        })
    }

    // ── Tail Metrics Computation ────────────────────────────────────

    fn compute_tail_metrics(
        &self,
        threat_class_id: &str,
        payoffs: &[i64],
        max_payoff: i64,
        worst_exploit: Option<String>,
    ) -> TailRiskMetrics {
        if payoffs.is_empty() {
            return TailRiskMetrics {
                threat_class_id: threat_class_id.to_string(),
                observation_count: 0,
                var_millionths: 0,
                cvar_millionths: 0,
                alpha_millionths: self.config.cvar_alpha_millionths,
                e_value_millionths: MILLION,
                alarm_active: false,
                max_payoff_millionths: max_payoff,
                worst_exploit,
            };
        }

        let mut sorted = payoffs.to_vec();
        sorted.sort_unstable();

        let n = sorted.len();

        // VaR: quantile at alpha.
        let var_index = ((self.config.cvar_alpha_millionths as u64 * n as u64) / MILLION as u64)
            .min(n as u64 - 1) as usize;
        let var = sorted[var_index];

        // CVaR: average of observations >= VaR.
        let tail_obs: Vec<i64> = sorted.iter().filter(|&&x| x >= var).copied().collect();
        let cvar = if tail_obs.is_empty() {
            var
        } else {
            tail_obs.iter().sum::<i64>() / tail_obs.len() as i64
        };

        // E-value: product-form likelihood ratio alarm.
        // Simplified: e_value = (max_payoff / mean_payoff) if mean > 0.
        let mean = sorted.iter().sum::<i64>() / n as i64;
        let e_value = if mean > 0 {
            (max_payoff * MILLION) / mean
        } else if max_payoff > 0 {
            self.config.e_value_alarm_threshold_millionths + 1
        } else {
            MILLION
        };

        let alarm = e_value > self.config.e_value_alarm_threshold_millionths;

        TailRiskMetrics {
            threat_class_id: threat_class_id.to_string(),
            observation_count: n as u64,
            var_millionths: var,
            cvar_millionths: cvar,
            alpha_millionths: self.config.cvar_alpha_millionths,
            e_value_millionths: e_value,
            alarm_active: alarm,
            max_payoff_millionths: max_payoff,
            worst_exploit,
        }
    }

    fn compute_aggregate_cvar(&self, metrics: &[TailRiskMetrics]) -> i64 {
        let mut total_weight: i64 = 0;
        let mut weighted_cvar: i64 = 0;

        for m in metrics {
            if let Some(tc) = self.threat_classes.get(&m.threat_class_id) {
                weighted_cvar += (m.cvar_millionths * tc.impact_weight_millionths) / MILLION;
                total_weight += tc.impact_weight_millionths;
            }
        }

        if total_weight == 0 {
            return 0;
        }

        (weighted_cvar * MILLION) / total_weight
    }

    // ── Rollback Playbook Generation ────────────────────────────────

    fn generate_rollback_playbook(
        &self,
        release_candidate_id: &str,
        risk_metrics: &[TailRiskMetrics],
    ) -> RollbackPlaybook {
        let triggering_threats: Vec<String> = risk_metrics
            .iter()
            .filter(|m| m.exceeds_budget(self.config.tail_budget_millionths) || m.alarm_active)
            .map(|m| m.threat_class_id.clone())
            .collect();

        let mut steps = Vec::new();
        steps.push(MitigationStep {
            step: 1,
            description: "Route all traffic to safe fallback lane".to_string(),
            automated: true,
            action: Some(LaneAction::FallbackSafe),
        });
        steps.push(MitigationStep {
            step: 2,
            description: format!(
                "Demote release candidate {} from active lanes",
                release_candidate_id
            ),
            automated: true,
            action: Some(LaneAction::Demote {
                from_lane: LaneId("active".to_string()),
                reason: DemotionReason::CvarExceeded,
            }),
        });
        steps.push(MitigationStep {
            step: 3,
            description: "Route to safe baseline lane".to_string(),
            automated: true,
            action: Some(LaneAction::RouteTo(self.config.rollback_lane.clone())),
        });
        steps.push(MitigationStep {
            step: 4,
            description: "Review tail-risk evidence and determine root cause".to_string(),
            automated: false,
            action: None,
        });

        let mut hash_buf = Vec::new();
        hash_buf.extend_from_slice(release_candidate_id.as_bytes());
        hash_buf.extend_from_slice(&self.config.epoch.as_u64().to_le_bytes());
        for t in &triggering_threats {
            hash_buf.extend_from_slice(t.as_bytes());
        }

        RollbackPlaybook {
            playbook_id: format!(
                "playbook-{}-{}",
                release_candidate_id, self.evaluation_count
            ),
            rollback_action: LaneAction::RouteTo(self.config.rollback_lane.clone()),
            triggering_threats,
            mitigation_steps: steps,
            evidence_hash: ContentHash::compute(&hash_buf),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_threat(id: &str, category: ThreatCategory, weight: i64) -> ThreatClass {
        ThreatClass {
            id: id.to_string(),
            label: format!("Threat {}", id),
            category,
            impact_weight_millionths: weight,
            related_exploits: BTreeSet::new(),
        }
    }

    fn make_tournament_result(rounds: u64, payoff: i64) -> TournamentResult {
        use crate::adversarial_coevolution_harness::{
            ConvergenceDiagnostic, PolicyDelta as CoevPolicyDelta,
        };

        TournamentResult {
            schema_version: "test".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            rounds_played: rounds,
            total_attacker_payoff_millionths: payoff * rounds as i64,
            total_defender_payoff_millionths: -payoff * rounds as i64,
            convergence: ConvergenceDiagnostic {
                attacker_avg_regret_millionths: 0,
                defender_avg_regret_millionths: 0,
                attacker_regret_bounded: true,
                defender_regret_bounded: true,
                exploit_classes: BTreeSet::new(),
                attacker_frequency: BTreeMap::new(),
                defender_frequency: BTreeMap::new(),
            },
            policy_delta: CoevPolicyDelta {
                delta_id: "delta-test".to_string(),
                recommended_mix: BTreeMap::new(),
                addressed_exploits: BTreeSet::new(),
                expected_improvement_millionths: 0,
                source_epoch: SecurityEpoch::from_raw(1),
                artifact_hash: ContentHash::compute(b"test"),
            },
            trajectory: None,
            artifact_hash: ContentHash::compute(b"test-tournament"),
        }
    }

    fn make_campaign(id: &str, threat_id: &str, payoffs: Vec<i64>) -> Campaign {
        let rounds = payoffs.len() as u64;
        Campaign {
            campaign_id: id.to_string(),
            threat_class_id: threat_id.to_string(),
            tournament_result: make_tournament_result(
                rounds,
                payoffs.iter().sum::<i64>() / rounds.max(1) as i64,
            ),
            attacker_payoffs: payoffs,
        }
    }

    fn default_gate() -> CatastrophicTailTournamentGate {
        let threats = vec![
            make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION),
            make_threat("t2", ThreatCategory::ResourceExhaustion, MILLION),
        ];
        CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap()
    }

    fn low_risk_payoffs(n: usize) -> Vec<i64> {
        // All small payoffs, well within budget.
        (0..n).map(|i| (i as i64) * 1000).collect()
    }

    fn high_risk_payoffs(n: usize) -> Vec<i64> {
        // Mostly small, but with catastrophic tail.
        let mut payoffs: Vec<i64> = (0..n).map(|_| 50_000).collect();
        // Add catastrophic tail events.
        let tail_start = n * 95 / 100;
        for p in payoffs.iter_mut().skip(tail_start) {
            *p = 5_000_000; // 5x MILLION
        }
        payoffs
    }

    // ── Constructor Tests ───────────────────────────────────────────

    #[test]
    fn new_creates_gate() {
        let gate = default_gate();
        assert_eq!(gate.threat_class_count(), 2);
        assert_eq!(gate.evaluation_count(), 0);
        assert!(gate.risk_ledger().is_empty());
    }

    #[test]
    fn new_rejects_no_threats() {
        let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), Vec::new());
        assert!(matches!(result, Err(TailGateError::NoThreatClasses)));
    }

    #[test]
    fn new_rejects_too_many_threats() {
        let threats: Vec<_> = (0..65)
            .map(|i| make_threat(&format!("t{}", i), ThreatCategory::PolicyBypass, MILLION))
            .collect();
        let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats);
        assert!(matches!(
            result,
            Err(TailGateError::TooManyThreatClasses { count: 65, max: 64 })
        ));
    }

    #[test]
    fn new_rejects_duplicate_threats() {
        let threats = vec![
            make_threat("dup", ThreatCategory::CapabilityEscalation, MILLION),
            make_threat("dup", ThreatCategory::ResourceExhaustion, MILLION),
        ];
        let result = CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats);
        assert!(matches!(
            result,
            Err(TailGateError::DuplicateThreatClass { .. })
        ));
    }

    #[test]
    fn new_rejects_invalid_alpha() {
        let config = TailGateConfig {
            cvar_alpha_millionths: 0,
            ..Default::default()
        };
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let result = CatastrophicTailTournamentGate::new(config, threats);
        assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
    }

    #[test]
    fn new_rejects_negative_budget() {
        let config = TailGateConfig {
            tail_budget_millionths: -1,
            ..Default::default()
        };
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let result = CatastrophicTailTournamentGate::new(config, threats);
        assert!(matches!(result, Err(TailGateError::InvalidConfig { .. })));
    }

    // ── Evaluation Tests ────────────────────────────────────────────

    #[test]
    fn evaluate_rejects_no_campaigns() {
        let mut gate = default_gate();
        let result = gate.evaluate("rc-1", &[]);
        assert!(matches!(result, Err(TailGateError::NoCampaigns)));
    }

    #[test]
    fn evaluate_rejects_unknown_threat() {
        let mut gate = default_gate();
        let campaign = make_campaign("c1", "unknown", low_risk_payoffs(200));
        let result = gate.evaluate("rc-1", &[campaign]);
        assert!(matches!(
            result,
            Err(TailGateError::UnknownThreatClass { .. })
        ));
    }

    #[test]
    fn evaluate_rejects_insufficient_rounds() {
        let mut gate = default_gate();
        let campaign = make_campaign("c1", "t1", low_risk_payoffs(50)); // Below 100 min
        let result = gate.evaluate("rc-1", &[campaign]);
        assert!(matches!(
            result,
            Err(TailGateError::InsufficientRounds { .. })
        ));
    }

    #[test]
    fn evaluate_passes_low_risk() {
        let mut gate = default_gate();
        let campaigns = vec![
            make_campaign("c1", "t1", low_risk_payoffs(200)),
            make_campaign("c2", "t2", low_risk_payoffs(200)),
        ];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.verdict, GateVerdict::Pass);
        assert!(decision.is_pass());
        assert!(decision.rollback_playbook.is_none());
        assert_eq!(decision.campaigns_evaluated, 2);
    }

    #[test]
    fn evaluate_fails_high_risk() {
        let config = TailGateConfig {
            tail_budget_millionths: 100_000, // Low budget
            ..Default::default()
        };
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();

        let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.verdict, GateVerdict::Fail);
        assert!(!decision.is_pass());
        assert!(decision.rollback_playbook.is_some());
    }

    #[test]
    fn evaluate_increments_count() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let _ = gate.evaluate("rc-1", &campaigns);
        assert_eq!(gate.evaluation_count(), 1);
        let _ = gate.evaluate("rc-2", &campaigns);
        assert_eq!(gate.evaluation_count(), 2);
    }

    #[test]
    fn evaluate_records_risk_ledger() {
        let mut gate = default_gate();
        let campaigns = vec![
            make_campaign("c1", "t1", low_risk_payoffs(200)),
            make_campaign("c2", "t2", low_risk_payoffs(200)),
        ];
        let _ = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(gate.risk_ledger().len(), 2);
    }

    #[test]
    fn evaluate_no_ledger_when_disabled() {
        let config = TailGateConfig {
            record_risk_ledger: false,
            ..Default::default()
        };
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();

        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let _ = gate.evaluate("rc-1", &campaigns).unwrap();
        assert!(gate.risk_ledger().is_empty());
    }

    // ── Tail Metrics Tests ──────────────────────────────────────────

    #[test]
    fn tail_metrics_cvar_computed() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        let metrics = &decision.risk_metrics[0];
        assert_eq!(metrics.threat_class_id, "t1");
        assert_eq!(metrics.observation_count, 200);
        assert!(metrics.var_millionths >= 0);
        assert!(metrics.cvar_millionths >= metrics.var_millionths);
    }

    #[test]
    fn tail_metrics_max_payoff() {
        let mut gate = default_gate();
        let payoffs = vec![100_000; 200];
        let campaigns = vec![make_campaign("c1", "t1", payoffs)];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.risk_metrics[0].max_payoff_millionths, 100_000);
    }

    #[test]
    fn tail_metrics_e_value_alarm() {
        let config = TailGateConfig {
            e_value_alarm_threshold_millionths: 5_000_000, // 5x
            ..Default::default()
        };
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();

        // Most payoffs small, one huge → high e-value.
        let mut payoffs = vec![1_000; 199];
        payoffs.push(100_000_000); // 100x MILLION
        let campaigns = vec![make_campaign("c1", "t1", payoffs)];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert!(decision.risk_metrics[0].alarm_active);
        assert!(decision.any_alarm_active);
    }

    #[test]
    fn tail_metrics_no_alarm_uniform() {
        let mut gate = default_gate();
        let payoffs = vec![100_000; 200]; // All same → e-value = 1x
        let campaigns = vec![make_campaign("c1", "t1", payoffs)];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert!(!decision.risk_metrics[0].alarm_active);
    }

    // ── Aggregate CVaR Tests ────────────────────────────────────────

    #[test]
    fn aggregate_cvar_weighted_by_impact() {
        let threats = vec![
            make_threat("t1", ThreatCategory::CapabilityEscalation, 2 * MILLION), // 2x weight
            make_threat("t2", ThreatCategory::ResourceExhaustion, MILLION),       // 1x weight
        ];
        let mut gate =
            CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();

        let campaigns = vec![
            make_campaign("c1", "t1", vec![100_000; 200]),
            make_campaign("c2", "t2", vec![200_000; 200]),
        ];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        // t1 has CVaR ~100k with weight 2M, t2 has CVaR ~200k with weight 1M
        // Aggregate = (100k*2 + 200k*1) / 3 ≈ 133k
        assert!(decision.aggregate_cvar_millionths > 0);
    }

    // ── Rollback Playbook Tests ─────────────────────────────────────

    #[test]
    fn rollback_playbook_generated_on_fail() {
        let config = TailGateConfig {
            tail_budget_millionths: 10_000, // Very low
            ..Default::default()
        };
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();

        let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.verdict, GateVerdict::Fail);
        let playbook = decision.rollback_playbook.as_ref().unwrap();
        assert!(!playbook.triggering_threats.is_empty());
        assert_eq!(playbook.mitigation_steps.len(), 4);
        assert!(playbook.mitigation_steps[0].automated);
        assert!(!playbook.mitigation_steps[3].automated);
    }

    #[test]
    fn no_playbook_on_pass() {
        let mut gate = default_gate();
        let campaigns = vec![
            make_campaign("c1", "t1", low_risk_payoffs(200)),
            make_campaign("c2", "t2", low_risk_payoffs(200)),
        ];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert!(decision.rollback_playbook.is_none());
    }

    #[test]
    fn no_playbook_when_disabled() {
        let mut config = TailGateConfig {
            tail_budget_millionths: 10_000,
            ..Default::default()
        };
        config.generate_rollback_playbook = false;
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();

        let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.verdict, GateVerdict::Fail);
        assert!(decision.rollback_playbook.is_none());
    }

    // ── Gate Decision Properties ────────────────────────────────────

    #[test]
    fn decision_has_artifact_hash() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_ne!(decision.artifact_hash, ContentHash::compute(b""));
    }

    #[test]
    fn decision_artifact_hash_deterministic() {
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];

        let mut g1 =
            CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats.clone())
                .unwrap();
        let d1 = g1.evaluate("rc-1", &campaigns).unwrap();

        let mut g2 =
            CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
        let d2 = g2.evaluate("rc-1", &campaigns).unwrap();

        assert_eq!(d1.artifact_hash, d2.artifact_hash);
    }

    #[test]
    fn decision_total_rounds() {
        let mut gate = default_gate();
        let campaigns = vec![
            make_campaign("c1", "t1", low_risk_payoffs(200)),
            make_campaign("c2", "t2", low_risk_payoffs(300)),
        ];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.total_rounds, 500);
    }

    // ── Display / Serde ─────────────────────────────────────────────

    #[test]
    fn gate_verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Pass), "pass");
        assert_eq!(format!("{}", GateVerdict::Fail), "fail");
        assert_eq!(format!("{}", GateVerdict::Inconclusive), "inconclusive");
    }

    #[test]
    fn threat_category_display() {
        assert_eq!(
            format!("{}", ThreatCategory::CapabilityEscalation),
            "capability-escalation"
        );
        assert_eq!(
            format!("{}", ThreatCategory::ResourceExhaustion),
            "resource-exhaustion"
        );
        assert_eq!(
            format!("{}", ThreatCategory::InformationLeakage),
            "information-leakage"
        );
        assert_eq!(format!("{}", ThreatCategory::PolicyBypass), "policy-bypass");
        assert_eq!(format!("{}", ThreatCategory::SupplyChain), "supply-chain");
        assert_eq!(
            format!("{}", ThreatCategory::TimingChannel),
            "timing-channel"
        );
    }

    #[test]
    fn threat_class_display() {
        let t = make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION);
        let display = format!("{}", t);
        assert!(display.contains("t1"));
    }

    #[test]
    fn tail_risk_metrics_display() {
        let m = TailRiskMetrics {
            threat_class_id: "t1".to_string(),
            observation_count: 100,
            var_millionths: 100_000,
            cvar_millionths: 150_000,
            alpha_millionths: 950_000,
            e_value_millionths: MILLION,
            alarm_active: false,
            max_payoff_millionths: 200_000,
            worst_exploit: None,
        };
        let display = format!("{}", m);
        assert!(display.contains("t1"));
        assert!(display.contains("cvar=150000"));
    }

    #[test]
    fn gate_decision_display() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        let display = format!("{}", decision);
        assert!(display.contains("rc-1"));
    }

    #[test]
    fn rollback_playbook_display() {
        let playbook = RollbackPlaybook {
            playbook_id: "pb-1".to_string(),
            rollback_action: LaneAction::FallbackSafe,
            triggering_threats: vec!["t1".to_string()],
            mitigation_steps: vec![MitigationStep {
                step: 1,
                description: "test".to_string(),
                automated: true,
                action: None,
            }],
            evidence_hash: ContentHash::compute(b"test"),
        };
        let display = format!("{}", playbook);
        assert!(display.contains("pb-1"));
    }

    #[test]
    fn error_display() {
        assert_eq!(
            format!("{}", TailGateError::NoThreatClasses),
            "no threat classes defined"
        );
        assert!(
            format!(
                "{}",
                TailGateError::TooManyThreatClasses {
                    count: 100,
                    max: 64
                }
            )
            .contains("100")
        );
        assert!(
            format!(
                "{}",
                TailGateError::UnknownThreatClass {
                    campaign_id: "c1".to_string(),
                    threat_class_id: "x".to_string()
                }
            )
            .contains("x")
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err = TailGateError::NoThreatClasses;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn serde_roundtrip_threat_class() {
        let tc = make_threat("t1", ThreatCategory::CapabilityEscalation, MILLION);
        let json = serde_json::to_string(&tc).unwrap();
        let back: ThreatClass = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, back);
    }

    #[test]
    fn serde_roundtrip_tail_risk_metrics() {
        let m = TailRiskMetrics {
            threat_class_id: "t1".to_string(),
            observation_count: 100,
            var_millionths: 100_000,
            cvar_millionths: 150_000,
            alpha_millionths: 950_000,
            e_value_millionths: MILLION,
            alarm_active: false,
            max_payoff_millionths: 200_000,
            worst_exploit: None,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: TailRiskMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn serde_roundtrip_gate_decision() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        let back: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn serde_roundtrip_config() {
        let config = TailGateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TailGateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    #[test]
    fn single_threat_single_campaign() {
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate =
            CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.risk_metrics.len(), 1);
    }

    #[test]
    fn multiple_campaigns_same_threat() {
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate =
            CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
        let campaigns = vec![
            make_campaign("c1", "t1", low_risk_payoffs(200)),
            make_campaign("c2", "t1", low_risk_payoffs(300)),
        ];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        // Should merge payoffs from both campaigns for one threat class.
        assert_eq!(decision.risk_metrics.len(), 1);
        assert_eq!(decision.risk_metrics[0].observation_count, 500);
    }

    #[test]
    fn zero_payoffs_pass() {
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate =
            CatastrophicTailTournamentGate::new(TailGateConfig::default(), threats).unwrap();
        let campaigns = vec![make_campaign("c1", "t1", vec![0; 200])];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(decision.verdict, GateVerdict::Pass);
    }

    #[test]
    fn config_accessor() {
        let gate = default_gate();
        assert_eq!(
            gate.config().cvar_alpha_millionths,
            DEFAULT_CVAR_ALPHA_MILLIONTHS
        );
    }

    #[test]
    fn config_default_values() {
        let config = TailGateConfig::default();
        assert_eq!(config.cvar_alpha_millionths, DEFAULT_CVAR_ALPHA_MILLIONTHS);
        assert_eq!(
            config.tail_budget_millionths,
            DEFAULT_TAIL_BUDGET_MILLIONTHS
        );
        assert_eq!(
            config.e_value_alarm_threshold_millionths,
            DEFAULT_E_VALUE_ALARM_MILLIONTHS
        );
        assert_eq!(config.min_rounds_per_campaign, DEFAULT_MIN_ROUNDS);
        assert!(config.generate_rollback_playbook);
        assert!(config.record_risk_ledger);
    }

    #[test]
    fn exceeds_budget_check() {
        let m = TailRiskMetrics {
            threat_class_id: "t1".to_string(),
            observation_count: 100,
            var_millionths: 100_000,
            cvar_millionths: 600_000,
            alpha_millionths: 950_000,
            e_value_millionths: MILLION,
            alarm_active: false,
            max_payoff_millionths: 200_000,
            worst_exploit: None,
        };
        assert!(m.exceeds_budget(500_000));
        assert!(!m.exceeds_budget(700_000));
    }

    #[test]
    fn campaign_round_count() {
        let campaign = make_campaign("c1", "t1", vec![100_000; 150]);
        assert_eq!(campaign.round_count(), 150);
    }

    #[test]
    fn risk_ledger_entry_epoch() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let _ = gate.evaluate("rc-1", &campaigns).unwrap();
        assert_eq!(gate.risk_ledger()[0].epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn mitigation_step_action() {
        let step = MitigationStep {
            step: 1,
            description: "test".to_string(),
            automated: true,
            action: Some(LaneAction::FallbackSafe),
        };
        assert!(step.action.is_some());
    }

    #[test]
    fn fail_rationale_mentions_cvar() {
        let config = TailGateConfig {
            tail_budget_millionths: 10_000,
            ..Default::default()
        };
        let threats = vec![make_threat(
            "t1",
            ThreatCategory::CapabilityEscalation,
            MILLION,
        )];
        let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
        let campaigns = vec![make_campaign("c1", "t1", high_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert!(
            decision.rationale.contains("CVaR")
                || decision.rationale.contains("cvar")
                || decision.rationale.contains("alarm")
        );
    }

    #[test]
    fn pass_rationale_mentions_within_budget() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let decision = gate.evaluate("rc-1", &campaigns).unwrap();
        assert!(decision.rationale.contains("within budget"));
    }

    // ── Enrichment: Clone Equality ──────────────────────────────────

    #[test]
    fn clone_eq_threat_class() {
        let tc = make_threat("tc-clone", ThreatCategory::InformationLeakage, 750_000);
        let cloned = tc.clone();
        assert_eq!(tc, cloned);
    }

    #[test]
    fn clone_eq_tail_risk_metrics() {
        let m = TailRiskMetrics {
            threat_class_id: "t-clone".to_string(),
            observation_count: 42,
            var_millionths: 80_000,
            cvar_millionths: 120_000,
            alpha_millionths: 950_000,
            e_value_millionths: 3_000_000,
            alarm_active: false,
            max_payoff_millionths: 300_000,
            worst_exploit: Some("xss-variant".to_string()),
        };
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn clone_eq_gate_decision() {
        let mut gate = default_gate();
        let campaigns = vec![make_campaign("c1", "t1", low_risk_payoffs(200))];
        let decision = gate.evaluate("rc-clone", &campaigns).unwrap();
        let cloned = decision.clone();
        assert_eq!(decision, cloned);
    }

    #[test]
    fn clone_eq_rollback_playbook() {
        let playbook = RollbackPlaybook {
            playbook_id: "pb-clone".to_string(),
            rollback_action: LaneAction::FallbackSafe,
            triggering_threats: vec!["t1".to_string(), "t2".to_string()],
            mitigation_steps: vec![
                MitigationStep {
                    step: 1,
                    description: "first step".to_string(),
                    automated: true,
                    action: Some(LaneAction::FallbackSafe),
                },
                MitigationStep {
                    step: 2,
                    description: "manual review".to_string(),
                    automated: false,
                    action: None,
                },
            ],
            evidence_hash: ContentHash::compute(b"clone-test"),
        };
        let cloned = playbook.clone();
        assert_eq!(playbook, cloned);
    }

    #[test]
    fn clone_eq_risk_ledger_entry() {
        let entry = RiskLedgerEntry {
            epoch: SecurityEpoch::from_raw(5),
            threat_class_id: "t-ledger".to_string(),
            cvar_millionths: 250_000,
            e_value_millionths: 4_000_000,
            budget_exceeded: true,
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    // ── Enrichment: JSON Field Presence ─────────────────────────────

    #[test]
    fn json_fields_threat_class() {
        let tc = make_threat("t-json", ThreatCategory::SupplyChain, MILLION);
        let json = serde_json::to_string(&tc).unwrap();
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"label\""));
        assert!(json.contains("\"category\""));
        assert!(json.contains("\"impact_weight_millionths\""));
        assert!(json.contains("\"related_exploits\""));
    }

    #[test]
    fn json_fields_tail_risk_metrics() {
        let m = TailRiskMetrics {
            threat_class_id: "t-json-m".to_string(),
            observation_count: 10,
            var_millionths: 50_000,
            cvar_millionths: 70_000,
            alpha_millionths: 950_000,
            e_value_millionths: MILLION,
            alarm_active: true,
            max_payoff_millionths: 90_000,
            worst_exploit: None,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"threat_class_id\""));
        assert!(json.contains("\"observation_count\""));
        assert!(json.contains("\"var_millionths\""));
        assert!(json.contains("\"cvar_millionths\""));
        assert!(json.contains("\"alpha_millionths\""));
        assert!(json.contains("\"e_value_millionths\""));
        assert!(json.contains("\"alarm_active\""));
        assert!(json.contains("\"max_payoff_millionths\""));
        assert!(json.contains("\"worst_exploit\""));
    }

    #[test]
    fn json_fields_risk_ledger_entry() {
        let entry = RiskLedgerEntry {
            epoch: SecurityEpoch::from_raw(3),
            threat_class_id: "t-json-le".to_string(),
            cvar_millionths: 100_000,
            e_value_millionths: 2_000_000,
            budget_exceeded: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"threat_class_id\""));
        assert!(json.contains("\"cvar_millionths\""));
        assert!(json.contains("\"e_value_millionths\""));
        assert!(json.contains("\"budget_exceeded\""));
    }

    // ── Enrichment: Serde Roundtrip ─────────────────────────────────

    #[test]
    fn serde_roundtrip_risk_ledger_entry() {
        let entry = RiskLedgerEntry {
            epoch: SecurityEpoch::from_raw(7),
            threat_class_id: "t-rt".to_string(),
            cvar_millionths: 300_000,
            e_value_millionths: 5_000_000,
            budget_exceeded: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RiskLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // ── Enrichment: Display Uniqueness ──────────────────────────────

    #[test]
    fn display_all_gate_verdicts_unique() {
        let variants = [
            GateVerdict::Pass,
            GateVerdict::Fail,
            GateVerdict::Inconclusive,
        ];
        let mut seen = BTreeSet::new();
        for v in &variants {
            let s = format!("{}", v);
            assert!(seen.insert(s.clone()), "duplicate Display for {:?}", v);
        }
        assert_eq!(seen.len(), 3);
    }

    // ── Enrichment: Boundary Conditions ─────────────────────────────

    #[test]
    fn tail_budget_zero_boundary() {
        let config = TailGateConfig {
            tail_budget_millionths: 0, // exactly zero — any nonzero CVaR fails
            ..Default::default()
        };
        let threats = vec![make_threat("t1", ThreatCategory::PolicyBypass, MILLION)];
        let mut gate = CatastrophicTailTournamentGate::new(config, threats).unwrap();
        let campaigns = vec![make_campaign("c1", "t1", vec![1; 200])];
        let decision = gate.evaluate("rc-boundary", &campaigns).unwrap();
        // CVaR of all-1 payoffs is 1, which exceeds budget 0
        assert_eq!(decision.verdict, GateVerdict::Fail);
    }

    // ── Enrichment: std::error::Error::source ───────────────────────

    #[test]
    fn error_source_is_none() {
        use std::error::Error;
        let variants: Vec<TailGateError> = vec![
            TailGateError::NoThreatClasses,
            TailGateError::NoCampaigns,
            TailGateError::TooManyThreatClasses { count: 70, max: 64 },
            TailGateError::InvalidConfig {
                detail: "bad".to_string(),
            },
        ];
        for err in &variants {
            assert!(err.source().is_none(), "expected no source for {:?}", err);
        }
    }
}
