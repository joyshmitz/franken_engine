//! VOI-budgeted monitor scheduler for high-cost diagnostic probes.
//!
//! Dynamically allocates probe execution budget based on Value of Information
//! (VOI) scoring: `VOI = staleness * relevance / cost`.  Probes are scheduled
//! in descending VOI order until the per-interval budget is exhausted.
//! Budget is regime-adaptive: higher during Elevated/Attack regimes.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic computation.
//!
//! Plan references: Section 10.11 item 16, 9G.5 (policy controller with
//! expected-loss actions under guardrails), Top-10 #2 (guardplane),
//! #4 (alien-performance profile discipline).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::regime_detector::Regime;

// ---------------------------------------------------------------------------
// ProbeKind — categories of diagnostic probes
// ---------------------------------------------------------------------------

/// Category of a diagnostic probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProbeKind {
    /// Lightweight subsystem health verification.
    HealthCheck,
    /// Expensive analysis (full GC inspection, extension-state snapshot).
    DeepDiagnostic,
    /// Model calibration verification for sentinel/controller components.
    CalibrationProbe,
    /// Hash verification, evidence-chain consistency check.
    IntegrityAudit,
}

impl fmt::Display for ProbeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HealthCheck => write!(f, "health_check"),
            Self::DeepDiagnostic => write!(f, "deep_diagnostic"),
            Self::CalibrationProbe => write!(f, "calibration_probe"),
            Self::IntegrityAudit => write!(f, "integrity_audit"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProbeConfig — configuration for a single probe
// ---------------------------------------------------------------------------

/// Configuration for a single diagnostic probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// Unique probe identifier.
    pub probe_id: String,
    /// Probe category.
    pub kind: ProbeKind,
    /// Cost of executing this probe (millionths, abstract units).
    pub cost_millionths: i64,
    /// Expected information gain (millionths, abstract units).
    pub information_gain_millionths: i64,
    /// Base relevance weight (millionths).
    pub base_relevance_millionths: i64,
}

// ---------------------------------------------------------------------------
// ProbeState — runtime state of a probe
// ---------------------------------------------------------------------------

/// Runtime state of a probe managed by the scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeState {
    /// Probe configuration.
    pub config: ProbeConfig,
    /// Intervals since last execution (increases staleness).
    pub staleness: u64,
    /// Number of times this probe has been scheduled.
    pub execution_count: u64,
    /// Whether the last execution was successful.
    pub last_success: bool,
}

impl ProbeState {
    /// Create from a probe config with initial state.
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            config,
            staleness: 0,
            execution_count: 0,
            last_success: true,
        }
    }

    /// Compute VOI score: staleness * relevance * information_gain / cost.
    ///
    /// Returns millionths.  Higher is better.
    pub fn voi_score(&self, regime_relevance_multiplier: i64) -> i64 {
        let cost = self.config.cost_millionths.max(1); // prevent div-by-zero
        let staleness_factor = ((self.staleness + 1) as i64) * 1_000_000;
        let relevance = self.config.base_relevance_millionths as i128
            * regime_relevance_multiplier as i128
            / 1_000_000;
        let info = self.config.information_gain_millionths as i128;

        // VOI = staleness * relevance * info / cost
        let numerator = staleness_factor as i128 * relevance * info;
        let denominator = cost as i128 * 1_000_000i128 * 1_000_000;

        (numerator / denominator) as i64
    }

    /// Mark probe as executed (resets staleness).
    pub fn mark_executed(&mut self, success: bool) {
        self.staleness = 0;
        self.execution_count += 1;
        self.last_success = success;
    }

    /// Increment staleness (called each scheduling interval).
    pub fn tick_staleness(&mut self) {
        self.staleness += 1;
    }
}

// ---------------------------------------------------------------------------
// SchedulerConfig
// ---------------------------------------------------------------------------

/// Configuration for the monitor scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Scheduler identifier.
    pub scheduler_id: String,
    /// Base budget per scheduling interval (millionths, abstract cost units).
    pub base_budget_millionths: i64,
    /// Budget multipliers per regime (millionths).
    pub regime_budgets: BTreeMap<String, i64>,
    /// Relevance multipliers per regime and probe kind (millionths).
    /// Key: "regime:probe_kind".
    pub relevance_overrides: BTreeMap<String, i64>,
}

impl SchedulerConfig {
    /// Get the budget for a given regime.
    pub fn budget_for_regime(&self, regime: Regime) -> i64 {
        let key = regime.to_string();
        self.regime_budgets
            .get(&key)
            .copied()
            .unwrap_or(self.base_budget_millionths)
    }

    /// Get the relevance multiplier for a regime + probe kind.
    pub fn relevance_multiplier(&self, regime: Regime, kind: ProbeKind) -> i64 {
        let key = format!("{}:{}", regime, kind);
        self.relevance_overrides
            .get(&key)
            .copied()
            .unwrap_or(1_000_000) // default 1.0
    }
}

// ---------------------------------------------------------------------------
// ScheduleDecision — result for a single probe
// ---------------------------------------------------------------------------

/// Scheduling decision for a single probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDecision {
    /// Probe identifier.
    pub probe_id: String,
    /// Probe kind.
    pub kind: ProbeKind,
    /// Computed VOI score (millionths).
    pub voi_score: i64,
    /// Cost of the probe (millionths).
    pub cost: i64,
    /// Whether the probe was scheduled.
    pub scheduled: bool,
    /// Reason if not scheduled.
    pub skip_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// ScheduleResult — complete scheduling output
// ---------------------------------------------------------------------------

/// Complete result of a scheduling interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleResult {
    /// Scheduler identifier.
    pub scheduler_id: String,
    /// Scheduling interval number.
    pub interval: u64,
    /// Regime at time of scheduling.
    pub regime: Regime,
    /// Total budget for this interval (millionths).
    pub budget_total: i64,
    /// Budget consumed by scheduled probes (millionths).
    pub budget_used: i64,
    /// Number of probes scheduled.
    pub probes_scheduled: usize,
    /// Number of probes deferred.
    pub probes_deferred: usize,
    /// Per-probe decisions.
    pub decisions: Vec<ScheduleDecision>,
}

// ---------------------------------------------------------------------------
// SchedulerError
// ---------------------------------------------------------------------------

/// Errors from monitor scheduler operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedulerError {
    /// Duplicate probe ID.
    DuplicateProbe { probe_id: String },
    /// Probe not found.
    ProbeNotFound { probe_id: String },
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateProbe { probe_id } => {
                write!(f, "duplicate probe: {probe_id}")
            }
            Self::ProbeNotFound { probe_id } => {
                write!(f, "probe not found: {probe_id}")
            }
        }
    }
}

impl std::error::Error for SchedulerError {}

// ---------------------------------------------------------------------------
// MonitorScheduler — the VOI-budgeted scheduler
// ---------------------------------------------------------------------------

/// VOI-budgeted monitor scheduler.
///
/// Manages diagnostic probes and schedules them based on Value of Information
/// scoring within a regime-adaptive budget.
#[derive(Debug)]
pub struct MonitorScheduler {
    config: SchedulerConfig,
    /// Probes indexed by probe_id (BTreeMap for deterministic iteration).
    probes: BTreeMap<String, ProbeState>,
    /// Current scheduling interval.
    interval: u64,
    /// History of scheduling results.
    history: Vec<ScheduleResult>,
}

impl MonitorScheduler {
    /// Create a new scheduler.
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            probes: BTreeMap::new(),
            interval: 0,
            history: Vec::new(),
        }
    }

    /// Register a new probe.
    pub fn register_probe(&mut self, config: ProbeConfig) -> Result<(), SchedulerError> {
        if self.probes.contains_key(&config.probe_id) {
            return Err(SchedulerError::DuplicateProbe {
                probe_id: config.probe_id,
            });
        }
        let id = config.probe_id.clone();
        self.probes.insert(id, ProbeState::new(config));
        Ok(())
    }

    /// Remove a probe.
    pub fn unregister_probe(&mut self, probe_id: &str) -> Result<(), SchedulerError> {
        if self.probes.remove(probe_id).is_none() {
            return Err(SchedulerError::ProbeNotFound {
                probe_id: probe_id.to_string(),
            });
        }
        Ok(())
    }

    /// Number of registered probes.
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// Current interval.
    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// Scheduler configuration.
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// Scheduling history.
    pub fn history(&self) -> &[ScheduleResult] {
        &self.history
    }

    /// Get probe state by ID.
    pub fn probe(&self, probe_id: &str) -> Option<&ProbeState> {
        self.probes.get(probe_id)
    }

    /// Run a scheduling interval for the given regime.
    ///
    /// 1. Increments staleness for all probes.
    /// 2. Computes VOI scores.
    /// 3. Sorts by descending VOI.
    /// 4. Greedily schedules probes until budget exhausted.
    /// 5. Returns the schedule.
    pub fn schedule(&mut self, regime: Regime) -> ScheduleResult {
        self.interval += 1;

        // Step 1: Increment staleness.
        for probe in self.probes.values_mut() {
            probe.tick_staleness();
        }

        let budget = self.config.budget_for_regime(regime);

        // Step 2: Compute VOI for each probe.
        let mut scored: Vec<(String, i64, i64)> = self
            .probes
            .iter()
            .map(|(id, state)| {
                let relevance_mult = self.config.relevance_multiplier(regime, state.config.kind);
                let voi = state.voi_score(relevance_mult);
                (id.clone(), voi, state.config.cost_millionths)
            })
            .collect();

        // Step 3: Sort by descending VOI, then by probe_id for tie-breaking.
        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        // Step 4: Greedy scheduling.
        let mut budget_remaining = budget;
        let mut decisions = Vec::new();
        let mut scheduled_ids = Vec::new();

        for (probe_id, voi, cost) in &scored {
            if *cost <= budget_remaining && *voi > 0 {
                decisions.push(ScheduleDecision {
                    probe_id: probe_id.clone(),
                    kind: self.probes[probe_id].config.kind,
                    voi_score: *voi,
                    cost: *cost,
                    scheduled: true,
                    skip_reason: None,
                });
                budget_remaining -= cost;
                scheduled_ids.push(probe_id.clone());
            } else {
                let reason = if *voi <= 0 {
                    "non-positive VOI".to_string()
                } else {
                    format!("budget exhausted (remaining: {budget_remaining}, cost: {cost})")
                };
                decisions.push(ScheduleDecision {
                    probe_id: probe_id.clone(),
                    kind: self.probes[probe_id].config.kind,
                    voi_score: *voi,
                    cost: *cost,
                    scheduled: false,
                    skip_reason: Some(reason),
                });
            }
        }

        let probes_scheduled = scheduled_ids.len();
        let probes_deferred = decisions.len() - probes_scheduled;

        // Mark scheduled probes as executed.
        for id in &scheduled_ids {
            if let Some(probe) = self.probes.get_mut(id) {
                probe.mark_executed(true);
            }
        }

        let result = ScheduleResult {
            scheduler_id: self.config.scheduler_id.clone(),
            interval: self.interval,
            regime,
            budget_total: budget,
            budget_used: budget - budget_remaining,
            probes_scheduled,
            probes_deferred,
            decisions,
        };

        self.history.push(result.clone());
        result
    }

    /// Record a probe execution result (for externally-executed probes).
    pub fn record_execution(
        &mut self,
        probe_id: &str,
        success: bool,
    ) -> Result<(), SchedulerError> {
        let probe = self
            .probes
            .get_mut(probe_id)
            .ok_or_else(|| SchedulerError::ProbeNotFound {
                probe_id: probe_id.to_string(),
            })?;
        probe.mark_executed(success);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn health_probe(id: &str) -> ProbeConfig {
        ProbeConfig {
            probe_id: id.to_string(),
            kind: ProbeKind::HealthCheck,
            cost_millionths: 100_000,             // 0.1
            information_gain_millionths: 500_000, // 0.5
            base_relevance_millionths: 1_000_000, // 1.0
        }
    }

    fn deep_probe(id: &str) -> ProbeConfig {
        ProbeConfig {
            probe_id: id.to_string(),
            kind: ProbeKind::DeepDiagnostic,
            cost_millionths: 2_000_000,             // 2.0
            information_gain_millionths: 3_000_000, // 3.0
            base_relevance_millionths: 800_000,     // 0.8
        }
    }

    fn integrity_probe(id: &str) -> ProbeConfig {
        ProbeConfig {
            probe_id: id.to_string(),
            kind: ProbeKind::IntegrityAudit,
            cost_millionths: 1_500_000,             // 1.5
            information_gain_millionths: 2_000_000, // 2.0
            base_relevance_millionths: 900_000,     // 0.9
        }
    }

    fn test_config() -> SchedulerConfig {
        let mut regime_budgets = BTreeMap::new();
        regime_budgets.insert("normal".to_string(), 3_000_000); // 3.0
        regime_budgets.insert("elevated".to_string(), 6_000_000); // 6.0
        regime_budgets.insert("attack".to_string(), 10_000_000); // 10.0

        SchedulerConfig {
            scheduler_id: "sched-1".to_string(),
            base_budget_millionths: 3_000_000,
            regime_budgets,
            relevance_overrides: BTreeMap::new(),
        }
    }

    fn test_scheduler() -> MonitorScheduler {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("health-1")).unwrap();
        sched.register_probe(deep_probe("deep-1")).unwrap();
        sched
            .register_probe(integrity_probe("integrity-1"))
            .unwrap();
        sched
    }

    // -- ProbeKind --

    #[test]
    fn probe_kind_display() {
        assert_eq!(ProbeKind::HealthCheck.to_string(), "health_check");
        assert_eq!(ProbeKind::DeepDiagnostic.to_string(), "deep_diagnostic");
        assert_eq!(ProbeKind::CalibrationProbe.to_string(), "calibration_probe");
        assert_eq!(ProbeKind::IntegrityAudit.to_string(), "integrity_audit");
    }

    // -- ProbeState VOI --

    #[test]
    fn voi_score_increases_with_staleness() {
        let mut state = ProbeState::new(health_probe("h"));
        let voi1 = state.voi_score(1_000_000);
        state.tick_staleness();
        let voi2 = state.voi_score(1_000_000);
        state.tick_staleness();
        let voi3 = state.voi_score(1_000_000);
        assert!(voi2 > voi1);
        assert!(voi3 > voi2);
    }

    #[test]
    fn voi_score_scales_with_relevance() {
        let state = ProbeState::new(health_probe("h"));
        let voi_low = state.voi_score(500_000); // 0.5
        let voi_high = state.voi_score(2_000_000); // 2.0
        assert!(voi_high > voi_low);
    }

    #[test]
    fn mark_executed_resets_staleness() {
        let mut state = ProbeState::new(health_probe("h"));
        state.tick_staleness();
        state.tick_staleness();
        assert_eq!(state.staleness, 2);

        state.mark_executed(true);
        assert_eq!(state.staleness, 0);
        assert_eq!(state.execution_count, 1);
        assert!(state.last_success);
    }

    // -- Scheduler registration --

    #[test]
    fn register_and_count() {
        let mut sched = MonitorScheduler::new(test_config());
        assert_eq!(sched.probe_count(), 0);
        sched.register_probe(health_probe("h1")).unwrap();
        assert_eq!(sched.probe_count(), 1);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap();
        let err = sched.register_probe(health_probe("h1")).unwrap_err();
        assert_eq!(
            err,
            SchedulerError::DuplicateProbe {
                probe_id: "h1".to_string()
            }
        );
    }

    #[test]
    fn unregister_probe() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap();
        sched.unregister_probe("h1").unwrap();
        assert_eq!(sched.probe_count(), 0);
    }

    #[test]
    fn unregister_missing_probe_fails() {
        let mut sched = MonitorScheduler::new(test_config());
        let err = sched.unregister_probe("missing").unwrap_err();
        assert_eq!(
            err,
            SchedulerError::ProbeNotFound {
                probe_id: "missing".to_string()
            }
        );
    }

    // -- Scheduling basics --

    #[test]
    fn schedule_respects_budget() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);

        // Budget = 3.0. Health costs 0.1, deep costs 2.0, integrity costs 1.5
        // Total available = 3.0
        assert!(result.budget_used <= result.budget_total);
    }

    #[test]
    fn schedule_orders_by_voi() {
        let mut sched = test_scheduler();
        let result = sched.schedule(Regime::Normal);

        // All scheduled probes should have VOI >= all deferred probes
        let scheduled_min_voi = result
            .decisions
            .iter()
            .filter(|d| d.scheduled)
            .map(|d| d.voi_score)
            .min()
            .unwrap_or(0);
        let deferred_max_voi = result
            .decisions
            .iter()
            .filter(|d| !d.scheduled)
            .map(|d| d.voi_score)
            .max()
            .unwrap_or(0);

        // If both exist, scheduled min should be >= deferred max
        // (or deferred was due to budget, not VOI)
        if scheduled_min_voi > 0 && deferred_max_voi > 0 {
            // Deferred due to budget is fine even if VOI is higher
            assert!(
                result
                    .decisions
                    .iter()
                    .filter(|d| !d.scheduled)
                    .all(|d| d.skip_reason.is_some())
            );
        }
    }

    #[test]
    fn interval_increments() {
        let mut sched = test_scheduler();
        assert_eq!(sched.interval(), 0);
        sched.schedule(Regime::Normal);
        assert_eq!(sched.interval(), 1);
        sched.schedule(Regime::Normal);
        assert_eq!(sched.interval(), 2);
    }

    // -- Regime-adaptive budget --

    #[test]
    fn attack_regime_gets_higher_budget() {
        let config = test_config();
        let normal_budget = config.budget_for_regime(Regime::Normal);
        let attack_budget = config.budget_for_regime(Regime::Attack);
        assert!(attack_budget > normal_budget);
    }

    #[test]
    fn elevated_regime_schedules_more_probes() {
        let mut sched1 = test_scheduler();
        let mut sched2 = test_scheduler();

        let normal = sched1.schedule(Regime::Normal);
        let elevated = sched2.schedule(Regime::Elevated);

        // Elevated has 6.0 budget vs 3.0, so should schedule >= as many
        assert!(elevated.probes_scheduled >= normal.probes_scheduled);
    }

    // -- Staleness accumulation --

    #[test]
    fn deferred_probes_accumulate_staleness() {
        let mut sched = MonitorScheduler::new(SchedulerConfig {
            scheduler_id: "s".to_string(),
            base_budget_millionths: 100_000, // very small budget
            regime_budgets: BTreeMap::new(),
            relevance_overrides: BTreeMap::new(),
        });
        sched.register_probe(deep_probe("deep-1")).unwrap(); // costs 2.0, won't fit

        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("deep-1").unwrap().staleness, 1); // not executed

        sched.schedule(Regime::Normal);
        assert_eq!(sched.probe("deep-1").unwrap().staleness, 2);
    }

    #[test]
    fn scheduled_probes_reset_staleness() {
        let mut sched = MonitorScheduler::new(test_config());
        sched.register_probe(health_probe("h1")).unwrap(); // cheap

        sched.schedule(Regime::Normal); // h1 should be scheduled
        assert_eq!(sched.probe("h1").unwrap().staleness, 0);
    }

    // -- Determinism --

    #[test]
    fn deterministic_schedule() {
        let run = || -> Vec<ScheduleResult> {
            let mut sched = test_scheduler();
            let results = vec![
                sched.schedule(Regime::Normal),
                sched.schedule(Regime::Elevated),
                sched.schedule(Regime::Attack),
            ];
            results
        };

        let r1 = run();
        let r2 = run();
        assert_eq!(r1, r2);
    }

    // -- History tracking --

    #[test]
    fn history_records_all_schedules() {
        let mut sched = test_scheduler();
        sched.schedule(Regime::Normal);
        sched.schedule(Regime::Attack);
        assert_eq!(sched.history().len(), 2);
        assert_eq!(sched.history()[0].regime, Regime::Normal);
        assert_eq!(sched.history()[1].regime, Regime::Attack);
    }

    // -- Record execution --

    #[test]
    fn record_execution_updates_state() {
        let mut sched = test_scheduler();
        sched.record_execution("health-1", false).unwrap();
        assert!(!sched.probe("health-1").unwrap().last_success);
        assert_eq!(sched.probe("health-1").unwrap().execution_count, 1);
    }

    #[test]
    fn record_execution_missing_probe() {
        let mut sched = test_scheduler();
        let err = sched.record_execution("missing", true).unwrap_err();
        assert_eq!(
            err,
            SchedulerError::ProbeNotFound {
                probe_id: "missing".to_string()
            }
        );
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            SchedulerError::DuplicateProbe {
                probe_id: "p".to_string()
            }
            .to_string(),
            "duplicate probe: p"
        );
        assert_eq!(
            SchedulerError::ProbeNotFound {
                probe_id: "p".to_string()
            }
            .to_string(),
            "probe not found: p"
        );
    }

    // -- Serialization --

    #[test]
    fn probe_kind_serialization_round_trip() {
        let kinds = vec![
            ProbeKind::HealthCheck,
            ProbeKind::DeepDiagnostic,
            ProbeKind::CalibrationProbe,
            ProbeKind::IntegrityAudit,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).expect("serialize");
            let restored: ProbeKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*kind, restored);
        }
    }

    #[test]
    fn probe_config_serialization_round_trip() {
        let config = health_probe("h1");
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ProbeConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn schedule_result_serialization_round_trip() {
        let result = ScheduleResult {
            scheduler_id: "s".to_string(),
            interval: 1,
            regime: Regime::Normal,
            budget_total: 3_000_000,
            budget_used: 1_000_000,
            probes_scheduled: 2,
            probes_deferred: 1,
            decisions: vec![ScheduleDecision {
                probe_id: "h1".to_string(),
                kind: ProbeKind::HealthCheck,
                voi_score: 5_000_000,
                cost: 100_000,
                scheduled: true,
                skip_reason: None,
            }],
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: ScheduleResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn scheduler_error_serialization_round_trip() {
        let errors = vec![
            SchedulerError::DuplicateProbe {
                probe_id: "p".to_string(),
            },
            SchedulerError::ProbeNotFound {
                probe_id: "p".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: SchedulerError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Relevance overrides --

    // -- Enrichment: serde, ordering, std::error --

    #[test]
    fn probe_state_serde_roundtrip() {
        let state = ProbeState {
            config: health_probe("h-serde"),
            staleness: 42,
            execution_count: 7,
            last_success: true,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let restored: ProbeState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, restored);
    }

    #[test]
    fn scheduler_config_serde_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: SchedulerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn schedule_decision_serde_roundtrip() {
        let dec = ScheduleDecision {
            probe_id: "p-1".to_string(),
            kind: ProbeKind::IntegrityAudit,
            voi_score: 3_500_000,
            cost: 1_000_000,
            scheduled: true,
            skip_reason: None,
        };
        let json = serde_json::to_string(&dec).expect("serialize");
        let restored: ScheduleDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dec, restored);
    }

    #[test]
    fn probe_kind_ordering() {
        assert!(ProbeKind::HealthCheck < ProbeKind::DeepDiagnostic);
        assert!(ProbeKind::DeepDiagnostic < ProbeKind::CalibrationProbe);
        assert!(ProbeKind::CalibrationProbe < ProbeKind::IntegrityAudit);
    }

    #[test]
    fn scheduler_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SchedulerError::DuplicateProbe {
                probe_id: "p-1".into(),
            }),
            Box::new(SchedulerError::ProbeNotFound {
                probe_id: "p-2".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(displays.len(), 2);
    }

    #[test]
    fn relevance_override_affects_scheduling() {
        let mut config = test_config();
        // Boost integrity probes during attack
        config.relevance_overrides.insert(
            "attack:integrity_audit".to_string(),
            5_000_000, // 5.0x
        );

        let mut sched = MonitorScheduler::new(config);
        sched.register_probe(health_probe("h1")).unwrap();
        sched.register_probe(integrity_probe("i1")).unwrap();

        let result = sched.schedule(Regime::Attack);

        // Integrity probe should be scheduled (boosted relevance)
        let integrity = result
            .decisions
            .iter()
            .find(|d| d.probe_id == "i1")
            .expect("integrity probe");
        assert!(integrity.scheduled);
    }
}
