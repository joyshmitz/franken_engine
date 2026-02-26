//! Cancellation checkpoint contract for long-running loops.
//!
//! Every long-running loop (dispatch, scanning, policy iteration, replay,
//! decode/verify) must contain well-defined checkpoint sites where the
//! runtime checks for pending cancellation and transitions to drain/finalize.
//!
//! Checkpoint density is enforced: no loop may exceed `max_iterations`
//! without hitting a checkpoint.
//!
//! Plan references: Section 10.11 item 3, 9G.2 (cancellation as protocol),
//! Top-10 #3 (deterministic evidence graph + replay), #8 (budget).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CheckpointReason — why the checkpoint fired
// ---------------------------------------------------------------------------

/// Reason a checkpoint was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CheckpointReason {
    /// Periodic checkpoint (iteration count hit density bound).
    Periodic,
    /// Cancellation is pending.
    CancelPending,
    /// Iteration budget exhausted.
    BudgetExhausted,
    /// Explicit checkpoint inserted by the loop body.
    Explicit,
}

impl fmt::Display for CheckpointReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Periodic => write!(f, "periodic"),
            Self::CancelPending => write!(f, "cancel_pending"),
            Self::BudgetExhausted => write!(f, "budget_exhausted"),
            Self::Explicit => write!(f, "explicit"),
        }
    }
}

// ---------------------------------------------------------------------------
// CheckpointAction — what the loop should do
// ---------------------------------------------------------------------------

/// Action the loop should take after a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointAction {
    /// Continue execution.
    Continue,
    /// Transition to drain state (cancellation pending).
    Drain,
    /// Abort immediately (budget exhausted, hard limit).
    Abort,
}

// ---------------------------------------------------------------------------
// LoopSite — identifies a specific checkpoint-instrumented loop
// ---------------------------------------------------------------------------

/// Identifies a specific long-running loop site for checkpoint tracking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LoopSite {
    /// Bytecode dispatch loop.
    BytecodeDispatch,
    /// GC scanning/mark phase.
    GcScanning,
    /// GC sweep phase.
    GcSweep,
    /// Policy iteration loop.
    PolicyIteration,
    /// Decision-contract evaluation loop.
    ContractEvaluation,
    /// Deterministic replay step loop.
    ReplayStep,
    /// Module decode pass.
    ModuleDecode,
    /// Module verification pass.
    ModuleVerify,
    /// IR lowering pass.
    IrLowering,
    /// IR compilation pass.
    IrCompilation,
    /// Custom loop site with identifier.
    Custom(String),
}

impl fmt::Display for LoopSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BytecodeDispatch => write!(f, "bytecode_dispatch"),
            Self::GcScanning => write!(f, "gc_scanning"),
            Self::GcSweep => write!(f, "gc_sweep"),
            Self::PolicyIteration => write!(f, "policy_iteration"),
            Self::ContractEvaluation => write!(f, "contract_evaluation"),
            Self::ReplayStep => write!(f, "replay_step"),
            Self::ModuleDecode => write!(f, "module_decode"),
            Self::ModuleVerify => write!(f, "module_verify"),
            Self::IrLowering => write!(f, "ir_lowering"),
            Self::IrCompilation => write!(f, "ir_compilation"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CheckpointEvent — structured event for evidence/replay
// ---------------------------------------------------------------------------

/// Structured event emitted at each checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointEvent {
    /// Trace identifier for correlation.
    pub trace_id: String,
    /// Component that owns this loop.
    pub component: String,
    /// Loop site identifier.
    pub loop_site: LoopSite,
    /// Iteration count since last checkpoint.
    pub iteration_count: u64,
    /// Total iterations in this loop invocation.
    pub total_iterations: u64,
    /// Why this checkpoint fired.
    pub reason: CheckpointReason,
    /// What action was taken.
    pub action: CheckpointAction,
    /// Virtual timestamp (for deterministic replay).
    pub timestamp_virtual: u64,
}

// ---------------------------------------------------------------------------
// DensityConfig — checkpoint density policy
// ---------------------------------------------------------------------------

/// Checkpoint density policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DensityConfig {
    /// Maximum iterations between checkpoints.
    pub max_iterations: u64,
    /// Maximum total iterations before budget exhaustion.
    pub max_total_iterations: u64,
}

impl Default for DensityConfig {
    fn default() -> Self {
        Self {
            max_iterations: 1024,
            max_total_iterations: 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// CancellationToken — shared cancellation signal
// ---------------------------------------------------------------------------

/// Shared cancellation token that loops check at checkpoint sites.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a new non-cancelled token.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Reset the token (for reuse after drain/finalize).
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Release);
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CheckpointGuard — per-loop checkpoint tracker
// ---------------------------------------------------------------------------

/// Tracks checkpoint density within a single loop invocation.
///
/// Call `tick()` on each iteration and `check()` to determine if a
/// checkpoint should fire and what action to take.
#[derive(Debug)]
pub struct CheckpointGuard {
    loop_site: LoopSite,
    component: String,
    trace_id: String,
    config: DensityConfig,
    token: CancellationToken,
    /// Iterations since last checkpoint.
    iterations_since_checkpoint: u64,
    /// Total iterations in this loop invocation.
    total_iterations: u64,
    /// Virtual time counter.
    virtual_time: u64,
    /// Accumulated events.
    events: Vec<CheckpointEvent>,
}

impl CheckpointGuard {
    /// Create a new checkpoint guard for a loop.
    pub fn new(
        loop_site: LoopSite,
        component: impl Into<String>,
        trace_id: impl Into<String>,
        config: DensityConfig,
        token: CancellationToken,
    ) -> Self {
        Self {
            loop_site,
            component: component.into(),
            trace_id: trace_id.into(),
            config,
            token,
            iterations_since_checkpoint: 0,
            total_iterations: 0,
            virtual_time: 0,
            events: Vec::new(),
        }
    }

    /// Advance the iteration counter.
    pub fn tick(&mut self) {
        self.iterations_since_checkpoint += 1;
        self.total_iterations += 1;
        self.virtual_time += 1;
    }

    /// Check if a checkpoint should fire and what action to take.
    ///
    /// Call after `tick()` on each iteration.
    pub fn check(&mut self) -> CheckpointAction {
        // Priority 1: cancellation pending
        if self.token.is_cancelled() {
            let action = CheckpointAction::Drain;
            self.emit_event(CheckpointReason::CancelPending, action);
            self.iterations_since_checkpoint = 0;
            return action;
        }

        // Priority 2: total budget exhausted
        if self.total_iterations >= self.config.max_total_iterations {
            let action = CheckpointAction::Abort;
            self.emit_event(CheckpointReason::BudgetExhausted, action);
            self.iterations_since_checkpoint = 0;
            return action;
        }

        // Priority 3: density bound reached
        if self.iterations_since_checkpoint >= self.config.max_iterations {
            let action = CheckpointAction::Continue;
            self.emit_event(CheckpointReason::Periodic, action);
            self.iterations_since_checkpoint = 0;
            return action;
        }

        CheckpointAction::Continue
    }

    /// Insert an explicit checkpoint (e.g., at a logical boundary).
    pub fn explicit_checkpoint(&mut self) -> CheckpointAction {
        let action = if self.token.is_cancelled() {
            CheckpointAction::Drain
        } else {
            CheckpointAction::Continue
        };
        self.emit_event(CheckpointReason::Explicit, action);
        self.iterations_since_checkpoint = 0;
        action
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<CheckpointEvent> {
        std::mem::take(&mut self.events)
    }

    /// Total iterations executed.
    pub fn total_iterations(&self) -> u64 {
        self.total_iterations
    }

    /// Current virtual time.
    pub fn virtual_time(&self) -> u64 {
        self.virtual_time
    }

    /// Number of events emitted.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn emit_event(&mut self, reason: CheckpointReason, action: CheckpointAction) {
        self.events.push(CheckpointEvent {
            trace_id: self.trace_id.clone(),
            component: self.component.clone(),
            loop_site: self.loop_site.clone(),
            iteration_count: self.iterations_since_checkpoint,
            total_iterations: self.total_iterations,
            reason,
            action,
            timestamp_virtual: self.virtual_time,
        });
    }
}

// ---------------------------------------------------------------------------
// CheckpointCoverage — static verification of checkpoint placement
// ---------------------------------------------------------------------------

/// Records which loop sites have checkpoint instrumentation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointCoverage {
    /// Map from loop site name -> whether it has checkpoint instrumentation.
    coverage: BTreeMap<String, bool>,
}

impl CheckpointCoverage {
    /// Create a new coverage tracker with all mandatory sites unregistered.
    pub fn new() -> Self {
        let mut coverage = BTreeMap::new();
        let mandatory = [
            "bytecode_dispatch",
            "gc_scanning",
            "gc_sweep",
            "policy_iteration",
            "contract_evaluation",
            "replay_step",
            "module_decode",
            "module_verify",
            "ir_lowering",
            "ir_compilation",
        ];
        for site in mandatory {
            coverage.insert(site.to_string(), false);
        }
        Self { coverage }
    }

    /// Mark a loop site as having checkpoint instrumentation.
    pub fn register(&mut self, site: &str) {
        self.coverage.insert(site.to_string(), true);
    }

    /// Check if all mandatory sites are covered.
    pub fn all_covered(&self) -> bool {
        self.coverage.values().all(|&v| v)
    }

    /// Get uncovered sites.
    pub fn uncovered(&self) -> Vec<String> {
        self.coverage
            .iter()
            .filter(|&(_, &v)| !v)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Total mandatory sites.
    pub fn total(&self) -> usize {
        self.coverage.len()
    }

    /// Number of covered sites.
    pub fn covered_count(&self) -> usize {
        self.coverage.values().filter(|&&v| v).count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guard() -> (CheckpointGuard, CancellationToken) {
        let token = CancellationToken::new();
        let guard = CheckpointGuard::new(
            LoopSite::PolicyIteration,
            "policy_controller",
            "trace-1",
            DensityConfig {
                max_iterations: 10,
                max_total_iterations: 100,
            },
            token.clone(),
        );
        (guard, token)
    }

    // -- CheckpointReason --

    #[test]
    fn reason_display() {
        assert_eq!(CheckpointReason::Periodic.to_string(), "periodic");
        assert_eq!(
            CheckpointReason::CancelPending.to_string(),
            "cancel_pending"
        );
        assert_eq!(
            CheckpointReason::BudgetExhausted.to_string(),
            "budget_exhausted"
        );
        assert_eq!(CheckpointReason::Explicit.to_string(), "explicit");
    }

    // -- LoopSite --

    #[test]
    fn loop_site_display() {
        assert_eq!(LoopSite::BytecodeDispatch.to_string(), "bytecode_dispatch");
        assert_eq!(LoopSite::GcScanning.to_string(), "gc_scanning");
        assert_eq!(
            LoopSite::Custom("test".to_string()).to_string(),
            "custom:test"
        );
    }

    // -- CancellationToken --

    #[test]
    fn token_starts_not_cancelled() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancel_sets_flag() {
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn reset_clears_flag() {
        let token = CancellationToken::new();
        token.cancel();
        token.reset();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cloned_tokens_share_state() {
        let token1 = CancellationToken::new();
        let token2 = token1.clone();
        token1.cancel();
        assert!(token2.is_cancelled());
    }

    // -- CheckpointGuard: periodic checkpoints --

    #[test]
    fn periodic_checkpoint_at_density_bound() {
        let (mut guard, _token) = test_guard();

        // Run 9 iterations — no checkpoint event yet
        for _ in 0..9 {
            guard.tick();
            let action = guard.check();
            assert_eq!(action, CheckpointAction::Continue);
        }
        assert_eq!(guard.event_count(), 0);

        // 10th iteration hits density bound
        guard.tick();
        let action = guard.check();
        assert_eq!(action, CheckpointAction::Continue);
        assert_eq!(guard.event_count(), 1);

        let events = guard.drain_events();
        assert_eq!(events[0].reason, CheckpointReason::Periodic);
        assert_eq!(events[0].iteration_count, 10);
    }

    // -- CheckpointGuard: cancellation --

    #[test]
    fn cancel_detected_at_next_check() {
        let (mut guard, token) = test_guard();

        guard.tick();
        token.cancel();
        let action = guard.check();
        assert_eq!(action, CheckpointAction::Drain);

        let events = guard.drain_events();
        assert_eq!(events[0].reason, CheckpointReason::CancelPending);
    }

    #[test]
    fn cancel_detected_before_density_bound() {
        let (mut guard, token) = test_guard();

        // Only 3 iterations, well under density of 10
        for _ in 0..3 {
            guard.tick();
        }
        token.cancel();
        let action = guard.check();
        assert_eq!(action, CheckpointAction::Drain);
    }

    // -- CheckpointGuard: budget exhaustion --

    #[test]
    fn budget_exhaustion_triggers_abort() {
        let token = CancellationToken::new();
        let mut guard = CheckpointGuard::new(
            LoopSite::GcScanning,
            "gc",
            "t",
            DensityConfig {
                max_iterations: 50,
                max_total_iterations: 100,
            },
            token,
        );

        for _ in 0..100 {
            guard.tick();
            guard.check(); // periodic checkpoints at 50, budget at 100
        }

        let action = guard.check();
        assert_eq!(action, CheckpointAction::Abort);

        let events = guard.drain_events();
        let budget_events: Vec<_> = events
            .iter()
            .filter(|e| e.reason == CheckpointReason::BudgetExhausted)
            .collect();
        assert!(!budget_events.is_empty());
    }

    // -- CheckpointGuard: explicit checkpoint --

    #[test]
    fn explicit_checkpoint_resets_counter() {
        let (mut guard, _token) = test_guard();

        for _ in 0..5 {
            guard.tick();
        }
        let action = guard.explicit_checkpoint();
        assert_eq!(action, CheckpointAction::Continue);

        // Counter reset, so another 10 iterations needed for periodic
        for _ in 0..9 {
            guard.tick();
            guard.check();
        }
        // At iteration 9 after reset, no periodic yet
        assert_eq!(
            guard
                .drain_events()
                .iter()
                .filter(|e| e.reason == CheckpointReason::Periodic)
                .count(),
            0
        );
    }

    #[test]
    fn explicit_checkpoint_detects_cancel() {
        let (mut guard, token) = test_guard();
        token.cancel();
        let action = guard.explicit_checkpoint();
        assert_eq!(action, CheckpointAction::Drain);
    }

    // -- CheckpointGuard: event structure --

    #[test]
    fn event_carries_correct_fields() {
        let (mut guard, _) = test_guard();
        for _ in 0..10 {
            guard.tick();
        }
        guard.check();

        let events = guard.drain_events();
        let event = &events[0];
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.component, "policy_controller");
        assert_eq!(event.loop_site, LoopSite::PolicyIteration);
        assert_eq!(event.total_iterations, 10);
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_checkpoint_sequence() {
        let run = |cancel_at: Option<u64>| -> Vec<CheckpointEvent> {
            let token = CancellationToken::new();
            let mut guard = CheckpointGuard::new(
                LoopSite::ReplayStep,
                "replay",
                "t",
                DensityConfig {
                    max_iterations: 5,
                    max_total_iterations: 50,
                },
                token.clone(),
            );

            for i in 0..25 {
                guard.tick();
                if cancel_at == Some(i) {
                    token.cancel();
                }
                let action = guard.check();
                if action == CheckpointAction::Drain || action == CheckpointAction::Abort {
                    break;
                }
            }
            guard.drain_events()
        };

        let events1 = run(None);
        let events2 = run(None);
        assert_eq!(events1, events2);

        let events_cancel1 = run(Some(12));
        let events_cancel2 = run(Some(12));
        assert_eq!(events_cancel1, events_cancel2);
    }

    // -- CheckpointCoverage --

    #[test]
    fn new_coverage_has_all_mandatory_uncovered() {
        let cov = CheckpointCoverage::new();
        assert!(!cov.all_covered());
        assert_eq!(cov.total(), 10);
        assert_eq!(cov.covered_count(), 0);
    }

    #[test]
    fn registering_all_sites_gives_full_coverage() {
        let mut cov = CheckpointCoverage::new();
        for site in cov.uncovered() {
            cov.register(&site);
        }
        assert!(cov.all_covered());
        assert_eq!(cov.covered_count(), cov.total());
    }

    #[test]
    fn uncovered_returns_missing_sites() {
        let mut cov = CheckpointCoverage::new();
        cov.register("bytecode_dispatch");
        cov.register("gc_scanning");

        let uncov = cov.uncovered();
        assert!(!uncov.contains(&"bytecode_dispatch".to_string()));
        assert!(!uncov.contains(&"gc_scanning".to_string()));
        assert!(uncov.contains(&"gc_sweep".to_string()));
    }

    // -- Serialization --

    #[test]
    fn checkpoint_reason_serialization_round_trip() {
        let reasons = vec![
            CheckpointReason::Periodic,
            CheckpointReason::CancelPending,
            CheckpointReason::BudgetExhausted,
            CheckpointReason::Explicit,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).expect("serialize");
            let restored: CheckpointReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*reason, restored);
        }
    }

    #[test]
    fn checkpoint_event_serialization_round_trip() {
        let event = CheckpointEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            loop_site: LoopSite::PolicyIteration,
            iteration_count: 10,
            total_iterations: 100,
            reason: CheckpointReason::Periodic,
            action: CheckpointAction::Continue,
            timestamp_virtual: 42,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: CheckpointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn density_config_serialization_round_trip() {
        let config = DensityConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: DensityConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn loop_site_serialization_round_trip() {
        let sites = vec![
            LoopSite::BytecodeDispatch,
            LoopSite::GcScanning,
            LoopSite::Custom("x".to_string()),
        ];
        for site in &sites {
            let json = serde_json::to_string(site).expect("serialize");
            let restored: LoopSite = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*site, restored);
        }
    }

    // -- Enrichment: serde & Display --

    #[test]
    fn checkpoint_action_serde_all_variants() {
        for action in [
            CheckpointAction::Continue,
            CheckpointAction::Drain,
            CheckpointAction::Abort,
        ] {
            let json = serde_json::to_string(&action).expect("serialize");
            let restored: CheckpointAction = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(action, restored);
        }
    }

    #[test]
    fn loop_site_display_all_variants() {
        let sites = vec![
            (LoopSite::BytecodeDispatch, "bytecode_dispatch"),
            (LoopSite::GcScanning, "gc_scanning"),
            (LoopSite::GcSweep, "gc_sweep"),
            (LoopSite::PolicyIteration, "policy_iteration"),
            (LoopSite::ContractEvaluation, "contract_evaluation"),
            (LoopSite::ReplayStep, "replay_step"),
            (LoopSite::ModuleDecode, "module_decode"),
            (LoopSite::ModuleVerify, "module_verify"),
            (LoopSite::IrLowering, "ir_lowering"),
            (LoopSite::IrCompilation, "ir_compilation"),
            (LoopSite::Custom("mysite".to_string()), "custom:mysite"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (site, expected) in &sites {
            let display = format!("{site}");
            assert_eq!(&display, *expected);
            seen.insert(display);
        }
        assert_eq!(seen.len(), 11, "all 11 variants produce distinct strings");
    }

    #[test]
    fn coverage_serialization_round_trip() {
        let mut cov = CheckpointCoverage::new();
        cov.register("bytecode_dispatch");
        let json = serde_json::to_string(&cov).expect("serialize");
        let restored: CheckpointCoverage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cov, restored);
    }

    // --- enrichment tests ---

    #[test]
    fn density_config_default_values() {
        let cfg = DensityConfig::default();
        assert_eq!(cfg.max_iterations, 1024);
        assert_eq!(cfg.max_total_iterations, 1_000_000);
    }

    #[test]
    fn guard_virtual_time_advances_with_tick() {
        let (mut guard, _) = test_guard();
        assert_eq!(guard.virtual_time(), 0);
        guard.tick();
        assert_eq!(guard.virtual_time(), 1);
        guard.tick();
        guard.tick();
        assert_eq!(guard.virtual_time(), 3);
    }

    #[test]
    fn guard_total_iterations_accessor() {
        let (mut guard, _) = test_guard();
        assert_eq!(guard.total_iterations(), 0);
        for _ in 0..7 {
            guard.tick();
        }
        assert_eq!(guard.total_iterations(), 7);
    }

    #[test]
    fn multiple_periodic_checkpoints_in_one_loop() {
        let (mut guard, _) = test_guard(); // max_iterations=10
        for _ in 0..30 {
            guard.tick();
            guard.check();
        }
        let events = guard.drain_events();
        let periodic_count = events
            .iter()
            .filter(|e| e.reason == CheckpointReason::Periodic)
            .count();
        assert_eq!(periodic_count, 3);
    }

    #[test]
    fn cancel_takes_priority_over_budget_exhaustion() {
        let token = CancellationToken::new();
        let mut guard = CheckpointGuard::new(
            LoopSite::GcScanning,
            "gc",
            "t",
            DensityConfig {
                max_iterations: 50,
                max_total_iterations: 10,
            },
            token.clone(),
        );
        for _ in 0..10 {
            guard.tick();
        }
        token.cancel();
        let action = guard.check();
        assert_eq!(action, CheckpointAction::Drain);
        let events = guard.drain_events();
        assert_eq!(
            events.last().unwrap().reason,
            CheckpointReason::CancelPending
        );
    }

    #[test]
    fn drain_events_clears_buffer() {
        let (mut guard, _) = test_guard();
        for _ in 0..10 {
            guard.tick();
        }
        guard.check();
        assert_eq!(guard.event_count(), 1);
        let _ = guard.drain_events();
        assert_eq!(guard.event_count(), 0);
    }

    #[test]
    fn coverage_register_custom_site_outside_mandatory() {
        let mut cov = CheckpointCoverage::new();
        let initial_total = cov.total();
        cov.register("my_custom_loop");
        assert_eq!(cov.total(), initial_total + 1);
        assert!(cov.coverage.get("my_custom_loop") == Some(&true));
    }

    #[test]
    fn coverage_default_is_empty() {
        let cov = CheckpointCoverage::default();
        assert!(cov.all_covered());
        assert_eq!(cov.total(), 0);
    }

    #[test]
    fn guard_with_custom_loop_site() {
        let token = CancellationToken::new();
        let mut guard = CheckpointGuard::new(
            LoopSite::Custom("my_scan".to_string()),
            "scanner",
            "t-scan",
            DensityConfig {
                max_iterations: 2,
                max_total_iterations: 100,
            },
            token,
        );
        guard.tick();
        guard.tick();
        guard.check();
        let events = guard.drain_events();
        assert_eq!(events[0].loop_site, LoopSite::Custom("my_scan".to_string()));
    }

    #[test]
    fn guard_max_iterations_one_fires_every_tick() {
        let token = CancellationToken::new();
        let mut guard = CheckpointGuard::new(
            LoopSite::ModuleDecode,
            "decoder",
            "t",
            DensityConfig {
                max_iterations: 1,
                max_total_iterations: 100,
            },
            token,
        );
        for _ in 0..5 {
            guard.tick();
            guard.check();
        }
        let events = guard.drain_events();
        assert_eq!(events.len(), 5);
        assert!(
            events
                .iter()
                .all(|e| e.reason == CheckpointReason::Periodic)
        );
    }

    #[test]
    fn checkpoint_reason_ordering() {
        assert!(CheckpointReason::Periodic < CheckpointReason::CancelPending);
        assert!(CheckpointReason::CancelPending < CheckpointReason::BudgetExhausted);
        assert!(CheckpointReason::BudgetExhausted < CheckpointReason::Explicit);
    }

    #[test]
    fn explicit_checkpoint_event_has_correct_reason() {
        let (mut guard, _) = test_guard();
        for _ in 0..3 {
            guard.tick();
        }
        guard.explicit_checkpoint();
        let events = guard.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, CheckpointReason::Explicit);
        assert_eq!(events[0].action, CheckpointAction::Continue);
        assert_eq!(events[0].iteration_count, 3);
    }

    #[test]
    fn token_default_is_not_cancelled() {
        let token = CancellationToken::default();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn event_virtual_timestamp_matches_guard_time() {
        let (mut guard, _) = test_guard();
        for _ in 0..10 {
            guard.tick();
        }
        guard.check();
        let events = guard.drain_events();
        assert_eq!(events[0].timestamp_virtual, 10);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, serde, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn checkpoint_reason_display_all_unique() {
        let reasons = [
            CheckpointReason::Periodic,
            CheckpointReason::CancelPending,
            CheckpointReason::BudgetExhausted,
            CheckpointReason::Explicit,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in &reasons {
            seen.insert(r.to_string());
        }
        assert_eq!(
            seen.len(),
            4,
            "all 4 CheckpointReason Display strings must be unique"
        );
    }

    #[test]
    fn checkpoint_action_equality() {
        assert_eq!(CheckpointAction::Continue, CheckpointAction::Continue);
        assert_ne!(CheckpointAction::Continue, CheckpointAction::Drain);
        assert_ne!(CheckpointAction::Drain, CheckpointAction::Abort);
    }

    #[test]
    fn checkpoint_event_serde_with_custom_loop_site() {
        let event = CheckpointEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            loop_site: LoopSite::Custom("my_custom".to_string()),
            iteration_count: 5,
            total_iterations: 50,
            reason: CheckpointReason::Explicit,
            action: CheckpointAction::Continue,
            timestamp_virtual: 100,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: CheckpointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn guard_no_events_before_checkpoint() {
        let (mut guard, _) = test_guard();
        for _ in 0..5 {
            guard.tick();
        }
        // No check() called — should have no events
        assert_eq!(guard.event_count(), 0);
    }

    #[test]
    fn guard_budget_check_reports_correct_total() {
        let token = CancellationToken::new();
        let mut guard = CheckpointGuard::new(
            LoopSite::ModuleVerify,
            "verifier",
            "t",
            DensityConfig {
                max_iterations: 1000,
                max_total_iterations: 50,
            },
            token,
        );
        for _ in 0..50 {
            guard.tick();
        }
        let action = guard.check();
        assert_eq!(action, CheckpointAction::Abort);
        assert_eq!(guard.total_iterations(), 50);
    }

    #[test]
    fn loop_site_serde_all_mandatory_variants() {
        let sites = [
            LoopSite::BytecodeDispatch,
            LoopSite::GcScanning,
            LoopSite::GcSweep,
            LoopSite::PolicyIteration,
            LoopSite::ContractEvaluation,
            LoopSite::ReplayStep,
            LoopSite::ModuleDecode,
            LoopSite::ModuleVerify,
            LoopSite::IrLowering,
            LoopSite::IrCompilation,
        ];
        for site in &sites {
            let json = serde_json::to_string(site).expect("serialize");
            let restored: LoopSite = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*site, restored);
        }
    }

    #[test]
    fn coverage_register_idempotent() {
        let mut cov = CheckpointCoverage::new();
        cov.register("bytecode_dispatch");
        cov.register("bytecode_dispatch");
        assert_eq!(cov.total(), 10); // no duplicate entries
        assert_eq!(cov.covered_count(), 1);
    }

    #[test]
    fn explicit_checkpoint_after_cancel_emits_drain() {
        let (mut guard, token) = test_guard();
        guard.tick();
        guard.tick();
        token.cancel();
        let action = guard.explicit_checkpoint();
        assert_eq!(action, CheckpointAction::Drain);
        let events = guard.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, CheckpointReason::Explicit);
        assert_eq!(events[0].action, CheckpointAction::Drain);
    }
}
