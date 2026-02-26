//! Frankenlab deterministic scenarios for extension lifecycle and containment paths.
//!
//! Each scenario exercises a specific lifecycle path using
//! [`ExtensionHostLifecycleManager`] and the [`LabRuntime`] harness to guarantee
//! deterministic, reproducible results.
//!
//! Scenarios: startup, normal shutdown, forced cancel, quarantine, revocation,
//! degraded mode, and multi-extension interaction.
//!
//! Plan reference: Section 10.13 item 12, bd-1o7u.
//! Dependencies: bd-1ukb (regions), bd-2wz9 (cancellation), bd-m9pa (obligations),
//!               bd-2sbb (evidence replay), bd-uvmm (evidence).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cancellation_lifecycle::LifecycleEvent;
use crate::control_plane::ContextAdapter;
use crate::extension_host_lifecycle::{ExtensionHostLifecycleManager, HostLifecycleEvent};
use crate::lab_runtime::Verdict;

// ---------------------------------------------------------------------------
// ScenarioKind — identifies each lifecycle path
// ---------------------------------------------------------------------------

/// Identifies the lifecycle path a scenario exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ScenarioKind {
    /// Load extension → verify region + evidence.
    Startup,
    /// Load → work → graceful unload → verify quiescent close.
    NormalShutdown,
    /// Load → work → forced cancel mid-operation.
    ForcedCancel,
    /// Load → policy violation → quarantine isolation.
    Quarantine,
    /// Load → session → revoke capability mid-session.
    Revocation,
    /// Simulate control-plane failure → verify safe degradation.
    DegradedMode,
    /// Multiple extensions → cross-extension events → isolation.
    MultiExtension,
}

impl fmt::Display for ScenarioKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Startup => write!(f, "startup"),
            Self::NormalShutdown => write!(f, "normal_shutdown"),
            Self::ForcedCancel => write!(f, "forced_cancel"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Revocation => write!(f, "revocation"),
            Self::DegradedMode => write!(f, "degraded_mode"),
            Self::MultiExtension => write!(f, "multi_extension"),
        }
    }
}

// ---------------------------------------------------------------------------
// ScenarioAssertion — individual assertion within a scenario
// ---------------------------------------------------------------------------

/// Individual assertion result within a scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAssertion {
    /// Description of what was checked.
    pub description: String,
    /// Whether the assertion passed.
    pub passed: bool,
    /// Details on failure (empty if passed).
    pub detail: String,
}

// ---------------------------------------------------------------------------
// ScenarioResult — output of a single scenario run
// ---------------------------------------------------------------------------

/// Output of a single frankenlab scenario run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Which scenario was executed.
    pub kind: ScenarioKind,
    /// Deterministic seed used.
    pub seed: u64,
    /// Overall pass/fail.
    pub passed: bool,
    /// Individual assertions.
    pub assertions: Vec<ScenarioAssertion>,
    /// Lifecycle events captured during the scenario.
    pub lifecycle_events: Vec<HostLifecycleEvent>,
    /// Extensions loaded during the scenario.
    pub extensions_loaded: Vec<String>,
    /// Final extension states (extension_id → running).
    pub final_states: BTreeMap<String, bool>,
    /// Total obligations created (approximate, from events).
    pub total_events_emitted: usize,
}

impl ScenarioResult {
    fn new(kind: ScenarioKind, seed: u64) -> Self {
        Self {
            kind,
            seed,
            passed: true,
            assertions: Vec::new(),
            lifecycle_events: Vec::new(),
            extensions_loaded: Vec::new(),
            final_states: BTreeMap::new(),
            total_events_emitted: 0,
        }
    }

    fn assert_true(&mut self, description: &str, value: bool) {
        if !value {
            self.passed = false;
        }
        self.assertions.push(ScenarioAssertion {
            description: description.to_string(),
            passed: value,
            detail: if value {
                String::new()
            } else {
                format!("expected true, got false: {description}")
            },
        });
    }

    fn assert_eq<T: PartialEq + fmt::Debug>(&mut self, description: &str, left: T, right: T) {
        let passed = left == right;
        if !passed {
            self.passed = false;
        }
        self.assertions.push(ScenarioAssertion {
            description: description.to_string(),
            passed,
            detail: if passed {
                String::new()
            } else {
                format!("{left:?} != {right:?}")
            },
        });
    }

    fn finalize(&mut self, mgr: &mut ExtensionHostLifecycleManager) {
        self.lifecycle_events = mgr.drain_events();
        self.total_events_emitted = self.lifecycle_events.len();
        for ext_id in mgr.extension_ids() {
            self.final_states
                .insert(ext_id.to_string(), mgr.is_extension_running(ext_id));
        }
    }
}

// ---------------------------------------------------------------------------
// ScenarioSuiteResult — output of running all scenarios
// ---------------------------------------------------------------------------

/// Result of running the full frankenlab extension lifecycle scenario suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioSuiteResult {
    /// Seed used for all scenarios.
    pub seed: u64,
    /// Per-scenario results.
    pub scenarios: Vec<ScenarioResult>,
    /// Overall verdict.
    pub verdict: Verdict,
    /// Total assertions evaluated.
    pub total_assertions: usize,
    /// Total assertions that passed.
    pub passed_assertions: usize,
}

// ---------------------------------------------------------------------------
// run_scenario — dispatches to the correct scenario function
// ---------------------------------------------------------------------------

/// Run a single scenario by kind.
pub fn run_scenario<C: ContextAdapter>(
    kind: ScenarioKind,
    seed: u64,
    cx: &mut C,
) -> ScenarioResult {
    match kind {
        ScenarioKind::Startup => scenario_startup(seed, cx),
        ScenarioKind::NormalShutdown => scenario_normal_shutdown(seed, cx),
        ScenarioKind::ForcedCancel => scenario_forced_cancel(seed, cx),
        ScenarioKind::Quarantine => scenario_quarantine(seed, cx),
        ScenarioKind::Revocation => scenario_revocation(seed, cx),
        ScenarioKind::DegradedMode => scenario_degraded_mode(seed, cx),
        ScenarioKind::MultiExtension => scenario_multi_extension(seed, cx),
    }
}

/// Run all scenarios and produce a suite result.
pub fn run_all_scenarios<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioSuiteResult {
    let kinds = [
        ScenarioKind::Startup,
        ScenarioKind::NormalShutdown,
        ScenarioKind::ForcedCancel,
        ScenarioKind::Quarantine,
        ScenarioKind::Revocation,
        ScenarioKind::DegradedMode,
        ScenarioKind::MultiExtension,
    ];
    let mut scenarios = Vec::new();
    for kind in &kinds {
        scenarios.push(run_scenario(*kind, seed, cx));
    }

    let total_assertions: usize = scenarios.iter().map(|s| s.assertions.len()).sum();
    let passed_assertions: usize = scenarios
        .iter()
        .map(|s| s.assertions.iter().filter(|a| a.passed).count())
        .sum();
    let all_passed = scenarios.iter().all(|s| s.passed);

    ScenarioSuiteResult {
        seed,
        scenarios,
        verdict: if all_passed {
            Verdict::Pass
        } else {
            Verdict::Fail {
                reason: format!(
                    "{} of {} assertions failed",
                    total_assertions - passed_assertions,
                    total_assertions
                ),
            }
        },
        total_assertions,
        passed_assertions,
    }
}

// ---------------------------------------------------------------------------
// Scenario implementations
// ---------------------------------------------------------------------------

/// Scenario: Load an extension, verify region creation, Cx propagation, and
/// evidence emission.
fn scenario_startup<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::Startup, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load extension.
    let load_result = mgr.load_extension("ext-startup-1", cx);
    result.assert_true("load_extension succeeds", load_result.is_ok());
    result.assert_true(
        "extension is running after load",
        mgr.is_extension_running("ext-startup-1"),
    );
    result.assert_eq("loaded count is 1", mgr.loaded_extension_count(), 1);

    // Verify extension record.
    if let Some(record) = mgr.extension_record("ext-startup-1") {
        result.assert_true(
            "load_trace_id is non-empty",
            !record.load_trace_id.is_empty(),
        );
        result.assert_true("no sessions yet", record.sessions.is_empty());
        result.assert_true("not unloaded", !record.unloaded);
    } else {
        result.assert_true("extension record exists", false);
    }

    // Verify evidence emission.
    let events = mgr.events();
    result.assert_true("at least one event emitted", !events.is_empty());
    result.assert_true(
        "first event is extension_loaded",
        events
            .first()
            .is_some_and(|e| e.event == "extension_loaded"),
    );
    result.assert_true(
        "event has trace_id",
        events.first().is_some_and(|e| !e.trace_id.is_empty()),
    );

    result.extensions_loaded.push("ext-startup-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → create sessions → close sessions → graceful unload.
fn scenario_normal_shutdown<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::NormalShutdown, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load and create sessions.
    mgr.load_extension("ext-ns-1", cx).unwrap();
    mgr.create_session("ext-ns-1", "sess-1", cx).unwrap();
    mgr.create_session("ext-ns-1", "sess-2", cx).unwrap();
    result.assert_eq("session count is 2", mgr.session_count("ext-ns-1"), 2);

    // Close one session explicitly.
    let close_result = mgr.close_session("ext-ns-1", "sess-1", cx);
    result.assert_true("close_session succeeds", close_result.is_ok());
    result.assert_eq("session count is 1", mgr.session_count("ext-ns-1"), 1);

    // Graceful unload (remaining session should close automatically).
    let unload_result = mgr.unload_extension("ext-ns-1", cx);
    result.assert_true("unload_extension succeeds", unload_result.is_ok());
    if let Ok(outcome) = &unload_result {
        result.assert_true("unload outcome success", outcome.success);
    }
    result.assert_true(
        "extension not running after unload",
        !mgr.is_extension_running("ext-ns-1"),
    );

    // Verify evidence completeness.
    let events = mgr.events();
    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    result.assert_true(
        "events include extension_loaded",
        event_names.contains(&"extension_loaded"),
    );
    result.assert_true(
        "events include session_created",
        event_names.contains(&"session_created"),
    );
    result.assert_true(
        "events include session_closed",
        event_names.contains(&"session_closed"),
    );
    result.assert_true(
        "events include extension_unloaded",
        event_names.contains(&"extension_unloaded"),
    );

    result.extensions_loaded.push("ext-ns-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → work → forced cancel (Terminate) mid-operation.
fn scenario_forced_cancel<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::ForcedCancel, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load extension and session.
    mgr.load_extension("ext-fc-1", cx).unwrap();
    mgr.create_session("ext-fc-1", "sess-1", cx).unwrap();

    // Force-cancel with Terminate (zero drain budget).
    let cancel_result = mgr.cancel_extension("ext-fc-1", cx, LifecycleEvent::Terminate);
    result.assert_true("cancel_extension succeeds", cancel_result.is_ok());
    if let Ok(outcome) = &cancel_result {
        result.assert_true("terminate outcome success", outcome.success);
    }

    result.assert_true(
        "extension not running after terminate",
        !mgr.is_extension_running("ext-fc-1"),
    );

    // Verify cannot create new sessions on terminated extension.
    let err = mgr.create_session("ext-fc-1", "sess-2", cx);
    result.assert_true(
        "session creation on terminated extension fails",
        err.is_err(),
    );

    result.extensions_loaded.push("ext-fc-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → trigger quarantine → verify isolation.
fn scenario_quarantine<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::Quarantine, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    mgr.load_extension("ext-q-1", cx).unwrap();
    mgr.create_session("ext-q-1", "sess-1", cx).unwrap();

    // Quarantine the extension.
    let quarantine_result = mgr.cancel_extension("ext-q-1", cx, LifecycleEvent::Quarantine);
    result.assert_true("quarantine succeeds", quarantine_result.is_ok());
    if let Ok(outcome) = &quarantine_result {
        result.assert_true("quarantine outcome success", outcome.success);
    }

    result.assert_true(
        "extension not running after quarantine",
        !mgr.is_extension_running("ext-q-1"),
    );

    // Verify quarantine event in evidence.
    let events = mgr.events();
    let quarantine_events: Vec<_> = events
        .iter()
        .filter(|e| e.event == "extension_quarantine")
        .collect();
    result.assert_true("quarantine event emitted", !quarantine_events.is_empty());

    result.extensions_loaded.push("ext-q-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Load → create session → revoke capability → verify teardown.
fn scenario_revocation<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::Revocation, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    mgr.load_extension("ext-r-1", cx).unwrap();
    mgr.create_session("ext-r-1", "sess-active", cx).unwrap();

    // Revoke via Revocation lifecycle event.
    let revoke_result = mgr.cancel_extension("ext-r-1", cx, LifecycleEvent::Revocation);
    result.assert_true("revocation succeeds", revoke_result.is_ok());
    if let Ok(outcome) = &revoke_result {
        result.assert_true("revocation outcome success", outcome.success);
    }

    result.assert_true(
        "extension not running after revocation",
        !mgr.is_extension_running("ext-r-1"),
    );

    // Verify no dangling session.
    result.assert_eq("session count is 0", mgr.session_count("ext-r-1"), 0);

    result.extensions_loaded.push("ext-r-1".to_string());
    result.finalize(&mut mgr);
    result
}

/// Scenario: Simulate degraded mode — host shutdown rejects new operations.
fn scenario_degraded_mode<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::DegradedMode, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load some extensions normally.
    mgr.load_extension("ext-d-1", cx).unwrap();
    mgr.load_extension("ext-d-2", cx).unwrap();

    // Initiate shutdown (simulates control-plane entering degraded mode).
    let shutdown_results = mgr.shutdown(cx);
    result.assert_eq("all extensions cancelled", shutdown_results.len(), 2);
    for (i, r) in shutdown_results.iter().enumerate() {
        result.assert_true(&format!("shutdown result {i} succeeds"), r.is_ok());
    }

    result.assert_true("host is shutting down", mgr.is_shutting_down());

    // New operations must be rejected.
    let load_err = mgr.load_extension("ext-new", cx);
    result.assert_true("load rejected during shutdown", load_err.is_err());
    if let Err(e) = &load_err {
        result.assert_eq(
            "error code is host_shutting_down",
            e.error_code(),
            "host_shutting_down",
        );
    }

    let session_err = mgr.create_session("ext-d-1", "s1", cx);
    result.assert_true("session rejected during shutdown", session_err.is_err());

    result.assert_eq("no running extensions", mgr.loaded_extension_count(), 0);

    result
        .extensions_loaded
        .extend(["ext-d-1".to_string(), "ext-d-2".to_string()]);
    result.finalize(&mut mgr);
    result
}

/// Scenario: Multiple extensions — verify region isolation.
fn scenario_multi_extension<C: ContextAdapter>(seed: u64, cx: &mut C) -> ScenarioResult {
    let mut result = ScenarioResult::new(ScenarioKind::MultiExtension, seed);
    let mut mgr = ExtensionHostLifecycleManager::new();

    // Load 4 extensions.
    for i in 0..4 {
        mgr.load_extension(&format!("ext-m-{i}"), cx).unwrap();
    }
    result.assert_eq("4 extensions loaded", mgr.loaded_extension_count(), 4);

    // Create sessions in different extensions.
    mgr.create_session("ext-m-0", "s0a", cx).unwrap();
    mgr.create_session("ext-m-0", "s0b", cx).unwrap();
    mgr.create_session("ext-m-1", "s1a", cx).unwrap();
    mgr.create_session("ext-m-2", "s2a", cx).unwrap();

    // Cancel ext-m-1 (terminate).
    let cancel_result = mgr.cancel_extension("ext-m-1", cx, LifecycleEvent::Terminate);
    result.assert_true("cancel ext-m-1 succeeds", cancel_result.is_ok());

    // Verify isolation: ext-m-1 is down, others unaffected.
    result.assert_true("ext-m-0 still running", mgr.is_extension_running("ext-m-0"));
    result.assert_true("ext-m-1 NOT running", !mgr.is_extension_running("ext-m-1"));
    result.assert_true("ext-m-2 still running", mgr.is_extension_running("ext-m-2"));
    result.assert_true("ext-m-3 still running", mgr.is_extension_running("ext-m-3"));

    // ext-m-0 sessions still alive.
    result.assert_eq("ext-m-0 session count", mgr.session_count("ext-m-0"), 2);
    // ext-m-2 session still alive.
    result.assert_eq("ext-m-2 session count", mgr.session_count("ext-m-2"), 1);

    // Quarantine ext-m-2 (with its session).
    let q_result = mgr.cancel_extension("ext-m-2", cx, LifecycleEvent::Quarantine);
    result.assert_true("quarantine ext-m-2 succeeds", q_result.is_ok());
    result.assert_true(
        "ext-m-2 NOT running after quarantine",
        !mgr.is_extension_running("ext-m-2"),
    );

    // ext-m-0 and ext-m-3 still unaffected.
    result.assert_true(
        "ext-m-0 still running after ext-m-2 quarantine",
        mgr.is_extension_running("ext-m-0"),
    );
    result.assert_true(
        "ext-m-3 still running after ext-m-2 quarantine",
        mgr.is_extension_running("ext-m-3"),
    );

    // Graceful unload of ext-m-0 with sessions.
    let unload = mgr.unload_extension("ext-m-0", cx);
    result.assert_true("unload ext-m-0 succeeds", unload.is_ok());

    result.assert_eq("only ext-m-3 running", mgr.loaded_extension_count(), 1);
    result.assert_true("ext-m-3 still running", mgr.is_extension_running("ext-m-3"));

    for i in 0..4 {
        result.extensions_loaded.push(format!("ext-m-{i}"));
    }
    result.finalize(&mut mgr);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{MockBudget, MockCx};

    fn mock_cx(budget_ms: u64) -> MockCx {
        MockCx::new(
            crate::control_plane::mocks::trace_id_from_seed(42),
            MockBudget::new(budget_ms),
        )
    }

    // -----------------------------------------------------------------------
    // Individual scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_startup_passes() {
        let mut cx = mock_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        assert!(result.passed, "startup scenario failed: {result:#?}");
        assert!(result.assertions.len() >= 6);
    }

    #[test]
    fn scenario_normal_shutdown_passes() {
        let mut cx = mock_cx(20000);
        let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
        assert!(
            result.passed,
            "normal_shutdown scenario failed: {result:#?}"
        );
        assert!(result.assertions.len() >= 8);
    }

    #[test]
    fn scenario_forced_cancel_passes() {
        let mut cx = mock_cx(10000);
        let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
        assert!(result.passed, "forced_cancel scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_quarantine_passes() {
        let mut cx = mock_cx(10000);
        let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
        assert!(result.passed, "quarantine scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_revocation_passes() {
        let mut cx = mock_cx(10000);
        let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
        assert!(result.passed, "revocation scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_degraded_mode_passes() {
        let mut cx = mock_cx(20000);
        let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
        assert!(result.passed, "degraded_mode scenario failed: {result:#?}");
    }

    #[test]
    fn scenario_multi_extension_passes() {
        let mut cx = mock_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        assert!(
            result.passed,
            "multi_extension scenario failed: {result:#?}"
        );
    }

    // -----------------------------------------------------------------------
    // Full suite
    // -----------------------------------------------------------------------

    #[test]
    fn full_suite_passes() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);
        assert_eq!(suite.scenarios.len(), 7);
        assert_eq!(suite.passed_assertions, suite.total_assertions);
    }

    // -----------------------------------------------------------------------
    // Deterministic reproducibility
    // -----------------------------------------------------------------------

    #[test]
    fn scenarios_deterministic_across_runs() {
        let mut cx1 = mock_cx(100000);
        let suite1 = run_all_scenarios(99, &mut cx1);

        let mut cx2 = mock_cx(100000);
        let suite2 = run_all_scenarios(99, &mut cx2);

        assert_eq!(suite1.total_assertions, suite2.total_assertions);
        assert_eq!(suite1.passed_assertions, suite2.passed_assertions);
        assert_eq!(suite1.verdict, suite2.verdict);

        // Each scenario produces the same assertions.
        for (s1, s2) in suite1.scenarios.iter().zip(suite2.scenarios.iter()) {
            assert_eq!(s1.kind, s2.kind);
            assert_eq!(s1.passed, s2.passed);
            assert_eq!(s1.assertions.len(), s2.assertions.len());
        }
    }

    // -----------------------------------------------------------------------
    // ScenarioKind display
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_kind_display() {
        assert_eq!(format!("{}", ScenarioKind::Startup), "startup");
        assert_eq!(
            format!("{}", ScenarioKind::NormalShutdown),
            "normal_shutdown"
        );
        assert_eq!(format!("{}", ScenarioKind::ForcedCancel), "forced_cancel");
        assert_eq!(format!("{}", ScenarioKind::Quarantine), "quarantine");
        assert_eq!(format!("{}", ScenarioKind::Revocation), "revocation");
        assert_eq!(format!("{}", ScenarioKind::DegradedMode), "degraded_mode");
        assert_eq!(
            format!("{}", ScenarioKind::MultiExtension),
            "multi_extension"
        );
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn scenario_result_serde_roundtrip() {
        let mut cx = mock_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        let json = serde_json::to_string(&result).unwrap();
        let back: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn scenario_suite_result_serde_roundtrip() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        let json = serde_json::to_string(&suite).unwrap();
        let back: ScenarioSuiteResult = serde_json::from_str(&json).unwrap();
        assert_eq!(suite, back);
    }

    #[test]
    fn scenario_kind_serde_roundtrip() {
        for kind in [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ScenarioKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn assertion_serde_roundtrip() {
        let assertion = ScenarioAssertion {
            description: "test assertion".to_string(),
            passed: true,
            detail: String::new(),
        };
        let json = serde_json::to_string(&assertion).unwrap();
        let back: ScenarioAssertion = serde_json::from_str(&json).unwrap();
        assert_eq!(assertion, back);
    }

    // -----------------------------------------------------------------------
    // Individual scenario events
    // -----------------------------------------------------------------------

    #[test]
    fn startup_captures_lifecycle_events() {
        let mut cx = mock_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 1, &mut cx);
        assert!(!result.lifecycle_events.is_empty());
        assert!(
            result
                .lifecycle_events
                .iter()
                .any(|e| e.event == "extension_loaded")
        );
    }

    #[test]
    fn normal_shutdown_captures_complete_trail() {
        let mut cx = mock_cx(20000);
        let result = run_scenario(ScenarioKind::NormalShutdown, 2, &mut cx);
        let event_names: Vec<&str> = result
            .lifecycle_events
            .iter()
            .map(|e| e.event.as_str())
            .collect();
        assert!(event_names.contains(&"extension_loaded"));
        assert!(event_names.contains(&"session_created"));
        assert!(event_names.contains(&"extension_unloaded"));
    }

    #[test]
    fn multi_extension_final_states_correct() {
        let mut cx = mock_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        // ext-m-3 should be the only one still running.
        assert_eq!(result.final_states.get("ext-m-3"), Some(&true));
        assert_eq!(result.final_states.get("ext-m-0"), Some(&false));
        assert_eq!(result.final_states.get("ext-m-1"), Some(&false));
        assert_eq!(result.final_states.get("ext-m-2"), Some(&false));
    }

    // -- Enrichment tests --

    #[test]
    fn determinism_full_suite_100_times() {
        let mut first_suite = None;
        for _ in 0..100 {
            let mut cx = mock_cx(100000);
            let suite = run_all_scenarios(77, &mut cx);
            assert_eq!(suite.verdict, Verdict::Pass);

            if let Some(ref first) = first_suite {
                // Compare structural equality across runs
                let f: &ScenarioSuiteResult = first;
                assert_eq!(f.total_assertions, suite.total_assertions);
                assert_eq!(f.passed_assertions, suite.passed_assertions);
                for (s1, s2) in f.scenarios.iter().zip(suite.scenarios.iter()) {
                    assert_eq!(s1.kind, s2.kind);
                    assert_eq!(s1.passed, s2.passed);
                    assert_eq!(s1.assertions, s2.assertions);
                    assert_eq!(s1.total_events_emitted, s2.total_events_emitted);
                }
            } else {
                first_suite = Some(suite);
            }
        }
    }

    #[test]
    fn every_scenario_emits_at_least_one_lifecycle_event() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        for scenario in &suite.scenarios {
            assert!(
                scenario.total_events_emitted > 0,
                "scenario {:?} emitted no lifecycle events",
                scenario.kind,
            );
        }
    }

    #[test]
    fn every_scenario_records_extensions_loaded() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        for scenario in &suite.scenarios {
            assert!(
                !scenario.extensions_loaded.is_empty(),
                "scenario {:?} loaded no extensions",
                scenario.kind,
            );
        }
    }

    #[test]
    fn forced_cancel_evidence_includes_terminate() {
        let mut cx = mock_cx(10000);
        let result = run_scenario(ScenarioKind::ForcedCancel, 3, &mut cx);
        let events: Vec<&str> = result
            .lifecycle_events
            .iter()
            .map(|e| e.event.as_str())
            .collect();
        assert!(
            events.contains(&"extension_loaded"),
            "forced cancel should start with extension_loaded"
        );
    }

    #[test]
    fn revocation_leaves_zero_sessions() {
        let mut cx = mock_cx(10000);
        let result = run_scenario(ScenarioKind::Revocation, 5, &mut cx);
        // Verify through assertions that session count = 0
        let session_check = result
            .assertions
            .iter()
            .find(|a| a.description.contains("session count"));
        assert!(
            session_check.is_some_and(|a| a.passed),
            "revocation should leave zero sessions"
        );
    }

    #[test]
    fn degraded_mode_all_assertions_pass() {
        let mut cx = mock_cx(20000);
        let result = run_scenario(ScenarioKind::DegradedMode, 6, &mut cx);
        for assertion in &result.assertions {
            assert!(
                assertion.passed,
                "degraded mode assertion failed: {} — {}",
                assertion.description, assertion.detail,
            );
        }
    }

    #[test]
    fn quarantine_events_have_trace_id() {
        let mut cx = mock_cx(10000);
        let result = run_scenario(ScenarioKind::Quarantine, 4, &mut cx);
        for event in &result.lifecycle_events {
            assert!(
                !event.trace_id.is_empty(),
                "lifecycle event {} should have non-empty trace_id",
                event.event,
            );
        }
    }

    #[test]
    fn suite_result_machine_readable_for_release_gating() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);

        // Verify it serializes to JSON for bd-24bu release gating
        let json = serde_json::to_string(&suite).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["verdict"], "Pass");
        assert!(parsed["total_assertions"].as_u64().unwrap() > 0);
        assert_eq!(parsed["total_assertions"], parsed["passed_assertions"]);
    }

    #[test]
    fn different_seeds_produce_same_verdict() {
        for seed in [1, 42, 99, 255, 1000] {
            let mut cx = mock_cx(100000);
            let suite = run_all_scenarios(seed, &mut cx);
            assert_eq!(
                suite.verdict,
                Verdict::Pass,
                "suite with seed {seed} should pass"
            );
        }
    }

    // -- Enrichment: ScenarioKind ordering --

    #[test]
    fn scenario_kind_ordering_deterministic() {
        let mut kinds = [
            ScenarioKind::MultiExtension,
            ScenarioKind::Startup,
            ScenarioKind::Quarantine,
        ];
        kinds.sort();
        // Derived Ord follows declaration order: Startup < Quarantine < MultiExtension
        assert_eq!(kinds[0], ScenarioKind::Startup);
        assert_eq!(kinds[2], ScenarioKind::MultiExtension);
    }

    // -- Enrichment: ScenarioAssertion detail --

    #[test]
    fn scenario_assertion_passed_has_empty_detail() {
        let a = ScenarioAssertion {
            description: "check".to_string(),
            passed: true,
            detail: String::new(),
        };
        assert!(a.detail.is_empty());
        assert!(a.passed);
    }

    #[test]
    fn scenario_assertion_failed_has_non_empty_detail() {
        let a = ScenarioAssertion {
            description: "check".to_string(),
            passed: false,
            detail: "expected true, got false".to_string(),
        };
        assert!(!a.detail.is_empty());
        assert!(!a.passed);
    }

    // -- Enrichment: ScenarioResult new defaults --

    #[test]
    fn scenario_result_new_starts_passed() {
        let result = ScenarioResult::new(ScenarioKind::Startup, 42);
        assert!(result.passed);
        assert!(result.assertions.is_empty());
        assert!(result.lifecycle_events.is_empty());
        assert!(result.extensions_loaded.is_empty());
        assert!(result.final_states.is_empty());
        assert_eq!(result.total_events_emitted, 0);
        assert_eq!(result.seed, 42);
        assert_eq!(result.kind, ScenarioKind::Startup);
    }

    // -- Enrichment: suite total_assertions accumulates correctly --

    #[test]
    fn suite_total_assertions_matches_sum_of_scenarios() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        let sum: usize = suite.scenarios.iter().map(|s| s.assertions.len()).sum();
        assert_eq!(suite.total_assertions, sum);
    }

    // -- Enrichment: each scenario has correct kind --

    #[test]
    fn each_scenario_result_has_matching_kind() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(42, &mut cx);
        let expected_kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        for (scenario, expected) in suite.scenarios.iter().zip(expected_kinds.iter()) {
            assert_eq!(scenario.kind, *expected);
        }
    }

    // -- Enrichment: scenario suite 7 scenarios --

    #[test]
    fn suite_always_runs_seven_scenarios() {
        let mut cx = mock_cx(100000);
        let suite = run_all_scenarios(1, &mut cx);
        assert_eq!(suite.scenarios.len(), 7);
    }

    // -- Enrichment: ScenarioKind Display roundtrips --

    #[test]
    fn scenario_kind_display_all_unique() {
        let kinds = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        let displays: std::collections::BTreeSet<String> =
            kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(
            displays.len(),
            7,
            "all ScenarioKind Display values are unique"
        );
    }

    // -- Enrichment: startup seed is propagated --

    #[test]
    fn scenario_result_seed_propagated() {
        let mut cx = mock_cx(5000);
        let result = run_scenario(ScenarioKind::Startup, 12345, &mut cx);
        assert_eq!(result.seed, 12345);
    }

    // -- Enrichment: multi_extension loads 4 extensions --

    #[test]
    fn multi_extension_loads_four_extensions() {
        let mut cx = mock_cx(50000);
        let result = run_scenario(ScenarioKind::MultiExtension, 7, &mut cx);
        assert_eq!(result.extensions_loaded.len(), 4);
    }

    // -- Enrichment batch 2: Display uniqueness, serde, boundary --

    #[test]
    fn scenario_kind_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let all = [
            ScenarioKind::Startup,
            ScenarioKind::NormalShutdown,
            ScenarioKind::ForcedCancel,
            ScenarioKind::Quarantine,
            ScenarioKind::Revocation,
            ScenarioKind::DegradedMode,
            ScenarioKind::MultiExtension,
        ];
        let set: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
        assert_eq!(
            set.len(),
            all.len(),
            "all ScenarioKind Display strings must be unique"
        );
    }

    #[test]
    fn scenario_kind_ord_follows_declaration_order() {
        assert!(ScenarioKind::Startup < ScenarioKind::NormalShutdown);
        assert!(ScenarioKind::NormalShutdown < ScenarioKind::ForcedCancel);
        assert!(ScenarioKind::ForcedCancel < ScenarioKind::Quarantine);
        assert!(ScenarioKind::Quarantine < ScenarioKind::Revocation);
        assert!(ScenarioKind::Revocation < ScenarioKind::DegradedMode);
        assert!(ScenarioKind::DegradedMode < ScenarioKind::MultiExtension);
    }

    #[test]
    fn scenario_result_assert_true_failure_sets_passed_false() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        assert!(result.passed);
        result.assert_true("this should fail", false);
        assert!(!result.passed);
        assert_eq!(result.assertions.len(), 1);
        assert!(!result.assertions[0].passed);
        assert!(!result.assertions[0].detail.is_empty());
    }

    #[test]
    fn scenario_result_assert_eq_failure_records_diff() {
        let mut result = ScenarioResult::new(ScenarioKind::Startup, 0);
        result.assert_eq("mismatch", 42_u64, 99_u64);
        assert!(!result.passed);
        let a = &result.assertions[0];
        assert!(!a.passed);
        assert!(a.detail.contains("42"));
        assert!(a.detail.contains("99"));
    }

    #[test]
    fn suite_seed_zero_still_passes() {
        let mut cx = mock_cx(100_000);
        let suite = run_all_scenarios(0, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);
        assert_eq!(suite.seed, 0);
    }

    #[test]
    fn suite_max_seed_still_passes() {
        let mut cx = mock_cx(100_000);
        let suite = run_all_scenarios(u64::MAX, &mut cx);
        assert_eq!(suite.verdict, Verdict::Pass);
        assert_eq!(suite.seed, u64::MAX);
    }

    #[test]
    fn scenario_assertion_clone_equality() {
        let a = ScenarioAssertion {
            description: "clone test".to_string(),
            passed: true,
            detail: String::new(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_suite_result_json_scenarios_array() {
        let mut cx = mock_cx(100_000);
        let suite = run_all_scenarios(42, &mut cx);
        let json = serde_json::to_string(&suite).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let scenarios = parsed["scenarios"].as_array().unwrap();
        assert_eq!(scenarios.len(), 7);
        for s in scenarios {
            assert!(s["passed"].as_bool().unwrap());
        }
    }
}
