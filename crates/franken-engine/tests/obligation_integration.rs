use frankenengine_engine::control_plane::{
    Budget, ContextAdapter, ControlPlaneAdapterError, TraceId,
};
use frankenengine_engine::execution_cell::{CellKind, ExecutionCell};
use frankenengine_engine::obligation_integration::{
    LeakPolicy, ObligationTracker, OperationPhase, TwoPhaseCategory,
};
use frankenengine_engine::region_lifecycle::{CancelReason, DrainDeadline};

#[derive(Debug, Clone)]
struct IntegrationCx {
    seed: u64,
    remaining_ms: u64,
}

impl IntegrationCx {
    fn new(seed: u64, budget_ms: u64) -> Self {
        Self {
            seed,
            remaining_ms: budget_ms,
        }
    }

    fn trace_id_from_seed(seed: u64) -> TraceId {
        TraceId::from_parts(1_700_000_000_000 + seed, u128::from(seed) << 4)
    }
}

impl ContextAdapter for IntegrationCx {
    fn trace_id(&self) -> TraceId {
        Self::trace_id_from_seed(self.seed)
    }

    fn budget(&self) -> Budget {
        Budget::new(self.remaining_ms)
    }

    fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
        if requested_ms > self.remaining_ms {
            return Err(ControlPlaneAdapterError::BudgetExhausted { requested_ms });
        }
        self.remaining_ms -= requested_ms;
        Ok(())
    }
}

#[test]
fn extension_lifecycle_resolves_all_two_phase_obligations() {
    let mut cell = ExecutionCell::new("ext-clean", CellKind::Extension, "trace-clean");
    let mut cx = IntegrationCx::new(1, 500);
    let mut tracker = ObligationTracker::default();

    let ops = [
        (
            "alloc-1",
            TwoPhaseCategory::ResourceAlloc,
            "allocate buffer",
        ),
        ("perm-1", TwoPhaseCategory::PermissionGrant, "grant socket"),
        ("state-1", TwoPhaseCategory::StateMutation, "write config"),
        (
            "evidence-1",
            TwoPhaseCategory::EvidenceCommit,
            "publish evidence",
        ),
    ];

    for (id, category, desc) in ops {
        tracker
            .begin_operation(&mut cell, id, category, desc)
            .expect("begin should succeed");
    }

    tracker
        .commit_operation(&mut cell, "alloc-1")
        .expect("commit alloc");
    tracker
        .commit_operation(&mut cell, "perm-1")
        .expect("commit permission");
    tracker
        .abort_operation(&mut cell, "state-1")
        .expect("abort state mutation");
    tracker
        .commit_operation(&mut cell, "evidence-1")
        .expect("commit evidence");

    let close = cell
        .close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 8 },
        )
        .expect("close should succeed");
    assert!(close.success);
    assert_eq!(tracker.detect_leaks(&cell).len(), 0);
    assert!(!tracker.has_leaks());

    let stats = tracker.category_stats();
    assert_eq!(stats[&TwoPhaseCategory::ResourceAlloc].started, 1);
    assert_eq!(stats[&TwoPhaseCategory::ResourceAlloc].committed, 1);
    assert_eq!(stats[&TwoPhaseCategory::PermissionGrant].started, 1);
    assert_eq!(stats[&TwoPhaseCategory::PermissionGrant].committed, 1);
    assert_eq!(stats[&TwoPhaseCategory::StateMutation].aborted, 1);
    assert_eq!(stats[&TwoPhaseCategory::EvidenceCommit].committed, 1);
}

#[test]
fn frankenlab_mode_flags_unresolved_obligations_as_run_failure() {
    let mut cell = ExecutionCell::new("ext-lab", CellKind::Extension, "trace-lab");
    let mut cx = IntegrationCx::new(2, 300);
    let mut tracker = ObligationTracker::lab();

    tracker
        .begin_operation(
            &mut cell,
            "op-lab",
            TwoPhaseCategory::ResourceAlloc,
            "allocate and forget",
        )
        .expect("begin should succeed");

    let close = cell
        .close(
            &mut cx,
            CancelReason::Quarantine,
            DrainDeadline { max_ticks: 1 },
        )
        .expect("close should complete");
    assert!(close.drain_timeout_escalated);

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 1);
    assert_eq!(tracker.leak_policy(), LeakPolicy::Lab);
    assert!(tracker.has_leaks());
    assert_eq!(
        tracker
            .get_operation("op-lab")
            .expect("operation must exist")
            .phase,
        OperationPhase::Leaked
    );

    assert!(
        tracker.should_fail_run(),
        "lab runs must fail when leaks are present"
    );
    assert!(
        tracker
            .events()
            .iter()
            .any(|event| event.event == "lab_failure" && event.operation_id == "op-lab")
    );
}

#[test]
fn unresolved_obligation_emits_structured_leak_event() {
    let mut cell = ExecutionCell::new("ext-evidence", CellKind::Extension, "trace-evidence");
    let mut cx = IntegrationCx::new(3, 300);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "grant-1",
            TwoPhaseCategory::PermissionGrant,
            "grant capability",
        )
        .expect("begin should succeed");

    cell.close(
        &mut cx,
        CancelReason::OperatorShutdown,
        DrainDeadline { max_ticks: 1 },
    )
    .expect("close should complete");
    tracker.detect_leaks(&cell);

    let leak_event = tracker
        .events()
        .iter()
        .find(|event| event.event == "leak_detected")
        .expect("leak event should be present");
    assert_eq!(leak_event.trace_id, "trace-evidence");
    assert_eq!(leak_event.operation_id, "grant-1");
    assert_eq!(leak_event.category, TwoPhaseCategory::PermissionGrant);
    assert_eq!(leak_event.cell_kind, CellKind::Extension);
    assert_eq!(leak_event.component, "obligation_integration");
    assert_eq!(leak_event.outcome, "leaked");
    assert_eq!(leak_event.phase, OperationPhase::Leaked);
    assert!(tracker.events().iter().any(|event| {
        event.event == "production_fallback"
            && event.outcome == "forced_cleanup"
            && event.operation_id == "grant-1"
    }));
}

#[test]
fn cancellation_timeout_force_resolves_cell_obligation_and_logs_leak() {
    let mut cell = ExecutionCell::new("ext-timeout", CellKind::Extension, "trace-timeout");
    let mut cx = IntegrationCx::new(4, 300);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "timeout-op",
            TwoPhaseCategory::EvidenceCommit,
            "publish evidence later",
        )
        .expect("begin should succeed");

    let close = cell
        .close(
            &mut cx,
            CancelReason::Revocation,
            DrainDeadline { max_ticks: 1 },
        )
        .expect("close should complete");
    assert!(close.drain_timeout_escalated);
    assert_eq!(close.obligations_aborted, 1);

    let leaks = tracker.detect_leaks(&cell);
    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].operation_id, "timeout-op");
    assert!(!tracker.should_fail_run());
    assert!(
        tracker
            .events()
            .iter()
            .any(|event| { event.event == "leak_detected" && event.operation_id == "timeout-op" })
    );
    assert!(tracker.events().iter().any(|event| {
        event.event == "production_fallback"
            && event.outcome == "forced_cleanup"
            && event.operation_id == "timeout-op"
    }));
}

#[test]
fn commit_during_drain_succeeds_before_finalize() {
    let mut cell = ExecutionCell::new("ext-drain", CellKind::Extension, "trace-drain");
    let mut cx = IntegrationCx::new(5, 300);
    let mut tracker = ObligationTracker::default();

    tracker
        .begin_operation(
            &mut cell,
            "drain-op",
            TwoPhaseCategory::StateMutation,
            "commit during drain",
        )
        .expect("begin should succeed");

    cell.initiate_close(
        &mut cx,
        CancelReason::Quarantine,
        DrainDeadline { max_ticks: 5 },
    )
    .expect("initiate close");

    tracker
        .commit_operation(&mut cell, "drain-op")
        .expect("commit during drain should succeed");
    let close = cell.finalize().expect("finalize");
    assert!(close.success);
    assert_eq!(close.obligations_committed, 1);
    assert!(tracker.detect_leaks(&cell).is_empty());
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn two_phase_category_serde_round_trip_all_variants() {
    for category in [
        TwoPhaseCategory::ResourceAlloc,
        TwoPhaseCategory::PermissionGrant,
        TwoPhaseCategory::StateMutation,
        TwoPhaseCategory::EvidenceCommit,
    ] {
        let json = serde_json::to_string(&category).expect("serialize");
        let recovered: TwoPhaseCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(category, recovered);
    }
}

#[test]
fn two_phase_category_display_formats_are_snake_case() {
    assert_eq!(
        TwoPhaseCategory::ResourceAlloc.to_string(),
        "resource_alloc"
    );
    assert_eq!(
        TwoPhaseCategory::PermissionGrant.to_string(),
        "permission_grant"
    );
    assert_eq!(
        TwoPhaseCategory::StateMutation.to_string(),
        "state_mutation"
    );
    assert_eq!(
        TwoPhaseCategory::EvidenceCommit.to_string(),
        "evidence_commit"
    );
}

#[test]
fn operation_phase_serde_round_trip_all_variants() {
    for phase in [
        OperationPhase::Phase1Active,
        OperationPhase::Committed,
        OperationPhase::Aborted,
        OperationPhase::Leaked,
    ] {
        let json = serde_json::to_string(&phase).expect("serialize");
        let recovered: OperationPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(phase, recovered);
    }
}

#[test]
fn operation_phase_display_formats() {
    assert_eq!(OperationPhase::Phase1Active.to_string(), "phase1_active");
    assert_eq!(OperationPhase::Committed.to_string(), "committed");
    assert_eq!(OperationPhase::Aborted.to_string(), "aborted");
    assert_eq!(OperationPhase::Leaked.to_string(), "leaked");
}

#[test]
fn leak_policy_serde_round_trip_all_variants() {
    for policy in [LeakPolicy::Lab, LeakPolicy::Production] {
        let json = serde_json::to_string(&policy).expect("serialize");
        let recovered: LeakPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, recovered);
    }
}

#[test]
fn obligation_tracker_default_is_production_policy() {
    let tracker = ObligationTracker::default();
    assert_eq!(tracker.leak_policy(), LeakPolicy::Production);
    assert!(!tracker.has_leaks());
    assert!(!tracker.should_fail_run());
    assert!(tracker.events().is_empty());
}

#[test]
fn obligation_tracker_lab_mode_uses_lab_policy() {
    let tracker = ObligationTracker::lab();
    assert_eq!(tracker.leak_policy(), LeakPolicy::Lab);
}

#[test]
fn obligation_event_serde_round_trip() {
    let mut cell = ExecutionCell::new("ext-serde", CellKind::Extension, "trace-serde");
    let mut tracker = ObligationTracker::default();
    tracker
        .begin_operation(
            &mut cell,
            "serde-op",
            TwoPhaseCategory::ResourceAlloc,
            "allocate for serde test",
        )
        .expect("begin");
    tracker
        .commit_operation(&mut cell, "serde-op")
        .expect("commit");
    let events = tracker.events();
    assert!(!events.is_empty());
    let json = serde_json::to_string(&events[0]).expect("serialize");
    assert!(!json.is_empty());
}

#[test]
fn double_begin_same_operation_id_fails() {
    let mut cell = ExecutionCell::new("ext-dup", CellKind::Extension, "trace-dup");
    let mut tracker = ObligationTracker::default();
    tracker
        .begin_operation(
            &mut cell,
            "op-dup",
            TwoPhaseCategory::ResourceAlloc,
            "first begin",
        )
        .expect("first begin should succeed");
    let err = tracker.begin_operation(
        &mut cell,
        "op-dup",
        TwoPhaseCategory::ResourceAlloc,
        "duplicate begin",
    );
    assert!(err.is_err(), "duplicate begin must fail");
}

#[test]
fn commit_unknown_operation_id_fails() {
    let mut cell = ExecutionCell::new("ext-unknown", CellKind::Extension, "trace-unknown");
    let mut tracker = ObligationTracker::default();
    let err = tracker.commit_operation(&mut cell, "nonexistent-op");
    assert!(err.is_err(), "commit unknown operation must fail");
}

#[test]
fn category_stats_empty_tracker() {
    let tracker = ObligationTracker::default();
    let stats = tracker.category_stats();
    for (_category, stat) in stats {
        assert_eq!(stat.started, 0);
        assert_eq!(stat.committed, 0);
        assert_eq!(stat.aborted, 0);
    }
}

#[test]
fn abort_unknown_operation_id_fails() {
    let mut cell = ExecutionCell::new("ext-abort-unk", CellKind::Extension, "trace-abort-unk");
    let mut tracker = ObligationTracker::default();
    let err = tracker.abort_operation(&mut cell, "nonexistent-op");
    assert!(err.is_err(), "abort unknown operation must fail");
}

#[test]
fn get_operation_returns_none_for_unknown_id() {
    let tracker = ObligationTracker::default();
    assert!(
        tracker.get_operation("does-not-exist").is_none(),
        "unknown operation id must return None"
    );
}

#[test]
fn lab_tracker_with_no_leaks_does_not_fail_run() {
    let mut cell = ExecutionCell::new("ext-lab-clean", CellKind::Extension, "trace-lab-clean");
    let mut tracker = ObligationTracker::lab();
    tracker
        .begin_operation(
            &mut cell,
            "clean-op",
            TwoPhaseCategory::ResourceAlloc,
            "allocate and commit cleanly",
        )
        .expect("begin");
    tracker
        .commit_operation(&mut cell, "clean-op")
        .expect("commit");
    assert!(!tracker.has_leaks());
    assert!(!tracker.should_fail_run());
}
