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
