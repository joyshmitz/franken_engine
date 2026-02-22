use frankenengine_engine::release_checklist_gate::{
    ArtifactRef, ChecklistItem, ChecklistItemStatus, ChecklistWaiver, ERROR_RELEASE_BLOCKED,
    RELEASE_CHECKLIST_COMPONENT, RELEASE_CHECKLIST_SCHEMA_VERSION, ReleaseChecklist,
    ReleaseChecklistError, query_release_checklists_by_tag, required_checklist_items,
    run_release_checklist_gate, validate_release_checklist,
};
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

fn artifact_ref(item_id: &str) -> ArtifactRef {
    ArtifactRef {
        artifact_id: format!("artifact-{item_id}"),
        path: format!("artifacts/releases/{item_id}.json"),
        sha256: Some("deadbeef".to_string()),
    }
}

fn baseline_checklist(release_tag: &str) -> ReleaseChecklist {
    let items = required_checklist_items()
        .iter()
        .map(|required| ChecklistItem {
            item_id: required.item_id.to_string(),
            category: required.category,
            required: true,
            status: ChecklistItemStatus::Pass,
            artifact_refs: vec![artifact_ref(required.item_id)],
            waiver: None,
        })
        .collect();

    ReleaseChecklist {
        schema_version: RELEASE_CHECKLIST_SCHEMA_VERSION.to_string(),
        release_tag: release_tag.to_string(),
        generated_at_utc: "2026-02-22T06:31:00+00:00".to_string(),
        trace_id: format!("trace-release-checklist-{release_tag}"),
        decision_id: format!("decision-release-checklist-{release_tag}"),
        policy_id: "policy-release-checklist-v1".to_string(),
        items,
    }
}

#[test]
fn gate_allows_release_when_all_required_items_pass_and_store_with_release_tag() {
    let mut adapter = InMemoryStorageAdapter::default();
    let checklist = baseline_checklist("v1.2.3");

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert!(decision.allows_release());
    assert!(!decision.blocked);
    assert_eq!(decision.error_code, None);
    assert_eq!(
        decision.storage_integration_point,
        "frankensqlite::benchmark::ledger"
    );
    assert!(
        decision
            .store_key
            .as_ref()
            .is_some_and(|value| value.contains("v1.2.3"))
    );

    for event in &decision.events {
        assert_eq!(event.component, RELEASE_CHECKLIST_COMPONENT);
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }

    let stored = query_release_checklists_by_tag(
        &mut adapter,
        "v1.2.3",
        &checklist.trace_id,
        &checklist.decision_id,
        &checklist.policy_id,
    )
    .expect("query should succeed");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].release_tag, "v1.2.3");
    validate_release_checklist(&stored[0]).expect("stored checklist must validate");
}

#[test]
fn gate_denies_release_when_required_items_missing_or_failed() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v1.2.4");
    checklist
        .items
        .retain(|item| item.item_id != "performance.gc_pause_budget");
    let failing = checklist
        .items
        .iter_mut()
        .find(|item| item.item_id == "security.ifc_coverage")
        .expect("required item present");
    failing.status = ChecklistItemStatus::Fail;

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_RELEASE_BLOCKED));
    assert!(decision.store_key.is_some());

    let blockers = decision.blockers.join(" | ");
    assert!(blockers.contains("missing required checklist item `performance.gc_pause_budget`"));
    assert!(blockers.contains("required item `security.ifc_coverage` is `fail`"));
}

#[test]
fn gate_fails_when_waived_item_lacks_complete_waiver_metadata() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v1.2.5");
    let waived = checklist
        .items
        .iter_mut()
        .find(|item| item.item_id == "operational.safe_mode_test")
        .expect("required item present");
    waived.status = ChecklistItemStatus::Waived;
    waived.waiver = Some(ChecklistWaiver {
        reason: "".to_string(),
        approver: "ops-reviewer".to_string(),
        exception_artifact_link: "artifact://waiver/safe-mode".to_string(),
    });

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-RCHK-1003"));
    assert!(decision.store_key.is_none());
    assert_eq!(decision.checklist_id, None);
}

#[test]
fn gate_checklist_id_is_deterministic_for_identical_input() {
    let checklist = baseline_checklist("v1.2.6");

    let mut adapter_a = InMemoryStorageAdapter::default();
    let mut adapter_b = InMemoryStorageAdapter::default();
    let decision_a = run_release_checklist_gate(&mut adapter_a, &checklist);
    let decision_b = run_release_checklist_gate(&mut adapter_b, &checklist);

    assert_eq!(decision_a.checklist_id, decision_b.checklist_id);
    assert_eq!(decision_a.store_key, decision_b.store_key);
    assert_eq!(decision_a.outcome, "allow");
    assert_eq!(decision_b.outcome, "allow");
}

#[test]
fn query_rejects_empty_release_tag() {
    let mut adapter = InMemoryStorageAdapter::default();
    let err = query_release_checklists_by_tag(
        &mut adapter,
        "   ",
        "trace-release-checklist-query",
        "decision-release-checklist-query",
        "policy-release-checklist-v1",
    )
    .expect_err("empty release tag should fail");

    match err {
        ReleaseChecklistError::InvalidRequest { field, .. } => {
            assert_eq!(field, "release_tag");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
