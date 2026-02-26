use frankenengine_engine::assumptions_ledger::{DemotionAction, DemotionPolicy};
use frankenengine_engine::semantic_twin::{
    SEMANTIC_TWIN_LOG_SCHEMA_VERSION, SemanticTwinRuntime, SemanticTwinSpecification,
};

#[test]
fn semantic_twin_spec_and_runtime_cover_core_falsification_flow() {
    let spec = SemanticTwinSpecification::frx_19_1_default().expect("default spec");
    spec.validate().expect("spec should validate");

    let mut runtime = SemanticTwinRuntime::new(
        spec,
        "trace-frx-19-1",
        "decision-frx-19-1",
        "policy-frx-19-1",
        11,
        DemotionPolicy::default(),
    )
    .expect("runtime");

    // Healthy observation should produce a structured ok event.
    let healthy = runtime.observe("risk_calibration_error_millionths", 90_000, 11);
    assert!(healthy.actions.is_empty());
    assert_eq!(healthy.events.len(), 1);
    let ok_event = &healthy.events[0];
    assert_eq!(ok_event.schema_version, SEMANTIC_TWIN_LOG_SCHEMA_VERSION);
    assert_eq!(ok_event.trace_id, "trace-frx-19-1");
    assert_eq!(ok_event.decision_id, "decision-frx-19-1");
    assert_eq!(ok_event.policy_id, "policy-frx-19-1");
    assert_eq!(ok_event.outcome, "ok");

    // Violate a fatal FRIR linkage assumption and ensure fail-safe demotion action.
    let violated = runtime.observe("frir_witness_linkage_millionths", 0, 11);
    assert_eq!(violated.actions.len(), 1);
    assert!(matches!(
        violated.actions[0],
        DemotionAction::EnterSafeMode { .. }
    ));
    assert_eq!(violated.events.len(), 1);
    let fail_event = &violated.events[0];
    assert_eq!(fail_event.schema_version, SEMANTIC_TWIN_LOG_SCHEMA_VERSION);
    assert_eq!(fail_event.event, "assumption_falsified");
    assert_eq!(fail_event.outcome, "falsified");
    assert_eq!(
        fail_event.error_code.as_deref(),
        Some("FE-SEMANTIC-TWIN-0001")
    );
    assert!(fail_event.assumption_id.is_some());
    assert!(fail_event.monitor_id.is_some());

    // Ledger should now record at least one violated assumption.
    assert!(runtime.ledger().violated_count() >= 1);
}
