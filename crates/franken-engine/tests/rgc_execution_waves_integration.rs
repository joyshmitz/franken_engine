#![forbid(unsafe_code)]
//! Integration tests for RGC execution-wave coordination protocol.

use frankenengine_engine::rgc_execution_waves::{
    AntiStallAction, CoordinationValidationError, RGC_COORDINATION_EVENT_SCHEMA_VERSION,
    RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION, RGC_WAVE_HANDOFF_SCHEMA_VERSION,
    default_rgc_execution_wave_protocol, default_wave_handoff_package, run_coordination_dry_run,
    validate_execution_wave_protocol, validate_wave_handoff_package,
};

#[test]
fn rgc_execution_waves_default_contract_versions_are_stable() {
    assert_eq!(
        RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION,
        "franken-engine.rgc-execution-wave-protocol.v1"
    );
    assert_eq!(
        RGC_WAVE_HANDOFF_SCHEMA_VERSION,
        "franken-engine.rgc-wave-handoff.v1"
    );
    assert_eq!(
        RGC_COORDINATION_EVENT_SCHEMA_VERSION,
        "franken-engine.rgc-coordination.event.v1"
    );
}

#[test]
fn rgc_execution_waves_protocol_and_handoff_validate() {
    let protocol = default_rgc_execution_wave_protocol();
    validate_execution_wave_protocol(&protocol).expect("default protocol must validate");

    let handoff = default_wave_handoff_package();
    validate_wave_handoff_package(&protocol, &handoff).expect("default handoff must validate");
}

#[test]
fn rgc_execution_waves_handoff_rejects_unknown_wave() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.waves.pop(); // remove wave_3 entry

    let mut handoff = default_wave_handoff_package();
    handoff.wave = frankenengine_engine::rgc_execution_waves::ExecutionWave::Wave3;

    let error = validate_wave_handoff_package(&protocol, &handoff)
        .expect_err("handoff with missing wave should fail");
    assert!(matches!(
        error,
        CoordinationValidationError::UnknownWaveForHandoff { .. }
    ));
}

#[test]
fn rgc_execution_waves_dry_run_emits_required_coordination_events() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();

    let report = run_coordination_dry_run(
        &protocol,
        &handoff,
        3_700,
        "trace-rgc-e2e-01",
        "decision-rgc-e2e-01",
    )
    .expect("dry run should succeed");

    assert_eq!(report.action, AntiStallAction::Split);
    assert_eq!(report.events.len(), 4);

    let required_events = [
        "protocol_validated",
        "handoff_validated",
        "anti_stall_split",
        "dry_run_completed",
    ];

    for (index, expected) in required_events.iter().enumerate() {
        let event = &report.events[index];
        assert_eq!(event.event, *expected);
        assert_eq!(event.schema_version, RGC_COORDINATION_EVENT_SCHEMA_VERSION);
        assert_eq!(event.trace_id, "trace-rgc-e2e-01");
        assert_eq!(event.decision_id, "decision-rgc-e2e-01");
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }
}
