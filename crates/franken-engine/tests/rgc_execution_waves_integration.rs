#![forbid(unsafe_code)]
//! Integration tests for RGC execution-wave coordination protocol.

use frankenengine_engine::rgc_execution_waves::{
    AntiStallAction, CoordinationValidationError, ExecutionWave,
    RGC_COORDINATION_EVENT_SCHEMA_VERSION, RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION,
    RGC_WAVE_HANDOFF_SCHEMA_VERSION, WaveHandoffPackage, default_rgc_execution_wave_protocol,
    default_wave_handoff_package, run_coordination_dry_run, validate_execution_wave_protocol,
    validate_wave_handoff_package,
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
fn rgc_execution_waves_serde_tags_are_stable() {
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave0).unwrap(),
        "\"wave_0\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave1).unwrap(),
        "\"wave_1\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave2).unwrap(),
        "\"wave_2\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave3).unwrap(),
        "\"wave_3\""
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
fn rgc_execution_waves_handoff_rejects_missing_artifact_triad_member() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.artifact_links = vec![
        "artifacts/rgc_execution_waves_coordination/demo/run_manifest.json".to_string(),
        "artifacts/rgc_execution_waves_coordination/demo/events.jsonl".to_string(),
    ];

    let error = validate_wave_handoff_package(&protocol, &handoff)
        .expect_err("handoff without commands.txt artifact should fail");
    assert!(matches!(
        error,
        CoordinationValidationError::MissingRequiredArtifactLink { .. }
    ));
}

#[test]
fn rgc_execution_waves_handoff_rejects_next_steps_without_target_bead_reference() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.next_steps = vec![
        "notify wave lead".to_string(),
        "prepare reservation request".to_string(),
    ];

    let error = validate_wave_handoff_package(&protocol, &handoff).expect_err(
        "handoff next steps must reference at least one target wave bead id for automation",
    );
    assert!(matches!(
        error,
        CoordinationValidationError::MissingTargetWaveNextStep { .. }
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

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn execution_wave_all_const_covers_four_waves() {
    assert_eq!(ExecutionWave::ALL.len(), 4);
    for wave in ExecutionWave::ALL {
        let json = serde_json::to_string(&wave).expect("serialize");
        let recovered: ExecutionWave = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(wave, recovered);
    }
}

#[test]
fn anti_stall_action_serde_round_trip_all_variants() {
    for action in [
        AntiStallAction::Healthy,
        AntiStallAction::Warn,
        AntiStallAction::Escalate,
        AntiStallAction::Reassign,
        AntiStallAction::Split,
    ] {
        let json = serde_json::to_string(&action).expect("serialize");
        let recovered: AntiStallAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(action, recovered);
    }
}

#[test]
fn anti_stall_action_as_str_is_non_empty() {
    for action in [
        AntiStallAction::Healthy,
        AntiStallAction::Warn,
        AntiStallAction::Escalate,
        AntiStallAction::Reassign,
        AntiStallAction::Split,
    ] {
        assert!(!action.as_str().is_empty());
    }
}

#[test]
fn coordination_validation_error_display_is_non_empty() {
    let errors: Vec<CoordinationValidationError> = vec![
        CoordinationValidationError::InvalidSchemaVersion {
            field: "schema".to_string(),
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        },
        CoordinationValidationError::EmptyField {
            field: "from_owner".to_string(),
        },
        CoordinationValidationError::DuplicateWaveEntry {
            wave: "wave_0".to_string(),
        },
        CoordinationValidationError::MissingWaveEntry {
            wave: "wave_3".to_string(),
        },
        CoordinationValidationError::UnknownWaveForHandoff {
            wave: "wave_5".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "error display must not be empty: {err:?}");
    }
}

#[test]
fn wave_handoff_package_serde_round_trip() {
    let handoff = default_wave_handoff_package();
    let json = serde_json::to_string(&handoff).expect("serialize");
    let recovered: WaveHandoffPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(handoff, recovered);
}

#[test]
fn default_protocol_has_entries_for_all_waves() {
    let protocol = default_rgc_execution_wave_protocol();
    assert_eq!(protocol.waves.len(), 4);
    let json = serde_json::to_string(&protocol).expect("serialize");
    assert!(json.contains("wave_0"));
    assert!(json.contains("wave_3"));
}
