use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[path = "../src/wave_handoff_contract.rs"]
mod wave_handoff_contract;

use wave_handoff_contract::{
    HandoffValidationErrorCode, WAVE_HANDOFF_FAILURE_CODE, WaveId, WaveTransitionContract,
    simulate_wave_transition, validate_handoff,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = read_to_string(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct HandoffSchemaContract {
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    properties: std::collections::BTreeMap<String, serde_json::Value>,
}

#[test]
fn rgc_015_doc_contains_wave_entry_exit_and_handoff_sections() {
    let path = repo_root().join("docs/FRX_CROSS_TRACK_HANDOFF_PROTOCOL_V1.md");
    let doc = read_to_string(&path);

    let required_sections = [
        "# FRX Cross-Track Handoff Protocol v1",
        "## Wave Model",
        "## Wave Entry Criteria",
        "## Wave Exit Criteria",
        "## Mandatory Handoff Package",
        "## Automated Validation and Failure Policy",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }

    for phrase in [
        "wave_0",
        "wave_1",
        "wave_2",
        "wave_3",
        "entry",
        "exit",
        "handoff package",
        "artifact",
        "open risks",
        "next-step recommendations",
        "fe-rgc-015-handoff-0001",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn rgc_015_schema_includes_wave_and_handoff_package_requirements() {
    let path = repo_root().join("docs/frx_handoff_packet_schema_v1.json");
    let schema: HandoffSchemaContract = load_json(&path);
    let required = schema.required;

    for field in [
        "wave_id",
        "producer_owner",
        "consumer_owner",
        "entry_criteria",
        "exit_criteria",
        "criteria_attestations",
        "handoff_package",
    ] {
        assert!(
            required
                .iter()
                .any(|required_field| required_field == field),
            "required field missing from schema: {field}"
        );
    }

    for field in [
        "wave_id",
        "producer_owner",
        "consumer_owner",
        "entry_criteria",
        "exit_criteria",
        "criteria_attestations",
        "handoff_package",
    ] {
        assert!(
            schema.properties.contains_key(field),
            "properties missing expected key: {field}"
        );
    }
}

#[test]
fn rgc_015_validation_accepts_complete_handoff_package() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let package = wave_handoff_contract::HandoffPackage::baseline();

    let report = validate_handoff(
        "trace-rgc-015-pass",
        "decision-rgc-015-pass",
        "policy-rgc-015-v1",
        &contract,
        &package,
    );
    assert!(report.valid);
    assert_eq!(report.outcome, "pass");
    assert_eq!(report.error_code, "none");
}

#[test]
fn rgc_015_validation_rejects_weak_or_missing_handoff_contents() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut package = wave_handoff_contract::HandoffPackage::baseline();
    package.next_step_recommendations.clear();
    package.completeness_score_milli = 100;
    package.criteria_attestations.pop();

    let report = validate_handoff(
        "trace-rgc-015-fail",
        "decision-rgc-015-fail",
        "policy-rgc-015-v1",
        &contract,
        &package,
    );
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
    assert_eq!(report.error_code, WAVE_HANDOFF_FAILURE_CODE);
    assert!(report.failures.iter().any(|failure| {
        failure.code == HandoffValidationErrorCode::MissingRequiredField
            && failure.message.contains("next_step_recommendations")
    }));
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.code == HandoffValidationErrorCode::WeakHandoffPackage)
    );
    assert!(report.failures.iter().any(|failure| {
        failure.code == HandoffValidationErrorCode::MissingCriterionAttestation
            && failure.message.contains("exit-handoff-schema")
    }));
}

#[test]
fn rgc_015_e2e_transition_emits_deterministic_structured_events() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let package = wave_handoff_contract::HandoffPackage::baseline();

    let (report, events) = simulate_wave_transition(
        "trace-rgc-015-e2e",
        "decision-rgc-015-e2e",
        "policy-rgc-015-v1",
        &contract,
        &package,
    );

    assert!(report.valid);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event, "handoff_received");
    assert_eq!(events[1].event, "criteria_validated");
    assert_eq!(events[2].event, "ownership_transition_committed");

    for event in events {
        assert_eq!(event.schema_version, "frx.handoff.packet.v1");
        assert_eq!(event.trace_id, "trace-rgc-015-e2e");
        assert_eq!(event.decision_id, "decision-rgc-015-e2e");
        assert_eq!(event.policy_id, "policy-rgc-015-v1");
        assert_eq!(event.component, "rgc_wave_handoff_contract");
        assert_eq!(event.wave_id, "wave_1");
        assert_eq!(event.packet_id, "pkt-rgc-wave-1-demo");
    }
}
