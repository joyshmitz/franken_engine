#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserThirdPartyRerunKitFixture {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_modes: Vec<String>,
    required_manifest_keys: Vec<String>,
    required_log_keys: Vec<String>,
    matrix_input_statuses: Vec<String>,
    upstream_matrix_inputs: Vec<String>,
    replay_command: String,
}

fn load_fixture() -> ParserThirdPartyRerunKitFixture {
    let path = Path::new("tests/fixtures/parser_third_party_rerun_kit_v1.json");
    let bytes = fs::read(path).expect("read parser third-party rerun kit fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser third-party rerun kit fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_THIRD_PARTY_RERUN_KIT.md");
    fs::read_to_string(path).expect("read parser third-party rerun kit contract doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_third_party_rerun_kit.sh");
    fs::read_to_string(path).expect("read parser third-party rerun kit script")
}

fn classify_matrix_input_status(
    matrix_summary_provided: bool,
    matrix_complete: bool,
    critical_delta_count: u64,
) -> &'static str {
    if !matrix_summary_provided {
        return "pending_upstream_matrix";
    }
    if !matrix_complete {
        return "incomplete_matrix";
    }
    if critical_delta_count > 0 {
        return "blocked_critical_deltas";
    }
    "ready_for_external_rerun"
}

fn assert_required_event_keys(event: &Value, required_keys: &[String]) {
    for key in required_keys {
        let value = event
            .get(key)
            .unwrap_or_else(|| panic!("missing required key in event: {key}"));
        if key == "error_code" {
            assert!(
                value.is_null() || value.as_str().is_some_and(|raw| !raw.is_empty()),
                "error_code must be null or non-empty string"
            );
            continue;
        }
        assert!(
            value.as_str().is_some_and(|raw| !raw.is_empty()),
            "event key `{key}` must be non-empty string"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "# Parser Third-Party Rerun Kit Contract",
        "## Scope",
        "## Contract Version",
        "## Upstream Dependencies",
        "## Kit Contents",
        "## Matrix Input Status Model",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "third-party rerun kit doc missing section: {section}"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_fixture_declares_expected_versions() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-third-party-rerun-kit.fixture.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-2mds.1.7.3");
    assert_eq!(fixture.policy_id, "policy-parser-third-party-rerun-kit-v1");
    assert_eq!(
        fixture.replay_command,
        "./scripts/e2e/parser_third_party_rerun_kit_replay.sh package"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_modes_and_statuses_are_complete() {
    let fixture = load_fixture();

    let expected_modes: BTreeSet<_> = ["check", "test", "clippy", "ci", "package"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_modes: BTreeSet<_> = fixture.required_modes.iter().cloned().collect();
    assert_eq!(actual_modes, expected_modes);

    let expected_statuses: BTreeSet<_> = [
        "pending_upstream_matrix",
        "incomplete_matrix",
        "blocked_critical_deltas",
        "ready_for_external_rerun",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_statuses: BTreeSet<_> = fixture.matrix_input_statuses.iter().cloned().collect();
    assert_eq!(actual_statuses, expected_statuses);

    let expected_inputs: BTreeSet<_> = ["summary", "deltas", "run_manifest"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_inputs: BTreeSet<_> = fixture.upstream_matrix_inputs.iter().cloned().collect();
    assert_eq!(actual_inputs, expected_inputs);
}

#[test]
fn parser_third_party_rerun_kit_matrix_status_classifier_remains_stable() {
    assert_eq!(
        classify_matrix_input_status(false, false, 0),
        "pending_upstream_matrix"
    );
    assert_eq!(
        classify_matrix_input_status(true, false, 0),
        "incomplete_matrix"
    );
    assert_eq!(
        classify_matrix_input_status(true, true, 2),
        "blocked_critical_deltas"
    );
    assert_eq!(
        classify_matrix_input_status(true, true, 0),
        "ready_for_external_rerun"
    );
}

#[test]
fn parser_third_party_rerun_kit_structured_events_require_contract_keys() {
    let fixture = load_fixture();

    let gate_event = json!({
        "schema_version": "franken-engine.parser-third-party-rerun-kit.event.v1",
        "trace_id": "trace-parser-third-party-rerun-kit-static",
        "decision_id": "decision-parser-third-party-rerun-kit-static",
        "policy_id": fixture.policy_id,
        "component": "parser_third_party_rerun_kit_gate",
        "event": "gate_completed",
        "matrix_input_status": "pending_upstream_matrix",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&gate_event, &fixture.required_log_keys);
}

#[test]
fn parser_third_party_rerun_kit_script_contains_required_markers() {
    let script = load_script();
    let required_markers = [
        "source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\"",
        "parser_frontier_bootstrap_env",
        "policy-parser-third-party-rerun-kit-v1",
        "RCH-E326",
        "PARSER_RERUN_KIT_MATRIX_SUMMARY",
        "parser_frontier_emit_manifest_environment_fields",
        "./scripts/e2e/parser_third_party_rerun_kit_replay.sh",
    ];

    for marker in required_markers {
        assert!(
            script.contains(marker),
            "rerun kit script missing marker: {marker}"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_fixture_manifest_and_log_key_sets_are_exact() {
    let fixture = load_fixture();

    let expected_manifest: BTreeSet<_> = [
        "schema_version",
        "bead_id",
        "deterministic_env_schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "matrix_input_status",
        "deterministic_environment",
        "replay_command",
        "commands",
        "artifacts",
        "operator_verification",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_manifest: BTreeSet<_> = fixture.required_manifest_keys.iter().cloned().collect();
    assert_eq!(actual_manifest, expected_manifest);

    let expected_logs: BTreeSet<_> = [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_logs: BTreeSet<_> = fixture.required_log_keys.iter().cloned().collect();
    assert_eq!(actual_logs, expected_logs);
}
