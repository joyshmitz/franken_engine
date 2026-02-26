#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IncidentScenario {
    scenario_id: String,
    symptom: String,
    severity: String,
    expected_triage: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserOperatorDeveloperRunbookFixture {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_modes: Vec<String>,
    required_manifest_keys: Vec<String>,
    required_log_keys: Vec<String>,
    drill_replay_commands: Vec<String>,
    incident_matrix: Vec<IncidentScenario>,
}

fn load_fixture() -> ParserOperatorDeveloperRunbookFixture {
    let path = Path::new("tests/fixtures/parser_operator_developer_runbook_v1.json");
    let bytes = fs::read(path).expect("read parser operator/developer runbook fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser operator/developer runbook fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md");
    fs::read_to_string(path).expect("read parser operator/developer runbook doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_operator_developer_runbook.sh");
    fs::read_to_string(path).expect("read parser operator/developer runbook script")
}

fn load_readme() -> String {
    fs::read_to_string(Path::new("../../README.md"))
        .expect("read repository README for runbook references")
}

fn triage_action(scenario: &IncidentScenario) -> &'static str {
    let symptom = scenario.symptom.to_ascii_lowercase();
    let severity = scenario.severity.to_ascii_lowercase();

    if severity == "critical" && symptom.contains("user impact") {
        return "hold_rollout_and_rerun_user_impact_replay";
    }
    if severity == "critical" && symptom.contains("fallback") {
        return "fail_closed_and_rerun_failover_controls";
    }
    if symptom.contains("diagnostic") {
        return "rerun_diagnostics_rubric";
    }
    if symptom.contains("resync") {
        return "rerun_error_recovery_replay";
    }
    if symptom.contains("api compatibility") {
        return "rerun_api_compatibility_gate";
    }
    "unknown"
}

fn assert_required_event_keys(event: &Value, required_keys: &[String]) {
    let obj = event
        .as_object()
        .expect("structured event must be a json object");

    for key in required_keys {
        let value = obj
            .get(key)
            .unwrap_or_else(|| panic!("missing required key `{key}`"));
        if key == "error_code" {
            assert!(
                value.is_null() || value.as_str().is_some_and(|raw| !raw.is_empty()),
                "error_code must be null or non-empty string"
            );
            continue;
        }
        assert!(
            value.as_str().is_some_and(|raw| !raw.trim().is_empty()),
            "required key `{key}` must be non-empty string"
        );
    }
}

#[test]
fn parser_operator_runbook_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser Operator/Developer Runbook (`bd-2mds.1.10.4`)",
        "## Fresh-Operator Dry Run",
        "## Replay-First Troubleshooting Decision Tree",
        "## Scriptable Drill Lane",
        "## Escalation And Rollback Posture",
        "./scripts/run_parser_operator_developer_runbook.sh ci",
        "./scripts/e2e/parser_operator_developer_runbook_replay.sh drill",
    ] {
        assert!(
            doc.contains(section),
            "runbook doc missing required section or command: {section}"
        );
    }
}

#[test]
fn parser_operator_runbook_fixture_contract_versions_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-operator-developer-runbook.fixture.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-2mds.1.10.4");
    assert_eq!(
        fixture.policy_id,
        "policy-parser-operator-developer-runbook-v1"
    );
}

#[test]
fn parser_operator_runbook_fixture_mode_and_key_sets_are_exact() {
    let fixture = load_fixture();

    let expected_modes: BTreeSet<_> = ["check", "test", "clippy", "ci", "drill"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_modes: BTreeSet<_> = fixture.required_modes.iter().cloned().collect();
    assert_eq!(actual_modes, expected_modes);

    let expected_manifest: BTreeSet<_> = [
        "schema_version",
        "bead_id",
        "deterministic_env_schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "deterministic_environment",
        "replay_command",
        "drill_replay_commands",
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

#[test]
fn parser_operator_runbook_replay_drills_cover_required_paths() {
    let fixture = load_fixture();
    assert_eq!(fixture.drill_replay_commands.len(), 2);
    for replay_command in &fixture.drill_replay_commands {
        assert!(
            replay_command.starts_with("./scripts/e2e/parser_"),
            "drill replay command must use parser e2e wrapper: {replay_command}"
        );
        assert!(
            replay_command.ends_with(".sh"),
            "drill replay command must be a shell entrypoint: {replay_command}"
        );
    }
}

#[test]
fn parser_operator_runbook_incident_matrix_triage_is_stable() {
    let fixture = load_fixture();
    assert_eq!(fixture.incident_matrix.len(), 5);
    for scenario in &fixture.incident_matrix {
        let derived = triage_action(scenario);
        assert_eq!(
            derived, scenario.expected_triage,
            "triage mismatch for scenario `{}`",
            scenario.scenario_id
        );
        assert!(
            scenario.replay_command.starts_with("./scripts/"),
            "scenario `{}` replay command must be script entrypoint",
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_operator_runbook_emits_structured_event_contract() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-parser-operator-runbook-static",
        "decision_id": "decision-parser-operator-runbook-static",
        "policy_id": fixture.policy_id,
        "component": "parser_operator_developer_runbook_gate",
        "event": "gate_completed",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&event, &fixture.required_log_keys);
}

#[test]
fn parser_operator_runbook_script_contains_required_markers() {
    let script = load_script();
    for marker in [
        "source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\"",
        "parser_frontier_bootstrap_env",
        "policy-parser-operator-developer-runbook-v1",
        "./scripts/e2e/parser_operator_developer_runbook_replay.sh",
        "parser_frontier_emit_manifest_environment_fields",
        "validate_parser_log_schema.sh --events",
    ] {
        assert!(
            script.contains(marker),
            "runbook script missing required marker: {marker}"
        );
    }
}

#[test]
fn readme_references_operator_runbook_gate_and_replay() {
    let readme = load_readme();
    assert!(
        readme.contains("## Parser Operator/Developer Runbook Gate"),
        "README missing parser operator/developer runbook heading"
    );
    assert!(
        readme.contains("./scripts/run_parser_operator_developer_runbook.sh ci"),
        "README missing parser operator/developer runbook gate command"
    );
    assert!(
        readme.contains("./scripts/e2e/parser_operator_developer_runbook_replay.sh"),
        "README missing parser operator/developer runbook replay command"
    );
}
