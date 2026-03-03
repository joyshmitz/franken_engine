#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::runtime_diagnostics_cli::{
    GcPressureSample, RuntimeDiagnosticsCliInput, RuntimeExtensionState, RuntimeStateInput,
    SchedulerLaneSample,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Deserialize;
use serde_json::Value;

const RGC_061_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-cli-operator-workflow-verification-pack.v1";
const RGC_061_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_cli_operator_workflow_verification_pack_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc061Contract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    workflow_stages: Vec<String>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    failure_scenarios: Vec<Rgc061FailureScenario>,
    gate_runner: Rgc061GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc061FailureScenario {
    scenario_id: String,
    path_type: String,
    command_template: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc061GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> Rgc061Contract {
    serde_json::from_str(RGC_061_CONTRACT_JSON)
        .expect("RGC CLI/operator workflow verification contract must parse")
}

fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!(
        "{prefix}_{}_{}.{}",
        std::process::id(),
        nonce,
        extension
    ));
    path
}

fn write_runtime_input(input: &RuntimeDiagnosticsCliInput) -> PathBuf {
    let path = unique_temp_path("rgc_061_runtime_input", "json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(input).expect("runtime diagnostics input should serialize"),
    )
    .expect("runtime diagnostics input should write");
    path
}

fn write_json_value(value: &Value) -> PathBuf {
    let path = unique_temp_path("rgc_061_signals", "json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(value).expect("json value should serialize"),
    )
    .expect("signals file should write");
    path
}

fn write_text_file(contents: &str) -> PathBuf {
    let path = unique_temp_path("rgc_061_invalid_signals", "json");
    fs::write(&path, contents).expect("text file should write");
    path
}

fn cleanup_path(path: &Path) {
    if !path.exists() {
        return;
    }

    if path.is_dir() {
        let _ = fs::remove_dir_all(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

fn build_clean_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-rgc-061".to_string(),
        decision_id: "decision-rgc-061".to_string(),
        policy_id: "policy-rgc-061".to_string(),
        runtime_state: RuntimeStateInput {
            snapshot_timestamp_ns: 42_000,
            loaded_extensions: vec![RuntimeExtensionState {
                extension_id: "ext-weather".to_string(),
                containment_state: ContainmentState::Running,
            }],
            active_policies: vec!["policy-rgc-061".to_string()],
            security_epoch: SecurityEpoch::from_raw(7),
            gc_pressure: vec![GcPressureSample {
                extension_id: "ext-weather".to_string(),
                used_bytes: 64,
                budget_bytes: 8_192,
            }],
            scheduler_lanes: vec![SchedulerLaneSample {
                lane: "ready".to_string(),
                queue_depth: 0,
                max_depth: 32,
                tasks_submitted: 8,
                tasks_scheduled: 8,
                tasks_completed: 8,
                tasks_timed_out: 0,
            }],
        },
        evidence_entries: Vec::new(),
        hostcall_records: Vec::new(),
        containment_receipts: Vec::new(),
        replay_artifacts: Vec::new(),
    }
}

#[test]
fn rgc_061_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC CLI and Operator Workflow Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Workflow Stages",
        "## Golden-Path and Failure-Path Matrix",
        "## Structured Logging Contract",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_061_contract_is_versioned_and_actionable() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, RGC_061_CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.11");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-cli-operator-workflow-verification-pack-v1"
    );

    let stage_set: BTreeSet<_> = contract
        .workflow_stages
        .iter()
        .map(String::as_str)
        .collect();
    let expected_stage_set: BTreeSet<_> = [
        "init",
        "compile",
        "run",
        "verify",
        "benchmark",
        "replay",
        "triage",
    ]
    .into_iter()
    .collect();
    assert_eq!(stage_set, expected_stage_set);

    let required_log_keys: BTreeSet<_> = contract
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "scenario_id",
        "path_type",
        "outcome",
        "error_code",
    ] {
        assert!(
            required_log_keys.contains(key),
            "missing required log key {key}"
        );
    }

    let required_artifacts: BTreeSet<_> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "support_bundle/preflight_report.json",
        "support_bundle/onboarding_scorecard.json",
    ] {
        assert!(
            required_artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_cli_operator_workflow_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-cli-operator-workflow-verification-pack.run-manifest.v1"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_input"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-061-INPUT-0001"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_signals_json"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-061-SIGNALS-0002"
    }));

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_rgc_cli_operator_workflow_verification_pack.sh ci"))
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("rgc_cli_operator_workflow_verification_pack_replay.sh"))
    );
}

#[test]
fn rgc_061_onboarding_scorecard_golden_path_is_ready_and_writes_artifacts() {
    let input_path = write_runtime_input(&build_clean_input());
    let out_dir = unique_temp_path("rgc_061_out", "dir");

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--summary",
            "--out-dir",
            out_dir.to_str().expect("output dir should be utf8"),
            "--workload-id",
            "pkg/weather-clean",
            "--package-name",
            "weather-clean",
            "--target-platform",
            "linux-x64",
            "--target-platform",
            "linux-x64",
            "--target-platform",
            "macos-arm64",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());

    let summary = String::from_utf8(output.stdout).expect("summary stdout should be utf8");
    assert!(
        summary
            .contains("schema_version: franken-engine.runtime-diagnostics.onboarding-scorecard.v1")
    );
    assert!(summary.contains("readiness: ready"));
    assert!(summary.contains("reproducible_commands:"));

    let scorecard_path = out_dir.join("support_bundle/onboarding_scorecard.json");
    let preflight_path = out_dir.join("support_bundle/preflight_report.json");
    assert!(scorecard_path.exists(), "scorecard artifact should exist");
    assert!(preflight_path.exists(), "preflight artifact should exist");

    let scorecard_json: Value = serde_json::from_str(&read_to_string(&scorecard_path))
        .expect("scorecard artifact should parse");
    assert_eq!(scorecard_json["readiness"], "ready");
    assert_eq!(scorecard_json["score"]["critical_signals"], 0);
    assert_eq!(
        scorecard_json["target_platforms"],
        serde_json::json!(["linux-x64", "macos-arm64"])
    );

    cleanup_path(&input_path);
    cleanup_path(&out_dir);
}

#[test]
fn rgc_061_onboarding_scorecard_failure_path_surfaces_blocked_with_actionable_steps() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_json_value(&serde_json::json!([
        {
            "signal_id": "compat:missing-node-fs-watch",
            "source": "compatibility_advisory",
            "severity": "critical",
            "summary": "missing fs.watch compatibility shim",
            "remediation": "enable fallback watcher shim and rerun compatibility probe",
            "reproducible_command": "frankenctl verify --workflow onboarding",
            "evidence_links": ["artifacts/compatibility/latest/report.json"],
            "owner_hint": "compatibility-lane"
        }
    ]));

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let output_json: Value = serde_json::from_str(&stdout).expect("output should be valid json");

    assert_eq!(output_json["readiness"], "blocked");
    assert_eq!(output_json["score"]["critical_signals"], 1);
    assert_eq!(output_json["next_steps"][0]["owner"], "compatibility-lane");
    assert_eq!(output_json["logs"][0]["event"], "onboarding_scorecard");
    assert_eq!(output_json["logs"][0]["outcome"], "fail");
    assert!(
        output_json["reproducible_commands"]
            .as_array()
            .is_some_and(|commands| commands
                .iter()
                .any(|command| command == "frankenctl verify --workflow onboarding"))
    );

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}

#[test]
fn rgc_061_missing_input_reports_actionable_error() {
    let missing_path = unique_temp_path("rgc_061_missing_input", "json");
    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            missing_path.to_str().expect("missing path should be utf8"),
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("failed to read input file"));
}

#[test]
fn rgc_061_invalid_signals_json_reports_actionable_error() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_text_file("this is not valid json");

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("failed to parse signal file"));
    assert!(stderr.contains("JSON array"));

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}
