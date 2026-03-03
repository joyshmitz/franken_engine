#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const PACK_SCHEMA_VERSION: &str = "franken-engine.rgc-runtime-semantics-verification-pack.v1";
const VECTORS_SCHEMA_VERSION: &str =
    "franken-engine.rgc-runtime-semantics-verification-vectors.v1";
const PACK_JSON: &str =
    include_str!("../../../docs/rgc_runtime_semantics_verification_pack_v1.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/rgc_runtime_semantics_verification_vectors_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeSemanticsPackContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_semantics_classes: Vec<String>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    test_vectors_source: String,
    failure_scenarios: Vec<FailureScenario>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FailureScenario {
    scenario_id: String,
    path_type: String,
    command_template: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeSemanticsVectors {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    vectors: Vec<RuntimeSemanticsVector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeSemanticsVector {
    scenario_id: String,
    semantics_class: String,
    severity: String,
    path_type: String,
    deterministic_seed: u64,
    expected_outcome: String,
    expected_policy_action: String,
    command_template: String,
    minimal_repro_pointer: String,
    requires_replay: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> RuntimeSemanticsPackContract {
    serde_json::from_str(PACK_JSON).expect("runtime semantics pack contract must parse")
}

fn parse_vectors() -> RuntimeSemanticsVectors {
    serde_json::from_str(VECTORS_JSON).expect("runtime semantics vectors must parse")
}

fn expected_policy_action_for_class(class_name: &str) -> &'static str {
    match class_name {
        "arithmetic_control_flow" => "execute",
        "object_closure_semantics" => "execute_with_closure_environment",
        "async_error_path" => "execute_with_async_replay",
        _ => "unknown",
    }
}

#[test]
fn rgc_057_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Runtime Semantics Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Required Semantics Classes",
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
fn rgc_057_readme_gate_section_documents_contract_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC Runtime Semantics Verification Pack",
        "./scripts/run_rgc_runtime_semantics_verification_pack.sh ci",
        "./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh ci",
        "docs/rgc_runtime_semantics_verification_pack_v1.json",
        "docs/rgc_runtime_semantics_verification_vectors_v1.json",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/run_manifest.json",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/events.jsonl",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/commands.txt",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/runtime_semantics_verification_report.json",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/step_logs/step_*.log",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_057_contract_is_versioned_and_replay_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, PACK_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.7");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-runtime-semantics-verification-pack-v1"
    );
    assert_eq!(
        contract.test_vectors_source,
        "docs/rgc_runtime_semantics_verification_vectors_v1.json"
    );

    let required_classes: BTreeSet<&str> = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect();
    for class_name in [
        "arithmetic_control_flow",
        "object_closure_semantics",
        "async_error_path",
    ] {
        assert!(
            required_classes.contains(class_name),
            "missing required semantics class {class_name}"
        );
    }

    let log_keys: BTreeSet<&str> = contract
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
        "semantics_class",
        "path_type",
        "outcome",
        "error_code",
    ] {
        assert!(log_keys.contains(key), "missing required log key {key}");
    }

    let artifacts: BTreeSet<&str> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "runtime_semantics_verification_report.json",
        "step_logs/step_*.log",
    ] {
        assert!(
            artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_runtime_semantics_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-runtime-semantics-verification-pack.run-manifest.v1"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_vectors_file"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-057-VECTORS-0001"
            && scenario.expected_message_fragment.contains("missing vectors JSON")
            && !scenario.command_template.trim().is_empty()
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_json"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-057-VECTORS-0002"
            && scenario
                .expected_message_fragment
                .contains("failed to parse vectors JSON")
            && !scenario.command_template.trim().is_empty()
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_semantics"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-057-VECTORS-0003"
            && scenario
                .expected_message_fragment
                .contains("vector contract validation failed")
            && !scenario.command_template.trim().is_empty()
    }));

    assert!(contract.operator_verification.iter().any(|entry| {
        entry.contains("run_rgc_runtime_semantics_verification_pack.sh ci")
    }));
    assert!(contract.operator_verification.iter().any(|entry| {
        entry.contains("rgc_runtime_semantics_verification_pack_replay.sh")
    }));
}

#[test]
fn rgc_057_vectors_are_deterministic_unique_and_complete() {
    let vectors = parse_vectors();
    let contract = parse_contract();

    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
    assert_eq!(vectors.contract_version, "1.0.0");
    assert_eq!(vectors.bead_id, "bd-1lsy.11.7");
    assert_eq!(vectors.generated_by, "bd-1lsy.11.7");
    assert!(vectors.generated_at_utc.ends_with('Z'));
    assert_eq!(vectors.vectors.len(), 3);

    let mut scenario_ids = BTreeSet::new();
    let mut seeds = BTreeSet::new();
    let mut classes_seen = BTreeSet::new();

    for vector in &vectors.vectors {
        assert!(
            scenario_ids.insert(vector.scenario_id.as_str()),
            "duplicate scenario_id {}",
            vector.scenario_id
        );
        assert!(
            seeds.insert(vector.deterministic_seed),
            "duplicate deterministic_seed {}",
            vector.deterministic_seed
        );
        assert!(
            ["critical", "high", "medium", "low"].contains(&vector.severity.as_str()),
            "invalid severity {}",
            vector.severity
        );
        assert!(
            ["golden", "failure"].contains(&vector.path_type.as_str()),
            "invalid path_type {}",
            vector.path_type
        );
        assert!(
            ["expect_pass", "expect_fail_with_minimal_repro"].contains(&vector.expected_outcome.as_str()),
            "invalid expected_outcome {}",
            vector.expected_outcome
        );
        assert!(
            [
                "execute",
                "execute_with_closure_environment",
                "execute_with_async_replay"
            ]
            .contains(&vector.expected_policy_action.as_str()),
            "invalid expected_policy_action {}",
            vector.expected_policy_action
        );
        assert!(vector.requires_replay, "all vectors must require replay");
        assert!(
            !vector.command_template.trim().is_empty(),
            "command_template must not be empty"
        );
        assert!(
            !vector.minimal_repro_pointer.trim().is_empty(),
            "minimal_repro_pointer must not be empty"
        );
        assert_eq!(
            vector.expected_outcome,
            "expect_pass",
            "runtime semantics vectors must currently be golden-path deterministic checks"
        );
        assert_eq!(
            vector.expected_policy_action,
            expected_policy_action_for_class(&vector.semantics_class),
            "unexpected policy action for class {}",
            vector.semantics_class
        );

        classes_seen.insert(vector.semantics_class.as_str());
    }

    let required_classes: BTreeSet<&str> = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(classes_seen, required_classes);
}

#[test]
fn rgc_057_lane_script_preserves_step_logs_and_failure_classification() {
    let path = repo_root().join("scripts/run_rgc_runtime_semantics_verification_pack.sh");
    let script = read_to_string(&path);

    for required_fragment in [
        "step_logs_dir=\"${run_dir}/step_logs\"",
        "step_logs+=(\"${log_path}\")",
        "(timeout-${rch_timeout_seconds}s)",
        "(rch-exit=${status}; remote-exit=${remote_exit_code})",
        "(rch-exit=${status}; missing-remote-exit-marker)",
        "(rch-local-fallback-detected)",
        "rgc-runtime-semantics-verification-pack.run-manifest.v1",
    ] {
        assert!(
            script.contains(required_fragment),
            "missing script fragment in {}: {required_fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_057_contract_and_vectors_files_exist_at_declared_paths() {
    let root = repo_root();
    for path in [
        "docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md",
        "docs/rgc_runtime_semantics_verification_pack_v1.json",
        "docs/rgc_runtime_semantics_verification_vectors_v1.json",
        "scripts/run_rgc_runtime_semantics_verification_pack.sh",
        "scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh",
        "crates/franken-engine/tests/rgc_runtime_semantics_verification_pack.rs",
    ] {
        let full = root.join(path);
        assert!(full.exists(), "expected path to exist: {}", full.display());
    }
}
