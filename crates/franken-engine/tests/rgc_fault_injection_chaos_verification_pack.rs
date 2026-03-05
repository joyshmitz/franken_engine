#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const PACK_SCHEMA_VERSION: &str = "franken-engine.rgc-fault-injection-chaos-verification-pack.v1";
const VECTORS_SCHEMA_VERSION: &str =
    "franken-engine.rgc-fault-injection-chaos-verification-vectors.v1";
const PACK_JSON: &str =
    include_str!("../../../docs/rgc_fault_injection_chaos_verification_pack_v1.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/rgc_fault_injection_chaos_verification_vectors_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChaosVerificationPackContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_chaos_classes: Vec<String>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    test_vectors_source: String,
    failure_scenarios: Vec<FailureScenario>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FailureScenario {
    scenario_id: String,
    path_type: String,
    command_template: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChaosVerificationVectors {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    vectors: Vec<ChaosScenarioVector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChaosScenarioVector {
    scenario_id: String,
    chaos_class: String,
    severity: String,
    path_type: String,
    deterministic_seed: u64,
    expected_outcome: String,
    expected_policy_action: String,
    command_template: String,
    requires_replay: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> ChaosVerificationPackContract {
    serde_json::from_str(PACK_JSON).expect("chaos verification pack contract must parse")
}

fn parse_vectors() -> ChaosVerificationVectors {
    serde_json::from_str(VECTORS_JSON).expect("chaos verification vectors must parse")
}

fn expected_policy_action_for_class(class_name: &str) -> &'static str {
    match class_name {
        "containment_trigger" => "challenge_and_contain",
        "fault_containment" => "quarantine",
        "degraded_mode_recovery" => "degraded_mode",
        _ => "unknown",
    }
}

fn expected_outcome_for_class(class_name: &str) -> &'static str {
    match class_name {
        "fault_containment" => "expect_fail_with_containment",
        "containment_trigger" | "degraded_mode_recovery" => "expect_pass",
        _ => "unknown",
    }
}

#[test]
fn rgc_056_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_FAULT_INJECTION_CHAOS_VERIFICATION_PACK_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Fault-Injection and Chaos Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Required Chaos Classes",
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
fn rgc_056_readme_gate_section_documents_contract_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC Fault-Injection and Chaos Verification Pack",
        "./scripts/run_rgc_fault_injection_chaos_verification_pack.sh ci",
        "./scripts/e2e/rgc_fault_injection_chaos_verification_pack_replay.sh ci",
        "docs/rgc_fault_injection_chaos_verification_pack_v1.json",
        "docs/rgc_fault_injection_chaos_verification_vectors_v1.json",
        "artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/run_manifest.json",
        "artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/events.jsonl",
        "artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/commands.txt",
        "artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/chaos_verification_report.json",
        "artifacts/rgc_fault_injection_chaos_verification_pack/<timestamp>/step_logs/step_*.log",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_056_contract_is_versioned_and_replay_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, PACK_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.6");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-fault-injection-chaos-verification-pack-v1"
    );
    assert_eq!(
        contract.test_vectors_source,
        "docs/rgc_fault_injection_chaos_verification_vectors_v1.json"
    );

    let required_classes: BTreeSet<&str> = contract
        .required_chaos_classes
        .iter()
        .map(String::as_str)
        .collect();
    for class_name in [
        "containment_trigger",
        "fault_containment",
        "degraded_mode_recovery",
    ] {
        assert!(
            required_classes.contains(class_name),
            "missing required chaos class {class_name}"
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
        "chaos_class",
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
        "chaos_verification_report.json",
        "step_logs/step_*.log",
    ] {
        assert!(
            artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_fault_injection_chaos_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_fault_injection_chaos_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-fault-injection-chaos-verification-pack.run-manifest.v1"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_vectors_file"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-056-VECTORS-0001"
            && scenario
                .expected_message_fragment
                .contains("missing vectors JSON")
            && !scenario.command_template.trim().is_empty()
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_json"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-056-VECTORS-0002"
            && scenario
                .expected_message_fragment
                .contains("failed to parse vectors JSON")
            && !scenario.command_template.trim().is_empty()
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_semantics"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-056-VECTORS-0003"
            && scenario
                .expected_message_fragment
                .contains("vector contract validation failed")
            && !scenario.command_template.trim().is_empty()
    }));

    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("run_rgc_fault_injection_chaos_verification_pack.sh ci")
        })
    );
    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("rgc_fault_injection_chaos_verification_pack_replay.sh")
        })
    );
}

#[test]
fn rgc_056_vectors_are_deterministic_unique_and_complete() {
    let vectors = parse_vectors();
    let contract = parse_contract();

    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
    assert_eq!(vectors.contract_version, "1.0.0");
    assert_eq!(vectors.bead_id, "bd-1lsy.11.6");
    assert_eq!(vectors.generated_by, "bd-1lsy.11.6");
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
            [
                "expect_pass",
                "expect_fail_with_containment",
                "expect_fail_without_containment",
            ]
            .contains(&vector.expected_outcome.as_str()),
            "invalid expected_outcome {}",
            vector.expected_outcome
        );
        assert!(
            ["challenge_and_contain", "quarantine", "degraded_mode"]
                .contains(&vector.expected_policy_action.as_str()),
            "invalid expected_policy_action {}",
            vector.expected_policy_action
        );
        assert!(vector.requires_replay, "all vectors must require replay");
        assert!(
            !vector.command_template.trim().is_empty(),
            "command_template must not be empty"
        );
        assert_eq!(
            vector.expected_policy_action,
            expected_policy_action_for_class(&vector.chaos_class),
            "unexpected policy action for class {}",
            vector.chaos_class
        );
        assert_eq!(
            vector.expected_outcome,
            expected_outcome_for_class(&vector.chaos_class),
            "unexpected outcome for class {}",
            vector.chaos_class
        );

        classes_seen.insert(vector.chaos_class.as_str());
    }

    let required_classes: BTreeSet<&str> = contract
        .required_chaos_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(classes_seen, required_classes);
}

#[test]
fn rgc_056_lane_script_preserves_step_logs_and_failure_classification() {
    let path = repo_root().join("scripts/run_rgc_fault_injection_chaos_verification_pack.sh");
    let script = read_to_string(&path);

    for required_fragment in [
        "step_logs_dir=\"${run_dir}/step_logs\"",
        "step_logs+=(\"${log_path}\")",
        "(timeout-${rch_timeout_seconds}s)",
        "(rch-exit=${status}; remote-exit=${remote_exit_code})",
        "(rch-exit=${status}; missing-remote-exit-marker)",
        "(rch-local-fallback-detected)",
        "rgc-fault-injection-chaos-verification-pack.run-manifest.v1",
    ] {
        assert!(
            script.contains(required_fragment),
            "missing script fragment in {}: {required_fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_056_contract_and_vectors_files_exist_at_declared_paths() {
    let root = repo_root();
    for path in [
        "docs/RGC_FAULT_INJECTION_CHAOS_VERIFICATION_PACK_V1.md",
        "docs/rgc_fault_injection_chaos_verification_pack_v1.json",
        "docs/rgc_fault_injection_chaos_verification_vectors_v1.json",
        "scripts/run_rgc_fault_injection_chaos_verification_pack.sh",
        "scripts/e2e/rgc_fault_injection_chaos_verification_pack_replay.sh",
        "crates/franken-engine/tests/rgc_fault_injection_chaos_verification_pack.rs",
    ] {
        let full = root.join(path);
        assert!(full.exists(), "expected path to exist: {}", full.display());
    }
}

// ---------- contract field completeness ----------

#[test]
fn rgc_056_contract_failure_scenarios_have_unique_ids() {
    let contract = parse_contract();
    let mut ids = BTreeSet::new();
    for scenario in &contract.failure_scenarios {
        assert!(
            ids.insert(scenario.scenario_id.as_str()),
            "duplicate failure scenario id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_056_contract_failure_scenarios_all_have_failure_path_type() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert_eq!(
            scenario.path_type, "failure",
            "scenario {} should be failure path_type",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_056_contract_error_codes_all_start_with_fe_rgc_056() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(
            scenario
                .expected_error_code
                .starts_with("FE-RGC-056-"),
            "scenario {} error code should start with FE-RGC-056-: {}",
            scenario.scenario_id,
            scenario.expected_error_code
        );
    }
}

#[test]
fn rgc_056_contract_chaos_classes_are_exactly_three() {
    let contract = parse_contract();
    assert_eq!(contract.required_chaos_classes.len(), 3);
    let classes: BTreeSet<&str> = contract
        .required_chaos_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        classes,
        ["containment_trigger", "degraded_mode_recovery", "fault_containment"]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn rgc_056_contract_required_log_keys_exactly_ten() {
    let contract = parse_contract();
    assert_eq!(contract.required_log_keys.len(), 10);
}

#[test]
fn rgc_056_contract_required_artifacts_exactly_five() {
    let contract = parse_contract();
    assert_eq!(contract.required_artifacts.len(), 5);
}

// ---------- vectors cross-referencing ----------

#[test]
fn rgc_056_vectors_match_contract_version() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    assert_eq!(contract.contract_version, vectors.contract_version);
}

#[test]
fn rgc_056_vectors_bead_id_matches_contract() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    assert_eq!(contract.bead_id, vectors.bead_id);
}

#[test]
fn rgc_056_vectors_test_vectors_source_path_matches_actual_file() {
    let contract = parse_contract();
    let root = repo_root();
    let vectors_path = root.join(&contract.test_vectors_source);
    assert!(
        vectors_path.exists(),
        "test_vectors_source path should exist: {}",
        vectors_path.display()
    );
}

#[test]
fn rgc_056_all_vector_scenario_ids_are_nonempty() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        assert!(
            !vector.scenario_id.trim().is_empty(),
            "scenario_id must not be empty"
        );
    }
}

#[test]
fn rgc_056_all_vector_chaos_classes_are_in_contract() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    let required: BTreeSet<&str> = contract
        .required_chaos_classes
        .iter()
        .map(String::as_str)
        .collect();
    for vector in &vectors.vectors {
        assert!(
            required.contains(vector.chaos_class.as_str()),
            "vector chaos_class {} not in contract required classes",
            vector.chaos_class
        );
    }
}

#[test]
fn rgc_056_vectors_have_positive_deterministic_seeds() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        assert!(
            vector.deterministic_seed > 0,
            "deterministic_seed must be positive for {}",
            vector.scenario_id
        );
    }
}

// ---------- serde roundtrip ----------

#[test]
fn rgc_056_contract_json_serde_roundtrip() {
    let contract = parse_contract();
    let json = serde_json::to_string(&contract).expect("contract should serialize");
    let recovered: ChaosVerificationPackContract =
        serde_json::from_str(&json).expect("contract should deserialize");
    assert_eq!(contract, recovered);
}

#[test]
fn rgc_056_vectors_json_serde_roundtrip() {
    let vectors = parse_vectors();
    let json = serde_json::to_string(&vectors).expect("vectors should serialize");
    let recovered: ChaosVerificationVectors =
        serde_json::from_str(&json).expect("vectors should deserialize");
    assert_eq!(vectors, recovered);
}

// ---------- gate runner fields ----------

#[test]
fn rgc_056_gate_runner_script_exists_on_disk() {
    let contract = parse_contract();
    let root = repo_root();
    let script_path = root.join(&contract.gate_runner.script);
    assert!(
        script_path.exists(),
        "gate runner script should exist: {}",
        script_path.display()
    );
}

#[test]
fn rgc_056_gate_runner_replay_wrapper_exists_on_disk() {
    let contract = parse_contract();
    let root = repo_root();
    let replay_path = root.join(&contract.gate_runner.replay_wrapper);
    assert!(
        replay_path.exists(),
        "gate runner replay wrapper should exist: {}",
        replay_path.display()
    );
}

// ---------- expected_policy_action_for_class coverage ----------

#[test]
fn rgc_056_expected_policy_action_for_class_unknown_returns_unknown() {
    assert_eq!(expected_policy_action_for_class("nonexistent"), "unknown");
}

#[test]
fn rgc_056_expected_outcome_for_class_unknown_returns_unknown() {
    assert_eq!(expected_outcome_for_class("nonexistent"), "unknown");
}

#[test]
fn rgc_056_expected_policy_action_for_all_classes_is_not_unknown() {
    let contract = parse_contract();
    for class in &contract.required_chaos_classes {
        let action = expected_policy_action_for_class(class);
        assert_ne!(
            action, "unknown",
            "expected_policy_action_for_class should handle {class}"
        );
    }
}

#[test]
fn rgc_056_expected_outcome_for_all_classes_is_not_unknown() {
    let contract = parse_contract();
    for class in &contract.required_chaos_classes {
        let outcome = expected_outcome_for_class(class);
        assert_ne!(
            outcome, "unknown",
            "expected_outcome_for_class should handle {class}"
        );
    }
}
