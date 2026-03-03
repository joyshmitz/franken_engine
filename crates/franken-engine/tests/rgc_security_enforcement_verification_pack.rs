#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

const PACK_SCHEMA_VERSION: &str = "franken-engine.rgc-security-enforcement-verification-pack.v1";
const VECTORS_SCHEMA_VERSION: &str =
    "franken-engine.rgc-security-enforcement-verification-vectors.v1";
const PACK_JSON: &str =
    include_str!("../../../docs/rgc_security_enforcement_verification_pack_v1.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/rgc_security_enforcement_verification_vectors_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SecurityVerificationPackContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_attack_classes: Vec<String>,
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
struct SecurityVerificationVectors {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    vectors: Vec<SecurityScenarioVector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SecurityScenarioVector {
    scenario_id: String,
    attack_class: String,
    severity: String,
    path_type: String,
    deterministic_seed: u64,
    expected_policy_action: String,
    expected_containment_state: String,
    expected_outcome: String,
    command_template: String,
    requires_replay: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> SecurityVerificationPackContract {
    serde_json::from_str(PACK_JSON).expect("security verification pack contract must parse")
}

fn parse_vectors() -> SecurityVerificationVectors {
    serde_json::from_str(VECTORS_JSON).expect("security verification vectors must parse")
}

#[test]
fn rgc_059_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# RGC Security Enforcement Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Required Attack Classes",
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
fn rgc_059_contract_is_versioned_and_replay_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, PACK_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.9");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-security-enforcement-verification-pack-v1"
    );

    let attack_classes: BTreeSet<&str> = contract
        .required_attack_classes
        .iter()
        .map(String::as_str)
        .collect();
    for class_name in [
        "capability_denial",
        "ifc_declassification",
        "containment_escalation",
    ] {
        assert!(
            attack_classes.contains(class_name),
            "missing required attack class {class_name}"
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
        "attack_class",
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
        "security_verification_report.json",
    ] {
        assert!(
            artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_security_enforcement_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-security-enforcement-verification-pack.run-manifest.v1"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_vectors_file"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-059-VECTORS-0001"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_json"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-059-VECTORS-0002"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_semantics"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-059-VECTORS-0003"
    }));

    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("run_rgc_security_enforcement_verification_pack.sh ci")
        })
    );
    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("rgc_security_enforcement_verification_pack_replay.sh")
        })
    );
}

#[test]
fn rgc_059_vectors_are_deterministic_unique_and_complete() {
    let vectors = parse_vectors();
    let contract = parse_contract();

    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
    assert_eq!(vectors.contract_version, "1.0.0");
    assert_eq!(vectors.bead_id, "bd-1lsy.11.9");
    assert_eq!(vectors.generated_by, "bd-1lsy.11.9");
    assert!(vectors.generated_at_utc.ends_with('Z'));
    assert!(
        vectors.vectors.len() >= 3,
        "expected at least three vectors"
    );

    let mut scenario_ids = BTreeSet::new();
    let mut seeds = BTreeSet::new();
    let mut attack_classes_seen = BTreeSet::new();

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
            ["golden", "failure"].contains(&vector.path_type.as_str()),
            "invalid path_type {}",
            vector.path_type
        );
        assert!(
            ["critical", "high", "medium", "low"].contains(&vector.severity.as_str()),
            "invalid severity {}",
            vector.severity
        );
        assert!(
            ["deny", "quarantine", "terminate", "allow"]
                .contains(&vector.expected_policy_action.as_str()),
            "invalid expected_policy_action {}",
            vector.expected_policy_action
        );
        assert!(
            ["running", "quarantined", "terminated"]
                .contains(&vector.expected_containment_state.as_str()),
            "invalid expected_containment_state {}",
            vector.expected_containment_state
        );
        assert_eq!(vector.expected_outcome, "pass");
        assert!(vector.requires_replay, "all vectors must require replay");
        assert!(
            !vector.command_template.trim().is_empty(),
            "command_template must not be empty"
        );

        attack_classes_seen.insert(vector.attack_class.as_str());
    }

    let required_attack_classes: BTreeSet<&str> = contract
        .required_attack_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(attack_classes_seen, required_attack_classes);
}

#[test]
fn rgc_059_contract_and_vectors_files_exist_at_declared_paths() {
    let root = repo_root();
    for path in [
        "docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md",
        "docs/rgc_security_enforcement_verification_pack_v1.json",
        "docs/rgc_security_enforcement_verification_vectors_v1.json",
        "scripts/run_rgc_security_enforcement_verification_pack.sh",
        "scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh",
    ] {
        let full = root.join(path);
        assert!(full.exists(), "expected path to exist: {}", full.display());
    }
}
