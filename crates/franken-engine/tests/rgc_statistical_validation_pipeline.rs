#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::performance_statistical_validation::{
    StatisticalValidationInput, StatisticalValidationPolicy, WorkloadOutcome, WorkloadSamples,
    evaluate_statistical_validation,
};
use serde::Deserialize;

const RGC_702_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-statistical-validation-pipeline.v1";
const RGC_702_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_statistical_validation_pipeline_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702Contract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    thresholds: Rgc702Thresholds,
    failure_scenarios: Vec<Rgc702FailureScenario>,
    gate_runner: Rgc702GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702Thresholds {
    max_cv_millionths: u32,
    warning_regression_millionths: u32,
    fail_regression_millionths: u32,
    max_p_value_millionths: u32,
    min_effect_size_millionths: u32,
    confidence_level_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702FailureScenario {
    scenario_id: String,
    path_type: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc702GateRunner {
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

fn parse_contract() -> Rgc702Contract {
    serde_json::from_str(RGC_702_CONTRACT_JSON)
        .expect("RGC statistical validation pipeline contract must parse")
}

fn sample_workload() -> WorkloadSamples {
    WorkloadSamples::new(
        "router_hot_path",
        "golden",
        "sha256:router-hot-path",
        vec![1000, 1001, 999, 1000, 1002, 998, 1000, 1001, 999],
        vec![1030, 1031, 1029, 1030, 1032, 1028, 1031, 1030, 1029],
    )
}

#[test]
fn rgc_702_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_STATISTICAL_VALIDATION_PIPELINE_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Statistical Validation Pipeline V1",
        "## Scope",
        "## Threshold Contract",
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
fn rgc_702_readme_gate_section_documents_contract_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC Statistical Validation Pipeline",
        "./scripts/run_rgc_statistical_validation_pipeline.sh ci",
        "./scripts/e2e/rgc_statistical_validation_pipeline_replay.sh ci",
        "docs/rgc_statistical_validation_pipeline_v1.json",
        "artifacts/rgc_statistical_validation_pipeline/<timestamp>/run_manifest.json",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_702_contract_schema_and_thresholds_are_valid() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, RGC_702_CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.8.2");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-statistical-validation-pipeline-v1"
    );

    assert!(
        contract.thresholds.fail_regression_millionths
            >= contract.thresholds.warning_regression_millionths,
        "fail threshold must not be lower than warning"
    );
    assert!(
        contract.thresholds.max_p_value_millionths <= 1_000_000,
        "p-value threshold must be within millionths"
    );
    assert!(
        (500_000..=999_999).contains(&contract.thresholds.confidence_level_millionths),
        "confidence must be in (0.5, 1.0)"
    );
}

#[test]
fn rgc_702_gate_runner_references_expected_scripts() {
    let contract = parse_contract();

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_statistical_validation_pipeline.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_statistical_validation_pipeline_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-statistical-validation-pipeline.run-manifest.v1"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
}

#[test]
fn rgc_702_failure_scenarios_cover_core_fail_closed_paths() {
    let contract = parse_contract();

    assert!(
        contract
            .failure_scenarios
            .iter()
            .any(|scenario| scenario.expected_error_code == "FE-RGC-702-INTEGRITY-0001"),
        "missing integrity failure scenario"
    );
    assert!(
        contract
            .failure_scenarios
            .iter()
            .any(|scenario| scenario.expected_error_code == "FE-RGC-702-VARIANCE-0003"),
        "missing variance quarantine scenario"
    );
    assert!(
        contract
            .failure_scenarios
            .iter()
            .any(|scenario| scenario.expected_error_code == "FE-RGC-702-REGRESSION-0004"),
        "missing regression failure scenario"
    );
}

#[test]
fn rgc_702_pipeline_flags_regression_failure() {
    let mut policy = StatisticalValidationPolicy::default();
    policy.warmup_drop_samples = 0;
    policy.min_samples_after_filter = 5;
    policy.outlier_policy.min_retained_samples = 5;
    policy.thresholds.warning_regression_millionths = 10_000;
    policy.thresholds.fail_regression_millionths = 20_000;
    policy.thresholds.max_p_value_millionths = 50_000;
    policy.thresholds.min_effect_size_millionths = 3_000;

    let input = StatisticalValidationInput::new(
        "trace-rgc-702",
        "decision-rgc-702",
        "policy-rgc-statistical-validation-pipeline-v1",
        vec![sample_workload()],
    );

    let report = evaluate_statistical_validation(&input, &policy);

    assert!(!report.promote_allowed);
    assert_eq!(report.verdicts.len(), 1);
    assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Fail);
    assert!(
        report
            .failed_workloads
            .contains(&"router_hot_path".to_string()),
        "expected failing workload list to include router_hot_path"
    );
    assert!(
        report.logs.iter().any(|event| {
            event.event == "workload_evaluated" && event.workload_id == "router_hot_path"
        }),
        "expected workload evaluation log event"
    );
}
