#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const RGC_060_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-performance-regression-verification-pack.v1";
const RGC_060_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_performance_regression_verification_pack_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc060Contract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    integrity_requirements: Vec<String>,
    regression_thresholds: RegressionThresholds,
    failure_scenarios: Vec<Rgc060FailureScenario>,
    gate_runner: Rgc060GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RegressionThresholds {
    warning_millionths: u32,
    fail_millionths: u32,
    max_p_value_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc060FailureScenario {
    scenario_id: String,
    path_type: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc060GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkObservation {
    workload_id: String,
    baseline_ns: u64,
    observed_ns: u64,
    p_value_millionths: u32,
    profiler_receipt_id: Option<String>,
    benchmark_metadata_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegressionFinding {
    workload_id: String,
    error_code: String,
    reason: String,
    regression_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateDecision {
    outcome: &'static str,
    findings: Vec<RegressionFinding>,
    culprits: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> Rgc060Contract {
    serde_json::from_str(RGC_060_CONTRACT_JSON)
        .expect("RGC performance/regression verification contract must parse")
}

fn regression_millionths(baseline_ns: u64, observed_ns: u64) -> u32 {
    if baseline_ns == 0 || observed_ns <= baseline_ns {
        return 0;
    }
    let regression = observed_ns.saturating_sub(baseline_ns);
    regression
        .saturating_mul(1_000_000)
        .saturating_div(baseline_ns) as u32
}

fn evaluate_regression_gate(
    observations: &[BenchmarkObservation],
    thresholds: &RegressionThresholds,
) -> GateDecision {
    let mut findings = Vec::new();
    let mut culprits = Vec::new();

    for observation in observations {
        let regression = regression_millionths(observation.baseline_ns, observation.observed_ns);
        let case_id = observation.workload_id.as_str();

        if observation.baseline_ns == 0 {
            findings.push(RegressionFinding {
                workload_id: case_id.to_string(),
                error_code: "FE-RGC-060-BASELINE-0001".to_string(),
                reason: "missing or zero baseline".to_string(),
                regression_millionths: regression,
            });
            culprits.push(case_id.to_string());
            continue;
        }

        if observation
            .profiler_receipt_id
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
        {
            findings.push(RegressionFinding {
                workload_id: case_id.to_string(),
                error_code: "FE-RGC-060-PROFILER-0002".to_string(),
                reason: "missing profiler receipt".to_string(),
                regression_millionths: regression,
            });
            culprits.push(case_id.to_string());
            continue;
        }

        if observation.benchmark_metadata_hash.trim().is_empty() {
            findings.push(RegressionFinding {
                workload_id: case_id.to_string(),
                error_code: "FE-RGC-060-INTEGRITY-0004".to_string(),
                reason: "missing benchmark metadata hash".to_string(),
                regression_millionths: regression,
            });
            culprits.push(case_id.to_string());
            continue;
        }

        if observation.p_value_millionths > thresholds.max_p_value_millionths {
            findings.push(RegressionFinding {
                workload_id: case_id.to_string(),
                error_code: "FE-RGC-060-SIGNIFICANCE-0005".to_string(),
                reason: "insufficient statistical significance".to_string(),
                regression_millionths: regression,
            });
            culprits.push(case_id.to_string());
            continue;
        }

        if regression >= thresholds.fail_millionths {
            findings.push(RegressionFinding {
                workload_id: case_id.to_string(),
                error_code: "FE-RGC-060-REGRESSION-0003".to_string(),
                reason: "regression exceeds fail threshold".to_string(),
                regression_millionths: regression,
            });
            culprits.push(case_id.to_string());
            continue;
        }

        if regression >= thresholds.warning_millionths {
            findings.push(RegressionFinding {
                workload_id: case_id.to_string(),
                error_code: "WARN-RGC-060-REGRESSION-0001".to_string(),
                reason: "warning-level regression".to_string(),
                regression_millionths: regression,
            });
        }
    }

    culprits.sort();
    culprits.dedup();

    GateDecision {
        outcome: if culprits.is_empty() {
            "promote"
        } else {
            "hold"
        },
        findings,
        culprits,
    }
}

fn sample_observations() -> Vec<BenchmarkObservation> {
    vec![
        BenchmarkObservation {
            workload_id: "router_hot_path".to_string(),
            baseline_ns: 100_000,
            observed_ns: 101_000,
            p_value_millionths: 10_000,
            profiler_receipt_id: Some("receipt-router-hot-path".to_string()),
            benchmark_metadata_hash: "sha256:abc123".to_string(),
        },
        BenchmarkObservation {
            workload_id: "dom_commit_batch".to_string(),
            baseline_ns: 200_000,
            observed_ns: 202_000,
            p_value_millionths: 12_000,
            profiler_receipt_id: Some("receipt-dom-commit-batch".to_string()),
            benchmark_metadata_hash: "sha256:def456".to_string(),
        },
    ]
}

#[test]
fn rgc_060_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_PERFORMANCE_REGRESSION_VERIFICATION_PACK_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Performance and Regression Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Integrity Requirements",
        "## Regression Classification",
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
fn rgc_060_readme_gate_section_documents_contract_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC Performance and Regression Verification Pack",
        "./scripts/run_rgc_performance_regression_verification_pack.sh ci",
        "./scripts/e2e/rgc_performance_regression_verification_pack_replay.sh ci",
        "docs/rgc_performance_regression_verification_pack_v1.json",
        "artifacts/rgc_performance_regression_verification_pack/<timestamp>/run_manifest.json",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_060_contract_is_versioned_and_actionable() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, RGC_060_CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.10");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-performance-regression-verification-pack-v1"
    );
    assert!(
        contract.regression_thresholds.warning_millionths
            < contract.regression_thresholds.fail_millionths
    );

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
        "support_bundle/benchmark_report.json",
        "support_bundle/regression_findings.json",
    ] {
        assert!(
            required_artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    let integrity_requirements: BTreeSet<_> = contract
        .integrity_requirements
        .iter()
        .map(String::as_str)
        .collect();
    for requirement in [
        "benchmark_metadata_complete",
        "profiler_receipts_required",
        "baseline_pins_required",
        "environment_manifest_required",
    ] {
        assert!(
            integrity_requirements.contains(requirement),
            "missing integrity requirement {requirement}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_performance_regression_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_performance_regression_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-performance-regression-verification-pack.run-manifest.v1"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_baseline"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-060-BASELINE-0001"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_profiler_receipt"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-060-PROFILER-0002"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "regression_threshold_breach"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-060-REGRESSION-0003"
    }));

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_rgc_performance_regression_verification_pack.sh ci"))
    );
    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("rgc_performance_regression_verification_pack_replay.sh")
        })
    );
}

#[test]
fn rgc_060_regression_gate_promotes_clean_benchmark_samples() {
    let contract = parse_contract();
    let first = evaluate_regression_gate(&sample_observations(), &contract.regression_thresholds);
    let second = evaluate_regression_gate(&sample_observations(), &contract.regression_thresholds);

    assert_eq!(
        first, second,
        "regression gate decision must be deterministic"
    );
    assert_eq!(first.outcome, "promote");
    assert!(first.culprits.is_empty());
}

#[test]
fn rgc_060_regression_gate_blocks_fail_threshold_breach_with_culprit() {
    let contract = parse_contract();
    let mut observations = sample_observations();
    observations.push(BenchmarkObservation {
        workload_id: "scheduler_lane_router".to_string(),
        baseline_ns: 100_000,
        observed_ns: 130_000,
        p_value_millionths: 5_000,
        profiler_receipt_id: Some("receipt-scheduler-lane-router".to_string()),
        benchmark_metadata_hash: "sha256:987654".to_string(),
    });

    let decision = evaluate_regression_gate(&observations, &contract.regression_thresholds);
    assert_eq!(decision.outcome, "hold");
    assert!(
        decision
            .findings
            .iter()
            .any(|finding| finding.error_code == "FE-RGC-060-REGRESSION-0003"),
        "fail-threshold breach must be reported"
    );
    assert_eq!(decision.culprits, vec!["scheduler_lane_router".to_string()]);
}

#[test]
fn rgc_060_regression_gate_blocks_integrity_failures_before_publication() {
    let contract = parse_contract();
    let mut observations = sample_observations();
    observations[0].profiler_receipt_id = Some(String::new());
    observations[1].baseline_ns = 0;

    let decision = evaluate_regression_gate(&observations, &contract.regression_thresholds);
    assert_eq!(decision.outcome, "hold");
    assert!(
        decision
            .findings
            .iter()
            .any(|finding| finding.error_code == "FE-RGC-060-PROFILER-0002"),
        "missing profiler receipt must block publication"
    );
    assert!(
        decision
            .findings
            .iter()
            .any(|finding| finding.error_code == "FE-RGC-060-BASELINE-0001"),
        "missing baseline must block publication"
    );
}
