#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use frankenengine_engine::performance_regression_gate::{
    evaluate_performance_regression_gate, RegressionGateInput, RegressionGatePolicy,
    RegressionObservation, RegressionWaiver,
};
use serde::Deserialize;

const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_performance_regression_gate_v1.json");

#[derive(Debug, Deserialize)]
struct Contract {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
}

#[derive(Debug, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn rgc_703_contract_is_parseable_and_points_to_expected_surfaces() {
    let contract: Contract = serde_json::from_str(CONTRACT_JSON).expect("contract must parse");
    assert_eq!(
        contract.schema_version,
        "franken-engine.rgc-performance-regression-gate.contract.v1"
    );
    assert_eq!(contract.bead_id, "bd-1lsy.8.3");
    assert!(contract
        .required_artifacts
        .iter()
        .any(|artifact| artifact == "regression_report.json"));

    let root = repo_root();
    assert!(root.join(&contract.gate_runner.script).is_file());
    assert!(root.join(&contract.gate_runner.replay_wrapper).is_file());
}

#[test]
fn regression_gate_produces_fail_closed_decision_and_culprit_ranking() {
    let input = RegressionGateInput::new(
        "trace",
        "decision",
        "policy",
        1_700_000_000,
        vec![
            RegressionObservation::new(
                "scheduler_lane",
                "baseline",
                "sha256:scheduler",
                100_000,
                121_000,
                20_000,
                Some("commit-a".to_string()),
            ),
            RegressionObservation::new(
                "dom_commit",
                "baseline",
                "sha256:dom",
                200_000,
                245_000,
                15_000,
                Some("commit-b".to_string()),
            ),
        ],
        Vec::new(),
    );

    let policy = RegressionGatePolicy {
        warning_regression_millionths: 20_000,
        fail_regression_millionths: 40_000,
        critical_regression_millionths: 200_000,
        max_p_value_millionths: 50_000,
        max_culprits: 5,
    };
    let report = evaluate_performance_regression_gate(&input, &policy);

    assert!(report.blocking, "high regressions must block promotion");
    assert_eq!(report.culprit_ranking.len(), 2);
    assert_eq!(report.culprit_ranking[0].workload_id, "dom_commit");
    assert_eq!(report.culprit_ranking[1].workload_id, "scheduler_lane");
}

#[test]
fn valid_waiver_clears_blocking_outcome() {
    let input = RegressionGateInput::new(
        "trace",
        "decision",
        "policy",
        1_700_000_000,
        vec![RegressionObservation::new(
            "scheduler_lane",
            "baseline",
            "sha256:scheduler",
            100_000,
            150_000,
            20_000,
            Some("commit-a".to_string()),
        )],
        vec![RegressionWaiver::new(
            "waiver-rgc-703",
            "scheduler_lane",
            "perf-oncall",
            1_800_000_000,
            "temporary host jitter",
        )],
    );

    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(
        !report.blocking,
        "valid waiver should suppress blocking finding"
    );
    assert_eq!(report.culprit_ranking.len(), 0);
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].status.as_str(), "waived");
}

#[test]
fn readme_mentions_rgc_703_gate_commands() {
    let readme_path = repo_root().join("README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", readme_path.display()));

    for fragment in [
        "## RGC Performance Regression Gate",
        "./scripts/run_rgc_performance_regression_gate.sh ci",
        "./scripts/e2e/rgc_performance_regression_gate_replay.sh ci",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment: {fragment}"
        );
    }
}
