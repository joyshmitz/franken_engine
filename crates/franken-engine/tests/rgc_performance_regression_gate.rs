#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use frankenengine_engine::performance_regression_gate::{
    RegressionGateInput, RegressionGatePolicy, RegressionObservation, RegressionWaiver,
    evaluate_performance_regression_gate,
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
    assert!(
        contract
            .required_artifacts
            .iter()
            .any(|artifact| artifact == "regression_report.json")
    );

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

// ---------- RegressionGateInput ----------

#[test]
fn regression_gate_input_serde_roundtrip() {
    let input = RegressionGateInput::new(
        "trace-1",
        "decision-1",
        "policy-1",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload",
            "baseline",
            "sha256:abc",
            100_000,
            110_000,
            10_000,
            Some("commit-x".to_string()),
        )],
        Vec::new(),
    );
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: RegressionGateInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-1");
    assert_eq!(recovered.observations.len(), 1);
}

#[test]
fn regression_gate_input_empty_observations() {
    let input = RegressionGateInput::new(
        "trace-empty",
        "decision-empty",
        "policy-empty",
        1_700_000_000,
        Vec::new(),
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(!report.blocking);
    assert_eq!(report.culprit_ranking.len(), 0);
    assert_eq!(report.regressions.len(), 0);
}

// ---------- RegressionObservation ----------

#[test]
fn regression_observation_serde_roundtrip() {
    let obs = RegressionObservation::new(
        "workload-a",
        "scenario-1",
        "sha256:meta",
        50_000,
        60_000,
        30_000,
        None,
    );
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: RegressionObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, "workload-a");
    assert_eq!(recovered.baseline_ns, 50_000);
    assert!(recovered.commit_id.is_none());
}

// ---------- RegressionWaiver ----------

#[test]
fn regression_waiver_serde_roundtrip() {
    let waiver = RegressionWaiver::new(
        "waiver-1",
        "workload-a",
        "oncall-alice",
        1_800_000_000,
        "host jitter",
    );
    let json = serde_json::to_string(&waiver).expect("serialize");
    let recovered: RegressionWaiver = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.waiver_id, "waiver-1");
    assert_eq!(recovered.owner, "oncall-alice");
}

// ---------- RegressionGatePolicy ----------

#[test]
fn regression_gate_policy_default_values() {
    let policy = RegressionGatePolicy::default();
    assert_eq!(policy.warning_regression_millionths, 25_000);
    assert_eq!(policy.fail_regression_millionths, 50_000);
    assert_eq!(policy.critical_regression_millionths, 100_000);
    assert_eq!(policy.max_p_value_millionths, 50_000);
    assert_eq!(policy.max_culprits, 10);
}

#[test]
fn regression_gate_policy_serde_roundtrip() {
    let policy = RegressionGatePolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: RegressionGatePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

// ---------- severity classification ----------

#[test]
fn zero_baseline_produces_critical_finding() {
    let input = RegressionGateInput::new(
        "trace-zero",
        "decision-zero",
        "policy-zero",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-zero-base",
            "scenario-zero",
            "sha256:meta",
            0,
            100_000,
            10_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(report.blocking);
    assert!(!report.regressions.is_empty());
    assert!(report
        .regressions
        .iter()
        .any(|finding| finding.error_code.contains("BASELINE")));
}

#[test]
fn missing_metadata_hash_produces_high_severity() {
    let input = RegressionGateInput::new(
        "trace-meta",
        "decision-meta",
        "policy-meta",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-no-meta",
            "scenario-meta",
            "",
            100_000,
            200_000,
            10_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(report.blocking);
    assert!(report
        .regressions
        .iter()
        .any(|finding| finding.error_code.contains("INTEGRITY")));
}

#[test]
fn warning_level_regression_does_not_block() {
    let policy = RegressionGatePolicy {
        warning_regression_millionths: 20_000,
        fail_regression_millionths: 200_000,
        critical_regression_millionths: 500_000,
        max_p_value_millionths: 50_000,
        max_culprits: 5,
    };
    let input = RegressionGateInput::new(
        "trace-warn",
        "decision-warn",
        "policy-warn",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-small-regression",
            "scenario-warn",
            "sha256:meta",
            1_000_000,
            1_030_000,
            10_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert!(!report.blocking, "warning-only regression should not block");
}

// ---------- culprit ranking ----------

#[test]
fn culprit_ranking_is_bounded_by_max_culprits() {
    let mut observations = Vec::new();
    for i in 0..15 {
        observations.push(RegressionObservation::new(
            format!("workload-{i}"),
            "scenario-rank",
            "sha256:meta",
            100_000,
            200_000,
            10_000,
            Some(format!("commit-{i}")),
        ));
    }
    let policy = RegressionGatePolicy {
        max_culprits: 5,
        ..RegressionGatePolicy::default()
    };
    let input = RegressionGateInput::new(
        "trace-rank",
        "decision-rank",
        "policy-rank",
        1_700_000_000,
        observations,
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert!(report.culprit_ranking.len() <= 5);
}

// ---------- expired waiver ----------

#[test]
fn expired_waiver_does_not_suppress_blocking() {
    let input = RegressionGateInput::new(
        "trace-expired",
        "decision-expired",
        "policy-expired",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-expired",
            "scenario-expired",
            "sha256:meta",
            100_000,
            200_000,
            10_000,
            None,
        )],
        vec![RegressionWaiver::new(
            "waiver-old",
            "workload-expired",
            "oncall-bob",
            1_600_000_000,
            "no longer valid",
        )],
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(report.blocking, "expired waiver should not suppress blocking");
}

// ---------- report fields ----------

#[test]
fn report_schema_version_is_set() {
    let input = RegressionGateInput::new(
        "trace-schema",
        "decision-schema",
        "policy-schema",
        1_700_000_000,
        Vec::new(),
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(!report.schema_version.is_empty());
    assert_eq!(report.trace_id, "trace-schema");
    assert_eq!(report.decision_id, "decision-schema");
    assert_eq!(report.policy_id, "policy-schema");
    assert_eq!(report.component, "performance_regression_gate");
}

// ---------- determinism ----------

#[test]
fn gate_evaluation_is_deterministic() {
    let input = RegressionGateInput::new(
        "trace-det",
        "decision-det",
        "policy-det",
        1_700_000_000,
        vec![
            RegressionObservation::new("wl-b", "scen", "sha256:b", 100_000, 180_000, 10_000, None),
            RegressionObservation::new("wl-a", "scen", "sha256:a", 100_000, 160_000, 10_000, None),
        ],
        Vec::new(),
    );
    let policy = RegressionGatePolicy::default();
    let left = evaluate_performance_regression_gate(&input, &policy);
    let right = evaluate_performance_regression_gate(&input, &policy);
    assert_eq!(
        serde_json::to_string(&left).unwrap(),
        serde_json::to_string(&right).unwrap()
    );
}

#[test]
fn no_observations_produces_non_blocking_report() {
    let input = RegressionGateInput::new(
        "trace-empty",
        "decision-empty",
        "policy-empty",
        1_700_000_000,
        Vec::new(),
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(!report.blocking, "no observations should not block");
    assert!(report.regressions.is_empty());
}

#[test]
fn contract_json_has_schema_version() {
    let contract: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse contract");
    assert!(!contract.schema_version.is_empty());
    assert!(!contract.bead_id.is_empty());
}

#[test]
fn regression_gate_policy_custom_thresholds_roundtrip() {
    let policy = RegressionGatePolicy {
        warning_regression_millionths: 10_000,
        fail_regression_millionths: 80_000,
        critical_regression_millionths: 200_000,
        max_p_value_millionths: 25_000,
        max_culprits: 3,
    };
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: RegressionGatePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

#[test]
fn regression_gate_policy_default_is_constructible() {
    let policy = RegressionGatePolicy::default();
    assert!(policy.max_culprits > 0);
}

#[test]
fn contract_json_deterministic_double_parse() {
    let a: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse a");
    let b: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse b");
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
}

#[test]
fn regression_observation_all_fields_serde_roundtrip() {
    let obs = RegressionObservation {
        workload_id: "w1".to_string(),
        scenario_id: "s1".to_string(),
        benchmark_metadata_hash: "sha256:abc".to_string(),
        baseline_ns: 1000,
        observed_ns: 1100,
        p_value_millionths: 50_000,
        commit_id: None,
    };
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: RegressionObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, "w1");
}
