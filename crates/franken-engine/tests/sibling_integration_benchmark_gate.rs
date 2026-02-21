use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::sibling_integration_benchmark_gate::{
    BaselineLedger, BenchmarkGateFailureCode, BenchmarkGateInput, BenchmarkGateThresholds,
    BenchmarkSnapshot, ControlPlaneOperation, OperationLatencySamples, SiblingIntegration,
    evaluate_sibling_integration_benchmark,
};

fn required_integrations() -> BTreeSet<SiblingIntegration> {
    BTreeSet::from([
        SiblingIntegration::Frankentui,
        SiblingIntegration::Frankensqlite,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::FastapiRust,
    ])
}

fn op_samples(without: &[u64], with: &[u64]) -> OperationLatencySamples {
    OperationLatencySamples {
        without_integrations_ns: without.to_vec(),
        with_integrations_ns: with.to_vec(),
    }
}

fn snapshot(id: &str, run_id: &str, policy_query_with: &[u64]) -> BenchmarkSnapshot {
    let mut operation_samples = BTreeMap::new();
    operation_samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        op_samples(
            &[1_000_000, 1_010_000, 1_020_000, 1_030_000, 1_040_000],
            &[1_200_000, 1_210_000, 1_220_000, 1_230_000, 1_240_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        op_samples(
            &[800_000, 810_000, 820_000, 830_000, 840_000],
            policy_query_with,
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        op_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[1_080_000, 1_090_000, 1_100_000, 1_110_000, 1_120_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TuiDataUpdate,
        op_samples(
            &[1_200_000, 1_210_000, 1_220_000, 1_230_000, 1_240_000],
            &[1_420_000, 1_430_000, 1_440_000, 1_450_000, 1_460_000],
        ),
    );
    BenchmarkSnapshot {
        snapshot_id: id.to_string(),
        benchmark_run_id: run_id.to_string(),
        integrations: required_integrations(),
        operation_samples,
    }
}

#[test]
fn benchmark_gate_rejects_policy_query_regression_and_sets_rollback() {
    let baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate",
        "candidate-run",
        &[1_350_000, 1_360_000, 1_370_000, 1_380_000, 1_390_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-bench-regress".to_string(),
        policy_id: "policy-bench-regress".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    assert!(!decision.pass);
    assert!(decision.rollback_required);
    assert!(
        decision
            .findings
            .iter()
            .any(|finding| finding.code == BenchmarkGateFailureCode::RegressionThresholdExceeded)
    );
    let summary_log = decision
        .logs
        .last()
        .expect("decision log must be present for failed gate");
    assert_eq!(summary_log.component, "sibling_integration_benchmark_gate");
    assert_eq!(summary_log.event, "benchmark_gate_decision");
    assert_eq!(summary_log.outcome, "fail");
}

#[test]
fn benchmark_gate_decision_is_replay_deterministic() {
    let baseline = snapshot(
        "baseline-replay",
        "baseline-run-replay",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate-replay",
        "candidate-run-replay",
        &[970_000, 975_000, 980_000, 985_000, 990_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-bench-replay".to_string(),
        policy_id: "policy-bench-replay".to_string(),
        baseline,
        candidate,
    };

    let first = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let second =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    assert_eq!(first.decision_id, second.decision_id);
    assert_eq!(first.findings, second.findings);
    assert_eq!(first.evaluations, second.evaluations);
    assert_eq!(first.pass, second.pass);
}

#[test]
fn baseline_ledger_latest_snapshot_can_drive_next_gate_run() {
    let mut ledger = BaselineLedger::default();
    let baseline = snapshot(
        "baseline-ledger",
        "baseline-run-ledger",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    ledger
        .record(1, baseline)
        .expect("initial baseline must record");

    let next_baseline = ledger
        .latest()
        .expect("latest baseline must be available")
        .snapshot
        .clone();
    let candidate = snapshot(
        "candidate-ledger",
        "candidate-run-ledger",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-ledger".to_string(),
        policy_id: "policy-ledger".to_string(),
        baseline: next_baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(decision.pass);
    assert!(!decision.rollback_required);
}
