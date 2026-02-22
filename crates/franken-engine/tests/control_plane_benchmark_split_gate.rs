use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::control_plane_benchmark_split_gate::{
    BenchmarkSplit, BenchmarkSplitFailureCode, BenchmarkSplitGateInput, BenchmarkSplitSnapshot,
    BenchmarkSplitThresholds, LatencyStatsNs, SplitBenchmarkMetrics,
    evaluate_control_plane_benchmark_split,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn metrics(
    throughput_ops_per_sec: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    peak_rss_delta_bytes: u64,
) -> SplitBenchmarkMetrics {
    SplitBenchmarkMetrics {
        throughput_ops_per_sec,
        latency_ns: LatencyStatsNs {
            p50_ns,
            p95_ns,
            p99_ns,
        },
        peak_rss_delta_bytes,
    }
}

fn stable_baseline_runs() -> Vec<u64> {
    vec![
        1_000_100, 1_000_250, 999_950, 1_000_000, 1_000_150, 1_000_300, 999_975, 1_000_050,
        1_000_125, 1_000_225,
    ]
}

fn previous_snapshot() -> BenchmarkSplitSnapshot {
    BenchmarkSplitSnapshot {
        snapshot_id: "prev-snapshot".to_string(),
        benchmark_run_id: "prev-run".to_string(),
        split_metrics: BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                metrics(1_002_000, 950_000, 1_000_000, 1_050_000, 0),
            ),
            (
                BenchmarkSplit::CxThreading,
                metrics(997_000, 960_000, 1_008_000, 1_060_000, 8 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::DecisionContracts,
                metrics(994_000, 970_000, 1_052_000, 1_098_000, 16 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                metrics(976_000, 980_000, 1_068_000, 1_116_000, 24 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::FullIntegration,
                metrics(958_000, 990_000, 1_080_000, 1_130_000, 30 * 1024 * 1024),
            ),
        ]),
        baseline_throughput_runs_ops_per_sec: stable_baseline_runs(),
    }
}

fn candidate_snapshot(adapter_sleep_ns: u64, evidence_enabled: bool) -> BenchmarkSplitSnapshot {
    let sleep_latency_delta = adapter_sleep_ns;
    let throughput_penalty = adapter_sleep_ns.saturating_mul(50).div_ceil(1_000_000);

    let mut split_metrics = BTreeMap::from([
        (
            BenchmarkSplit::Baseline,
            metrics(1_000_000, 950_000, 1_000_000, 1_050_000, 0),
        ),
        (
            BenchmarkSplit::CxThreading,
            metrics(
                995_000,
                962_000,
                1_008_000 + sleep_latency_delta,
                1_060_000 + sleep_latency_delta,
                8 * 1024 * 1024,
            ),
        ),
        (
            BenchmarkSplit::DecisionContracts,
            metrics(
                993_500u64.saturating_sub(throughput_penalty),
                972_000,
                1_055_000 + sleep_latency_delta,
                1_100_000 + sleep_latency_delta,
                16 * 1024 * 1024,
            ),
        ),
        (
            BenchmarkSplit::EvidenceEmission,
            metrics(
                975_000u64.saturating_sub(throughput_penalty),
                980_000,
                1_068_000 + sleep_latency_delta,
                1_115_000 + sleep_latency_delta,
                24 * 1024 * 1024,
            ),
        ),
        (
            BenchmarkSplit::FullIntegration,
            metrics(
                955_000u64.saturating_sub(throughput_penalty.saturating_mul(2)),
                990_000,
                1_080_000 + sleep_latency_delta,
                1_130_000 + sleep_latency_delta,
                30 * 1024 * 1024,
            ),
        ),
    ]);

    if !evidence_enabled {
        let decision_metrics = split_metrics
            .get(&BenchmarkSplit::DecisionContracts)
            .expect("decision split")
            .clone();
        split_metrics.insert(BenchmarkSplit::EvidenceEmission, decision_metrics.clone());
        split_metrics.insert(BenchmarkSplit::FullIntegration, decision_metrics);
    }

    BenchmarkSplitSnapshot {
        snapshot_id: "candidate-snapshot".to_string(),
        benchmark_run_id: "candidate-run".to_string(),
        split_metrics,
        baseline_throughput_runs_ops_per_sec: stable_baseline_runs(),
    }
}

fn input(
    previous: BenchmarkSplitSnapshot,
    candidate: BenchmarkSplitSnapshot,
) -> BenchmarkSplitGateInput {
    BenchmarkSplitGateInput {
        trace_id: "trace-bd-1rdj".to_string(),
        policy_id: "policy-bd-1rdj".to_string(),
        previous_snapshot: previous,
        candidate_snapshot: candidate,
    }
}

#[test]
fn baseline_stability_requires_ten_runs_with_low_variance() {
    let previous = previous_snapshot();

    let mut too_few_runs = candidate_snapshot(0, true);
    too_few_runs.baseline_throughput_runs_ops_per_sec.pop();
    let too_few_decision = evaluate_control_plane_benchmark_split(
        &input(previous.clone(), too_few_runs),
        &BenchmarkSplitThresholds::default(),
    );
    assert!(too_few_decision.findings.iter().any(|finding| {
        finding.code == BenchmarkSplitFailureCode::InsufficientBaselineRuns
            && finding.split == Some(BenchmarkSplit::Baseline)
    }));

    let mut high_variance = candidate_snapshot(0, true);
    high_variance.baseline_throughput_runs_ops_per_sec = vec![
        750_000, 1_250_000, 740_000, 1_260_000, 760_000, 1_240_000, 730_000, 1_270_000, 770_000,
        1_230_000,
    ];
    let high_variance_decision = evaluate_control_plane_benchmark_split(
        &input(previous, high_variance),
        &BenchmarkSplitThresholds::default(),
    );

    assert!(high_variance_decision.findings.iter().any(|finding| {
        finding.code == BenchmarkSplitFailureCode::BaselineVarianceExceeded
            && finding.split == Some(BenchmarkSplit::Baseline)
    }));
}

#[test]
fn regression_detection_flags_adapter_sleep_injection_and_requires_rollback() {
    let decision = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(350_000, true)),
        &BenchmarkSplitThresholds::default(),
    );

    assert!(!decision.pass);
    assert!(decision.rollback_required);
    assert!(decision.findings.iter().any(|finding| {
        finding.code == BenchmarkSplitFailureCode::LatencyRegressionExceeded
            || finding.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
            || finding.code == BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
    }));

    assert!(decision.logs.iter().any(|event| {
        event.event == "benchmark_split_decision"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("control_plane_benchmark_split_failed")
            && event.trace_id == "trace-bd-1rdj"
            && event.policy_id == "policy-bd-1rdj"
    }));
}

#[test]
fn disabling_evidence_emission_restores_expected_split_throughput() {
    let previous = previous_snapshot();
    let enabled = evaluate_control_plane_benchmark_split(
        &input(previous.clone(), candidate_snapshot(0, true)),
        &BenchmarkSplitThresholds::default(),
    );
    let disabled = evaluate_control_plane_benchmark_split(
        &input(previous, candidate_snapshot(0, false)),
        &BenchmarkSplitThresholds::default(),
    );

    let enabled_evidence = enabled
        .evaluations
        .iter()
        .find(|evaluation| evaluation.split == BenchmarkSplit::EvidenceEmission)
        .expect("enabled evidence split eval");
    let disabled_evidence = disabled
        .evaluations
        .iter()
        .find(|evaluation| evaluation.split == BenchmarkSplit::EvidenceEmission)
        .expect("disabled evidence split eval");
    let disabled_decision = disabled
        .evaluations
        .iter()
        .find(|evaluation| evaluation.split == BenchmarkSplit::DecisionContracts)
        .expect("disabled decision split eval");

    assert!(
        disabled_evidence.candidate_metrics.throughput_ops_per_sec
            >= enabled_evidence.candidate_metrics.throughput_ops_per_sec
    );
    assert_eq!(
        disabled_evidence.candidate_metrics.throughput_ops_per_sec,
        disabled_decision.candidate_metrics.throughput_ops_per_sec
    );
}

#[test]
fn version_matrix_workflow_runs_control_plane_benchmark_split_gate_suite() {
    let workflow_path = repo_root().join(".github/workflows/version_matrix_conformance.yml");
    let workflow = fs::read_to_string(&workflow_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow_path.display()));

    assert!(
        workflow.contains("./scripts/run_control_plane_benchmark_split_gate_suite.sh ci"),
        "version_matrix_conformance workflow must run control-plane benchmark split gate suite"
    );
}
