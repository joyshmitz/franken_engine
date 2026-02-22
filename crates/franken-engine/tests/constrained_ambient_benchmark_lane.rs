use frankenengine_engine::constrained_ambient_benchmark_lane::{
    ConstrainedAmbientBenchmarkRequest, LaneWorkloadMetrics, ProofAttributionSample,
    run_constrained_ambient_benchmark_lane,
};

#[allow(clippy::too_many_arguments)]
fn workload(
    workload_id: &str,
    output_digest: &str,
    throughput_ops_per_sec: u64,
    latency_p50_ns: u64,
    latency_p95_ns: u64,
    latency_p99_ns: u64,
    memory_peak_bytes: u64,
    allocation_count: u64,
) -> LaneWorkloadMetrics {
    LaneWorkloadMetrics {
        workload_id: workload_id.to_string(),
        output_digest: output_digest.to_string(),
        throughput_ops_per_sec,
        latency_p50_ns,
        latency_p95_ns,
        latency_p99_ns,
        memory_peak_bytes,
        allocation_count,
    }
}

fn attribution(
    proof_id: &str,
    specialization_id: &str,
    constrained_throughput_ops_per_sec: u64,
    without_proof_throughput_ops_per_sec: u64,
    constrained_latency_p95_ns: u64,
    without_proof_latency_p95_ns: u64,
) -> ProofAttributionSample {
    ProofAttributionSample {
        proof_id: proof_id.to_string(),
        specialization_id: specialization_id.to_string(),
        constrained_throughput_ops_per_sec,
        without_proof_throughput_ops_per_sec,
        constrained_latency_p95_ns,
        without_proof_latency_p95_ns,
    }
}

fn baseline_request() -> ConstrainedAmbientBenchmarkRequest {
    ConstrainedAmbientBenchmarkRequest {
        trace_id: "trace-cabl-test".to_string(),
        decision_id: "decision-cabl-test".to_string(),
        policy_id: "policy-cabl-v1".to_string(),
        benchmark_run_id: "bench-run-cabl-001".to_string(),
        constrained_lane: vec![
            workload(
                "parser-hot",
                "digest-parser-hot",
                1_200,
                1_800_000,
                2_500_000,
                4_500_000,
                90_000_000,
                45_000,
            ),
            workload(
                "module-cache",
                "digest-module-cache",
                2_300,
                1_250_000,
                2_100_000,
                3_600_000,
                110_000_000,
                54_000,
            ),
        ],
        ambient_lane: vec![
            workload(
                "parser-hot",
                "digest-parser-hot",
                1_000,
                2_000_000,
                3_000_000,
                5_000_000,
                100_000_000,
                50_000,
            ),
            workload(
                "module-cache",
                "digest-module-cache",
                2_000,
                1_500_000,
                2_500_000,
                4_000_000,
                120_000_000,
                60_000,
            ),
        ],
        proof_attribution: vec![
            attribution(
                "proof-ifc-elide",
                "spec-parser-hot",
                1_200,
                1_000,
                2_500_000,
                3_000_000,
            ),
            attribution(
                "proof-plas-dispatch",
                "spec-module-cache",
                2_300,
                2_000,
                2_100_000,
                2_500_000,
            ),
        ],
    }
}

#[test]
fn allows_when_constrained_lane_beats_ambient_with_identical_outputs() {
    let request = baseline_request();
    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert!(decision.allows_publication());
    assert!(!decision.blocked);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.error_code, None);
    assert_eq!(decision.workload_reports.len(), 2);
    assert_eq!(decision.attribution_reports.len(), 2);
    assert_eq!(decision.summary.workload_count, 2);
    assert_eq!(decision.summary.attribution_count, 2);

    for report in &decision.workload_reports {
        assert!(report.throughput_delta_millionths > 0);
        assert!(report.latency_p95_improvement_millionths > 0);
    }
    for report in &decision.attribution_reports {
        assert!(report.supports_uplift);
    }
    for event in &decision.events {
        assert_eq!(event.component, "constrained_ambient_benchmark_lane");
        assert_eq!(event.trace_id, "trace-cabl-test");
        assert_eq!(event.decision_id, "decision-cabl-test");
        assert_eq!(event.policy_id, "policy-cabl-v1");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn denies_when_output_digests_do_not_match() {
    let mut request = baseline_request();
    request.constrained_lane[0].output_digest = "digest-mismatch".to_string();

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1004"));
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("output digest mismatch"))
    );
}

#[test]
fn denies_when_constrained_lane_regresses_performance() {
    let mut request = baseline_request();
    request.constrained_lane[1].throughput_ops_per_sec = 1_900;

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1005"));
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("regressed"))
    );
}

#[test]
fn denies_when_proof_attribution_shows_no_uplift() {
    let mut request = baseline_request();
    request.proof_attribution[0].constrained_throughput_ops_per_sec = 1_000;
    request.proof_attribution[0].without_proof_throughput_ops_per_sec = 1_000;
    request.proof_attribution[0].constrained_latency_p95_ns = 3_000_000;
    request.proof_attribution[0].without_proof_latency_p95_ns = 3_000_000;

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1006"));
    assert!(
        decision
            .attribution_reports
            .iter()
            .any(|report| !report.supports_uplift)
    );
}

#[test]
fn fails_on_invalid_request_metadata() {
    let mut request = baseline_request();
    request.trace_id.clear();

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn report_id_is_deterministic_for_identical_inputs() {
    let request = baseline_request();
    let decision_a = run_constrained_ambient_benchmark_lane(&request);
    let decision_b = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision_a.report_id, decision_b.report_id);
    assert_eq!(decision_a.workload_reports, decision_b.workload_reports);
    assert_eq!(
        decision_a.attribution_reports,
        decision_b.attribution_reports
    );
}
