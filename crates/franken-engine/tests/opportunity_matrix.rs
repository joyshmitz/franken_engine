use frankenengine_engine::benchmark_denominator::BenchmarkCase;
use frankenengine_engine::flamegraph_pipeline::{
    FLAMEGRAPH_STORAGE_INTEGRATION_POINT, FlamegraphArtifact, FlamegraphDiffEntry,
    FlamegraphEvidenceLink, FlamegraphKind, FlamegraphMetadata, FoldedStackSample,
};
use frankenengine_engine::opportunity_matrix::{
    HotspotProfileEntry, OpportunityMatrixRequest, OpportunityOutcomeObservation,
    OpportunityStatus, benchmark_pressure_from_cases, derive_candidates_from_hotspots,
    hotspot_profile_from_flamegraphs, run_opportunity_matrix_scoring,
};

fn benchmark_case(workload: &str, franken: f64, baseline: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload.to_string(),
        throughput_franken_tps: franken,
        throughput_baseline_tps: baseline,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn flamegraph_artifact(
    artifact_id: &str,
    benchmark_run_id: &str,
    folded_stacks: Vec<FoldedStackSample>,
) -> FlamegraphArtifact {
    let total_samples = folded_stacks
        .iter()
        .map(|entry| entry.sample_count)
        .sum::<u64>();
    let folded_stacks_text = folded_stacks
        .iter()
        .map(|entry| format!("{} {}", entry.stack, entry.sample_count))
        .collect::<Vec<_>>()
        .join("\n");

    FlamegraphArtifact {
        schema_version: "franken-engine.flamegraph-artifact.v1".to_string(),
        artifact_id: artifact_id.to_string(),
        kind: FlamegraphKind::Cpu,
        metadata: FlamegraphMetadata {
            benchmark_run_id: benchmark_run_id.to_string(),
            baseline_benchmark_run_id: None,
            workload_id: "workload-mixed".to_string(),
            benchmark_profile: "profile-s".to_string(),
            config_fingerprint: "cfg-001".to_string(),
            git_commit: "deadbeef".to_string(),
            generated_at_utc: "2026-02-22T00:00:00Z".to_string(),
        },
        evidence_link: FlamegraphEvidenceLink {
            trace_id: "trace-opportunity".to_string(),
            decision_id: "decision-opportunity".to_string(),
            policy_id: "policy-performance".to_string(),
            benchmark_run_id: benchmark_run_id.to_string(),
            optimization_decision_id: "opt-run-001".to_string(),
            evidence_node_id: "evidence-1".to_string(),
        },
        folded_stacks,
        folded_stacks_text,
        svg: "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".to_string(),
        total_samples,
        diff_from_artifact_id: None,
        diff_entries: Vec::<FlamegraphDiffEntry>::new(),
        warnings: Vec::new(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
    }
}

fn base_request_from_hotspots(hotspots: Vec<HotspotProfileEntry>) -> OpportunityMatrixRequest {
    let node_cases = vec![
        benchmark_case("boot-storm", 150.0, 100.0),
        benchmark_case("capability-churn", 140.0, 100.0),
    ];
    let bun_cases = vec![
        benchmark_case("boot-storm", 160.0, 100.0),
        benchmark_case("capability-churn", 155.0, 100.0),
    ];
    let pressure = benchmark_pressure_from_cases(&node_cases, &bun_cases);
    let candidates =
        derive_candidates_from_hotspots(&hotspots, pressure, 2, 200_000, 1_000_000, 1_000_000, 4);

    OpportunityMatrixRequest {
        trace_id: "trace-opportunity".to_string(),
        decision_id: "decision-opportunity".to_string(),
        policy_id: "policy-performance".to_string(),
        optimization_run_id: "opt-run-001".to_string(),
        benchmark_pressure_millionths: pressure,
        hotspots,
        candidates,
        historical_outcomes: vec![OpportunityOutcomeObservation {
            opportunity_id: "opp:vm:dispatch".to_string(),
            predicted_gain_millionths: 500_000,
            actual_gain_millionths: 420_000,
            completed_at_utc: "2026-02-22T12:00:00Z".to_string(),
        }],
    }
}

#[test]
fn end_to_end_profile_to_ranked_output() {
    let artifacts = vec![
        flamegraph_artifact(
            "fg-1",
            "bench-1",
            vec![
                FoldedStackSample {
                    stack: "vm;dispatch".to_string(),
                    sample_count: 700,
                },
                FoldedStackSample {
                    stack: "vm;gc_tick".to_string(),
                    sample_count: 200,
                },
                FoldedStackSample {
                    stack: "net;socket_poll".to_string(),
                    sample_count: 100,
                },
            ],
        ),
        flamegraph_artifact(
            "fg-2",
            "bench-2",
            vec![FoldedStackSample {
                stack: "vm;dispatch".to_string(),
                sample_count: 100,
            }],
        ),
    ];

    let hotspots = hotspot_profile_from_flamegraphs(&artifacts);
    assert!(!hotspots.is_empty());
    assert_eq!(hotspots[0].module, "vm");
    assert_eq!(hotspots[0].function, "dispatch");

    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);

    assert_eq!(decision.outcome, "allow");
    assert!(decision.has_selected_opportunities());
    assert!(!decision.selected_opportunity_ids.is_empty());
    assert_eq!(
        decision.ranked_opportunities[0].target_function, "dispatch",
        "highest hotspot should rank first in deterministic ordering",
    );
}

#[test]
fn structured_events_contain_required_fields() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);

    assert!(!decision.events.is_empty());
    for event in &decision.events {
        assert_eq!(event.trace_id, "trace-opportunity");
        assert_eq!(event.decision_id, "decision-opportunity");
        assert_eq!(event.policy_id, "policy-performance");
        assert_eq!(event.component, "opportunity_matrix");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn historical_tracking_records_predicted_vs_actual_error() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    request.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp:vm:dispatch".to_string(),
            predicted_gain_millionths: 400_000,
            actual_gain_millionths: 520_000,
            completed_at_utc: "2026-02-22T12:00:00Z".to_string(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp:vm:gc_tick".to_string(),
            predicted_gain_millionths: 300_000,
            actual_gain_millionths: 250_000,
            completed_at_utc: "2026-02-22T12:05:00Z".to_string(),
        },
    ];

    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.historical_tracking.len(), 2);
    assert_eq!(
        decision.historical_tracking[0].signed_error_millionths,
        120_000
    );
    assert_eq!(
        decision.historical_tracking[1].signed_error_millionths,
        -50_000
    );
    assert_eq!(
        decision.historical_tracking[1].absolute_error_millionths,
        50_000
    );
}

#[test]
fn invalid_historical_timestamp_causes_fail_outcome() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    request.historical_outcomes = vec![OpportunityOutcomeObservation {
        opportunity_id: "opp:vm:dispatch".to_string(),
        predicted_gain_millionths: 500_000,
        actual_gain_millionths: 450_000,
        completed_at_utc: "not-a-timestamp".to_string(),
    }];

    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.error_code.is_some());
}

#[test]
fn security_clearance_zero_prevents_selection() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    assert!(!request.candidates.is_empty());
    request.candidates[0].security_clearance_millionths = 0;

    let decision = run_opportunity_matrix_scoring(&request);
    let first = &decision.ranked_opportunities[0];
    assert_eq!(first.status, OpportunityStatus::RejectedSecurityClearance);
    assert!(!first.threshold_met);
}
