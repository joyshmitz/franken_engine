use frankenengine_engine::plas_benchmark_bundle::{
    PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION, PlasBenchmarkBundleRequest, PlasBenchmarkCohort,
    PlasBenchmarkExtensionSample, PlasBenchmarkThresholds, PlasBenchmarkTrendPoint,
    build_plas_benchmark_bundle,
};

fn base_sample(extension_id: &str, cohort: PlasBenchmarkCohort) -> PlasBenchmarkExtensionSample {
    PlasBenchmarkExtensionSample {
        extension_id: extension_id.to_string(),
        cohort,
        synthesized_capability_count: 11,
        empirically_required_capability_count: 10,
        manual_authoring_time_ms: 1_000,
        plas_authoring_time_ms: 250,
        benign_request_count: 10_000,
        benign_false_deny_count: 30,
        escrow_event_count: 4,
        observation_window_ns: 3_600_000_000_000,
        witness_present: true,
    }
}

fn representative_samples() -> Vec<PlasBenchmarkExtensionSample> {
    vec![
        base_sample("ext-simple", PlasBenchmarkCohort::Simple),
        base_sample("ext-complex", PlasBenchmarkCohort::Complex),
        base_sample("ext-high-risk", PlasBenchmarkCohort::HighRisk),
        base_sample("ext-boundary", PlasBenchmarkCohort::Boundary),
    ]
}

fn request_with_samples(samples: Vec<PlasBenchmarkExtensionSample>) -> PlasBenchmarkBundleRequest {
    PlasBenchmarkBundleRequest {
        trace_id: "trace-plas-benchmark".to_string(),
        decision_id: "decision-plas-benchmark".to_string(),
        policy_id: "policy-plas-v1".to_string(),
        benchmark_run_id: "run-001".to_string(),
        generated_at_ns: 1_710_000_000_000_000_000,
        samples,
        historical_runs: Vec::new(),
        thresholds: None,
    }
}

#[test]
fn bundle_allows_publication_when_thresholds_pass_for_all_cohorts() {
    let request = request_with_samples(representative_samples());
    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert_eq!(
        decision.schema_version,
        PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION
    );
    assert!(decision.publish_allowed);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.cohort_summaries.len(), 4);
    assert!(decision.overall_summary.required_cohorts_present);
    assert_eq!(decision.trend.len(), 1);

    let json = decision.to_json_pretty().expect("json should serialize");
    assert!(json.contains("plas-bundle-"));

    let markdown = decision.to_markdown_report();
    assert!(markdown.contains("# PLAS Benchmark Bundle"));
    assert!(markdown.contains("## Cohort Summary"));
}

#[test]
fn bundle_denies_when_false_deny_threshold_exceeded() {
    let mut samples = representative_samples();
    samples[2].benign_false_deny_count = 90; // 0.9%

    let request = request_with_samples(samples);
    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("false-deny"))
    );
    assert!(decision
        .events
        .iter()
        .any(|event| event.event == "plas_benchmark_bundle_decision" && event.outcome == "deny"));
}

#[test]
fn bundle_denies_when_required_cohort_is_missing() {
    let mut samples = representative_samples();
    samples.retain(|sample| sample.cohort != PlasBenchmarkCohort::Boundary);

    let request = request_with_samples(samples);
    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("missing representative cohort coverage"))
    );
}

#[test]
fn trend_regression_is_detected_without_blocking_by_default() {
    let mut request = request_with_samples(representative_samples());
    request.historical_runs.push(PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-000".to_string(),
        generated_at_ns: request.generated_at_ns - 1,
        mean_over_privilege_ratio_millionths: 1_050_000,
        mean_authoring_time_reduction_millionths: 800_000,
        mean_false_deny_rate_millionths: 2_000,
        mean_escrow_event_rate_per_hour_millionths: 2_000_000,
        witness_coverage_millionths: 1_000_000,
    });

    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(decision.trend_regression_detected);
    assert!(decision.publish_allowed);
    assert!(
        decision
            .events
            .iter()
            .any(|event| event.event == "trend_regression_check" && event.outcome == "warn")
    );
}

#[test]
fn trend_regression_can_block_when_configured() {
    let mut request = request_with_samples(representative_samples());
    request.historical_runs.push(PlasBenchmarkTrendPoint {
        benchmark_run_id: "run-000".to_string(),
        generated_at_ns: request.generated_at_ns - 1,
        mean_over_privilege_ratio_millionths: 1_050_000,
        mean_authoring_time_reduction_millionths: 800_000,
        mean_false_deny_rate_millionths: 2_000,
        mean_escrow_event_rate_per_hour_millionths: 2_000_000,
        witness_coverage_millionths: 1_000_000,
    });

    request.thresholds = Some(PlasBenchmarkThresholds {
        fail_on_trend_regression: true,
        ..PlasBenchmarkThresholds::default()
    });

    let decision = build_plas_benchmark_bundle(&request).expect("bundle should build");

    assert!(decision.trend_regression_detected);
    assert!(!decision.publish_allowed);
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("trend regression detected"))
    );
}

#[test]
fn bundle_id_is_deterministic_for_reordered_samples() {
    let request_a = request_with_samples(representative_samples());

    let mut reordered = representative_samples();
    reordered.reverse();
    let request_b = request_with_samples(reordered);

    let decision_a = build_plas_benchmark_bundle(&request_a).expect("bundle A should build");
    let decision_b = build_plas_benchmark_bundle(&request_b).expect("bundle B should build");

    assert_eq!(decision_a.bundle_id, decision_b.bundle_id);
    assert_eq!(decision_a.extension_results, decision_b.extension_results);
    assert_eq!(decision_a.cohort_summaries, decision_b.cohort_summaries);
    assert_eq!(decision_a.overall_summary, decision_b.overall_summary);
    assert_eq!(decision_a.publish_allowed, decision_b.publish_allowed);
}
