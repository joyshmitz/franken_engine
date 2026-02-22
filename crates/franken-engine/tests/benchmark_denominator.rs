use frankenengine_engine::benchmark_denominator::{
    BaselineEngine, BenchmarkCase, BenchmarkDenominatorError, NativeCoveragePoint,
    PublicationContext, PublicationGateInput, SCORE_THRESHOLD, evaluate_publication_gate,
    weighted_geometric_mean,
};

fn case(workload_id: &str, speedup: f64, weight: Option<f64>) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload_id.to_string(),
        throughput_franken_tps: 100.0 * speedup,
        throughput_baseline_tps: 100.0,
        weight,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn context() -> PublicationContext {
    PublicationContext::new(
        "trace-benchmark-denominator-test",
        "decision-benchmark-denominator-test",
        "policy-benchmark-denominator-v1",
    )
}

fn coverage() -> Vec<NativeCoveragePoint> {
    vec![
        NativeCoveragePoint {
            recorded_at_utc: "2026-02-22T00:00:00Z".to_string(),
            native_slots: 80,
            total_slots: 100,
        },
        NativeCoveragePoint {
            recorded_at_utc: "2026-02-23T00:00:00Z".to_string(),
            native_slots: 84,
            total_slots: 100,
        },
    ]
}

#[test]
fn weighted_geometric_mean_matches_known_vector() {
    let cases = vec![case("c1", 2.0, Some(0.5)), case("c2", 8.0, Some(0.5))];
    let score =
        weighted_geometric_mean(&cases, BaselineEngine::Node).expect("score should compute");
    assert!(
        (score - 4.0).abs() < 1e-12,
        "expected score 4.0, got {score}"
    );
}

#[test]
fn weighted_geometric_mean_handles_single_case_equal_weight_defaults_and_outlier() {
    let single = vec![case("single", 3.25, None)];
    let single_score =
        weighted_geometric_mean(&single, BaselineEngine::Node).expect("single-case score");
    assert!((single_score - 3.25).abs() < 1e-12);

    let equal_defaults = vec![
        case("a", 5.0, None),
        case("b", 5.0, None),
        case("c", 5.0, None),
    ];
    let equal_score = weighted_geometric_mean(&equal_defaults, BaselineEngine::Bun)
        .expect("equal default-weight score");
    assert!((equal_score - 5.0).abs() < 1e-12);

    let outlier = vec![
        case("x", 100.0, None),
        case("y", 1.0, None),
        case("z", 1.0, None),
    ];
    let outlier_score =
        weighted_geometric_mean(&outlier, BaselineEngine::Node).expect("outlier score");
    assert!(outlier_score > 4.5 && outlier_score < 4.7);
}

#[test]
fn weighted_geometric_mean_rejects_invalid_weight_sum() {
    let invalid = vec![case("c1", 2.0, Some(0.7)), case("c2", 2.0, Some(0.7))];
    let err = weighted_geometric_mean(&invalid, BaselineEngine::Node)
        .expect_err("invalid weight sum should fail");

    match err {
        BenchmarkDenominatorError::InvalidWeightSum { baseline, .. } => {
            assert_eq!(baseline, "node");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn publication_gate_allows_when_scores_and_quality_gates_pass() {
    let input = PublicationGateInput {
        node_cases: vec![case("n1", 3.2, None), case("n2", 3.4, None)],
        bun_cases: vec![case("b1", 3.1, None), case("b2", 3.3, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-slot-a".to_string(), "lineage-slot-b".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert!(decision.publish_allowed, "gate should allow publication");
    assert!(decision.score_vs_node >= SCORE_THRESHOLD);
    assert!(decision.score_vs_bun >= SCORE_THRESHOLD);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.events.len(), 3);
}

#[test]
fn publication_gate_denies_on_equivalence_or_threshold_failures() {
    let mut node_bad = case("node-bad", 3.5, None);
    node_bad.behavior_equivalent = false;

    let input = PublicationGateInput {
        node_cases: vec![node_bad],
        bun_cases: vec![case("bun-low", 2.5, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-slot-z".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    assert!(!decision.publish_allowed);

    let blockers = decision.blockers.join(" | ");
    assert!(blockers.contains("failed behavior-equivalence"));
    assert!(blockers.contains("score_vs_bun below threshold"));

    let gate_event = decision
        .events
        .iter()
        .find(|event| event.event == "publication_gate_decision")
        .expect("publication gate event should exist");
    assert_eq!(gate_event.outcome, "deny");
    assert!(gate_event.error_code.is_some());
}

#[test]
fn publication_gate_requires_coverage_and_lineage_metadata() {
    let missing_coverage = PublicationGateInput {
        node_cases: vec![case("n", 3.0, None)],
        bun_cases: vec![case("b", 3.0, None)],
        native_coverage_progression: Vec::new(),
        replacement_lineage_ids: vec!["lineage".to_string()],
    };

    let coverage_err = evaluate_publication_gate(&missing_coverage, &context())
        .expect_err("missing coverage should fail");
    assert!(matches!(
        coverage_err,
        BenchmarkDenominatorError::MissingCoverageProgression
    ));

    let missing_lineage = PublicationGateInput {
        node_cases: vec![case("n", 3.0, None)],
        bun_cases: vec![case("b", 3.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["  ".to_string()],
    };

    let lineage_err = evaluate_publication_gate(&missing_lineage, &context())
        .expect_err("missing lineage should fail");
    assert!(matches!(
        lineage_err,
        BenchmarkDenominatorError::MissingReplacementLineage
    ));
}

#[test]
fn publication_gate_events_include_required_structured_fields() {
    let input = PublicationGateInput {
        node_cases: vec![case("n", 3.0, None)],
        bun_cases: vec![case("b", 3.0, None)],
        native_coverage_progression: coverage(),
        replacement_lineage_ids: vec!["lineage-slot-1".to_string()],
    };

    let decision = evaluate_publication_gate(&input, &context()).expect("gate should evaluate");
    for event in decision.events {
        assert_eq!(event.component, "benchmark_denominator");
        assert_eq!(event.trace_id, "trace-benchmark-denominator-test");
        assert_eq!(event.decision_id, "decision-benchmark-denominator-test");
        assert_eq!(event.policy_id, "policy-benchmark-denominator-v1");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}
