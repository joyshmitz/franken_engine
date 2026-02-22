use frankenengine_engine::flamegraph_pipeline::{
    FlamegraphKind, FlamegraphPipelineRequest, FlamegraphQuery, query_flamegraph_artifacts,
    run_flamegraph_pipeline, validate_flamegraph_artifact,
};
use frankenengine_engine::storage_adapter::{
    EventContext, InMemoryStorageAdapter, StorageAdapter, StoreKind, StoreQuery,
};

fn candidate_cpu_folded() -> String {
    [
        "runtime;dispatch;policy_eval 36",
        "runtime;dispatch;hostcall 22",
        "runtime;scheduler;poll 12",
    ]
    .join("\n")
}

fn candidate_alloc_folded() -> String {
    [
        "runtime;alloc;vec_grow 20",
        "runtime;alloc;string_clone 18",
        "runtime;alloc;hashmap_resize 8",
    ]
    .join("\n")
}

fn baseline_cpu_folded() -> String {
    [
        "runtime;dispatch;policy_eval 10",
        "runtime;dispatch;hostcall 30",
        "runtime;scheduler;poll 12",
    ]
    .join("\n")
}

fn baseline_alloc_folded() -> String {
    [
        "runtime;alloc;vec_grow 8",
        "runtime;alloc;string_clone 18",
        "runtime;alloc;hashmap_resize 14",
    ]
    .join("\n")
}

fn request_with_diff() -> FlamegraphPipelineRequest {
    FlamegraphPipelineRequest {
        trace_id: "trace-flamegraph-pipeline".to_string(),
        decision_id: "decision-flamegraph-pipeline".to_string(),
        policy_id: "policy-flamegraph-pipeline-v1".to_string(),
        benchmark_run_id: "bench-run-0001".to_string(),
        optimization_decision_id: "opt-dec-001".to_string(),
        workload_id: "mixed-cpu-io-agent-mesh/L".to_string(),
        benchmark_profile: "L".to_string(),
        config_fingerprint: "cfg-fp-9c91f3ad".to_string(),
        git_commit: "deadbeefcafefeed".to_string(),
        generated_at_utc: "2026-02-22T06:00:00Z".to_string(),
        cpu_folded_stacks: candidate_cpu_folded(),
        allocation_folded_stacks: candidate_alloc_folded(),
        baseline_benchmark_run_id: Some("bench-run-0000".to_string()),
        baseline_cpu_folded_stacks: Some(baseline_cpu_folded()),
        baseline_allocation_folded_stacks: Some(baseline_alloc_folded()),
    }
}

#[test]
fn integration_run_generates_and_stores_cpu_alloc_and_diff_flamegraphs() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(decision.is_success());
    assert_eq!(decision.artifacts.len(), 4);
    assert_eq!(decision.store_keys.len(), 4);

    for artifact in &decision.artifacts {
        validate_flamegraph_artifact(artifact).expect("artifact should be valid");
        assert!(
            artifact.folded_stacks_text.contains(' '),
            "folded-stack payload should contain stack/count rows"
        );
        assert!(artifact.svg.starts_with("<svg"));
        assert!(
            artifact.svg.ends_with("</svg>"),
            "svg must have a closing tag"
        );
    }

    assert!(
        decision.events.iter().any(|event| {
            event.event == "pipeline_completed"
                && event.outcome == "pass"
                && event.error_code.is_none()
        }),
        "pipeline completion event should be present"
    );
    assert_eq!(
        decision
            .events
            .iter()
            .filter(|event| event.event == "flamegraph_stored")
            .count(),
        4
    );
}

#[test]
fn diff_flamegraph_highlights_expected_regression_and_improvement() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let cpu_diff = decision
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == FlamegraphKind::DiffCpu)
        .expect("cpu diff artifact should exist");

    let hotspot_regression = cpu_diff
        .diff_entries
        .iter()
        .find(|entry| entry.stack == "runtime;dispatch;policy_eval")
        .expect("expected regression stack");
    assert_eq!(hotspot_regression.baseline_samples, 10);
    assert_eq!(hotspot_regression.candidate_samples, 36);
    assert_eq!(hotspot_regression.delta_samples, 26);

    let hotspot_improvement = cpu_diff
        .diff_entries
        .iter()
        .find(|entry| entry.stack == "runtime;dispatch;hostcall")
        .expect("expected improvement stack");
    assert_eq!(hotspot_improvement.baseline_samples, 30);
    assert_eq!(hotspot_improvement.candidate_samples, 22);
    assert_eq!(hotspot_improvement.delta_samples, -8);
}

#[test]
fn metadata_is_complete_and_queryable_from_benchmark_ledger_store() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);
    assert!(decision.is_success());

    let cpu_artifacts = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery {
            benchmark_run_id: Some("bench-run-0001".to_string()),
            workload_id: Some("mixed-cpu-io-agent-mesh/L".to_string()),
            git_commit: Some("deadbeefcafefeed".to_string()),
            kind: Some(FlamegraphKind::Cpu),
            decision_id: Some("decision-flamegraph-pipeline".to_string()),
            trace_id: Some("trace-flamegraph-pipeline".to_string()),
            limit: Some(10),
        },
        "trace-query",
        "decision-query",
        "policy-query",
    )
    .expect("query should succeed");

    assert_eq!(cpu_artifacts.len(), 1);
    let artifact = &cpu_artifacts[0];
    assert_eq!(artifact.kind, FlamegraphKind::Cpu);
    assert_eq!(artifact.metadata.benchmark_run_id, "bench-run-0001");
    assert_eq!(artifact.metadata.workload_id, "mixed-cpu-io-agent-mesh/L");
    assert_eq!(artifact.metadata.git_commit, "deadbeefcafefeed");
    assert_eq!(
        artifact.storage_integration_point,
        "frankensqlite::benchmark::ledger"
    );
}

#[test]
fn invalid_folded_stack_returns_typed_error_and_no_partial_artifacts() {
    let mut request = request_with_diff();
    request.cpu_folded_stacks = "runtime;dispatch;policy_eval".to_string();
    request.baseline_cpu_folded_stacks = None;
    request.baseline_allocation_folded_stacks = None;
    request.baseline_benchmark_run_id = None;

    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1003"));
    assert!(!decision.rollback_required);
    assert!(
        decision.events.iter().any(|event| {
            event.event == "pipeline_completed"
                && event.outcome == "fail"
                && event.error_code.as_deref() == Some("FE-FLAME-1003")
        }),
        "failure completion event must include typed error code"
    );

    let stored = query_flamegraph_artifacts(
        &mut adapter,
        &FlamegraphQuery::default(),
        "trace-query-empty",
        "decision-query-empty",
        "policy-query-empty",
    )
    .expect("empty query should succeed");
    assert!(stored.is_empty(), "no artifacts should have been stored");
}

#[test]
fn storage_failure_sets_rollback_required_and_keeps_store_empty() {
    let request = request_with_diff();
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let decision = run_flamegraph_pipeline(&mut adapter, &request);

    assert!(!decision.is_success());
    assert_eq!(decision.error_code.as_deref(), Some("FE-FLAME-1007"));
    assert!(
        decision.rollback_required,
        "storage failures should trigger rollback-required semantics"
    );

    let context = EventContext::new(
        "trace-store-check",
        "decision-store-check",
        "policy-store-check",
    )
    .expect("context");
    let rows = adapter
        .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
        .expect("query should succeed");
    assert!(
        rows.is_empty(),
        "put_batch failure must not leave partial benchmark ledger writes"
    );
}

#[test]
fn artifact_ids_are_deterministic_for_identical_inputs() {
    let request = request_with_diff();

    let mut adapter_a = InMemoryStorageAdapter::new();
    let mut adapter_b = InMemoryStorageAdapter::new();
    let decision_a = run_flamegraph_pipeline(&mut adapter_a, &request);
    let decision_b = run_flamegraph_pipeline(&mut adapter_b, &request);

    assert!(decision_a.is_success());
    assert!(decision_b.is_success());

    let mut ids_a: Vec<String> = decision_a
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    let mut ids_b: Vec<String> = decision_b
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    ids_a.sort();
    ids_b.sort();
    assert_eq!(ids_a, ids_b);
}
