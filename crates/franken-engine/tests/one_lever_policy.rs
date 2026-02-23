use std::path::PathBuf;

use frankenengine_engine::one_lever_policy::{
    ERROR_MISSING_EVIDENCE, ERROR_MULTI_LEVER_VIOLATION, ERROR_SCORE_BELOW_THRESHOLD,
    LeverCategory, ONE_LEVER_POLICY_COMPONENT, OneLeverEvidenceRefs, OneLeverPolicyRequest,
    evaluate_one_lever_policy,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn complete_evidence(score_millionths: i64) -> OneLeverEvidenceRefs {
    OneLeverEvidenceRefs {
        baseline_benchmark_run_id: Some("bench://baseline/run-001".to_string()),
        post_change_benchmark_run_id: Some("bench://after/run-002".to_string()),
        delta_report_ref: Some("artifact://delta/run-002".to_string()),
        semantic_equivalence_ref: Some("artifact://golden/equivalence-v1".to_string()),
        trace_replay_ref: Some("artifact://replay/trace-001".to_string()),
        isomorphism_ledger_ref: Some("artifact://isomorphism/ledger-001".to_string()),
        rollback_instructions_ref: Some("docs://rollback/optimization-001".to_string()),
        reprofile_after_merge_ref: Some("artifact://reprofile/post-merge-001".to_string()),
        opportunity_score_millionths: Some(score_millionths),
    }
}

fn base_request() -> OneLeverPolicyRequest {
    OneLeverPolicyRequest {
        trace_id: "trace-one-lever-001".to_string(),
        decision_id: "decision-one-lever-001".to_string(),
        policy_id: "policy-one-lever-v1".to_string(),
        commit_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
        commit_message: "perf: optimize dispatch hotpath".to_string(),
        changed_paths: vec!["crates/franken-engine/src/baseline_interpreter.rs".to_string()],
        evidence: complete_evidence(2_400_000),
    }
}

#[test]
fn multi_lever_change_without_override_is_denied() {
    let mut request = base_request();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/gc_pause.rs".to_string(),
    ];

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_MULTI_LEVER_VIOLATION)
    );
    assert!(decision.is_multi_lever);
    assert!(decision.override_reason.is_none());
    assert!(
        decision
            .lever_categories
            .contains(&LeverCategory::Execution)
    );
    assert!(decision.lever_categories.contains(&LeverCategory::Memory));
}

#[test]
fn multi_lever_override_allows_with_reason() {
    let mut request = base_request();
    request.commit_message =
        "perf: coupled runtime fix [multi-lever: scheduler and gc are tightly coupled]".to_string();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/gc_pause.rs".to_string(),
    ];

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(decision.allows_change());
    assert!(decision.is_multi_lever);
    assert_eq!(
        decision.override_reason.as_deref(),
        Some("scheduler and gc are tightly coupled")
    );
}

#[test]
fn missing_baseline_after_evidence_is_denied() {
    let mut request = base_request();
    request.evidence.baseline_benchmark_run_id = None;
    request.evidence.post_change_benchmark_run_id = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
    assert!(
        decision
            .missing_requirements
            .contains(&"post_change_benchmark_run_id".to_string())
    );
}

#[test]
fn missing_semantic_equivalence_and_replay_refs_is_denied() {
    let mut request = base_request();
    request.evidence.semantic_equivalence_ref = None;
    request.evidence.trace_replay_ref = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"semantic_equivalence_ref".to_string())
    );
    assert!(
        decision
            .missing_requirements
            .contains(&"trace_replay_ref".to_string())
    );
}

#[test]
fn missing_rollback_or_reprofile_is_denied() {
    let mut request = base_request();
    request.evidence.rollback_instructions_ref = None;
    request.evidence.reprofile_after_merge_ref = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"rollback_instructions_ref".to_string())
    );
    assert!(
        decision
            .missing_requirements
            .contains(&"reprofile_after_merge_ref".to_string())
    );
}

#[test]
fn below_threshold_opportunity_score_is_denied() {
    let mut request = base_request();
    request.evidence = complete_evidence(1_999_999);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_SCORE_BELOW_THRESHOLD)
    );
}

#[test]
fn docs_and_tests_only_change_is_exempt() {
    let mut request = base_request();
    request.changed_paths = vec![
        "docs/perf_playbook.md".to_string(),
        "crates/franken-engine/tests/opportunity_matrix.rs".to_string(),
        ".github/workflows/version_matrix_conformance.yml".to_string(),
    ];
    request.evidence = OneLeverEvidenceRefs::default();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(!decision.optimization_change);
    assert!(decision.lever_categories.is_empty());
}

#[test]
fn decision_is_deterministic_for_identical_input() {
    let request = base_request();
    let decision_a = evaluate_one_lever_policy(&request);
    let decision_b = evaluate_one_lever_policy(&request);
    assert_eq!(decision_a, decision_b);
}

#[test]
fn structured_events_have_required_stable_fields() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);

    assert!(!decision.events.is_empty());
    for event in &decision.events {
        assert_eq!(event.trace_id, "trace-one-lever-001");
        assert_eq!(event.decision_id, "decision-one-lever-001");
        assert_eq!(event.policy_id, "policy-one-lever-v1");
        assert_eq!(event.component, ONE_LEVER_POLICY_COMPONENT);
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn version_matrix_workflow_runs_one_lever_policy_gate() {
    let workflow_path = repo_root().join(".github/workflows/version_matrix_conformance.yml");
    let workflow = std::fs::read_to_string(&workflow_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow_path.display()));

    assert!(
        workflow.contains("./scripts/check_one_lever.sh ci"),
        "version_matrix_conformance workflow must run one-lever policy gate script"
    );
}
