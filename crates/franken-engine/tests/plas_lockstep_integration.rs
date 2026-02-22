use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::plas_lockstep::{
    evaluate_plas_lockstep_case, LockstepFailureClass, LockstepRuntime, PlasLockstepCase,
    PlasLockstepError, RuntimeObservation, RuntimeTolerance,
};

fn observation(runtime: LockstepRuntime, tag: &str, elapsed_ns: u64) -> RuntimeObservation {
    RuntimeObservation {
        runtime,
        output_digest: format!("output:{tag}"),
        side_effect_digest: format!("side_effect:{tag}"),
        state_digest: format!("state:{tag}"),
        error_code: None,
        capability_denials: Vec::new(),
        elapsed_ns,
    }
}

fn baseline_case() -> PlasLockstepCase {
    PlasLockstepCase {
        trace_id: "trace-lockstep-001".to_string(),
        decision_id: "decision-lockstep-001".to_string(),
        policy_id: "policy-lockstep-v1".to_string(),
        extension_id: "extension://plas/lockstep".to_string(),
        scenario_id: "scenario-basic-pass".to_string(),
        full_manifest: observation(LockstepRuntime::FrankenEngineFull, "ok", 1_000),
        minimal_policy: observation(LockstepRuntime::FrankenEngineMinimal, "ok", 1_050),
        node_reference: Some(observation(LockstepRuntime::Node, "ok", 980)),
        bun_reference: Some(observation(LockstepRuntime::Bun, "ok", 990)),
        reference_tolerances: BTreeMap::new(),
        max_performance_degradation_millionths: 200_000,
    }
}

#[test]
fn minimal_policy_preserving_behavior_passes_lockstep() {
    let evaluation = evaluate_plas_lockstep_case(baseline_case()).expect("lockstep evaluation");
    assert!(evaluation.pass);
    assert_eq!(evaluation.failure_class, None);
    assert_eq!(evaluation.log.outcome, "pass");
    assert_eq!(evaluation.log.error_code, None);
}

#[test]
fn missing_capability_is_classified_as_capability_gap() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-capability-gap".to_string();
    case.minimal_policy.output_digest = "output:gap".to_string();
    case.minimal_policy.error_code = Some("capability_denied".to_string());
    case.minimal_policy.capability_denials =
        vec!["filesystem.read".to_string(), "network.egress".to_string()];

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::CapabilityGap)
    );
    assert_eq!(evaluation.log.error_code.as_deref(), Some("capability_gap"));
}

#[test]
fn semantic_drift_without_denials_is_correctness_regression() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-correctness-regression".to_string();
    case.minimal_policy.side_effect_digest = "side_effect:drift".to_string();

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
    assert_eq!(
        evaluation.log.error_code.as_deref(),
        Some("correctness_regression")
    );
}

#[test]
fn reference_mismatch_with_matching_minimal_is_platform_divergence() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-platform-divergence".to_string();
    let node = case.node_reference.as_mut().expect("node reference");
    node.output_digest = "output:node-divergent".to_string();

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::PlatformDivergence)
    );
    assert_eq!(
        evaluation.log.error_code.as_deref(),
        Some("platform_divergence")
    );
}

#[test]
fn configured_runtime_tolerance_allows_known_reference_difference() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-runtime-tolerance".to_string();
    let node = case.node_reference.as_mut().expect("node reference");
    node.output_digest = "output:node-known-diff".to_string();
    let mut tolerance = RuntimeTolerance {
        allow_output_digest_mismatch: true,
        allow_side_effect_digest_mismatch: false,
        allow_state_digest_mismatch: false,
        allowed_error_codes: BTreeSet::new(),
    };
    tolerance
        .allowed_error_codes
        .insert("node_known_waiver".to_string());
    case.reference_tolerances
        .insert(LockstepRuntime::Node, tolerance);

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(evaluation.pass);
    assert_eq!(evaluation.failure_class, None);
}

#[test]
fn excessive_performance_degradation_is_correctness_regression() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-performance-regression".to_string();
    case.max_performance_degradation_millionths = 100_000;
    case.minimal_policy.elapsed_ns = 1_400;

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
    let detail = evaluation.failure_detail.expect("failure detail");
    assert!(detail.contains("performance degradation"));
}

#[test]
fn requires_reference_runtime_for_cross_engine_lockstep() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-no-reference".to_string();
    case.node_reference = None;
    case.bun_reference = None;

    let err = evaluate_plas_lockstep_case(case).expect_err("expected invalid case error");
    assert!(matches!(err, PlasLockstepError::InvalidCase { .. }));
    assert!(err.to_string().contains("at least one Node/Bun reference"));
}

#[test]
fn structured_log_fields_are_stable() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-log-contract".to_string();
    case.minimal_policy.output_digest = "output:gap".to_string();
    case.minimal_policy.capability_denials = vec!["ipc.spawn".to_string()];
    case.minimal_policy.error_code = Some("capability_denied".to_string());

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert_eq!(evaluation.log.trace_id, "trace-lockstep-001");
    assert_eq!(evaluation.log.decision_id, "decision-lockstep-001");
    assert_eq!(evaluation.log.policy_id, "policy-lockstep-v1");
    assert_eq!(evaluation.log.component, "plas_lockstep");
    assert_eq!(evaluation.log.event, "plas_lockstep_case_evaluated");
    assert_eq!(evaluation.log.outcome, "fail");
    assert_eq!(evaluation.log.error_code.as_deref(), Some("capability_gap"));
}
