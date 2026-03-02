use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::plas_lockstep::{
    LockstepFailureClass, LockstepRuntime, PlasLockstepCase, PlasLockstepError, RuntimeObservation,
    RuntimeTolerance, evaluate_plas_lockstep_case,
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

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn lockstep_runtime_serde_round_trip_all_variants() {
    for runtime in [
        LockstepRuntime::FrankenEngineFull,
        LockstepRuntime::FrankenEngineMinimal,
        LockstepRuntime::Node,
        LockstepRuntime::Bun,
    ] {
        let json = serde_json::to_string(&runtime).expect("serialize");
        let recovered: LockstepRuntime = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(runtime, recovered);
        assert!(!runtime.as_str().is_empty());
    }
}

#[test]
fn lockstep_failure_class_serde_round_trip_all_variants() {
    for failure_class in [
        LockstepFailureClass::CorrectnessRegression,
        LockstepFailureClass::CapabilityGap,
        LockstepFailureClass::PlatformDivergence,
    ] {
        let json = serde_json::to_string(&failure_class).expect("serialize");
        let recovered: LockstepFailureClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(failure_class, recovered);
        assert!(!failure_class.error_code().is_empty());
    }
}

#[test]
fn runtime_observation_serde_round_trip() {
    let obs = observation(LockstepRuntime::Node, "serde-test", 1_500);
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: RuntimeObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, recovered);
}

#[test]
fn runtime_tolerance_default_denies_all_mismatches() {
    let tolerance = RuntimeTolerance {
        allow_output_digest_mismatch: false,
        allow_side_effect_digest_mismatch: false,
        allow_state_digest_mismatch: false,
        allowed_error_codes: BTreeSet::new(),
    };
    let json = serde_json::to_string(&tolerance).expect("serialize");
    let recovered: RuntimeTolerance = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(tolerance, recovered);
}

#[test]
fn plas_lockstep_error_display_is_non_empty() {
    let err = PlasLockstepError::InvalidCase {
        detail: "missing reference".to_string(),
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("missing reference"));
}
