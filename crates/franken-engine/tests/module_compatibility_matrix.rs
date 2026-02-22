use std::collections::BTreeSet;

use frankenengine_engine::feature_parity_tracker::{
    FeatureParityTracker, TrackerContext, WaiverRecord,
};
use frankenengine_engine::module_compatibility_matrix::{
    CompatibilityContext, CompatibilityMatrixErrorCode, CompatibilityMode,
    CompatibilityObservation, CompatibilityRuntime, DEFAULT_MATRIX_JSON, ModuleCompatibilityMatrix,
    ModuleFeature,
};

fn context() -> CompatibilityContext {
    CompatibilityContext::new(
        "trace-modcompat-integration",
        "decision-modcompat-integration",
        "policy-modcompat-integration",
    )
}

#[test]
fn default_matrix_is_machine_readable_and_validates_with_declared_waivers() {
    serde_json::from_str::<serde_json::Value>(DEFAULT_MATRIX_JSON)
        .expect("default matrix json must parse");

    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let waivers = matrix.required_waiver_ids();
    assert!(!waivers.is_empty(), "expected at least one required waiver");

    matrix
        .validate_with_waivers(&waivers, &context())
        .expect("default matrix should validate with declared waivers");

    let event = matrix
        .events()
        .last()
        .expect("validation should emit at least one event");
    assert_eq!(event.component, "module_compatibility_matrix");
    assert_eq!(event.trace_id, "trace-modcompat-integration");
    assert_eq!(event.decision_id, "decision-modcompat-integration");
    assert_eq!(event.policy_id, "policy-modcompat-integration");
    assert!(!event.event.is_empty());
    assert!(!event.outcome.is_empty());
    assert!(!event.error_code.is_empty());
}

#[test]
fn default_matrix_covers_required_feature_categories() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let features = matrix
        .entries()
        .into_iter()
        .map(|entry| entry.feature)
        .collect::<BTreeSet<_>>();

    assert!(features.contains(&ModuleFeature::Esm));
    assert!(features.contains(&ModuleFeature::Cjs));
    assert!(features.contains(&ModuleFeature::DualMode));
    assert!(features.contains(&ModuleFeature::ConditionalExports));
    assert!(features.contains(&ModuleFeature::PackageJsonFields));
}

#[test]
fn missing_waiver_fails_validation_with_stable_error_code() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let error = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect_err("expected missing-waiver validation error");

    assert_eq!(error.code, CompatibilityMatrixErrorCode::MissingWaiver);
    let event = error.event.expect("validation errors should include event");
    assert_eq!(
        event.error_code,
        CompatibilityMatrixErrorCode::MissingWaiver.stable_code()
    );
    assert_eq!(event.component, "module_compatibility_matrix");
}

#[test]
fn observation_evaluation_supports_match_and_mismatch_paths() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let waivers = matrix.required_waiver_ids();
    matrix
        .validate_with_waivers(&waivers, &context())
        .expect("matrix validation must pass before observation checks");

    let matched = matrix
        .evaluate_observation(
            &CompatibilityObservation::new(
                "esm-import-cjs-default",
                CompatibilityRuntime::FrankenEngine,
                CompatibilityMode::Native,
                "namespace_default_projection",
            ),
            &context(),
        )
        .expect("expected observation match");
    assert!(matched.matched);
    assert_eq!(matched.event.outcome, "allow");
    assert_eq!(matched.event.error_code, "none");

    let mismatch = matrix
        .evaluate_observation(
            &CompatibilityObservation::new(
                "cjs-require-esm",
                CompatibilityRuntime::FrankenEngine,
                CompatibilityMode::Native,
                "unexpected_behavior",
            ),
            &context(),
        )
        .expect_err("expected mismatch error");
    assert_eq!(
        mismatch.code,
        CompatibilityMatrixErrorCode::ObservationMismatch
    );
}

#[test]
fn tracker_backed_validation_uses_registered_waiver_ids() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");

    let mut tracker = FeatureParityTracker::new();
    let tracker_feature_id = tracker
        .features()
        .keys()
        .next()
        .cloned()
        .expect("tracker should have default features");
    let tracker_ctx = TrackerContext {
        trace_id: "trace-tracker".to_string(),
        decision_id: "decision-tracker".to_string(),
        policy_id: "policy-tracker".to_string(),
    };

    for waiver_id in matrix.required_waiver_ids() {
        tracker
            .register_waiver(
                WaiverRecord {
                    waiver_id,
                    feature_id: tracker_feature_id.clone(),
                    reason: "module edge divergence approved".to_string(),
                    approved_by: "ops".to_string(),
                    approved_at_ns: 10,
                    valid_until_ns: Some(20),
                    test262_exemptions: Vec::new(),
                    lockstep_exemptions: Vec::new(),
                    sealed: false,
                },
                &tracker_ctx,
            )
            .expect("waiver registration should succeed");
    }

    matrix
        .validate_against_tracker(&tracker, &context())
        .expect("tracker-backed validation should pass");
}

#[test]
fn canonical_hash_is_stable_across_reloads() {
    let a = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix a");
    let b = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix b");
    assert_eq!(a.canonical_hash(), b.canonical_hash());
}
