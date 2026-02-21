use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::privacy_learning_contract::PrivacyLearningContract;
use frankenengine_engine::privacy_learning_contract::{
    ClippingMethod, ClippingStrategy, CompositionMethod, CoordinatorTrustModel,
    CreateContractInput, DataRetentionPolicy, DpBudgetSemantics, FeatureField, FeatureFieldType,
    FeatureSchema, HumanOverrideRequest, SafetyMetric, SafetyMetricSnapshot, SecretSharingScheme,
    SecureAggregationRequirements, ShadowEvaluationCandidate, ShadowEvaluationGate,
    ShadowEvaluationGateConfig, ShadowPromotionVerdict, ShadowReplayReference, UpdatePolicy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

const TEST_ZONE: &str = "shadow-eval-zone";

fn governance_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x11; 32])
}

fn participant_ids() -> BTreeSet<EngineObjectId> {
    let mut set = BTreeSet::new();
    set.insert(EngineObjectId([0xAA; 32]));
    set.insert(EngineObjectId([0xBB; 32]));
    set
}

fn feature_schema() -> FeatureSchema {
    FeatureSchema {
        version: 1,
        fields: BTreeMap::from([(
            "calibration_residual".to_string(),
            FeatureField {
                name: "calibration_residual".to_string(),
                field_type: FeatureFieldType::FixedPoint,
                description: "residual".to_string(),
                existed_in_prior_version: false,
            },
        )]),
        prior_version: None,
    }
}

fn contract() -> PrivacyLearningContract {
    PrivacyLearningContract::create_signed(
        &governance_signing_key(),
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(7),
            zone: TEST_ZONE,
            feature_schema: feature_schema(),
            update_policy: UpdatePolicy {
                min_local_samples: 100,
                min_submission_interval: 3600,
                max_data_age: 86400,
                allow_skip: true,
                max_consecutive_skips: 3,
            },
            clipping_strategy: ClippingStrategy {
                method: ClippingMethod::L2Norm,
                global_bound_millionths: 1_000_000,
                per_field_bounds: BTreeMap::new(),
            },
            dp_budget: DpBudgetSemantics {
                epsilon_per_epoch_millionths: 100_000,
                delta_per_epoch_millionths: 1_000,
                composition_method: CompositionMethod::Renyi,
                lifetime_epsilon_budget_millionths: 10_000_000,
                lifetime_delta_budget_millionths: 100_000,
                fail_closed_on_exhaustion: true,
            },
            aggregation: SecureAggregationRequirements {
                min_participants: 5,
                dropout_tolerance_millionths: 100_000,
                secret_sharing_scheme: SecretSharingScheme::Additive,
                sharing_threshold: None,
                coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
            },
            retention: DataRetentionPolicy {
                max_intermediate_retention: 86_400,
                max_snapshot_retention: 604_800,
                delete_local_after_submission: true,
                delete_shares_after_aggregation: true,
            },
            authorized_participants: participant_ids(),
        },
    )
    .expect("contract")
}

fn baseline_metrics() -> SafetyMetricSnapshot {
    SafetyMetricSnapshot {
        values_millionths: BTreeMap::from([
            (SafetyMetric::FalsePositiveRate, 120_000),
            (SafetyMetric::FalseNegativeRate, 90_000),
            (SafetyMetric::CalibrationError, 70_000),
            (SafetyMetric::DriftDetectionAccuracy, 760_000),
            (SafetyMetric::ContainmentTime, 500_000),
        ]),
    }
}

fn improved_metrics() -> SafetyMetricSnapshot {
    SafetyMetricSnapshot {
        values_millionths: BTreeMap::from([
            (SafetyMetric::FalsePositiveRate, 115_000),
            (SafetyMetric::FalseNegativeRate, 88_000),
            (SafetyMetric::CalibrationError, 68_000),
            (SafetyMetric::DriftDetectionAccuracy, 780_000),
            (SafetyMetric::ContainmentTime, 495_000),
        ]),
    }
}

fn regressed_metrics() -> SafetyMetricSnapshot {
    SafetyMetricSnapshot {
        values_millionths: BTreeMap::from([
            (SafetyMetric::FalsePositiveRate, 150_000),
            (SafetyMetric::FalseNegativeRate, 100_000),
            (SafetyMetric::CalibrationError, 80_000),
            (SafetyMetric::DriftDetectionAccuracy, 740_000),
            (SafetyMetric::ContainmentTime, 525_000),
        ]),
    }
}

fn replay_reference() -> ShadowReplayReference {
    ShadowReplayReference {
        replay_corpus_id: "fleet-corpus-v7".to_string(),
        randomness_snapshot_id: "rng-snapshot-v7".to_string(),
        replay_seed_hash: [0x22; 32],
        replay_seed_counter: 17,
    }
}

fn candidate(
    decision_id: &str,
    candidate_metrics: SafetyMetricSnapshot,
    epsilon_spent: i64,
    delta_spent: i64,
) -> ShadowEvaluationCandidate {
    ShadowEvaluationCandidate {
        trace_id: format!("trace-{decision_id}"),
        decision_id: decision_id.to_string(),
        policy_id: "policy-shadow-gate".to_string(),
        candidate_version: "v7.1".to_string(),
        baseline_snapshot_id: "snapshot-v7.0".to_string(),
        rollback_token: "rollback-token-v7.0".to_string(),
        epoch_id: SecurityEpoch::from_raw(7),
        baseline_metrics: baseline_metrics(),
        candidate_metrics,
        replay_reference: replay_reference(),
        epsilon_spent_millionths: epsilon_spent,
        delta_spent_millionths: delta_spent,
    }
}

fn gate() -> ShadowEvaluationGate {
    ShadowEvaluationGate::new(ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 2_500,
    })
    .expect("gate")
}

#[test]
fn shadow_gate_full_lifecycle_pass_reject_override_and_rollback() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let pass_artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-pass", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass candidate");
    assert_eq!(pass_artifact.verdict, ShadowPromotionVerdict::Pass);
    assert!(gate.active_artifact("policy-shadow-gate").is_some());

    let rollback = gate
        .evaluate_post_deployment_metrics(&pass_artifact, regressed_metrics(), &signing)
        .expect("post deployment evaluation")
        .expect("rollback required");
    assert_eq!(rollback.policy_id, "policy-shadow-gate");
    assert!(!rollback.triggered_regressions.is_empty());
    assert!(gate.active_artifact("policy-shadow-gate").is_none());

    let rejected = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-reject", regressed_metrics(), 90_000, 900),
            &signing,
        )
        .expect("reject candidate");
    assert_eq!(rejected.verdict, ShadowPromotionVerdict::Reject);

    let overridden = gate
        .apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "human-approver-1".to_string(),
                summary: "external risk context justifies temporary override".to_string(),
                bypassed_risk_criteria: vec!["false_positive_rate <= baseline+5000".to_string()],
                acknowledged_bypass: true,
            },
            &signing,
        )
        .expect("override");
    assert_eq!(overridden.verdict, ShadowPromotionVerdict::OverrideApproved);
    assert!(gate.active_artifact("policy-shadow-gate").is_some());
    assert!(overridden.human_override.is_some());
}

#[test]
fn shadow_gate_rejects_nondeterministic_replay_inputs() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let mut invalid = candidate("decision-invalid", improved_metrics(), 90_000, 900);
    invalid.replay_reference.replay_seed_hash = [0u8; 32];
    let err = gate
        .evaluate_candidate(&contract, invalid, &signing)
        .expect_err("candidate must be rejected");
    assert!(
        err.to_string()
            .contains("replay_seed_hash must not be all zeros")
    );
}
