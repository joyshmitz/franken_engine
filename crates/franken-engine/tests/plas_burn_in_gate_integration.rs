use frankenengine_engine::capability_witness::RollbackToken;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::plas_burn_in_gate::{
    BurnInFailureCode, BurnInLifecycleState, BurnInSession, BurnInSessionConfig, BurnInThresholds,
    ExtensionRiskClass, RollbackProofArtifacts, ShadowObservation,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn session_config() -> BurnInSessionConfig {
    BurnInSessionConfig {
        trace_id: "trace-burn-in-001".to_string(),
        decision_id: "decision-burn-in-001".to_string(),
        policy_id: "policy-burn-in-v1".to_string(),
        extension_id: "extension://plas/burn-in".to_string(),
        risk_class: ExtensionRiskClass::Standard,
        thresholds: BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 100_000,
            min_shadow_duration_ns: 1_000,
            min_shadow_observations: 5,
        },
        shadow_start_timestamp_ns: 1_000_000,
    }
}

fn complete_rollback_artifacts() -> RollbackProofArtifacts {
    RollbackProofArtifacts {
        rollback_command_tested: true,
        previous_policy_snapshot_ref: Some("snapshot://policy/previous".to_string()),
        transition_receipt_signed: true,
        transition_receipt_ref: Some("receipt://transition/001".to_string()),
        rollback_token: Some(RollbackToken {
            previous_witness_hash: ContentHash::compute(b"prev-witness"),
            previous_witness_id: None,
            created_epoch: SecurityEpoch::from_raw(42),
            sequence: 7,
        }),
    }
}

fn observation(id: &str, timestamp_ns: u64, success: bool, false_deny: bool) -> ShadowObservation {
    ShadowObservation {
        observation_id: id.to_string(),
        timestamp_ns,
        success,
        false_deny,
    }
}

#[test]
fn full_lifecycle_passes_and_promotes_auto_enforcement() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::ShadowStart);

    session.begin_shadow_evaluation().unwrap();
    assert_eq!(
        session.lifecycle_state(),
        BurnInLifecycleState::ShadowEvaluation
    );

    let timestamps = [1_000_100, 1_000_200, 1_000_300, 1_000_400, 1_001_500];
    for (idx, ts) in timestamps.iter().enumerate() {
        let maybe_artifact = session
            .record_shadow_observation(observation(&format!("obs-{idx}"), *ts, true, false))
            .unwrap();
        assert!(maybe_artifact.is_none());
    }

    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(
        session.lifecycle_state(),
        BurnInLifecycleState::AutoEnforcement
    );
    assert_eq!(
        artifact.lifecycle_state,
        BurnInLifecycleState::AutoEnforcement
    );
    assert_eq!(artifact.outcome, "pass");
    assert!(artifact.failure_codes.is_empty());
    assert!(artifact.rollback_artifacts_verified);
}

#[test]
fn early_termination_triggers_on_false_deny_envelope_breach() {
    let mut cfg = session_config();
    cfg.thresholds.max_false_deny_millionths = 0;

    let mut session = BurnInSession::new(cfg, complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    let artifact = session
        .record_shadow_observation(observation("obs-early", 1_000_100, false, true))
        .unwrap()
        .expect("expected early termination artifact");
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert_eq!(artifact.outcome, "fail");
    assert_eq!(
        artifact.failure_codes,
        vec![BurnInFailureCode::EarlyTerminationFalseDeny]
    );
}

#[test]
fn promotion_gate_rejects_when_success_rate_below_threshold() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    // 4/5 successes = 800_000 < 900_000
    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-2", 1_000_200, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-3", 1_000_300, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-4", 1_000_400, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-5", 1_001_500, false, false))
        .unwrap();

    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert!(artifact
        .failure_codes
        .contains(&BurnInFailureCode::ShadowSuccessRateBelowThreshold));
}

#[test]
fn false_deny_envelope_breach_triggers_early_rejection_artifact() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    // 1/5 false denies = 200_000 > 100_000, triggering early termination.
    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-2", 1_000_200, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-3", 1_000_300, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-4", 1_000_400, true, false))
        .unwrap();
    let artifact = session
        .record_shadow_observation(observation("obs-5", 1_001_500, true, true))
        .unwrap()
        .expect("expected early rejection artifact");
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert_eq!(
        artifact.failure_codes,
        vec![BurnInFailureCode::EarlyTerminationFalseDeny]
    );
}

#[test]
fn promotion_gate_rejects_when_rollback_artifacts_are_incomplete() {
    let mut artifacts = complete_rollback_artifacts();
    artifacts.transition_receipt_signed = false;

    let mut session = BurnInSession::new(session_config(), artifacts).unwrap();
    session.begin_shadow_evaluation().unwrap();

    for idx in 0..5 {
        session
            .record_shadow_observation(observation(
                &format!("obs-{idx}"),
                1_000_100 + (idx as u64) * 100,
                true,
                false,
            ))
            .unwrap();
    }

    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert!(artifact
        .failure_codes
        .contains(&BurnInFailureCode::RollbackProofArtifactsMissing));
}

#[test]
fn non_monotonic_observation_timestamp_is_rejected() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    session
        .record_shadow_observation(observation("obs-1", 1_000_200, true, false))
        .unwrap();
    let err = session
        .record_shadow_observation(observation("obs-2", 1_000_100, true, false))
        .unwrap_err();
    assert!(err.to_string().contains("non-monotonic timestamp"));
}

#[test]
fn risk_class_defaults_get_stricter_for_high_risk_extensions() {
    let low = BurnInThresholds::for_risk_class(ExtensionRiskClass::Low);
    let standard = BurnInThresholds::for_risk_class(ExtensionRiskClass::Standard);
    let high = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);

    assert!(low.min_shadow_success_millionths < standard.min_shadow_success_millionths);
    assert!(high.min_shadow_success_millionths > standard.min_shadow_success_millionths);
    assert!(high.max_false_deny_millionths < standard.max_false_deny_millionths);
    assert!(high.min_shadow_observations > standard.min_shadow_observations);
}

#[test]
fn structured_log_contract_is_stable() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let early = session
        .record_shadow_observation(observation("obs-1", 1_000_100, false, true))
        .unwrap()
        .expect("expected early termination");

    assert_eq!(early.trace_id, "trace-burn-in-001");
    assert_eq!(early.decision_id, "decision-burn-in-001");
    assert_eq!(early.policy_id, "policy-burn-in-v1");
    assert_eq!(early.outcome, "fail");
    assert!(!early.decision_hash.as_bytes().is_empty());

    let final_log = session.logs().last().unwrap();
    assert_eq!(final_log.trace_id, "trace-burn-in-001");
    assert_eq!(final_log.decision_id, "decision-burn-in-001");
    assert_eq!(final_log.policy_id, "policy-burn-in-v1");
    assert_eq!(final_log.component, "plas_burn_in_gate");
    assert_eq!(final_log.event, "shadow_evaluation");
    assert_eq!(final_log.outcome, "fail");
    assert_eq!(
        final_log.error_code.as_deref(),
        Some("early_termination_false_deny")
    );
    assert_eq!(final_log.lifecycle_state, BurnInLifecycleState::Rejection);
}
