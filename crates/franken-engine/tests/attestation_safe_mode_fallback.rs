use frankenengine_engine::receipt_verifier_pipeline::{
    LayerResult, UnifiedReceiptVerificationVerdict, VerificationFailureClass,
};
use frankenengine_engine::safe_mode_fallback::{
    ActionTier, AttestationActionRequest, AttestationFallbackConfig, AttestationFallbackDecision,
    AttestationFallbackManager, AttestationFallbackState, AttestationHealth, AutonomousAction,
    attestation_health_from_verdict,
};
use frankenengine_engine::signature_preimage::SigningKey;

fn mk_manager(timeout_ns: u64) -> AttestationFallbackManager {
    AttestationFallbackManager::new(
        AttestationFallbackConfig {
            unavailable_timeout_ns: timeout_ns,
            challenge_on_fallback: true,
            sandbox_on_fallback: true,
        },
        SigningKey::from_bytes([9u8; 32]),
    )
}

fn mk_request(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    action: AutonomousAction,
    tier: ActionTier,
    timestamp_ns: u64,
) -> AttestationActionRequest {
    AttestationActionRequest {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        action,
        tier,
        timestamp_ns,
    }
}

#[test]
fn high_impact_action_is_deferred_on_failed_attestation() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-hi-fail",
        "decision-hi-fail",
        "policy-hi-fail",
        AutonomousAction::Terminate,
        ActionTier::HighImpact,
        100,
    );

    let decision = mgr
        .evaluate_action(req, AttestationHealth::VerificationFailed)
        .expect("fallback decision");

    match decision {
        AttestationFallbackDecision::Deferred {
            attestation_status,
            status,
            challenge_required,
            sandbox_required,
            ..
        } => {
            assert_eq!(attestation_status, "degraded");
            assert_eq!(status, "attestation-pending");
            assert!(challenge_required);
            assert!(sandbox_required);
        }
        other => panic!("expected deferred decision, got {other:?}"),
    }

    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    assert_eq!(mgr.pending_decisions().len(), 1);
    assert_eq!(mgr.pending_decisions()[0].status, "attestation-pending");
    assert_eq!(mgr.transition_receipts().len(), 1);
    mgr.transition_receipts()[0]
        .verify()
        .expect("valid transition signature");
}

#[test]
fn standard_action_warns_but_continues_in_degraded_mode() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-std",
        "decision-std",
        "policy-std",
        AutonomousAction::RoutineMonitoring,
        ActionTier::Standard,
        100,
    );

    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceExpired)
        .expect("fallback decision");

    match decision {
        AttestationFallbackDecision::Execute {
            attestation_status,
            warning,
        } => {
            assert_eq!(attestation_status, "degraded");
            assert!(warning.is_some());
        }
        other => panic!("expected execute decision, got {other:?}"),
    }

    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    assert!(mgr.pending_decisions().is_empty());
    let event = mgr.events().last().expect("event emitted");
    assert_eq!(event.component, "attestation_safe_mode");
    assert_eq!(event.trace_id, "trace-std");
    assert_eq!(event.decision_id, "decision-std");
    assert_eq!(event.policy_id, "policy-std");
    assert_eq!(event.event, "attestation_standard_warn");
    assert_eq!(event.outcome, "warn");
}

#[test]
fn low_impact_action_continues_without_warning() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-low",
        "decision-low",
        "policy-low",
        AutonomousAction::MetricsEmission,
        ActionTier::LowImpact,
        100,
    );

    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceUnavailable)
        .expect("fallback decision");

    match decision {
        AttestationFallbackDecision::Execute {
            attestation_status,
            warning,
        } => {
            assert_eq!(attestation_status, "unavailable");
            assert!(warning.is_none());
        }
        other => panic!("expected execute decision, got {other:?}"),
    }

    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
}

#[test]
fn prolonged_unavailability_requires_operator_review() {
    let mut mgr = mk_manager(100);

    let first = mk_request(
        "trace-timeout-1",
        "decision-timeout-1",
        "policy-timeout",
        AutonomousAction::Quarantine,
        ActionTier::HighImpact,
        1_000,
    );
    mgr.evaluate_action(first, AttestationHealth::EvidenceUnavailable)
        .expect("first decision");
    assert!(!mgr.operator_review_required());

    let second = mk_request(
        "trace-timeout-2",
        "decision-timeout-2",
        "policy-timeout",
        AutonomousAction::RoutineMonitoring,
        ActionTier::Standard,
        1_150,
    );
    mgr.evaluate_action(second, AttestationHealth::EvidenceUnavailable)
        .expect("second decision");
    assert!(mgr.operator_review_required());

    let event = mgr
        .events()
        .iter()
        .find(|event| event.event == "attestation_operator_review_required")
        .expect("escalation event");
    assert_eq!(event.outcome, "fail");
    assert_eq!(
        event.error_code.as_deref(),
        Some("attestation_unavailable_timeout")
    );
}

#[test]
fn recovery_moves_pending_backlog_and_restores_normal_state() {
    let mut mgr = mk_manager(500);

    let degraded_req = mk_request(
        "trace-recover-1",
        "decision-recover-1",
        "policy-recover",
        AutonomousAction::PolicyPromotion,
        ActionTier::HighImpact,
        100,
    );
    let first_decision = mgr
        .evaluate_action(degraded_req, AttestationHealth::EvidenceExpired)
        .expect("first decision");
    assert!(matches!(
        first_decision,
        AttestationFallbackDecision::Deferred { .. }
    ));
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

    let restored_req = mk_request(
        "trace-recover-2",
        "decision-recover-2",
        "policy-recover",
        AutonomousAction::Quarantine,
        ActionTier::HighImpact,
        200,
    );
    let second_decision = mgr
        .evaluate_action(restored_req, AttestationHealth::Valid)
        .expect("second decision");
    assert!(matches!(
        second_decision,
        AttestationFallbackDecision::Execute { .. }
    ));

    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    assert!(!mgr.operator_review_required());
    assert!(mgr.pending_decisions().is_empty());

    let backlog = mgr.take_recovery_backlog();
    assert_eq!(backlog.len(), 1);
    assert_eq!(backlog[0].decision_id, "decision-recover-1");
    assert_eq!(backlog[0].status, "attestation-pending");

    // normal->degraded, degraded->restoring, restoring->normal
    assert_eq!(mgr.transition_receipts().len(), 3);
    for receipt in mgr.transition_receipts() {
        receipt.verify().expect("transition signature must verify");
    }
}

fn layer(passed: bool, error_code: Option<&str>) -> LayerResult {
    LayerResult {
        passed,
        error_code: error_code.map(std::string::ToString::to_string),
        checks: Vec::new(),
    }
}

#[test]
fn verifier_verdict_maps_to_attestation_health_classes() {
    let mut verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "r-1".to_string(),
        trace_id: "trace-map".to_string(),
        decision_id: "decision-map".to_string(),
        policy_id: "policy-map".to_string(),
        verification_timestamp_ns: 1,
        passed: false,
        failure_class: Some(VerificationFailureClass::StaleData),
        exit_code: 23,
        signature: layer(true, None),
        transparency: layer(true, None),
        attestation: layer(true, None),
        warnings: vec!["attestation_policy_cache_stale".to_string()],
        logs: Vec::new(),
    };
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceExpired
    );

    verdict.failure_class = Some(VerificationFailureClass::Attestation);
    verdict.warnings.clear();
    verdict.attestation = layer(false, Some("attestation_trust_root_missing"));
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceUnavailable
    );

    verdict.attestation = layer(false, Some("attestation_policy_measurement_mismatch"));
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::VerificationFailed
    );
}
