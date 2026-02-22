use std::collections::BTreeSet;

use frankenengine_engine::runtime_observability::{
    AuthFailureType, CAPABILITY_DENIAL_TOTAL, CHECKPOINT_VIOLATION_TOTAL,
    CROSS_ZONE_REFERENCE_TOTAL, CapabilityDenialReason, CheckpointViolationType,
    CrossZoneReferenceType, REPLAY_DROP_TOTAL, REVOCATION_CHECK_TOTAL,
    REVOCATION_FRESHNESS_DEGRADED_SECONDS, ReplayDropReason, RevocationCheckOutcome,
    RuntimeSecurityObservability, SecurityEventContext, parse_security_logs_jsonl,
};

fn context(timestamp_ns: u64, component: &str) -> SecurityEventContext {
    SecurityEventContext {
        timestamp_ns,
        trace_id: "trace-001".to_string(),
        principal_id: "principal-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        zone_id: "zone-core".to_string(),
        component: component.to_string(),
    }
}

#[test]
fn records_all_failure_categories_and_updates_required_metrics() {
    let mut observability = RuntimeSecurityObservability::new();

    observability.record_auth_failure(
        context(10, "auth_verifier"),
        AuthFailureType::KeyRevoked,
        Some("raw-key-material"),
        Some("token-content"),
    );
    observability.record_capability_denial(
        context(11, "capability_gate"),
        CapabilityDenialReason::AudienceMismatch,
        "write_policy",
    );
    observability.record_replay_drop(
        context(12, "session_channel"),
        ReplayDropReason::DuplicateSeq,
        42,
        43,
        "session-001",
    );
    observability.record_checkpoint_violation(
        context(13, "checkpoint_frontier"),
        CheckpointViolationType::RollbackAttempt,
        5,
        7,
    );
    observability.record_revocation_check(
        context(14, "revocation_freshness"),
        RevocationCheckOutcome::Stale,
        10,
        20,
        5,
        Some(12),
    );
    observability.record_cross_zone_reference(
        context(15, "zone_reference_checker"),
        CrossZoneReferenceType::AuthorityDenied,
        "zone-community",
        "zone-owner",
    );

    let metrics = observability.metrics();
    assert_eq!(metrics.auth_failure_total[&AuthFailureType::KeyRevoked], 1);
    assert_eq!(
        metrics.capability_denial_total[&CapabilityDenialReason::AudienceMismatch],
        1
    );
    assert_eq!(
        metrics.replay_drop_total[&ReplayDropReason::DuplicateSeq],
        1
    );
    assert_eq!(
        metrics.checkpoint_violation_total[&CheckpointViolationType::RollbackAttempt],
        1
    );
    assert_eq!(
        metrics.revocation_check_total[&RevocationCheckOutcome::Stale],
        1
    );
    assert_eq!(metrics.revocation_freshness_degraded_seconds, 12);
    assert_eq!(
        metrics.cross_zone_reference_total[&CrossZoneReferenceType::AuthorityDenied],
        1
    );

    let logs = observability.logs();
    assert_eq!(logs.len(), 6);
    for event in logs {
        assert!(event.required_fields_present());
    }

    let auth = &logs[0];
    assert_eq!(auth.event_type, "auth_failure");
    assert_eq!(auth.outcome, "denied");
    assert!(auth.error_code.is_some());
    let key_hash = auth
        .metadata
        .get("key_material_hash")
        .expect("hash should be present");
    assert!(key_hash.starts_with("sha256:"));
    assert_ne!(key_hash, "raw-key-material");
    assert!(
        !auth
            .metadata
            .values()
            .any(|value| value.contains("token-content"))
    );
}

#[test]
fn revocation_pass_emits_counter_without_error_code() {
    let mut observability = RuntimeSecurityObservability::new();

    let event = observability.record_revocation_check(
        context(100, "revocation_freshness"),
        RevocationCheckOutcome::Pass,
        120,
        120,
        5,
        None,
    );

    assert_eq!(event.event_type, "revocation_check");
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_code, None);
    assert_eq!(
        observability.metrics().revocation_check_total[&RevocationCheckOutcome::Pass],
        1
    );
    assert_eq!(
        observability
            .metrics()
            .revocation_freshness_degraded_seconds,
        0
    );
}

#[test]
fn synchronous_emission_updates_metrics_and_logs_immediately() {
    let mut observability = RuntimeSecurityObservability::new();

    let event = observability.record_checkpoint_violation(
        context(200, "checkpoint_frontier"),
        CheckpointViolationType::ForkDetected,
        90,
        91,
    );

    assert_eq!(observability.logs().len(), 1);
    assert_eq!(
        observability.metrics().checkpoint_violation_total[&CheckpointViolationType::ForkDetected],
        1
    );
    assert_eq!(observability.logs()[0], event);
}

#[test]
fn prometheus_export_contains_required_metric_families() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(
        context(300, "auth_verifier"),
        AuthFailureType::SignatureInvalid,
        Some("secret"),
        None,
    );

    let output = observability.export_prometheus_metrics();
    for metric in [
        "auth_failure_total",
        CAPABILITY_DENIAL_TOTAL,
        REPLAY_DROP_TOTAL,
        CHECKPOINT_VIOLATION_TOTAL,
        REVOCATION_FRESHNESS_DEGRADED_SECONDS,
        REVOCATION_CHECK_TOTAL,
        CROSS_ZONE_REFERENCE_TOTAL,
    ] {
        assert!(
            output.contains(metric),
            "prometheus export should contain {metric}"
        );
    }
}

#[test]
fn jsonl_export_is_parseable_and_stable() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_capability_denial(
        context(400, "capability_gate"),
        CapabilityDenialReason::InsufficientAuthority,
        "admin_policy_write",
    );
    observability.record_cross_zone_reference(
        context(401, "zone_reference_checker"),
        CrossZoneReferenceType::ProvenanceAllowed,
        "zone-team-a",
        "zone-team-b",
    );

    let jsonl = observability.export_logs_jsonl();
    let parsed = parse_security_logs_jsonl(&jsonl).expect("jsonl should parse");
    assert_eq!(parsed, observability.logs());
    for event in parsed {
        assert!(event.required_fields_present());
    }
}

#[test]
fn metric_label_sets_are_bounded_enums() {
    let auth_labels = AuthFailureType::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(auth_labels.len(), AuthFailureType::ALL.len());

    let denial_labels = CapabilityDenialReason::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(denial_labels.len(), CapabilityDenialReason::ALL.len());

    let replay_labels = ReplayDropReason::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(replay_labels.len(), ReplayDropReason::ALL.len());

    let checkpoint_labels = CheckpointViolationType::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(checkpoint_labels.len(), CheckpointViolationType::ALL.len());

    let revocation_labels = RevocationCheckOutcome::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(revocation_labels.len(), RevocationCheckOutcome::ALL.len());

    let zone_labels = CrossZoneReferenceType::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(zone_labels.len(), CrossZoneReferenceType::ALL.len());
}
