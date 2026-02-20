use std::collections::BTreeMap;

use frankenengine_engine::frankentui_adapter::{
    ActionCandidateView, AdapterEnvelope, AdapterStream, ControlDashboardPartial,
    ControlDashboardView, DashboardMetricView, DriverView, FrankentuiViewPayload,
    IncidentReplayView, PolicyExplanationCardView, PolicyExplanationPartial, ReplayEventView,
    UpdateKind,
};

#[test]
fn incident_replay_view_round_trips_for_static_replay() {
    let replay = IncidentReplayView::snapshot(
        "trace-replay-1",
        "credential-exfiltration-drill",
        vec![ReplayEventView::new(
            1,
            "replay_engine",
            "decision_replayed",
            "allow",
            1_700_000_000_000,
        )],
    );

    let envelope = AdapterEnvelope::new(
        "trace-replay-1",
        1_700_000_000_001,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::IncidentReplay);
    assert_eq!(decoded.trace_id, "trace-replay-1");
}

#[test]
fn policy_explanation_view_round_trips_for_card_rendering() {
    let policy = PolicyExplanationCardView::from_partial(PolicyExplanationPartial {
        decision_id: "decision-42".to_string(),
        policy_id: "policy-safe-default".to_string(),
        selected_action: "sandbox".to_string(),
        confidence_millionths: Some(812_000),
        expected_loss_millionths: Some(123_000),
        action_candidates: vec![
            ActionCandidateView {
                action: "allow".to_string(),
                expected_loss_millionths: 410_000,
            },
            ActionCandidateView {
                action: "sandbox".to_string(),
                expected_loss_millionths: 123_000,
            },
        ],
        key_drivers: vec![
            DriverView {
                name: "hostcall_anomaly_rate".to_string(),
                contribution_millionths: 80_000,
            },
            DriverView {
                name: "publisher_revocation_signal".to_string(),
                contribution_millionths: 43_000,
            },
        ],
    });

    let envelope = AdapterEnvelope::new(
        "trace-policy-1",
        1_700_000_000_100,
        AdapterStream::PolicyExplanation,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::PolicyExplanation(policy),
    )
    .with_decision_context("decision-42", "policy-safe-default");

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::PolicyExplanation);
    assert_eq!(decoded.decision_id.as_deref(), Some("decision-42"));
    assert_eq!(decoded.policy_id.as_deref(), Some("policy-safe-default"));
}

#[test]
fn control_dashboard_view_supports_delta_updates() {
    let mut incidents = BTreeMap::new();
    incidents.insert("quarantine".to_string(), 2);

    let dashboard = ControlDashboardView::from_partial(ControlDashboardPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(9),
        runtime_mode: "secure".to_string(),
        metrics: vec![DashboardMetricView {
            metric: "containment_latency_p95_ms".to_string(),
            value: 84,
            unit: "ms".to_string(),
        }],
        extension_rows: vec![],
        incident_counts: incidents,
    });

    let envelope = AdapterEnvelope::new(
        "trace-dashboard-1",
        1_700_000_000_200,
        AdapterStream::ControlDashboard,
        UpdateKind::Delta,
        FrankentuiViewPayload::ControlDashboard(dashboard),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::ControlDashboard);
    assert_eq!(decoded.update_kind, UpdateKind::Delta);
}
