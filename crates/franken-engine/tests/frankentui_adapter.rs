use std::collections::BTreeMap;

use frankenengine_engine::frankentui_adapter::{
    ActionCandidateView, ActiveSpecializationRowView, AdapterEnvelope, AdapterStream,
    BenchmarkTrendPointView, BlockedFlowView, CancellationEventView, CancellationKind,
    ConfinementProofView, ConfinementStatus, ControlDashboardPartial, ControlDashboardView,
    ControlPlaneInvariantsDashboardView, ControlPlaneInvariantsPartial, DashboardAlertMetric,
    DashboardAlertRule, DashboardMetricView, DashboardRefreshPolicy, DashboardSeverity,
    DecisionOutcomeKind, DeclassificationDecisionView, DeclassificationOutcome, DriverView,
    EvidenceStreamEntryView, FlowDecisionDashboardView, FlowDecisionPartial, FlowProofCoverageView,
    FlowSensitivityLevel, FrankentuiViewPayload, IncidentReplayView, LabelMapEdgeView,
    LabelMapNodeView, LabelMapView, ObligationState, ObligationStatusRowView,
    PolicyExplanationCardView, PolicyExplanationPartial, ProofInventoryKind, ProofInventoryRowView,
    ProofSpecializationInvalidationReason, ProofSpecializationLineageDashboardView,
    ProofSpecializationLineagePartial, ProofValidityStatus, RecoveryStatus, RegionLifecycleRowView,
    ReplacementOpportunityInput, ReplacementProgressDashboardView, ReplacementProgressPartial,
    ReplacementRiskLevel, ReplayEventView, ReplayHealthPanelView, ReplayHealthStatus,
    RollbackEventView, RollbackStatus, SafeModeActivationView, SchemaCompatibilityStatus,
    SchemaVersionPanelView, SlotStatusOverviewRow, SpecializationFallbackEventView,
    SpecializationFallbackReason, SpecializationInvalidationRowView, ThresholdComparator,
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

#[test]
fn control_plane_invariants_dashboard_round_trips_with_alerts() {
    let invariants =
        ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
            cluster: "prod".to_string(),
            zone: "us-central-1".to_string(),
            runtime_mode: "secure".to_string(),
            generated_at_unix_ms: Some(1_700_000_000_400),
            refresh_policy: Some(DashboardRefreshPolicy {
                evidence_stream_refresh_secs: 5,
                aggregate_refresh_secs: 45,
            }),
            evidence_stream_last_updated_unix_ms: Some(1_700_000_000_398),
            aggregates_last_updated_unix_ms: Some(1_700_000_000_380),
            evidence_stream: vec![EvidenceStreamEntryView {
                trace_id: "trace-inv-1".to_string(),
                decision_id: "decision-inv-1".to_string(),
                policy_id: "policy-safe".to_string(),
                action_type: "fallback".to_string(),
                decision_outcome: DecisionOutcomeKind::Fallback,
                expected_loss_millionths: 240_000,
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                severity: DashboardSeverity::Critical,
                component: "guardplane".to_string(),
                event: "safe_mode_activated".to_string(),
                outcome: "fallback".to_string(),
                error_code: Some("FE-SAFE-001".to_string()),
                timestamp_unix_ms: 1_700_000_000_397,
            }],
            obligation_rows: vec![ObligationStatusRowView {
                obligation_id: "obl-incident-1".to_string(),
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                state: ObligationState::Failed,
                severity: DashboardSeverity::Critical,
                due_at_unix_ms: 1_700_000_000_800,
                updated_at_unix_ms: 1_700_000_000_398,
                detail: "replay divergence unresolved".to_string(),
            }],
            region_rows: vec![RegionLifecycleRowView {
                region_id: "region-a".to_string(),
                is_active: true,
                active_extensions: 3,
                created_at_unix_ms: 1_700_000_000_000,
                closed_at_unix_ms: None,
                quiescent_close_time_ms: None,
            }],
            cancellation_events: vec![CancellationEventView {
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                cancellation_kind: CancellationKind::Quarantine,
                severity: DashboardSeverity::Critical,
                detail: "containment escalation".to_string(),
                timestamp_unix_ms: 1_700_000_000_399,
            }],
            replay_health: Some(ReplayHealthPanelView {
                last_run_status: ReplayHealthStatus::Fail,
                divergence_count: 2,
                last_replay_timestamp_unix_ms: Some(1_700_000_000_360),
            }),
            benchmark_points: vec![BenchmarkTrendPointView {
                timestamp_unix_ms: 1_700_000_000_300,
                throughput_tps: 1_900,
                latency_p95_ms: 140,
                memory_peak_mb: 780,
            }],
            throughput_floor_tps: Some(2_000),
            latency_p95_ceiling_ms: Some(120),
            memory_peak_ceiling_mb: Some(750),
            safe_mode_activations: vec![SafeModeActivationView {
                activation_id: "sm-critical-1".to_string(),
                activation_type: "replay_divergence".to_string(),
                extension_id: "ext-critical".to_string(),
                region_id: "region-a".to_string(),
                severity: DashboardSeverity::Critical,
                recovery_status: RecoveryStatus::Recovering,
                activated_at_unix_ms: 1_700_000_000_395,
                recovered_at_unix_ms: None,
            }],
            schema_version: Some(SchemaVersionPanelView {
                evidence_schema_version: 4,
                last_migration_unix_ms: Some(1_699_999_999_500),
                compatibility_status: SchemaCompatibilityStatus::Compatible,
            }),
            alert_rules: vec![DashboardAlertRule {
                rule_id: "alert-fallback-activation".to_string(),
                description: "fallback activations > 0".to_string(),
                metric: DashboardAlertMetric::FallbackActivationCount,
                comparator: ThresholdComparator::GreaterThan,
                threshold: 0,
                severity: DashboardSeverity::Critical,
            }],
            ..Default::default()
        });

    assert!(invariants.meets_refresh_sla());
    assert_eq!(invariants.triggered_alerts().len(), 1);

    let envelope = AdapterEnvelope::new(
        "trace-invariants-1",
        1_700_000_000_401,
        AdapterStream::ControlPlaneInvariantsDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::ControlPlaneInvariantsDashboard(invariants),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(
        decoded.stream,
        AdapterStream::ControlPlaneInvariantsDashboard
    );
    match decoded.payload {
        FrankentuiViewPayload::ControlPlaneInvariantsDashboard(view) => {
            assert_eq!(view.evidence_stream.len(), 1);
            assert_eq!(view.obligation_status.failed_count, 1);
            assert_eq!(view.triggered_alerts().len(), 1);
        }
        other => panic!("expected invariants dashboard payload, got {other:?}"),
    }
}

#[test]
fn flow_decision_dashboard_round_trips_with_ifc_views() {
    let flow_dashboard = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
        cluster: "prod".to_string(),
        zone: "us-west-1".to_string(),
        security_epoch: Some(22),
        generated_at_unix_ms: Some(1_700_000_000_700),
        label_map: LabelMapView {
            nodes: vec![
                LabelMapNodeView {
                    label_id: "pii".to_string(),
                    sensitivity: FlowSensitivityLevel::High,
                    description: "personal data".to_string(),
                    extension_overlays: vec!["ext-a".to_string()],
                },
                LabelMapNodeView {
                    label_id: "public".to_string(),
                    sensitivity: FlowSensitivityLevel::Low,
                    description: "public".to_string(),
                    extension_overlays: vec!["ext-a".to_string(), "ext-b".to_string()],
                },
            ],
            edges: vec![LabelMapEdgeView {
                source_label: "pii".to_string(),
                sink_clearance: "high".to_string(),
                route_policy_id: Some("policy-ifc-1".to_string()),
                route_enabled: true,
            }],
        },
        blocked_flows: vec![BlockedFlowView {
            flow_id: "flow-1".to_string(),
            extension_id: "ext-a".to_string(),
            source_label: "pii".to_string(),
            sink_clearance: "external".to_string(),
            sensitivity: FlowSensitivityLevel::Critical,
            blocked_reason: "sink clearance mismatch".to_string(),
            attempted_exfiltration: true,
            code_path_ref: "src/ext_a/main.ts:90".to_string(),
            extension_context_ref: "frankentui://extension/ext-a".to_string(),
            trace_id: "trace-ifc-1".to_string(),
            decision_id: "decision-ifc-1".to_string(),
            policy_id: "policy-ifc-1".to_string(),
            error_code: Some("FE-IFC-BLOCK".to_string()),
            occurred_at_unix_ms: 1_700_000_000_680,
        }],
        declassification_history: vec![DeclassificationDecisionView {
            decision_id: "decl-1".to_string(),
            extension_id: "ext-a".to_string(),
            source_label: "pii".to_string(),
            sink_clearance: "external".to_string(),
            sensitivity: FlowSensitivityLevel::Critical,
            outcome: DeclassificationOutcome::Denied,
            policy_id: "policy-ifc-1".to_string(),
            loss_assessment_summary: "expected loss too high".to_string(),
            rationale: "deny".to_string(),
            receipt_ref: "frankentui://declassification/decl-1".to_string(),
            replay_ref: "frankentui://replay/decl-1".to_string(),
            decided_at_unix_ms: 1_700_000_000_690,
        }],
        confinement_proofs: vec![ConfinementProofView {
            extension_id: "ext-a".to_string(),
            status: ConfinementStatus::Partial,
            covered_flow_count: 5,
            uncovered_flow_count: 1,
            proof_rows: vec![FlowProofCoverageView {
                proof_id: "proof-1".to_string(),
                source_label: "pii".to_string(),
                sink_clearance: "external".to_string(),
                covered: false,
                proof_ref: "frankentui://proof/proof-1".to_string(),
            }],
            uncovered_flow_refs: vec!["frankentui://flow/flow-1".to_string()],
        }],
        blocked_flow_alert_threshold: Some(1),
        ..Default::default()
    });

    let envelope = AdapterEnvelope::new(
        "trace-flow-dashboard-1",
        1_700_000_000_701,
        AdapterStream::FlowDecisionDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::FlowDecisionDashboard(flow_dashboard),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::FlowDecisionDashboard);
    match decoded.payload {
        FrankentuiViewPayload::FlowDecisionDashboard(view) => {
            assert_eq!(view.blocked_flows.len(), 1);
            assert_eq!(view.declassification_history.len(), 1);
            assert_eq!(view.confinement_proofs.len(), 1);
            assert!(!view.alert_indicators.is_empty());
        }
        other => panic!("expected flow decision dashboard payload, got {other:?}"),
    }
}

#[test]
fn replacement_progress_dashboard_view_round_trips_with_ranked_ev() {
    let replacement = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
        cluster: "prod".to_string(),
        zone: "us-east-1".to_string(),
        security_epoch: Some(17),
        generated_at_unix_ms: Some(1_700_000_000_250),
        slot_status_overview: vec![
            SlotStatusOverviewRow {
                slot_id: "parser".to_string(),
                slot_kind: "parser".to_string(),
                implementation_kind: "delegate".to_string(),
                promotion_status: "promotion_candidate".to_string(),
                risk_level: ReplacementRiskLevel::High,
                last_transition_unix_ms: 1_700_000_000_100,
                health: "blocked".to_string(),
                lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
            },
            SlotStatusOverviewRow {
                slot_id: "gc".to_string(),
                slot_kind: "garbage_collector".to_string(),
                implementation_kind: "native".to_string(),
                promotion_status: "promoted".to_string(),
                risk_level: ReplacementRiskLevel::Low,
                last_transition_unix_ms: 1_700_000_000_080,
                health: "healthy".to_string(),
                lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
            },
        ],
        replacement_inputs: vec![
            ReplacementOpportunityInput {
                slot_id: "parser".to_string(),
                slot_kind: "parser".to_string(),
                performance_uplift_millionths: 500_000,
                invocation_frequency_per_minute: 150,
                risk_reduction_millionths: 200_000,
            },
            ReplacementOpportunityInput {
                slot_id: "async-runtime".to_string(),
                slot_kind: "async_runtime".to_string(),
                performance_uplift_millionths: 800_000,
                invocation_frequency_per_minute: 5,
                risk_reduction_millionths: 100_000,
            },
        ],
        rollback_events: vec![RollbackEventView {
            slot_id: "parser".to_string(),
            receipt_id: "rcpt-parser-1".to_string(),
            reason: "divergence detected".to_string(),
            status: RollbackStatus::Investigating,
            occurred_at_unix_ms: 1_700_000_000_200,
            lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
            evidence_ref: "frankentui://evidence/parser".to_string(),
        }],
        ..Default::default()
    });

    let envelope = AdapterEnvelope::new(
        "trace-replacement-1",
        1_700_000_000_251,
        AdapterStream::ReplacementProgressDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::ReplacementProgressDashboard(replacement),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.stream, AdapterStream::ReplacementProgressDashboard);
    match decoded.payload {
        FrankentuiViewPayload::ReplacementProgressDashboard(view) => {
            assert_eq!(view.native_coverage.native_slots, 1);
            assert_eq!(view.native_coverage.delegate_slots, 1);
            assert_eq!(view.next_best_replacements[0].slot_id, "parser");
        }
        other => panic!("expected replacement dashboard payload, got {other:?}"),
    }
}

#[test]
fn proof_specialization_lineage_dashboard_round_trips_with_alert_views() {
    let proof_lineage =
        ProofSpecializationLineageDashboardView::from_partial(ProofSpecializationLineagePartial {
            cluster: "prod".to_string(),
            zone: "us-east-2".to_string(),
            security_epoch: Some(33),
            generated_at_unix_ms: Some(1_700_000_000_900),
            proof_inventory: vec![
                ProofInventoryRowView {
                    proof_id: "proof-cap-1".to_string(),
                    proof_kind: ProofInventoryKind::CapabilityWitness,
                    validity_status: ProofValidityStatus::Valid,
                    epoch_id: 33,
                    linked_specialization_count: 2,
                    enabled_specialization_ids: vec!["spec-a".to_string(), "spec-b".to_string()],
                    proof_ref: "frankentui://proof/proof-cap-1".to_string(),
                },
                ProofInventoryRowView {
                    proof_id: "proof-flow-2".to_string(),
                    proof_kind: ProofInventoryKind::FlowProof,
                    validity_status: ProofValidityStatus::ExpiringSoon,
                    epoch_id: 33,
                    linked_specialization_count: 1,
                    enabled_specialization_ids: vec!["spec-b".to_string()],
                    proof_ref: "frankentui://proof/proof-flow-2".to_string(),
                },
            ],
            active_specializations: vec![
                ActiveSpecializationRowView {
                    specialization_id: "spec-a".to_string(),
                    target_id: "ext-a".to_string(),
                    target_kind: "extension".to_string(),
                    optimization_class: "ifc_check_elision".to_string(),
                    latency_reduction_millionths: 350_000,
                    throughput_increase_millionths: 450_000,
                    proof_input_ids: vec!["proof-cap-1".to_string()],
                    transformation_ref: "frankentui://transform/spec-a".to_string(),
                    receipt_ref: "frankentui://receipt/spec-a".to_string(),
                    activated_at_unix_ms: 1_700_000_000_860,
                },
                ActiveSpecializationRowView {
                    specialization_id: "spec-b".to_string(),
                    target_id: "slot-parser".to_string(),
                    target_kind: "slot".to_string(),
                    optimization_class: "hostcall_dispatch_specialization".to_string(),
                    latency_reduction_millionths: 120_000,
                    throughput_increase_millionths: 180_000,
                    proof_input_ids: vec!["proof-cap-1".to_string(), "proof-flow-2".to_string()],
                    transformation_ref: "frankentui://transform/spec-b".to_string(),
                    receipt_ref: "frankentui://receipt/spec-b".to_string(),
                    activated_at_unix_ms: 1_700_000_000_865,
                },
            ],
            invalidation_feed: vec![SpecializationInvalidationRowView {
                invalidation_id: "inv-1".to_string(),
                specialization_id: "spec-b".to_string(),
                target_id: "slot-parser".to_string(),
                reason: ProofSpecializationInvalidationReason::ProofExpired,
                reason_detail: "proof validity window elapsed".to_string(),
                proof_id: Some("proof-flow-2".to_string()),
                old_epoch_id: Some(33),
                new_epoch_id: Some(34),
                fallback_confirmed: true,
                fallback_confirmation_ref: "frankentui://fallback/spec-b".to_string(),
                occurred_at_unix_ms: 1_700_000_000_870,
            }],
            fallback_events: vec![SpecializationFallbackEventView {
                event_id: "fb-1".to_string(),
                specialization_id: Some("spec-b".to_string()),
                target_id: "slot-parser".to_string(),
                reason: SpecializationFallbackReason::ProofExpired,
                reason_detail: "using unspecialized parser path".to_string(),
                unspecialized_path_ref: "frankentui://path/slot-parser/unspecialized".to_string(),
                compilation_ref: "frankentui://compile/slot-parser/1".to_string(),
                occurred_at_unix_ms: 1_700_000_000_871,
            }],
            bulk_invalidation_alert_threshold: Some(1),
            degraded_coverage_alert_threshold_millionths: Some(950_000),
            ..Default::default()
        });

    let envelope = AdapterEnvelope::new(
        "trace-proof-lineage-1",
        1_700_000_000_901,
        AdapterStream::ProofSpecializationLineageDashboard,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::ProofSpecializationLineageDashboard(proof_lineage),
    );

    let encoded = envelope.encode_json().expect("encode");
    let decoded: AdapterEnvelope = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(
        decoded.stream,
        AdapterStream::ProofSpecializationLineageDashboard
    );
    match decoded.payload {
        FrankentuiViewPayload::ProofSpecializationLineageDashboard(view) => {
            assert_eq!(view.proof_inventory.len(), 2);
            assert_eq!(view.active_specializations.len(), 2);
            assert_eq!(view.invalidation_feed.len(), 1);
            assert_eq!(view.fallback_events.len(), 1);
            assert_eq!(view.performance_impact.active_specialization_count, 2);
            assert!(!view.alert_indicators.is_empty());
        }
        other => panic!("expected proof specialization payload, got {other:?}"),
    }
}
