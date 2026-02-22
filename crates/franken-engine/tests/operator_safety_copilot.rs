use frankenengine_engine::policy_controller::operator_safety_copilot::{
    ActionRecommendationCandidate, ActiveIncidentSummary, BoundaryTriggerDirection,
    CalibrationPoint, CategoryDetectionCount, ConfidenceBand, ContainmentActionOutcome,
    CopilotError, DecisionBoundaryHint, EvidenceStrength, ExtensionTrustCard, ExtensionTrustLevel,
    IncidentSeverity, IncidentTimelineEvent, OperatorIdentity, OperatorRole,
    OperatorSafetyCopilotInput, PolicyEffectivenessInput, RecommendationReversibility,
    RollbackReceiptInput, TimeSensitivity, TimelineDrilldownPointers, build_fleet_health_overview,
    build_operator_safety_copilot_surface, build_policy_effectiveness_view,
    build_rollback_execution_receipt, confirm_selected_recommendation, render_copilot_summary,
    select_recommendation_for_review,
};

fn sample_input() -> OperatorSafetyCopilotInput {
    OperatorSafetyCopilotInput {
        trace_id: "trace-copilot-1".to_string(),
        decision_id: "decision-copilot-1".to_string(),
        policy_id: "policy-copilot-1".to_string(),
        incident_id: "incident-copilot-1".to_string(),
        no_action_expected_loss_millionths: 8_400_000,
        recommendations: vec![
            ActionRecommendationCandidate {
                action_type: "sandbox".to_string(),
                target_extension: "ext-alpha".to_string(),
                expected_loss_reduction_millionths: 6_200_000,
                confidence_millionths: 730_000,
                side_effects: vec!["limited filesystem access".to_string()],
                collateral_extensions: 1,
                estimated_action_latency_ms: 200,
                reversibility: RecommendationReversibility::LimitedWindow,
                time_sensitivity: TimeSensitivity::Immediate,
                rollback_window_ms: Some(300_000),
                snapshot_id: Some("snap-alpha-1".to_string()),
            },
            ActionRecommendationCandidate {
                action_type: "terminate".to_string(),
                target_extension: "ext-alpha".to_string(),
                expected_loss_reduction_millionths: 7_100_000,
                confidence_millionths: 690_000,
                side_effects: vec!["interrupts active requests".to_string()],
                collateral_extensions: 3,
                estimated_action_latency_ms: 120,
                reversibility: RecommendationReversibility::Irreversible,
                time_sensitivity: TimeSensitivity::Immediate,
                rollback_window_ms: None,
                snapshot_id: None,
            },
            ActionRecommendationCandidate {
                action_type: "challenge".to_string(),
                target_extension: "ext-alpha".to_string(),
                expected_loss_reduction_millionths: 200_000,
                confidence_millionths: 810_000,
                side_effects: vec!["adds challenge latency".to_string()],
                collateral_extensions: 0,
                estimated_action_latency_ms: 35,
                reversibility: RecommendationReversibility::Reversible,
                time_sensitivity: TimeSensitivity::NearTerm,
                rollback_window_ms: None,
                snapshot_id: Some("snap-alpha-2".to_string()),
            },
        ],
        confidence_bands: vec![
            ConfidenceBand {
                metric: "p_malicious".to_string(),
                point_millionths: 730_000,
                lower_millionths: 580_000,
                upper_millionths: 850_000,
                confidence_level_bps: 8_000,
            },
            ConfidenceBand {
                metric: "containment_success_probability".to_string(),
                point_millionths: 940_000,
                lower_millionths: 880_000,
                upper_millionths: 980_000,
                confidence_level_bps: 8_000,
            },
        ],
        evidence_strength: EvidenceStrength {
            evidence_atoms: 47,
            observation_window_seconds: 720,
        },
        decision_boundary_hints: vec![
            DecisionBoundaryHint {
                metric: "rollback_risk_floor".to_string(),
                current_millionths: 120_000,
                threshold_millionths: 90_000,
                additional_evidence_needed: 1,
                evidence_type: "stability_probe".to_string(),
                trigger_direction: BoundaryTriggerDirection::AtOrBelow,
            },
            DecisionBoundaryHint {
                metric: "posterior_auto_terminate".to_string(),
                current_millionths: 730_000,
                threshold_millionths: 850_000,
                additional_evidence_needed: 2,
                evidence_type: "hostcall_anomaly".to_string(),
                trigger_direction: BoundaryTriggerDirection::AtOrAbove,
            },
        ],
        timeline: vec![
            IncidentTimelineEvent {
                timestamp_ns: 300,
                event_id: "ev-3".to_string(),
                event_type: "decision".to_string(),
                detail: "selected sandbox".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                drilldown: TimelineDrilldownPointers {
                    evidence_pointer: None,
                    decision_receipt_pointer: Some("receipt://decision-3".to_string()),
                    replay_pointer: Some("replay://incident-copilot-1".to_string()),
                    counterfactual_pointer: Some("counterfactual://sandbox-minus-120s".to_string()),
                },
            },
            IncidentTimelineEvent {
                timestamp_ns: 100,
                event_id: "ev-1".to_string(),
                event_type: "evidence".to_string(),
                detail: "suspicious hostcall burst".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                drilldown: TimelineDrilldownPointers {
                    evidence_pointer: Some("evidence://atom-1".to_string()),
                    decision_receipt_pointer: None,
                    replay_pointer: None,
                    counterfactual_pointer: None,
                },
            },
            IncidentTimelineEvent {
                timestamp_ns: 200,
                event_id: "ev-2".to_string(),
                event_type: "posterior_update".to_string(),
                detail: "p_malicious increased".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                drilldown: TimelineDrilldownPointers::default(),
            },
        ],
    }
}

fn operator(operator_id: &str, role: OperatorRole) -> OperatorIdentity {
    OperatorIdentity {
        operator_id: operator_id.to_string(),
        role,
    }
}

#[test]
fn copilot_surface_ranks_recommendations_deterministically() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");

    assert!(surface.read_only);
    assert_eq!(surface.recommended_action.action_type, "terminate");
    assert_eq!(surface.recommended_action.rank, 1);
    assert_eq!(surface.alternatives.len(), 2);
    assert_eq!(surface.alternatives[0].action_type, "sandbox");
    assert_eq!(surface.alternatives[1].action_type, "challenge");

    let second = build_operator_safety_copilot_surface(&input).expect("surface");
    assert_eq!(surface, second);
}

#[test]
fn copilot_surface_sorts_timeline_by_timestamp_then_id() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");

    let event_ids = surface
        .timeline
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(event_ids, vec!["ev-1", "ev-2", "ev-3"]);
    assert_eq!(
        surface.timeline[2]
            .drilldown
            .counterfactual_pointer
            .as_deref(),
        Some("counterfactual://sandbox-minus-120s")
    );
}

#[test]
fn copilot_surface_rejects_invalid_confidence_band_bounds() {
    let mut input = sample_input();
    input.confidence_bands[0].lower_millionths = 900_000;
    input.confidence_bands[0].point_millionths = 700_000;

    let err = build_operator_safety_copilot_surface(&input).expect_err("invalid bounds");
    assert_eq!(
        err,
        CopilotError::InvalidConfidenceBand {
            metric: "p_malicious".to_string()
        }
    );
}

#[test]
fn copilot_surface_rejects_missing_snapshot_for_reversible_action() {
    let mut input = sample_input();
    input.recommendations[0].snapshot_id = None;

    let err = build_operator_safety_copilot_surface(&input).expect_err("missing snapshot");
    assert_eq!(
        err,
        CopilotError::MissingSnapshotForRollback {
            action_type: "sandbox".to_string(),
            target_extension: "ext-alpha".to_string()
        }
    );
}

#[test]
fn copilot_surface_rejects_invalid_decision_boundary_hint() {
    let mut input = sample_input();
    input.decision_boundary_hints[0].additional_evidence_needed = 0;

    let err = build_operator_safety_copilot_surface(&input).expect_err("invalid boundary");
    assert_eq!(
        err,
        CopilotError::InvalidDecisionBoundaryHint {
            metric: "rollback_risk_floor".to_string()
        }
    );
}

#[test]
fn rollback_command_is_deterministic_and_policy_linked() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");

    let top = &surface.recommended_action.rollback_command.command;
    assert!(top.contains("--trace-id trace-copilot-1"));
    assert!(top.contains("--decision-id decision-copilot-1"));
    assert!(top.contains("--policy-id policy-copilot-1"));

    let irreversible = &surface.recommended_action;
    assert_eq!(
        irreversible.rollback_command.safety_summary,
        "irreversible action; dependent_extensions=3; estimated_latency_ms=120"
    );

    let limited_window = &surface.alternatives[0];
    assert!(
        limited_window
            .rollback_command
            .command
            .contains("--window-ms 300000")
    );
}

#[test]
fn summary_contains_recommendation_inaction_and_boundary_lines() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");
    let summary = render_copilot_summary(&surface);

    assert!(summary.contains("incident_id: incident-copilot-1"));
    assert!(summary.contains("recommended_action: terminate ext-alpha"));
    assert!(summary.contains("no_action_expected_loss: 8.400000"));
    assert!(summary.contains("decision_boundary:posterior_auto_terminate"));
    assert!(summary.contains("confidence_band:p_malicious=0.730000 [0.580000..0.850000] @8000bps"));
}

#[test]
fn structured_log_event_uses_required_fields() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");

    assert_eq!(surface.logs.len(), 1);
    let event = &surface.logs[0];
    assert_eq!(event.trace_id, "trace-copilot-1");
    assert_eq!(event.decision_id, "decision-copilot-1");
    assert_eq!(event.policy_id, "policy-copilot-1");
    assert_eq!(event.component, "operator_safety_copilot");
    assert_eq!(event.event, "copilot_surface_built");
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_code, None);
}

#[test]
fn viewer_cannot_select_recommendation_for_execution() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");
    let viewer = operator("view-1", OperatorRole::Viewer);

    let err =
        select_recommendation_for_review(&surface, &viewer, 1, 1_000).expect_err("viewer denied");
    assert_eq!(
        err,
        CopilotError::UnauthorizedRole {
            role: OperatorRole::Viewer,
            action: "select_recommendation".to_string(),
        }
    );
}

#[test]
fn action_selection_and_confirmation_emit_audit_and_deterministic_receipt() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");
    let op = operator("operator-7", OperatorRole::Operator);

    let review = select_recommendation_for_review(&surface, &op, 2, 1_234).expect("review");
    assert_eq!(review.selected_recommendation.action_type, "sandbox");
    assert_eq!(review.impact_summary.dependent_extensions_affected, 1);
    assert_eq!(review.impact_summary.estimated_latency_ms, 200);
    assert_eq!(
        review.impact_summary.rollback_window_ms_remaining,
        Some(300_000)
    );
    assert_eq!(review.audit_event.event, "copilot_action_selected");
    assert_eq!(review.audit_event.outcome, "pending_confirmation");

    let confirmed =
        confirm_selected_recommendation(&review, &op, "confirm-token-1", 2_000).expect("confirm");
    let confirmed_2 =
        confirm_selected_recommendation(&review, &op, "confirm-token-1", 2_000).expect("confirm");

    assert_eq!(confirmed, confirmed_2);
    assert!(
        confirmed
            .execution_command
            .contains("execute sandbox --extension ext-alpha")
    );
    assert!(
        confirmed
            .execution_command
            .contains("--confirmation-token-hash")
    );
    assert!(
        confirmed
            .rollback_command
            .command
            .contains("--window-ms 300000")
    );
    assert_eq!(confirmed.audit_event.event, "copilot_action_confirmed");
    assert_eq!(confirmed.audit_event.outcome, "executed");

    assert_eq!(confirmed.log_event.trace_id, "trace-copilot-1");
    assert_eq!(confirmed.log_event.decision_id, "decision-copilot-1");
    assert_eq!(confirmed.log_event.policy_id, "policy-copilot-1");
    assert_eq!(confirmed.log_event.component, "operator_safety_copilot");
    assert_eq!(confirmed.log_event.event, "copilot_action_confirmed");
    assert_eq!(confirmed.log_event.outcome, "pass");
    assert_eq!(confirmed.log_event.error_code, None);
}

#[test]
fn confirmation_requires_same_operator_and_nonempty_token() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");
    let op_a = operator("operator-a", OperatorRole::Operator);
    let op_b = operator("operator-b", OperatorRole::Administrator);

    let review = select_recommendation_for_review(&surface, &op_a, 1, 9_000).expect("review");

    let mismatch = confirm_selected_recommendation(&review, &op_b, "confirm-token", 9_100)
        .expect_err("mismatch");
    assert_eq!(
        mismatch,
        CopilotError::OperatorMismatch {
            selected_by: "operator-a".to_string(),
            confirmed_by: "operator-b".to_string(),
        }
    );

    let missing_token =
        confirm_selected_recommendation(&review, &op_a, "   ", 9_200).expect_err("missing token");
    assert_eq!(missing_token, CopilotError::MissingConfirmationToken);
}

#[test]
fn rollback_receipt_is_deterministic_and_action_linked() {
    let input = sample_input();
    let surface = build_operator_safety_copilot_surface(&input).expect("surface");
    let op = operator("operator-rb", OperatorRole::Operator);
    let review = select_recommendation_for_review(&surface, &op, 2, 40).expect("review");
    let confirmed = confirm_selected_recommendation(&review, &op, "tkn", 60).expect("confirmed");

    let rollback_input = RollbackReceiptInput {
        trace_id: "trace-copilot-1".to_string(),
        decision_id: "decision-copilot-1".to_string(),
        policy_id: "policy-copilot-1".to_string(),
        action_receipt_id: confirmed.receipt.receipt_id.clone(),
        rollback_decision_id: "rollback-decision-1".to_string(),
        evidence_pointer: "evidence://rollback-checkpoint-1".to_string(),
        restoration_verification: "restored ext-alpha snapshot snap-alpha-1".to_string(),
        executed_at_ns: 100,
    };

    let receipt_1 = build_rollback_execution_receipt(&rollback_input).expect("receipt");
    let receipt_2 = build_rollback_execution_receipt(&rollback_input).expect("receipt");

    assert_eq!(receipt_1, receipt_2);
    assert!(!receipt_1.signature.is_empty());
    assert_eq!(receipt_1.action_receipt_id, confirmed.receipt.receipt_id);
    assert_eq!(receipt_1.rollback_decision_id, "rollback-decision-1");
    assert_eq!(
        receipt_1.restoration_verification,
        "restored ext-alpha snapshot snap-alpha-1"
    );
}

#[test]
fn fleet_health_overview_is_sorted_and_deterministic() {
    let extension_cards = vec![
        ExtensionTrustCard {
            extension_id: "ext-z".to_string(),
            trust_level: ExtensionTrustLevel::High,
            recent_evidence_atoms: 12,
            recent_decision_ids: vec!["decision-z".to_string()],
            current_recommendation: Some("monitor".to_string()),
        },
        ExtensionTrustCard {
            extension_id: "ext-a".to_string(),
            trust_level: ExtensionTrustLevel::Quarantined,
            recent_evidence_atoms: 80,
            recent_decision_ids: vec!["decision-a".to_string()],
            current_recommendation: Some("terminate".to_string()),
        },
        ExtensionTrustCard {
            extension_id: "ext-b".to_string(),
            trust_level: ExtensionTrustLevel::Guarded,
            recent_evidence_atoms: 33,
            recent_decision_ids: vec!["decision-b".to_string()],
            current_recommendation: Some("sandbox".to_string()),
        },
    ];

    let active_incidents = vec![
        ActiveIncidentSummary {
            incident_id: "incident-2".to_string(),
            extension_id: "ext-z".to_string(),
            severity: IncidentSeverity::High,
            started_at_ns: 200,
            status: "active".to_string(),
        },
        ActiveIncidentSummary {
            incident_id: "incident-1".to_string(),
            extension_id: "ext-a".to_string(),
            severity: IncidentSeverity::Critical,
            started_at_ns: 100,
            status: "active".to_string(),
        },
    ];

    let containment = vec![
        ContainmentActionOutcome {
            incident_id: "incident-2".to_string(),
            action_type: "sandbox".to_string(),
            outcome: "pass".to_string(),
            latency_ms: 250,
        },
        ContainmentActionOutcome {
            incident_id: "incident-1".to_string(),
            action_type: "terminate".to_string(),
            outcome: "pass".to_string(),
            latency_ms: 150,
        },
    ];

    let roi = vec![210_000, 180_000, 140_000];

    let overview_1 =
        build_fleet_health_overview(&extension_cards, &active_incidents, &roi, &containment);
    let overview_2 =
        build_fleet_health_overview(&extension_cards, &active_incidents, &roi, &containment);

    assert_eq!(overview_1, overview_2);
    assert_eq!(overview_1.active_incidents_count, 2);
    assert_eq!(overview_1.highest_severity, IncidentSeverity::Critical);
    assert_eq!(overview_1.trust_level_distribution[0].extensions, 1);
    assert_eq!(overview_1.trust_level_distribution[1].extensions, 1);
    assert_eq!(overview_1.trust_level_distribution[2].extensions, 0);
    assert_eq!(overview_1.trust_level_distribution[3].extensions, 1);

    let extension_ids = overview_1
        .extension_details
        .iter()
        .map(|entry| entry.extension_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(extension_ids, vec!["ext-a", "ext-b", "ext-z"]);

    let incident_ids = overview_1
        .active_incidents
        .iter()
        .map(|entry| entry.incident_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(incident_ids, vec!["incident-1", "incident-2"]);
}

#[test]
fn policy_effectiveness_view_computes_rates_and_percentiles() {
    let input = PolicyEffectivenessInput {
        detection_counts: vec![
            CategoryDetectionCount {
                category: "phishing".to_string(),
                detected_events: 1,
                total_events: 2,
            },
            CategoryDetectionCount {
                category: "malware".to_string(),
                detected_events: 3,
                total_events: 4,
            },
        ],
        false_positive_rate_trend_millionths: vec![90_000, 110_000, 80_000],
        containment_latencies_ms: vec![90, 10, 30, 50],
        calibration_history: vec![
            CalibrationPoint {
                timestamp_ns: 200,
                expected_millionths: 700_000,
                observed_millionths: 690_000,
            },
            CalibrationPoint {
                timestamp_ns: 100,
                expected_millionths: 500_000,
                observed_millionths: 510_000,
            },
        ],
    };

    let view = build_policy_effectiveness_view(&input).expect("view");
    assert_eq!(view.detection_rate_by_category[0].category, "malware");
    assert_eq!(view.detection_rate_by_category[0].rate_millionths, 750_000);
    assert_eq!(view.detection_rate_by_category[1].category, "phishing");
    assert_eq!(view.detection_rate_by_category[1].rate_millionths, 500_000);

    assert_eq!(view.containment_latency_p50_ms, 50);
    assert_eq!(view.containment_latency_p95_ms, 90);
    assert_eq!(view.calibration_history[0].timestamp_ns, 100);
    assert_eq!(view.calibration_history[1].timestamp_ns, 200);
}
