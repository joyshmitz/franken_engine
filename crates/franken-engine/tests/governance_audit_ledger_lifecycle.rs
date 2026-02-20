use std::collections::BTreeSet;

use frankenengine_engine::moonshot_contract::MoonshotStage;
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceLedgerInput, GovernanceLedgerQuery, GovernanceRationale, ScorecardSnapshot,
};
use frankenengine_engine::portfolio_governor::{GovernorDecision, GovernorDecisionKind, Scorecard};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn sample_scorecard() -> Scorecard {
    Scorecard {
        moonshot_id: "moon-it-1".to_string(),
        ev_millionths: 900_000,
        confidence_millionths: 880_000,
        risk_of_harm_millionths: 140_000,
        implementation_friction_millionths: 110_000,
        cross_initiative_interference_millionths: 70_000,
        operational_burden_millionths: 220_000,
        computed_at_ns: 10,
        epoch: SecurityEpoch::from_raw(3),
    }
}

fn ledger() -> GovernanceAuditLedger {
    GovernanceAuditLedger::new(GovernanceLedgerConfig {
        checkpoint_interval: 2,
        signer_key: b"governance-it-key".to_vec(),
        policy_id: "moonshot-governor-policy-it".to_string(),
    })
    .expect("ledger should initialize")
}

#[test]
fn lifecycle_records_automatic_and_override_entries_with_query_and_report_support() {
    let mut ledger = ledger();

    let promote = GovernorDecision {
        decision_id: "auto-1".to_string(),
        moonshot_id: "moon-it-1".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "all gate criteria met".to_string(),
    };
    ledger
        .append_governor_decision(
            &promote,
            GovernanceActor::System("portfolio-governor".to_string()),
            vec!["artifact://scorecard/auto-1".to_string()],
            Some(10),
        )
        .expect("automatic append");

    ledger
        .append(GovernanceLedgerInput {
            decision_id: "ovr-1".to_string(),
            moonshot_id: "moon-it-1".to_string(),
            decision_type: GovernanceDecisionType::Override,
            actor: GovernanceActor::Human("operator-17".to_string()),
            rationale: GovernanceRationale {
                summary: "override hold due external incident context".to_string(),
                passed_criteria: vec!["artifact_obligations_met".to_string()],
                failed_criteria: vec!["risk_threshold".to_string()],
                confidence_millionths: 760_000,
                risk_of_harm_millionths: 260_000,
                bypassed_risk_criteria: vec!["risk_of_harm <= 200_000".to_string()],
                acknowledged_bypass: true,
            },
            scorecard_snapshot: ScorecardSnapshot::from(&sample_scorecard()),
            artifact_references: vec!["artifact://override/ovr-1".to_string()],
            timestamp_ns: 200,
            moonshot_started_at_ns: Some(10),
        })
        .expect("override append");

    ledger.verify_chain().expect("chain integrity");
    assert_eq!(ledger.entries().len(), 2);
    assert_eq!(ledger.checkpoints().len(), 1);

    let mut decision_types = BTreeSet::new();
    decision_types.insert(GovernanceDecisionType::Override);
    let rows = ledger.query(&GovernanceLedgerQuery {
        moonshot_id: Some("moon-it-1".to_string()),
        decision_types: Some(decision_types),
        actor_id: Some("operator-17".to_string()),
        start_time_ns: Some(150),
        end_time_ns: Some(220),
        override_only: Some(true),
    });
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].decision_id, "ovr-1");

    let report = ledger
        .governance_report(0, 1_000, 500)
        .expect("report generation");
    assert_eq!(report.total_decisions, 2);
    assert_eq!(report.override_count, 1);
    assert_eq!(report.override_frequency_millionths, 500_000);
    assert_eq!(report.mean_time_to_decision_ns, Some(140));
}

#[test]
fn append_failure_emits_stable_structured_event_fields() {
    let mut ledger = ledger();
    let err = ledger
        .append(GovernanceLedgerInput {
            decision_id: "ovr-bad".to_string(),
            moonshot_id: "moon-it-1".to_string(),
            decision_type: GovernanceDecisionType::Override,
            actor: GovernanceActor::Human("operator-17".to_string()),
            rationale: GovernanceRationale {
                summary: "bad override".to_string(),
                passed_criteria: Vec::new(),
                failed_criteria: Vec::new(),
                confidence_millionths: 700_000,
                risk_of_harm_millionths: 300_000,
                bypassed_risk_criteria: vec!["risk".to_string()],
                acknowledged_bypass: false,
            },
            scorecard_snapshot: ScorecardSnapshot::from(&sample_scorecard()),
            artifact_references: Vec::new(),
            timestamp_ns: 300,
            moonshot_started_at_ns: Some(10),
        })
        .expect_err("invalid override should fail");

    assert_eq!(err.code(), "FE-GOV-LED-0002");
    let event = ledger.events().last().expect("error event");
    assert_eq!(event.trace_id, "trace:ovr-bad");
    assert_eq!(event.decision_id, "ovr-bad");
    assert_eq!(event.policy_id, "moonshot-governor-policy-it");
    assert_eq!(event.component, "governance_audit_ledger");
    assert_eq!(event.event, "append_decision");
    assert_eq!(event.outcome, "rejected");
    assert_eq!(event.error_code.as_deref(), Some("FE-GOV-LED-0002"));
}
