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

// ────────────────────────────────────────────────────────────
// Enrichment: query, report, chain integrity, serde, actors
// ────────────────────────────────────────────────────────────

#[test]
fn empty_ledger_has_no_entries_or_checkpoints() {
    let ledger = ledger();
    assert!(ledger.entries().is_empty());
    assert!(ledger.checkpoints().is_empty());
    assert!(ledger.events().is_empty());
    assert!(ledger.latest_entry().is_none());
    assert!(ledger.latest_checkpoint().is_none());
}

#[test]
fn empty_ledger_chain_verification_succeeds() {
    let ledger = ledger();
    ledger.verify_chain().expect("empty chain should verify");
}

#[test]
fn query_all_returns_all_entries() {
    let mut ledger = ledger();

    let promote = GovernorDecision {
        decision_id: "auto-q1".to_string(),
        moonshot_id: "moon-q1".to_string(),
        kind: GovernorDecisionKind::Promote {
            from: MoonshotStage::Research,
            to: MoonshotStage::Shadow,
        },
        scorecard: sample_scorecard(),
        timestamp_ns: 100,
        epoch: SecurityEpoch::from_raw(3),
        rationale: "gate met".to_string(),
    };
    ledger
        .append_governor_decision(
            &promote,
            GovernanceActor::System("portfolio-governor".to_string()),
            vec!["artifact://q1".to_string()],
            Some(10),
        )
        .expect("append");

    let all = ledger.query(&GovernanceLedgerQuery::all());
    assert_eq!(all.len(), 1);
}

#[test]
fn query_by_moonshot_id_filters_correctly() {
    let mut ledger = ledger();

    for (i, moonshot) in ["moon-a", "moon-b"].iter().enumerate() {
        let decision = GovernorDecision {
            decision_id: format!("auto-{i}"),
            moonshot_id: moonshot.to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: (100 + i as u64) * 10,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(10),
            )
            .expect("append");
    }

    let query = GovernanceLedgerQuery {
        moonshot_id: Some("moon-b".to_string()),
        ..GovernanceLedgerQuery::all()
    };
    let results = ledger.query(&query);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].moonshot_id, "moon-b");
}

#[test]
fn governance_actor_is_human() {
    let human = GovernanceActor::Human("operator".to_string());
    assert!(human.is_human());
    assert_eq!(human.actor_id(), "operator");

    let system = GovernanceActor::System("portfolio-governor".to_string());
    assert!(!system.is_human());
    assert_eq!(system.actor_id(), "portfolio-governor");
}

#[test]
fn governance_decision_type_serde_round_trip() {
    for dtype in [
        GovernanceDecisionType::Promote,
        GovernanceDecisionType::Override,
    ] {
        let json = serde_json::to_string(&dtype).expect("serialize");
        let recovered: GovernanceDecisionType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dtype, recovered);
    }
}

#[test]
fn governance_rationale_for_automatic_decision() {
    let rationale = GovernanceRationale::for_automatic_decision(
        "all criteria met",
        850_000,
        150_000,
        vec!["ev_threshold".to_string(), "confidence".to_string()],
        vec![],
    );
    assert_eq!(rationale.summary, "all criteria met");
    assert_eq!(rationale.passed_criteria.len(), 2);
    assert!(rationale.failed_criteria.is_empty());
    assert!(rationale.bypassed_risk_criteria.is_empty());
    assert!(!rationale.acknowledged_bypass);
}

#[test]
fn latest_entry_and_checkpoint_after_appends() {
    let mut ledger = ledger();

    // Append 3 entries; config has checkpoint_interval=2
    for i in 0..3 {
        let decision = GovernorDecision {
            decision_id: format!("d-{i}"),
            moonshot_id: "moon-latest".to_string(),
            kind: GovernorDecisionKind::Promote {
                from: MoonshotStage::Research,
                to: MoonshotStage::Shadow,
            },
            scorecard: sample_scorecard(),
            timestamp_ns: 100 + i * 100,
            epoch: SecurityEpoch::from_raw(3),
            rationale: "gate met".to_string(),
        };
        ledger
            .append_governor_decision(
                &decision,
                GovernanceActor::System("gov".to_string()),
                vec![],
                Some(10),
            )
            .expect("append");
    }

    let latest = ledger.latest_entry().expect("should have entries");
    assert_eq!(latest.decision_id, "d-2");

    // With checkpoint_interval=2 and 3 entries, at least 1 checkpoint
    assert!(!ledger.checkpoints().is_empty());
    assert!(ledger.latest_checkpoint().is_some());
}

#[test]
fn governance_report_on_empty_ledger() {
    let ledger = ledger();
    let report = ledger
        .governance_report(0, 1_000, 500)
        .expect("report on empty");
    assert_eq!(report.total_decisions, 0);
    assert_eq!(report.override_count, 0);
}

#[test]
fn scorecard_snapshot_from_scorecard() {
    let sc = sample_scorecard();
    let snap = ScorecardSnapshot::from(&sc);
    assert_eq!(snap.ev_millionths, sc.ev_millionths);
    assert_eq!(snap.confidence_millionths, sc.confidence_millionths);
    assert_eq!(snap.risk_of_harm_millionths, sc.risk_of_harm_millionths);
}
