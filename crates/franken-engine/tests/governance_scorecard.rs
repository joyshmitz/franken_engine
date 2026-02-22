use std::collections::BTreeMap;

use frankenengine_engine::dp_budget_accountant::{AccountantConfig, BudgetAccountant};
use frankenengine_engine::governance_scorecard::{
    AttestedReceiptObservation, CrossRepoConformanceInput, GOVERNANCE_SCORECARD_SCHEMA_VERSION,
    GovernanceScorecardOutcome, GovernanceScorecardRequest, GovernanceScorecardThresholds,
    GovernanceScorecardTrendPoint, MoonshotGovernorHealthInput, PrivacyBudgetHealthInput,
    publish_governance_scorecard, verify_governance_scorecard_signature,
};
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceReport,
};
use frankenengine_engine::privacy_learning_contract::CompositionMethod;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::version_matrix_lane::MatrixHealthSummary;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([0x7A; 32])
}

fn baseline_budget_accountant() -> BudgetAccountant {
    let mut accountant = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: 1_000_000,
        delta_per_epoch_millionths: 100_000,
        lifetime_epsilon_budget_millionths: 10_000_000,
        lifetime_delta_budget_millionths: 1_000_000,
        composition_method: CompositionMethod::Basic,
        epoch: SecurityEpoch::from_raw(7),
        zone: "zone-governance-scorecard".to_string(),
        now_ns: 1_720_000_000_000_000_000,
    })
    .expect("accountant");

    accountant
        .consume(300_000, 30_000, "baseline", 2_000_000_000)
        .expect("consume");
    accountant
}

fn baseline_request() -> GovernanceScorecardRequest {
    let receipts = vec![
        AttestedReceiptObservation {
            receipt_id: "r-001".to_string(),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 10,
        },
        AttestedReceiptObservation {
            receipt_id: "r-002".to_string(),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 11,
        },
        AttestedReceiptObservation {
            receipt_id: "r-003".to_string(),
            high_impact: false,
            attestation_binding_valid: false,
            timestamp_ns: 12,
        },
    ];

    GovernanceScorecardRequest {
        trace_id: "trace-governance-scorecard".to_string(),
        decision_id: "decision-governance-scorecard".to_string(),
        policy_id: "policy-governance-scorecard-v1".to_string(),
        scorecard_run_id: "".to_string(),
        generated_at_ns: 1_720_000_000_000_000_000,
        attested_receipts: receipts,
        privacy_budget: PrivacyBudgetHealthInput {
            accountant: baseline_budget_accountant(),
            overrun_incidents: 0,
            measurement_window_ns: 24 * 3_600_000_000_000,
            measurement_end_ns: 1_720_000_000_000_000_000,
        },
        moonshot_governor: MoonshotGovernorHealthInput {
            governance_report: GovernanceReport {
                total_decisions: 10,
                override_count: 1,
                kill_count: 1,
                override_frequency_millionths: 100_000,
                kill_rate_millionths: 100_000,
                mean_time_to_decision_ns: Some(10_000_000_000),
                portfolio_health_trend: Vec::new(),
            },
            active_moonshots: 4,
            paused_moonshots: 1,
            killed_moonshots: 1,
        },
        conformance: CrossRepoConformanceInput {
            release_id: "release-2026.02.22".to_string(),
            matrix_health: MatrixHealthSummary {
                total_cells: 20,
                passed_cells: 19,
                failed_cells: 1,
                universal_failures: 0,
                version_specific_failures: 1,
            },
            failure_class_distribution: BTreeMap::from([
                ("behavioral".to_string(), 1),
                ("observability".to_string(), 0),
            ]),
            outstanding_exemptions: 0,
        },
        historical: Vec::new(),
        thresholds: None,
    }
}

fn ledger() -> GovernanceAuditLedger {
    GovernanceAuditLedger::new(GovernanceLedgerConfig::default()).expect("ledger")
}

#[test]
fn publish_healthy_scorecard_signs_and_records_in_ledger() {
    let request = baseline_request();
    let mut governance_ledger = ledger();

    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(
        publication.schema_version,
        GOVERNANCE_SCORECARD_SCHEMA_VERSION
    );
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Healthy);
    assert!(publication.blockers.is_empty());
    assert!(publication.warnings.is_empty());
    assert_eq!(publication.ledger_sequence, 1);
    assert_eq!(governance_ledger.entries().len(), 1);
    assert_eq!(
        governance_ledger.entries()[0].decision_type,
        GovernanceDecisionType::Promote
    );
    assert!(verify_governance_scorecard_signature(&publication).is_ok());

    let json = publication.to_json_pretty().expect("json");
    assert!(json.contains("governance-scorecard"));
    let markdown = publication.to_markdown_report();
    assert!(markdown.contains("# Governance Scorecard"));
    assert!(markdown.contains("## Dimensions"));
}

#[test]
fn low_attested_coverage_triggers_critical_and_kill_decision() {
    let mut request = baseline_request();
    request.attested_receipts[1].attestation_binding_valid = false;

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(!publication.blockers.is_empty());
    assert!(
        publication
            .blockers
            .iter()
            .any(|blocker| blocker.contains("attested-receipt coverage"))
    );
    assert_eq!(
        governance_ledger.entries()[0].decision_type,
        GovernanceDecisionType::Kill
    );
}

#[test]
fn near_term_privacy_exhaustion_surfaces_warning_without_blocker() {
    let mut request = baseline_request();
    request.privacy_budget.accountant = {
        let mut accountant = BudgetAccountant::new(AccountantConfig {
            epsilon_per_epoch_millionths: 1_000_000,
            delta_per_epoch_millionths: 100_000,
            lifetime_epsilon_budget_millionths: 10_000_000,
            lifetime_delta_budget_millionths: 1_000_000,
            composition_method: CompositionMethod::Basic,
            epoch: SecurityEpoch::from_raw(7),
            zone: "zone-governance-scorecard".to_string(),
            now_ns: 1_720_000_000_000_000_000,
        })
        .expect("accountant");
        accountant
            .consume(850_000, 85_000, "heavy-load", 2_000_000_000)
            .expect("consume");
        accountant
    };
    request.thresholds = Some(GovernanceScorecardThresholds {
        warn_privacy_exhaustion_within_ns: Some(7 * 24 * 3_600_000_000_000),
        ..GovernanceScorecardThresholds::default()
    });

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Warning);
    assert!(publication.blockers.is_empty());
    assert!(
        publication
            .warnings
            .iter()
            .any(|warning| warning.contains("projected to exhaust"))
    );
    assert_eq!(
        governance_ledger.entries()[0].decision_type,
        GovernanceDecisionType::Hold
    );
}

#[test]
fn trend_regression_warns_by_default() {
    let mut request = baseline_request();
    request.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "historical-1".to_string(),
        generated_at_ns: request.generated_at_ns.saturating_sub(1),
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 250_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 1_000_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert!(publication.trend_regression_detected);
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Warning);
    assert!(
        publication
            .warnings
            .iter()
            .any(|warning| warning.contains("trend regression"))
    );
}

#[test]
fn trend_regression_can_block_when_configured() {
    let mut request = baseline_request();
    request.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "historical-1".to_string(),
        generated_at_ns: request.generated_at_ns.saturating_sub(1),
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 250_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 1_000_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    request.thresholds = Some(GovernanceScorecardThresholds {
        fail_on_trend_regression: true,
        ..GovernanceScorecardThresholds::default()
    });

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert!(publication.trend_regression_detected);
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(
        publication
            .blockers
            .iter()
            .any(|blocker| blocker.contains("trend regression"))
    );
}

#[test]
fn derived_scorecard_id_is_deterministic_for_reordered_receipts() {
    let request_a = baseline_request();
    let mut request_b = baseline_request();
    request_b.attested_receipts.reverse();

    let mut ledger_a = ledger();
    let mut ledger_b = ledger();

    let publication_a = publish_governance_scorecard(
        &request_a,
        &signing_key(),
        &mut ledger_a,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication A");

    let publication_b = publish_governance_scorecard(
        &request_b,
        &signing_key(),
        &mut ledger_b,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication B");

    assert_eq!(publication_a.scorecard_id, publication_b.scorecard_id);
    assert_eq!(
        publication_a.attested_receipt_coverage,
        publication_b.attested_receipt_coverage
    );
    assert_eq!(publication_a.outcome, publication_b.outcome);
}
