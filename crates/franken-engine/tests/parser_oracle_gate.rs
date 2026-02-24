use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParserMode};
use frankenengine_engine::parser_oracle::{
    DriftClass, OracleGateMode, OraclePartition, ParserOracleConfig, derive_seed, run_parser_oracle,
};
use serde_json::json;

fn fixture_hash(source: &str, goal: ParseGoal) -> String {
    CanonicalEs2020Parser
        .parse(source, goal)
        .unwrap_or_else(|error| panic!("failed to parse `{source}` for fixture hash: {error}"))
        .canonical_hash()
}

fn write_fixture_catalog(fixtures: serde_json::Value) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken_engine_parser_oracle_{nanos}.json"));
    let payload = json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": fixtures
    });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&payload).expect("serialize fixture catalog"),
    )
    .expect("write fixture catalog");
    path
}

#[test]
fn derive_seed_is_deterministic_and_mode_scoped() {
    let first = derive_seed(17, "fixture_a", ParserMode::ScalarReference);
    let second = derive_seed(17, "fixture_a", ParserMode::ScalarReference);
    let third = derive_seed(17, "fixture_b", ParserMode::ScalarReference);
    assert_eq!(first, second);
    assert_ne!(first, third);
}

#[test]
fn smoke_partition_selects_four_sorted_fixtures() {
    let fixtures = json!([
        {
            "id": "fixture_zeta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha",
            "expected_hash": fixture_hash("alpha", ParseGoal::Script)
        },
        {
            "id": "fixture_beta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "beta",
            "expected_hash": fixture_hash("beta", ParseGoal::Script)
        },
        {
            "id": "fixture_theta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "theta",
            "expected_hash": fixture_hash("theta", ParseGoal::Script)
        },
        {
            "id": "fixture_alpha",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha + beta",
            "expected_hash": fixture_hash("alpha + beta", ParseGoal::Script)
        },
        {
            "id": "fixture_delta",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "delta",
            "expected_hash": fixture_hash("delta", ParseGoal::Script)
        }
    ]);
    let path = write_fixture_catalog(fixtures);

    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::FailClosed, 7);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-test-smoke".to_string();
    config.decision_id = "decision-test-smoke".to_string();
    config.policy_id = "policy-test-smoke".to_string();

    let report = run_parser_oracle(&config).expect("run parser oracle");
    assert_eq!(report.summary.total_fixtures, 4);
    let ids: Vec<&str> = report
        .fixture_results
        .iter()
        .map(|entry| entry.fixture_id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "fixture_alpha",
            "fixture_beta",
            "fixture_delta",
            "fixture_theta"
        ]
    );
    assert!(!report.decision.promotion_blocked);

    let _ = fs::remove_file(path);
}

#[test]
fn artifact_hash_mismatch_is_critical_in_fail_closed_mode() {
    let fixtures = json!([
        {
            "id": "fixture_bad_hash",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha",
            "expected_hash": "sha256:deadbeef"
        }
    ]);
    let path = write_fixture_catalog(fixtures);

    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 13);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-test-fail-closed".to_string();
    config.decision_id = "decision-test-fail-closed".to_string();
    config.policy_id = "policy-test-fail-closed".to_string();

    let report = run_parser_oracle(&config).expect("run parser oracle");
    assert_eq!(report.summary.critical_drift_count, 1);
    assert!(report.decision.promotion_blocked);
    assert_eq!(
        report.decision.action,
        frankenengine_engine::parser_oracle::GateAction::Reject
    );
    assert_eq!(
        report.fixture_results[0].drift_class,
        DriftClass::ArtifactIntegrityFailure
    );

    let _ = fs::remove_file(path);
}

#[test]
fn report_only_mode_does_not_block_even_when_critical_drift_exists() {
    let fixtures = json!([
        {
            "id": "fixture_bad_hash",
            "family_id": "statement.expression",
            "goal": "script",
            "source": "alpha",
            "expected_hash": "sha256:deadbeef"
        }
    ]);
    let path = write_fixture_catalog(fixtures);

    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::ReportOnly, 13);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-test-report-only".to_string();
    config.decision_id = "decision-test-report-only".to_string();
    config.policy_id = "policy-test-report-only".to_string();

    let report = run_parser_oracle(&config).expect("run parser oracle");
    assert_eq!(report.summary.critical_drift_count, 1);
    assert!(!report.decision.promotion_blocked);
    assert!(report.decision.fallback_triggered);

    let _ = fs::remove_file(path);
}
