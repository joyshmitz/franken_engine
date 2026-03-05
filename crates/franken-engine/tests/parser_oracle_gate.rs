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
    assert_eq!(
        report.taxonomy_version,
        "franken-engine.parser-oracle.taxonomy.v1"
    );
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
    assert_eq!(
        report.taxonomy_version,
        "franken-engine.parser-oracle.taxonomy.v1"
    );
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
    assert_eq!(
        report.taxonomy_version,
        "franken-engine.parser-oracle.taxonomy.v1"
    );
    assert_eq!(report.summary.critical_drift_count, 1);
    assert!(!report.decision.promotion_blocked);
    assert!(report.decision.fallback_triggered);

    let _ = fs::remove_file(path);
}

// ---------- OraclePartition ----------

#[test]
fn oracle_partition_as_str_values() {
    assert_eq!(OraclePartition::Smoke.as_str(), "smoke");
    assert_eq!(OraclePartition::Full.as_str(), "full");
    assert_eq!(OraclePartition::Nightly.as_str(), "nightly");
}

#[test]
fn oracle_partition_smoke_fixture_limit_is_four() {
    assert_eq!(OraclePartition::Smoke.fixture_limit(), Some(4));
}

#[test]
fn oracle_partition_full_has_no_fixture_limit() {
    assert_eq!(OraclePartition::Full.fixture_limit(), None);
}

#[test]
fn oracle_partition_nightly_has_no_fixture_limit() {
    assert_eq!(OraclePartition::Nightly.fixture_limit(), None);
}

#[test]
fn oracle_partition_metamorphic_pairs_increase_by_tier() {
    assert!(OraclePartition::Smoke.metamorphic_pairs() < OraclePartition::Full.metamorphic_pairs());
    assert!(
        OraclePartition::Full.metamorphic_pairs() < OraclePartition::Nightly.metamorphic_pairs()
    );
}

#[test]
fn oracle_partition_from_str_roundtrip() {
    for p in [
        OraclePartition::Smoke,
        OraclePartition::Full,
        OraclePartition::Nightly,
    ] {
        let parsed: OraclePartition = p.as_str().parse().expect("parse partition");
        assert_eq!(parsed, p);
    }
}

// ---------- OracleGateMode ----------

#[test]
fn oracle_gate_mode_as_str_values() {
    assert_eq!(OracleGateMode::ReportOnly.as_str(), "report_only");
    assert_eq!(OracleGateMode::FailClosed.as_str(), "fail_closed");
}

#[test]
fn oracle_gate_mode_from_str_roundtrip() {
    for m in [OracleGateMode::ReportOnly, OracleGateMode::FailClosed] {
        let parsed: OracleGateMode = m.as_str().parse().expect("parse gate mode");
        assert_eq!(parsed, m);
    }
}

// ---------- DriftClass ----------

#[test]
fn drift_class_equivalent_is_not_critical_or_minor() {
    assert!(!DriftClass::Equivalent.is_critical());
    assert!(!DriftClass::Equivalent.is_minor());
}

#[test]
fn drift_class_semantic_drift_is_critical() {
    assert!(DriftClass::SemanticDrift.is_critical());
    assert!(!DriftClass::SemanticDrift.is_minor());
}

#[test]
fn drift_class_diagnostics_drift_is_minor() {
    assert!(!DriftClass::DiagnosticsDrift.is_critical());
    assert!(DriftClass::DiagnosticsDrift.is_minor());
}

#[test]
fn drift_class_harness_nondeterminism_is_critical() {
    assert!(DriftClass::HarnessNondeterminism.is_critical());
}

#[test]
fn drift_class_artifact_integrity_failure_is_critical() {
    assert!(DriftClass::ArtifactIntegrityFailure.is_critical());
}

#[test]
fn drift_class_comparator_decisions() {
    assert_eq!(DriftClass::Equivalent.comparator_decision(), "equivalent");
    assert_eq!(
        DriftClass::DiagnosticsDrift.comparator_decision(),
        "drift_minor"
    );
    assert_eq!(
        DriftClass::SemanticDrift.comparator_decision(),
        "drift_critical"
    );
    assert_eq!(
        DriftClass::HarnessNondeterminism.comparator_decision(),
        "drift_critical"
    );
    assert_eq!(
        DriftClass::ArtifactIntegrityFailure.comparator_decision(),
        "drift_critical"
    );
}

// ---------- full partition ----------

#[test]
fn full_partition_uses_all_fixtures() {
    let fixtures = json!([
        { "id": "f1", "family_id": "fam", "goal": "script", "source": "a", "expected_hash": fixture_hash("a", ParseGoal::Script) },
        { "id": "f2", "family_id": "fam", "goal": "script", "source": "b", "expected_hash": fixture_hash("b", ParseGoal::Script) },
        { "id": "f3", "family_id": "fam", "goal": "script", "source": "c", "expected_hash": fixture_hash("c", ParseGoal::Script) },
        { "id": "f4", "family_id": "fam", "goal": "script", "source": "d", "expected_hash": fixture_hash("d", ParseGoal::Script) },
        { "id": "f5", "family_id": "fam", "goal": "script", "source": "e", "expected_hash": fixture_hash("e", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 42);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-full".to_string();
    config.decision_id = "decision-full".to_string();
    config.policy_id = "policy-full".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(report.summary.total_fixtures, 5);
    assert_eq!(report.fixture_results.len(), 5);
    let _ = fs::remove_file(path);
}

// ---------- all equivalent = Promote ----------

#[test]
fn all_equivalent_fixtures_produce_promote_action() {
    let fixtures = json!([
        { "id": "ok1", "family_id": "fam", "goal": "script", "source": "x", "expected_hash": fixture_hash("x", ParseGoal::Script) },
        { "id": "ok2", "family_id": "fam", "goal": "script", "source": "y", "expected_hash": fixture_hash("y", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 99);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-promote".to_string();
    config.decision_id = "decision-promote".to_string();
    config.policy_id = "policy-promote".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(report.summary.equivalent_count, 2);
    assert_eq!(report.summary.critical_drift_count, 0);
    assert_eq!(report.summary.minor_drift_count, 0);
    assert!(!report.decision.promotion_blocked);
    assert_eq!(
        report.decision.action,
        frankenengine_engine::parser_oracle::GateAction::Promote
    );
    let _ = fs::remove_file(path);
}

// ---------- report fields ----------

#[test]
fn report_schema_version_matches_constant() {
    let fixtures = json!([
        { "id": "sv", "family_id": "fam", "goal": "script", "source": "z", "expected_hash": fixture_hash("z", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::ReportOnly, 1);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-sv".to_string();
    config.decision_id = "decision-sv".to_string();
    config.policy_id = "policy-sv".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(
        report.schema_version,
        frankenengine_engine::parser_oracle::PARSER_ORACLE_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        report.taxonomy_version,
        frankenengine_engine::parser_oracle::PARSER_ORACLE_TAXONOMY_VERSION
    );
    let _ = fs::remove_file(path);
}

#[test]
fn report_fixture_results_have_replay_commands() {
    let fixtures = json!([
        { "id": "rc", "family_id": "fam", "goal": "script", "source": "w", "expected_hash": fixture_hash("w", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 2);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-rc".to_string();
    config.decision_id = "decision-rc".to_string();
    config.policy_id = "policy-rc".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    for result in &report.fixture_results {
        assert!(!result.replay_command.is_empty(), "must have replay command");
        assert!(!result.fixture_id.is_empty());
        assert!(!result.input_hash.is_empty());
    }
    let _ = fs::remove_file(path);
}

// ---------- derive_seed ----------

#[test]
fn derive_seed_different_master_seeds_diverge() {
    let a = derive_seed(1, "fixture_same", ParserMode::ScalarReference);
    let b = derive_seed(2, "fixture_same", ParserMode::ScalarReference);
    assert_ne!(a, b);
}

// ---------- config defaults ----------

#[test]
fn config_with_defaults_populates_trace_and_decision_ids() {
    let config =
        ParserOracleConfig::with_defaults(OraclePartition::Smoke, OracleGateMode::FailClosed, 123);
    assert!(!config.trace_id.is_empty());
    assert!(!config.decision_id.is_empty());
    assert!(!config.policy_id.is_empty());
    assert_eq!(config.seed, 123);
}

// ---------- summary drift rate ----------

#[test]
fn summary_drift_rate_zero_when_all_equivalent() {
    let fixtures = json!([
        { "id": "dr", "family_id": "fam", "goal": "script", "source": "v", "expected_hash": fixture_hash("v", ParseGoal::Script) }
    ]);
    let path = write_fixture_catalog(fixtures);
    let mut config =
        ParserOracleConfig::with_defaults(OraclePartition::Full, OracleGateMode::FailClosed, 3);
    config.fixture_catalog_path = path.clone();
    config.trace_id = "trace-dr".to_string();
    config.decision_id = "decision-dr".to_string();
    config.policy_id = "policy-dr".to_string();
    let report = run_parser_oracle(&config).expect("oracle");
    assert_eq!(report.summary.drift_rate_millionths, 0);
    let _ = fs::remove_file(path);
}
