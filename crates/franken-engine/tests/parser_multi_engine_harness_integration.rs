use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::parser_multi_engine_harness::{
    DriftCategory, DriftSeverity, HarnessEngineKind, HarnessEngineSpec, MultiEngineHarnessConfig,
    MultiEngineHarnessError, run_multi_engine_harness,
};

type EngineSignature = (String, String, bool, bool);
type FixtureSignature = (String, Vec<EngineSignature>);

fn test_config(seed: u64) -> MultiEngineHarnessConfig {
    let mut config = MultiEngineHarnessConfig::with_defaults(seed);
    config.fixture_catalog_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/parser_phase0_semantic_fixtures.json");
    config.fixture_limit = Some(2);
    config.trace_id = "trace-parser-multi-engine-integration".to_string();
    config.decision_id = "decision-parser-multi-engine-integration".to_string();
    config.policy_id = "policy-parser-multi-engine-integration-v1".to_string();
    config
}

fn write_empty_source_fixture_catalog() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "franken-engine-parser-harness-empty-source-{timestamp}.json"
    ));
    let payload = serde_json::json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": [
            {
                "id": "empty-source-diagnostic-parity",
                "family_id": "diagnostics.empty_source",
                "goal": "script",
                "source": "   ",
                "expected_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }
        ]
    });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&payload).expect("catalog payload should serialize"),
    )
    .expect("fixture catalog should write");
    path
}

fn stable_fixture_signatures(
    report: &frankenengine_engine::parser_multi_engine_harness::MultiEngineHarnessReport,
) -> Vec<FixtureSignature> {
    report
        .fixture_results
        .iter()
        .map(|fixture| {
            let engine_rows = fixture
                .engine_results
                .iter()
                .map(|engine| {
                    (
                        engine.engine_id.clone(),
                        format!("{:?}:{}", engine.first_run.kind, engine.first_run.value),
                        engine.first_run.deterministic,
                        engine.second_run.deterministic,
                    )
                })
                .collect::<Vec<_>>();
            (fixture.fixture_id.clone(), engine_rows)
        })
        .collect()
}

#[test]
fn harness_report_is_stable_for_same_seed_and_fixture_slice() {
    let config = test_config(7);
    let left = run_multi_engine_harness(&config).expect("left run should succeed");
    let right = run_multi_engine_harness(&config).expect("right run should succeed");

    assert_eq!(left.run_id, right.run_id);
    assert_eq!(left.fixture_catalog_hash, right.fixture_catalog_hash);
    assert_eq!(left.summary, right.summary);
    assert_eq!(
        stable_fixture_signatures(&left),
        stable_fixture_signatures(&right)
    );

    for fixture in &left.fixture_results {
        assert!(
            fixture
                .replay_command
                .contains("franken_parser_multi_engine_harness"),
            "missing replay command for fixture `{}`",
            fixture.fixture_id
        );
        assert!(
            fixture.replay_command.contains("--fixture-id"),
            "replay command should include fixture id for `{}`",
            fixture.fixture_id
        );
    }
}

#[test]
fn harness_detects_external_engine_divergence_deterministically() {
    let mut config = test_config(13);
    config.fixture_limit = Some(1);
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_mock".to_string(),
            display_name: "External Mock".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-mock@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"hash\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}\\n'"
                    .to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.summary.total_fixtures, 1);
    assert_eq!(report.summary.divergent_fixtures, 1);
    assert_eq!(report.summary.fixtures_with_nondeterminism, 0);
    assert_eq!(report.fixture_results.len(), 1);
    assert!(!report.fixture_results[0].equivalent_across_engines);
    assert!(
        report.fixture_results[0]
            .divergence_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("external_mock")),
        "divergence reason should name external engine"
    );
    let classification = report.fixture_results[0]
        .drift_classification
        .as_ref()
        .expect("drift classification");
    assert_eq!(classification.category, DriftCategory::Semantic);
    assert_eq!(classification.severity, DriftSeverity::Critical);
    assert_eq!(classification.owner_hint, "parser-core");
}

#[test]
fn harness_returns_explicit_error_when_fixture_filter_is_missing() {
    let mut config = test_config(5);
    config.fixture_id_filter = Some("does-not-exist".to_string());
    let err = run_multi_engine_harness(&config).expect_err("missing fixture should fail");
    assert!(
        matches!(
            err,
            MultiEngineHarnessError::FixtureFilterNotFound { ref fixture_id }
            if fixture_id == "does-not-exist"
        ),
        "unexpected error variant: {err}"
    );
}

#[test]
fn harness_normalizes_equivalent_parse_errors_across_engines() {
    let fixture_catalog = write_empty_source_fixture_catalog();

    let mut config = MultiEngineHarnessConfig::with_defaults(23);
    config.fixture_catalog_path = fixture_catalog.clone();
    config.fixture_limit = Some(1);
    config.trace_id = "trace-parser-multi-engine-diagnostic-normalization".to_string();
    config.decision_id = "decision-parser-multi-engine-diagnostic-normalization".to_string();
    config.policy_id = "policy-parser-multi-engine-diagnostic-normalization-v1".to_string();
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_lc_error".to_string(),
            display_name: "External Lowercase Error".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-lc-error@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"error_code\":\"empty_source\"}\\n'".to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.summary.total_fixtures, 1);
    assert_eq!(report.summary.equivalent_fixtures, 1);
    assert_eq!(report.summary.divergent_fixtures, 0);

    let fixture = report
        .fixture_results
        .first()
        .expect("fixture result should exist");
    assert!(
        fixture.equivalent_across_engines,
        "normalized diagnostics should be equivalent across engines"
    );
    assert_eq!(fixture.engine_results.len(), 2);
    let first = fixture.engine_results[0]
        .first_run
        .normalized_diagnostic
        .as_ref()
        .expect("franken diagnostic artifact");
    let second = fixture.engine_results[1]
        .first_run
        .normalized_diagnostic
        .as_ref()
        .expect("external diagnostic artifact");
    assert_eq!(first.diagnostic_code, second.diagnostic_code);
    assert_eq!(first.canonical_hash, second.canonical_hash);

    let _ = fs::remove_file(fixture_catalog);
}

#[test]
fn harness_classifies_diagnostics_drift_as_minor() {
    let fixture_catalog = write_empty_source_fixture_catalog();

    let mut config = MultiEngineHarnessConfig::with_defaults(29);
    config.fixture_catalog_path = fixture_catalog.clone();
    config.fixture_limit = Some(1);
    config.trace_id = "trace-parser-multi-engine-diagnostic-drift".to_string();
    config.decision_id = "decision-parser-multi-engine-diagnostic-drift".to_string();
    config.policy_id = "policy-parser-multi-engine-diagnostic-drift-v1".to_string();
    config.engines = vec![
        HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
        HarnessEngineSpec {
            engine_id: "external_invalid_goal".to_string(),
            display_name: "External Invalid Goal".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "external-invalid-goal@v1".to_string(),
            command: Some("sh".to_string()),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf '{\"error_code\":\"invalid_goal\"}\\n'".to_string(),
            ],
        },
    ];

    let report = run_multi_engine_harness(&config).expect("run should succeed");
    assert_eq!(report.summary.total_fixtures, 1);
    assert_eq!(report.summary.divergent_fixtures, 1);
    assert_eq!(report.summary.drift_minor_fixtures, 1);
    assert_eq!(report.summary.drift_critical_fixtures, 0);

    let fixture = report
        .fixture_results
        .first()
        .expect("fixture result should exist");
    let classification = fixture
        .drift_classification
        .as_ref()
        .expect("classification should exist");
    assert_eq!(classification.category, DriftCategory::Diagnostics);
    assert_eq!(classification.severity, DriftSeverity::Minor);
    assert_eq!(classification.comparator_decision, "drift_minor");
    assert_eq!(classification.owner_hint, "parser-diagnostics-taxonomy");

    let _ = fs::remove_file(fixture_catalog);
}
