use std::path::PathBuf;

use frankenengine_engine::parser_multi_engine_harness::{
    HarnessEngineKind, HarnessEngineSpec, MultiEngineHarnessConfig, MultiEngineHarnessError,
    run_multi_engine_harness,
};

type EngineSignature = (String, String, bool, bool);
type FixtureSignature = (String, Vec<EngineSignature>);

fn test_config(seed: u64) -> MultiEngineHarnessConfig {
    let mut config = MultiEngineHarnessConfig::with_defaults(seed);
    config.fixture_catalog_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parser_phase0_semantic_fixtures.json");
    config.fixture_limit = Some(2);
    config.trace_id = "trace-parser-multi-engine-integration".to_string();
    config.decision_id = "decision-parser-multi-engine-integration".to_string();
    config.policy_id = "policy-parser-multi-engine-integration-v1".to_string();
    config
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
            fixture.replay_command.contains("franken_parser_multi_engine_harness"),
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
