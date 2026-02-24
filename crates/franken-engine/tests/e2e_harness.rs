#[path = "../src/e2e_harness.rs"]
mod e2e_harness;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use e2e_harness::{
    ArtifactCollector, DeterministicRunner, FixtureStore, GoldenStore, GoldenVerificationError,
    LogExpectation, ReplayInputErrorCode, ScenarioStep, TestFixture, assert_structured_logs,
    audit_collected_artifacts, validate_replay_input, verify_replay,
};

fn test_temp_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-engine-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn sample_fixture() -> TestFixture {
    let mut error_metadata = BTreeMap::new();
    error_metadata.insert("error_code".to_string(), "FE-E2E-0007".to_string());

    TestFixture {
        fixture_id: "fixture-hello".to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed: 42,
        virtual_time_start_micros: 1_000,
        policy_id: "policy-default".to_string(),
        steps: vec![
            ScenarioStep {
                component: "scheduler".to_string(),
                event: "dispatch".to_string(),
                advance_micros: 100,
                metadata: BTreeMap::new(),
            },
            ScenarioStep {
                component: "guardplane".to_string(),
                event: "challenge".to_string(),
                advance_micros: 200,
                metadata: error_metadata,
            },
        ],
        expected_events: vec![],
        determinism_check: true,
    }
}

#[test]
fn deterministic_runner_replays_identically_for_same_fixture() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();

    let first = runner.run_fixture(&fixture).expect("first run");
    let second = runner.run_fixture(&fixture).expect("second run");
    let verification = verify_replay(&first, &second);

    assert!(verification.matches);
    assert_eq!(first.output_digest, second.output_digest);
    assert_eq!(first.events, second.events);
}

#[test]
fn deterministic_runner_detects_seed_change_as_replay_mismatch() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();

    let expected = runner.run_fixture(&fixture).expect("expected run");

    let mut mutated = fixture.clone();
    mutated.seed = fixture.seed + 1;
    let actual = runner.run_fixture(&mutated).expect("actual run");

    let verification = verify_replay(&expected, &actual);
    assert!(!verification.matches);
    assert_eq!(verification.reason.as_deref(), Some("digest mismatch"));
}

#[test]
fn fixture_store_roundtrips_content_addressed_fixture() {
    let root = test_temp_dir("fixture-store");
    let store = FixtureStore::new(&root).expect("store");
    let fixture = sample_fixture();

    let path = store.save_fixture(&fixture).expect("save");
    assert!(path.exists());
    assert!(path.file_name().and_then(|n| n.to_str()).is_some());

    let loaded = store.load_fixture(&path).expect("load");
    assert_eq!(loaded, fixture);
}

#[test]
fn structured_log_assertions_match_and_reject_expected_patterns() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let positive = vec![
        LogExpectation {
            component: "scheduler".to_string(),
            event: "dispatch".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        },
        LogExpectation {
            component: "guardplane".to_string(),
            event: "challenge".to_string(),
            outcome: "error".to_string(),
            error_code: Some("FE-E2E-0007".to_string()),
        },
    ];
    assert!(assert_structured_logs(&run.events, &positive).is_ok());

    let negative = vec![LogExpectation {
        component: "guardplane".to_string(),
        event: "challenge".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-E2E-9999".to_string()),
    }];
    assert!(assert_structured_logs(&run.events, &negative).is_err());
}

#[test]
fn artifact_collector_writes_manifest_events_and_reports() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let root = test_temp_dir("artifacts");
    let collector = ArtifactCollector::new(&root).expect("collector");
    let artifacts = collector.collect(&run).expect("collect");

    assert!(artifacts.manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.evidence_linkage_path.exists());
    assert!(artifacts.report_json_path.exists());
    assert!(artifacts.report_markdown_path.exists());

    let manifest = fs::read_to_string(&artifacts.manifest_path).expect("manifest string");
    assert!(manifest.contains("fixture-hello"));
    assert!(manifest.contains("replay://"));

    let report_md = fs::read_to_string(&artifacts.report_markdown_path).expect("report md");
    assert!(report_md.contains("# E2E Run Report"));
    assert!(report_md.contains("fixture-hello"));

    let completeness = audit_collected_artifacts(&artifacts);
    assert!(completeness.complete);
    assert_eq!(completeness.event_count, run.events.len());
    assert_eq!(completeness.linkage_count, run.events.len());
}

#[test]
fn replay_input_validation_surfaces_deterministic_edge_codes() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let missing_snapshot_err = validate_replay_input(&run, None).expect_err("missing snapshot");
    assert_eq!(
        missing_snapshot_err.code,
        ReplayInputErrorCode::MissingModelSnapshot
    );

    let mut transcript_corrupted = run.clone();
    transcript_corrupted.random_transcript.pop();
    let transcript_err = validate_replay_input(
        &transcript_corrupted,
        Some("model://snapshot/fixture-hello/seed/42"),
    )
    .expect_err("corrupted transcript");
    assert_eq!(
        transcript_err.code,
        ReplayInputErrorCode::CorruptedTranscript
    );
}

#[test]
fn version_controlled_fixture_loads_and_runs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_path = root.join("tests/fixtures/minimal_fixture.json");
    let store = FixtureStore::new(root.join("tests/fixtures")).expect("fixture store");
    let fixture = store
        .load_fixture(&fixture_path)
        .expect("load fixture file");

    let runner = DeterministicRunner::default();
    let run = runner.run_fixture(&fixture).expect("run");

    assert_eq!(run.fixture_id, "minimal-fixture");
    assert_eq!(run.events.len(), fixture.steps.len());
    assert!(!run.output_digest.is_empty());
}

#[test]
fn invalid_fixture_is_rejected() {
    let runner = DeterministicRunner::default();
    let mut invalid = sample_fixture();
    invalid.fixture_id.clear();

    let error = runner
        .run_fixture(&invalid)
        .expect_err("invalid fixture should fail");
    assert_eq!(error.to_string(), "fixture_id is required");
}

#[test]
fn golden_store_detects_mismatch_and_emits_signed_update_artifact() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();

    let baseline_run = runner.run_fixture(&fixture).expect("baseline run");
    let mut changed_fixture = fixture.clone();
    changed_fixture.seed = fixture.seed + 1;
    let changed_run = runner.run_fixture(&changed_fixture).expect("changed run");

    let root = test_temp_dir("golden-store");
    let store = GoldenStore::new(root.join("golden")).expect("golden store");
    let baseline_path = store.write_baseline(&baseline_run).expect("write baseline");
    assert!(baseline_path.exists());

    assert!(store.verify_run(&baseline_run).is_ok());

    let mismatch = store
        .verify_run(&changed_run)
        .expect_err("changed digest should mismatch");
    assert!(matches!(
        mismatch,
        GoldenVerificationError::DigestMismatch { .. }
    ));

    let update_path = store
        .write_signed_update(
            &changed_run,
            "maintainer@franken.engine",
            "sig:deadbeef",
            "accept deterministic update for fixture evolution",
        )
        .expect("write update artifact");
    assert!(update_path.exists());

    let update_json = fs::read_to_string(update_path).expect("update artifact json");
    assert!(update_json.contains("maintainer@franken.engine"));
    assert!(update_json.contains("sig:deadbeef"));
}

#[test]
fn golden_store_reports_missing_baseline() {
    let runner = DeterministicRunner::default();
    let fixture = sample_fixture();
    let run = runner.run_fixture(&fixture).expect("run");

    let root = test_temp_dir("golden-missing");
    let store = GoldenStore::new(root.join("golden")).expect("golden store");
    let err = store
        .verify_run(&run)
        .expect_err("missing baseline should fail");

    assert!(matches!(
        err,
        GoldenVerificationError::MissingBaseline { .. }
    ));
}
