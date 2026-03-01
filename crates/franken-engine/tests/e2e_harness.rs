#[path = "../src/e2e_harness.rs"]
mod e2e_harness;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use e2e_harness::{
    ArtifactCollector, DeterministicRunner, FixtureStore, GoldenStore, GoldenVerificationError,
    LogExpectation, ReplayInputErrorCode, ScenarioClass, ScenarioMatrixEntry, ScenarioStep,
    TestFixture, assert_structured_logs, audit_collected_artifacts,
    rgc_advanced_scenario_matrix_registry, run_scenario_matrix,
    select_rgc_advanced_scenario_matrix, validate_replay_input, verify_replay,
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

fn non_error_fixture(fixture_id: &str, seed: u64, step_count: usize) -> TestFixture {
    let mut steps = Vec::with_capacity(step_count);
    for idx in 0..step_count {
        steps.push(ScenarioStep {
            component: "scheduler".to_string(),
            event: format!("tick-{idx}"),
            advance_micros: 10,
            metadata: BTreeMap::new(),
        });
    }
    TestFixture {
        fixture_id: fixture_id.to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed,
        virtual_time_start_micros: 5_000,
        policy_id: "policy-matrix".to_string(),
        steps,
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

#[test]
fn scenario_matrix_emits_evidence_packs_for_baseline_differential_chaos_and_cross_arch() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");

    let scenarios = rgc_advanced_scenario_matrix_registry();

    let execution = run_scenario_matrix(&runner, &collector, &scenarios).expect("matrix run");
    assert_eq!(execution.report.total_scenarios, 6);
    assert_eq!(execution.report.pass_scenarios, 5);
    assert_eq!(execution.report.fail_scenarios, 1);
    assert_eq!(
        execution.report.schema_version,
        "franken-engine.e2e-scenario-matrix.report.v2"
    );
    assert!(execution.summary_json_path.exists());
    assert!(execution.summary_markdown_path.exists());

    for pack in &execution.report.scenario_packs {
        assert!(!pack.scenario_id.is_empty());
        assert!(pack.replay_pointer.starts_with("replay://"));
        assert!(
            !pack.unit_anchor_ids.is_empty(),
            "unit anchors must be present for {}",
            pack.scenario_id
        );
        assert!(
            collector
                .root()
                .join(&pack.artifact_paths.manifest)
                .exists(),
            "manifest missing for {}",
            pack.scenario_id
        );
        assert!(
            collector.root().join(&pack.artifact_paths.events).exists(),
            "events missing for {}",
            pack.scenario_id
        );
        assert!(
            collector
                .root()
                .join(&pack.artifact_paths.evidence_linkage)
                .exists(),
            "evidence linkage missing for {}",
            pack.scenario_id
        );
    }

    let cross_arch = execution
        .report
        .scenario_packs
        .iter()
        .find(|pack| pack.scenario_class == ScenarioClass::CrossArch)
        .expect("cross-arch scenario");
    assert_eq!(
        cross_arch.target_arch.as_deref(),
        Some("aarch64-unknown-linux-gnu")
    );
    let differential = execution
        .report
        .scenario_packs
        .iter()
        .find(|pack| pack.scenario_class == ScenarioClass::Differential)
        .expect("differential scenario");
    assert_eq!(
        differential.baseline_scenario_id.as_deref(),
        Some("rgc-053-runtime-baseline-01")
    );
    let chaos = execution
        .report
        .scenario_packs
        .iter()
        .find(|pack| pack.scenario_class == ScenarioClass::Chaos)
        .expect("chaos scenario");
    assert_eq!(
        chaos.chaos_profile.as_deref(),
        Some("latency_spike_partial_failure")
    );

    let summary_json =
        fs::read_to_string(&execution.summary_json_path).expect("matrix summary json");
    assert!(summary_json.contains("rgc-053-runtime-baseline-01"));
    assert!(summary_json.contains("rgc-053-module-differential-01"));
    assert!(summary_json.contains("rgc-053-security-chaos-01"));
    assert!(summary_json.contains("rgc-053-runtime-stress-01"));
    assert!(summary_json.contains("rgc-053-security-fault-01"));
    assert!(summary_json.contains("rgc-053-runtime-cross-arch-01"));
    assert!(summary_json.contains("franken-engine.e2e-scenario-matrix.report.v2"));
}

#[test]
fn scenario_matrix_rejects_empty_input() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-empty");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let err = run_scenario_matrix(&runner, &collector, &[]).expect_err("must reject empty matrix");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn scenario_matrix_rejects_missing_unit_anchors() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-missing-unit-anchors");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let scenarios = vec![ScenarioMatrixEntry {
        scenario_id: "baseline-missing-unit".to_string(),
        scenario_class: ScenarioClass::Baseline,
        fixture: non_error_fixture("baseline-missing-unit", 710, 4),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: Vec::new(),
        target_arch: None,
        worker_pool: Some("pool-baseline".to_string()),
    }];

    let err = run_scenario_matrix(&runner, &collector, &scenarios)
        .expect_err("missing unit anchors should fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("requires at least one unit_anchor_id"),
        "unexpected error: {err}"
    );
}

#[test]
fn scenario_matrix_rejects_differential_without_baseline_id() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-differential-missing-baseline");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let scenarios = vec![ScenarioMatrixEntry {
        scenario_id: "differential-no-baseline".to_string(),
        scenario_class: ScenarioClass::Differential,
        fixture: non_error_fixture("differential-no-baseline", 711, 5),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: vec!["unit.e2e_harness.diff_missing_baseline".to_string()],
        target_arch: None,
        worker_pool: Some("pool-diff".to_string()),
    }];

    let err = run_scenario_matrix(&runner, &collector, &scenarios)
        .expect_err("differential scenarios require baseline_scenario_id");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string()
            .contains("(differential) requires baseline_scenario_id"),
        "unexpected error: {err}"
    );
}

#[test]
fn scenario_matrix_rejects_chaos_without_profile() {
    let runner = DeterministicRunner::default();
    let root = test_temp_dir("scenario-matrix-chaos-missing-profile");
    let collector = ArtifactCollector::new(root.join("artifacts")).expect("collector");
    let scenarios = vec![ScenarioMatrixEntry {
        scenario_id: "chaos-no-profile".to_string(),
        scenario_class: ScenarioClass::Chaos,
        fixture: non_error_fixture("chaos-no-profile", 712, 5),
        baseline_scenario_id: None,
        chaos_profile: None,
        unit_anchor_ids: vec!["unit.e2e_harness.chaos_missing_profile".to_string()],
        target_arch: None,
        worker_pool: Some("pool-chaos".to_string()),
    }];

    let err = run_scenario_matrix(&runner, &collector, &scenarios)
        .expect_err("chaos scenarios require chaos_profile");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("(chaos) requires chaos_profile"),
        "unexpected error: {err}"
    );
}

#[test]
fn advanced_scenario_matrix_selector_filters_classes_and_faults() {
    let all = select_rgc_advanced_scenario_matrix(&[], true);
    assert_eq!(all.len(), 6);

    let no_faults = select_rgc_advanced_scenario_matrix(&[], false);
    assert_eq!(no_faults.len(), 5);
    assert!(
        no_faults
            .iter()
            .all(|scenario| scenario.scenario_class != ScenarioClass::FaultInjection)
    );

    let chaos_only = select_rgc_advanced_scenario_matrix(&[ScenarioClass::Chaos], true);
    assert_eq!(chaos_only.len(), 1);
    assert_eq!(chaos_only[0].scenario_class, ScenarioClass::Chaos);
    assert_eq!(
        chaos_only[0].chaos_profile.as_deref(),
        Some("latency_spike_partial_failure")
    );
}
