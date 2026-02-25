#[path = "../src/e2e_harness.rs"]
mod e2e_harness;

use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use e2e_harness::{
    ArtifactCollector, DeterministicRunner, EvidenceLinkageRecord, FixtureStore,
    ReplayEnvironmentFingerprint, ReplayInputErrorCode, audit_collected_artifacts,
    compare_counterfactual, diagnose_cross_machine_replay, evaluate_replay_performance,
    validate_replay_input, verify_replay,
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

fn replay_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/replay_counterfactual_fixture.json")
}

#[test]
fn baseline_replay_and_counterfactual_delta_are_reported() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");

    let baseline = runner.run_fixture(&fixture).expect("baseline run");
    let replay = runner.run_fixture(&fixture).expect("replay run");
    let replay_verification = verify_replay(&baseline, &replay);
    assert!(replay_verification.matches);

    let mut counterfactual = fixture.clone();
    counterfactual.policy_id = "policy-counterfactual".to_string();
    counterfactual.steps[1]
        .metadata
        .insert("outcome".to_string(), "challenge".to_string());
    let counterfactual_run = runner
        .run_fixture(&counterfactual)
        .expect("counterfactual run");

    let delta = compare_counterfactual(&baseline, &counterfactual_run);
    assert!(delta.digest_changed);
    assert_eq!(delta.diverged_at_sequence, Some(0));
    assert!(delta.changed_events >= 1);
    assert!(delta.changed_outcomes >= 1);
    assert!(!delta.transcript_changed);
    assert!(delta.transcript_diverged_at_index.is_none());
    assert!(!delta.divergence_samples.is_empty());
    assert_eq!(delta.divergence_samples[0].sequence, 0);
}

#[test]
fn replay_artifacts_include_replay_pointer_and_reports() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");
    let baseline = runner.run_fixture(&fixture).expect("baseline run");

    let collector = ArtifactCollector::new(test_temp_dir("replay-artifacts")).expect("collector");
    let artifacts = collector.collect(&baseline).expect("collect artifacts");

    let manifest_json = fs::read_to_string(&artifacts.manifest_path).expect("manifest json");
    let report_json = fs::read_to_string(&artifacts.report_json_path).expect("report json");
    let events_jsonl = fs::read_to_string(&artifacts.events_path).expect("events jsonl");
    let evidence_linkage_json =
        fs::read_to_string(&artifacts.evidence_linkage_path).expect("evidence linkage json");

    assert!(manifest_json.contains("\"replay_pointer\":\"replay://"));
    assert!(manifest_json.contains("\"model_snapshot_pointer\":\"model://snapshot/"));
    assert!(manifest_json.contains("\"artifact_schema_version\":1"));
    assert!(manifest_json.contains("\"environment_fingerprint\""));
    assert!(manifest_json.contains("\"pointer_width_bits\""));
    assert!(report_json.contains("\"output_digest\""));
    assert!(!events_jsonl.trim().is_empty());
    assert!(evidence_linkage_json.contains("\"evidence_hash\""));

    let evidence_linkage: Vec<EvidenceLinkageRecord> =
        serde_json::from_str(&evidence_linkage_json).expect("parse evidence linkage");
    assert_eq!(evidence_linkage.len(), baseline.events.len());
    for (index, (record, event)) in evidence_linkage.iter().zip(&baseline.events).enumerate() {
        assert_eq!(record.trace_id, event.trace_id);
        assert_eq!(record.decision_id, event.decision_id);
        assert_eq!(record.policy_id, event.policy_id);
        assert_eq!(record.event_sequence, index as u64);
        assert!(!record.evidence_hash.trim().is_empty());
    }

    let completeness = audit_collected_artifacts(&artifacts);
    assert!(completeness.complete);
    assert_eq!(completeness.event_count, baseline.events.len());
    assert_eq!(completeness.linkage_count, baseline.events.len());
}

#[test]
fn schema_version_mismatch_is_deterministic_error() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let mut fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");

    fixture.fixture_version += 1;
    let err = runner
        .run_fixture(&fixture)
        .expect_err("unsupported fixture version should fail");
    assert!(
        err.to_string()
            .starts_with("unsupported fixture version: expected")
    );
}

#[test]
fn schema_legacy_fixture_v0_migrates_and_runs() {
    let fixture_root = test_temp_dir("legacy-fixture");
    let legacy_fixture_path = fixture_root.join("legacy_fixture_v0.json");
    fs::write(
        &legacy_fixture_path,
        r#"{
  "fixture_id": "legacy-replay-fixture",
  "fixture_version": 0,
  "seed": 123,
  "virtual_time_start_micros": 1000,
  "policy_id": "policy-legacy",
  "steps": [
    {"component": "scheduler", "event": "dispatch", "advance_micros": 10},
    {"component": "guardplane", "event": "challenge", "advance_micros": 20}
  ]
}"#,
    )
    .expect("write legacy fixture");

    let fixture_store = FixtureStore::new(&fixture_root).expect("fixture store");
    let fixture = fixture_store
        .load_fixture(&legacy_fixture_path)
        .expect("legacy fixture should migrate");
    assert_eq!(fixture.fixture_version, 1);
    assert!(fixture.determinism_check);

    let runner = DeterministicRunner::default();
    let baseline = runner.run_fixture(&fixture).expect("baseline run");
    let replay = runner.run_fixture(&fixture).expect("replay run");
    let replay_verification = verify_replay(&baseline, &replay);
    assert!(replay_verification.matches);

    fs::remove_dir_all(fixture_root).ok();
}

#[test]
fn transcript_fault_injection_reports_diagnostic_index() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");

    let baseline = runner.run_fixture(&fixture).expect("baseline run");
    let mut faulted = baseline.clone();
    faulted.random_transcript[0] = faulted.random_transcript[0].wrapping_add(1);

    let replay_verification = verify_replay(&baseline, &faulted);
    assert!(!replay_verification.matches);
    assert_eq!(
        replay_verification.reason.as_deref(),
        Some("random transcript mismatch")
    );
    assert_eq!(replay_verification.transcript_mismatch_index, Some(0));
    assert_eq!(
        replay_verification.expected_transcript_len,
        baseline.events.len()
    );
    assert_eq!(
        replay_verification.actual_transcript_len,
        baseline.events.len()
    );
}

#[test]
fn replay_input_validation_detects_missing_model_snapshot() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");

    let baseline = runner.run_fixture(&fixture).expect("baseline run");
    let err = validate_replay_input(&baseline, None).expect_err("missing snapshot pointer");
    assert_eq!(err.code, ReplayInputErrorCode::MissingModelSnapshot);
}

#[test]
fn replay_input_validation_detects_partial_trace_gap() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");

    let mut baseline = runner.run_fixture(&fixture).expect("baseline run");
    baseline.events[0].sequence = 7;
    let err = validate_replay_input(&baseline, Some("model://snapshot/replay-fixture/seed/77"))
        .expect_err("partial trace should fail");
    assert_eq!(err.code, ReplayInputErrorCode::PartialTrace);
}

#[test]
fn replay_input_validation_detects_corrupted_transcript() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");

    let mut baseline = runner.run_fixture(&fixture).expect("baseline run");
    baseline.random_transcript.pop();
    let err = validate_replay_input(&baseline, Some("model://snapshot/replay-fixture/seed/77"))
        .expect_err("corrupted transcript should fail");
    assert_eq!(err.code, ReplayInputErrorCode::CorruptedTranscript);
}

#[test]
fn replay_is_faster_than_virtual_time_budget() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let mut fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");
    for step in &mut fixture.steps {
        step.advance_micros = 500_000;
    }

    let start = Instant::now();
    let run = runner.run_fixture(&fixture).expect("replay run");
    let wall_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let perf = evaluate_replay_performance(&run, wall_micros);

    assert!(perf.virtual_duration_micros > 0);
    assert!(perf.faster_than_realtime);
    assert!(perf.speedup_milli >= 1000);
}

#[test]
fn cross_machine_replay_diagnosis_surfaces_environment_deltas() {
    let runner = DeterministicRunner::default();
    let fixture_store =
        FixtureStore::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
            .expect("fixture store");
    let fixture = fixture_store
        .load_fixture(replay_fixture_path())
        .expect("load replay fixture");

    let baseline = runner.run_fixture(&fixture).expect("baseline run");
    let replay = runner.run_fixture(&fixture).expect("replay run");

    let expected_env = ReplayEnvironmentFingerprint {
        os: "linux".to_string(),
        architecture: "x86_64".to_string(),
        family: "unix".to_string(),
        pointer_width_bits: 64,
        endian: "little".to_string(),
    };
    let actual_env = ReplayEnvironmentFingerprint {
        os: "linux".to_string(),
        architecture: "aarch64".to_string(),
        family: "unix".to_string(),
        pointer_width_bits: 64,
        endian: "little".to_string(),
    };

    let diagnosis = diagnose_cross_machine_replay(&baseline, &replay, &expected_env, &actual_env);
    assert!(diagnosis.cross_machine_match);
    assert_eq!(diagnosis.environment_mismatches, vec!["architecture"]);
    assert_eq!(
        diagnosis.diagnosis.as_deref(),
        Some("replay matched across environment deltas: architecture")
    );
}
