#[path = "../src/e2e_harness.rs"]
mod e2e_harness;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use e2e_harness::{
    ArtifactCollector, DeterministicRunner, FixtureStore, ReplayEnvironmentFingerprint,
    compare_counterfactual, diagnose_cross_machine_replay, verify_replay,
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

    assert!(manifest_json.contains("\"replay_pointer\":\"replay://"));
    assert!(manifest_json.contains("\"environment_fingerprint\""));
    assert!(manifest_json.contains("\"pointer_width_bits\""));
    assert!(report_json.contains("\"output_digest\""));
    assert!(!events_jsonl.trim().is_empty());
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
