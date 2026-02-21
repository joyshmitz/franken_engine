#[path = "../src/conformance_harness.rs"]
mod conformance_harness;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use conformance_harness::{
    ConformanceEvidenceCollector, ConformanceFailureClass, ConformanceReproMetadata,
    ConformanceRunner, ConformanceRunnerConfig, ConformanceWaiverSet, classify_conformance_delta,
    classify_failure_class,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn test_temp_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("franken-engine-conformance-repro-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn write_case_manifest(
    root: &Path,
    source: &str,
    observed_output: &str,
    expected_output: &str,
) -> PathBuf {
    let fixtures_dir = root.join("fixtures");
    let expected_dir = root.join("expected");
    fs::create_dir_all(&fixtures_dir).expect("create fixtures dir");
    fs::create_dir_all(&expected_dir).expect("create expected dir");

    let fixture_path = fixtures_dir.join("case.fixture.json");
    let expected_path = expected_dir.join("case.expected.txt");

    let fixture_json = json!({
        "donor_harness": "quickjs",
        "source": source,
        "observed_output": observed_output,
    });
    fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture_json).expect("serialize fixture"),
    )
    .expect("write fixture");
    fs::write(&expected_path, expected_output).expect("write expected output");

    let fixture_hash = sha256_hex(&fs::read(&fixture_path).expect("read fixture bytes"));
    let expected_hash = sha256_hex(&fs::read(&expected_path).expect("read expected bytes"));

    let manifest = json!({
        "schema_version": "franken-engine.conformance-assets.v1",
        "generated_at_utc": "2026-02-20T00:00:00Z",
        "assets": [
            {
                "asset_id": "asset-case",
                "source_donor": "quickjs",
                "semantic_domain": "conformance/min-repro",
                "normative_reference": "tc39/test262",
                "fixture_path": "fixtures/case.fixture.json",
                "fixture_hash": fixture_hash,
                "expected_output_path": "expected/case.expected.txt",
                "expected_output_hash": expected_hash,
                "import_date": "2026-02-20"
            }
        ]
    });

    let manifest_path = root.join("conformance_assets.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
    manifest_path
}

fn runner_with_metadata() -> ConformanceRunner {
    let mut version_combination = BTreeMap::new();
    version_combination.insert("franken_engine".to_string(), "0.1.0-test".to_string());
    version_combination.insert("franken_node".to_string(), "0.9.0-test".to_string());

    ConformanceRunner {
        config: ConformanceRunnerConfig {
            seed: 41,
            run_date: "2026-02-20".to_string(),
            repro_metadata: ConformanceReproMetadata {
                version_combination,
                first_seen_commit: "abc1234".to_string(),
                regression_commit: Some("def5678".to_string()),
                ci_run_id: Some("ci-run-77".to_string()),
                issue_tracker_project: "beads".to_string(),
                issue_tracking_bead: Some("bd-352c".to_string()),
            },
            ..ConformanceRunnerConfig::default()
        },
        ..ConformanceRunner::default()
    }
}

#[test]
fn repro_artifact_round_trip_contains_required_metadata() {
    let temp = test_temp_dir("roundtrip");
    let manifest = write_case_manifest(
        &temp,
        "let a = 1;\nlet b = 2;\nprint(a + b);",
        "value 4\nprops:a,b",
        "value 3\nprops:a,b",
    );

    let run = runner_with_metadata()
        .run(&manifest, &ConformanceWaiverSet::default())
        .expect("run should succeed");

    assert_eq!(run.summary.failed, 1);
    assert_eq!(run.minimized_repros.len(), 1);

    let artifact = run.minimized_repros.first().expect("artifact present");
    assert_eq!(artifact.failure_id.len(), 19);
    assert_eq!(artifact.issue_tracker.issue_id, "bd-352c");
    assert_eq!(artifact.first_seen_commit, "abc1234");
    assert_eq!(artifact.regression_commit.as_deref(), Some("def5678"));
    assert_eq!(artifact.linked_run.ci_run_id.as_deref(), Some("ci-run-77"));
    assert!(
        artifact
            .replay
            .replay_command
            .starts_with("franken-conformance replay")
    );
    artifact.verify_replay().expect("replay verification");

    let round_trip: conformance_harness::ConformanceMinimizedReproArtifact =
        serde_json::from_slice(&serde_json::to_vec(artifact).expect("serialize artifact"))
            .expect("deserialize artifact");
    assert_eq!(round_trip, *artifact);
}

#[test]
fn delta_classification_is_machine_readable_for_schema_error_and_timing_changes() {
    let schema_delta = classify_conformance_delta("props:a,b", "props:a,b,c");
    assert!(
        schema_delta.iter().any(|entry| {
            entry.kind == conformance_harness::ConformanceDeltaKind::SchemaFieldAdded
                && entry.field.as_deref() == Some("c")
        }),
        "expected schema field-added classification"
    );
    assert_eq!(
        classify_failure_class(&schema_delta),
        ConformanceFailureClass::Breaking
    );

    let error_delta = classify_conformance_delta("TypeError: bad arg", "ReferenceError: bad arg");
    assert!(
        error_delta
            .iter()
            .any(|entry| entry.kind == conformance_harness::ConformanceDeltaKind::ErrorFormatChange),
        "expected error format classification"
    );
    assert_eq!(
        classify_failure_class(&error_delta),
        ConformanceFailureClass::Observability
    );

    let timing_delta = classify_conformance_delta("latency 10", "latency 12");
    assert!(
        timing_delta
            .iter()
            .any(|entry| entry.kind == conformance_harness::ConformanceDeltaKind::TimingChange),
        "expected timing classification"
    );
    assert_eq!(
        classify_failure_class(&timing_delta),
        ConformanceFailureClass::Performance
    );
}

#[test]
fn minimization_preserves_failure_class_and_replay_contract() {
    let temp = test_temp_dir("minimize");
    let manifest = write_case_manifest(
        &temp,
        "let alpha = 1;\nlet beta = 2;\nlet gamma = 3;\nprint(alpha + beta + gamma);",
        "prefix\nprops:a,b,d\nsuffix",
        "prefix\nprops:a,b,c\nsuffix",
    );

    let run = runner_with_metadata()
        .run(&manifest, &ConformanceWaiverSet::default())
        .expect("run should succeed");

    let artifact = run.minimized_repros.first().expect("artifact present");
    assert!(artifact.minimization.preserved_failure_class);
    assert!(
        artifact.minimization.minimized_expected_lines
            <= artifact.minimization.original_expected_lines
    );
    assert!(
        artifact.minimization.minimized_actual_lines <= artifact.minimization.original_actual_lines
    );
    assert!(
        artifact.minimization.minimized_source_lines <= artifact.minimization.original_source_lines
    );
    artifact.verify_replay().expect("replay verification");
}

#[test]
fn collector_writes_repro_index_and_structured_events() {
    let temp = test_temp_dir("collector");
    let manifest = write_case_manifest(
        &temp,
        "x = 1;\ny = 2;\nprint(x + y);",
        "TypeError: mismatch\nprops:q,p",
        "ReferenceError: mismatch\nprops:q,p",
    );

    let run = runner_with_metadata()
        .run(&manifest, &ConformanceWaiverSet::default())
        .expect("run should succeed");
    let artifact = run
        .minimized_repros
        .first()
        .expect("artifact present")
        .clone();

    let collector = ConformanceEvidenceCollector::new(test_temp_dir("collector-artifacts"))
        .expect("collector init");
    let collected = collector.collect(&run).expect("collect artifacts");

    assert!(collected.run_manifest_path.exists());
    assert!(collected.conformance_evidence_path.exists());
    assert_eq!(collected.minimized_repro_paths.len(), 1);
    let index_path = collected
        .minimized_repro_index_path
        .as_ref()
        .expect("index path present");
    let events_path = collected
        .minimized_repro_events_path
        .as_ref()
        .expect("events path present");
    assert!(index_path.exists());
    assert!(events_path.exists());

    let index: Value = serde_json::from_str(&fs::read_to_string(index_path).expect("read index"))
        .expect("parse index json");
    assert_eq!(index["run_id"], run.run_id);
    assert_eq!(index["entries"][0]["failure_id"], artifact.failure_id);
    assert_eq!(
        index["entries"][0]["issue_tracker_id"],
        artifact.issue_tracker.issue_id
    );

    let first_event = fs::read_to_string(events_path)
        .expect("read events")
        .lines()
        .next()
        .expect("first event line")
        .to_string();
    let event: Value = serde_json::from_str(&first_event).expect("parse event line");
    assert!(event.get("trace_id").is_some());
    assert!(event.get("decision_id").is_some());
    assert!(event.get("policy_id").is_some());
    assert_eq!(event["component"], "conformance_repro_collector");
    assert_eq!(event["event"], "minimized_repro_persisted");
    assert_eq!(event["outcome"], "pass");
}

#[test]
fn minimization_property_sweep_keeps_replayable_failure_class() {
    let cases = [
        (
            "a();\nb();\nc();",
            "props:a,b",
            "props:a,b,c",
            ConformanceFailureClass::Breaking,
        ),
        (
            "a();\nb();\nc();",
            "TypeError: invalid",
            "ReferenceError: invalid",
            ConformanceFailureClass::Observability,
        ),
        (
            "a();\nb();\nc();",
            "latency 10",
            "latency 11",
            ConformanceFailureClass::Performance,
        ),
        (
            "a();\nb();\nc();",
            "result ok",
            "result changed",
            ConformanceFailureClass::Behavioral,
        ),
    ];

    for (idx, (source, expected, observed, expected_class)) in cases.iter().enumerate() {
        let temp = test_temp_dir(&format!("property-{idx}"));
        let manifest = write_case_manifest(&temp, source, observed, expected);

        let run = runner_with_metadata()
            .run(&manifest, &ConformanceWaiverSet::default())
            .expect("run should succeed");
        let artifact = run.minimized_repros.first().expect("artifact present");

        assert_eq!(artifact.failure_class, *expected_class);
        assert!(artifact.minimization.preserved_failure_class);
        assert_eq!(
            artifact.failure_class,
            classify_failure_class(&artifact.delta_classification)
        );
        artifact.verify_replay().expect("replay verification");
    }
}
