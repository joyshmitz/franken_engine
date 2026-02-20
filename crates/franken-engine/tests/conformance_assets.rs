#[path = "../src/conformance_harness.rs"]
mod conformance_harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use conformance_harness::{
    ConformanceEvidenceCollector, ConformanceManifestError, ConformanceRunner,
    ConformanceRunnerConfig, ConformanceWaiverSet, DonorHarnessAdapter, DonorHarnessApi,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn test_temp_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-engine-conformance-{suffix}-{nanos}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn sample_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/transplanted/conformance_assets.json")
}

fn sample_waiver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance_waivers.toml")
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

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst tree");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let metadata = entry.metadata().expect("metadata");
        if metadata.is_dir() {
            copy_tree(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("copy file");
        }
    }
}

fn update_expected_hash_for_asset(manifest_path: &Path, asset_id: &str, expected_file: &Path) {
    let mut manifest: Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("manifest read"))
            .expect("manifest parse");
    let hash = sha256_hex(&fs::read(expected_file).expect("expected bytes"));

    let assets = manifest["assets"]
        .as_array_mut()
        .expect("assets should be an array");
    for asset in assets {
        if asset["asset_id"] == asset_id {
            asset["expected_output_hash"] = Value::String(hash.clone());
        }
    }

    let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest serialize");
    fs::write(manifest_path, bytes).expect("manifest write");
}

#[test]
fn transplanted_manifest_runs_and_emits_conformance_evidence_artifact() {
    let runner = ConformanceRunner::default();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");

    let run = runner
        .run(sample_manifest_path(), &waivers)
        .expect("conformance run");

    assert_eq!(run.summary.total_assets, 2);
    assert_eq!(run.summary.failed, 0);
    assert_eq!(run.summary.errored, 0);
    assert!(run.logs.iter().all(|log| log.outcome == "pass"));
    run.enforce_ci_gate().expect("ci gate pass");

    let collector =
        ConformanceEvidenceCollector::new(test_temp_dir("evidence")).expect("collector");
    let artifacts = collector.collect(&run).expect("collect artifacts");

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.conformance_evidence_path.exists());

    let evidence = fs::read_to_string(artifacts.conformance_evidence_path).expect("evidence read");
    let first_line = evidence.lines().next().expect("summary line");
    assert!(first_line.contains("asset_manifest_hash"));
    assert!(first_line.contains("env_fingerprint"));
}

#[test]
fn harness_adapter_maps_donor_conventions_without_runtime_shims() {
    let adapter = DonorHarnessAdapter;
    let source = "$262.createRealm(); $DONE(print('ok'));";
    let adapted = adapter.adapt_source(source);

    assert!(adapted.contains("__franken_create_realm()"));
    assert!(adapted.contains("__franken_done"));
    assert!(adapted.contains("franken_print("));
}

#[test]
fn manifest_integrity_meta_test_detects_tampered_fixture_hash() {
    let source_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/transplanted");
    let temp_root = test_temp_dir("tamper").join("transplanted");
    copy_tree(&source_root, &temp_root);

    let fixture_path = temp_root.join("fixtures/promise_resolution.fixture.json");
    fs::write(
        &fixture_path,
        "{\"donor_harness\":\"quickjs\",\"source\":\"$DONE()\",\"observed_output\":\"tampered\"}",
    )
    .expect("tamper fixture");

    let manifest_path = temp_root.join("conformance_assets.json");
    let err = ConformanceRunner::default()
        .run(&manifest_path, &ConformanceWaiverSet::default())
        .expect_err("tampered fixture hash should fail");

    match err {
        conformance_harness::ConformanceRunError::Manifest(
            ConformanceManifestError::FixtureHashMismatch { asset_id, .. },
        ) => {
            assert_eq!(asset_id, "asset-promise-resolution");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn waiver_enforcement_meta_test_blocks_unwaived_and_accepts_waived_failures() {
    let source_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/transplanted");
    let temp_root = test_temp_dir("waivers").join("transplanted");
    copy_tree(&source_root, &temp_root);

    let manifest_path = temp_root.join("conformance_assets.json");
    let expected_path = temp_root.join("expected/proxy_trap_ordering.expected.txt");

    // Force one deterministic mismatch, then refresh manifest hash so integrity checks still pass.
    fs::write(&expected_path, "mismatch output\nprops:q,p").expect("rewrite expected output");
    update_expected_hash_for_asset(&manifest_path, "asset-proxy-trap-ordering", &expected_path);

    let runner = ConformanceRunner::default();
    let run_unwaived = runner
        .run(&manifest_path, &ConformanceWaiverSet::default())
        .expect("unwaived run");
    assert_eq!(run_unwaived.summary.failed, 1);
    assert_eq!(run_unwaived.summary.waived, 0);
    assert!(run_unwaived.enforce_ci_gate().is_err());

    let waiver_path = temp_root.join("conformance_waivers.toml");
    fs::write(
        &waiver_path,
        r#"[[waiver]]
asset_id = "asset-proxy-trap-ordering"
reason_code = "harness_gap"
tracking_bead = "bd-d93"
expiry_date = "2027-12-31"
"#,
    )
    .expect("waiver write");
    let waivers = ConformanceWaiverSet::load_toml(&waiver_path).expect("waiver parse");

    let run_waived = runner.run(&manifest_path, &waivers).expect("waived run");
    assert_eq!(run_waived.summary.failed, 0);
    assert_eq!(run_waived.summary.waived, 1);
    run_waived
        .enforce_ci_gate()
        .expect("waived should pass gate");
}

#[test]
fn determinism_meta_test_same_seed_matches_different_seed_changes_output() {
    let manifest_path = sample_manifest_path();
    let waivers = ConformanceWaiverSet::load_toml(sample_waiver_path()).expect("waiver load");

    let runner_a = ConformanceRunner {
        config: ConformanceRunnerConfig {
            seed: 19,
            run_date: "2026-02-20".to_string(),
            ..ConformanceRunnerConfig::default()
        },
        ..ConformanceRunner::default()
    };
    let runner_b = runner_a.clone();

    let run_a = runner_a.run(&manifest_path, &waivers).expect("run_a");
    let run_b = runner_b.run(&manifest_path, &waivers).expect("run_b");
    assert_eq!(run_a.logs, run_b.logs);
    assert_eq!(run_a.summary, run_b.summary);

    let runner_c = ConformanceRunner {
        config: ConformanceRunnerConfig {
            seed: 20,
            run_date: "2026-02-20".to_string(),
            ..ConformanceRunnerConfig::default()
        },
        ..ConformanceRunner::default()
    };

    let run_c = runner_c.run(&manifest_path, &waivers).expect("run_c");
    assert_ne!(run_a.logs, run_c.logs);
}
