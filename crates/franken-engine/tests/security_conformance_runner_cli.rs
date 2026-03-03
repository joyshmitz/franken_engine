#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let unique = format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct CorpusFixture {
    _guard: TestTempDir,
    labels_root: PathBuf,
    output_root: PathBuf,
    observations_jsonl: PathBuf,
    policy_snapshot_hash: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn write_file(path: &Path, content: &str) {
    let parent = path.parent().expect("file has parent");
    fs::create_dir_all(parent).expect("create file parent");
    fs::write(path, content).expect("write file");
}

fn build_fixture() -> CorpusFixture {
    let guard = TestTempDir::new("security-conformance-runner-cli");
    let labels_root = guard.path.join("labels");
    let output_root = guard.path.join("artifacts");
    let observations_jsonl = guard.path.join("observations.jsonl");
    let policy_snapshot_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let benign_rel = PathBuf::from("benign/echo_read/workload_label.toml");
    let malicious_rel = PathBuf::from("malicious/credential_exfil/workload_label.toml");
    let benign_path = labels_root.join(&benign_rel);
    let malicious_path = labels_root.join(&malicious_rel);

    let benign_label = r#"workload_id = "benign-echo-read"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
semantic_domain = "filesystem/read"
"#;
    let malicious_label = r#"workload_id = "malicious-credential-exfil"
corpus = "malicious"
attack_taxonomy = "exfil"
expected_outcome = "contain"
expected_detection_latency_bound_ms = 25
hostcall_sequence_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
semantic_domain = "network/exfiltration"
"#;

    write_file(&benign_path, benign_label);
    write_file(&malicious_path, malicious_label);

    let benign_hash = sha256_hex(benign_label.as_bytes());
    let malicious_hash = sha256_hex(malicious_label.as_bytes());
    let manifest = format!(
        r#"schema_version = "franken-engine.security-conformance-corpus-manifest.v1"
corpus_version = "v1"
generated_at_utc = "2026-03-02T00:00:00Z"

[[entries]]
workload_id = "benign-echo-read"
corpus = "benign"
label_path = "{benign_rel}"
label_sha256 = "{benign_hash}"

[[entries]]
workload_id = "malicious-credential-exfil"
corpus = "malicious"
label_path = "{malicious_rel}"
label_sha256 = "{malicious_hash}"
"#,
        benign_rel = benign_rel.display(),
        benign_hash = benign_hash,
        malicious_rel = malicious_rel.display(),
        malicious_hash = malicious_hash,
    );
    write_file(&labels_root.join("corpus_manifest.toml"), &manifest);

    let observations = [
        json!({
            "workload_id": "benign-echo-read",
            "actual_outcome": "allow",
            "detection_latency_us": 4000,
            "sentinel_posterior": 0.02,
            "policy_action": "allow",
            "containment_action": "none",
            "error_code": Value::Null
        }),
        json!({
            "workload_id": "malicious-credential-exfil",
            "actual_outcome": "contain",
            "detection_latency_us": 15000,
            "sentinel_posterior": 0.99,
            "policy_action": "contain",
            "containment_action": "sandbox",
            "error_code": Value::Null
        }),
    ];
    let mut observations_text = String::new();
    for observation in observations {
        observations_text.push_str(
            &serde_json::to_string(&observation).expect("serialize security observation"),
        );
        observations_text.push('\n');
    }
    write_file(&observations_jsonl, &observations_text);

    CorpusFixture {
        _guard: guard,
        labels_root,
        output_root,
        observations_jsonl,
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
    }
}

fn runner_command(fixture: &CorpusFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_franken_security_conformance_runner"));
    command
        .arg("--labels-root")
        .arg(&fixture.labels_root)
        .arg("--output-root")
        .arg(&fixture.output_root)
        .arg("--observations-jsonl")
        .arg(&fixture.observations_jsonl)
        .arg("--policy-snapshot-hash")
        .arg(&fixture.policy_snapshot_hash);
    command
}

fn parse_evidence_path(stdout: &str) -> PathBuf {
    let evidence_line = stdout
        .lines()
        .find(|line| line.starts_with("security evidence="))
        .expect("runner should print security evidence path");
    PathBuf::from(
        evidence_line
            .trim_start_matches("security evidence=")
            .trim(),
    )
}

fn normalize_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .expect("current dir")
            .join(path)
            .to_path_buf()
    }
}

#[test]
fn runner_writes_summary_and_workload_evidence_lines() {
    let fixture = build_fixture();
    let output = runner_command(&fixture)
        .arg("--allow-small-corpus")
        .output()
        .expect("run security conformance runner");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let evidence_path = normalize_path(parse_evidence_path(&stdout));
    assert!(
        evidence_path.exists(),
        "missing evidence: {}",
        evidence_path.display()
    );

    let evidence_text = fs::read_to_string(&evidence_path).expect("read evidence");
    let evidence_lines = evidence_text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse JSONL line"))
        .collect::<Vec<_>>();
    assert_eq!(
        evidence_lines.len(),
        3,
        "expect 1 summary + 2 workload lines"
    );

    let summary = &evidence_lines[0];
    assert_eq!(
        summary["schema_version"],
        "franken-engine.security-conformance-evidence.v1"
    );
    assert_eq!(summary["component"], "security_conformance_runner");
    assert_eq!(summary["event"], "summary");
    // With a tiny corpus (enabled only by --allow-small-corpus), CI bounds are
    // intentionally strict and the aggregate gate should fail closed.
    assert_eq!(summary["outcome"], "fail");
    assert_eq!(
        summary["policy_snapshot_hash"],
        fixture.policy_snapshot_hash
    );
    assert_eq!(summary["error_code"], "FE-SECURITY-CONFORMANCE-GATE");
    assert!(
        summary["gate_failure_reasons"]
            .as_array()
            .expect("summary gate_failure_reasons array")
            .iter()
            .any(|reason| reason.as_str().unwrap_or_default().contains("TPR")),
        "expected TPR-related gate failure in tiny-corpus run: {:?}",
        summary["gate_failure_reasons"]
    );
    assert!(
        summary["trace_id"]
            .as_str()
            .expect("summary trace_id")
            .starts_with("trace-")
    );

    let workload_lines = &evidence_lines[1..];
    for workload in workload_lines {
        assert_eq!(workload["event"], "workload_result");
        assert_eq!(workload["component"], "security_conformance_runner");
        assert_eq!(workload["outcome"], "pass");
        assert!(
            workload["trace_id"]
                .as_str()
                .expect("workload trace_id")
                .starts_with("trace-")
        );
    }
}

#[test]
fn runner_fails_without_allow_small_corpus_flag() {
    let fixture = build_fixture();
    let output = runner_command(&fixture)
        .output()
        .expect("run security conformance runner");
    assert!(
        !output.status.success(),
        "runner unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("security corpus size below release thresholds"),
        "stderr missing threshold failure message:\n{stderr}"
    );
}

#[test]
fn runner_fails_on_manifest_hash_tamper() {
    let fixture = build_fixture();
    let tampered_manifest = r#"schema_version = "franken-engine.security-conformance-corpus-manifest.v1"
corpus_version = "v1"
generated_at_utc = "2026-03-02T00:00:00Z"

[[entries]]
workload_id = "benign-echo-read"
corpus = "benign"
label_path = "benign/echo_read/workload_label.toml"
label_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

[[entries]]
workload_id = "malicious-credential-exfil"
corpus = "malicious"
label_path = "malicious/credential_exfil/workload_label.toml"
label_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
"#;
    write_file(
        &fixture.labels_root.join("corpus_manifest.toml"),
        tampered_manifest,
    );

    let output = runner_command(&fixture)
        .arg("--allow-small-corpus")
        .output()
        .expect("run security conformance runner");
    assert!(
        !output.status.success(),
        "runner unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("ManifestLabelHashMismatch")
            || stderr.contains("corpus manifest hash mismatch"),
        "stderr missing manifest mismatch:\n{stderr}"
    );
}
