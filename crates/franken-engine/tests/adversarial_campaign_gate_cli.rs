use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/adversarial_campaign_gate_input_v1.json")
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{now}.json", std::process::id()))
}

#[test]
fn suppression_gate_cli_passes_with_fixture_input_and_writes_report() {
    let out_path = unique_temp_path("franken-adv-gate-pass");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .arg("--input")
        .arg(fixture_path())
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("should execute suppression gate CLI");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json report");
    assert_eq!(
        stdout_json["schema_version"],
        "franken-engine.adversarial-campaign-gate-report.v1"
    );
    assert_eq!(
        stdout_json["result"]["passed"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        stdout_json["result"]["release_candidate_id"],
        "rc-adversarial-gate-v1"
    );

    let report_bytes = fs::read(&out_path).expect("report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report file should be valid json");
    assert_eq!(
        report_json["result"]["passed"],
        serde_json::Value::Bool(true)
    );

    let _ = fs::remove_file(out_path);
}

#[test]
fn suppression_gate_cli_returns_exit_two_when_gate_fails() {
    let mut input_json: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture_path()).expect("fixture should be readable"))
            .expect("fixture JSON should parse");

    input_json["continuous_run"] = serde_json::Value::Bool(false);
    input_json["trend_points"] = serde_json::json!([
      {
        "release_candidate_id": "rc-only-one",
        "timestamp_ns": 1700000000000000000u64,
        "samples_evaluated": 1500u64
      }
    ]);

    let failing_input_path = unique_temp_path("franken-adv-gate-fail-input");
    fs::write(
        &failing_input_path,
        serde_json::to_vec_pretty(&input_json).expect("failing input should encode"),
    )
    .expect("failing input should be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .arg("--input")
        .arg(&failing_input_path)
        .output()
        .expect("should execute suppression gate CLI");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected gate-failure exit code, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json report");
    assert_eq!(
        stdout_json["result"]["passed"],
        serde_json::Value::Bool(false)
    );
    assert!(
        stdout_json["result"]["failures"]
            .as_array()
            .is_some_and(|failures| !failures.is_empty())
    );

    let _ = fs::remove_file(failing_input_path);
}
