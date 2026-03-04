#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::deterministic_replay::{NondeterminismSource, NondeterminismTrace};

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}.{}", std::process::id(), nonce, ext));
    path
}

fn write_source(path: &Path, source: &str) {
    fs::write(path, source).expect("source fixture should write");
}

fn parse_stdout_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout should contain valid json")
}

#[test]
fn frankenctl_help_lists_supported_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("--help")
        .output()
        .expect("help command should execute");

    assert!(
        output.status.success(),
        "help failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("frankenctl usage"));
    assert!(stdout.contains("frankenctl compile"));
    assert!(stdout.contains("frankenctl run"));
    assert!(stdout.contains("frankenctl verify"));
    assert!(stdout.contains("frankenctl benchmark run"));
    assert!(stdout.contains("frankenctl replay run"));
}

#[test]
fn frankenctl_compile_then_verify_compile_artifact_round_trip() {
    let source_path = temp_path("frankenctl_compile_source", "js");
    let artifact_path = temp_path("frankenctl_compile_artifact", "json");
    write_source(&source_path, "const answer = 40 + 2;\n");

    let compile_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--out",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
            "--goal",
            "script",
            "--trace-id",
            "trace-cli-compile",
            "--decision-id",
            "decision-cli-compile",
            "--policy-id",
            "policy-cli-compile",
        ])
        .output()
        .expect("compile command should execute");

    assert!(
        compile_output.status.success(),
        "compile failed with stderr={}",
        String::from_utf8_lossy(&compile_output.stderr)
    );
    let compile_json = parse_stdout_json(&compile_output);
    assert_eq!(
        compile_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(compile_json["parse_goal"].as_str(), Some("script"));
    assert_eq!(
        compile_json["artifact_path"].as_str(),
        artifact_path.to_str()
    );

    let artifact_bytes = fs::read(&artifact_path).expect("compile artifact should exist");
    let artifact_json: serde_json::Value =
        serde_json::from_slice(&artifact_bytes).expect("artifact should be valid json");
    assert_eq!(
        artifact_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.compile-artifact.v1")
    );

    let verify_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
        ])
        .output()
        .expect("verify command should execute");

    assert!(
        verify_output.status.success(),
        "verify failed with stderr={}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_json = parse_stdout_json(&verify_output);
    assert_eq!(
        verify_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(verify_json["passed"].as_bool(), Some(true));
    assert_eq!(verify_json["errors"].as_array().map(Vec::len), Some(0));

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_run_writes_execution_report() {
    let source_path = temp_path("frankenctl_run_source", "js");
    let report_path = temp_path("frankenctl_run_report", "json");
    write_source(&source_path, "let value = 2 + 3;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--extension-id",
            "ext-cli-run",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("run command should execute");

    assert!(
        output.status.success(),
        "run failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(stdout_json["extension_id"].as_str(), Some("ext-cli-run"));
    assert!(stdout_json["trace_id"].as_str().is_some());
    assert!(stdout_json["decision_id"].as_str().is_some());
    assert!(stdout_json["lane"].as_str().is_some());
    assert!(stdout_json["containment_action"].as_str().is_some());

    let report_bytes = fs::read(&report_path).expect("run report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should parse as json");
    assert_eq!(report_json["extension_id"].as_str(), Some("ext-cli-run"));

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_replay_run_replays_trace_without_divergence() {
    let trace_path = temp_path("frankenctl_replay_trace", "json");
    let replay_report_path = temp_path("frankenctl_replay_report", "json");

    let mut trace = NondeterminismTrace::new("session-cli-replay");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![7],
        1,
        "integration-test",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![1, 2, 3],
        2,
        "integration-test",
    );
    trace.finalise(3);

    fs::write(
        &trace_path,
        serde_json::to_vec_pretty(&trace).expect("trace should serialize"),
    )
    .expect("trace file should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path
                .to_str()
                .expect("trace path should be valid utf8"),
            "--mode",
            "strict",
            "--out",
            replay_report_path
                .to_str()
                .expect("replay report path should be valid utf8"),
        ])
        .output()
        .expect("replay command should execute");

    assert!(
        output.status.success(),
        "replay failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(stdout_json["mode"].as_str(), Some("strict"));
    assert_eq!(stdout_json["event_count"].as_u64(), Some(2));
    assert_eq!(stdout_json["divergence_count"].as_u64(), Some(0));
    assert_eq!(stdout_json["critical_divergences"].as_u64(), Some(0));
    assert_eq!(stdout_json["complete"].as_bool(), Some(true));

    let report_bytes = fs::read(&replay_report_path).expect("replay report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("replay report should parse as json");
    assert_eq!(
        report_json["session_id"].as_str(),
        Some("session-cli-replay")
    );

    let _ = fs::remove_file(trace_path);
    let _ = fs::remove_file(replay_report_path);
}

#[test]
fn frankenctl_verify_compile_artifact_failure_includes_trace_and_remediation() {
    let artifact_path = temp_path("frankenctl_invalid_compile_artifact", "json");
    fs::write(&artifact_path, "{}\n").expect("invalid artifact fixture should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
        ])
        .output()
        .expect("verify command should execute");

    assert!(
        !output.status.success(),
        "verify compile-artifact should fail for invalid payload"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=verify"),
        "stderr should include command label, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Inspect input artifact/receipt payload and rerun `frankenctl verify ...`."
        ),
        "stderr should include remediation guidance, got: {stderr}"
    );

    let _ = fs::remove_file(artifact_path);
}
