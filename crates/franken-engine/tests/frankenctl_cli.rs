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

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temp dir should be creatable");
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
    assert!(stdout.contains("frankenctl benchmark score"));
    assert!(stdout.contains("frankenctl benchmark verify"));
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

#[test]
fn frankenctl_benchmark_score_and_verify_bundle_round_trip() {
    let score_input_path = temp_path("frankenctl_benchmark_score_input", "json");
    let score_results_path = temp_path("frankenctl_benchmark_score_results", "json");
    let verify_report_path = temp_path("frankenctl_benchmark_verify_report", "json");
    let bundle_dir = temp_dir("frankenctl_benchmark_bundle");

    let score_input = serde_json::json!({
        "node_cases": [
            {
                "workload_id": "boot-storm/s",
                "throughput_franken_tps": 3000.0,
                "throughput_baseline_tps": 900.0,
                "weight": null,
                "behavior_equivalent": true,
                "latency_envelope_ok": true,
                "error_envelope_ok": true
            }
        ],
        "bun_cases": [
            {
                "workload_id": "boot-storm/s",
                "throughput_franken_tps": 3000.0,
                "throughput_baseline_tps": 950.0,
                "weight": null,
                "behavior_equivalent": true,
                "latency_envelope_ok": true,
                "error_envelope_ok": true
            }
        ],
        "native_coverage_progression": [
            {
                "recorded_at_utc": "2026-03-01T00:00:00Z",
                "native_slots": 42,
                "total_slots": 48
            }
        ],
        "replacement_lineage_ids": ["lineage-a"]
    });
    fs::write(
        &score_input_path,
        serde_json::to_vec_pretty(&score_input).expect("score input should serialize"),
    )
    .expect("score input should write");

    let score_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--input",
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8"),
            "--trace-id",
            "trace-bench-score-cli",
            "--decision-id",
            "decision-bench-score-cli",
            "--policy-id",
            "policy-bench-score-cli",
            "--output",
            score_results_path
                .to_str()
                .expect("score result path should be valid utf8"),
        ])
        .output()
        .expect("benchmark score command should execute");

    assert!(
        score_output.status.success(),
        "benchmark score failed with stderr={}",
        String::from_utf8_lossy(&score_output.stderr)
    );
    let score_json = parse_stdout_json(&score_output);
    assert_eq!(
        score_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(
        score_json["trace_id"].as_str(),
        Some("trace-bench-score-cli")
    );
    assert_eq!(
        score_json["decision_id"].as_str(),
        Some("decision-bench-score-cli")
    );
    assert_eq!(
        score_json["policy_id"].as_str(),
        Some("policy-bench-score-cli")
    );
    assert_eq!(score_json["publish_allowed"].as_bool(), Some(true));

    let results_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&score_results_path).expect("score results should be written"),
    )
    .expect("score results should parse");
    assert_eq!(
        results_json["trace_id"].as_str(),
        Some("trace-bench-score-cli")
    );
    assert_eq!(
        results_json["claimed"]["publish_allowed"].as_bool(),
        Some(true)
    );

    let bundle_results_path = bundle_dir.join("results.json");
    fs::copy(&score_results_path, &bundle_results_path).expect("results.json should copy");
    fs::write(
        bundle_dir.join("env.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "toolchain": "rust-1.86.0",
            "os": "linux",
            "arch": "x86_64"
        }))
        .expect("env fixture should serialize"),
    )
    .expect("env fixture should write");
    fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "franken-engine.benchmark.bundle.v1",
            "trace_id": "trace-bench-score-cli",
            "decision_id": "decision-bench-score-cli",
            "policy_id": "policy-bench-score-cli"
        }))
        .expect("manifest fixture should serialize"),
    )
    .expect("manifest fixture should write");
    fs::write(
        bundle_dir.join("repro.lock"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "franken-engine.benchmark.repro-lock.v1",
            "bundle_digest_sha256": "abc123"
        }))
        .expect("repro lock fixture should serialize"),
    )
    .expect("repro lock fixture should write");
    fs::write(
        bundle_dir.join("commands.txt"),
        "rch exec -- cargo test -p frankenengine-engine --test benchmark_denominator\n",
    )
    .expect("commands fixture should write");

    let verify_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir
                .to_str()
                .expect("bundle path should be valid utf8"),
            "--summary",
            "--output",
            verify_report_path
                .to_str()
                .expect("verify report path should be valid utf8"),
        ])
        .output()
        .expect("benchmark verify command should execute");

    assert!(
        verify_output.status.success(),
        "benchmark verify failed with stderr={}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_stdout = String::from_utf8(verify_output.stdout).expect("stdout should be utf8");
    assert!(verify_stdout.contains("claim_type=benchmark"));

    let verify_report: serde_json::Value = serde_json::from_slice(
        &fs::read(&verify_report_path).expect("verify report should be written"),
    )
    .expect("verify report should parse");
    assert_eq!(verify_report["claim_type"].as_str(), Some("benchmark"));
    assert_eq!(verify_report["verdict"].as_str(), Some("verified"));
    assert!(
        verify_report["checks"]
            .as_array()
            .is_some_and(|checks| !checks.is_empty())
    );
    assert!(
        verify_report["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty())
    );

    let _ = fs::remove_file(score_input_path);
    let _ = fs::remove_file(score_results_path);
    let _ = fs::remove_file(verify_report_path);
    let _ = fs::remove_dir_all(bundle_dir);
}
