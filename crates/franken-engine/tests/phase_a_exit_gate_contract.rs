#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_{label}_{nanos}_{}",
        std::process::id()
    ))
}

fn latest_run_dir(root: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = fs::read_dir(root)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", root.display()))
        .map(|entry| entry.expect("directory entry should load").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs.pop().expect("expected one phase-a run directory")
}

#[test]
fn phase_a_gate_blocked_mode_emits_standard_artifact_triad() {
    let artifacts_root = temp_dir("phase_a_exit_gate_contract");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate script should execute");

    assert!(
        !output.status.success(),
        "blocked dependency state should fail closed"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("Phase-A gate blocked by unresolved dependencies"),
        "expected blocked message in stderr, got: {stderr}"
    );

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    assert!(manifest_path.exists(), "manifest must exist");
    assert!(events_path.exists(), "events.jsonl must exist");
    assert!(commands_path.exists(), "commands.txt must exist");
    assert!(
        !run_dir.join("phase_a_exit_gate_events.jsonl").exists(),
        "legacy event filename must not be emitted"
    );

    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display())),
    )
    .expect("manifest json should parse");

    assert_eq!(
        manifest["schema_version"],
        "franken-engine.phase-a-exit-gate.run-manifest.v1"
    );
    assert_eq!(manifest["component"], "phase_a_exit_gate");
    assert_eq!(manifest["bead_id"], "bd-1csl");
    assert_eq!(manifest["mode"], "check");
    assert_eq!(manifest["skip_subgates"], 1);
    assert_eq!(manifest["outcome"], "fail");
    let unmet_dependencies = manifest["unmet_dependencies"]
        .as_array()
        .expect("unmet dependencies should be array");
    assert!(
        unmet_dependencies
            .iter()
            .any(|value| value.as_str().is_some_and(|value| value.starts_with("bd-ntq="))),
        "expected unresolved phase-a dependencies in manifest: {manifest:#}"
    );
    let operator_verification: Vec<&str> = manifest["operator_verification"]
        .as_array()
        .expect("operator verification should be array")
        .iter()
        .map(|value| value.as_str().expect("operator command should be string"))
        .collect();
    assert!(
        operator_verification
            .iter()
            .any(|command| command.ends_with("/run_manifest.json")),
        "expected manifest inspection command in operator verification: {operator_verification:?}"
    );
    assert!(
        operator_verification
            .iter()
            .any(|command| command.ends_with("/events.jsonl")),
        "expected events inspection command in operator verification: {operator_verification:?}"
    );
    assert!(
        operator_verification
            .iter()
            .any(|command| command.contains("PHASE_A_GATE_SKIP_SUBGATES=1")),
        "expected skip-subgates replay command in operator verification: {operator_verification:?}"
    );

    let events = fs::read_to_string(&events_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", events_path.display()));
    assert!(
        events.contains("\"event\":\"phase_a_gate_completed\""),
        "expected completion event in events.jsonl: {events}"
    );
    assert!(
        events.contains("\"outcome\":\"fail\""),
        "expected fail outcome in events.jsonl: {events}"
    );
    assert!(
        events.contains("\"error_code\":\"FE-PHASE-A-GATE-1001\""),
        "expected fail-closed error code in events.jsonl: {events}"
    );

    let commands = fs::read_to_string(&commands_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", commands_path.display()));
    assert!(
        commands.trim().is_empty(),
        "skip-subgates blocked run should not record sub-gate commands: {commands}"
    );

    assert!(
        stdout.contains("phase-a gate run manifest:"),
        "expected manifest path in stdout, got: {stdout}"
    );
    assert!(
        stdout.contains("phase-a gate events:"),
        "expected events path in stdout, got: {stdout}"
    );
}
