use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    path.push(format!("{}_{}_{}.{}", name, std::process::id(), nonce, ext));
    path
}

fn write_fixture_catalog(path: &Path) -> String {
    let source = "let value = 41 + 1;";
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("fixture source should parse");
    let expected_hash = tree.canonical_hash();

    let catalog = serde_json::json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": [
            {
                "id": "lockstep-fixture-1",
                "family_id": "statement.expression",
                "goal": "script",
                "source": source,
                "expected_hash": expected_hash
            }
        ]
    });

    fs::write(
        path,
        serde_json::to_vec_pretty(&catalog).expect("fixture catalog should serialize"),
    )
    .expect("fixture catalog should be written");

    expected_hash
}

fn write_runtime_specs(path: &Path, expected_hash: &str) {
    let toml = format!(
        "schema_version = \"franken-engine.lockstep-runtimes.v1\"

[[runtimes]]
runtime_id = \"node\"
display_name = \"Node.js test adapter\"
version_pin = \"node@test\"
command = \"sh\"
args = ['-c', 'cat >/dev/null; echo \"{{\\\"hash\\\":\\\"{expected_hash}\\\"}}\"']

[[runtimes]]
runtime_id = \"bun\"
display_name = \"Bun test adapter\"
version_pin = \"bun@test\"
command = \"sh\"
args = ['-c', 'cat >/dev/null; echo \"{{\\\"hash\\\":\\\"{expected_hash}\\\"}}\"']
"
    );
    fs::write(path, toml).expect("runtime spec file should be written");
}

fn write_engine_specs(path: &Path) {
    let payload = serde_json::json!([
        {
            "engine_id": "fixture_expected_hash",
            "display_name": "Fixture Expected Hash Baseline",
            "kind": "fixture_expected_hash",
            "version_pin": "fixture-catalog@phase0-v1"
        }
    ]);
    fs::write(
        path,
        serde_json::to_vec_pretty(&payload).expect("engine spec json should serialize"),
    )
    .expect("engine spec file should write");
}

#[test]
fn lockstep_runner_help_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .arg("--help")
        .output()
        .expect("help command should execute");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("franken_lockstep_runner"));
    assert!(stdout.contains("--fixture-catalog"));
    assert!(stdout.contains("--runtime-specs"));
}

#[test]
fn lockstep_runner_unknown_argument_exits_nonzero() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .arg("--definitely-unknown")
        .output()
        .expect("command should execute");

    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("unknown argument"));
}

#[test]
fn lockstep_runner_generates_report_with_lockstep_replay_command() {
    let catalog_path = temp_path("franken_lockstep_runner_fixture_catalog", "json");
    let report_path = temp_path("franken_lockstep_runner_report", "json");
    write_fixture_catalog(&catalog_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--fixture-limit",
            "1",
            "--seed",
            "17",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report_bytes = fs::read(&report_path).expect("report file should exist");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should be valid json");

    assert_eq!(report["fixture_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["equivalent_fixtures"].as_u64(), Some(1));

    let replay = report["fixture_results"][0]["replay_command"]
        .as_str()
        .expect("replay command should be a string");
    assert!(replay.contains("franken_lockstep_runner"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn lockstep_runner_loads_runtime_specs_as_external_engines() {
    let catalog_path = temp_path("franken_lockstep_runner_runtime_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_runtime_specs", "toml");
    let report_path = temp_path("franken_lockstep_runner_runtime_report", "json");
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs(&runtime_specs_path, expected_hash.as_str());

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--fixture-limit",
            "1",
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report_bytes = fs::read(&report_path).expect("report file should exist");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should be valid json");
    assert_eq!(report["summary"]["equivalent_fixtures"].as_u64(), Some(1));

    let engine_specs = report["engine_specs"]
        .as_array()
        .expect("engine_specs should be an array");
    assert_eq!(engine_specs.len(), 3);
    assert_eq!(
        engine_specs[0]["engine_id"].as_str(),
        Some("franken_canonical")
    );
    assert_eq!(engine_specs[1]["engine_id"].as_str(), Some("node"));
    assert_eq!(engine_specs[1]["version_pin"].as_str(), Some("node@test"));
    assert_eq!(engine_specs[2]["engine_id"].as_str(), Some("bun"));
    assert_eq!(engine_specs[2]["version_pin"].as_str(), Some("bun@test"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn lockstep_runner_rejects_runtime_specs_and_engine_specs_combination() {
    let catalog_path = temp_path("franken_lockstep_runner_runtime_conflict_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_runtime_conflict_specs", "toml");
    let engine_specs_path = temp_path(
        "franken_lockstep_runner_runtime_conflict_engine_specs",
        "json",
    );
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs(&runtime_specs_path, expected_hash.as_str());
    write_engine_specs(&engine_specs_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--engine-specs",
            engine_specs_path
                .to_str()
                .expect("engine specs path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("cannot combine --engine-specs with --runtime-specs"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(engine_specs_path);
}
