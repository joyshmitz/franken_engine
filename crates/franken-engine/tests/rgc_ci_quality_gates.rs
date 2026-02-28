use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LaneCommandContract {
    lane: String,
    command: String,
    requires_rch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RegressionVerdictSample {
    sample_id: String,
    verdict: Value,
    expected_blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RgcCiQualityGatesFixture {
    schema_version: String,
    gate_version: String,
    required_modes: Vec<String>,
    required_structured_log_fields: Vec<String>,
    lane_command_contract: Vec<LaneCommandContract>,
    regression_verdict_samples: Vec<RegressionVerdictSample>,
    required_artifacts: Vec<String>,
}

fn load_fixture() -> RgcCiQualityGatesFixture {
    let path = Path::new("tests/fixtures/rgc_ci_quality_gates_v1.json");
    let bytes = fs::read(path).expect("read rgc ci quality gates fixture");
    serde_json::from_slice(&bytes).expect("deserialize rgc ci quality gates fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RGC_CI_QUALITY_GATES.md");
    fs::read_to_string(path).expect("read rgc ci quality gates doc")
}

fn severity_is_blocking(raw: &str) -> bool {
    matches!(raw, "critical" | "high")
}

fn verdict_blocks(verdict: &Value) -> bool {
    let highest = verdict
        .get("highest_severity")
        .or_else(|| verdict.get("severity"))
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_ascii_lowercase();

    let blocking_flag = verdict
        .get("blocking")
        .or_else(|| verdict.get("is_blocking"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let has_open_high_or_critical = verdict
        .get("regressions")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter().any(|row| {
                let status = row
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("active")
                    .to_ascii_lowercase();
                if status == "waived" {
                    return false;
                }
                let severity = row
                    .get("severity")
                    .or_else(|| row.get("level"))
                    .and_then(Value::as_str)
                    .unwrap_or("none")
                    .to_ascii_lowercase();
                severity_is_blocking(&severity)
            })
        })
        .unwrap_or(false);

    blocking_flag || severity_is_blocking(&highest) || has_open_high_or_critical
}

#[test]
fn rgc_ci_quality_fixture_schema_and_modes_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.rgc-ci-quality-gates.v1"
    );
    assert_eq!(fixture.gate_version, "1.0.0");

    let modes = fixture.required_modes.into_iter().collect::<BTreeSet<_>>();
    for mode in [
        "check",
        "clippy",
        "unit",
        "integration",
        "e2e",
        "replay",
        "regression",
        "ci",
    ] {
        assert!(modes.contains(mode), "missing required mode {mode}");
    }
}

#[test]
fn rgc_ci_quality_log_and_artifact_contract_is_complete() {
    let fixture = load_fixture();

    let log_fields = fixture
        .required_structured_log_fields
        .into_iter()
        .collect::<BTreeSet<_>>();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(log_fields.contains(key), "missing structured log key {key}");
    }

    let artifacts = fixture
        .required_artifacts
        .into_iter()
        .collect::<BTreeSet<_>>();
    for required in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "failure_summary.json",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }
}

#[test]
fn rgc_ci_quality_regression_verdict_samples_match_policy() {
    let fixture = load_fixture();

    for sample in fixture.regression_verdict_samples {
        let observed = verdict_blocks(&sample.verdict);
        assert_eq!(
            observed, sample.expected_blocking,
            "sample {} expected blocking={} but observed {}",
            sample.sample_id, sample.expected_blocking, observed
        );
    }
}

#[test]
fn rgc_ci_quality_script_contract_references_rch_for_heavy_lanes() {
    let fixture = load_fixture();
    let script = fs::read_to_string("../../scripts/run_rgc_ci_quality_gates.sh")
        .expect("read rgc ci quality script");

    assert!(
        script.contains("run_rch"),
        "script must define run_rch helper"
    );
    assert!(
        script.contains("rch exec -- env"),
        "script must route heavy lanes through rch"
    );

    for contract in fixture.lane_command_contract {
        assert!(
            script.contains(&contract.command),
            "script missing lane command {}",
            contract.command
        );
        if contract.requires_rch {
            assert!(
                matches!(
                    contract.lane.as_str(),
                    "check" | "clippy" | "unit" | "integration"
                ),
                "unexpected rch-required lane {}",
                contract.lane
            );
        }
    }
}

#[test]
fn rgc_ci_quality_doc_and_replay_wrapper_exist_and_reference_contract() {
    let doc = load_doc();
    let replay = fs::read_to_string("../../scripts/e2e/rgc_ci_quality_gates_replay.sh")
        .expect("read rgc ci quality replay wrapper");

    assert!(
        doc.contains("# RGC CI Quality Gates Contract (`bd-1lsy.11.5`)"),
        "doc title must include bead id"
    );
    assert!(doc.contains("## Lane Entry Points"));
    assert!(doc.contains("## Regression Verdict Ingestion (RGC-703 hook)"));
    assert!(doc.contains("## Required Artifacts"));
    assert!(doc.contains("./scripts/run_rgc_ci_quality_gates.sh ci"));

    assert!(
        replay.contains("run_rgc_ci_quality_gates.sh"),
        "replay wrapper must call main gate script"
    );
    assert!(
        replay.contains("parser_frontier_bootstrap_env"),
        "replay wrapper must bootstrap deterministic env"
    );
}
