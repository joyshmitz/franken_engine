use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_track_e_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_E_VERIFICATION_FUZZ_FORMAL_COVERAGE_SPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track E Verification/Fuzz/Formal Coverage Sprint Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Confidence Trajectory and Metrics Contract",
        "## Promotion Gate and Escalation Behavior",
        "## Counterexample Reproduction and Ownership Routing",
        "## Formal/Model-Check Stewardship",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track E charter missing section: {section}"
        );
    }

    let required_clauses = [
        "confidence trajectory over time",
        "promotion gatekeeper",
        "blocking reports",
        "minimized reproductions",
        "ownership routing",
        "metamorphic relations",
        "schedule perturbation harnesses",
        "formal/model-checking artifacts",
    ];

    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "track E charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_e_contract_is_machine_readable_and_fail_closed() {
    let path =
        repo_root().join("docs/frx_track_e_verification_fuzz_formal_coverage_sprint_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-e.verification-fuzz-formal-coverage.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.5"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.5"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.5"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_critical_unresolved_counterexample"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_confidence_regression"].as_bool(),
        Some(true)
    );

    let blocking_report_fields = value["outputs"]["blocking_report"]["required_fields"]
        .as_array()
        .expect("blocking report fields must be an array");

    for field in [
        "counterexample_id",
        "owner_track",
        "minimized_reproduction_id",
        "replay_command",
    ] {
        assert!(
            blocking_report_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "blocking report field missing: {field}"
        );
    }
}

#[test]
fn frx_track_e_readme_gate_instructions_present() {
    let path = repo_root().join("README.md");
    let readme = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    assert!(
        readme.contains("## FRX Track E Verification/Fuzz/Formal Coverage Sprint Gate"),
        "README missing track E gate heading"
    );
    assert!(
        readme.contains(
            "./scripts/run_frx_track_e_verification_fuzz_formal_coverage_sprint_suite.sh ci"
        ),
        "README missing track E gate command"
    );
    assert!(
        readme.contains(
            "./scripts/e2e/frx_track_e_verification_fuzz_formal_coverage_sprint_replay.sh"
        ),
        "README missing track E replay command"
    );
}
