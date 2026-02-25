use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_verification_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Verification/Formal Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Differential and Metamorphic Evidence Obligations",
        "## Formal Assurance Obligations",
        "## Counterexample Triage and Reproducibility",
        "## Promotion Blocking Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "verification lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "semantic non-regression evidence",
        "formal assurance artifacts",
        "Missing any required evidence bundle is a promotion blocker.",
        "If confidence degrades below gate threshold, block promotion.",
        "deterministic replay command",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "verification lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_verification_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_verification_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.verification.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.4"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.4"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.4"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_confidence_below_threshold"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_replay_artifact"].as_bool(),
        Some(true)
    );

    let triage_fields = value["counterexample_triage"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_triage_fields = [
        "counterexample_id",
        "taxonomy_label",
        "replay_command",
        "minimized_payload_ref",
        "owner_lane",
        "confidence_impact",
    ];
    for field in expected_triage_fields {
        assert!(
            triage_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "counterexample triage field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_verification_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["verification_lane_charter"].as_str(),
        Some("docs/FRX_VERIFICATION_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["verification_lane_contract"].as_str(),
        Some("docs/frx_verification_lane_contract_v1.json")
    );
}
