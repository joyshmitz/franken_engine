use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_compiler_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Compiler/FRIR Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## FRIR Schema Governance",
        "## Pass Witness Obligations",
        "## Failure and Fallback Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "compiler lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "SWC/OXC parity obligations",
        "Deterministic FRIR artifacts",
        "Missing or malformed witness metadata blocks activation.",
        "fail-closed",
        "deterministic fallback",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "compiler lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_compiler_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.compiler.lane.contract.v1")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.2"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.2"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_verification_or_fallback_metadata"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_reuse_scan_outcome"].as_bool(),
        Some(true)
    );

    let witness_fields = value["outputs"]["pass_witness_bundle"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_witness_fields = [
        "pass_id",
        "input_hash",
        "output_hash",
        "invariant_results",
        "budget_summary",
        "replay_linkage",
    ];
    for field in expected_witness_fields {
        assert!(
            witness_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "pass witness field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_compiler_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["compiler_lane_charter"].as_str(),
        Some("docs/FRX_COMPILER_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["compiler_lane_contract"].as_str(),
        Some("docs/frx_compiler_lane_contract_v1.json")
    );
}
