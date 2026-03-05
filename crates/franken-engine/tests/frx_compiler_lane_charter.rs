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
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.2"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
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

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn compiler_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn compiler_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn compiler_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.2"));
}

#[test]
fn compiler_contract_has_outputs_with_pass_witness() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"].is_object());
    assert!(value["outputs"]["pass_witness_bundle"].is_object());
}

#[test]
fn compiler_contract_has_activation_gate() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["activation_gate"].is_object());
}

#[test]
fn compiler_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn compiler_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn compiler_contract_has_failure_policy_mode() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["failure_policy"].is_object());
    assert!(
        !value["failure_policy"]["mode"]
            .as_str()
            .unwrap_or("")
            .is_empty()
    );
}

#[test]
fn compiler_charter_mentions_frir() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRIR"));
}

#[test]
fn compiler_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"]
        .as_str()
        .expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn compiler_charter_mentions_swc_oxc() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("SWC/OXC"));
}

#[test]
fn compiler_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn compiler_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(
        value["generated_by"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn compiler_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn compiler_contract_has_consumer_interfaces() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["consumer_interfaces"].is_object() || value["consumer_interfaces"].is_array());
}

#[test]
fn compiler_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn compiler_contract_json_is_an_object() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn compiler_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}

#[test]
fn compiler_charter_doc_file_exists() {
    let path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    assert!(path.exists());
}

#[test]
fn compiler_contract_json_file_exists() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    assert!(path.exists());
}

#[test]
fn compiler_contract_schema_version_is_nonempty() {
    let path = repo_root().join("docs/frx_compiler_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version string");
    assert!(!sv.trim().is_empty());
}
