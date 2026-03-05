use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_governance_evidence_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Governance/Evidence Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Policy-as-Data Integrity and Signing",
        "## Evidence Ledger and Explainability Surfaces",
        "## Failure and Deterministic Safe Mode Policy",
        "## Interface Contracts",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "governance/evidence lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "policy-as-data integrity",
        "evidence-ledger correctness",
        "machine-readable evidence ID",
        "disable adaptive behavior",
        "conservative deterministic mode",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "governance/evidence lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_governance_evidence_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.governance-evidence.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.7"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.7"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.7"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("conservative_deterministic")
    );
    assert_eq!(
        value["failure_policy"]["disable_adaptive_behavior_on_integrity_failure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["incident_artifact_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["block_promotion_until_revalidated"].as_bool(),
        Some(true)
    );

    let required_logging_fields = value["logging_contract"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    for field in ["trace_id", "decision_id", "policy_id", "evidence_id"] {
        assert!(
            required_logging_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "required logging field missing: {field}"
        );
    }

    let required_query_fields = value["outputs"]["evidence_ledger"]["required_query_fields"]
        .as_array()
        .expect("required_query_fields must be an array");
    for field in ["trace_id", "decision_id", "policy_id", "evidence_id"] {
        assert!(
            required_query_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "required evidence ledger query field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_governance_evidence_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["governance_lane_charter"].as_str(),
        Some("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["governance_lane_contract"].as_str(),
        Some("docs/frx_governance_evidence_lane_contract_v1.json")
    );
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- charter doc ----------

#[test]
fn governance_charter_doc_is_nonempty() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(!doc.is_empty());
}

#[test]
fn governance_charter_references_program_constitution() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("FRX_PROGRAM_CONSTITUTION_V1.md"));
}

// ---------- JSON contract fields ----------

#[test]
fn governance_contract_has_lane_section() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["lane"].is_object());
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.7"));
}

#[test]
fn governance_contract_has_logging_contract() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["logging_contract"].is_object());
}

#[test]
fn governance_contract_has_evidence_ledger_output() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["outputs"]["evidence_ledger"].is_object());
}

#[test]
fn governance_contract_json_is_deterministic() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let v1: Value = serde_json::from_str(&raw).expect("parse first");
    let v2: Value = serde_json::from_str(&raw).expect("parse second");
    assert_eq!(v1, v2);
}

#[test]
fn governance_contract_has_generated_at_utc() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let ts = value["generated_at_utc"].as_str().expect("generated_at_utc must be string");
    assert!(ts.ends_with('Z'), "generated_at_utc must end with Z");
}

#[test]
fn governance_contract_has_failure_policy_object() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["failure_policy"].is_object());
    assert!(!value["failure_policy"]["mode"].as_str().unwrap_or("").is_empty());
}

#[test]
fn governance_charter_mentions_evidence() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.to_ascii_lowercase().contains("evidence"));
}

#[test]
fn governance_contract_has_primary_bead() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let pb = value["primary_bead"].as_str().expect("primary_bead must be string");
    assert!(!pb.trim().is_empty());
}

#[test]
fn governance_charter_mentions_policy_as_data() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read charter doc");
    assert!(doc.contains("policy-as-data"));
}

#[test]
fn governance_contract_has_schema_version() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    let sv = value["schema_version"].as_str().expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

#[test]
fn governance_contract_has_generated_by() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["generated_by"].as_str().is_some_and(|s| !s.is_empty()));
}

#[test]
fn governance_contract_has_release_gate_contract() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["release_gate_contract"].is_object());
}

#[test]
fn governance_contract_has_inputs_section() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value["inputs"].is_object() || value["inputs"].is_array());
}

#[test]
fn governance_charter_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_GOVERNANCE_EVIDENCE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

#[test]
fn governance_contract_is_a_json_object() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let value: Value = serde_json::from_str(&raw).expect("parse JSON");
    assert!(value.is_object());
}

#[test]
fn governance_contract_deterministic_double_parse() {
    let path = repo_root().join("docs/frx_governance_evidence_lane_contract_v1.json");
    let raw = fs::read_to_string(&path).expect("read JSON");
    let a: Value = serde_json::from_str(&raw).expect("parse 1");
    let b: Value = serde_json::from_str(&raw).expect("parse 2");
    assert_eq!(a, b);
}
