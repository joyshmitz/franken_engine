use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_optimization_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Optimization/Performance Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Profile-First Evidence Discipline",
        "## One-Lever and Isomorphism Proof Discipline",
        "## Regression and Rollback Gates",
        "## Failure and Fallback Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "optimization lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "profile-driven performance improvement",
        "one-lever optimization discipline",
        "isomorphism proof note",
        "tail-latency budget gate",
        "Any unproven optimization is blocked from merge and promotion.",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "optimization lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_optimization_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_optimization_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.optimization.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.5"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.5"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.5"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["require_profile_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["require_rollback_plan"].as_bool(),
        Some(true)
    );

    let ranking_fields = value["outputs"]["optimization_campaign_ranking"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_ranking_fields = [
        "campaign_id",
        "expected_value",
        "relevance_score",
        "risk_score",
        "confidence",
    ];
    for field in expected_ranking_fields {
        assert!(
            ranking_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "optimization campaign ranking field missing: {field}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_optimization_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["optimization_lane_charter"].as_str(),
        Some("docs/FRX_OPTIMIZATION_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["optimization_lane_contract"].as_str(),
        Some("docs/frx_optimization_lane_contract_v1.json")
    );
}
