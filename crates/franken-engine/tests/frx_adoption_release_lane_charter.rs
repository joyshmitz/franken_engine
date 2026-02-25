use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_adoption_release_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Adoption/Release Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Stage-Gate and Artifact Prerequisites",
        "## Rollback and Oncall Readiness",
        "## Claim Publication Integrity",
        "## Failure and Promotion Halt Policy",
        "## Interface Contracts",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "adoption/release lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "pilot rollout strategy",
        "stage-gate discipline",
        "rollback drills",
        "oncall readiness",
        "complete reproducibility bundles",
        "claim-to-artifact linkage",
        "halt promotion and enforce remediation",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "adoption/release lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_adoption_release_lane_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_adoption_release_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.adoption-release.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.8"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.8"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.8"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("promotion_halt")
    );
    assert_eq!(
        value["failure_policy"]["halt_promotion_on_stage_gate_failure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["halt_promotion_on_rollback_readiness_failure"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["block_claim_publication_on_incomplete_repro_bundle"].as_bool(),
        Some(true)
    );

    let stages = value["ownership"]["stage_gate_authority"]["stages"]
        .as_array()
        .expect("stages must be an array");
    for stage in ["alpha", "beta", "ga"] {
        assert!(
            stages.iter().any(|entry| entry.as_str() == Some(stage)),
            "stage missing: {stage}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_adoption_release_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["adoption_lane_charter"].as_str(),
        Some("docs/FRX_ADOPTION_RELEASE_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["adoption_lane_contract"].as_str(),
        Some("docs/frx_adoption_release_lane_contract_v1.json")
    );
}
