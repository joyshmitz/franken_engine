use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_toolchain_lane_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Toolchain/Ecosystem Lane Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Supported Integration Profiles",
        "## Migration and Rollout Controls",
        "## Failure and Fallback Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "toolchain lane charter missing section: {section}"
        );
    }

    let required_clauses = [
        "conservative compatibility mode",
        "compatibility class",
        "Rollout toggles (`file`, `component`, `route`, `policy`)",
        "safe defaults",
        "block promotion",
    ];

    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "toolchain lane charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_toolchain_lane_contract_is_machine_readable_and_fail_safe() {
    let path = repo_root().join("docs/frx_toolchain_lane_contract_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.toolchain.lane.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.10.6"));
    assert_eq!(
        value["generated_at_utc"].as_str(),
        Some("2026-02-25T00:00:00Z")
    );
    assert_eq!(value["lane"]["id"].as_str(), Some("FRX-10.6"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.10.6"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("conservative_compatibility")
    );
    assert_eq!(
        value["failure_policy"]["auto_route_on_instability"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["failure_policy"]["block_promotion_on_persistent_instability"].as_bool(),
        Some(true)
    );

    let rollout_axes =
        value["ownership"]["incremental_adoption_controls"]["supported_rollout_axes"]
            .as_array()
            .expect("supported_rollout_axes must be an array");
    let expected_axes = ["file", "component", "route", "policy"];
    for axis in expected_axes {
        assert!(
            rollout_axes
                .iter()
                .any(|entry| entry.as_str() == Some(axis)),
            "rollout axis missing: {axis}"
        );
    }
}

#[test]
fn frx_c0_freeze_manifest_links_toolchain_lane_artifacts() {
    let path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["artifacts"]["toolchain_lane_charter"].as_str(),
        Some("docs/FRX_TOOLCHAIN_ECOSYSTEM_LANE_CHARTER_V1.md")
    );
    assert_eq!(
        value["artifacts"]["toolchain_lane_contract"].as_str(),
        Some("docs/frx_toolchain_lane_contract_v1.json")
    );
}
