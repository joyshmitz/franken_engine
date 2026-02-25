use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_track_b_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_B_COMPILER_FRIR_SPINE_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track B Compiler/FRIR Spine Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Canonical Binder Contract",
        "## FRIR Lowering and Witness Contract",
        "## Optimization Budget and Isomorphism Guard",
        "## Promotion Blocking and Rollback",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track B charter missing section: {section}"
        );
    }

    let required_clauses = [
        "canonical binder representation",
        "FRIR schema version stability",
        "witness bundle linkage",
        "isomorphism checks",
        "fail closed",
        "replay command",
    ];

    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "track B charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_b_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_track_b_compiler_frir_spine_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-b.compiler-frir-spine.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.2"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.2"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.2"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_witness_linkage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_failed_isomorphism_check"].as_bool(),
        Some(true)
    );

    let witness_fields = value["outputs"]["witness_bundle_contract"]["required_fields"]
        .as_array()
        .expect("required_fields must be an array");
    let expected_witness_fields = [
        "pass_id",
        "input_hash",
        "output_hash",
        "invariant_results",
        "budget_summary",
        "replay_linkage",
        "producer_track",
    ];

    for field in expected_witness_fields {
        assert!(
            witness_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "witness field missing: {field}"
        );
    }
}
