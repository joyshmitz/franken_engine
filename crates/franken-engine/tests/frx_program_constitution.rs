use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_program_constitution_contains_required_sections() {
    let path = repo_root().join("docs/FRX_PROGRAM_CONSTITUTION_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Program Constitution v1",
        "## Purpose",
        "## Objective Function",
        "## Compatibility Scope and Non-Goals",
        "## Testable Constitutional Invariants",
        "## Loss Matrix, Calibration, and Fallback Linkage",
        "## Program Metrics (North-Star + Guardrails)",
        "## Downstream Workstream Contract",
        "## Program-Wide Test Gate",
        "## Change Control",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "program constitution missing section: {section}"
        );
    }

    let required_clauses = [
        "frx.program.constitution.v1",
        "FRX-CI-001",
        "FRX-CI-005",
        "deterministic safe mode",
        "fail-closed",
    ];
    for clause in required_clauses {
        assert!(
            doc.contains(clause),
            "program constitution missing clause: {clause}"
        );
    }
}

#[test]
fn frx_objective_function_contract_is_machine_readable() {
    let path = repo_root().join("docs/frx_objective_function_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.objective_function.v1")
    );
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.1"));
    assert_eq!(
        value["constitution_ref"].as_str(),
        Some("docs/FRX_PROGRAM_CONSTITUTION_V1.md")
    );

    let dimensions = value["objective"]["dimensions"]
        .as_array()
        .expect("objective.dimensions must be an array");
    let expected_dimensions = ["compatibility", "deterministic_reliability", "performance"];
    for dim in expected_dimensions {
        assert!(
            dimensions.iter().any(|entry| entry.as_str() == Some(dim)),
            "objective dimension missing: {dim}"
        );
    }

    let required_decision_links = [
        (
            "loss_matrix_source",
            "crates/franken-engine/src/expected_loss_selector.rs",
        ),
        (
            "calibration_source",
            "crates/franken-engine/src/runtime_decision_theory.rs",
        ),
        (
            "fallback_policy_source",
            "crates/franken-engine/src/safe_mode_fallback.rs",
        ),
    ];
    for (field, expected) in required_decision_links {
        assert_eq!(
            value["decision_model"][field].as_str(),
            Some(expected),
            "unexpected {field}"
        );
    }
}

#[test]
fn frx_freeze_manifest_and_lane_charters_reference_program_constitution() {
    let freeze_manifest_path = repo_root().join("docs/FRX_C0_FREEZE_MANIFEST_V1.json");
    let freeze_manifest_raw = fs::read_to_string(&freeze_manifest_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", freeze_manifest_path.display()));
    let freeze_manifest: Value = serde_json::from_str(&freeze_manifest_raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", freeze_manifest_path.display()));

    assert_eq!(
        freeze_manifest["artifacts"]["program_constitution"].as_str(),
        Some("docs/FRX_PROGRAM_CONSTITUTION_V1.md")
    );
    assert_eq!(
        freeze_manifest["artifacts"]["objective_function_contract"].as_str(),
        Some("docs/frx_objective_function_v1.json")
    );

    let compiler_charter_path = repo_root().join("docs/FRX_COMPILER_LANE_CHARTER_V1.md");
    let compiler_charter = fs::read_to_string(&compiler_charter_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", compiler_charter_path.display()));
    assert!(
        compiler_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "compiler lane charter must reference program constitution"
    );

    let semantics_charter_path = repo_root().join("docs/FRX_SEMANTICS_LANE_CHARTER_V1.md");
    let semantics_charter = fs::read_to_string(&semantics_charter_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", semantics_charter_path.display()));
    assert!(
        semantics_charter.contains("docs/FRX_PROGRAM_CONSTITUTION_V1.md"),
        "semantics lane charter must reference program constitution"
    );
}
