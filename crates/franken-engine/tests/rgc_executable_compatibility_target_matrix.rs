#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::Deserialize;

const MATRIX_SCHEMA_VERSION: &str = "rgc.executable-compatibility-target-matrix.v1";
const MATRIX_JSON: &str =
    include_str!("../../../docs/rgc_executable_compatibility_target_matrix_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CompatibilityMatrix {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: MatrixTrack,
    scope: MatrixScope,
    required_structured_log_fields: Vec<String>,
    critical_behavior_bead_ids: Vec<String>,
    milestone_targets: Vec<MilestoneTarget>,
    coverage_rows: Vec<CoverageRow>,
    waiver_governance: WaiverGovernance,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MatrixTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MatrixScope {
    project_epic: String,
    snapshot_source: String,
    snapshot_generated_at_utc: String,
    open_bead_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MilestoneTarget {
    milestone: String,
    description: String,
    required_beads: Vec<String>,
    stop_go_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CoverageRow {
    row_id: String,
    bead_selectors: Vec<String>,
    requirement_id: String,
    test_kind: String,
    harness_entrypoint: String,
    deterministic_seed_policy: String,
    required_log_fields: Vec<String>,
    artifact_paths: Vec<String>,
    gate_owner: String,
    pass_fail_interpretation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct WaiverGovernance {
    waiver_required_fields: Vec<String>,
    max_waiver_age_hours: u64,
    fail_closed_on_expired_waiver: bool,
    fail_closed_on_missing_signature: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_matrix() -> CompatibilityMatrix {
    serde_json::from_str(MATRIX_JSON).expect("rgc compatibility target matrix json must parse")
}

fn selector_matches(selector: &str, bead_id: &str) -> bool {
    if let Some(prefix) = selector.strip_suffix(".*") {
        bead_id == prefix || bead_id.starts_with(&format!("{prefix}."))
    } else {
        bead_id == selector
    }
}

fn matched_row_ids<'a>(matrix: &'a CompatibilityMatrix, bead_id: &str) -> Vec<&'a str> {
    matrix
        .coverage_rows
        .iter()
        .filter(|row| {
            row.bead_selectors
                .iter()
                .any(|selector| selector_matches(selector, bead_id))
        })
        .map(|row| row.row_id.as_str())
        .collect()
}

#[test]
fn rgc_011_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_EXECUTABLE_COMPATIBILITY_TARGET_MATRIX_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Executable Compatibility Target Matrix V1",
        "## Purpose",
        "## Matrix Model",
        "## Compatibility Targets By Milestone",
        "## Required Logging Fields",
        "## Waiver Governance",
        "## Diff-Reviewability Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_011_matrix_is_versioned_and_track_bound() {
    let matrix = parse_matrix();

    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.bead_id, "bd-1lsy.1.1");
    assert_eq!(matrix.generated_by, "bd-1lsy.1.1");
    assert_eq!(matrix.track.id, "RGC-011");
    assert_eq!(matrix.track.name, "Executable Compatibility Target Matrix");
    assert!(matrix.generated_at_utc.ends_with('Z'));
    assert!(matrix.scope.snapshot_generated_at_utc.ends_with('Z'));
    assert_eq!(matrix.scope.project_epic, "bd-1lsy");
    assert!(
        matrix
            .scope
            .snapshot_source
            .contains("br list --json filtered")
    );
}

#[test]
fn rgc_011_scope_snapshot_has_unique_sorted_open_beads() {
    let matrix = parse_matrix();
    assert!(
        !matrix.scope.open_bead_ids.is_empty(),
        "expected non-empty RGC open bead scope"
    );

    let mut sorted = matrix.scope.open_bead_ids.clone();
    sorted.sort();
    assert_eq!(
        sorted, matrix.scope.open_bead_ids,
        "open_bead_ids snapshot must be lexicographically sorted"
    );

    let unique: BTreeSet<_> = matrix.scope.open_bead_ids.iter().collect();
    assert_eq!(
        unique.len(),
        matrix.scope.open_bead_ids.len(),
        "open_bead_ids snapshot must not contain duplicates"
    );
}

#[test]
fn rgc_011_all_open_beads_are_mapped_to_at_least_one_verification_row() {
    let matrix = parse_matrix();

    for bead_id in &matrix.scope.open_bead_ids {
        let matched = matched_row_ids(&matrix, bead_id);
        assert!(
            !matched.is_empty(),
            "open bead {bead_id} has no verification mapping row"
        );
    }
}

#[test]
fn rgc_011_critical_behavior_beads_have_unit_integration_and_e2e_rows() {
    let matrix = parse_matrix();

    let row_kind_by_id: BTreeMap<&str, &str> = matrix
        .coverage_rows
        .iter()
        .map(|row| (row.row_id.as_str(), row.test_kind.as_str()))
        .collect();

    for bead_id in &matrix.critical_behavior_bead_ids {
        let matched = matched_row_ids(&matrix, bead_id);
        assert!(
            !matched.is_empty(),
            "critical behavior bead {bead_id} must have at least one matched row"
        );

        let kinds: BTreeSet<&str> = matched
            .iter()
            .map(|row_id| {
                row_kind_by_id
                    .get(row_id)
                    .copied()
                    .unwrap_or_else(|| panic!("row_id {row_id} missing from row_kind index"))
            })
            .collect();

        for required in ["unit", "integration", "e2e"] {
            assert!(
                kinds.contains(required),
                "critical bead {bead_id} missing required {required} coverage kind"
            );
        }
    }
}

#[test]
fn rgc_011_rows_reference_executable_entrypoints_logs_and_artifact_triad() {
    let matrix = parse_matrix();

    let required_log_fields: BTreeSet<&str> = [
        "trace_id",
        "decision_id",
        "runtime_lane",
        "seed",
        "result",
        "error_code",
    ]
    .into_iter()
    .collect();

    for row in &matrix.coverage_rows {
        assert!(
            !row.requirement_id.trim().is_empty(),
            "row {} missing requirement_id",
            row.row_id
        );
        assert!(
            ["unit", "integration", "e2e"].contains(&row.test_kind.as_str()),
            "row {} has unsupported test kind {}",
            row.row_id,
            row.test_kind
        );
        assert!(
            !row.harness_entrypoint.trim().is_empty(),
            "row {} missing harness entrypoint",
            row.row_id
        );
        assert!(
            !row.deterministic_seed_policy.trim().is_empty(),
            "row {} missing deterministic seed policy",
            row.row_id
        );
        assert!(
            !row.gate_owner.trim().is_empty(),
            "row {} missing gate owner",
            row.row_id
        );
        assert!(
            !row.pass_fail_interpretation.trim().is_empty(),
            "row {} missing pass/fail interpretation",
            row.row_id
        );

        let field_set: BTreeSet<&str> =
            row.required_log_fields.iter().map(String::as_str).collect();
        for required in &required_log_fields {
            assert!(
                field_set.contains(required),
                "row {} missing required log field {}",
                row.row_id,
                required
            );
        }

        let triad_checks = ["run_manifest.json", "events.jsonl", "commands.txt"];
        for triad in triad_checks {
            assert!(
                row.artifact_paths.iter().any(|path| path.ends_with(triad)),
                "row {} missing artifact triad member {}",
                row.row_id,
                triad
            );
        }
    }
}

#[test]
fn rgc_011_matrix_required_log_fields_and_waiver_rules_are_fail_closed() {
    let matrix = parse_matrix();

    let required = [
        "trace_id",
        "decision_id",
        "runtime_lane",
        "seed",
        "result",
        "error_code",
    ];

    let root_fields: BTreeSet<&str> = matrix
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();

    for field in required {
        assert!(
            root_fields.contains(field),
            "matrix root missing required log field {field}"
        );
    }

    assert!(matrix.waiver_governance.max_waiver_age_hours > 0);
    assert!(matrix.waiver_governance.fail_closed_on_expired_waiver);
    assert!(matrix.waiver_governance.fail_closed_on_missing_signature);

    let waiver_required: BTreeSet<&str> = matrix
        .waiver_governance
        .waiver_required_fields
        .iter()
        .map(String::as_str)
        .collect();

    for field in [
        "waiver_id",
        "bead_id",
        "requirement_id",
        "owner",
        "expiry_utc",
        "rationale",
        "mitigation_plan",
        "approval_signature_ref",
    ] {
        assert!(
            waiver_required.contains(field),
            "waiver governance missing required field {field}"
        );
    }
}

#[test]
fn rgc_011_milestone_targets_reference_required_beads_and_rules() {
    let matrix = parse_matrix();

    let allowed = BTreeSet::from([
        "M1".to_string(),
        "M2".to_string(),
        "M3".to_string(),
        "M4".to_string(),
        "M5".to_string(),
    ]);

    assert_eq!(
        matrix.milestone_targets.len(),
        5,
        "expected exactly five milestone targets"
    );

    for target in &matrix.milestone_targets {
        assert!(allowed.contains(&target.milestone));
        assert!(!target.description.trim().is_empty());
        assert!(!target.stop_go_rule.trim().is_empty());
        assert!(
            !target.required_beads.is_empty(),
            "milestone {} missing required beads",
            target.milestone
        );
        for bead in &target.required_beads {
            assert!(
                matrix.scope.open_bead_ids.contains(bead),
                "milestone {} references bead not in open scope snapshot: {}",
                target.milestone,
                bead
            );
        }
    }
}

#[test]
fn rgc_011_operator_verification_commands_are_present() {
    let matrix = parse_matrix();
    assert!(
        matrix.operator_verification.len() >= 3,
        "expected operator verification command set"
    );

    assert!(
        matrix
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty")),
        "operator verification must include json validation"
    );
    assert!(
        matrix.operator_verification.iter().any(|cmd| cmd.contains(
            "cargo test -p frankenengine-engine --test rgc_executable_compatibility_target_matrix"
        )),
        "operator verification must include matrix contract test"
    );
}
