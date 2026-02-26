#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "frx.incremental-adoption-controls.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/frx_incremental_adoption_controls_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AdoptionControlsContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    rollout_axes: Vec<String>,
    policy_toggles: BTreeMap<String, PolicyToggle>,
    canary_flow: CanaryFlow,
    migration_diagnostics: Vec<MigrationDiagnostic>,
    required_structured_log_fields: Vec<String>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PolicyToggle {
    required: bool,
    default: bool,
    description: String,
    fallback_route: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CanaryFlow {
    stages: Vec<String>,
    allowed_transitions: Vec<CanaryTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CanaryTransition {
    from: String,
    to: String,
    kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MigrationDiagnostic {
    diagnostic_code: String,
    compatibility_class: String,
    fallback_route: String,
    remediation_id: String,
    remediation_summary: String,
    owner_lane: String,
    target_milestone: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> AdoptionControlsContract {
    serde_json::from_str(CONTRACT_JSON).expect("incremental adoption controls json must parse")
}

#[test]
fn frx_07_4_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_INCREMENTAL_ADOPTION_CONTROLS_V1.md");
    let doc =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Incremental Adoption Controls v1",
        "## Scope",
        "## Rollout Axes and Opt-In Granularity",
        "## Policy Opt-Out and Force-Fallback Toggles",
        "## Canary and Rollback Flow",
        "## Migration Diagnostics and Remediation UX",
        "## Deterministic Logging and Evidence Contract",
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
fn frx_07_4_contract_is_versioned_and_track_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-mjh3.7.4");
    assert_eq!(contract.generated_by, "bd-mjh3.7.4");
    assert_eq!(contract.track.id, "FRX-07.4");
    assert!(contract.track.name.contains("Incremental Adoption Controls"));
    assert!(contract.generated_at_utc.ends_with('Z'));
}

#[test]
fn frx_07_4_rollout_axes_and_policy_toggles_are_complete() {
    let contract = parse_contract();

    let axes: BTreeSet<&str> = contract.rollout_axes.iter().map(String::as_str).collect();
    let expected_axes: BTreeSet<&str> = ["file", "component", "route", "policy"].into_iter().collect();
    assert_eq!(axes, expected_axes);

    for toggle_name in [
        "force_fallback",
        "policy_opt_out",
        "denylist_opt_out",
        "canary_pause",
    ] {
        let toggle = contract
            .policy_toggles
            .get(toggle_name)
            .unwrap_or_else(|| panic!("missing policy toggle: {toggle_name}"));
        assert!(toggle.required, "toggle must be required: {toggle_name}");
        assert!(!toggle.description.trim().is_empty());
        assert!(!toggle.fallback_route.trim().is_empty());
    }

    let fallback_routes: BTreeSet<&str> = contract
        .policy_toggles
        .values()
        .map(|toggle| toggle.fallback_route.as_str())
        .collect();
    assert!(fallback_routes.contains("compatibility_fallback"));
    assert!(fallback_routes.contains("deterministic_safe_mode"));
}

#[test]
fn frx_07_4_canary_flow_contains_required_promote_and_rollback_paths() {
    let contract = parse_contract();

    let stages: BTreeSet<&str> = contract.canary_flow.stages.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = ["shadow", "canary", "ramp", "active"].into_iter().collect();
    assert_eq!(stages, expected);

    let transitions: BTreeSet<(String, String, String)> = contract
        .canary_flow
        .allowed_transitions
        .iter()
        .map(|t| (t.from.clone(), t.to.clone(), t.kind.clone()))
        .collect();

    for expected in [
        ("shadow", "canary", "promote"),
        ("canary", "ramp", "promote"),
        ("ramp", "active", "promote"),
        ("canary", "shadow", "rollback"),
        ("ramp", "canary", "rollback"),
        ("active", "canary", "rollback"),
    ] {
        assert!(
            transitions.contains(&(expected.0.to_string(), expected.1.to_string(), expected.2.to_string())),
            "missing canary transition: {} -> {} ({})",
            expected.0,
            expected.1,
            expected.2
        );
    }
}

#[test]
fn frx_07_4_migration_diagnostics_are_actionable_and_fail_closed() {
    let contract = parse_contract();

    assert!(
        contract.migration_diagnostics.len() >= 3,
        "expected at least three migration diagnostics"
    );

    for diagnostic in &contract.migration_diagnostics {
        assert!(diagnostic.diagnostic_code.starts_with("FRX-MIG-"));
        assert!(!diagnostic.compatibility_class.trim().is_empty());
        assert!(!diagnostic.remediation_id.trim().is_empty());
        assert!(!diagnostic.remediation_summary.trim().is_empty());
        assert!(!diagnostic.owner_lane.trim().is_empty());
        assert!(diagnostic.target_milestone.starts_with("FRX-07."));
        assert!(
            ["compatibility_fallback", "deterministic_safe_mode"]
                .contains(&diagnostic.fallback_route.as_str()),
            "invalid fallback route for diagnostic {}: {}",
            diagnostic.diagnostic_code,
            diagnostic.fallback_route
        );
    }
}

#[test]
fn frx_07_4_contract_matches_runtime_surfaces_and_logging_requirements() {
    let contract = parse_contract();

    let required_fields: BTreeSet<&str> = [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "decision_path",
        "seed",
        "timing_us",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let actual_fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    assert!(
        contract.operator_verification.iter().any(|line| {
            line.contains("run_frx_incremental_adoption_controls_suite.sh ci")
        }),
        "operator verification must include CI gate command"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| line.contains("frx_incremental_adoption_controls_replay.sh")),
        "operator verification must include replay command"
    );

    let activation = fs::read_to_string(repo_root().join("crates/franken-engine/src/activation_lifecycle.rs"))
        .expect("activation_lifecycle source must exist");
    for snippet in ["RolloutPhase", "Canary", "advance_rollout", "pub fn rollback"] {
        assert!(activation.contains(snippet), "activation_lifecycle missing: {snippet}");
    }

    let migration_kit = fs::read_to_string(repo_root().join("crates/franken-engine/src/migration_kit.rs"))
        .expect("migration_kit source must exist");
    for snippet in ["MigrationManifest", "CompatibilityReport", "MigrationEvent"] {
        assert!(migration_kit.contains(snippet), "migration_kit missing: {snippet}");
    }

    let safe_mode = fs::read_to_string(repo_root().join("crates/franken-engine/src/safe_mode_fallback.rs"))
        .expect("safe_mode_fallback source must exist");
    for snippet in ["SafeModeManager", "FailureType", "SafeModeEvent"] {
        assert!(safe_mode.contains(snippet), "safe_mode_fallback missing: {snippet}");
    }
}
