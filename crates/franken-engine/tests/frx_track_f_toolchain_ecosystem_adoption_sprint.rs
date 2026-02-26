use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_track_f_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_F_TOOLCHAIN_ECOSYSTEM_ADOPTION_SPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track F Toolchain/Ecosystem/Adoption Sprint Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## Bundler and Source-Map Fidelity Contract",
        "## Ecosystem Compatibility and Migration Diagnostics Contract",
        "## Pilot/Canary Evidence Contract",
        "## Fallback Routing and Promotion-Block Policy",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track F charter missing section: {section}"
        );
    }

    let lower = doc.to_ascii_lowercase();
    for clause in [
        "bundler adapters",
        "source-map fidelity",
        "ecosystem compatibility",
        "migration diagnostics",
        "pilot",
        "canary",
        "fallback routing",
        "block promotion",
        "fail-closed",
    ] {
        assert!(
            lower.contains(clause),
            "track F charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_f_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_track_f_toolchain_ecosystem_adoption_sprint_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-f.toolchain-ecosystem-adoption-sprint.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.6"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.6"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.6"));

    assert_eq!(
        value["activation_gate"]["block_on_missing_bundler_adapter_coverage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_source_map_fidelity_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_untriaged_compatibility_regressions"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_pilot_canary_bundle"].as_bool(),
        Some(true)
    );

    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["failure_policy"]["fallback_mode"].as_str(),
        Some("conservative_compatibility")
    );
    assert_eq!(
        value["failure_policy"]["error_code"].as_str(),
        Some("FE-FRX-11-6-GATE-0001")
    );
    assert_eq!(
        value["failure_policy"]["promotion_block_on_repeated_class_regressions"].as_bool(),
        Some(true)
    );

    let dashboard_fields = value["outputs"]["integration_readiness_dashboard"]["required_fields"]
        .as_array()
        .expect("integration_readiness_dashboard.required_fields must be an array");
    for field in [
        "profile_id",
        "bundler",
        "compatibility_class",
        "confidence_grade",
        "fallback_route",
    ] {
        assert!(
            dashboard_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "dashboard field missing: {field}"
        );
    }
}

#[test]
fn frx_track_f_runtime_surfaces_exist_for_adoption_track() {
    let module_compat_path =
        repo_root().join("crates/franken-engine/src/module_compatibility_matrix.rs");
    let module_compat = fs::read_to_string(&module_compat_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", module_compat_path.display()));
    for snippet in [
        "pub struct ModuleCompatibilityMatrix",
        "pub enum CompatibilityRuntime",
        "pub enum CompatibilityMode",
    ] {
        assert!(
            module_compat.contains(snippet),
            "module_compatibility_matrix missing surface: {snippet}"
        );
    }

    let migration_kit_path = repo_root().join("crates/franken-engine/src/migration_kit.rs");
    let migration_kit = fs::read_to_string(&migration_kit_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", migration_kit_path.display()));
    for snippet in [
        "pub struct MigrationManifest",
        "pub struct CompatibilityReport",
        "pub struct BehaviorValidationReport",
        "pub enum MigrationKitError",
    ] {
        assert!(
            migration_kit.contains(snippet),
            "migration_kit missing surface: {snippet}"
        );
    }

    let migration_compat_path =
        repo_root().join("crates/franken-engine/src/migration_compatibility.rs");
    let migration_compat = fs::read_to_string(&migration_compat_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", migration_compat_path.display()));
    for snippet in [
        "pub struct MigrationCompatibilityChecker",
        "pub struct MigrationRegistry",
        "pub struct MigrationError",
    ] {
        assert!(
            migration_compat.contains(snippet),
            "migration_compatibility missing surface: {snippet}"
        );
    }

    let safe_mode_path = repo_root().join("crates/franken-engine/src/safe_mode_fallback.rs");
    let safe_mode = fs::read_to_string(&safe_mode_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", safe_mode_path.display()));
    for snippet in [
        "pub struct SafeModeManager",
        "pub enum FailureType",
        "pub struct SafeModeEvent",
    ] {
        assert!(
            safe_mode.contains(snippet),
            "safe_mode_fallback missing surface: {snippet}"
        );
    }
}
