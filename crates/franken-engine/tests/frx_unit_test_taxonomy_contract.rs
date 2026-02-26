#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::test_taxonomy::{
    DeterminismContract, FIXTURE_REGISTRY_SCHEMA_VERSION, FixtureEntry, FixtureRegistry,
    TEST_TAXONOMY_SCHEMA_VERSION, TestClass, TestSurface,
};
use serde::Deserialize;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn parse_test_class(raw: &str) -> TestClass {
    match raw {
        "core" => TestClass::Core,
        "edge" => TestClass::Edge,
        "adversarial" => TestClass::Adversarial,
        "regression" => TestClass::Regression,
        "fault_injection" => TestClass::FaultInjection,
        other => panic!("unknown test class: {other}"),
    }
}

fn parse_surface(raw: &str) -> TestSurface {
    match raw {
        "compiler" => TestSurface::Compiler,
        "runtime" => TestSurface::Runtime,
        "router" => TestSurface::Router,
        "governance" => TestSurface::Governance,
        "parser" => TestSurface::Parser,
        "scheduler" => TestSurface::Scheduler,
        "evidence" => TestSurface::Evidence,
        "security" => TestSurface::Security,
        other => panic!("unknown test surface: {other}"),
    }
}

#[derive(Debug, Deserialize)]
struct UnitTaxonomyContract {
    schema_version: String,
    primary_bead: String,
    generated_by: String,
    taxonomy: TaxonomySection,
    fixture_registry: FixtureRegistrySection,
    determinism_contract: DeterminismSection,
    lane_ownership_map: Vec<LaneOwnershipEntry>,
    unit_to_e2e_mappings: Vec<UnitToE2eMapping>,
    logging_contract: LoggingContract,
    failure_policy: FailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TaxonomySection {
    module_schema_version: String,
    fixture_registry_schema_version: String,
    classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureRegistrySection {
    required_fields: Vec<String>,
    provenance_levels: Vec<String>,
    seed_policy: SeedPolicy,
    artifact_retention_hooks: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SeedPolicy {
    required_for_classes: Vec<String>,
    optional_for_classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DeterminismSection {
    strict_contract_schema: String,
    seed_control_required_classes: Vec<String>,
    virtual_clock_required_classes: Vec<String>,
    deterministic_rng_required_classes: Vec<String>,
    environment_controls: Vec<String>,
    replay_requirements: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LaneOwnershipEntry {
    surface: String,
    lane_charter_ref: String,
    required_classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UnitToE2eMapping {
    test_class: String,
    scenario_families: Vec<String>,
    coverage_rationale: String,
}

#[derive(Debug, Deserialize)]
struct LoggingContract {
    component: String,
    required_fields: Vec<String>,
    artifact_retention_hooks: Vec<String>,
    fail_closed_on_missing_fields: bool,
}

#[derive(Debug, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
    block_on_schema_drift: bool,
    block_on_missing_lane_ownership: bool,
    block_on_missing_unit_to_e2e_mapping: bool,
    block_on_logging_contract_gap: bool,
}

#[test]
fn frx_20_1_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_UNIT_TEST_TAXONOMY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# FRX Unit-Test Taxonomy and Fixture Registry V1",
        "## Scope",
        "## Unit-Test Taxonomy",
        "## Fixture Registry Schema",
        "## Determinism and Replay Contract",
        "## Lane Ownership Map",
        "## Unit-to-E2E Coverage Mapping",
        "## Logging and Artifact Retention Hooks",
        "## CI Gate and Failure Policy",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section `{section}` in {}",
            path.display()
        );
    }
}

#[test]
fn frx_20_1_contract_schema_versions_are_pinned() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    assert_eq!(
        contract.schema_version, "frx.unit-test-taxonomy.contract.v1",
        "contract schema version drift"
    );
    assert_eq!(contract.primary_bead, "bd-mjh3.20.1");
    assert_eq!(contract.generated_by, "bd-mjh3.20.1");
    assert_eq!(
        contract.taxonomy.module_schema_version,
        TEST_TAXONOMY_SCHEMA_VERSION
    );
    assert_eq!(
        contract.taxonomy.fixture_registry_schema_version,
        FIXTURE_REGISTRY_SCHEMA_VERSION
    );
    assert_eq!(
        contract.determinism_contract.strict_contract_schema,
        TEST_TAXONOMY_SCHEMA_VERSION
    );
}

#[test]
fn frx_20_1_taxonomy_classes_cover_all_canonical_variants() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let classes_from_contract: BTreeSet<TestClass> = contract
        .taxonomy
        .classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let expected: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();

    assert_eq!(classes_from_contract, expected);
}

#[test]
fn frx_20_1_lane_ownership_map_covers_every_surface_and_class() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let expected_classes: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();
    let expected_surfaces: BTreeSet<TestSurface> = TestSurface::ALL.iter().copied().collect();

    let mapped_surfaces: BTreeSet<TestSurface> = contract
        .lane_ownership_map
        .iter()
        .map(|entry| parse_surface(entry.surface.as_str()))
        .collect();

    assert_eq!(
        mapped_surfaces, expected_surfaces,
        "surface coverage mismatch"
    );

    for entry in &contract.lane_ownership_map {
        let surface = parse_surface(entry.surface.as_str());
        assert_eq!(entry.lane_charter_ref, surface.lane_charter_ref());

        let classes: BTreeSet<TestClass> = entry
            .required_classes
            .iter()
            .map(|raw| parse_test_class(raw))
            .collect();
        assert_eq!(
            classes, expected_classes,
            "ownership entry `{}` does not require full class set",
            entry.surface
        );
    }
}

#[test]
fn frx_20_1_determinism_class_requirements_match_runtime_contracts() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let required_seed: BTreeSet<TestClass> = contract
        .determinism_contract
        .seed_control_required_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let required_clock: BTreeSet<TestClass> = contract
        .determinism_contract
        .virtual_clock_required_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let required_rng: BTreeSet<TestClass> = contract
        .determinism_contract
        .deterministic_rng_required_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();

    for class in TestClass::ALL {
        let dc = DeterminismContract::for_class(*class);

        assert_eq!(
            required_seed.contains(class),
            dc.seed_required,
            "seed requirement mismatch for class {class}"
        );
        assert_eq!(
            required_clock.contains(class),
            dc.virtual_clock_required,
            "virtual clock requirement mismatch for class {class}"
        );
        assert_eq!(
            required_rng.contains(class),
            dc.deterministic_rng_required,
            "deterministic RNG requirement mismatch for class {class}"
        );
    }

    for control in [
        "timezone",
        "locale",
        "rust_toolchain",
        "seed_transcript_checksum",
        "env_fingerprint",
    ] {
        assert!(
            contract
                .determinism_contract
                .environment_controls
                .iter()
                .any(|item| item == control),
            "missing determinism environment control: {control}"
        );
    }

    for replay_req in [
        "record_replay_command",
        "record_target_dir",
        "record_rch_execution_mode",
        "retain_gate_artifacts",
    ] {
        assert!(
            contract
                .determinism_contract
                .replay_requirements
                .iter()
                .any(|item| item == replay_req),
            "missing replay requirement: {replay_req}"
        );
    }
}

#[test]
fn frx_20_1_unit_to_e2e_mapping_is_complete_and_rationalized() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let mapped_classes: BTreeSet<TestClass> = contract
        .unit_to_e2e_mappings
        .iter()
        .map(|mapping| parse_test_class(mapping.test_class.as_str()))
        .collect();
    let expected: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();

    assert_eq!(mapped_classes, expected, "unit->e2e mapping is incomplete");

    for mapping in &contract.unit_to_e2e_mappings {
        assert!(
            !mapping.scenario_families.is_empty(),
            "scenario families missing for class {}",
            mapping.test_class
        );
        assert!(
            !mapping.coverage_rationale.trim().is_empty(),
            "coverage rationale missing for class {}",
            mapping.test_class
        );
    }
}

#[test]
fn frx_20_1_logging_contract_and_failure_policy_are_fail_closed() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    assert_eq!(
        contract.logging_contract.component,
        "frx_unit_test_taxonomy_contract"
    );
    assert!(contract.logging_contract.fail_closed_on_missing_fields);

    for field in [
        "fixture_id",
        "description",
        "test_class",
        "surfaces",
        "provenance",
        "seed",
        "content_hash",
        "format_version",
        "origin_ref",
        "tags",
    ] {
        assert!(
            contract
                .fixture_registry
                .required_fields
                .iter()
                .any(|item| item == field),
            "missing fixture registry field: {field}"
        );
    }

    for level in ["authored", "generated", "captured", "synthesized"] {
        assert!(
            contract
                .fixture_registry
                .provenance_levels
                .iter()
                .any(|item| item == level),
            "missing provenance level: {level}"
        );
    }

    for field in [
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "seed",
        "timing",
        "decision_path",
        "outcome",
        "error_code",
        "replay_command",
    ] {
        assert!(
            contract
                .logging_contract
                .required_fields
                .iter()
                .any(|item| item == field),
            "missing logging field: {field}"
        );
    }

    for hook in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(
            contract
                .logging_contract
                .artifact_retention_hooks
                .iter()
                .any(|item| item == hook),
            "missing logging artifact hook: {hook}"
        );
        assert!(
            contract
                .fixture_registry
                .artifact_retention_hooks
                .iter()
                .any(|item| item == hook),
            "missing fixture artifact hook: {hook}"
        );
    }

    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        "FE-FRX-20-1-TAXONOMY-0001"
    );
    assert!(contract.failure_policy.block_on_schema_drift);
    assert!(contract.failure_policy.block_on_missing_lane_ownership);
    assert!(contract.failure_policy.block_on_missing_unit_to_e2e_mapping);
    assert!(contract.failure_policy.block_on_logging_contract_gap);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("run_frx_unit_test_taxonomy_contract_suite.sh ci"))
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("frx_unit_test_taxonomy_contract_replay.sh ci"))
    );
}

#[test]
fn frx_20_1_fixture_registry_contract_can_satisfy_seed_and_coverage_requirements() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let required_seed_classes: BTreeSet<TestClass> = contract
        .fixture_registry
        .seed_policy
        .required_for_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let optional_seed_classes: BTreeSet<TestClass> = contract
        .fixture_registry
        .seed_policy
        .optional_for_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();

    let all_classes: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();
    assert_eq!(
        required_seed_classes
            .union(&optional_seed_classes)
            .copied()
            .collect::<BTreeSet<_>>(),
        all_classes,
        "seed policy must partition all classes"
    );

    let mut registry = FixtureRegistry::new();
    let mut counter = 0_u64;

    for class in TestClass::ALL {
        for surface in TestSurface::ALL {
            counter += 1;
            let seed = if required_seed_classes.contains(class) {
                Some(1_000 + counter)
            } else {
                None
            };
            let entry = FixtureEntry {
                fixture_id: format!("frx20-{}-{}", class.as_str(), surface.as_str()),
                description: format!(
                    "FRX-20.1 contract fixture for {} {}",
                    class.as_str(),
                    surface.as_str()
                ),
                test_class: *class,
                surfaces: BTreeSet::from([*surface]),
                provenance: class.min_provenance_level(),
                seed,
                content_hash: format!("sha256:frx20-{}-{}", class.as_str(), surface.as_str()),
                format_version: "frx.unit-fixture.v1".to_string(),
                origin_ref: "bd-mjh3.20.1".to_string(),
                tags: BTreeSet::from([class.as_str().to_string(), surface.as_str().to_string()]),
            };
            registry.register(entry).unwrap();
        }
    }

    assert!(registry.validate_all().is_empty());
    assert!(registry.coverage_gaps().is_empty());
}
