use std::{collections::BTreeSet, fs, path::PathBuf};

#[path = "../src/unit_test_taxonomy.rs"]
mod unit_test_taxonomy;

use serde_json::Value;
use unit_test_taxonomy::{
    LaneId, REQUIRED_STRUCTURED_LOG_FIELDS, UnitTestClass, default_frx20_bundle,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_20_1_doc_has_required_sections() {
    let path = repo_root().join("docs/FRX_UNIT_TEST_TAXONOMY_FIXTURE_REGISTRY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Unit-Test Taxonomy and Fixture Registry v1",
        "## Scope",
        "## Unit-Test Taxonomy",
        "## Fixture Registry Contract",
        "## Determinism Contract",
        "## Lane Ownership and Coverage Mapping",
        "## Structured Logging and Artifact Retention",
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
fn frx_20_1_contract_is_machine_readable_and_versioned() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_fixture_registry_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.unit-test-taxonomy.v1")
    );
    assert_eq!(value["bead_id"].as_str(), Some("bd-mjh3.20.1"));
    assert_eq!(
        value["fixture_registry_schema_version"].as_str(),
        Some("frx.fixture-registry.v1")
    );
    assert_eq!(
        value["determinism_contract"]["schema_version"].as_str(),
        Some("frx.test-determinism-contract.v1")
    );

    assert_eq!(
        value["determinism_contract"]["require_seed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["determinism_contract"]["require_seed_transcript_checksum"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["determinism_contract"]["require_toolchain_fingerprint"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["determinism_contract"]["require_replay_command"].as_bool(),
        Some(true)
    );
}

#[test]
fn frx_20_1_runtime_bundle_validates() {
    let bundle = default_frx20_bundle();
    assert_eq!(bundle.validate_for_gate(), Ok(()));
}

#[test]
fn frx_20_1_lane_coverage_is_complete() {
    let bundle = default_frx20_bundle();

    let seen_lanes: BTreeSet<_> = bundle.lane_coverage.iter().map(|entry| entry.lane).collect();
    for lane in LaneId::ALL {
        assert!(
            seen_lanes.contains(&lane),
            "missing lane coverage for {}",
            lane.as_str()
        );
    }

    for entry in &bundle.lane_coverage {
        assert!(
            !entry.required_unit_classes.is_empty(),
            "lane {} missing required unit classes",
            entry.lane.as_str()
        );
        assert!(
            !entry.mapped_e2e_families.is_empty(),
            "lane {} missing e2e family mapping",
            entry.lane.as_str()
        );
    }
}

#[test]
fn frx_20_1_fixture_registry_points_to_existing_assets() {
    let bundle = default_frx20_bundle();

    for fixture in &bundle.fixture_registry {
        let fixture_path = repo_root().join(&fixture.fixture_path);
        assert!(
            fixture_path.exists(),
            "fixture path does not exist for {}: {}",
            fixture.fixture_id,
            fixture_path.display()
        );

        if let Some(trace_path) = &fixture.trace_path {
            let trace = repo_root().join(trace_path);
            assert!(
                trace.exists(),
                "trace path does not exist for {}: {}",
                fixture.fixture_id,
                trace.display()
            );
        }

        let provenance = repo_root().join(&fixture.provenance);
        assert!(
            provenance.exists(),
            "provenance path does not exist for {}: {}",
            fixture.fixture_id,
            provenance.display()
        );
    }
}

#[test]
fn frx_20_1_registry_requires_all_structured_log_fields() {
    let bundle = default_frx20_bundle();

    for fixture in &bundle.fixture_registry {
        let present: BTreeSet<&str> = fixture
            .structured_log_fields
            .iter()
            .map(String::as_str)
            .collect();

        for field in REQUIRED_STRUCTURED_LOG_FIELDS {
            assert!(
                present.contains(field),
                "fixture {} missing required structured log field {}",
                fixture.fixture_id,
                field
            );
        }
    }
}

#[test]
fn frx_20_1_all_test_classes_appear_in_lane_requirements() {
    let bundle = default_frx20_bundle();

    let mut seen = BTreeSet::new();
    for coverage in &bundle.lane_coverage {
        for class in &coverage.required_unit_classes {
            seen.insert(*class);
        }
    }

    for class in UnitTestClass::ALL {
        assert!(
            seen.contains(&class),
            "unit test class {} not represented in any lane coverage",
            class.as_str()
        );
    }
}

#[test]
fn frx_20_1_operator_verification_commands_present() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_fixture_registry_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    let commands = value["operator_verification"]
        .as_array()
        .expect("operator_verification should be an array");

    assert!(
        commands.iter().any(|cmd| {
            cmd.as_str().is_some_and(|line| {
                line.contains("run_frx_unit_test_taxonomy_fixture_registry_gate.sh ci")
            })
        }),
        "operator verification must include CI gate command"
    );

    assert!(
        commands.iter().any(|cmd| {
            cmd.as_str().is_some_and(|line| {
                line.contains("frx_unit_test_taxonomy_fixture_registry_replay.sh")
            })
        }),
        "operator verification must include replay command"
    );
}
