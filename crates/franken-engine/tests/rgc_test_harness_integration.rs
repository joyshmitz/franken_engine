#![forbid(unsafe_code)]
//! Integration tests for shared deterministic RGC test harness utilities.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::rgc_test_harness::{
    BaselineScenarioDomain, BaselineScenarioOutcome,
    DeterministicTestContext, EventInput, HarnessLane, HarnessRunManifest,
    RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION, RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION,
    baseline_e2e_scenario_registry, load_json_fixture, select_baseline_e2e_scenarios,
    validate_artifact_triad, write_artifact_triad,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DemoFixture {
    scenario_id: String,
    expected_lane: String,
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_{label}_{nanos}_{}",
        std::process::id()
    ))
}

#[test]
fn rgc_harness_event_contains_required_correlation_keys() {
    let context = DeterministicTestContext::new(
        "rgc-052-runtime-smoke",
        "fixture-runtime-smoke",
        HarnessLane::Runtime,
        77,
    );
    let event = context.event(EventInput {
        sequence: 3,
        component: "runtime_lane",
        event: "execute",
        outcome: "pass",
        error_code: None,
        timing_us: 105,
        timestamp_unix_ms: 1_700_000_100_123,
    });

    assert_eq!(
        event.schema_version, RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION,
        "event schema must stay stable for downstream validators"
    );
    assert_eq!(event.scenario_id, "rgc-052-runtime-smoke");
    assert_eq!(event.fixture_id, "fixture-runtime-smoke");
    assert_eq!(event.trace_id, context.trace_id);
    assert_eq!(event.decision_id, context.decision_id);
    assert_eq!(event.policy_id, context.policy_id);
    assert_eq!(event.seed, 77);
}

#[test]
fn rgc_harness_fixture_load_and_artifact_triad_round_trip() {
    let root = temp_dir("rgc_harness_roundtrip");
    let fixtures_root = root.join("fixtures");
    fs::create_dir_all(&fixtures_root).expect("create fixture root");

    let fixture_path = fixtures_root.join("runtime_smoke.json");
    fs::write(
        &fixture_path,
        r#"{"scenario_id":"rgc-052-runtime-smoke","expected_lane":"runtime"}"#,
    )
    .expect("write fixture");

    let fixture: DemoFixture = load_json_fixture(&fixtures_root, "runtime_smoke.json")
        .expect("fixture loader should parse deterministic JSON fixture");
    assert_eq!(fixture.scenario_id, "rgc-052-runtime-smoke");
    assert_eq!(fixture.expected_lane, "runtime");

    let context = DeterministicTestContext::new(
        fixture.scenario_id.clone(),
        "runtime_smoke",
        HarnessLane::Runtime,
        7,
    );
    let run_id = context.default_run_id();

    let events = vec![
        context.event(EventInput {
            sequence: 0,
            component: "fixture_loader",
            event: "fixture_loaded",
            outcome: "pass",
            error_code: None,
            timing_us: 40,
            timestamp_unix_ms: 1_700_000_200_010,
        }),
        context.event(EventInput {
            sequence: 1,
            component: "runtime_lane",
            event: "semantic_assertions_complete",
            outcome: "pass",
            error_code: None,
            timing_us: 90,
            timestamp_unix_ms: 1_700_000_200_100,
        }),
    ];
    let commands = vec![
        "cargo check -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
    ];
    let manifest = HarnessRunManifest::from_context(
        &context,
        run_id,
        events.len(),
        commands.len(),
        "./scripts/e2e/rgc_test_harness_replay.sh ci",
        1_700_000_200_500,
    );

    let artifacts_root = root.join("artifacts");
    let triad = write_artifact_triad(&artifacts_root, &manifest, &events, &commands)
        .expect("artifact triad should be emitted");
    assert!(triad.manifest_path.exists());
    assert!(triad.events_path.exists());
    assert!(triad.commands_path.exists());

    let saved_manifest: HarnessRunManifest = serde_json::from_str(
        &fs::read_to_string(&triad.manifest_path).expect("read saved manifest"),
    )
    .expect("parse saved manifest");
    assert_eq!(
        saved_manifest.schema_version,
        RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(saved_manifest.event_count, 2);
    assert_eq!(saved_manifest.command_count, 2);
}

#[test]
fn rgc_harness_fixture_loader_rejects_escape_paths() {
    let fixtures_root = temp_dir("rgc_harness_escape");
    fs::create_dir_all(&fixtures_root).expect("create fixture root");

    let error = load_json_fixture::<DemoFixture>(&fixtures_root, "../secrets.json")
        .expect_err("escape path must fail");
    let message = error.to_string();
    assert!(
        message.contains("must not escape root"),
        "unexpected error message: {message}"
    );
}

#[test]
fn rgc_baseline_registry_selection_and_validator_cover_representative_lanes() {
    let registry = baseline_e2e_scenario_registry();
    assert_eq!(registry.len(), 6, "expected runtime/module/security happy+failure");
    assert!(registry.iter().any(|scenario| {
        scenario.domain == BaselineScenarioDomain::Runtime
            && scenario.outcome == BaselineScenarioOutcome::CanonicalFailure
    }));
    assert!(registry.iter().any(|scenario| {
        scenario.domain == BaselineScenarioDomain::Module
            && scenario.outcome == BaselineScenarioOutcome::HappyPath
    }));
    assert!(registry.iter().any(|scenario| {
        scenario.domain == BaselineScenarioDomain::Security
            && scenario.outcome == BaselineScenarioOutcome::CanonicalFailure
    }));

    let selected = select_baseline_e2e_scenarios(
        &[BaselineScenarioDomain::Runtime, BaselineScenarioDomain::Security],
        true,
    );
    assert_eq!(selected.len(), 4);
    let selected_repeat = select_baseline_e2e_scenarios(
        &[BaselineScenarioDomain::Runtime, BaselineScenarioDomain::Security],
        true,
    );
    assert_eq!(selected, selected_repeat, "selection order must be deterministic");

    let root = temp_dir("rgc_baseline_validator");
    for (lane, scenario_id, fixture_id, component, event, error_code) in [
        (
            HarnessLane::Runtime,
            "rgc-053a-runtime-happy",
            "runtime-smoke-happy",
            "runtime_lane",
            "execute_runtime_smoke",
            None,
        ),
        (
            HarnessLane::Security,
            "rgc-053a-security-failure",
            "security-smoke-failure",
            "security_guardplane",
            "containment_triggered",
            Some("FE-RGC-053A-SECURITY-0001"),
        ),
        (
            HarnessLane::E2e,
            "rgc-053a-module-happy",
            "module-smoke-happy",
            "module_loader",
            "resolve_graph",
            None,
        ),
    ] {
        let context = DeterministicTestContext::new(scenario_id, fixture_id, lane, 53);
        let run_id = context.default_run_id();
        let events = vec![context.event(EventInput {
            sequence: 0,
            component,
            event,
            outcome: if error_code.is_some() { "fail" } else { "pass" },
            error_code,
            timing_us: 77,
            timestamp_unix_ms: 1_700_100_200_000,
        })];
        let commands = vec![
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_test_harness_replay.sh ci",
            1_700_100_200_100,
        );

        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("artifact triad should be emitted");
        let validation = validate_artifact_triad(&triad.run_dir);
        assert!(
            validation.valid,
            "expected valid triad for lane {lane}, findings: {:?}",
            validation.findings
        );
    }
}
