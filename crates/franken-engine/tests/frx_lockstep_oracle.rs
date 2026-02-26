use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::frx_lockstep_oracle::{
    FrxDivergenceClass, FrxLockstepCaseInput, FrxLockstepRunContext, FrxObservableTrace,
    FrxTraceEvent, evaluate_case, run_lockstep_oracle,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build_trace(
    fixture_ref: &str,
    scenario_id: &str,
    trace_id: &str,
    events: Vec<FrxTraceEvent>,
) -> FrxObservableTrace {
    FrxObservableTrace {
        schema_version: "frx.react.observable.trace.v1".to_string(),
        trace_id: trace_id.to_string(),
        decision_id: format!("decision-{trace_id}"),
        policy_id: "policy-frx-react-corpus-v1".to_string(),
        component: "frx_react_corpus".to_string(),
        scenario_id: scenario_id.to_string(),
        fixture_ref: fixture_ref.to_string(),
        seed: 42,
        events,
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn event(seq: u64, phase: &str, event: &str, decision_path: &str, timing_us: u64) -> FrxTraceEvent {
    FrxTraceEvent {
        seq,
        phase: phase.to_string(),
        actor: "Harness".to_string(),
        event: event.to_string(),
        decision_path: decision_path.to_string(),
        timing_us,
        outcome: "ok".to_string(),
    }
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("frx_lockstep_oracle_{prefix}_{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_trace_file(dir: &Path, fixture_ref: &str, trace: &FrxObservableTrace) {
    let path = dir.join(format!("{fixture_ref}.trace.json"));
    let json = serde_json::to_string_pretty(trace).expect("serialize trace");
    fs::write(path, json).expect("write trace");
}

#[test]
fn evaluate_case_identical_traces_passes() {
    let fixture_ref = "compat.render.dom_snapshot_basic";
    let scenario_id = "frx-react-test-001";
    let events = vec![
        event(1, "render", "dom_commit", "render_path", 100),
        event(2, "effects", "effect_cleanup", "effect_path", 140),
    ];

    let react_trace = build_trace(fixture_ref, scenario_id, "trace-react-001", events.clone());
    let franken_trace = build_trace(fixture_ref, scenario_id, "trace-franken-001", events);

    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: fixture_ref.to_string(),
        scenario_id: scenario_id.to_string(),
        react_trace,
        franken_trace,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("case should evaluate");

    assert!(result.pass);
    assert!(result.divergence.is_none());
}

#[test]
fn evaluate_case_classifies_hydration_drift() {
    let fixture_ref = "compat.hydration.server_client_mismatch";
    let scenario_id = "frx-react-test-002";

    let react_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-react-002",
        vec![
            event(1, "hydrate", "server_markup_loaded", "hydrate_path", 100),
            event(2, "hydrate", "mismatch_detected:text", "hydrate_path", 120),
        ],
    );
    let franken_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-franken-002",
        vec![
            event(1, "hydrate", "server_markup_loaded", "hydrate_path", 100),
            event(2, "hydrate", "recover_client_render", "hydrate_path", 120),
        ],
    );

    let result = evaluate_case(FrxLockstepCaseInput {
        fixture_ref: fixture_ref.to_string(),
        scenario_id: scenario_id.to_string(),
        react_trace,
        franken_trace,
        react_trace_path: None,
        franken_trace_path: None,
    })
    .expect("case should evaluate");

    assert!(!result.pass);
    let divergence = result.divergence.expect("divergence should be present");
    assert_eq!(divergence.class, FrxDivergenceClass::HydrationOutcome);
    assert_eq!(divergence.event_index, Some(1));
}

#[test]
fn run_lockstep_oracle_corpus_self_compare_is_green() {
    let traces_dir =
        repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces");
    let report = run_lockstep_oracle(
        traces_dir.as_path(),
        traces_dir.as_path(),
        FrxLockstepRunContext::deterministic(
            "trace-frx-lockstep-test-corpus",
            "decision-frx-lockstep-test-corpus",
            "policy-frx-lockstep-test-corpus",
        ),
        None,
    )
    .expect("oracle run should succeed");

    let total_cases = report.case_results.len() as u64;
    assert!(
        total_cases >= 10,
        "expected canonical corpus to include at least 10 fixtures"
    );
    assert_eq!(report.summary.total_cases, total_cases);
    assert_eq!(report.summary.failed_cases, 0);
    assert_eq!(report.summary.pass_cases, total_cases);
    assert!(report.case_results.iter().all(|result| result.pass));
    assert!(
        report
            .case_results
            .iter()
            .any(|result| result.fixture_ref.starts_with("compat.hydration"))
    );
}

#[test]
fn run_lockstep_oracle_marks_missing_candidate_trace_as_schema_violation() {
    let react_dir = unique_temp_dir("react");
    let franken_dir = unique_temp_dir("franken");

    let fixture_ref = "compat.custom.synthetic";
    let scenario_id = "frx-react-synthetic-001";
    let react_trace = build_trace(
        fixture_ref,
        scenario_id,
        "trace-react-synthetic",
        vec![event(1, "render", "dom_commit", "render_path", 100)],
    );
    write_trace_file(react_dir.as_path(), fixture_ref, &react_trace);

    let report = run_lockstep_oracle(
        react_dir.as_path(),
        franken_dir.as_path(),
        FrxLockstepRunContext::deterministic(
            "trace-frx-lockstep-test-missing",
            "decision-frx-lockstep-test-missing",
            "policy-frx-lockstep-test-missing",
        ),
        None,
    )
    .expect("oracle run should still succeed with failed case");

    assert_eq!(report.summary.total_cases, 1);
    assert_eq!(report.summary.failed_cases, 1);
    let case = &report.case_results[0];
    assert!(!case.pass);
    assert_eq!(
        case.divergence.as_ref().expect("divergence expected").class,
        FrxDivergenceClass::SchemaViolation
    );
}
