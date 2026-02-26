#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

const STRATEGY_SCHEMA_VERSION: &str = "frx.ssr-hydration-rsc-compatibility-strategy.v1";
const STRATEGY_JSON: &str =
    include_str!("../../../docs/frx_ssr_hydration_rsc_compatibility_strategy_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct StrategyContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: StrategyTrack,
    required_structured_log_fields: Vec<String>,
    strategy: StrategyPolicy,
    scenarios: Vec<StrategyScenario>,
    known_divergences: Vec<KnownDivergence>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct StrategyTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct StrategyPolicy {
    failure_mode: String,
    default_fallback_route: String,
    deterministic_safe_mode_route: String,
    require_hydration_boundary_equivalence: bool,
    require_explicit_rsc_routing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct StrategyScenario {
    scenario_id: String,
    fixture_ref: String,
    category: String,
    runtime_mode: String,
    expected_policy_action: String,
    expected_outcome: String,
    divergence_class: String,
    decision_path: String,
    structured_log_template: StructuredLogTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct StructuredLogTemplate {
    scenario_id: String,
    component: String,
    decision_path: String,
    outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct KnownDivergence {
    fixture_ref: String,
    divergence_summary: String,
    fallback_route: String,
    mitigation_plan: String,
    owner_lane: String,
    blocking_issue: String,
    error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FixtureSpec {
    schema_version: String,
    scenario_id: String,
    fixture_ref: String,
    runtime_mode: String,
    semantic_focus: Vec<String>,
    expected_observable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ObservableTrace {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    scenario_id: String,
    fixture_ref: String,
    seed: u64,
    events: Vec<TraceEvent>,
    outcome: String,
    error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TraceEvent {
    seq: u64,
    phase: String,
    actor: String,
    event: String,
    decision_path: String,
    timing_us: u64,
    outcome: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_strategy() -> StrategyContract {
    serde_json::from_str(STRATEGY_JSON)
        .expect("SSR/hydration/RSC compatibility strategy JSON must parse")
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn fixture_path(fixture_ref: &str) -> PathBuf {
    repo_root().join(format!(
        "crates/franken-engine/tests/conformance/frx_react_corpus/fixtures/{fixture_ref}.fixture.json"
    ))
}

fn trace_path(fixture_ref: &str) -> PathBuf {
    repo_root().join(format!(
        "crates/franken-engine/tests/conformance/frx_react_corpus/traces/{fixture_ref}.trace.json"
    ))
}

#[test]
fn frx_07_2_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_SSR_HYDRATION_RSC_COMPATIBILITY_STRATEGY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX SSR/Hydration/RSC Compatibility Strategy V1",
        "## Scope",
        "## SSR Render Contract",
        "## Hydration Boundary Equivalence Rules",
        "## RSC Interaction Routing and Fallback Policy",
        "## Known Divergences and Mitigation Plan",
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

    let doc_lower = doc.to_ascii_lowercase();
    for phrase in [
        "fail-closed",
        "deterministic",
        "hydration",
        "server",
        "stream",
        "rsc",
        "fallback",
    ] {
        assert!(
            doc_lower.contains(phrase),
            "missing strategy phrase in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_07_2_contract_is_machine_readable_and_track_bound() {
    let strategy = parse_strategy();

    assert_eq!(strategy.schema_version, STRATEGY_SCHEMA_VERSION);
    assert_eq!(strategy.bead_id, "bd-mjh3.7.2");
    assert_eq!(strategy.generated_by, "bd-mjh3.7.2");
    assert_eq!(strategy.track.id, "FRX-07.2");
    assert_eq!(
        strategy.track.name,
        "SSR/Hydration/RSC Compatibility Strategy"
    );
    assert!(strategy.generated_at_utc.ends_with('Z'));

    assert_eq!(strategy.strategy.failure_mode, "fail_closed");
    assert_eq!(
        strategy.strategy.default_fallback_route,
        "compatibility_fallback"
    );
    assert_eq!(
        strategy.strategy.deterministic_safe_mode_route,
        "deterministic_safe_mode"
    );
    assert!(strategy.strategy.require_hydration_boundary_equivalence);
    assert!(strategy.strategy.require_explicit_rsc_routing);
}

#[test]
fn frx_07_2_required_scenarios_are_declared_and_fail_closed() {
    let strategy = parse_strategy();

    let scenario_index: BTreeMap<_, _> = strategy
        .scenarios
        .iter()
        .map(|scenario| (scenario.fixture_ref.as_str(), scenario))
        .collect();

    for fixture_ref in [
        "compat.hydration.server_client_mismatch",
        "compat.ssr.streaming.suspense_handoff",
        "compat.rsc.server_component_hook_violation",
    ] {
        assert!(
            scenario_index.contains_key(fixture_ref),
            "missing required strategy scenario for fixture {fixture_ref}"
        );
    }

    let allowed_modes: BTreeSet<&str> = ["client", "server", "hydrate", "hydration"]
        .into_iter()
        .collect();
    let allowed_outcomes: BTreeSet<&str> = ["pass", "fallback"].into_iter().collect();

    for scenario in &strategy.scenarios {
        assert!(
            allowed_modes.contains(scenario.runtime_mode.as_str()),
            "invalid runtime_mode for {}: {}",
            scenario.fixture_ref,
            scenario.runtime_mode
        );
        assert!(
            allowed_outcomes.contains(scenario.expected_outcome.as_str()),
            "invalid expected_outcome for {}: {}",
            scenario.fixture_ref,
            scenario.expected_outcome
        );
        assert!(!scenario.category.trim().is_empty());
        assert!(!scenario.decision_path.trim().is_empty());
        assert!(!scenario.divergence_class.trim().is_empty());

        let template = &scenario.structured_log_template;
        assert!(template.scenario_id.starts_with("frx-07.2-"));
        assert_eq!(
            template.component,
            "frx_ssr_hydration_rsc_compatibility_strategy"
        );
        assert_eq!(template.decision_path, scenario.decision_path);
        assert_eq!(template.outcome, scenario.expected_outcome);

        if scenario.expected_outcome == "fallback" {
            assert_ne!(scenario.expected_policy_action, "native");
        }
    }
}

#[test]
fn frx_07_2_fixtures_and_traces_match_strategy_scenarios() {
    let strategy = parse_strategy();

    for scenario in &strategy.scenarios {
        let fixture: FixtureSpec = load_json(&fixture_path(&scenario.fixture_ref));
        let trace: ObservableTrace = load_json(&trace_path(&scenario.fixture_ref));

        assert_eq!(fixture.schema_version, "frx.react.fixture.v1");
        assert_eq!(fixture.fixture_ref, scenario.fixture_ref);
        assert_eq!(fixture.scenario_id, scenario.scenario_id);
        assert_eq!(fixture.runtime_mode, scenario.runtime_mode);
        assert!(!fixture.semantic_focus.is_empty());
        assert!(!fixture.expected_observable.is_empty());

        assert_eq!(trace.schema_version, "frx.react.observable.trace.v1");
        assert_eq!(trace.component, "frx_react_corpus");
        assert_eq!(trace.fixture_ref, scenario.fixture_ref);
        assert_eq!(trace.scenario_id, scenario.scenario_id);
        assert!(trace.trace_id.starts_with("trace-frx-react-"));
        assert!(trace.decision_id.starts_with("decision-frx-react-"));
        assert!(trace.policy_id.starts_with("policy-frx-react-corpus-v"));
        assert!(trace.seed > 0);
        assert_eq!(trace.outcome, scenario.expected_outcome);
        assert!(!trace.events.is_empty());

        let mut prev_seq = 0_u64;
        let mut prev_timing = 0_u64;
        for event in &trace.events {
            assert!(event.seq > prev_seq, "trace seq must increase");
            assert!(
                event.timing_us >= prev_timing,
                "trace timing must be monotonic"
            );
            assert!(!event.phase.trim().is_empty());
            assert!(!event.actor.trim().is_empty());
            assert!(!event.event.trim().is_empty());
            assert!(!event.decision_path.trim().is_empty());
            assert!(!event.outcome.trim().is_empty());
            prev_seq = event.seq;
            prev_timing = event.timing_us;
        }

        assert!(
            trace
                .events
                .iter()
                .any(|event| event.decision_path == scenario.decision_path),
            "trace for {} must include strategy decision_path {}",
            scenario.fixture_ref,
            scenario.decision_path
        );

        if trace.outcome == "pass" {
            assert!(
                trace.error_code.is_none(),
                "pass traces must not carry error_code for {}",
                scenario.fixture_ref
            );
        }
    }
}

#[test]
fn frx_07_2_hydration_mismatch_routes_to_deterministic_recovery() {
    let trace: ObservableTrace = load_json(&trace_path("compat.hydration.server_client_mismatch"));

    assert_eq!(trace.outcome, "pass");
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event.contains("mismatch_detected")),
        "hydration mismatch trace must include mismatch detection event"
    );
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event.contains("recover_client_render")),
        "hydration mismatch trace must include deterministic recovery event"
    );
}

#[test]
fn frx_07_2_ssr_streaming_handoff_preserves_suspense_order() {
    let trace: ObservableTrace = load_json(&trace_path("compat.ssr.streaming.suspense_handoff"));

    assert_eq!(trace.outcome, "pass");

    let events: Vec<&str> = trace
        .events
        .iter()
        .map(|event| event.event.as_str())
        .collect();
    assert_eq!(events[0], "stream_start");
    assert_eq!(events[1], "flush_shell");
    assert_eq!(events[2], "deferred_chunk_resolved");
    assert_eq!(events[3], "handoff_committed");
}

#[test]
fn frx_07_2_rsc_violation_is_fail_closed_to_safe_mode() {
    let trace: ObservableTrace =
        load_json(&trace_path("compat.rsc.server_component_hook_violation"));

    assert_eq!(trace.outcome, "fallback");
    assert_eq!(trace.error_code.as_deref(), Some("FE-FRX-07-2-RSC-0001"));
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event == "disallowed_client_hook_detected"),
        "RSC fallback trace must include capability-gap detection"
    );
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event == "route_deterministic_safe_mode_fallback"),
        "RSC fallback trace must include deterministic safe-mode routing"
    );
}

#[test]
fn frx_07_2_known_divergences_are_traceable_and_routed() {
    let strategy = parse_strategy();

    let scenario_by_fixture: BTreeMap<_, _> = strategy
        .scenarios
        .iter()
        .map(|scenario| (scenario.fixture_ref.as_str(), scenario))
        .collect();

    assert!(!strategy.known_divergences.is_empty());

    for divergence in &strategy.known_divergences {
        let scenario = scenario_by_fixture
            .get(divergence.fixture_ref.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "unknown fixture_ref in known_divergences: {}",
                    divergence.fixture_ref
                )
            });

        assert!(!divergence.divergence_summary.trim().is_empty());
        assert!(!divergence.mitigation_plan.trim().is_empty());
        assert!(!divergence.owner_lane.trim().is_empty());
        assert!(divergence.blocking_issue.starts_with("bd-mjh3."));
        assert!(divergence.error_code.starts_with("FE-FRX-07-2-DIV-"));

        if scenario.expected_outcome == "fallback" {
            assert!(
                divergence.fallback_route == "compatibility_fallback"
                    || divergence.fallback_route == "deterministic_safe_mode",
                "fallback scenario must route to deterministic fallback surface"
            );
        }
    }
}

#[test]
fn frx_07_2_structured_log_fields_and_operator_commands_are_present() {
    let strategy = parse_strategy();

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

    let actual_fields: BTreeSet<&str> = strategy
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    assert!(
        strategy.operator_verification.iter().any(|entry| {
            entry.contains("run_frx_ssr_hydration_rsc_compatibility_strategy_suite.sh ci")
        }),
        "operator verification must include CI gate command"
    );
    assert!(
        strategy.operator_verification.iter().any(|entry| {
            entry.contains("frx_ssr_hydration_rsc_compatibility_strategy_replay.sh")
        }),
        "operator verification must include replay command"
    );
    assert!(
        strategy.operator_verification.iter().any(|entry| {
            entry.contains("jq empty docs/frx_ssr_hydration_rsc_compatibility_strategy_v1.json")
        }),
        "operator verification must include JSON validation command"
    );
}

#[test]
fn frx_07_2_readme_registers_gate_commands() {
    let readme_path = repo_root().join("README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", readme_path.display()));

    for marker in [
        "## FRX SSR/Hydration/RSC Compatibility Strategy Gate",
        "./scripts/run_frx_ssr_hydration_rsc_compatibility_strategy_suite.sh ci",
        "./scripts/e2e/frx_ssr_hydration_rsc_compatibility_strategy_replay.sh ci",
        "artifacts/frx_ssr_hydration_rsc_compatibility_strategy/<timestamp>/run_manifest.json",
    ] {
        assert!(
            readme.contains(marker),
            "README missing FRX-07.2 marker: {marker}"
        );
    }
}
