#![forbid(unsafe_code)]

use frankenengine_engine::hook_effect_contract::{
    FallbackExecutionRoute, HookKind, HookManifest, HookRuleViolation, HookSlot, HookSlotIndex,
    RenderPhase, UnsupportedSemanticsTrigger, build_unsupported_semantics_diagnostic,
    classify_unsupported_semantics, validate_hook_consistency,
};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "franken-engine.hook-effect-unsupported-semantics.scenario-log.v1";
const POLICY_ID: &str = "policy-frx-unsupported-semantics-v1";
const COMPONENT: &str = "hook_effect_fallback_contract";
const REPLAY_COMMAND: &str = "./scripts/e2e/frx_unsupported_semantics_fallback_rules_replay.sh ci";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScenarioLogEvent {
    schema_version: String,
    scenario_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    decision_path: String,
    trigger: String,
    fallback_route: String,
    outcome: String,
    error_code: Option<String>,
    hardening_guidance: String,
    replay_command: String,
}

fn make_slot(index: u32, kind: HookKind) -> HookSlot {
    HookSlot {
        index: HookSlotIndex(index),
        kind,
        deps: None,
    }
}

struct LogEventInput<'a> {
    scenario_id: &'a str,
    trace_id: &'a str,
    decision_id: &'a str,
    event: &'a str,
    decision_path: &'a str,
    trigger: UnsupportedSemanticsTrigger,
    route: FallbackExecutionRoute,
    outcome: &'a str,
    error_code: Option<&'a str>,
    hardening_guidance: &'a str,
}

fn log_event(input: LogEventInput<'_>) -> ScenarioLogEvent {
    ScenarioLogEvent {
        schema_version: SCHEMA_VERSION.to_string(),
        scenario_id: input.scenario_id.to_string(),
        trace_id: input.trace_id.to_string(),
        decision_id: input.decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: input.event.to_string(),
        decision_path: input.decision_path.to_string(),
        trigger: format!("{:?}", input.trigger),
        fallback_route: format!("{:?}", input.route),
        outcome: input.outcome.to_string(),
        error_code: input.error_code.map(str::to_string),
        hardening_guidance: input.hardening_guidance.to_string(),
        replay_command: REPLAY_COMMAND.to_string(),
    }
}

#[test]
fn unsupported_semantics_hook_topology_drift_fails_closed_with_compat_route() {
    let prev = HookManifest::new(
        "App",
        vec![
            make_slot(0, HookKind::State),
            make_slot(1, HookKind::Effect),
            make_slot(2, HookKind::Memo),
        ],
    );
    let curr = HookManifest::new("App", vec![make_slot(0, HookKind::State)]);

    let violations = validate_hook_consistency(&prev, &curr);
    assert_eq!(violations.len(), 1);
    let trigger = classify_unsupported_semantics(&violations[0]);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);

    let diagnostic = build_unsupported_semantics_diagnostic(
        "App",
        trigger,
        "trace-hook-topology-drift",
        "decision-hook-topology-drift",
    );
    assert!(diagnostic.compile_path_rejected);
    assert_eq!(
        diagnostic.fallback_route,
        FallbackExecutionRoute::CompatibilityRuntimeLane
    );
    assert_eq!(diagnostic.error_code, "FE-HOOK-UNSUPPORTED-0001");

    let event = log_event(LogEventInput {
        scenario_id: "unsupported_semantics_hook_topology_drift",
        trace_id: &diagnostic.trace_id,
        decision_id: &diagnostic.decision_id,
        event: "fallback_decision",
        decision_path: "validate_hook_consistency->fallback",
        trigger: diagnostic.trigger,
        route: diagnostic.fallback_route,
        outcome: "pass",
        error_code: Some(&diagnostic.error_code),
        hardening_guidance: &diagnostic.hardening_guidance,
    });

    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.outcome, "pass");
    assert_eq!(
        event.error_code.as_deref(),
        Some("FE-HOOK-UNSUPPORTED-0001")
    );
    assert_eq!(event.replay_command, REPLAY_COMMAND);
}

#[test]
fn unsupported_semantics_out_of_render_violation_uses_safe_mode_lane() {
    let violation = HookRuleViolation::HookOutsideRender {
        component: "Widget".to_string(),
        slot: HookSlotIndex(1),
        actual_phase: RenderPhase::Idle,
    };

    let trigger = classify_unsupported_semantics(&violation);
    assert_eq!(
        trigger,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution
    );

    let diagnostic = build_unsupported_semantics_diagnostic(
        "Widget",
        trigger,
        "trace-outside-render",
        "decision-outside-render",
    );

    assert!(diagnostic.compile_path_rejected);
    assert_eq!(
        diagnostic.fallback_route,
        FallbackExecutionRoute::DeterministicSafeModeLane
    );
    assert_eq!(diagnostic.error_code, "FE-HOOK-UNSUPPORTED-0003");
    assert!(diagnostic.hardening_guidance.contains("phase"));
}

#[test]
fn unsupported_semantics_same_input_yields_identical_diagnostic() {
    let d1 = build_unsupported_semantics_diagnostic(
        "Counter",
        UnsupportedSemanticsTrigger::TransformationProofMissing,
        "trace-proof-missing",
        "decision-proof-missing",
    );
    let d2 = build_unsupported_semantics_diagnostic(
        "Counter",
        UnsupportedSemanticsTrigger::TransformationProofMissing,
        "trace-proof-missing",
        "decision-proof-missing",
    );

    assert_eq!(d1, d2);
    assert_eq!(d1.derive_id(), d2.derive_id());
    assert_eq!(
        d1.fallback_route,
        FallbackExecutionRoute::BaselineInterpreterLane
    );
    assert_eq!(d1.error_code, "FE-HOOK-UNSUPPORTED-0006");
}
