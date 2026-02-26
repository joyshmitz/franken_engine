#![forbid(unsafe_code)]

use frankenengine_engine::hook_effect_contract::{
    ComponentPhaseTracker, DepToken, EffectScheduler, EffectTiming, HookEffectContract, HookKind,
    HookManifest, HookRuleViolation, HookSlot, HookSlotIndex, RenderPhase,
    validate_hook_consistency,
};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "franken-engine.hook-effect-contract.scenario-log.v1";
const POLICY_ID: &str = "policy-frx-hook-effect-contract-v1";
const COMPONENT: &str = "hook_effect_contract";
const REPLAY_COMMAND: &str = "./scripts/e2e/frx_hook_effect_semantics_contract_replay.sh ci";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScenarioLogEvent {
    schema_version: String,
    scenario_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    seed: u64,
    timing: String,
    decision_path: String,
    outcome: String,
    error_code: Option<String>,
    replay_command: String,
}

fn make_slot(index: u32, kind: HookKind, deps: Option<Vec<DepToken>>) -> HookSlot {
    HookSlot {
        index: HookSlotIndex(index),
        kind,
        deps,
    }
}

struct LogEventInput<'a> {
    scenario_id: &'a str,
    trace_id: &'a str,
    decision_id: &'a str,
    seed: u64,
    event: &'a str,
    timing: &'a str,
    decision_path: &'a str,
    outcome: &'a str,
    error_code: Option<&'a str>,
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
        seed: input.seed,
        timing: input.timing.to_string(),
        decision_path: input.decision_path.to_string(),
        outcome: input.outcome.to_string(),
        error_code: input.error_code.map(str::to_string),
        replay_command: REPLAY_COMMAND.to_string(),
    }
}

fn run_happy_path(seed: u64, trace_id: &str) -> Vec<ScenarioLogEvent> {
    let scenario_id = "hook_effect_happy_path";
    let decision_id = format!("decision-{scenario_id}-{seed}");
    let mut events = Vec::new();

    let manifest = HookManifest::new(
        "App",
        vec![
            make_slot(0, HookKind::State, None),
            make_slot(1, HookKind::InsertionEffect, Some(vec![])),
            make_slot(2, HookKind::LayoutEffect, Some(vec![DepToken(1)])),
            make_slot(3, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    );
    assert!(manifest.validate().is_empty());

    let mut contract = HookEffectContract::new();
    contract.register_manifest(manifest);
    assert_eq!(contract.effect_hook_count(), 3);

    let mut scheduler = EffectScheduler::new();
    scheduler.enqueue(frankenengine_engine::hook_effect_contract::PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(1),
        timing: EffectTiming::Insertion,
        tree_order: 1,
        is_cleanup: false,
    });
    scheduler.enqueue(frankenengine_engine::hook_effect_contract::PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(2),
        timing: EffectTiming::Layout,
        tree_order: 1,
        is_cleanup: false,
    });
    scheduler.enqueue(frankenengine_engine::hook_effect_contract::PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(3),
        timing: EffectTiming::Passive,
        tree_order: 1,
        is_cleanup: false,
    });

    let mut tracker = ComponentPhaseTracker::new("App");
    tracker.transition_to(RenderPhase::Rendering).unwrap();
    tracker
        .transition_to(RenderPhase::InsertionEffectsPending)
        .unwrap();
    let (insertion_cleanups, insertion_creates) =
        scheduler.drain_for_timing(EffectTiming::Insertion);
    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "drain_insertion",
        timing: "insertion",
        decision_path: "render->insertion",
        outcome: "pass",
        error_code: None,
    }));
    assert_eq!(insertion_cleanups.len() + insertion_creates.len(), 1);

    tracker
        .transition_to(RenderPhase::LayoutEffectsPending)
        .unwrap();
    let (layout_cleanups, layout_creates) = scheduler.drain_for_timing(EffectTiming::Layout);
    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "drain_layout",
        timing: "layout",
        decision_path: "insertion->layout",
        outcome: "pass",
        error_code: None,
    }));
    assert_eq!(layout_cleanups.len() + layout_creates.len(), 1);

    tracker.transition_to(RenderPhase::PaintPending).unwrap();
    tracker
        .transition_to(RenderPhase::PassiveEffectsPending)
        .unwrap();
    let (passive_cleanups, passive_creates) = scheduler.drain_for_timing(EffectTiming::Passive);
    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "drain_passive",
        timing: "passive",
        decision_path: "paint->passive",
        outcome: "pass",
        error_code: None,
    }));
    assert_eq!(passive_cleanups.len() + passive_creates.len(), 1);

    tracker.transition_to(RenderPhase::Idle).unwrap();
    assert_eq!(tracker.render_count, 1);
    assert_eq!(scheduler.pending_count(), 0);

    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "cycle_complete",
        timing: "none",
        decision_path: "passive->idle",
        outcome: "pass",
        error_code: None,
    }));

    events
}

#[test]
fn hook_effect_contract_happy_path_emits_structured_logs() {
    let events = run_happy_path(41, "trace-hook-effect-happy-path");
    assert_eq!(events.len(), 4);
    assert!(
        events
            .iter()
            .all(|event| event.schema_version == SCHEMA_VERSION)
    );
    assert!(
        events
            .iter()
            .all(|event| event.replay_command == REPLAY_COMMAND)
    );
    assert!(events.iter().all(|event| !event.trace_id.is_empty()));
    assert!(events.iter().all(|event| !event.scenario_id.is_empty()));
    assert!(events.iter().all(|event| !event.decision_path.is_empty()));
    assert!(events.iter().all(|event| event.outcome == "pass"));
    assert!(events.iter().all(|event| event.error_code.is_none()));

    let jsonl = events
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");

    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        for key in [
            "schema_version",
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
            "replay_command",
        ] {
            assert!(value.get(key).is_some(), "missing structured field: {key}");
        }
    }
}

#[test]
fn hook_effect_contract_adversarial_count_drift_fails_closed_with_log() {
    let scenario_id = "hook_effect_adversarial_count_drift";
    let trace_id = "trace-hook-effect-count-drift";
    let decision_id = "decision-hook-effect-count-drift";
    let seed = 7_u64;

    let prev = HookManifest::new("App", vec![make_slot(0, HookKind::State, None)]);
    let curr = HookManifest::new(
        "App",
        vec![
            make_slot(0, HookKind::State, None),
            make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    );

    let violations = validate_hook_consistency(&prev, &curr);
    assert!(
        violations
            .iter()
            .any(|violation| matches!(violation, HookRuleViolation::HookCountMismatch { .. }))
    );

    let failure_event = log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id,
        seed,
        event: "consistency_validation",
        timing: "rendering",
        decision_path: "validate_hook_consistency",
        outcome: "fail",
        error_code: Some("FE-HOOK-EFFECT-CONTRACT-COUNT-MISMATCH"),
    });

    assert_eq!(failure_event.outcome, "fail");
    assert_eq!(
        failure_event.error_code.as_deref(),
        Some("FE-HOOK-EFFECT-CONTRACT-COUNT-MISMATCH")
    );
}

#[test]
fn hook_effect_contract_same_seed_is_deterministic() {
    let first = run_happy_path(99, "trace-hook-effect-determinism");
    let second = run_happy_path(99, "trace-hook-effect-determinism");
    assert_eq!(first, second);
}
