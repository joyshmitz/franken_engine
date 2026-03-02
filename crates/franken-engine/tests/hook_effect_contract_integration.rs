#![forbid(unsafe_code)]

use frankenengine_engine::hook_effect_contract::{
    ComponentPhaseTracker, DepToken, EffectScheduler, EffectTiming, HookEffectContract, HookKind,
    HookManifest, HookManifestError, HookRuleViolation, HookSlot, HookSlotIndex, RenderPhase,
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

// ────────────────────────────────────────────────────────────
// Enrichment: serde, classification, validation, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn hook_kind_all_serde_round_trips() {
    for kind in HookKind::ALL {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: HookKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, &recovered);
    }
}

#[test]
fn hook_kind_has_effect_phase_classification() {
    let effect_kinds: Vec<HookKind> = HookKind::ALL
        .iter()
        .copied()
        .filter(|k| k.has_effect_phase())
        .collect();
    assert_eq!(effect_kinds.len(), 3);
    assert!(effect_kinds.contains(&HookKind::Effect));
    assert!(effect_kinds.contains(&HookKind::LayoutEffect));
    assert!(effect_kinds.contains(&HookKind::InsertionEffect));
}

#[test]
fn hook_kind_can_trigger_rerender_classification() {
    assert!(HookKind::State.can_trigger_rerender());
    assert!(HookKind::Reducer.can_trigger_rerender());
    assert!(HookKind::Context.can_trigger_rerender());
    assert!(!HookKind::Ref.can_trigger_rerender());
    assert!(!HookKind::Memo.can_trigger_rerender());
    assert!(!HookKind::DebugValue.can_trigger_rerender());
}

#[test]
fn hook_kind_has_dependency_array_classification() {
    assert!(HookKind::Effect.has_dependency_array());
    assert!(HookKind::LayoutEffect.has_dependency_array());
    assert!(HookKind::Memo.has_dependency_array());
    assert!(HookKind::Callback.has_dependency_array());
    assert!(!HookKind::State.has_dependency_array());
    assert!(!HookKind::Ref.has_dependency_array());
    assert!(!HookKind::Id.has_dependency_array());
}

#[test]
fn effect_timing_serde_round_trip() {
    for timing in [
        EffectTiming::Insertion,
        EffectTiming::Layout,
        EffectTiming::Passive,
    ] {
        let json = serde_json::to_string(&timing).expect("serialize");
        let recovered: EffectTiming = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(timing, recovered);
    }
}

#[test]
fn render_phase_legal_successors_cover_full_lifecycle() {
    let successors = RenderPhase::Rendering.legal_successors();
    assert!(successors.contains(&RenderPhase::InsertionEffectsPending));

    let idle_successors = RenderPhase::Idle.legal_successors();
    assert!(idle_successors.contains(&RenderPhase::Rendering));
}

#[test]
fn hook_manifest_validate_empty_returns_error() {
    let manifest = HookManifest::new("Empty", vec![]);
    let errors = manifest.validate();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, HookManifestError::EmptyManifest))
    );
}

#[test]
fn hook_manifest_validate_non_consecutive_indices_returns_error() {
    let manifest = HookManifest::new(
        "BadIndices",
        vec![
            make_slot(0, HookKind::State, None),
            make_slot(5, HookKind::Effect, Some(vec![])),
        ],
    );
    let errors = manifest.validate();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, HookManifestError::NonConsecutiveIndices { .. }))
    );
}

#[test]
fn hook_slot_index_ordering_is_numeric() {
    let a = HookSlotIndex(0);
    let b = HookSlotIndex(1);
    let c = HookSlotIndex(100);
    assert!(a < b);
    assert!(b < c);
}

#[test]
fn hook_rule_violation_count_mismatch_serde_round_trip() {
    let violation = HookRuleViolation::HookCountMismatch {
        component: "TestComp".to_string(),
        previous_count: 2,
        current_count: 3,
    };
    let json = serde_json::to_string(&violation).expect("serialize");
    let recovered: HookRuleViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(violation, recovered);
}
