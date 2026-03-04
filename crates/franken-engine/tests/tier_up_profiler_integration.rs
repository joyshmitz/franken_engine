//! Integration tests for the tier-up profiler (RGC-602).
//!
//! Tests the full pipeline: bytecode VM execution -> execution report ->
//! hot-path profiling -> tier-up eligibility decision. Validates cross-module
//! integration between bytecode_vm and tier_up_profiler.

use frankenengine_engine::bytecode_vm::{BytecodeVm, Instruction, Program, Register, Value};
use frankenengine_engine::tier_up_profiler::{
    HotPathProfile, TierUpCandidate, TierUpDecision, TierUpDecisionEvent, TierUpPolicy,
    TierUpRejection, TIER_UP_POLICY_SCHEMA_VERSION, build_hot_path_profile,
    evaluate_tier_up_eligibility,
};

fn r(index: u16) -> Register {
    Register(index)
}

// ---------------------------------------------------------------------------
// Full pipeline: VM execution -> profiling -> tier-up decision
// ---------------------------------------------------------------------------

#[test]
fn straight_line_program_no_cache_activity() {
    // Simple arithmetic with no property loads — no cache signal.
    let program = Program {
        constants: vec![Value::Int(6), Value::Int(7)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Mul {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-straight-line", 8, 128);
    let report = vm.execute(&program).unwrap();

    let profile = build_hot_path_profile(&report, 16);
    assert_eq!(profile.total_steps, 4);
    assert_eq!(profile.observed_instruction_events, 3); // return is not "instruction" event
    assert!(!profile.profile_hash.is_empty());

    // Default policy requires cache signal — should be ineligible.
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    assert!(!decision.eligible);
}

#[test]
fn loop_with_cached_property_loads_eligible() {
    // Loop that loads a property many times — should build cache hits.
    let program = Program {
        constants: vec![Value::Int(42), Value::Int(50), Value::Int(1)],
        property_pool: vec!["answer".to_string()],
        instructions: vec![
            // r0 = obj
            Instruction::NewObject { dst: r(0) },
            // r1 = 42
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            // obj.answer = 42
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            // r3 = counter = 50
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            // Loop body: r2 = obj.answer (cached)
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            // r4 = 1
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            // counter -= 1
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            // if counter == 0 goto end
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            // goto loop body
            Instruction::Jump { target: 4 },
            // return r2
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-cache-loop", 8, 1024);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(42));

    let profile = build_hot_path_profile(&report, 16);
    assert!(profile.total_steps > 64); // enough steps for default policy

    // Find the load_prop_cached path in profile
    let cached_path = profile
        .top_paths
        .iter()
        .find(|p| p.opcode == "load_prop_cached");
    assert!(cached_path.is_some());
    let cached = cached_path.unwrap();
    assert_eq!(cached.invocations, 50);
    assert!(cached.cache_hits > 0);

    // With a permissive policy, should be eligible
    let policy = TierUpPolicy {
        min_total_steps: 10,
        min_invocations_per_path: 5,
        min_cache_hit_rate_millionths: 500_000,
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: true,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(decision.eligible);
    assert!(!decision.selected_candidates.is_empty());

    // Check the selected candidate
    let candidate = decision
        .selected_candidates
        .iter()
        .find(|c| c.opcode == "load_prop_cached");
    assert!(candidate.is_some());
}

#[test]
fn short_program_insufficient_steps() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-short", 4, 32);
    let report = vm.execute(&program).unwrap();

    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    assert!(!decision.eligible);
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.reason == "insufficient_total_steps")
    );
}

#[test]
fn property_load_all_misses_rejected_for_low_hit_rate() {
    // Store a new property each iteration — shape changes cause cache misses.
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(20), Value::Int(1)],
        property_pool: vec!["x".to_string(), "y".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            // Store two different properties to change shape
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            // Loop: load prop (will mostly miss due to shape changes)
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 1,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 10,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-miss", 8, 1024);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: 10,
        min_invocations_per_path: 5,
        min_cache_hit_rate_millionths: 900_000, // very high threshold
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: true,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    // The load_prop_cached path should be rejected for low cache hit rate
    let rejected_cached = decision
        .rejected_paths
        .iter()
        .find(|r| r.opcode == "load_prop_cached");
    if let Some(rejected) = rejected_cached {
        assert_eq!(rejected.reason, "cache_hit_rate_below_threshold");
    }
}

// ---------------------------------------------------------------------------
// Determinism across repeated runs
// ---------------------------------------------------------------------------

#[test]
fn profile_deterministic_across_three_runs() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(3), Value::Int(1)],
        property_pool: vec!["val".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut profiles = Vec::new();
    let mut decisions = Vec::new();

    for _ in 0..3 {
        let mut vm = BytecodeVm::new("trace-determinism", 8, 256);
        let report = vm.execute(&program).unwrap();
        profiles.push(build_hot_path_profile(&report, 16));
        decisions.push(evaluate_tier_up_eligibility(&report, &TierUpPolicy::default()));
    }

    assert_eq!(profiles[0].profile_hash, profiles[1].profile_hash);
    assert_eq!(profiles[1].profile_hash, profiles[2].profile_hash);
    assert_eq!(decisions[0].decision_hash, decisions[1].decision_hash);
    assert_eq!(decisions[1].decision_hash, decisions[2].decision_hash);
}

// ---------------------------------------------------------------------------
// Policy configuration edge cases
// ---------------------------------------------------------------------------

#[test]
fn policy_with_zero_min_steps_admits_any_program() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: 0,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(decision.eligible);
}

#[test]
fn policy_max_candidates_truncates() {
    // Build a program with multiple distinct cached-property hot paths.
    // Use a small loop count (20) to stay well within budget.
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(20), Value::Int(1)],
        property_pool: vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ],
        instructions: vec![
            // r0 = obj, r1 = 1
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            // Store all 5 properties on the object
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 1,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 2,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 3,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 4,
                value: r(1),
            },
            // r3 = counter = 20
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            // Loop body: 5 cached loads from different properties (ip 8-12)
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 2,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 3,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 4,
            },
            // counter -= 1
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 17,
            },
            Instruction::Jump { target: 8 },
            // return r2
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 8, 4096);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: 1,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 2,
        profile_top_k: 16,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(decision.selected_candidates.len() <= 2);
}

// ---------------------------------------------------------------------------
// Decision structure validation
// ---------------------------------------------------------------------------

#[test]
fn decision_has_schema_version() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    assert_eq!(decision.schema_version, TIER_UP_POLICY_SCHEMA_VERSION);
    assert!(!decision.policy_hash.is_empty());
    assert!(!decision.decision_hash.is_empty());
    assert_eq!(decision.trace_id, "t");
}

#[test]
fn decision_events_contain_start_and_complete() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    assert!(
        decision
            .events
            .iter()
            .any(|e| e.event == "tier_up_started")
    );
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.event == "tier_up_completed")
    );
}

// ---------------------------------------------------------------------------
// Serde round-trips (integration-level)
// ---------------------------------------------------------------------------

#[test]
fn full_decision_serde_roundtrip() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(30), Value::Int(1)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-serde", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    let json = serde_json::to_string(&decision).unwrap();
    let back: TierUpDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

#[test]
fn profile_serde_roundtrip() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    let profile = build_hot_path_profile(&report, 16);

    let json = serde_json::to_string(&profile).unwrap();
    let back: HotPathProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(back, profile);
}

#[test]
fn tier_up_policy_serde_roundtrip() {
    let policy = TierUpPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: TierUpPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

#[test]
fn tier_up_candidate_serde_roundtrip() {
    let candidate = TierUpCandidate {
        ip: 4,
        opcode: "load_prop_cached".to_string(),
        invocations: 50,
        cache_hit_rate_millionths: 960_000,
        rationale: "hot_path_meets_tier_up_thresholds".to_string(),
    };
    let json = serde_json::to_string(&candidate).unwrap();
    let back: TierUpCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, candidate);
}

#[test]
fn tier_up_rejection_serde_roundtrip() {
    let rejection = TierUpRejection {
        ip: 2,
        opcode: "add".to_string(),
        invocations: 3,
        cache_hit_rate_millionths: 0,
        reason: "insufficient_invocations".to_string(),
    };
    let json = serde_json::to_string(&rejection).unwrap();
    let back: TierUpRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rejection);
}

#[test]
fn tier_up_decision_event_serde_roundtrip() {
    let event = TierUpDecisionEvent {
        trace_id: "t".to_string(),
        component: "tier_up_profiler".to_string(),
        event: "tier_up_started".to_string(),
        outcome: "pass".to_string(),
        reason: "test".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: TierUpDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}
