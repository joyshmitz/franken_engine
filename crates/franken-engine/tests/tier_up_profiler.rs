use frankenengine_engine::bytecode_vm::{BytecodeVm, Instruction, Program, Register, Value};
use frankenengine_engine::tier_up_profiler::{
    TierUpPolicy, build_hot_path_profile, evaluate_tier_up_eligibility,
};

fn r(index: u16) -> Register {
    Register(index)
}

fn cached_hot_loop_program() -> Program {
    Program {
        constants: vec![Value::Int(41), Value::Int(3), Value::Int(1)],
        property_pool: vec!["answer".to_string()],
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
                dst: r(2),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(3),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(2),
                lhs: r(2),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(2),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(3) },
        ],
    }
}

fn arithmetic_loop_program() -> Program {
    Program {
        constants: vec![Value::Int(4), Value::Int(1)],
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
            Instruction::Sub {
                dst: r(0),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 5,
            },
            Instruction::Jump { target: 2 },
            Instruction::Return { src: r(0) },
        ],
    }
}

#[test]
fn profile_and_decision_are_deterministic_for_identical_runs() {
    let program = cached_hot_loop_program();
    let policy = TierUpPolicy {
        policy_id: "policy-tier-loop".to_string(),
        min_total_steps: 8,
        min_invocations_per_path: 2,
        min_cache_hit_rate_millionths: 600_000,
        max_candidates: 2,
        profile_top_k: 8,
        require_cache_signal: true,
    };

    let mut vm_a = BytecodeVm::new("trace-tier-loop", 12, 256);
    let report_a = vm_a.execute(&program).expect("program A should execute");
    let profile_a = build_hot_path_profile(&report_a, policy.profile_top_k);
    let decision_a = evaluate_tier_up_eligibility(&report_a, &policy);

    let mut vm_b = BytecodeVm::new("trace-tier-loop", 12, 256);
    let report_b = vm_b.execute(&program).expect("program B should execute");
    let profile_b = build_hot_path_profile(&report_b, policy.profile_top_k);
    let decision_b = evaluate_tier_up_eligibility(&report_b, &policy);

    assert_eq!(profile_a, profile_b);
    assert_eq!(decision_a, decision_b);
    assert!(decision_a.eligible);
    assert!(
        decision_a
            .selected_candidates
            .iter()
            .any(|candidate| candidate.opcode == "load_prop_cached")
    );
}

#[test]
fn decision_denies_when_total_steps_below_policy_floor() {
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

    let policy = TierUpPolicy {
        min_total_steps: 32,
        ..TierUpPolicy::default()
    };

    let mut vm = BytecodeVm::new("trace-short", 4, 16);
    let report = vm.execute(&program).expect("program should execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    assert!(!decision.eligible);
    assert!(decision.selected_candidates.is_empty());
    assert_eq!(
        decision.events.last().map(|event| event.reason.as_str()),
        Some("insufficient_total_steps")
    );
}

#[test]
fn cache_signal_requirement_rejects_non_cached_paths() {
    let program = arithmetic_loop_program();
    let policy = TierUpPolicy {
        policy_id: "policy-require-cache".to_string(),
        min_total_steps: 4,
        min_invocations_per_path: 2,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 3,
        profile_top_k: 8,
        require_cache_signal: true,
    };

    let mut vm = BytecodeVm::new("trace-no-cache", 8, 128);
    let report = vm.execute(&program).expect("program should execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    assert!(!decision.eligible);
    assert!(decision.selected_candidates.is_empty());
    assert!(
        decision
            .rejected_paths
            .iter()
            .any(|path| path.reason == "missing_cache_signal")
    );
}
