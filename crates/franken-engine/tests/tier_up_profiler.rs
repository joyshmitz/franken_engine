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

// ---------- TierUpPolicy defaults ----------

#[test]
fn tier_up_policy_default_has_expected_field_values() {
    let policy = TierUpPolicy::default();
    assert_eq!(policy.policy_id, "policy-tier-up-v1");
    assert_eq!(policy.min_total_steps, 64);
    assert_eq!(policy.min_invocations_per_path, 16);
    assert_eq!(policy.min_cache_hit_rate_millionths, 600_000);
    assert_eq!(policy.max_candidates, 4);
    assert_eq!(policy.profile_top_k, 16);
    assert!(policy.require_cache_signal);
}

#[test]
fn tier_up_policy_hash_is_deterministic() {
    let policy = TierUpPolicy::default();
    let hash_a = policy.policy_hash();
    let hash_b = policy.policy_hash();
    assert_eq!(hash_a, hash_b);
    assert!(!hash_a.is_empty());
}

#[test]
fn tier_up_policy_hash_changes_with_different_fields() {
    let policy_a = TierUpPolicy::default();
    let policy_b = TierUpPolicy {
        min_total_steps: 128,
        ..TierUpPolicy::default()
    };
    assert_ne!(policy_a.policy_hash(), policy_b.policy_hash());
}

// ---------- schema version constant ----------

#[test]
fn tier_up_policy_schema_version_constant_is_nonempty() {
    assert!(!frankenengine_engine::tier_up_profiler::TIER_UP_POLICY_SCHEMA_VERSION.is_empty());
}

// ---------- build_hot_path_profile ----------

#[test]
fn hot_path_profile_is_deterministic_for_same_execution() {
    let program = cached_hot_loop_program();
    let mut vm = BytecodeVm::new("trace-profile-det", 12, 256);
    let report = vm.execute(&program).expect("execute");
    let profile_a = build_hot_path_profile(&report, 8);
    let profile_b = build_hot_path_profile(&report, 8);
    assert_eq!(profile_a, profile_b);
    assert_eq!(profile_a.profile_hash, profile_b.profile_hash);
}

#[test]
fn hot_path_profile_top_paths_are_sorted_by_invocations_descending() {
    let program = cached_hot_loop_program();
    let mut vm = BytecodeVm::new("trace-sort-check", 12, 256);
    let report = vm.execute(&program).expect("execute");
    let profile = build_hot_path_profile(&report, 8);

    for window in profile.top_paths.windows(2) {
        assert!(
            window[0].invocations >= window[1].invocations,
            "top_paths must be sorted by invocations descending"
        );
    }
}

#[test]
fn hot_path_profile_trace_id_matches_vm_trace() {
    let program = arithmetic_loop_program();
    let mut vm = BytecodeVm::new("trace-id-check", 8, 128);
    let report = vm.execute(&program).expect("execute");
    let profile = build_hot_path_profile(&report, 4);
    assert_eq!(profile.trace_id, "trace-id-check");
}

// ---------- evaluate_tier_up_eligibility ----------

#[test]
fn eligibility_decision_includes_schema_version() {
    let program = arithmetic_loop_program();
    let policy = TierUpPolicy {
        min_total_steps: 2,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };
    let mut vm = BytecodeVm::new("trace-schema", 8, 128);
    let report = vm.execute(&program).expect("execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(!decision.schema_version.is_empty());
}

#[test]
fn eligibility_decision_hash_is_deterministic() {
    let program = cached_hot_loop_program();
    let policy = TierUpPolicy {
        min_total_steps: 4,
        min_invocations_per_path: 1,
        ..TierUpPolicy::default()
    };
    let mut vm_a = BytecodeVm::new("trace-hash-det", 12, 256);
    let report_a = vm_a.execute(&program).expect("execute A");
    let decision_a = evaluate_tier_up_eligibility(&report_a, &policy);

    let mut vm_b = BytecodeVm::new("trace-hash-det", 12, 256);
    let report_b = vm_b.execute(&program).expect("execute B");
    let decision_b = evaluate_tier_up_eligibility(&report_b, &policy);

    assert_eq!(decision_a.decision_hash, decision_b.decision_hash);
    assert!(!decision_a.decision_hash.is_empty());
}

#[test]
fn eligibility_rejects_paths_with_insufficient_invocations() {
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
        min_total_steps: 1,
        min_invocations_per_path: 100,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };

    let mut vm = BytecodeVm::new("trace-insuf-invoc", 4, 16);
    let report = vm.execute(&program).expect("execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    assert!(!decision.eligible);
    assert!(
        decision
            .rejected_paths
            .iter()
            .any(|path| path.reason == "insufficient_invocations")
    );
}

#[test]
fn eligibility_max_candidates_truncates_selection() {
    let program = cached_hot_loop_program();
    let policy = TierUpPolicy {
        min_total_steps: 1,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 1,
        profile_top_k: 8,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };

    let mut vm = BytecodeVm::new("trace-trunc", 12, 256);
    let report = vm.execute(&program).expect("execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    assert!(decision.selected_candidates.len() <= 1);
}

#[test]
fn eligibility_events_include_started_and_completed() {
    let program = cached_hot_loop_program();
    let policy = TierUpPolicy {
        min_total_steps: 4,
        min_invocations_per_path: 1,
        ..TierUpPolicy::default()
    };

    let mut vm = BytecodeVm::new("trace-events", 12, 256);
    let report = vm.execute(&program).expect("execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    assert!(
        decision
            .events
            .iter()
            .any(|event| event.event == "tier_up_started"),
        "must include tier_up_started event"
    );
    assert!(
        decision
            .events
            .iter()
            .any(|event| event.event == "tier_up_completed"),
        "must include tier_up_completed event"
    );
}

// ---------- serde roundtrips ----------

#[test]
fn tier_up_policy_serde_roundtrip() {
    let policy = TierUpPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: TierUpPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.policy_id, policy.policy_id);
    assert_eq!(recovered.min_total_steps, policy.min_total_steps);
    assert_eq!(recovered.require_cache_signal, policy.require_cache_signal);
}

#[test]
fn tier_up_decision_serde_roundtrip() {
    let program = cached_hot_loop_program();
    let policy = TierUpPolicy {
        min_total_steps: 4,
        min_invocations_per_path: 1,
        ..TierUpPolicy::default()
    };
    let mut vm = BytecodeVm::new("trace-serde", 12, 256);
    let report = vm.execute(&program).expect("execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: frankenengine_engine::tier_up_profiler::TierUpDecision =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.eligible, decision.eligible);
    assert_eq!(recovered.schema_version, decision.schema_version);
    assert_eq!(recovered.decision_hash, decision.decision_hash);
}

#[test]
fn hot_path_profile_serde_roundtrip() {
    let program = arithmetic_loop_program();
    let mut vm = BytecodeVm::new("trace-profile-serde", 8, 128);
    let report = vm.execute(&program).expect("execute");
    let profile = build_hot_path_profile(&report, 4);

    let json = serde_json::to_string(&profile).expect("serialize");
    let recovered: frankenengine_engine::tier_up_profiler::HotPathProfile =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.profile_hash, profile.profile_hash);
    assert_eq!(recovered.total_steps, profile.total_steps);
}

// ---------- cache hit rate threshold ----------

#[test]
fn eligibility_rejects_cache_hit_rate_below_threshold() {
    let program = cached_hot_loop_program();
    let policy = TierUpPolicy {
        min_total_steps: 1,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 999_999,
        max_candidates: 4,
        profile_top_k: 8,
        require_cache_signal: true,
        ..TierUpPolicy::default()
    };

    let mut vm = BytecodeVm::new("trace-cache-thresh", 12, 256);
    let report = vm.execute(&program).expect("execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    let has_cache_rejection = decision
        .rejected_paths
        .iter()
        .any(|path| path.reason == "cache_hit_rate_below_threshold");
    let has_missing_signal = decision
        .rejected_paths
        .iter()
        .any(|path| path.reason == "missing_cache_signal");

    assert!(
        has_cache_rejection || has_missing_signal || !decision.eligible,
        "extreme threshold should produce rejections or ineligibility"
    );
}

#[test]
fn tier_up_policy_default_has_sane_values() {
    let policy = TierUpPolicy::default();
    assert!(policy.max_candidates > 0);
    assert!(policy.profile_top_k > 0);
}

#[test]
fn hot_path_profile_deterministic_for_same_program() {
    let program = arithmetic_loop_program();
    let mut vm_a = BytecodeVm::new("trace-det-same", 8, 128);
    let report_a = vm_a.execute(&program).expect("execute a");
    let profile_a = build_hot_path_profile(&report_a, 4);

    let mut vm_b = BytecodeVm::new("trace-det-same", 8, 128);
    let report_b = vm_b.execute(&program).expect("execute b");
    let profile_b = build_hot_path_profile(&report_b, 4);

    assert_eq!(profile_a.total_steps, profile_b.total_steps);
    assert_eq!(profile_a.profile_hash, profile_b.profile_hash);
}

#[test]
fn evaluate_tier_up_returns_decision_with_trace_id() {
    let program = arithmetic_loop_program();
    let policy = TierUpPolicy::default();
    let mut vm = BytecodeVm::new("trace-decision-tid", 8, 128);
    let report = vm.execute(&program).expect("execute");
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(!decision.trace_id.is_empty());
}
