#![forbid(unsafe_code)]
//! Integration tests for the `controller_composition_matrix` module (FRX-13.4).
//!
//! Exercises the full composition gate pipeline from outside the crate
//! boundary: matrix construction, interaction classification, microbench
//! harness, acceptance gate evaluation, and operator summary rendering.

use std::collections::BTreeSet;

use frankenengine_engine::controller_composition_matrix::{
    ControllerCompositionMatrix, ControllerRole, ControllerTimescale, GateConfig,
    GateFailureReason, GateResult, GateVerdict, InteractionClass, MatrixEntry, MicrobenchConfig,
    MicrobenchResult, OperatorSummary, evaluate_composition_gate, render_operator_summary,
    run_microbench,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn ts(name: &str, role: ControllerRole, obs: i64, write: i64) -> ControllerTimescale {
    ControllerTimescale {
        controller_name: name.to_string(),
        role,
        observation_interval_millionths: obs,
        write_interval_millionths: write,
        statement: format!("{name} timescale"),
    }
}

fn default_gate_config() -> GateConfig {
    GateConfig::default()
}

fn no_bench_config() -> GateConfig {
    GateConfig {
        run_microbench: false,
        microbench_config: MicrobenchConfig::default(),
        per_pair_budget_millionths: 500_000,
    }
}

// ===========================================================================
// 1. ControllerRole
// ===========================================================================

#[test]
fn controller_role_display_all() {
    let roles = ControllerRole::all();
    let displays: BTreeSet<String> = roles.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), roles.len(), "all roles have unique display");
}

#[test]
fn controller_role_as_str() {
    let r = ControllerRole::Router;
    assert!(!r.as_str().is_empty());
}

#[test]
fn controller_role_serde_round_trip() {
    for role in ControllerRole::all() {
        let json = serde_json::to_string(role).unwrap();
        let back: ControllerRole = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, role);
    }
}

#[test]
fn controller_role_ordering() {
    assert!(ControllerRole::Router < ControllerRole::Custom);
}

// ===========================================================================
// 2. InteractionClass
// ===========================================================================

#[test]
fn interaction_class_display_all() {
    let classes = [
        InteractionClass::Independent,
        InteractionClass::ReadShared,
        InteractionClass::ProducerConsumer,
        InteractionClass::WriteConflict,
        InteractionClass::MutuallyExclusive,
    ];
    let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), classes.len());
}

#[test]
fn interaction_class_as_str() {
    assert!(!InteractionClass::Independent.as_str().is_empty());
}

#[test]
fn mutually_exclusive_blocks_composition() {
    assert!(InteractionClass::MutuallyExclusive.blocks_composition());
    assert!(!InteractionClass::WriteConflict.blocks_composition());
    assert!(!InteractionClass::Independent.blocks_composition());
}

#[test]
fn write_conflict_requires_timescale_separation() {
    assert!(InteractionClass::WriteConflict.requires_timescale_separation());
    assert!(InteractionClass::ProducerConsumer.requires_timescale_separation());
}

#[test]
fn independent_no_separation_needed() {
    assert!(!InteractionClass::Independent.requires_timescale_separation());
}

#[test]
fn read_shared_no_separation_needed() {
    assert!(!InteractionClass::ReadShared.requires_timescale_separation());
}

#[test]
fn interaction_class_serde_round_trip() {
    let c = InteractionClass::ProducerConsumer;
    let json = serde_json::to_string(&c).unwrap();
    let back: InteractionClass = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 3. Default matrix
// ===========================================================================

#[test]
fn default_matrix_has_fifteen_entries() {
    let m = ControllerCompositionMatrix::default_matrix();
    // 5 roles: 5 diagonal + C(5,2) = 10 off-diagonal = 15
    assert_eq!(m.entries.len(), 15);
}

#[test]
fn default_matrix_schema_version() {
    let m = ControllerCompositionMatrix::default_matrix();
    assert!(!m.schema_version.is_empty());
}

#[test]
fn default_matrix_symmetric_lookup() {
    let m = ControllerCompositionMatrix::default_matrix();
    let ab = m.lookup(ControllerRole::Router, ControllerRole::Optimizer);
    let ba = m.lookup(ControllerRole::Optimizer, ControllerRole::Router);
    assert!(ab.is_some());
    assert_eq!(ab.unwrap().interaction, ba.unwrap().interaction);
}

#[test]
fn default_matrix_router_router_exclusive() {
    let m = ControllerCompositionMatrix::default_matrix();
    let e = m
        .lookup(ControllerRole::Router, ControllerRole::Router)
        .unwrap();
    assert_eq!(e.interaction, InteractionClass::MutuallyExclusive);
}

#[test]
fn default_matrix_monitor_monitor_shared() {
    let m = ControllerCompositionMatrix::default_matrix();
    let e = m
        .lookup(ControllerRole::Monitor, ControllerRole::Monitor)
        .unwrap();
    assert_eq!(e.interaction, InteractionClass::ReadShared);
}

#[test]
fn default_matrix_blocked_pairs() {
    let m = ControllerCompositionMatrix::default_matrix();
    let blocked = m.blocked_pairs();
    assert!(blocked.len() >= 2); // Router-Router, Fallback-Fallback
    assert!(blocked
        .iter()
        .any(|e| e.role_a == ControllerRole::Router && e.role_b == ControllerRole::Router));
}

#[test]
fn default_matrix_separation_required_pairs() {
    let m = ControllerCompositionMatrix::default_matrix();
    let sep = m.separation_required_pairs();
    assert!(!sep.is_empty());
    for e in &sep {
        assert!(e.min_timescale_separation_millionths > 0);
    }
}

// ===========================================================================
// 4. Matrix modification
// ===========================================================================

#[test]
fn set_entry_overrides() {
    let mut m = ControllerCompositionMatrix::default_matrix();
    let original = m
        .lookup(ControllerRole::Router, ControllerRole::Optimizer)
        .unwrap()
        .interaction;
    m.set_entry(MatrixEntry {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Optimizer,
        interaction: InteractionClass::Independent,
        min_timescale_separation_millionths: 0,
        rationale: "overridden for test".to_string(),
    });
    let updated = m
        .lookup(ControllerRole::Router, ControllerRole::Optimizer)
        .unwrap();
    assert_eq!(updated.interaction, InteractionClass::Independent);
    assert_ne!(updated.interaction, original);
}

// ===========================================================================
// 5. Matrix deterministic ID
// ===========================================================================

#[test]
fn matrix_id_deterministic() {
    let m1 = ControllerCompositionMatrix::default_matrix();
    let m2 = ControllerCompositionMatrix::default_matrix();
    assert_eq!(m1.derive_matrix_id(), m2.derive_matrix_id());
}

#[test]
fn matrix_id_changes_on_modification() {
    let m1 = ControllerCompositionMatrix::default_matrix();
    let mut m2 = ControllerCompositionMatrix::default_matrix();
    m2.set_entry(MatrixEntry {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Optimizer,
        interaction: InteractionClass::Independent,
        min_timescale_separation_millionths: 0,
        rationale: "changed".to_string(),
    });
    assert_ne!(m1.derive_matrix_id(), m2.derive_matrix_id());
}

// ===========================================================================
// 6. Matrix serde
// ===========================================================================

#[test]
fn matrix_serde_round_trip() {
    let m = ControllerCompositionMatrix::default_matrix();
    let json = serde_json::to_string(&m).unwrap();
    let back: ControllerCompositionMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entries.len(), m.entries.len());
    assert_eq!(back.schema_version, m.schema_version);
}

// ===========================================================================
// 7. Microbench — independent controllers
// ===========================================================================

#[test]
fn microbench_independent_pair_low_cost() {
    let controllers = vec![
        ts("mon_1", ControllerRole::Monitor, 1_000_000, 500_000),
        ts("mon_2", ControllerRole::Monitor, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    assert_eq!(result.pairs_measured, 1);
    // ReadShared monitors should have low cost
    assert_eq!(result.pairs_over_budget, 0);
}

// ===========================================================================
// 8. Microbench — write conflict pair
// ===========================================================================

#[test]
fn microbench_write_conflict_has_higher_cost() {
    let controllers = vec![
        ts("opt_1", ControllerRole::Optimizer, 1_000_000, 500_000),
        ts("opt_2", ControllerRole::Optimizer, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    assert!(result.total_cost_millionths > 0);
}

// ===========================================================================
// 9. Microbench — empty controllers
// ===========================================================================

#[test]
fn microbench_empty_controllers() {
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&[], &m, &cfg);
    assert_eq!(result.pairs_measured, 0);
    assert_eq!(result.total_cost_millionths, 0);
}

// ===========================================================================
// 10. Microbench — single controller (no pairs)
// ===========================================================================

#[test]
fn microbench_single_controller() {
    let controllers = vec![ts("solo", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    assert_eq!(result.pairs_measured, 0);
}

// ===========================================================================
// 11. Microbench serde
// ===========================================================================

#[test]
fn microbench_result_serde_round_trip() {
    let controllers = vec![
        ts("mon_1", ControllerRole::Monitor, 1_000_000, 500_000),
        ts("mon_2", ControllerRole::Monitor, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let cfg = MicrobenchConfig::default();
    let result = run_microbench(&controllers, &m, &cfg);
    let json = serde_json::to_string(&result).unwrap();
    let back: MicrobenchResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pairs_measured, result.pairs_measured);
    assert_eq!(back.total_cost_millionths, result.total_cost_millionths);
}

// ===========================================================================
// 12. Gate — approved deployment
// ===========================================================================

#[test]
fn gate_approves_compatible_deployment() {
    let controllers = vec![
        ts("my_router", ControllerRole::Router, 1_000_000, 500_000),
        ts("my_monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-1", &controllers, &m, &no_bench_config());
    assert!(result.is_approved());
    assert_eq!(result.verdict, GateVerdict::Approved);
    assert!(result.failures.is_empty());
}

// ===========================================================================
// 13. Gate — empty deployment rejected
// ===========================================================================

#[test]
fn gate_rejects_empty_deployment() {
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-2", &[], &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(result
        .failures
        .iter()
        .any(|f| matches!(f, GateFailureReason::EmptyDeployment)));
}

// ===========================================================================
// 14. Gate — duplicate controllers rejected
// ===========================================================================

#[test]
fn gate_rejects_duplicate_controllers() {
    let controllers = vec![
        ts("dup", ControllerRole::Router, 1_000_000, 500_000),
        ts("dup", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-3", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(result
        .failures
        .iter()
        .any(|f| matches!(f, GateFailureReason::DuplicateController { .. })));
}

// ===========================================================================
// 15. Gate — mutually exclusive roles rejected
// ===========================================================================

#[test]
fn gate_rejects_mutually_exclusive_roles() {
    let controllers = vec![
        ts("router_a", ControllerRole::Router, 1_000_000, 500_000),
        ts("router_b", ControllerRole::Router, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-4", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(result
        .failures
        .iter()
        .any(|f| matches!(f, GateFailureReason::MutuallyExclusiveRoles { .. })));
}

// ===========================================================================
// 16. Gate — insufficient timescale separation
// ===========================================================================

#[test]
fn gate_rejects_insufficient_timescale_separation() {
    // Optimizer-Optimizer requires 500K separation, give them same timescale
    let controllers = vec![
        ts("opt_a", ControllerRole::Optimizer, 100_000, 100_000),
        ts("opt_b", ControllerRole::Optimizer, 100_000, 100_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-5", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
}

// ===========================================================================
// 17. Gate — invalid timescale rejected
// ===========================================================================

#[test]
fn gate_rejects_invalid_timescale() {
    let controllers = vec![ts(
        "bad",
        ControllerRole::Router,
        0, // invalid: zero observation interval
        500_000,
    )];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-6", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    assert!(result
        .failures
        .iter()
        .any(|f| matches!(f, GateFailureReason::InvalidTimescale { .. })));
}

// ===========================================================================
// 18. Gate — deterministic gate ID
// ===========================================================================

#[test]
fn gate_id_deterministic() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let r1 = evaluate_composition_gate("trace-7", &controllers, &m, &no_bench_config());
    let r2 = evaluate_composition_gate("trace-7", &controllers, &m, &no_bench_config());
    assert_eq!(r1.gate_id, r2.gate_id);
}

// ===========================================================================
// 19. Gate — evidence ID
// ===========================================================================

#[test]
fn gate_evidence_id_stable() {
    let controllers = vec![ts("router", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let r1 = evaluate_composition_gate("trace-8", &controllers, &m, &no_bench_config());
    let r2 = evaluate_composition_gate("trace-8", &controllers, &m, &no_bench_config());
    assert_eq!(r1.derive_evidence_id(), r2.derive_evidence_id());
}

// ===========================================================================
// 20. Gate — logs are populated
// ===========================================================================

#[test]
fn gate_has_logs() {
    let controllers = vec![ts("router", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-9", &controllers, &m, &no_bench_config());
    assert!(!result.logs.is_empty());
}

// ===========================================================================
// 21. Gate — controllers and pairs counts
// ===========================================================================

#[test]
fn gate_counts_controllers_and_pairs() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
        ts("optimizer", ControllerRole::Optimizer, 3_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-10", &controllers, &m, &no_bench_config());
    assert_eq!(result.controllers_evaluated, 3);
    assert_eq!(result.pairs_evaluated, 3); // C(3,2) = 3
}

// ===========================================================================
// 22. Gate — with microbench enabled
// ===========================================================================

#[test]
fn gate_with_microbench() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-11", &controllers, &m, &default_gate_config());
    assert!(result.microbench.is_some());
}

// ===========================================================================
// 23. Gate result serde
// ===========================================================================

#[test]
fn gate_result_serde_round_trip() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-12", &controllers, &m, &no_bench_config());
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.verdict, result.verdict);
    assert_eq!(back.gate_id, result.gate_id);
    assert_eq!(back.controllers_evaluated, result.controllers_evaluated);
}

// ===========================================================================
// 24. GateFailureReason display
// ===========================================================================

#[test]
fn gate_failure_reason_display_all() {
    let reasons = [
        GateFailureReason::EmptyDeployment,
        GateFailureReason::DuplicateController {
            controller_name: "dup".to_string(),
        },
        GateFailureReason::MutuallyExclusiveRoles {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Router,
            controller_a: "a".to_string(),
            controller_b: "b".to_string(),
        },
        GateFailureReason::InvalidTimescale {
            controller_name: "bad".to_string(),
            detail: "zero interval".to_string(),
        },
        GateFailureReason::InsufficientTimescaleSeparation {
            controller_a: "a".to_string(),
            controller_b: "b".to_string(),
            required_millionths: 500_000,
            actual_millionths: 100_000,
        },
        GateFailureReason::MicrobenchBudgetExceeded {
            pair: "a-b".to_string(),
            cost_millionths: 800_000,
            budget_millionths: 500_000,
        },
    ];
    for r in &reasons {
        let s = r.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn gate_failure_reason_serde_round_trip() {
    let r = GateFailureReason::MutuallyExclusiveRoles {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Router,
        controller_a: "a".to_string(),
        controller_b: "b".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: GateFailureReason = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 25. GateVerdict display and serde
// ===========================================================================

#[test]
fn gate_verdict_display() {
    assert!(!GateVerdict::Approved.to_string().is_empty());
    assert!(!GateVerdict::Rejected.to_string().is_empty());
    assert_ne!(
        GateVerdict::Approved.to_string(),
        GateVerdict::Rejected.to_string()
    );
}

#[test]
fn gate_verdict_serde_round_trip() {
    let v = GateVerdict::Approved;
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 26. Operator summary
// ===========================================================================

#[test]
fn operator_summary_approved() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-13", &controllers, &m, &no_bench_config());
    let summary = render_operator_summary(&result);
    assert_eq!(summary.verdict, "approved");
    assert_eq!(summary.failure_count, 0);
    assert!(!summary.lines.is_empty());
}

#[test]
fn operator_summary_rejected() {
    let controllers = vec![
        ts("r1", ControllerRole::Router, 1_000_000, 500_000),
        ts("r2", ControllerRole::Router, 2_000_000, 1_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-14", &controllers, &m, &no_bench_config());
    let summary = render_operator_summary(&result);
    assert_eq!(summary.verdict, "rejected");
    assert!(summary.failure_count > 0);
}

#[test]
fn operator_summary_serde_round_trip() {
    let controllers = vec![ts("router", ControllerRole::Router, 1_000_000, 500_000)];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-15", &controllers, &m, &no_bench_config());
    let summary = render_operator_summary(&result);
    let json = serde_json::to_string(&summary).unwrap();
    let back: OperatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.verdict, summary.verdict);
    assert_eq!(back.controllers, summary.controllers);
}

// ===========================================================================
// 27. GateConfig defaults and serde
// ===========================================================================

#[test]
fn gate_config_default() {
    let cfg = GateConfig::default();
    assert!(cfg.run_microbench);
    assert!(cfg.per_pair_budget_millionths > 0);
}

#[test]
fn gate_config_serde_round_trip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 28. MicrobenchConfig defaults and serde
// ===========================================================================

#[test]
fn microbench_config_default() {
    let cfg = MicrobenchConfig::default();
    assert!(cfg.max_iterations > 0);
    assert!(cfg.budget_cap_millionths > 0);
    assert!(cfg.min_iterations > 0);
}

#[test]
fn microbench_config_serde_round_trip() {
    let cfg = MicrobenchConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: MicrobenchConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 29. MatrixEntry serde
// ===========================================================================

#[test]
fn matrix_entry_serde_round_trip() {
    let e = MatrixEntry {
        role_a: ControllerRole::Router,
        role_b: ControllerRole::Optimizer,
        interaction: InteractionClass::ProducerConsumer,
        min_timescale_separation_millionths: 100_000,
        rationale: "Router → Optimizer".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: MatrixEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 30. ControllerTimescale serde
// ===========================================================================

#[test]
fn controller_timescale_serde_round_trip() {
    let t = ts("my_router", ControllerRole::Router, 1_000_000, 500_000);
    let json = serde_json::to_string(&t).unwrap();
    let back: ControllerTimescale = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// 31. Five-controller deployment
// ===========================================================================

#[test]
fn five_controller_deployment() {
    let controllers = vec![
        ts("router", ControllerRole::Router, 1_000_000, 500_000),
        ts("optimizer", ControllerRole::Optimizer, 5_000_000, 3_000_000),
        ts(
            "fallback",
            ControllerRole::Fallback,
            10_000_000,
            5_000_000,
        ),
        ts("monitor", ControllerRole::Monitor, 2_000_000, 1_000_000),
        ts("custom_ext", ControllerRole::Custom, 8_000_000, 4_000_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-big", &controllers, &m, &default_gate_config());
    assert_eq!(result.controllers_evaluated, 5);
    assert_eq!(result.pairs_evaluated, 10); // C(5,2) = 10
    // Should have microbench results
    assert!(result.microbench.is_some());
}

// ===========================================================================
// 32. Multiple failures accumulate
// ===========================================================================

#[test]
fn multiple_failures_accumulate() {
    let controllers = vec![
        ts("r1", ControllerRole::Router, 1_000_000, 500_000),
        ts("r2", ControllerRole::Router, 1_000_000, 500_000),
        ts("f1", ControllerRole::Fallback, 1_000_000, 500_000),
        ts("f2", ControllerRole::Fallback, 1_000_000, 500_000),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-multi", &controllers, &m, &no_bench_config());
    assert!(!result.is_approved());
    // Should have at least 2 failures: Router-Router and Fallback-Fallback exclusions
    assert!(result.failures.len() >= 2);
}

// ===========================================================================
// 33. GateLogEvent serde
// ===========================================================================

#[test]
fn gate_log_event_serde_round_trip() {
    use frankenengine_engine::controller_composition_matrix::GateLogEvent;
    let e = GateLogEvent {
        trace_id: "t1".to_string(),
        gate_id: "g1".to_string(),
        event: "gate_start".to_string(),
        detail: "evaluating 3 controllers".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: GateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 34. Approved deployment with wide timescale separation
// ===========================================================================

#[test]
fn approved_with_wide_separation() {
    // Give optimizers very different timescales to satisfy separation
    let controllers = vec![
        ts("opt_fast", ControllerRole::Optimizer, 1_000_000, 500_000),
        ts(
            "opt_slow",
            ControllerRole::Optimizer,
            100_000_000,
            50_000_000,
        ),
    ];
    let m = ControllerCompositionMatrix::default_matrix();
    let result = evaluate_composition_gate("trace-sep", &controllers, &m, &no_bench_config());
    // Wide separation should satisfy the 500K requirement
    assert!(result.is_approved());
}

// ===========================================================================
// 35. Matrix lookup for all role pairs
// ===========================================================================

#[test]
fn matrix_has_entries_for_all_role_pairs() {
    let m = ControllerCompositionMatrix::default_matrix();
    let roles = ControllerRole::all();
    for a in roles {
        for b in roles {
            assert!(
                m.lookup(*a, *b).is_some(),
                "missing entry for ({a:?}, {b:?})"
            );
        }
    }
}
