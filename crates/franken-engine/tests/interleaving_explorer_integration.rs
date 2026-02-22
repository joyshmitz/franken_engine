//! Integration tests for the `interleaving_explorer` module.
//!
//! Covers: OperationType, RaceSeverity, RaceSurface, RaceSurfaceCatalog,
//! ExplorationStrategy, InvariantResult, InvariantChecker, ExplorationFailure,
//! ExplorationReport, Scenario, ScenarioAction, InterleavingExplorer.

use frankenengine_engine::interleaving_explorer::{
    ExplorationFailure, ExplorationReport, ExplorationStrategy, InterleavingExplorer,
    InvariantChecker, InvariantResult, OperationType, RaceSeverity, RaceSurface,
    RaceSurfaceCatalog, Scenario, ScenarioAction,
};
use frankenengine_engine::lab_runtime::{
    FaultKind, LabEvent, LabRunResult, ScheduleTranscript, Verdict,
};

// ===========================================================================
// OperationType — serde + display + ord
// ===========================================================================

#[test]
fn operation_type_serde_roundtrip_all_variants() {
    let variants = [
        OperationType::CheckpointWrite,
        OperationType::RevocationPropagation,
        OperationType::PolicyUpdate,
        OperationType::EvidenceEmission,
        OperationType::RegionClose,
        OperationType::ObligationCommit,
        OperationType::TaskCompletion,
        OperationType::FaultInjection,
        OperationType::CancelInjection,
        OperationType::TimeAdvance,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: OperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn operation_type_display_all_variants() {
    assert_eq!(OperationType::CheckpointWrite.to_string(), "checkpoint_write");
    assert_eq!(
        OperationType::RevocationPropagation.to_string(),
        "revocation_propagation"
    );
    assert_eq!(OperationType::PolicyUpdate.to_string(), "policy_update");
    assert_eq!(
        OperationType::EvidenceEmission.to_string(),
        "evidence_emission"
    );
    assert_eq!(OperationType::RegionClose.to_string(), "region_close");
    assert_eq!(
        OperationType::ObligationCommit.to_string(),
        "obligation_commit"
    );
    assert_eq!(
        OperationType::TaskCompletion.to_string(),
        "task_completion"
    );
    assert_eq!(OperationType::FaultInjection.to_string(), "fault_injection");
    assert_eq!(
        OperationType::CancelInjection.to_string(),
        "cancel_injection"
    );
    assert_eq!(OperationType::TimeAdvance.to_string(), "time_advance");
}

#[test]
fn operation_type_ordering() {
    assert!(OperationType::CheckpointWrite < OperationType::RevocationPropagation);
    assert!(OperationType::RevocationPropagation < OperationType::PolicyUpdate);
}

// ===========================================================================
// RaceSeverity — serde + display + ord
// ===========================================================================

#[test]
fn race_severity_serde_roundtrip() {
    for v in [
        RaceSeverity::Low,
        RaceSeverity::Medium,
        RaceSeverity::High,
        RaceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: RaceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn race_severity_display() {
    assert_eq!(RaceSeverity::Low.to_string(), "low");
    assert_eq!(RaceSeverity::Medium.to_string(), "medium");
    assert_eq!(RaceSeverity::High.to_string(), "high");
    assert_eq!(RaceSeverity::Critical.to_string(), "critical");
}

#[test]
fn race_severity_ordering() {
    assert!(RaceSeverity::Low < RaceSeverity::Medium);
    assert!(RaceSeverity::Medium < RaceSeverity::High);
    assert!(RaceSeverity::High < RaceSeverity::Critical);
}

// ===========================================================================
// RaceSurface — serde
// ===========================================================================

#[test]
fn race_surface_serde_roundtrip() {
    let surface = RaceSurface {
        race_id: "test-race".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
        invariant: "test invariant".to_string(),
        severity: RaceSeverity::High,
    };
    let json = serde_json::to_string(&surface).unwrap();
    let restored: RaceSurface = serde_json::from_str(&json).unwrap();
    assert_eq!(surface, restored);
}

// ===========================================================================
// RaceSurfaceCatalog — construction + default catalog
// ===========================================================================

#[test]
fn empty_catalog() {
    let catalog = RaceSurfaceCatalog::new();
    assert!(catalog.is_empty());
    assert_eq!(catalog.len(), 0);
}

#[test]
fn default_catalog_has_known_races() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    assert!(catalog.len() >= 5);
    assert!(catalog.surfaces.contains_key("race-checkpoint-vs-revocation"));
    assert!(catalog.surfaces.contains_key("race-policy-vs-evidence"));
    assert!(catalog.surfaces.contains_key("race-checkpoint-vs-region-close"));
    assert!(catalog.surfaces.contains_key("race-obligation-vs-cancel"));
    assert!(catalog.surfaces.contains_key("race-completion-vs-fault"));
}

#[test]
fn catalog_add_and_lookup() {
    let mut catalog = RaceSurfaceCatalog::new();
    catalog.add(RaceSurface {
        race_id: "test-race".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
        invariant: "test invariant".to_string(),
        severity: RaceSeverity::Medium,
    });
    assert_eq!(catalog.len(), 1);
    assert!(!catalog.is_empty());
    assert!(catalog.surfaces.contains_key("test-race"));
}

#[test]
fn catalog_add_replaces_existing() {
    let mut catalog = RaceSurfaceCatalog::new();
    catalog.add(RaceSurface {
        race_id: "r1".to_string(),
        operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
        invariant: "v1".to_string(),
        severity: RaceSeverity::Low,
    });
    catalog.add(RaceSurface {
        race_id: "r1".to_string(),
        operations: [OperationType::PolicyUpdate, OperationType::EvidenceEmission],
        invariant: "v2".to_string(),
        severity: RaceSeverity::High,
    });
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog.surfaces["r1"].invariant, "v2");
}

#[test]
fn catalog_serde_roundtrip() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let json = serde_json::to_string(&catalog).unwrap();
    let restored: RaceSurfaceCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, restored);
}

#[test]
fn default_catalog_severity_levels() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let checkpoint_revocation = &catalog.surfaces["race-checkpoint-vs-revocation"];
    assert_eq!(checkpoint_revocation.severity, RaceSeverity::Critical);

    let policy_evidence = &catalog.surfaces["race-policy-vs-evidence"];
    assert_eq!(policy_evidence.severity, RaceSeverity::High);
}

// ===========================================================================
// ExplorationStrategy — serde + display
// ===========================================================================

#[test]
fn exploration_strategy_serde_roundtrip() {
    let strategies = [
        ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 100,
        },
        ExplorationStrategy::TargetedRace {
            race_ids: vec!["r1".to_string(), "r2".to_string()],
        },
    ];
    for s in &strategies {
        let json = serde_json::to_string(s).unwrap();
        let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn exploration_strategy_display() {
    assert_eq!(
        ExplorationStrategy::Exhaustive {
            max_permutations: 10
        }
        .to_string(),
        "exhaustive(max=10)"
    );
    assert_eq!(
        ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 100
        }
        .to_string(),
        "random_walk(seed=42, iters=100)"
    );
    assert!(
        ExplorationStrategy::TargetedRace {
            race_ids: vec!["r1".to_string()]
        }
        .to_string()
        .contains("r1")
    );
}

// ===========================================================================
// InvariantResult — serde
// ===========================================================================

#[test]
fn invariant_result_serde_roundtrip() {
    let results = [
        InvariantResult::Held,
        InvariantResult::Violated {
            description: "bad".to_string(),
        },
    ];
    for r in &results {
        let json = serde_json::to_string(r).unwrap();
        let restored: InvariantResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

// ===========================================================================
// InvariantChecker — serde + check
// ===========================================================================

#[test]
fn invariant_checker_serde_all_variants() {
    let checkers = [
        InvariantChecker::NoCompletedAndFaulted,
        InvariantChecker::AllTasksTerminal,
        InvariantChecker::FaultAfterCompletionForbidden,
        InvariantChecker::ForbiddenEventPattern {
            action: "test".to_string(),
            outcome: "fail".to_string(),
        },
    ];
    for c in &checkers {
        let json = serde_json::to_string(c).unwrap();
        let restored: InvariantChecker = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

fn make_lab_result(events: Vec<LabEvent>) -> LabRunResult {
    LabRunResult {
        seed: 42,
        transcript: ScheduleTranscript::new(42),
        events,
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    }
}

fn make_event(step: u64, action: &str, task_id: Option<u64>, outcome: &str) -> LabEvent {
    LabEvent {
        virtual_time: 0,
        step_index: step,
        action: action.to_string(),
        task_id,
        region_id: None,
        outcome: outcome.to_string(),
    }
}

#[test]
fn no_completed_and_faulted_holds_on_clean_run() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = make_lab_result(vec![make_event(1, "complete_task", Some(1), "completed")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn no_completed_and_faulted_detects_violation() {
    let checker = InvariantChecker::NoCompletedAndFaulted;
    let result = make_lab_result(vec![
        make_event(1, "complete_task", Some(1), "completed"),
        make_event(2, "inject_fault", Some(1), "fault=panic"),
    ]);
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

#[test]
fn all_tasks_terminal_holds_on_completed() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "complete_task", Some(1), "completed")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn all_tasks_terminal_holds_on_cancelled() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "cancel", Some(1), "cancelled")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn all_tasks_terminal_holds_on_faulted() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "inject_fault", Some(1), "fault=panic")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn all_tasks_terminal_detects_non_terminal() {
    let checker = InvariantChecker::AllTasksTerminal;
    let result = make_lab_result(vec![make_event(1, "run_task", Some(1), "running")]);
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

#[test]
fn forbidden_event_pattern_holds_when_absent() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "inject_fault".to_string(),
        outcome: "fault=panic".to_string(),
    };
    let result = make_lab_result(vec![make_event(1, "run_task", Some(1), "running")]);
    assert_eq!(checker.check(&result), InvariantResult::Held);
}

#[test]
fn forbidden_event_pattern_detects_match() {
    let checker = InvariantChecker::ForbiddenEventPattern {
        action: "inject_fault".to_string(),
        outcome: "fault=panic".to_string(),
    };
    let result = make_lab_result(vec![make_event(1, "inject_fault", Some(1), "fault=panic")]);
    assert!(matches!(
        checker.check(&result),
        InvariantResult::Violated { .. }
    ));
}

// ===========================================================================
// ScenarioAction — serde
// ===========================================================================

#[test]
fn scenario_action_serde_all_variants() {
    let actions = [
        ScenarioAction::RunTask { task_index: 0 },
        ScenarioAction::CompleteTask { task_index: 1 },
        ScenarioAction::AdvanceTime { ticks: 100 },
        ScenarioAction::InjectCancel {
            region_id: "r1".to_string(),
        },
        ScenarioAction::InjectFault {
            task_index: 0,
            fault: FaultKind::Panic,
        },
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let restored: ScenarioAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, restored);
    }
}

// ===========================================================================
// Scenario — serde
// ===========================================================================

#[test]
fn scenario_serde_roundtrip() {
    let scenario = Scenario {
        task_count: 2,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 1 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 42,
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let restored: Scenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, restored);
}

// ===========================================================================
// ExplorationFailure — serde
// ===========================================================================

#[test]
fn exploration_failure_serde_roundtrip() {
    let failure = ExplorationFailure {
        transcript: ScheduleTranscript::new(42),
        violations: vec!["test violation".to_string()],
        minimized_transcript: None,
        related_race_ids: vec!["race-1".to_string()],
    };
    let json = serde_json::to_string(&failure).unwrap();
    let restored: ExplorationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(failure, restored);
}

// ===========================================================================
// ExplorationReport — serde + computed fields
// ===========================================================================

#[test]
fn exploration_report_serde_roundtrip() {
    let report = ExplorationReport {
        exploration_id: "test".to_string(),
        strategy: ExplorationStrategy::RandomWalk {
            seed: 42,
            iterations: 10,
        },
        total_explored: 10,
        failures: vec![],
        race_surfaces_covered: 3,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: ExplorationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn coverage_millionths_calculation() {
    let report = ExplorationReport {
        exploration_id: "test".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 10,
        failures: vec![],
        race_surfaces_covered: 3,
        race_surfaces_total: 5,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 600_000);
}

#[test]
fn coverage_zero_when_no_surfaces() {
    let report = ExplorationReport {
        exploration_id: "test".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        total_explored: 0,
        failures: vec![],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    assert_eq!(report.coverage_millionths(), 0);
}

#[test]
fn report_all_passed_and_failure_count() {
    let passing = ExplorationReport {
        exploration_id: "pass".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    assert!(passing.all_passed());
    assert_eq!(passing.failure_count(), 0);

    let failing = ExplorationReport {
        exploration_id: "fail".to_string(),
        strategy: ExplorationStrategy::Exhaustive {
            max_permutations: 1,
        },
        total_explored: 1,
        failures: vec![ExplorationFailure {
            transcript: ScheduleTranscript::new(0),
            violations: vec!["bad".to_string()],
            minimized_transcript: None,
            related_race_ids: vec![],
        }],
        race_surfaces_covered: 0,
        race_surfaces_total: 0,
        regression_transcripts: vec![],
    };
    assert!(!failing.all_passed());
    assert_eq!(failing.failure_count(), 1);
}

// ===========================================================================
// InterleavingExplorer — exhaustive strategy
// ===========================================================================

#[test]
fn exhaustive_generates_correct_count_for_small_input() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let strategy = ExplorationStrategy::Exhaustive {
        max_permutations: 100,
    };
    let report = explorer.explore(&scenario, &strategy, "test-exhaustive");
    assert_eq!(report.total_explored, 6); // 3! = 6
}

#[test]
fn exhaustive_respects_max_bound() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
            ScenarioAction::AdvanceTime { ticks: 20 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let strategy = ExplorationStrategy::Exhaustive {
        max_permutations: 5,
    };
    let report = explorer.explore(&scenario, &strategy, "test-bounded");
    assert!(report.total_explored <= 5);
}

// ===========================================================================
// InterleavingExplorer — random walk strategy
// ===========================================================================

#[test]
fn random_walk_respects_iteration_count() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
    let strategy = ExplorationStrategy::RandomWalk {
        seed: 99,
        iterations: 7,
    };
    let report = explorer.explore(&scenario, &strategy, "test-rw");
    assert_eq!(report.total_explored, 7);
}

// ===========================================================================
// InterleavingExplorer — targeted race strategy
// ===========================================================================

#[test]
fn targeted_race_includes_identity_ordering() {
    let catalog = RaceSurfaceCatalog::default_catalog();
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectCancel {
                region_id: "r1".to_string(),
            },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(catalog, vec![]);
    let strategy = ExplorationStrategy::TargetedRace {
        race_ids: vec!["race-obligation-vs-cancel".to_string()],
    };
    let report = explorer.explore(&scenario, &strategy, "test-targeted");
    assert!(report.total_explored >= 1);
}

// ===========================================================================
// InterleavingExplorer — invariant-driven failure detection
// ===========================================================================

#[test]
fn explorer_finds_no_failures_on_clean_scenario() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::NoCompletedAndFaulted],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "clean-test",
    );
    assert!(report.all_passed());
    assert_eq!(report.failure_count(), 0);
}

#[test]
fn explorer_detects_failure_with_forbidden_pattern() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "fault-detection",
    );
    assert!(!report.all_passed());
    assert!(report.failure_count() >= 1);
}

#[test]
fn regression_transcripts_populated_from_failures() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "regression-test",
    );
    assert!(!report.regression_transcripts.is_empty());
}

// ===========================================================================
// InterleavingExplorer — determinism
// ===========================================================================

#[test]
fn exploration_is_deterministic() {
    let scenario = Scenario {
        task_count: 2,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::RunTask { task_index: 1 },
            ScenarioAction::AdvanceTime { ticks: 5 },
            ScenarioAction::InjectCancel {
                region_id: "r".to_string(),
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::NoCompletedAndFaulted],
    );
    let strategy = ExplorationStrategy::RandomWalk {
        seed: 123,
        iterations: 10,
    };
    let report1 = explorer.explore(&scenario, &strategy, "det-1");
    let report2 = explorer.explore(&scenario, &strategy, "det-1");
    assert_eq!(report1.total_explored, report2.total_explored);
    assert_eq!(report1.failures, report2.failures);
}

// ===========================================================================
// InterleavingExplorer — minimization
// ===========================================================================

#[test]
fn minimization_produces_shorter_transcript() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
            ScenarioAction::AdvanceTime { ticks: 20 },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        }],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 30,
        },
        "minimize-test",
    );
    assert!(!report.all_passed());
    let has_minimized = report
        .failures
        .iter()
        .any(|f| f.minimized_transcript.is_some());
    assert!(has_minimized);
}

// ===========================================================================
// InterleavingExplorer — multiple checkers
// ===========================================================================

#[test]
fn multiple_checkers_all_applied() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
            InvariantChecker::ForbiddenEventPattern {
                action: "inject_fault".to_string(),
                outcome: "fault=panic".to_string(),
            },
        ],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "multi-checker",
    );
    // At least the ForbiddenEventPattern should trigger.
    assert!(!report.all_passed());
}

// ===========================================================================
// InterleavingExplorer — race surface coverage tracking
// ===========================================================================

#[test]
fn race_surface_coverage_tracked() {
    let scenario = Scenario {
        task_count: 1,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 0 },
        ],
        seed: 42,
    };
    let catalog = RaceSurfaceCatalog::default_catalog();
    let catalog_size = catalog.len();
    let explorer = InterleavingExplorer::new(catalog, vec![]);
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::Exhaustive {
            max_permutations: 10,
        },
        "coverage-test",
    );
    // With 2 actions, all races should be "exercised" per the implementation.
    assert_eq!(report.race_surfaces_covered, catalog_size);
    assert_eq!(report.race_surfaces_total, catalog_size);
}

// ===========================================================================
// Stress — larger scenario with random walk
// ===========================================================================

#[test]
fn stress_random_walk_many_iterations() {
    let scenario = Scenario {
        task_count: 3,
        actions: vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::RunTask { task_index: 1 },
            ScenarioAction::RunTask { task_index: 2 },
            ScenarioAction::CompleteTask { task_index: 0 },
            ScenarioAction::AdvanceTime { ticks: 10 },
            ScenarioAction::InjectCancel {
                region_id: "region-a".to_string(),
            },
        ],
        seed: 42,
    };
    let explorer = InterleavingExplorer::new(
        RaceSurfaceCatalog::default_catalog(),
        vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
        ],
    );
    let report = explorer.explore(
        &scenario,
        &ExplorationStrategy::RandomWalk {
            seed: 777,
            iterations: 50,
        },
        "stress-rw",
    );
    assert_eq!(report.total_explored, 50);
    assert_eq!(report.exploration_id, "stress-rw");
}
