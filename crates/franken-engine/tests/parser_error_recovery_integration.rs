//! Integration tests for the parser_error_recovery module.

use frankenengine_engine::parser_error_recovery::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn simple_error() -> SyntaxError {
    SyntaxError {
        offset: 10,
        message: "expected ';'".to_string(),
        tokens_before: 5,
        tokens_after: 20,
        at_statement_boundary: true,
        candidates: vec![";".to_string()],
    }
}

fn ambiguous_error() -> SyntaxError {
    SyntaxError {
        offset: 25,
        message: "unexpected token".to_string(),
        tokens_before: 10,
        tokens_after: 15,
        at_statement_boundary: false,
        candidates: vec![
            ";".to_string(),
            ")".to_string(),
            "}".to_string(),
            ",".to_string(),
        ],
    }
}

fn unrecoverable_error() -> SyntaxError {
    SyntaxError {
        offset: 50,
        message: "completely garbled".to_string(),
        tokens_before: 2,
        tokens_after: 0,
        at_statement_boundary: false,
        candidates: vec![],
    }
}

fn diagnostic_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::Diagnostic,
        ..RecoveryConfig::default()
    }
}

fn execution_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::Execution,
        ..RecoveryConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Mode display
// ---------------------------------------------------------------------------

#[test]
fn mode_display_strict() {
    assert_eq!(RecoveryMode::Strict.to_string(), "strict");
}

#[test]
fn mode_display_diagnostic() {
    assert_eq!(RecoveryMode::Diagnostic.to_string(), "diagnostic");
}

#[test]
fn mode_display_execution() {
    assert_eq!(RecoveryMode::Execution.to_string(), "execution");
}

// ---------------------------------------------------------------------------
// ErrorState display
// ---------------------------------------------------------------------------

#[test]
fn error_state_display_all() {
    assert_eq!(ErrorState::Recoverable.to_string(), "recoverable");
    assert_eq!(ErrorState::Ambiguous.to_string(), "ambiguous");
    assert_eq!(ErrorState::Unrecoverable.to_string(), "unrecoverable");
}

// ---------------------------------------------------------------------------
// RecoveryAction display
// ---------------------------------------------------------------------------

#[test]
fn action_display_all() {
    assert_eq!(
        RecoveryAction::RecoverContinue.to_string(),
        "recover-continue"
    );
    assert_eq!(
        RecoveryAction::PartialRecover.to_string(),
        "partial-recover"
    );
    assert_eq!(RecoveryAction::FailStrict.to_string(), "fail-strict");
}

// ---------------------------------------------------------------------------
// RecoveryOutcome display
// ---------------------------------------------------------------------------

#[test]
fn outcome_display_all() {
    assert_eq!(RecoveryOutcome::CleanParse.to_string(), "clean-parse");
    assert_eq!(RecoveryOutcome::Recovered.to_string(), "recovered");
    assert_eq!(
        RecoveryOutcome::PartiallyRecovered.to_string(),
        "partially-recovered"
    );
    assert_eq!(RecoveryOutcome::StrictFailed.to_string(), "strict-failed");
    assert_eq!(
        RecoveryOutcome::RecoveryFailed.to_string(),
        "recovery-failed"
    );
    assert_eq!(
        RecoveryOutcome::BudgetExhausted.to_string(),
        "budget-exhausted"
    );
}

// ---------------------------------------------------------------------------
// StateProbabilities
// ---------------------------------------------------------------------------

#[test]
fn default_prior_sums_to_million() {
    let prior = StateProbabilities::default();
    assert!(prior.is_valid());
    assert_eq!(
        prior.recoverable + prior.ambiguous + prior.unrecoverable,
        1_000_000
    );
}

#[test]
fn default_prior_values() {
    let prior = StateProbabilities::default();
    assert_eq!(prior.recoverable, 600_000);
    assert_eq!(prior.ambiguous, 300_000);
    assert_eq!(prior.unrecoverable, 100_000);
}

#[test]
fn most_likely_recoverable_when_dominant() {
    let p = StateProbabilities {
        recoverable: 700_000,
        ambiguous: 200_000,
        unrecoverable: 100_000,
    };
    assert_eq!(p.most_likely(), ErrorState::Recoverable);
}

#[test]
fn most_likely_ambiguous_when_dominant() {
    let p = StateProbabilities {
        recoverable: 200_000,
        ambiguous: 600_000,
        unrecoverable: 200_000,
    };
    assert_eq!(p.most_likely(), ErrorState::Ambiguous);
}

#[test]
fn most_likely_unrecoverable_when_dominant() {
    let p = StateProbabilities {
        recoverable: 100_000,
        ambiguous: 200_000,
        unrecoverable: 700_000,
    };
    assert_eq!(p.most_likely(), ErrorState::Unrecoverable);
}

#[test]
fn confidence_returns_max_probability() {
    let p = StateProbabilities {
        recoverable: 100_000,
        ambiguous: 200_000,
        unrecoverable: 700_000,
    };
    assert_eq!(p.confidence(), 700_000);
}

#[test]
fn is_valid_detects_invalid_sum() {
    let p = StateProbabilities {
        recoverable: 500_000,
        ambiguous: 500_000,
        unrecoverable: 500_000,
    };
    assert!(!p.is_valid());
}

// ---------------------------------------------------------------------------
// Bayesian update
// ---------------------------------------------------------------------------

#[test]
fn bayesian_update_with_simple_error_favors_recoverable() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 5,
        tokens_after_error: 20,
        error_offset: 10,
        at_statement_boundary: true,
        single_token_fix: true,
        single_token_delete: true,
        candidate_count: 1,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
    assert_eq!(posterior.most_likely(), ErrorState::Recoverable);
    assert!(posterior.recoverable > prior.recoverable);
}

#[test]
fn bayesian_update_with_no_candidates_favors_unrecoverable() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 2,
        tokens_after_error: 0,
        error_offset: 50,
        at_statement_boundary: false,
        single_token_fix: false,
        single_token_delete: false,
        candidate_count: 0,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
    assert_eq!(posterior.most_likely(), ErrorState::Unrecoverable);
}

#[test]
fn bayesian_update_with_many_candidates_favors_ambiguous() {
    let prior = StateProbabilities {
        recoverable: 333_334,
        ambiguous: 333_333,
        unrecoverable: 333_333,
    };
    let evidence = EvidenceFeatures {
        tokens_before_error: 10,
        tokens_after_error: 15,
        error_offset: 25,
        at_statement_boundary: false,
        single_token_fix: false,
        single_token_delete: true,
        candidate_count: 5,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
    assert_eq!(posterior.most_likely(), ErrorState::Ambiguous);
}

#[test]
fn bayesian_update_deterministic() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 5,
        tokens_after_error: 20,
        error_offset: 10,
        at_statement_boundary: true,
        single_token_fix: true,
        single_token_delete: true,
        candidate_count: 1,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let p1 = bayesian_update(&prior, &evidence);
    let p2 = bayesian_update(&prior, &evidence);
    assert_eq!(p1, p2);
}

#[test]
fn bayesian_update_normalizes_output() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 100,
        tokens_after_error: 200,
        error_offset: 50,
        at_statement_boundary: true,
        single_token_fix: false,
        single_token_delete: true,
        candidate_count: 2,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
}

// ---------------------------------------------------------------------------
// Loss matrix and action selection
// ---------------------------------------------------------------------------

#[test]
fn default_loss_matrix_values() {
    let m = LossMatrix::default();
    assert_eq!(m.recover_recoverable, 2);
    assert_eq!(m.recover_unrecoverable, 90);
    assert_eq!(m.fail_unrecoverable, 1);
}

#[test]
fn expected_loss_for_strongly_recoverable_favors_recover() {
    let posterior = StateProbabilities {
        recoverable: 900_000,
        ambiguous: 50_000,
        unrecoverable: 50_000,
    };
    let matrix = LossMatrix::default();
    let el_recover = expected_loss(RecoveryAction::RecoverContinue, &posterior, &matrix);
    let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &matrix);
    assert!(el_recover < el_fail);
}

#[test]
fn expected_loss_for_strongly_unrecoverable_favors_fail() {
    let posterior = StateProbabilities {
        recoverable: 50_000,
        ambiguous: 50_000,
        unrecoverable: 900_000,
    };
    let matrix = LossMatrix::default();
    let el_recover = expected_loss(RecoveryAction::RecoverContinue, &posterior, &matrix);
    let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &matrix);
    assert!(el_fail < el_recover);
}

#[test]
fn select_action_picks_minimum_expected_loss() {
    let posterior = StateProbabilities {
        recoverable: 900_000,
        ambiguous: 50_000,
        unrecoverable: 50_000,
    };
    let matrix = LossMatrix::default();
    let action = select_action(&posterior, &matrix);
    assert_eq!(action, RecoveryAction::RecoverContinue);
}

#[test]
fn select_action_for_unrecoverable_picks_fail() {
    let posterior = StateProbabilities {
        recoverable: 50_000,
        ambiguous: 50_000,
        unrecoverable: 900_000,
    };
    let matrix = LossMatrix::default();
    let action = select_action(&posterior, &matrix);
    assert_eq!(action, RecoveryAction::FailStrict);
}

// ---------------------------------------------------------------------------
// RepairEdit display
// ---------------------------------------------------------------------------

#[test]
fn repair_edit_insert_display() {
    let edit = RepairEdit::Insert {
        offset: 10,
        token_text: ";".to_string(),
    };
    assert_eq!(edit.to_string(), "insert ';' at 10");
}

#[test]
fn repair_edit_delete_display() {
    let edit = RepairEdit::Delete {
        offset: 20,
        length: 3,
    };
    assert_eq!(edit.to_string(), "delete 3B at 20");
}

#[test]
fn repair_edit_replace_display() {
    let edit = RepairEdit::Replace {
        offset: 5,
        length: 2,
        replacement: "==".to_string(),
    };
    assert_eq!(edit.to_string(), "replace 2B at 5 with '=='");
}

#[test]
fn repair_edit_skip_display() {
    let edit = RepairEdit::Skip {
        offset: 30,
        count: 2,
    };
    assert_eq!(edit.to_string(), "skip 2 tokens at 30");
}

// ---------------------------------------------------------------------------
// RecoveryConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn default_config_is_strict() {
    let config = RecoveryConfig::default();
    assert_eq!(config.mode, RecoveryMode::Strict);
    assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
    assert_eq!(config.max_token_skips, DEFAULT_MAX_TOKEN_SKIPS);
    assert_eq!(config.max_insertions, DEFAULT_MAX_INSERTIONS);
    assert_eq!(
        config.confidence_threshold_millionths,
        DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS
    );
    assert!(config.prior.is_valid());
}

// ---------------------------------------------------------------------------
// run_recovery integration tests
// ---------------------------------------------------------------------------

#[test]
fn clean_parse_no_errors() {
    let config = diagnostic_config();
    let ledger = run_recovery(&[], 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::CleanParse);
    assert!(ledger.attempts.is_empty());
    assert_eq!(ledger.total_edits, 0);
}

#[test]
fn strict_mode_always_fails() {
    let config = RecoveryConfig::default();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::StrictFailed);
    assert!(ledger.attempts.is_empty());
}

#[test]
fn diagnostic_mode_recovers_simple_error() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::Recovered);
    assert_eq!(ledger.attempts.len(), 1);
    assert!(ledger.total_edits > 0);
    assert_eq!(ledger.mode, RecoveryMode::Diagnostic);
}

#[test]
fn diagnostic_mode_with_multiple_errors() {
    let config = diagnostic_config();
    let errors = vec![simple_error(), ambiguous_error()];
    let ledger = run_recovery(&errors, 200, &config);
    assert_eq!(ledger.attempts.len(), 2);
    assert!(ledger.total_edits > 0);
}

#[test]
fn execution_mode_with_recoverable_error() {
    let config = execution_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.mode, RecoveryMode::Execution);
    assert_eq!(ledger.attempts.len(), 1);
}

#[test]
fn unrecoverable_error_fails_recovery() {
    let config = diagnostic_config();
    let errors = vec![unrecoverable_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.attempts.len(), 1);
    // No candidates → fails
    assert!(!ledger.attempts[0].succeeded);
}

#[test]
fn budget_exhaustion_with_many_errors() {
    let mut config = diagnostic_config();
    config.max_attempts = 2;
    let errors = vec![simple_error(), ambiguous_error(), unrecoverable_error()];
    let ledger = run_recovery(&errors, 300, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::BudgetExhausted);
    assert_eq!(ledger.attempts.len(), 2);
}

#[test]
fn attempt_records_evidence_and_posterior() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    let attempt = &ledger.attempts[0];
    assert!(attempt.posterior.is_valid());
    assert_eq!(attempt.attempt_index, 0);
    assert!(attempt.confidence_millionths > 0);
}

#[test]
fn attempt_records_rejected_actions() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    let attempt = &ledger.attempts[0];
    assert_eq!(attempt.rejected_actions.len(), 2);
}

#[test]
fn repair_diff_hash_present_when_edits_applied() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    if ledger.total_edits > 0 {
        assert!(ledger.repair_diff_hash.is_some());
    }
}

#[test]
fn repair_diff_hash_absent_when_no_edits() {
    let config = RecoveryConfig::default(); // strict
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert!(ledger.repair_diff_hash.is_none());
}

#[test]
fn schema_version_present() {
    let config = diagnostic_config();
    let ledger = run_recovery(&[], 100, &config);
    assert_eq!(ledger.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Confidence gating in execution mode
// ---------------------------------------------------------------------------

#[test]
fn execution_mode_gates_on_confidence() {
    let mut config = execution_config();
    config.confidence_threshold_millionths = 999_999; // very high
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    // With extremely high threshold, action may be forced to FailStrict
    let attempt = &ledger.attempts[0];
    if attempt.confidence_millionths < 999_999 {
        assert_eq!(attempt.action, RecoveryAction::FailStrict);
    }
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_same_input_same_output() {
    let config = diagnostic_config();
    let errors = vec![simple_error(), ambiguous_error()];
    let l1 = run_recovery(&errors, 200, &config);
    let l2 = run_recovery(&errors, 200, &config);
    assert_eq!(l1.outcome, l2.outcome);
    assert_eq!(l1.total_edits, l2.total_edits);
    assert_eq!(l1.attempts.len(), l2.attempts.len());
    for (a1, a2) in l1.attempts.iter().zip(l2.attempts.iter()) {
        assert_eq!(a1.posterior, a2.posterior);
        assert_eq!(a1.action, a2.action);
    }
}

// ---------------------------------------------------------------------------
// CalibrationReport
// ---------------------------------------------------------------------------

#[test]
fn calibration_report_computes_rates() {
    let report = CalibrationReport::compute(80, 10, 90, 20, 800_000);
    assert_eq!(report.total_cases, 200);
    assert_eq!(report.true_positives, 80);
    assert_eq!(report.false_positives, 10);
    assert_eq!(report.true_negatives, 90);
    assert_eq!(report.false_negatives, 20);
    // FPR = 10 / (80+10) = 0.1111 ≈ 111_111 millionths
    assert!(report.false_positive_rate_millionths > 100_000);
    assert!(report.false_positive_rate_millionths < 120_000);
}

#[test]
fn calibration_report_zero_positives() {
    let report = CalibrationReport::compute(0, 0, 100, 0, 800_000);
    assert_eq!(report.false_positive_rate_millionths, 0);
}

#[test]
fn calibration_report_schema_version() {
    let report = CalibrationReport::compute(10, 1, 10, 1, 800_000);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Mode policy table
// ---------------------------------------------------------------------------

#[test]
fn mode_policy_table_has_three_entries() {
    let table = mode_policy_table();
    assert_eq!(table.len(), 3);
}

#[test]
fn mode_policy_strict_no_edits() {
    let table = mode_policy_table();
    let strict = table
        .iter()
        .find(|e| e.mode == RecoveryMode::Strict)
        .unwrap();
    assert!(!strict.edits_applied);
    assert!(!strict.execution_uses_recovery);
}

#[test]
fn mode_policy_execution_uses_recovery() {
    let table = mode_policy_table();
    let exec = table
        .iter()
        .find(|e| e.mode == RecoveryMode::Execution)
        .unwrap();
    assert!(exec.edits_applied);
    assert!(exec.execution_uses_recovery);
}

// ---------------------------------------------------------------------------
// EvidenceFeatures
// ---------------------------------------------------------------------------

#[test]
fn evidence_with_hash_updates_hash() {
    let e1 = EvidenceFeatures {
        tokens_before_error: 5,
        tokens_after_error: 20,
        error_offset: 10,
        at_statement_boundary: true,
        single_token_fix: true,
        single_token_delete: true,
        candidate_count: 1,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"placeholder"),
    };
    let e2 = e1.clone().with_hash();
    // Hash should change from placeholder
    assert_ne!(e1.features_hash, e2.features_hash);
}

#[test]
fn evidence_hash_deterministic() {
    let make = || {
        EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: true,
            candidate_count: 1,
            features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"placeholder"),
        }
        .with_hash()
    };
    assert_eq!(make().features_hash, make().features_hash);
}

// ---------------------------------------------------------------------------
// Serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_recovery_mode() {
    for mode in [
        RecoveryMode::Strict,
        RecoveryMode::Diagnostic,
        RecoveryMode::Execution,
    ] {
        let s = serde_json::to_string(&mode).unwrap();
        let back: RecoveryMode = serde_json::from_str(&s).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn serde_roundtrip_error_state() {
    for state in [
        ErrorState::Recoverable,
        ErrorState::Ambiguous,
        ErrorState::Unrecoverable,
    ] {
        let s = serde_json::to_string(&state).unwrap();
        let back: ErrorState = serde_json::from_str(&s).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn serde_roundtrip_recovery_action() {
    for action in [
        RecoveryAction::RecoverContinue,
        RecoveryAction::PartialRecover,
        RecoveryAction::FailStrict,
    ] {
        let s = serde_json::to_string(&action).unwrap();
        let back: RecoveryAction = serde_json::from_str(&s).unwrap();
        assert_eq!(action, back);
    }
}

#[test]
fn serde_roundtrip_state_probabilities() {
    let p = StateProbabilities::default();
    let s = serde_json::to_string(&p).unwrap();
    let back: StateProbabilities = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}

#[test]
fn serde_roundtrip_loss_matrix() {
    let m = LossMatrix::default();
    let s = serde_json::to_string(&m).unwrap();
    let back: LossMatrix = serde_json::from_str(&s).unwrap();
    assert_eq!(m, back);
}

#[test]
fn serde_roundtrip_recovery_config() {
    let c = RecoveryConfig::default();
    let s = serde_json::to_string(&c).unwrap();
    let back: RecoveryConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(c, back);
}

#[test]
fn serde_roundtrip_repair_edit() {
    let edits = vec![
        RepairEdit::Insert {
            offset: 10,
            token_text: ";".to_string(),
        },
        RepairEdit::Delete {
            offset: 20,
            length: 3,
        },
        RepairEdit::Replace {
            offset: 5,
            length: 2,
            replacement: "==".to_string(),
        },
        RepairEdit::Skip {
            offset: 30,
            count: 2,
        },
    ];
    for edit in edits {
        let s = serde_json::to_string(&edit).unwrap();
        let back: RepairEdit = serde_json::from_str(&s).unwrap();
        assert_eq!(edit, back);
    }
}

#[test]
fn serde_roundtrip_decision_ledger() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    let s = serde_json::to_string(&ledger).unwrap();
    let back: DecisionLedger = serde_json::from_str(&s).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn serde_roundtrip_calibration_report() {
    let report = CalibrationReport::compute(80, 10, 90, 20, 800_000);
    let s = serde_json::to_string(&report).unwrap();
    let back: CalibrationReport = serde_json::from_str(&s).unwrap();
    assert_eq!(report, back);
}

#[test]
fn serde_roundtrip_recovery_outcome() {
    for outcome in [
        RecoveryOutcome::CleanParse,
        RecoveryOutcome::Recovered,
        RecoveryOutcome::PartiallyRecovered,
        RecoveryOutcome::StrictFailed,
        RecoveryOutcome::RecoveryFailed,
        RecoveryOutcome::BudgetExhausted,
    ] {
        let s = serde_json::to_string(&outcome).unwrap();
        let back: RecoveryOutcome = serde_json::from_str(&s).unwrap();
        assert_eq!(outcome, back);
    }
}

// ---------------------------------------------------------------------------
// Mixed-scenario integration
// ---------------------------------------------------------------------------

#[test]
fn mixed_errors_produce_partially_recovered() {
    let config = diagnostic_config();
    let errors = vec![simple_error(), unrecoverable_error()];
    let ledger = run_recovery(&errors, 200, &config);
    // simple succeeds, unrecoverable fails
    assert_eq!(ledger.outcome, RecoveryOutcome::PartiallyRecovered);
}

#[test]
fn all_unrecoverable_gives_recovery_failed() {
    let config = diagnostic_config();
    let errors = vec![unrecoverable_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::RecoveryFailed);
}

#[test]
fn input_hash_deterministic() {
    let config = diagnostic_config();
    let l1 = run_recovery(&[], 100, &config);
    let l2 = run_recovery(&[], 100, &config);
    assert_eq!(l1.input_hash, l2.input_hash);
}

#[test]
fn input_hash_changes_with_size() {
    let config = diagnostic_config();
    let l1 = run_recovery(&[], 100, &config);
    let l2 = run_recovery(&[], 200, &config);
    assert_ne!(l1.input_hash, l2.input_hash);
}

#[test]
fn constants_consistent_with_config_defaults() {
    assert_eq!(DEFAULT_MAX_ATTEMPTS, RecoveryConfig::default().max_attempts);
    assert_eq!(
        DEFAULT_MAX_TOKEN_SKIPS,
        RecoveryConfig::default().max_token_skips
    );
    assert_eq!(
        DEFAULT_MAX_INSERTIONS,
        RecoveryConfig::default().max_insertions
    );
    assert_eq!(
        DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS,
        RecoveryConfig::default().confidence_threshold_millionths
    );
}
