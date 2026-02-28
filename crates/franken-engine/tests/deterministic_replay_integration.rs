//! Integration tests for the `deterministic_replay` module.
//!
//! Exercises the public API from outside the crate boundary:
//! NondeterminismSource, TraceEvent, NondeterminismTrace,
//! ReplayMode, ReplayDivergence, DivergenceSeverity,
//! ReplayEngine, ReplayError,
//! FailoverStrategy, FailoverReason, FailoverRecord, FailoverController, FailoverError,
//! IncidentSeverity, ArtifactKind, IncidentArtifact, IncidentBundle, IncidentBundleBuilder.

use frankenengine_engine::deterministic_replay::{
    ArtifactKind, DivergenceSeverity, FailoverController, FailoverError, FailoverReason,
    FailoverStrategy, IncidentArtifact, IncidentBundle, IncidentBundleBuilder, IncidentSeverity,
    NondeterminismSource, NondeterminismTrace, ReplayEngine, ReplayError, ReplayMode,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_trace() -> NondeterminismTrace {
    let mut trace = NondeterminismTrace::new("session-1");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "router",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 0, 0, 1],
        200,
        "scheduler",
    );
    trace.capture(
        NondeterminismSource::ExternalApiResponse,
        vec![1, 2, 3],
        300,
        "api-client",
    );
    trace
}

// =========================================================================
// NondeterminismSource
// =========================================================================

#[test]
fn source_all_variants() {
    assert_eq!(NondeterminismSource::ALL.len(), 6);
    for source in &NondeterminismSource::ALL {
        assert!(!source.as_str().is_empty());
    }
}

#[test]
fn source_as_str() {
    assert_eq!(
        NondeterminismSource::LaneSelectionRandom.as_str(),
        "lane_selection_random"
    );
    assert_eq!(NondeterminismSource::TimerRead.as_str(), "timer_read");
}

#[test]
fn source_serde_roundtrip() {
    for source in &NondeterminismSource::ALL {
        let json = serde_json::to_string(source).unwrap();
        let restored: NondeterminismSource = serde_json::from_str(&json).unwrap();
        assert_eq!(*source, restored);
    }
}

// =========================================================================
// NondeterminismTrace
// =========================================================================

#[test]
fn trace_new_empty() {
    let trace = NondeterminismTrace::new("session-1");
    assert_eq!(trace.event_count(), 0);
    assert!(!trace.is_finalised());
    assert_eq!(trace.session_id, "session-1");
}

#[test]
fn trace_capture_events() {
    let mut trace = NondeterminismTrace::new("s1");
    let seq0 = trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "router",
    );
    let seq1 = trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 1],
        200,
        "scheduler",
    );
    assert_eq!(seq0, 0);
    assert_eq!(seq1, 1);
    assert_eq!(trace.event_count(), 2);
}

#[test]
fn trace_finalise() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");
    trace.finalise(200);
    assert!(trace.is_finalised());
    assert_eq!(trace.capture_ended_vts, Some(200));
}

#[test]
fn trace_derive_id_deterministic() {
    let mut t1 = NondeterminismTrace::new("s1");
    t1.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");
    let mut t2 = NondeterminismTrace::new("s1");
    t2.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");
    assert_eq!(t1.derive_id(), t2.derive_id());
}

#[test]
fn trace_serde_roundtrip() {
    let trace = make_trace();
    let json = serde_json::to_string(&trace).unwrap();
    let restored: NondeterminismTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
}

// =========================================================================
// ReplayMode
// =========================================================================

#[test]
fn replay_mode_serde_roundtrip() {
    for mode in &[
        ReplayMode::Strict,
        ReplayMode::BestEffort,
        ReplayMode::Validate,
    ] {
        let json = serde_json::to_string(mode).unwrap();
        let restored: ReplayMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, restored);
    }
}

// =========================================================================
// DivergenceSeverity
// =========================================================================

#[test]
fn divergence_severity_ordering() {
    assert!(DivergenceSeverity::Benign < DivergenceSeverity::Warning);
    assert!(DivergenceSeverity::Warning < DivergenceSeverity::Critical);
}

// =========================================================================
// ReplayEngine — exact replay
// =========================================================================

#[test]
fn replay_exact_match() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    assert!(!engine.is_complete());
    assert_eq!(engine.remaining(), 3);

    // Replay with exact same values
    let v = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
        .unwrap();
    assert_eq!(v, vec![42]);

    let v = engine
        .replay_next(NondeterminismSource::TimerRead, &[0, 0, 0, 1])
        .unwrap();
    assert_eq!(v, vec![0, 0, 0, 1]);

    let v = engine
        .replay_next(NondeterminismSource::ExternalApiResponse, &[1, 2, 3])
        .unwrap();
    assert_eq!(v, vec![1, 2, 3]);

    assert!(engine.is_complete());
    assert_eq!(engine.remaining(), 0);
    assert_eq!(engine.divergence_count(), 0);
}

#[test]
fn replay_trace_exhausted() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    // Replay all 3
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
        .unwrap();
    engine
        .replay_next(NondeterminismSource::TimerRead, &[0, 0, 0, 1])
        .unwrap();
    engine
        .replay_next(NondeterminismSource::ExternalApiResponse, &[1, 2, 3])
        .unwrap();

    // Try one more
    let result = engine.replay_next(NondeterminismSource::TimerRead, &[0]);
    assert!(matches!(result, Err(ReplayError::TraceExhausted { .. })));
}

#[test]
fn replay_source_mismatch() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    // First event is LaneSelectionRandom, try TimerRead
    let result = engine.replay_next(NondeterminismSource::TimerRead, &[42]);
    assert!(matches!(result, Err(ReplayError::SourceMismatch { .. })));
}

#[test]
fn replay_strict_critical_divergence() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);

    // LaneSelectionRandom divergence is Critical
    let result = engine.replay_next(NondeterminismSource::LaneSelectionRandom, &[99]);
    assert!(matches!(
        result,
        Err(ReplayError::CriticalDivergence { .. })
    ));
    assert_eq!(engine.divergence_count(), 1);
    assert_eq!(engine.critical_divergences(), 1);
}

#[test]
fn replay_strict_benign_divergence_continues() {
    // TimerRead divergence is Benign
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let v = engine
        .replay_next(NondeterminismSource::TimerRead, &[99])
        .unwrap();
    // In strict mode, returns traced value (not live)
    assert_eq!(v, vec![1]);
    assert_eq!(engine.divergence_count(), 1);
}

#[test]
fn replay_best_effort_records_but_continues() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);

    // Critical divergence in best-effort still continues
    let v = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap();
    assert_eq!(v, vec![42]); // Returns traced value
    assert_eq!(engine.divergence_count(), 1);
}

#[test]
fn replay_validate_returns_live_value() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Validate);

    let v = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap();
    // Validate mode returns live value
    assert_eq!(v, vec![99]);
}

#[test]
fn replay_engine_serde_roundtrip() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
        .unwrap();

    let json = serde_json::to_string(&engine).unwrap();
    let restored: ReplayEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(engine, restored);
}

// =========================================================================
// FailoverStrategy
// =========================================================================

#[test]
fn failover_strategy_serde_roundtrip() {
    for s in &[
        FailoverStrategy::ImmediateBaseline,
        FailoverStrategy::RetryThenBaseline,
        FailoverStrategy::Halt,
    ] {
        let json = serde_json::to_string(s).unwrap();
        let restored: FailoverStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

// =========================================================================
// FailoverController
// =========================================================================

#[test]
fn failover_controller_new() {
    let fc = FailoverController::with_defaults();
    assert_eq!(fc.default_strategy, FailoverStrategy::RetryThenBaseline);
    assert_eq!(fc.max_failovers, 10);
    assert!(!fc.halted);
    assert_eq!(fc.total_failovers, 0);
    assert_eq!(fc.success_rate_millionths(), 1_000_000);
}

#[test]
fn failover_record_failover() {
    let mut fc = FailoverController::with_defaults();
    let record = fc
        .record_failover(
            FailoverReason::SafeModeTriggered,
            "wasm-lane",
            "js-lane",
            100,
            true,
        )
        .unwrap();
    assert_eq!(record.sequence, 0);
    assert_eq!(record.strategy, FailoverStrategy::RetryThenBaseline);
    assert!(record.success);
    assert_eq!(fc.total_failovers, 1);
    assert_eq!(fc.successful_failovers, 1);
    assert_eq!(fc.success_rate_millionths(), 1_000_000);
}

#[test]
fn failover_strategy_override() {
    let mut fc = FailoverController::with_defaults();
    fc.set_override("critical-component", FailoverStrategy::Halt);
    assert_eq!(
        fc.strategy_for("critical-component"),
        FailoverStrategy::Halt
    );
    assert_eq!(
        fc.strategy_for("other-component"),
        FailoverStrategy::RetryThenBaseline
    );
}

#[test]
fn failover_max_exceeded_halts() {
    let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 2);
    fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
        .unwrap();
    fc.record_failover(FailoverReason::Manual, "a", "b", 200, true)
        .unwrap();
    // Third should fail
    let result = fc.record_failover(FailoverReason::Manual, "a", "b", 300, true);
    assert!(matches!(
        result,
        Err(FailoverError::MaxFailoversExceeded { .. })
    ));
    assert!(fc.halted);

    // Further attempts fail with Halted
    let result = fc.record_failover(FailoverReason::Manual, "a", "b", 400, true);
    assert!(matches!(result, Err(FailoverError::Halted)));
}

#[test]
fn failover_controller_serde_roundtrip() {
    let mut fc = FailoverController::with_defaults();
    fc.record_failover(
        FailoverReason::LaneError {
            message: "timeout".into(),
        },
        "wasm",
        "js",
        100,
        true,
    )
    .unwrap();

    let json = serde_json::to_string(&fc).unwrap();
    let restored: FailoverController = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, restored);
}

// =========================================================================
// IncidentSeverity
// =========================================================================

#[test]
fn incident_severity_as_str() {
    assert_eq!(IncidentSeverity::Info.as_str(), "info");
    assert_eq!(IncidentSeverity::Warning.as_str(), "warning");
    assert_eq!(IncidentSeverity::Error.as_str(), "error");
    assert_eq!(IncidentSeverity::Critical.as_str(), "critical");
}

#[test]
fn incident_severity_ordering() {
    assert!(IncidentSeverity::Info < IncidentSeverity::Warning);
    assert!(IncidentSeverity::Warning < IncidentSeverity::Error);
    assert!(IncidentSeverity::Error < IncidentSeverity::Critical);
}

// =========================================================================
// ArtifactKind
// =========================================================================

#[test]
fn artifact_kind_as_str() {
    assert_eq!(
        ArtifactKind::NondeterminismTrace.as_str(),
        "nondeterminism_trace"
    );
    assert_eq!(ArtifactKind::DecisionLog.as_str(), "decision_log");
    assert_eq!(ArtifactKind::DivergenceReport.as_str(), "divergence_report");
}

// =========================================================================
// IncidentArtifact
// =========================================================================

#[test]
fn incident_artifact_new() {
    let artifact =
        IncidentArtifact::new("test-artifact", ArtifactKind::Configuration, vec![1, 2, 3]);
    assert_eq!(artifact.name, "test-artifact");
    assert_eq!(artifact.kind, ArtifactKind::Configuration);
    assert_eq!(artifact.data, vec![1, 2, 3]);
    assert!(!artifact.content_hash.is_empty());
}

#[test]
fn incident_artifact_hash_deterministic() {
    let a1 = IncidentArtifact::new("a", ArtifactKind::DecisionLog, vec![1, 2, 3]);
    let a2 = IncidentArtifact::new("a", ArtifactKind::DecisionLog, vec![1, 2, 3]);
    assert_eq!(a1.content_hash, a2.content_hash);
}

#[test]
fn incident_artifact_serde_roundtrip() {
    let artifact = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![42, 43]);
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: IncidentArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

// =========================================================================
// IncidentBundle
// =========================================================================

#[test]
fn incident_bundle_new() {
    let bundle = IncidentBundle::new(
        "inc-1",
        IncidentSeverity::Error,
        "test incident",
        "router",
        1000,
    );
    assert_eq!(bundle.incident_id, "inc-1");
    assert_eq!(bundle.severity, IncidentSeverity::Error);
    assert!(!bundle.is_finalised());
    assert_eq!(bundle.artifact_count(), 0);
}

#[test]
fn incident_bundle_add_artifacts_and_tags() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Warning, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1, 2, 3],
    ));
    bundle.add_artifact(IncidentArtifact::new(
        "log",
        ArtifactKind::DecisionLog,
        vec![4, 5],
    ));
    bundle.add_tag("auto");
    bundle.add_tag("replay");
    bundle.add_tag("auto"); // duplicate, should not add

    assert_eq!(bundle.artifact_count(), 2);
    assert_eq!(bundle.tags.len(), 2);
    assert_eq!(bundle.total_data_size(), 5);
}

#[test]
fn incident_bundle_finalise() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Critical, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "data",
        ArtifactKind::PerformanceMetrics,
        vec![1],
    ));
    assert!(!bundle.is_finalised());
    bundle.finalise();
    assert!(bundle.is_finalised());
    assert!(!bundle.bundle_hash.is_empty());
}

#[test]
fn incident_bundle_serde_roundtrip() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1],
    ));
    bundle.finalise();

    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}

// =========================================================================
// IncidentBundleBuilder
// =========================================================================

#[test]
fn builder_with_trace_and_failover() {
    let trace = make_trace();
    let mut fc = FailoverController::with_defaults();
    fc.record_failover(FailoverReason::SafeModeTriggered, "wasm", "js", 100, true)
        .unwrap();

    let builder = IncidentBundleBuilder::new(
        "inc-builder",
        IncidentSeverity::Error,
        "test builder",
        "wasm-lane",
        500,
    );

    let bundle = builder.build(Some(&trace), None, Some(&fc));
    assert!(bundle.is_finalised());
    // Should include trace artifact and failover log
    assert!(bundle.artifact_count() >= 2);
    assert!(bundle.tags.contains(&"auto-generated".to_string()));
    assert!(bundle.tags.contains(&"error".to_string()));
}

#[test]
fn builder_with_replay_divergences() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
    // Create a divergence
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap();

    let builder = IncidentBundleBuilder::new(
        "inc-diverge",
        IncidentSeverity::Warning,
        "divergence detected",
        "replay-engine",
        600,
    );

    let bundle = builder.build(Some(&trace), Some(&engine), None);
    assert!(bundle.is_finalised());
    // Should include trace + divergence report
    assert!(bundle.artifact_count() >= 2);
}

#[test]
fn builder_excludes_optional_artifacts() {
    let trace = make_trace();
    let builder = IncidentBundleBuilder::new(
        "inc-minimal",
        IncidentSeverity::Info,
        "minimal",
        "comp",
        100,
    )
    .with_trace(false)
    .with_failovers(false)
    .with_divergences(false);

    let bundle = builder.build(Some(&trace), None, None);
    // Only tags, no trace/failover/divergence artifacts
    assert_eq!(bundle.artifact_count(), 0);
}

#[test]
fn builder_serde_roundtrip() {
    let builder =
        IncidentBundleBuilder::new("inc-1", IncidentSeverity::Critical, "test", "comp", 100);
    let json = serde_json::to_string(&builder).unwrap();
    let restored: IncidentBundleBuilder = serde_json::from_str(&json).unwrap();
    assert_eq!(builder, restored);
}

// =========================================================================
// Full lifecycle: capture → replay → failover → incident bundle
// =========================================================================

#[test]
fn full_lifecycle() {
    // 1. Capture trace
    let mut trace = NondeterminismTrace::new("session-lifecycle");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![0, 42],
        100,
        "router",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 0, 10],
        200,
        "scheduler",
    );
    trace.capture(
        NondeterminismSource::ResourceCheck,
        vec![1],
        300,
        "resource-mgr",
    );
    trace.finalise(400);
    assert!(trace.is_finalised());
    assert_eq!(trace.event_count(), 3);

    // 2. Replay (best-effort, with a benign divergence in TimerRead)
    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[0, 42])
        .unwrap();
    engine
        .replay_next(NondeterminismSource::TimerRead, &[0, 0, 99])
        .unwrap(); // benign divergence
    engine
        .replay_next(NondeterminismSource::ResourceCheck, &[1])
        .unwrap();
    assert!(engine.is_complete());
    assert_eq!(engine.divergence_count(), 1);
    assert_eq!(engine.critical_divergences(), 0);

    // 3. Failover
    let mut fc = FailoverController::with_defaults();
    fc.record_failover(
        FailoverReason::Timeout {
            elapsed_us: 20_000,
            limit_us: 16_000,
        },
        "wasm-lane",
        "js-lane",
        350,
        true,
    )
    .unwrap();

    // 4. Build incident bundle
    let builder = IncidentBundleBuilder::new(
        "incident-lifecycle",
        IncidentSeverity::Warning,
        "timeout during replay",
        "wasm-lane",
        400,
    );
    let bundle = builder.build(Some(&trace), Some(&engine), Some(&fc));
    assert!(bundle.is_finalised());
    assert!(bundle.artifact_count() >= 3); // trace + failover + divergence

    // 5. Serde roundtrip
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}
