//! Integration tests for the `bulkhead` module.
//!
//! Tests concurrency limiting, backpressure signaling, RAII permits,
//! queue depth, waiter promotion, hot-reconfiguration, and serde roundtrips.

#![forbid(unsafe_code)]

use frankenengine_engine::bulkhead::{
    BulkheadClass, BulkheadConfig, BulkheadError, BulkheadEvent, BulkheadRegistry,
    BulkheadSnapshot, PermitId,
};

// ---------------------------------------------------------------------------
// BulkheadClass
// ---------------------------------------------------------------------------

#[test]
fn bulkhead_class_display() {
    assert_eq!(BulkheadClass::RemoteInFlight.to_string(), "remote_in_flight");
    assert_eq!(BulkheadClass::BackgroundMaintenance.to_string(), "background_maintenance");
    assert_eq!(BulkheadClass::SagaExecution.to_string(), "saga_execution");
    assert_eq!(BulkheadClass::EvidenceFlush.to_string(), "evidence_flush");
}

#[test]
fn default_configs_match_expected_limits() {
    assert_eq!(BulkheadClass::RemoteInFlight.default_config().max_concurrent, 64);
    assert_eq!(BulkheadClass::BackgroundMaintenance.default_config().max_concurrent, 16);
    assert_eq!(BulkheadClass::SagaExecution.default_config().max_concurrent, 8);
    assert_eq!(BulkheadClass::EvidenceFlush.default_config().max_concurrent, 4);
}

// ---------------------------------------------------------------------------
// PermitId
// ---------------------------------------------------------------------------

#[test]
fn permit_id_display() {
    assert_eq!(PermitId(42).to_string(), "permit:42");
    assert_eq!(PermitId(0).to_string(), "permit:0");
}

// ---------------------------------------------------------------------------
// BulkheadRegistry — creation
// ---------------------------------------------------------------------------

#[test]
fn with_defaults_creates_four() {
    let reg = BulkheadRegistry::with_defaults();
    assert_eq!(reg.bulkhead_count(), 4);
}

#[test]
fn empty_creates_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.bulkhead_count(), 0);
}

#[test]
fn register_custom_bulkhead() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("custom", BulkheadConfig {
        max_concurrent: 10,
        max_queue_depth: 20,
        pressure_threshold_pct: 80,
    }).unwrap();
    assert_eq!(reg.bulkhead_count(), 1);
}

#[test]
fn register_rejects_zero_concurrent() {
    let mut reg = BulkheadRegistry::empty();
    let err = reg.register("bad", BulkheadConfig {
        max_concurrent: 0,
        max_queue_depth: 10,
        pressure_threshold_pct: 80,
    }).unwrap_err();
    assert!(matches!(err, BulkheadError::InvalidConfig { .. }));
}

// ---------------------------------------------------------------------------
// Acquire and release
// ---------------------------------------------------------------------------

#[test]
fn acquire_and_release_basic() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 2, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();

    let p1 = reg.acquire("test", "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));

    let p2 = reg.acquire("test", "t2").unwrap();
    assert_eq!(reg.active_count("test"), Some(2));

    reg.release("test", p1, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));

    reg.release("test", p2, "t2").unwrap();
    assert_eq!(reg.active_count("test"), Some(0));
}

#[test]
fn acquire_queues_when_full() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 1, max_queue_depth: 2, pressure_threshold_pct: 80,
    }).unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap(); // queued
    assert_eq!(reg.queue_depth("test"), Some(1));
}

#[test]
fn acquire_rejects_when_both_full() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 1, max_queue_depth: 1, pressure_threshold_pct: 80,
    }).unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap(); // queued
    let err = reg.acquire("test", "t3").unwrap_err();
    assert!(matches!(err, BulkheadError::BulkheadFull { .. }));
}

#[test]
fn acquire_nonexistent_bulkhead() {
    let mut reg = BulkheadRegistry::empty();
    let err = reg.acquire("ghost", "t1").unwrap_err();
    assert!(matches!(err, BulkheadError::BulkheadNotFound { .. }));
}

#[test]
fn release_nonexistent_permit() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 2, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();
    let err = reg.release("test", PermitId(999), "t").unwrap_err();
    assert!(matches!(err, BulkheadError::PermitNotFound { .. }));
}

#[test]
fn release_promotes_waiter() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 1, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();

    let p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap(); // queued
    assert_eq!(reg.active_count("test"), Some(1));
    assert_eq!(reg.queue_depth("test"), Some(1));

    reg.release("test", p1, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1)); // p2 promoted
    assert_eq!(reg.queue_depth("test"), Some(0));
}

#[test]
fn release_queued_permit() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 1, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let p2 = reg.acquire("test", "t2").unwrap(); // queued
    assert_eq!(reg.queue_depth("test"), Some(1));

    reg.release("test", p2, "t2").unwrap();
    assert_eq!(reg.queue_depth("test"), Some(0));
}

// ---------------------------------------------------------------------------
// Backpressure
// ---------------------------------------------------------------------------

#[test]
fn pressure_detected_at_threshold() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 10, max_queue_depth: 20, pressure_threshold_pct: 80,
    }).unwrap();

    for i in 0..7 {
        reg.acquire("test", &format!("t{i}")).unwrap();
    }
    assert_eq!(reg.is_at_pressure("test"), Some(false));

    reg.acquire("test", "t7").unwrap();
    assert_eq!(reg.is_at_pressure("test"), Some(true));
}

#[test]
fn pressure_event_emitted() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 2, max_queue_depth: 4, pressure_threshold_pct: 50,
    }).unwrap();

    reg.acquire("test", "t1").unwrap();
    reg.acquire("test", "t2").unwrap();

    let events = reg.drain_events();
    assert!(events.iter().any(|e| e.event == "bulkhead_pressure"));
}

#[test]
fn is_at_pressure_nonexistent_returns_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.is_at_pressure("ghost"), None);
}

// ---------------------------------------------------------------------------
// Reconfigure
// ---------------------------------------------------------------------------

#[test]
fn reconfigure_preserves_permits() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 2, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap();

    reg.reconfigure("test", BulkheadConfig {
        max_concurrent: 1, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();

    assert_eq!(reg.active_count("test"), Some(2));
}

#[test]
fn reconfigure_rejects_zero() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 2, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();
    let err = reg.reconfigure("test", BulkheadConfig {
        max_concurrent: 0, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap_err();
    assert!(matches!(err, BulkheadError::InvalidConfig { .. }));
}

#[test]
fn reconfigure_nonexistent_fails() {
    let mut reg = BulkheadRegistry::empty();
    let err = reg.reconfigure("ghost", BulkheadConfig {
        max_concurrent: 1, max_queue_depth: 1, pressure_threshold_pct: 80,
    }).unwrap_err();
    assert!(matches!(err, BulkheadError::BulkheadNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

#[test]
fn snapshot_reflects_state() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 5, max_queue_depth: 10, pressure_threshold_pct: 80,
    }).unwrap();

    reg.acquire("test", "t1").unwrap();
    reg.acquire("test", "t2").unwrap();

    let snap = reg.snapshot();
    let s = &snap["test"];
    assert_eq!(s.active_count, 2);
    assert_eq!(s.max_concurrent, 5);
    assert_eq!(s.queue_depth, 0);
    assert!(!s.at_pressure);
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[test]
fn acquire_emits_event() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 10, max_queue_depth: 20, pressure_threshold_pct: 80,
    }).unwrap();
    reg.acquire("test", "trace-1").unwrap();

    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "permit_acquired");
    assert_eq!(events[0].trace_id, "trace-1");
}

#[test]
fn release_emits_event() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 2, max_queue_depth: 4, pressure_threshold_pct: 80,
    }).unwrap();
    let p = reg.acquire("test", "t1").unwrap();
    reg.drain_events();
    reg.release("test", p, "t1").unwrap();

    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "permit_released");
}

#[test]
fn reject_emits_event() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 1, max_queue_depth: 0, pressure_threshold_pct: 80,
    }).unwrap();
    reg.acquire("test", "t1").unwrap();
    reg.drain_events();

    let _ = reg.acquire("test", "t2");
    let events = reg.drain_events();
    assert!(!events.is_empty());
    assert_eq!(events[0].event, "permit_rejected");
}

#[test]
fn event_counts_track() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 10, max_queue_depth: 10, pressure_threshold_pct: 80,
    }).unwrap();
    let p1 = reg.acquire("test", "t1").unwrap();
    let p2 = reg.acquire("test", "t2").unwrap();
    reg.release("test", p1, "t1").unwrap();
    reg.release("test", p2, "t2").unwrap();

    assert_eq!(reg.event_counts().get("acquire"), Some(&2));
    assert_eq!(reg.event_counts().get("release"), Some(&2));
}

// ---------------------------------------------------------------------------
// BulkheadError display
// ---------------------------------------------------------------------------

#[test]
fn error_display_full() {
    let err = BulkheadError::BulkheadFull {
        bulkhead_id: "x".to_string(),
        max_concurrent: 10,
        queue_depth: 5,
    };
    let s = err.to_string();
    assert!(s.contains("full"));
    assert!(s.contains("x"));
}

#[test]
fn error_display_permit_not_found() {
    let err = BulkheadError::PermitNotFound { permit_id: 42 };
    assert!(err.to_string().contains("42"));
}

#[test]
fn error_display_not_found() {
    let err = BulkheadError::BulkheadNotFound { bulkhead_id: "ghost".to_string() };
    assert!(err.to_string().contains("ghost"));
}

#[test]
fn error_display_invalid_config() {
    let err = BulkheadError::InvalidConfig { reason: "bad".to_string() };
    assert!(err.to_string().contains("bad"));
}

#[test]
fn error_is_std_error() {
    let err = BulkheadError::PermitNotFound { permit_id: 1 };
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn bulkhead_class_serde_roundtrip() {
    let classes = [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ];
    for c in &classes {
        let json = serde_json::to_string(c).unwrap();
        let restored: BulkheadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

#[test]
fn bulkhead_config_serde_roundtrip() {
    let config = BulkheadConfig { max_concurrent: 64, max_queue_depth: 128, pressure_threshold_pct: 80 };
    let json = serde_json::to_string(&config).unwrap();
    let restored: BulkheadConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn bulkhead_event_serde_roundtrip() {
    let event = BulkheadEvent {
        bulkhead_id: "test".to_string(),
        current_count: 5,
        max_concurrent: 10,
        queue_depth: 2,
        action: "acquire".to_string(),
        trace_id: "t1".to_string(),
        event: "permit_acquired".to_string(),
        permit_id: 42,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: BulkheadEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn bulkhead_error_serde_roundtrip() {
    let errors = [
        BulkheadError::BulkheadFull { bulkhead_id: "t".to_string(), max_concurrent: 10, queue_depth: 5 },
        BulkheadError::PermitNotFound { permit_id: 42 },
        BulkheadError::BulkheadNotFound { bulkhead_id: "g".to_string() },
        BulkheadError::InvalidConfig { reason: "bad".to_string() },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: BulkheadError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn snapshot_serde_roundtrip() {
    let snap = BulkheadSnapshot {
        bulkhead_id: "test".to_string(),
        active_count: 3,
        max_concurrent: 10,
        queue_depth: 1,
        max_queue_depth: 20,
        at_pressure: false,
    };
    let json = serde_json::to_string(&snap).unwrap();
    let restored: BulkheadSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_acquire_release_sequence() {
    let run = || -> Vec<BulkheadEvent> {
        let mut reg = BulkheadRegistry::empty();
        reg.register("test", BulkheadConfig {
            max_concurrent: 2, max_queue_depth: 4, pressure_threshold_pct: 80,
        }).unwrap();
        let p1 = reg.acquire("test", "t1").unwrap();
        let p2 = reg.acquire("test", "t2").unwrap();
        reg.release("test", p1, "t1").unwrap();
        reg.release("test", p2, "t2").unwrap();
        reg.drain_events()
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// Full lifecycle with defaults
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_with_defaults() {
    let mut reg = BulkheadRegistry::with_defaults();
    let p1 = reg.acquire("remote_in_flight", "t1").unwrap();
    let p2 = reg.acquire("background_maintenance", "t2").unwrap();
    let p3 = reg.acquire("saga_execution", "t3").unwrap();
    let p4 = reg.acquire("evidence_flush", "t4").unwrap();

    assert_eq!(reg.active_count("remote_in_flight"), Some(1));
    assert_eq!(reg.active_count("background_maintenance"), Some(1));
    assert_eq!(reg.active_count("saga_execution"), Some(1));
    assert_eq!(reg.active_count("evidence_flush"), Some(1));

    reg.release("remote_in_flight", p1, "t1").unwrap();
    reg.release("background_maintenance", p2, "t2").unwrap();
    reg.release("saga_execution", p3, "t3").unwrap();
    reg.release("evidence_flush", p4, "t4").unwrap();

    assert_eq!(reg.active_count("remote_in_flight"), Some(0));
    assert_eq!(reg.active_count("evidence_flush"), Some(0));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn active_count_nonexistent_returns_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.active_count("ghost"), None);
}

#[test]
fn queue_depth_nonexistent_returns_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.queue_depth("ghost"), None);
}

#[test]
fn fill_to_capacity_and_drain() {
    let mut reg = BulkheadRegistry::empty();
    reg.register("test", BulkheadConfig {
        max_concurrent: 3, max_queue_depth: 0, pressure_threshold_pct: 80,
    }).unwrap();

    let p1 = reg.acquire("test", "t1").unwrap();
    let p2 = reg.acquire("test", "t2").unwrap();
    let p3 = reg.acquire("test", "t3").unwrap();
    assert!(reg.acquire("test", "t4").is_err());

    reg.release("test", p1, "t1").unwrap();
    reg.release("test", p2, "t2").unwrap();
    reg.release("test", p3, "t3").unwrap();
    assert_eq!(reg.active_count("test"), Some(0));
}
