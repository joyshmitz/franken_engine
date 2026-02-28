#![forbid(unsafe_code)]
//! Enrichment integration tests for `checkpoint_frontier`.
//!
//! Adds JSON field-name stability, exact Display values, Debug distinctness,
//! error coverage, serde roundtrips, construction and initial state, and
//! event type coverage beyond the existing 48 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::checkpoint_frontier::{
    CheckpointFrontierManager, FrontierEntry, FrontierError, FrontierEvent, FrontierEventType,
    FrontierState, InMemoryBackend,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn oid(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

// ===========================================================================
// 1) FrontierError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn frontier_error_display_all_unique() {
    let variants: Vec<String> = vec![
        FrontierError::RollbackRejected {
            zone: "z1".into(),
            frontier_seq: 10,
            attempted_seq: 5,
        }
        .to_string(),
        FrontierError::DuplicateCheckpoint {
            zone: "z2".into(),
            checkpoint_seq: 3,
        }
        .to_string(),
        FrontierError::ChainLinkageFailure {
            zone: "z3".into(),
            detail: "bad".into(),
        }
        .to_string(),
        FrontierError::QuorumFailure {
            zone: "z4".into(),
            detail: "low".into(),
        }
        .to_string(),
        FrontierError::UnknownZone { zone: "z5".into() }.to_string(),
        FrontierError::EpochRegression {
            zone: "z6".into(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(3),
        }
        .to_string(),
        FrontierError::PersistenceFailed {
            zone: "z7".into(),
            detail: "disk".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn frontier_error_is_std_error() {
    let e = FrontierError::UnknownZone { zone: "x".into() };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn frontier_error_display_contains_zone() {
    let e = FrontierError::RollbackRejected {
        zone: "myzone".into(),
        frontier_seq: 10,
        attempted_seq: 5,
    };
    let s = e.to_string();
    assert!(s.contains("myzone"), "should contain zone: {s}");
}

// ===========================================================================
// 2) FrontierEventType — Display exactness
// ===========================================================================

#[test]
fn frontier_event_type_display_zone_initialized() {
    let et = FrontierEventType::ZoneInitialized {
        zone: "z".into(),
        genesis_seq: 0,
    };
    let s = et.to_string();
    assert!(
        s.contains("zone_initialized") || s.contains("initialized"),
        "should describe init: {s}"
    );
    assert!(s.contains("z"), "should contain zone: {s}");
}

#[test]
fn frontier_event_type_display_checkpoint_accepted() {
    let et = FrontierEventType::CheckpointAccepted {
        zone: "z".into(),
        prev_seq: 1,
        new_seq: 2,
    };
    let s = et.to_string();
    assert!(
        s.contains("checkpoint_accepted") || s.contains("accepted"),
        "should describe accept: {s}"
    );
}

#[test]
fn frontier_event_type_display_all_distinct() {
    let variants: Vec<String> = vec![
        FrontierEventType::ZoneInitialized {
            zone: "z".into(),
            genesis_seq: 0,
        }
        .to_string(),
        FrontierEventType::CheckpointAccepted {
            zone: "z".into(),
            prev_seq: 1,
            new_seq: 2,
        }
        .to_string(),
        FrontierEventType::RollbackRejected {
            zone: "z".into(),
            frontier_seq: 3,
            attempted_seq: 1,
        }
        .to_string(),
        FrontierEventType::DuplicateRejected {
            zone: "z".into(),
            checkpoint_seq: 3,
        }
        .to_string(),
        FrontierEventType::EpochRegressionRejected {
            zone: "z".into(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(3),
        }
        .to_string(),
        FrontierEventType::FrontierLoaded {
            zone: "z".into(),
            frontier_seq: 10,
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_frontier_error() {
    let variants = [
        format!("{:?}", FrontierError::UnknownZone { zone: "a".into() }),
        format!(
            "{:?}",
            FrontierError::PersistenceFailed {
                zone: "b".into(),
                detail: "c".into()
            }
        ),
        format!(
            "{:?}",
            FrontierError::RollbackRejected {
                zone: "d".into(),
                frontier_seq: 1,
                attempted_seq: 0
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 4) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_frontier_error_all() {
    let variants = vec![
        FrontierError::RollbackRejected {
            zone: "z1".into(),
            frontier_seq: 10,
            attempted_seq: 5,
        },
        FrontierError::DuplicateCheckpoint {
            zone: "z2".into(),
            checkpoint_seq: 3,
        },
        FrontierError::ChainLinkageFailure {
            zone: "z3".into(),
            detail: "bad".into(),
        },
        FrontierError::QuorumFailure {
            zone: "z4".into(),
            detail: "low".into(),
        },
        FrontierError::UnknownZone { zone: "z5".into() },
        FrontierError::EpochRegression {
            zone: "z6".into(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(3),
        },
        FrontierError::PersistenceFailed {
            zone: "z7".into(),
            detail: "disk".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: FrontierError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_frontier_entry() {
    let fe = FrontierEntry {
        checkpoint_seq: 42,
        checkpoint_id: oid(1),
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&fe).unwrap();
    let rt: FrontierEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(fe, rt);
}

#[test]
fn serde_roundtrip_frontier_state() {
    let fs = FrontierState {
        zone: "test-zone".into(),
        frontier_seq: 10,
        frontier_checkpoint_id: oid(2),
        frontier_epoch: SecurityEpoch::from_raw(3),
        accept_count: 10,
        recent_ids: vec![
            FrontierEntry {
                checkpoint_seq: 9,
                checkpoint_id: oid(1),
                epoch: SecurityEpoch::from_raw(2),
            },
            FrontierEntry {
                checkpoint_seq: 10,
                checkpoint_id: oid(2),
                epoch: SecurityEpoch::from_raw(3),
            },
        ],
    };
    let json = serde_json::to_string(&fs).unwrap();
    let rt: FrontierState = serde_json::from_str(&json).unwrap();
    assert_eq!(fs, rt);
}

#[test]
fn serde_roundtrip_frontier_event() {
    let fe = FrontierEvent {
        event_type: FrontierEventType::ZoneInitialized {
            zone: "z".into(),
            genesis_seq: 0,
        },
        trace_id: "trace-1".into(),
    };
    let json = serde_json::to_string(&fe).unwrap();
    let rt: FrontierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(fe, rt);
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_frontier_entry() {
    let fe = FrontierEntry {
        checkpoint_seq: 1,
        checkpoint_id: oid(1),
        epoch: SecurityEpoch::from_raw(1),
    };
    let v: serde_json::Value = serde_json::to_value(&fe).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["checkpoint_seq", "checkpoint_id", "epoch"] {
        assert!(obj.contains_key(key), "FrontierEntry missing field: {key}");
    }
}

#[test]
fn json_fields_frontier_state() {
    let fs = FrontierState {
        zone: "z".into(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::from_raw(0),
        accept_count: 0,
        recent_ids: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&fs).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "zone",
        "frontier_seq",
        "frontier_checkpoint_id",
        "frontier_epoch",
        "accept_count",
        "recent_ids",
    ] {
        assert!(obj.contains_key(key), "FrontierState missing field: {key}");
    }
}

#[test]
fn json_fields_frontier_event() {
    let fe = FrontierEvent {
        event_type: FrontierEventType::FrontierLoaded {
            zone: "z".into(),
            frontier_seq: 0,
        },
        trace_id: "t".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fe).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["event_type", "trace_id"] {
        assert!(obj.contains_key(key), "FrontierEvent missing field: {key}");
    }
}

// ===========================================================================
// 6) InMemoryBackend — default
// ===========================================================================

#[test]
fn in_memory_backend_default() {
    let backend = InMemoryBackend::default();
    assert!(!backend.fail_on_persist);
    assert_eq!(backend.persist_count, 0);
}

#[test]
fn in_memory_backend_new() {
    let backend = InMemoryBackend::new();
    assert!(!backend.fail_on_persist);
}

// ===========================================================================
// 7) CheckpointFrontierManager — construction and initial state
// ===========================================================================

#[test]
fn manager_new_empty() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    assert!(manager.zones().is_empty());
}

#[test]
fn manager_get_frontier_unknown_zone() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    assert!(manager.get_frontier("nonexistent").is_none());
}

#[test]
fn manager_drain_events_initially_empty() {
    let backend = InMemoryBackend::new();
    let mut manager = CheckpointFrontierManager::new(backend);
    assert!(manager.drain_events().is_empty());
}

#[test]
fn manager_event_counts_initially_empty() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    assert!(manager.event_counts().is_empty());
}

#[test]
fn manager_recover_empty_backend() {
    let backend = InMemoryBackend::new();
    let mut manager = CheckpointFrontierManager::new(backend);
    let count = manager.recover("trace-1").unwrap();
    assert_eq!(count, 0);
}

#[test]
fn manager_backend_access() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    let b = manager.backend();
    assert!(!b.fail_on_persist);
}
