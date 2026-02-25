//! Global bulkheads for concurrency limiting with backpressure signaling.
//!
//! Bulkheads limit the maximum number of concurrent operations in specific
//! categories to prevent resource exhaustion and cascade failures. When a
//! bulkhead reaches >80% capacity, a backpressure event is emitted for
//! regime detection and adaptive load management.
//!
//! Predefined bulkheads:
//! - `RemoteInFlight`: outbound remote operations (default: 64).
//! - `BackgroundMaintenance`: background tasks (default: 16).
//! - `SagaExecution`: concurrent sagas (default: 8).
//! - `EvidenceFlush`: concurrent evidence writes (default: 4).
//!
//! Permits are RAII-style: acquiring returns a `PermitId` that must be
//! explicitly released. Queue depth limits prevent unbounded waiting.
//!
//! Plan references: Section 10.11 item 26, 9G.8 (scheduler + bulkheads),
//! Top-10 #4 (performance discipline), #8 (per-extension resource budget).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// BulkheadClass — predefined bulkhead categories
// ---------------------------------------------------------------------------

/// Predefined bulkhead categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BulkheadClass {
    /// Outbound remote operations.
    RemoteInFlight,
    /// Background maintenance (GC, compaction, audit, anti-entropy).
    BackgroundMaintenance,
    /// Concurrent saga instances.
    SagaExecution,
    /// Concurrent evidence write operations.
    EvidenceFlush,
}

impl fmt::Display for BulkheadClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteInFlight => f.write_str("remote_in_flight"),
            Self::BackgroundMaintenance => f.write_str("background_maintenance"),
            Self::SagaExecution => f.write_str("saga_execution"),
            Self::EvidenceFlush => f.write_str("evidence_flush"),
        }
    }
}

impl BulkheadClass {
    /// Default configuration for this bulkhead class.
    pub fn default_config(&self) -> BulkheadConfig {
        match self {
            Self::RemoteInFlight => BulkheadConfig {
                max_concurrent: 64,
                max_queue_depth: 128,
                pressure_threshold_pct: 80,
            },
            Self::BackgroundMaintenance => BulkheadConfig {
                max_concurrent: 16,
                max_queue_depth: 32,
                pressure_threshold_pct: 80,
            },
            Self::SagaExecution => BulkheadConfig {
                max_concurrent: 8,
                max_queue_depth: 16,
                pressure_threshold_pct: 80,
            },
            Self::EvidenceFlush => BulkheadConfig {
                max_concurrent: 4,
                max_queue_depth: 8,
                pressure_threshold_pct: 80,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// BulkheadConfig — configurable parameters
// ---------------------------------------------------------------------------

/// Configuration for a bulkhead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadConfig {
    /// Maximum concurrent operations.
    pub max_concurrent: usize,
    /// Maximum queue depth for waiting acquires.
    pub max_queue_depth: usize,
    /// Backpressure threshold as percentage of max_concurrent (0-100).
    pub pressure_threshold_pct: u8,
}

// ---------------------------------------------------------------------------
// PermitId — unique permit identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a bulkhead permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PermitId(pub u64);

impl fmt::Display for PermitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "permit:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// BulkheadEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for bulkhead state changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadEvent {
    /// Bulkhead identifier.
    pub bulkhead_id: String,
    /// Current in-flight count after the event.
    pub current_count: usize,
    /// Maximum concurrent limit.
    pub max_concurrent: usize,
    /// Current queue depth.
    pub queue_depth: usize,
    /// Action taken.
    pub action: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Event type.
    pub event: String,
    /// Permit ID (if applicable).
    pub permit_id: u64,
}

// ---------------------------------------------------------------------------
// BulkheadError — typed errors
// ---------------------------------------------------------------------------

/// Errors from bulkhead operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkheadError {
    /// Bulkhead is full and queue is full (no room to wait).
    BulkheadFull {
        bulkhead_id: String,
        max_concurrent: usize,
        queue_depth: usize,
    },
    /// Permit not found (double release or invalid ID).
    PermitNotFound { permit_id: u64 },
    /// Bulkhead not found.
    BulkheadNotFound { bulkhead_id: String },
    /// Invalid configuration.
    InvalidConfig { reason: String },
}

impl fmt::Display for BulkheadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BulkheadFull {
                bulkhead_id,
                max_concurrent,
                queue_depth,
            } => {
                write!(
                    f,
                    "bulkhead {bulkhead_id} full: {max_concurrent} active, {queue_depth} queued"
                )
            }
            Self::PermitNotFound { permit_id } => {
                write!(f, "permit {permit_id} not found")
            }
            Self::BulkheadNotFound { bulkhead_id } => {
                write!(f, "bulkhead {bulkhead_id} not found")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid bulkhead config: {reason}")
            }
        }
    }
}

impl std::error::Error for BulkheadError {}

// ---------------------------------------------------------------------------
// Bulkhead — a single concurrency limiter
// ---------------------------------------------------------------------------

/// A single bulkhead enforcing a concurrency ceiling.
#[derive(Debug)]
struct Bulkhead {
    config: BulkheadConfig,
    /// Currently held permits.
    active_permits: BTreeMap<u64, String>,
    /// Queued waiters (permit_id, trace_id).
    waiters: Vec<(u64, String)>,
}

impl Bulkhead {
    fn new(config: BulkheadConfig) -> Self {
        Self {
            config,
            active_permits: BTreeMap::new(),
            waiters: Vec::new(),
        }
    }

    fn active_count(&self) -> usize {
        self.active_permits.len()
    }

    fn queue_depth(&self) -> usize {
        self.waiters.len()
    }

    fn is_at_pressure(&self) -> bool {
        let threshold = self
            .config
            .max_concurrent
            .saturating_mul(self.config.pressure_threshold_pct as usize)
            / 100;
        self.active_count() >= threshold
    }
}

// ---------------------------------------------------------------------------
// BulkheadRegistry — centralized registry of all bulkheads
// ---------------------------------------------------------------------------

/// Centralized registry managing all bulkheads.
#[derive(Debug)]
pub struct BulkheadRegistry {
    /// Bulkheads by ID.
    bulkheads: BTreeMap<String, Bulkhead>,
    /// Next permit ID.
    next_permit_id: u64,
    /// Accumulated audit events.
    events: Vec<BulkheadEvent>,
    /// Event counters.
    event_counts: BTreeMap<String, u64>,
}

impl BulkheadRegistry {
    /// Create a registry with default bulkheads.
    pub fn with_defaults() -> Self {
        let mut registry = Self {
            bulkheads: BTreeMap::new(),
            next_permit_id: 1,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        };

        for class in &[
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ] {
            registry
                .bulkheads
                .insert(class.to_string(), Bulkhead::new(class.default_config()));
        }

        registry
    }

    /// Create an empty registry (no default bulkheads).
    pub fn empty() -> Self {
        Self {
            bulkheads: BTreeMap::new(),
            next_permit_id: 1,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Register a custom bulkhead.
    pub fn register(
        &mut self,
        bulkhead_id: &str,
        config: BulkheadConfig,
    ) -> Result<(), BulkheadError> {
        if config.max_concurrent == 0 {
            return Err(BulkheadError::InvalidConfig {
                reason: "max_concurrent must be > 0".to_string(),
            });
        }
        self.bulkheads
            .insert(bulkhead_id.to_string(), Bulkhead::new(config));
        Ok(())
    }

    /// Attempt to acquire a permit from the named bulkhead.
    ///
    /// Returns `Ok(PermitId)` if a slot is available.
    /// If the bulkhead is full but the queue has room, the permit is queued
    /// and returned as acquired (for synchronous deterministic semantics).
    /// If both are full, returns `Err(BulkheadFull)`.
    pub fn acquire(
        &mut self,
        bulkhead_id: &str,
        trace_id: &str,
    ) -> Result<PermitId, BulkheadError> {
        let bh = self
            .bulkheads
            .get_mut(bulkhead_id)
            .ok_or(BulkheadError::BulkheadNotFound {
                bulkhead_id: bulkhead_id.to_string(),
            })?;

        let permit_id = PermitId(self.next_permit_id);
        self.next_permit_id += 1;

        if bh.active_count() < bh.config.max_concurrent {
            // Slot available — acquire directly.
            bh.active_permits.insert(permit_id.0, trace_id.to_string());

            let was_at_pressure = bh.is_at_pressure();
            let current_count = bh.active_count();
            let max_concurrent = bh.config.max_concurrent;
            let queue_depth = bh.queue_depth();

            self.emit_event(BulkheadEvent {
                bulkhead_id: bulkhead_id.to_string(),
                current_count,
                max_concurrent,
                queue_depth,
                action: "acquire".to_string(),
                trace_id: trace_id.to_string(),
                event: "permit_acquired".to_string(),
                permit_id: permit_id.0,
            });
            self.record_count("acquire");

            if was_at_pressure {
                self.emit_event(BulkheadEvent {
                    bulkhead_id: bulkhead_id.to_string(),
                    current_count,
                    max_concurrent,
                    queue_depth,
                    action: "pressure".to_string(),
                    trace_id: trace_id.to_string(),
                    event: "bulkhead_pressure".to_string(),
                    permit_id: permit_id.0,
                });
                self.record_count("pressure");
            }

            Ok(permit_id)
        } else if bh.queue_depth() < bh.config.max_queue_depth {
            // Queue the waiter and immediately promote (deterministic mode).
            // In a real async runtime, this would block/await.
            // For deterministic semantics, we immediately admit the waiter
            // as an over-limit permit (tracked separately).
            bh.waiters.push((permit_id.0, trace_id.to_string()));

            let current_count = bh.active_count();
            let max_concurrent = bh.config.max_concurrent;
            let queue_depth = bh.queue_depth();

            self.emit_event(BulkheadEvent {
                bulkhead_id: bulkhead_id.to_string(),
                current_count,
                max_concurrent,
                queue_depth,
                action: "queued".to_string(),
                trace_id: trace_id.to_string(),
                event: "permit_queued".to_string(),
                permit_id: permit_id.0,
            });
            self.record_count("queued");

            Ok(permit_id)
        } else {
            // Both full — reject.
            let current_count = bh.active_count();
            let max_concurrent = bh.config.max_concurrent;
            let queue_depth = bh.queue_depth();

            self.emit_event(BulkheadEvent {
                bulkhead_id: bulkhead_id.to_string(),
                current_count,
                max_concurrent,
                queue_depth,
                action: "reject".to_string(),
                trace_id: trace_id.to_string(),
                event: "permit_rejected".to_string(),
                permit_id: permit_id.0,
            });
            self.record_count("reject");

            Err(BulkheadError::BulkheadFull {
                bulkhead_id: bulkhead_id.to_string(),
                max_concurrent,
                queue_depth,
            })
        }
    }

    /// Release a permit, freeing a concurrency slot.
    ///
    /// If waiters are queued, the next waiter is promoted to active.
    pub fn release(
        &mut self,
        bulkhead_id: &str,
        permit_id: PermitId,
        trace_id: &str,
    ) -> Result<(), BulkheadError> {
        let bh = self
            .bulkheads
            .get_mut(bulkhead_id)
            .ok_or(BulkheadError::BulkheadNotFound {
                bulkhead_id: bulkhead_id.to_string(),
            })?;

        // Try removing from active permits.
        if bh.active_permits.remove(&permit_id.0).is_some() {
            // Promote next waiter if any.
            if let Some((waiter_id, waiter_trace)) = bh.waiters.first().cloned() {
                bh.waiters.remove(0);
                bh.active_permits.insert(waiter_id, waiter_trace);
            }
        } else {
            // Try removing from waiters.
            let waiter_idx = bh.waiters.iter().position(|(id, _)| *id == permit_id.0);
            if let Some(idx) = waiter_idx {
                bh.waiters.remove(idx);
            } else {
                return Err(BulkheadError::PermitNotFound {
                    permit_id: permit_id.0,
                });
            }
        }

        let current_count = bh.active_count();
        let max_concurrent = bh.config.max_concurrent;
        let queue_depth = bh.queue_depth();

        self.emit_event(BulkheadEvent {
            bulkhead_id: bulkhead_id.to_string(),
            current_count,
            max_concurrent,
            queue_depth,
            action: "release".to_string(),
            trace_id: trace_id.to_string(),
            event: "permit_released".to_string(),
            permit_id: permit_id.0,
        });
        self.record_count("release");

        Ok(())
    }

    /// Get the active count for a bulkhead.
    pub fn active_count(&self, bulkhead_id: &str) -> Option<usize> {
        self.bulkheads.get(bulkhead_id).map(|bh| bh.active_count())
    }

    /// Get the queue depth for a bulkhead.
    pub fn queue_depth(&self, bulkhead_id: &str) -> Option<usize> {
        self.bulkheads.get(bulkhead_id).map(|bh| bh.queue_depth())
    }

    /// Check if a bulkhead is at backpressure threshold.
    pub fn is_at_pressure(&self, bulkhead_id: &str) -> Option<bool> {
        self.bulkheads
            .get(bulkhead_id)
            .map(|bh| bh.is_at_pressure())
    }

    /// Reconfigure a bulkhead (hot-reload). Existing permits are not dropped.
    pub fn reconfigure(
        &mut self,
        bulkhead_id: &str,
        new_config: BulkheadConfig,
    ) -> Result<(), BulkheadError> {
        if new_config.max_concurrent == 0 {
            return Err(BulkheadError::InvalidConfig {
                reason: "max_concurrent must be > 0".to_string(),
            });
        }
        let bh = self
            .bulkheads
            .get_mut(bulkhead_id)
            .ok_or(BulkheadError::BulkheadNotFound {
                bulkhead_id: bulkhead_id.to_string(),
            })?;
        bh.config = new_config;
        Ok(())
    }

    /// Snapshot of all bulkhead states.
    pub fn snapshot(&self) -> BTreeMap<String, BulkheadSnapshot> {
        self.bulkheads
            .iter()
            .map(|(id, bh)| {
                (
                    id.clone(),
                    BulkheadSnapshot {
                        bulkhead_id: id.clone(),
                        active_count: bh.active_count(),
                        max_concurrent: bh.config.max_concurrent,
                        queue_depth: bh.queue_depth(),
                        max_queue_depth: bh.config.max_queue_depth,
                        at_pressure: bh.is_at_pressure(),
                    },
                )
            })
            .collect()
    }

    /// Number of registered bulkheads.
    pub fn bulkhead_count(&self) -> usize {
        self.bulkheads.len()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<BulkheadEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn emit_event(&mut self, event: BulkheadEvent) {
        self.events.push(event);
    }

    fn record_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// BulkheadSnapshot — point-in-time state for dashboards
// ---------------------------------------------------------------------------

/// Point-in-time snapshot of a bulkhead's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadSnapshot {
    pub bulkhead_id: String,
    pub active_count: usize,
    pub max_concurrent: usize,
    pub queue_depth: usize,
    pub max_queue_depth: usize,
    pub at_pressure: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- BulkheadClass --

    #[test]
    fn bulkhead_class_display() {
        assert_eq!(
            BulkheadClass::RemoteInFlight.to_string(),
            "remote_in_flight"
        );
        assert_eq!(
            BulkheadClass::BackgroundMaintenance.to_string(),
            "background_maintenance"
        );
        assert_eq!(BulkheadClass::SagaExecution.to_string(), "saga_execution");
        assert_eq!(BulkheadClass::EvidenceFlush.to_string(), "evidence_flush");
    }

    #[test]
    fn default_configs() {
        assert_eq!(
            BulkheadClass::RemoteInFlight
                .default_config()
                .max_concurrent,
            64
        );
        assert_eq!(
            BulkheadClass::BackgroundMaintenance
                .default_config()
                .max_concurrent,
            16
        );
        assert_eq!(
            BulkheadClass::SagaExecution.default_config().max_concurrent,
            8
        );
        assert_eq!(
            BulkheadClass::EvidenceFlush.default_config().max_concurrent,
            4
        );
    }

    // -- Registry creation --

    #[test]
    fn with_defaults_creates_four_bulkheads() {
        let reg = BulkheadRegistry::with_defaults();
        assert_eq!(reg.bulkhead_count(), 4);
    }

    #[test]
    fn empty_creates_no_bulkheads() {
        let reg = BulkheadRegistry::empty();
        assert_eq!(reg.bulkhead_count(), 0);
    }

    #[test]
    fn register_custom_bulkhead() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "custom",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 20,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        assert_eq!(reg.bulkhead_count(), 1);
    }

    #[test]
    fn register_rejects_zero_concurrent() {
        let mut reg = BulkheadRegistry::empty();
        assert!(matches!(
            reg.register(
                "bad",
                BulkheadConfig {
                    max_concurrent: 0,
                    max_queue_depth: 10,
                    pressure_threshold_pct: 80,
                },
            ),
            Err(BulkheadError::InvalidConfig { .. })
        ));
    }

    // -- Acquire and release --

    #[test]
    fn acquire_and_release() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

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
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 2,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        let p2 = reg.acquire("test", "t2").unwrap(); // queued
        assert_eq!(reg.queue_depth("test"), Some(1));

        // Release p2 from waiters.
        reg.release("test", p2, "t2").unwrap();
        assert_eq!(reg.queue_depth("test"), Some(0));
    }

    #[test]
    fn acquire_rejects_when_both_full() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 1,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        let _p2 = reg.acquire("test", "t2").unwrap(); // queued
        assert!(matches!(
            reg.acquire("test", "t3"),
            Err(BulkheadError::BulkheadFull { .. })
        ));
    }

    #[test]
    fn acquire_nonexistent_bulkhead() {
        let mut reg = BulkheadRegistry::empty();
        assert!(matches!(
            reg.acquire("ghost", "t1"),
            Err(BulkheadError::BulkheadNotFound { .. })
        ));
    }

    #[test]
    fn release_nonexistent_permit() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        assert!(matches!(
            reg.release("test", PermitId(999), "t"),
            Err(BulkheadError::PermitNotFound { .. })
        ));
    }

    #[test]
    fn release_promotes_waiter() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let p1 = reg.acquire("test", "t1").unwrap();
        let _p2 = reg.acquire("test", "t2").unwrap(); // queued
        assert_eq!(reg.active_count("test"), Some(1));
        assert_eq!(reg.queue_depth("test"), Some(1));

        // Release p1 → p2 promoted to active.
        reg.release("test", p1, "t1").unwrap();
        assert_eq!(reg.active_count("test"), Some(1));
        assert_eq!(reg.queue_depth("test"), Some(0));
    }

    // -- Backpressure --

    #[test]
    fn pressure_detected_at_threshold() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 20,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        // Fill to 7 (below 80% of 10 = 8).
        for i in 0..7 {
            reg.acquire("test", &format!("t{i}")).unwrap();
        }
        assert_eq!(reg.is_at_pressure("test"), Some(false));

        // Fill to 8 (at 80%).
        reg.acquire("test", "t7").unwrap();
        assert_eq!(reg.is_at_pressure("test"), Some(true));
    }

    #[test]
    fn pressure_event_emitted() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 50,
            },
        )
        .unwrap();

        // At 50% threshold, 1 of 2 triggers pressure.
        reg.acquire("test", "t1").unwrap();
        // Second acquire should trigger pressure.
        reg.acquire("test", "t2").unwrap();

        let events = reg.drain_events();
        let pressure_events: Vec<_> = events
            .iter()
            .filter(|e| e.event == "bulkhead_pressure")
            .collect();
        assert!(!pressure_events.is_empty());
    }

    // -- Reconfigure --

    #[test]
    fn reconfigure_preserves_permits() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        let _p2 = reg.acquire("test", "t2").unwrap();

        // Reduce limit to 1 — existing permits not dropped.
        reg.reconfigure(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        assert_eq!(reg.active_count("test"), Some(2));
    }

    #[test]
    fn reconfigure_rejects_zero() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        assert!(matches!(
            reg.reconfigure(
                "test",
                BulkheadConfig {
                    max_concurrent: 0,
                    max_queue_depth: 4,
                    pressure_threshold_pct: 80,
                }
            ),
            Err(BulkheadError::InvalidConfig { .. })
        ));
    }

    // -- Snapshot --

    #[test]
    fn snapshot_reflects_state() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 5,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        reg.acquire("test", "t1").unwrap();
        reg.acquire("test", "t2").unwrap();

        let snap = reg.snapshot();
        let s = &snap["test"];
        assert_eq!(s.active_count, 2);
        assert_eq!(s.max_concurrent, 5);
        assert_eq!(s.queue_depth, 0);
        assert!(!s.at_pressure);
    }

    // -- Audit events --

    #[test]
    fn acquire_emits_event() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 20,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        reg.acquire("test", "trace-1").unwrap();

        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "permit_acquired");
        assert_eq!(events[0].trace_id, "trace-1");
    }

    #[test]
    fn release_emits_event() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
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
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 0,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
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
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        let p1 = reg.acquire("test", "t1").unwrap();
        let p2 = reg.acquire("test", "t2").unwrap();
        reg.release("test", p1, "t1").unwrap();
        reg.release("test", p2, "t2").unwrap();

        assert_eq!(reg.event_counts().get("acquire"), Some(&2));
        assert_eq!(reg.event_counts().get("release"), Some(&2));
    }

    // -- Serialization round-trips --

    #[test]
    fn bulkhead_class_serialization_round_trip() {
        let classes = vec![
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ];
        for c in &classes {
            let json = serde_json::to_string(c).expect("serialize");
            let restored: BulkheadClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*c, restored);
        }
    }

    #[test]
    fn bulkhead_config_serialization_round_trip() {
        let config = BulkheadConfig {
            max_concurrent: 64,
            max_queue_depth: 128,
            pressure_threshold_pct: 80,
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: BulkheadConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn bulkhead_event_serialization_round_trip() {
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
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: BulkheadEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn bulkhead_error_serialization_round_trip() {
        let errors = vec![
            BulkheadError::BulkheadFull {
                bulkhead_id: "test".to_string(),
                max_concurrent: 10,
                queue_depth: 5,
            },
            BulkheadError::PermitNotFound { permit_id: 42 },
            BulkheadError::BulkheadNotFound {
                bulkhead_id: "ghost".to_string(),
            },
            BulkheadError::InvalidConfig {
                reason: "bad".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: BulkheadError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn snapshot_serialization_round_trip() {
        let snap = BulkheadSnapshot {
            bulkhead_id: "test".to_string(),
            active_count: 3,
            max_concurrent: 10,
            queue_depth: 1,
            max_queue_depth: 20,
            at_pressure: false,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let restored: BulkheadSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, restored);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert!(
            BulkheadError::BulkheadFull {
                bulkhead_id: "x".to_string(),
                max_concurrent: 10,
                queue_depth: 5,
            }
            .to_string()
            .contains("full")
        );
        assert!(
            BulkheadError::PermitNotFound { permit_id: 42 }
                .to_string()
                .contains("42")
        );
        assert!(
            BulkheadError::InvalidConfig {
                reason: "bad".to_string()
            }
            .to_string()
            .contains("bad")
        );
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_acquire_release_sequence() {
        let run = || -> Vec<BulkheadEvent> {
            let mut reg = BulkheadRegistry::empty();
            reg.register(
                "test",
                BulkheadConfig {
                    max_concurrent: 2,
                    max_queue_depth: 4,
                    pressure_threshold_pct: 80,
                },
            )
            .unwrap();
            let p1 = reg.acquire("test", "t1").unwrap();
            let p2 = reg.acquire("test", "t2").unwrap();
            reg.release("test", p1, "t1").unwrap();
            reg.release("test", p2, "t2").unwrap();
            reg.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- Permit display --

    #[test]
    fn permit_id_display() {
        assert_eq!(PermitId(42).to_string(), "permit:42");
    }

    // -- Full lifecycle with defaults --

    // -- Enrichment: Ord, std::error --

    #[test]
    fn bulkhead_class_ordering() {
        assert!(BulkheadClass::RemoteInFlight < BulkheadClass::BackgroundMaintenance);
        assert!(BulkheadClass::BackgroundMaintenance < BulkheadClass::SagaExecution);
        assert!(BulkheadClass::SagaExecution < BulkheadClass::EvidenceFlush);
    }

    #[test]
    fn bulkhead_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(BulkheadError::BulkheadFull {
                bulkhead_id: "b-1".into(),
                max_concurrent: 10,
                queue_depth: 5,
            }),
            Box::new(BulkheadError::PermitNotFound { permit_id: 42 }),
            Box::new(BulkheadError::BulkheadNotFound {
                bulkhead_id: "b-2".into(),
            }),
            Box::new(BulkheadError::InvalidConfig {
                reason: "bad".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 variants produce distinct messages"
        );
    }

    #[test]
    fn full_lifecycle_with_defaults() {
        let mut reg = BulkheadRegistry::with_defaults();

        // Acquire from each bulkhead.
        let p1 = reg.acquire("remote_in_flight", "t1").unwrap();
        let p2 = reg.acquire("background_maintenance", "t2").unwrap();
        let p3 = reg.acquire("saga_execution", "t3").unwrap();
        let p4 = reg.acquire("evidence_flush", "t4").unwrap();

        assert_eq!(reg.active_count("remote_in_flight"), Some(1));
        assert_eq!(reg.active_count("background_maintenance"), Some(1));
        assert_eq!(reg.active_count("saga_execution"), Some(1));
        assert_eq!(reg.active_count("evidence_flush"), Some(1));

        // Release all.
        reg.release("remote_in_flight", p1, "t1").unwrap();
        reg.release("background_maintenance", p2, "t2").unwrap();
        reg.release("saga_execution", p3, "t3").unwrap();
        reg.release("evidence_flush", p4, "t4").unwrap();

        assert_eq!(reg.active_count("remote_in_flight"), Some(0));
        assert_eq!(reg.active_count("evidence_flush"), Some(0));
    }
}
