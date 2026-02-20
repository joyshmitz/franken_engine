//! Same-sequence divergent-checkpoint fork detection and safe-mode entry.
//!
//! When two checkpoints share the same `checkpoint_seq` but have different
//! `checkpoint_id` values, this indicates a fork — either a compromised
//! signer, split-brain, or implementation bug.  The system immediately
//! enters safe mode, emits forensic evidence, and awaits operator
//! resolution.
//!
//! Safe mode is sticky: it persists across restarts and cannot be exited
//! without explicit operator acknowledgment.
//!
//! Plan references: Section 10.10 item 8, 9E.3 (checkpointed policy
//! frontier with rollback/fork protection).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::policy_checkpoint::PolicyCheckpoint;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// ForkError
// ---------------------------------------------------------------------------

/// Errors from fork detection operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkError {
    /// A checkpoint fork was detected.
    ForkDetected {
        checkpoint_seq: u64,
        existing_id: EngineObjectId,
        divergent_id: EngineObjectId,
    },
    /// Operation denied: system is in safe mode.
    SafeModeActive { incident_seq: u64, reason: String },
    /// Safe-mode exit requires operator acknowledgment.
    AcknowledgmentRequired { incident_count: usize },
    /// Invalid resolution: the resolution checkpoint does not advance
    /// past the fork point.
    InvalidResolution { fork_seq: u64, resolution_seq: u64 },
    /// Persistence failure.
    PersistenceFailed { detail: String },
}

impl fmt::Display for ForkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForkDetected {
                checkpoint_seq,
                existing_id,
                divergent_id,
            } => write!(
                f,
                "fork detected at seq={checkpoint_seq}: \
                 existing={existing_id}, divergent={divergent_id}"
            ),
            Self::SafeModeActive {
                incident_seq,
                reason,
            } => write!(
                f,
                "safe mode active (incident at seq={incident_seq}): {reason}"
            ),
            Self::AcknowledgmentRequired { incident_count } => write!(
                f,
                "operator acknowledgment required for {incident_count} fork incident(s)"
            ),
            Self::InvalidResolution {
                fork_seq,
                resolution_seq,
            } => write!(
                f,
                "invalid resolution: fork at seq={fork_seq}, \
                 resolution at seq={resolution_seq} does not advance past fork"
            ),
            Self::PersistenceFailed { detail } => {
                write!(f, "persistence failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ForkError {}

// ---------------------------------------------------------------------------
// ForkIncidentReport — forensic evidence
// ---------------------------------------------------------------------------

/// Full forensic report of a checkpoint fork incident.
///
/// Contains both divergent checkpoints, the local frontier state at
/// detection time, and metadata for operator consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkIncidentReport {
    /// Unique identifier for this incident.
    pub incident_id: String,
    /// The checkpoint sequence number where the fork was detected.
    pub fork_seq: u64,
    /// The first (previously accepted or seen) checkpoint ID.
    pub existing_checkpoint_id: EngineObjectId,
    /// The divergent checkpoint ID.
    pub divergent_checkpoint_id: EngineObjectId,
    /// Epoch of the existing checkpoint.
    pub existing_epoch: SecurityEpoch,
    /// Epoch of the divergent checkpoint.
    pub divergent_epoch: SecurityEpoch,
    /// The trust zone where the fork was detected.
    pub zone: String,
    /// Local frontier sequence at detection time.
    pub frontier_seq_at_detection: u64,
    /// Local frontier epoch at detection time.
    pub frontier_epoch_at_detection: SecurityEpoch,
    /// Detection timestamp (deterministic tick).
    pub detected_at_tick: u64,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Whether the existing checkpoint was already accepted.
    pub existing_was_accepted: bool,
    /// Whether this incident has been acknowledged by an operator.
    pub acknowledged: bool,
}

// ---------------------------------------------------------------------------
// CheckpointHistoryEntry
// ---------------------------------------------------------------------------

/// A minimal record of a seen checkpoint at a given sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHistoryEntry {
    pub checkpoint_seq: u64,
    pub checkpoint_id: EngineObjectId,
    pub epoch: SecurityEpoch,
    /// True if this checkpoint was accepted into the frontier.
    pub accepted: bool,
}

// ---------------------------------------------------------------------------
// SafeModeState — persistent safe-mode flag
// ---------------------------------------------------------------------------

/// Persistent safe-mode state.
///
/// Sticky across restarts. Can only be cleared by explicit operator
/// acknowledgment of all fork incidents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeState {
    /// Whether safe mode is currently active.
    pub active: bool,
    /// The checkpoint sequence that triggered safe mode (if active).
    pub trigger_seq: Option<u64>,
    /// Number of unacknowledged incidents.
    pub unacknowledged_count: usize,
}

impl Default for SafeModeState {
    fn default() -> Self {
        Self {
            active: false,
            trigger_seq: None,
            unacknowledged_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ForkEvent — structured audit events
// ---------------------------------------------------------------------------

/// Types of fork-detection events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkEventType {
    /// Fork detected.
    ForkDetected { zone: String, checkpoint_seq: u64 },
    /// Safe mode entered.
    SafeModeEntered { zone: String, trigger_seq: u64 },
    /// Safe mode exited via operator acknowledgment.
    SafeModeExited {
        zone: String,
        acknowledged_incidents: usize,
    },
    /// Checkpoint recorded in history.
    CheckpointRecorded { zone: String, checkpoint_seq: u64 },
    /// Operation denied due to safe mode.
    OperationDenied { zone: String, operation: String },
    /// History window trimmed.
    HistoryTrimmed { zone: String, removed_count: usize },
}

impl fmt::Display for ForkEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForkDetected {
                zone,
                checkpoint_seq,
            } => write!(f, "fork_detected({zone}, seq={checkpoint_seq})"),
            Self::SafeModeEntered { zone, trigger_seq } => {
                write!(f, "safe_mode_entered({zone}, trigger_seq={trigger_seq})")
            }
            Self::SafeModeExited {
                zone,
                acknowledged_incidents,
            } => write!(
                f,
                "safe_mode_exited({zone}, acked={acknowledged_incidents})"
            ),
            Self::CheckpointRecorded {
                zone,
                checkpoint_seq,
            } => write!(f, "checkpoint_recorded({zone}, seq={checkpoint_seq})"),
            Self::OperationDenied { zone, operation } => {
                write!(f, "operation_denied({zone}, op={operation})")
            }
            Self::HistoryTrimmed {
                zone,
                removed_count,
            } => write!(f, "history_trimmed({zone}, removed={removed_count})"),
        }
    }
}

/// A structured fork-detection event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkEvent {
    pub event_type: ForkEventType,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// ForkDetector — per-zone fork detection engine
// ---------------------------------------------------------------------------

/// Per-zone state for fork detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneState {
    /// History of seen checkpoints: seq -> (checkpoint_id, epoch, accepted).
    history: BTreeMap<u64, CheckpointHistoryEntry>,
    /// Maximum history window size.
    max_history: usize,
    /// Safe-mode state for this zone.
    safe_mode: SafeModeState,
    /// Fork incident reports.
    incidents: Vec<ForkIncidentReport>,
    /// Incident counter for ID generation.
    incident_counter: u64,
}

impl ZoneState {
    fn new(max_history: usize) -> Self {
        Self {
            history: BTreeMap::new(),
            max_history,
            safe_mode: SafeModeState::default(),
            incidents: Vec::new(),
            incident_counter: 0,
        }
    }

    fn trim_history(&mut self) -> usize {
        if self.history.len() <= self.max_history {
            return 0;
        }
        let excess = self.history.len() - self.max_history;
        let keys_to_remove: Vec<u64> = self.history.keys().take(excess).copied().collect();
        for k in &keys_to_remove {
            self.history.remove(k);
        }
        keys_to_remove.len()
    }
}

/// Fork detection and safe-mode management across trust zones.
///
/// Maintains a persistent index of `(checkpoint_seq -> checkpoint_id)`
/// for a configurable history window. On fork detection, enters safe
/// mode and emits forensic evidence.
pub struct ForkDetector {
    /// Per-zone state.
    zones: BTreeMap<String, ZoneState>,
    /// Default history window size for new zones.
    default_max_history: usize,
    /// Audit events.
    events: Vec<ForkEvent>,
}

impl ForkDetector {
    /// Create a new fork detector with the given history window size.
    pub fn new(max_history: usize) -> Self {
        Self {
            zones: BTreeMap::new(),
            default_max_history: max_history,
            events: Vec::new(),
        }
    }

    /// Create with default history window of 1000.
    pub fn with_defaults() -> Self {
        Self::new(1000)
    }

    /// Record a checkpoint in the history and check for forks.
    ///
    /// Returns `Ok(())` if no fork is detected, or a `ForkIncidentReport`
    /// if a divergent checkpoint is found.
    ///
    /// The `accepted` parameter indicates whether this checkpoint was
    /// accepted into the frontier (vs. received via gossip/replication).
    pub fn record_checkpoint(
        &mut self,
        zone: &str,
        checkpoint: &PolicyCheckpoint,
        accepted: bool,
        frontier_seq: u64,
        frontier_epoch: SecurityEpoch,
        tick: u64,
        trace_id: &str,
    ) -> Result<(), ForkIncidentReport> {
        let zone_state = self
            .zones
            .entry(zone.to_string())
            .or_insert_with(|| ZoneState::new(self.default_max_history));

        let seq = checkpoint.checkpoint_seq;
        let id = checkpoint.checkpoint_id.clone();

        // Check for divergence against existing history.
        if let Some(existing) = zone_state.history.get(&seq) {
            if existing.checkpoint_id != id {
                // FORK DETECTED.
                zone_state.incident_counter += 1;
                let incident_id = format!(
                    "fork-{zone}-seq{seq}-{counter}",
                    counter = zone_state.incident_counter
                );

                let report = ForkIncidentReport {
                    incident_id,
                    fork_seq: seq,
                    existing_checkpoint_id: existing.checkpoint_id.clone(),
                    divergent_checkpoint_id: id,
                    existing_epoch: existing.epoch,
                    divergent_epoch: checkpoint.epoch_id,
                    zone: zone.to_string(),
                    frontier_seq_at_detection: frontier_seq,
                    frontier_epoch_at_detection: frontier_epoch,
                    detected_at_tick: tick,
                    trace_id: trace_id.to_string(),
                    existing_was_accepted: existing.accepted,
                    acknowledged: false,
                };

                // Enter safe mode.
                zone_state.safe_mode.active = true;
                zone_state.safe_mode.trigger_seq = Some(seq);
                zone_state.safe_mode.unacknowledged_count += 1;
                zone_state.incidents.push(report.clone());

                self.events.push(ForkEvent {
                    event_type: ForkEventType::ForkDetected {
                        zone: zone.to_string(),
                        checkpoint_seq: seq,
                    },
                    trace_id: trace_id.to_string(),
                });
                self.events.push(ForkEvent {
                    event_type: ForkEventType::SafeModeEntered {
                        zone: zone.to_string(),
                        trigger_seq: seq,
                    },
                    trace_id: trace_id.to_string(),
                });

                return Err(report);
            }
            // Same checkpoint at same seq — not a fork, just a duplicate.
            return Ok(());
        }

        // No existing entry — record it.
        zone_state.history.insert(
            seq,
            CheckpointHistoryEntry {
                checkpoint_seq: seq,
                checkpoint_id: checkpoint.checkpoint_id.clone(),
                epoch: checkpoint.epoch_id,
                accepted,
            },
        );

        self.events.push(ForkEvent {
            event_type: ForkEventType::CheckpointRecorded {
                zone: zone.to_string(),
                checkpoint_seq: seq,
            },
            trace_id: trace_id.to_string(),
        });

        // Trim history if needed.
        let trimmed = zone_state.trim_history();
        if trimmed > 0 {
            self.events.push(ForkEvent {
                event_type: ForkEventType::HistoryTrimmed {
                    zone: zone.to_string(),
                    removed_count: trimmed,
                },
                trace_id: trace_id.to_string(),
            });
        }

        Ok(())
    }

    /// Check if a zone is in safe mode.
    pub fn is_safe_mode(&self, zone: &str) -> bool {
        self.zones.get(zone).is_some_and(|z| z.safe_mode.active)
    }

    /// Get the safe-mode state for a zone.
    pub fn safe_mode_state(&self, zone: &str) -> Option<&SafeModeState> {
        self.zones.get(zone).map(|z| &z.safe_mode)
    }

    /// Deny an operation if the zone is in safe mode.
    ///
    /// Call this before any policy-gated operation.
    pub fn enforce_safe_mode(
        &mut self,
        zone: &str,
        operation: &str,
        trace_id: &str,
    ) -> Result<(), ForkError> {
        if let Some(zone_state) = self.zones.get(zone) {
            if zone_state.safe_mode.active {
                self.events.push(ForkEvent {
                    event_type: ForkEventType::OperationDenied {
                        zone: zone.to_string(),
                        operation: operation.to_string(),
                    },
                    trace_id: trace_id.to_string(),
                });
                return Err(ForkError::SafeModeActive {
                    incident_seq: zone_state.safe_mode.trigger_seq.unwrap_or(0),
                    reason: format!("operation '{operation}' denied during safe mode"),
                });
            }
        }
        Ok(())
    }

    /// Get all fork incidents for a zone.
    pub fn incidents(&self, zone: &str) -> &[ForkIncidentReport] {
        self.zones
            .get(zone)
            .map(|z| z.incidents.as_slice())
            .unwrap_or(&[])
    }

    /// Get unacknowledged incidents for a zone.
    pub fn unacknowledged_incidents(&self, zone: &str) -> Vec<&ForkIncidentReport> {
        self.zones
            .get(zone)
            .map(|z| z.incidents.iter().filter(|i| !i.acknowledged).collect())
            .unwrap_or_default()
    }

    /// Acknowledge a fork incident by incident_id.
    ///
    /// Returns true if the incident was found and acknowledged.
    pub fn acknowledge_incident(&mut self, zone: &str, incident_id: &str) -> bool {
        let Some(zone_state) = self.zones.get_mut(zone) else {
            return false;
        };

        let Some(incident) = zone_state
            .incidents
            .iter_mut()
            .find(|i| i.incident_id == incident_id && !i.acknowledged)
        else {
            return false;
        };

        incident.acknowledged = true;
        zone_state.safe_mode.unacknowledged_count =
            zone_state.safe_mode.unacknowledged_count.saturating_sub(1);
        true
    }

    /// Exit safe mode after all incidents are acknowledged.
    ///
    /// Requires that all incidents in the zone have been acknowledged.
    /// Returns `Err` if unacknowledged incidents remain.
    pub fn exit_safe_mode(&mut self, zone: &str, trace_id: &str) -> Result<usize, ForkError> {
        let Some(zone_state) = self.zones.get_mut(zone) else {
            return Ok(0);
        };

        if !zone_state.safe_mode.active {
            return Ok(0);
        }

        let unacked: usize = zone_state
            .incidents
            .iter()
            .filter(|i| !i.acknowledged)
            .count();
        if unacked > 0 {
            return Err(ForkError::AcknowledgmentRequired {
                incident_count: unacked,
            });
        }

        let acked_count = zone_state.incidents.len();
        zone_state.safe_mode.active = false;
        zone_state.safe_mode.trigger_seq = None;
        zone_state.safe_mode.unacknowledged_count = 0;

        self.events.push(ForkEvent {
            event_type: ForkEventType::SafeModeExited {
                zone: zone.to_string(),
                acknowledged_incidents: acked_count,
            },
            trace_id: trace_id.to_string(),
        });

        Ok(acked_count)
    }

    /// Get the checkpoint history for a zone.
    pub fn history(&self, zone: &str) -> Option<&BTreeMap<u64, CheckpointHistoryEntry>> {
        self.zones.get(zone).map(|z| &z.history)
    }

    /// Get the history window size for a zone.
    pub fn history_size(&self, zone: &str) -> usize {
        self.zones.get(zone).map(|z| z.history.len()).unwrap_or(0)
    }

    /// List all known zones.
    pub fn zones(&self) -> Vec<&str> {
        self.zones.keys().map(|s| s.as_str()).collect()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<ForkEvent> {
        std::mem::take(&mut self.events)
    }

    /// Count of events by type.
    pub fn event_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            let key = match &event.event_type {
                ForkEventType::ForkDetected { .. } => "fork_detected",
                ForkEventType::SafeModeEntered { .. } => "safe_mode_entered",
                ForkEventType::SafeModeExited { .. } => "safe_mode_exited",
                ForkEventType::CheckpointRecorded { .. } => "checkpoint_recorded",
                ForkEventType::OperationDenied { .. } => "operation_denied",
                ForkEventType::HistoryTrimmed { .. } => "history_trimmed",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Export the complete detector state for persistence.
    ///
    /// The caller is responsible for serializing the returned map
    /// (e.g., via `serde_json::to_vec`) and persisting it.
    pub fn export_state(&self) -> &BTreeMap<String, ZoneState> {
        &self.zones
    }

    /// Restore detector state from previously exported data.
    pub fn import_state(&mut self, zones: BTreeMap<String, ZoneState>) {
        self.zones = zones;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;
    use crate::policy_checkpoint::{
        CheckpointBuilder, DeterministicTimestamp, PolicyHead, PolicyType,
    };
    use crate::security_epoch::SecurityEpoch;
    use crate::signature_preimage::SigningKey;

    fn make_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn make_policy_head(pt: PolicyType, version: u64) -> PolicyHead {
        let hash_input = format!("{pt}-v{version}");
        PolicyHead {
            policy_type: pt,
            policy_hash: ContentHash::compute(hash_input.as_bytes()),
            policy_version: version,
        }
    }

    fn build_genesis(keys: &[SigningKey], zone: &str) -> PolicyCheckpoint {
        CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), zone)
            .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
            .build(keys)
            .unwrap()
    }

    fn build_after(
        prev: &PolicyCheckpoint,
        seq: u64,
        epoch: SecurityEpoch,
        tick: u64,
        keys: &[SigningKey],
        zone: &str,
    ) -> PolicyCheckpoint {
        CheckpointBuilder::after(prev, seq, epoch, DeterministicTimestamp(tick), zone)
            .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, seq + 1))
            .build(keys)
            .unwrap()
    }

    /// Build a divergent checkpoint at the same seq by using a different
    /// policy version (producing a different checkpoint_id).
    fn build_divergent_at_seq(
        prev: &PolicyCheckpoint,
        seq: u64,
        epoch: SecurityEpoch,
        tick: u64,
        keys: &[SigningKey],
        zone: &str,
        version_offset: u64,
    ) -> PolicyCheckpoint {
        CheckpointBuilder::after(prev, seq, epoch, DeterministicTimestamp(tick), zone)
            .add_policy_head(make_policy_head(
                PolicyType::RuntimeExecution,
                seq + 1 + version_offset,
            ))
            .build(keys)
            .unwrap()
    }

    // -- Basic recording --

    #[test]
    fn record_checkpoint_no_fork() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk], "zone-a");

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();

        assert_eq!(detector.history_size("zone-a"), 1);
        assert!(!detector.is_safe_mode("zone-a"));
    }

    #[test]
    fn duplicate_record_no_fork() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk], "zone-a");

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        // Record same checkpoint again (e.g., via gossip).
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                false,
                0,
                SecurityEpoch::GENESIS,
                200,
                "t-1",
            )
            .unwrap();

        assert_eq!(detector.history_size("zone-a"), 1);
        assert!(!detector.is_safe_mode("zone-a"));
    }

    // -- Fork detection --

    #[test]
    fn fork_detected_on_divergent_checkpoint() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        // Verify they have the same seq but different IDs.
        assert_eq!(cp1_a.checkpoint_seq, cp1_b.checkpoint_seq);
        assert_ne!(cp1_a.checkpoint_id, cp1_b.checkpoint_id);

        let mut detector = ForkDetector::with_defaults();

        // Record genesis.
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();

        // Record first seq=1 checkpoint.
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1a",
            )
            .unwrap();

        // Record divergent seq=1 checkpoint — should trigger fork.
        let report = detector
            .record_checkpoint(
                "zone-a",
                &cp1_b,
                false,
                1,
                SecurityEpoch::GENESIS,
                250,
                "t-1b",
            )
            .unwrap_err();

        assert_eq!(report.fork_seq, 1);
        assert_eq!(report.existing_checkpoint_id, cp1_a.checkpoint_id);
        assert_eq!(report.divergent_checkpoint_id, cp1_b.checkpoint_id);
        assert!(report.existing_was_accepted);
        assert!(!report.acknowledged);
    }

    #[test]
    fn fork_triggers_safe_mode() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1a",
            )
            .unwrap();
        let _ = detector.record_checkpoint(
            "zone-a",
            &cp1_b,
            false,
            1,
            SecurityEpoch::GENESIS,
            250,
            "t-1b",
        );

        assert!(detector.is_safe_mode("zone-a"));
        let sm = detector.safe_mode_state("zone-a").unwrap();
        assert!(sm.active);
        assert_eq!(sm.trigger_seq, Some(1));
        assert_eq!(sm.unacknowledged_count, 1);
    }

    // -- Safe mode enforcement --

    #[test]
    fn safe_mode_denies_operations() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1a",
            )
            .unwrap();
        let _ = detector.record_checkpoint(
            "zone-a",
            &cp1_b,
            false,
            1,
            SecurityEpoch::GENESIS,
            250,
            "t-1b",
        );

        // Operations should be denied.
        let err = detector
            .enforce_safe_mode("zone-a", "capability_grant", "t-deny")
            .unwrap_err();
        assert!(matches!(err, ForkError::SafeModeActive { .. }));
    }

    #[test]
    fn normal_zone_allows_operations() {
        let mut detector = ForkDetector::with_defaults();
        // No fork detected — operations should be allowed.
        detector
            .enforce_safe_mode("zone-a", "capability_grant", "t-ok")
            .unwrap();
    }

    // -- Acknowledgment and safe-mode exit --

    #[test]
    fn acknowledge_and_exit_safe_mode() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1a",
            )
            .unwrap();
        let report = detector
            .record_checkpoint(
                "zone-a",
                &cp1_b,
                false,
                1,
                SecurityEpoch::GENESIS,
                250,
                "t-1b",
            )
            .unwrap_err();

        // Cannot exit without acknowledgment.
        let err = detector.exit_safe_mode("zone-a", "t-exit").unwrap_err();
        assert!(matches!(
            err,
            ForkError::AcknowledgmentRequired { incident_count: 1 }
        ));

        // Acknowledge the incident.
        assert!(detector.acknowledge_incident("zone-a", &report.incident_id));

        // Now exit should work.
        let acked = detector.exit_safe_mode("zone-a", "t-exit").unwrap();
        assert_eq!(acked, 1);
        assert!(!detector.is_safe_mode("zone-a"));
    }

    #[test]
    fn cannot_exit_with_unacknowledged_incidents() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1a",
            )
            .unwrap();
        let _ = detector.record_checkpoint(
            "zone-a",
            &cp1_b,
            false,
            1,
            SecurityEpoch::GENESIS,
            250,
            "t-1b",
        );

        let err = detector.exit_safe_mode("zone-a", "t-exit").unwrap_err();
        assert!(matches!(
            err,
            ForkError::AcknowledgmentRequired { incident_count: 1 }
        ));
        assert!(detector.is_safe_mode("zone-a"));
    }

    // -- Per-zone isolation --

    #[test]
    fn fork_in_one_zone_does_not_affect_another() {
        let sk = make_sk(1);
        let genesis_a = build_genesis(&[sk.clone()], "zone-a");
        let genesis_b = build_genesis(&[sk.clone()], "zone-b");

        let cp1_a = build_after(
            &genesis_a,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_a_fork = build_divergent_at_seq(
            &genesis_a,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk.clone()],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();

        // Record zone-a genesis + checkpoint + fork.
        detector
            .record_checkpoint(
                "zone-a",
                &genesis_a,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-a0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-a1",
            )
            .unwrap();
        let _ = detector.record_checkpoint(
            "zone-a",
            &cp1_a_fork,
            false,
            1,
            SecurityEpoch::GENESIS,
            250,
            "t-a1-fork",
        );

        // Record zone-b genesis.
        detector
            .record_checkpoint(
                "zone-b",
                &genesis_b,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-b0",
            )
            .unwrap();

        // Zone-a in safe mode, zone-b is not.
        assert!(detector.is_safe_mode("zone-a"));
        assert!(!detector.is_safe_mode("zone-b"));

        // Zone-b operations should be allowed.
        detector
            .enforce_safe_mode("zone-b", "grant", "t-b-ok")
            .unwrap();
    }

    // -- Retroactive detection --

    #[test]
    fn retroactive_fork_detection() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );

        let mut detector = ForkDetector::with_defaults();

        // Accept genesis and cp1_a into frontier.
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1",
            )
            .unwrap();

        // Later, receive a divergent checkpoint via gossip (not accepted).
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );
        let report = detector
            .record_checkpoint(
                "zone-a",
                &cp1_b,
                false,
                1,
                SecurityEpoch::GENESIS,
                300,
                "t-gossip",
            )
            .unwrap_err();

        assert!(report.existing_was_accepted);
        assert!(detector.is_safe_mode("zone-a"));
    }

    // -- History window --

    #[test]
    fn history_bounded_by_max() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        // Use a small history window.
        let mut detector = ForkDetector::new(5);

        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();

        let mut prev = genesis;
        for i in 1..=10u64 {
            let cp = build_after(
                &prev,
                i,
                SecurityEpoch::GENESIS,
                100 + i * 100,
                &[sk.clone()],
                "zone-a",
            );
            detector
                .record_checkpoint(
                    "zone-a",
                    &cp,
                    true,
                    i,
                    SecurityEpoch::GENESIS,
                    100 + i * 100,
                    &format!("t-{i}"),
                )
                .unwrap();
            prev = cp;
        }

        // History should be bounded to 5 entries.
        assert!(detector.history_size("zone-a") <= 5);
    }

    // -- Incident listing --

    #[test]
    fn incidents_listed_correctly() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1",
            )
            .unwrap();
        let _ = detector.record_checkpoint(
            "zone-a",
            &cp1_b,
            false,
            1,
            SecurityEpoch::GENESIS,
            250,
            "t-fork",
        );

        assert_eq!(detector.incidents("zone-a").len(), 1);
        assert_eq!(detector.unacknowledged_incidents("zone-a").len(), 1);
    }

    // -- Event counts --

    #[test]
    fn event_counts_accurate() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1",
            )
            .unwrap();
        let _ = detector.record_checkpoint(
            "zone-a",
            &cp1_b,
            false,
            1,
            SecurityEpoch::GENESIS,
            250,
            "t-fork",
        );

        // Deny an operation.
        let _ = detector.enforce_safe_mode("zone-a", "grant", "t-deny");

        let counts = detector.event_counts();
        assert_eq!(counts["checkpoint_recorded"], 2);
        assert_eq!(counts["fork_detected"], 1);
        assert_eq!(counts["safe_mode_entered"], 1);
        assert_eq!(counts["operation_denied"], 1);
    }

    // -- Serialization --

    #[test]
    fn fork_error_serialization_round_trip() {
        let errors = vec![
            ForkError::ForkDetected {
                checkpoint_seq: 5,
                existing_id: EngineObjectId([1; 32]),
                divergent_id: EngineObjectId([2; 32]),
            },
            ForkError::SafeModeActive {
                incident_seq: 5,
                reason: "test".to_string(),
            },
            ForkError::AcknowledgmentRequired { incident_count: 2 },
            ForkError::PersistenceFailed {
                detail: "disk full".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ForkError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn fork_incident_report_serialization_round_trip() {
        let report = ForkIncidentReport {
            incident_id: "fork-z-seq1-1".to_string(),
            fork_seq: 1,
            existing_checkpoint_id: EngineObjectId([1; 32]),
            divergent_checkpoint_id: EngineObjectId([2; 32]),
            existing_epoch: SecurityEpoch::GENESIS,
            divergent_epoch: SecurityEpoch::GENESIS,
            zone: "zone-a".to_string(),
            frontier_seq_at_detection: 1,
            frontier_epoch_at_detection: SecurityEpoch::GENESIS,
            detected_at_tick: 250,
            trace_id: "t-1".to_string(),
            existing_was_accepted: true,
            acknowledged: false,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let restored: ForkIncidentReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, restored);
    }

    #[test]
    fn fork_event_serialization_round_trip() {
        let event = ForkEvent {
            event_type: ForkEventType::ForkDetected {
                zone: "z".to_string(),
                checkpoint_seq: 1,
            },
            trace_id: "t-1".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ForkEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn safe_mode_state_serialization_round_trip() {
        let state = SafeModeState {
            active: true,
            trigger_seq: Some(5),
            unacknowledged_count: 2,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let restored: SafeModeState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, restored);
    }

    // -- Display --

    #[test]
    fn fork_error_display() {
        let err = ForkError::ForkDetected {
            checkpoint_seq: 5,
            existing_id: EngineObjectId([1; 32]),
            divergent_id: EngineObjectId([2; 32]),
        };
        let s = err.to_string();
        assert!(s.contains("fork detected"));
        assert!(s.contains("seq=5"));
    }

    #[test]
    fn fork_event_type_display() {
        let et = ForkEventType::ForkDetected {
            zone: "z".to_string(),
            checkpoint_seq: 3,
        };
        assert!(et.to_string().contains("fork_detected"));
        assert!(et.to_string().contains("3"));
    }

    // -- State persistence --

    #[test]
    fn state_export_and_import() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();

        let exported = detector.export_state().clone();

        let mut detector2 = ForkDetector::with_defaults();
        detector2.import_state(exported);

        assert_eq!(detector2.history_size("zone-a"), 1);
    }

    #[test]
    fn safe_mode_persists_across_import() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk.clone()], "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            &[sk.clone()],
            "zone-a",
        );
        let cp1_b = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            &[sk],
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-0",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-a",
                &cp1_a,
                true,
                1,
                SecurityEpoch::GENESIS,
                200,
                "t-1",
            )
            .unwrap();
        let _ = detector.record_checkpoint(
            "zone-a",
            &cp1_b,
            false,
            1,
            SecurityEpoch::GENESIS,
            250,
            "t-fork",
        );

        assert!(detector.is_safe_mode("zone-a"));

        // Export and import.
        let exported = detector.export_state().clone();
        let mut detector2 = ForkDetector::with_defaults();
        detector2.import_state(exported);

        // Safe mode must persist.
        assert!(detector2.is_safe_mode("zone-a"));
        assert_eq!(detector2.incidents("zone-a").len(), 1);
    }

    // -- Zone listing --

    #[test]
    fn zones_listing() {
        let sk = make_sk(1);
        let genesis_a = build_genesis(&[sk.clone()], "zone-a");
        let genesis_b = build_genesis(&[sk], "zone-b");

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(
                "zone-a",
                &genesis_a,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-a",
            )
            .unwrap();
        detector
            .record_checkpoint(
                "zone-b",
                &genesis_b,
                true,
                0,
                SecurityEpoch::GENESIS,
                100,
                "t-b",
            )
            .unwrap();

        let zones = detector.zones();
        assert_eq!(zones.len(), 2);
        assert!(zones.contains(&"zone-a"));
        assert!(zones.contains(&"zone-b"));
    }
}
