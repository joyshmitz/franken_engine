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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeState {
    /// Whether safe mode is currently active.
    pub active: bool,
    /// The checkpoint sequence that triggered safe mode (if active).
    pub trigger_seq: Option<u64>,
    /// Number of unacknowledged incidents.
    pub unacknowledged_count: usize,
}

/// Environment variables that can force startup in safe mode.
pub const SAFE_MODE_ENV_FLAGS: [&str; 2] = ["FRANKEN_SAFE_MODE", "FRANKENENGINE_SAFE_MODE"];

/// Source that requested safe-mode startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeModeStartupSource {
    NotRequested,
    CliFlag,
    EnvironmentVariable,
}

impl fmt::Display for SafeModeStartupSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRequested => f.write_str("not-requested"),
            Self::CliFlag => f.write_str("cli-flag"),
            Self::EnvironmentVariable => f.write_str("environment-variable"),
        }
    }
}

/// Conservative runtime restrictions applied in startup safe mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeRestrictions {
    pub all_extensions_sandboxed: bool,
    pub auto_promotion_disabled: bool,
    pub conservative_policy_defaults: bool,
    pub enhanced_telemetry: bool,
    pub adaptive_tuning_disabled: bool,
}

impl SafeModeRestrictions {
    fn conservative() -> Self {
        Self {
            all_extensions_sandboxed: true,
            auto_promotion_disabled: true,
            conservative_policy_defaults: true,
            enhanced_telemetry: true,
            adaptive_tuning_disabled: true,
        }
    }

    fn normal() -> Self {
        Self {
            all_extensions_sandboxed: false,
            auto_promotion_disabled: false,
            conservative_policy_defaults: false,
            enhanced_telemetry: false,
            adaptive_tuning_disabled: false,
        }
    }
}

/// Structured startup-safe-mode event for deterministic diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeStartupEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Input for deterministic startup safe-mode evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeStartupInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub cli_safe_mode: bool,
    /// Environment snapshot read at startup (`key -> value`).
    pub environment: BTreeMap<String, String>,
}

/// Startup artifact describing mode selection and restrictions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeStartupArtifact {
    pub safe_mode_active: bool,
    pub source: SafeModeStartupSource,
    pub restrictions: SafeModeRestrictions,
    pub startup_sequence: Vec<String>,
    pub restricted_features: Vec<String>,
    pub exit_procedure: Vec<String>,
    pub evidence_preserved: bool,
    pub logs_preserved: bool,
    pub state_preserved: bool,
    pub events: Vec<SafeModeStartupEvent>,
}

/// Input for determining whether it is safe to leave startup safe mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeExitCheckInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub active_incidents: usize,
    pub pending_quarantines: usize,
    pub evidence_ledger_flushed: bool,
}

/// Exit readiness artifact for safe-mode recovery procedures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeExitCheckArtifact {
    pub can_exit: bool,
    pub blocking_reasons: Vec<String>,
    pub event: SafeModeStartupEvent,
}

/// Errors for safe-mode startup/exit evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeModeStartupError {
    MissingField { field: String },
}

impl fmt::Display for SafeModeStartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => write!(f, "missing required field: {field}"),
        }
    }
}

impl std::error::Error for SafeModeStartupError {}

fn parse_safe_mode_env_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn safe_mode_requested_by_env(environment: &BTreeMap<String, String>) -> bool {
    SAFE_MODE_ENV_FLAGS.iter().any(|key| {
        environment
            .get(*key)
            .is_some_and(|value| parse_safe_mode_env_value(value))
    })
}

fn validate_startup_metadata(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> Result<(), SafeModeStartupError> {
    if trace_id.trim().is_empty() {
        return Err(SafeModeStartupError::MissingField {
            field: "trace_id".to_string(),
        });
    }
    if decision_id.trim().is_empty() {
        return Err(SafeModeStartupError::MissingField {
            field: "decision_id".to_string(),
        });
    }
    if policy_id.trim().is_empty() {
        return Err(SafeModeStartupError::MissingField {
            field: "policy_id".to_string(),
        });
    }
    Ok(())
}

/// Evaluate startup mode selection with deterministic safe-mode behavior.
pub fn evaluate_safe_mode_startup(
    input: &SafeModeStartupInput,
) -> Result<SafeModeStartupArtifact, SafeModeStartupError> {
    validate_startup_metadata(&input.trace_id, &input.decision_id, &input.policy_id)?;

    let source = if input.cli_safe_mode {
        SafeModeStartupSource::CliFlag
    } else if safe_mode_requested_by_env(&input.environment) {
        SafeModeStartupSource::EnvironmentVariable
    } else {
        SafeModeStartupSource::NotRequested
    };
    let safe_mode_active = source != SafeModeStartupSource::NotRequested;

    let mut events = vec![SafeModeStartupEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "safe_mode_startup".to_string(),
        event: "safe_mode_flag_evaluated".to_string(),
        outcome: source.to_string(),
        error_code: if safe_mode_active {
            Some("FE-SAFE-MODE-STARTUP".to_string())
        } else {
            None
        },
    }];

    let (restrictions, startup_sequence, restricted_features, exit_procedure) = if safe_mode_active
    {
        events.push(SafeModeStartupEvent {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "safe_mode_startup".to_string(),
            event: "safe_mode_restrictions_applied".to_string(),
            outcome: "conservative".to_string(),
            error_code: Some("FE-SAFE-MODE-RESTRICTIONS".to_string()),
        });
        (
            SafeModeRestrictions::conservative(),
            vec![
                "initialize_runtime_context".to_string(),
                "force_all_extensions_sandboxed".to_string(),
                "disable_auto_promotion".to_string(),
                "apply_conservative_policy_defaults".to_string(),
                "enable_enhanced_telemetry".to_string(),
                "disable_adaptive_tuning".to_string(),
                "persist_safe_mode_entry_evidence".to_string(),
            ],
            vec![
                "extension_auto_promotion".to_string(),
                "adaptive_policy_tuning".to_string(),
                "speculative_optimizations".to_string(),
            ],
            vec![
                "verify_no_active_incidents".to_string(),
                "verify_no_pending_quarantines".to_string(),
                "verify_evidence_ledger_flushed".to_string(),
                "emit_safe_mode_exit_receipt".to_string(),
                "switch_runtime_to_normal_mode".to_string(),
            ],
        )
    } else {
        events.push(SafeModeStartupEvent {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "safe_mode_startup".to_string(),
            event: "safe_mode_not_enabled".to_string(),
            outcome: "normal".to_string(),
            error_code: None,
        });
        (
            SafeModeRestrictions::normal(),
            vec![
                "initialize_runtime_context".to_string(),
                "load_policy_frontier".to_string(),
                "load_extension_catalog".to_string(),
                "start_normal_execution_lanes".to_string(),
            ],
            Vec::new(),
            vec![
                "safe_mode_not_active".to_string(),
                "no_exit_transition_required".to_string(),
            ],
        )
    };

    Ok(SafeModeStartupArtifact {
        safe_mode_active,
        source,
        restrictions,
        startup_sequence,
        restricted_features,
        exit_procedure,
        evidence_preserved: true,
        logs_preserved: true,
        state_preserved: true,
        events,
    })
}

/// Evaluate whether safe-mode exit can proceed with deterministic blocking reasons.
pub fn evaluate_safe_mode_exit(
    input: &SafeModeExitCheckInput,
) -> Result<SafeModeExitCheckArtifact, SafeModeStartupError> {
    validate_startup_metadata(&input.trace_id, &input.decision_id, &input.policy_id)?;

    let mut blocking_reasons = Vec::new();
    if input.active_incidents > 0 {
        blocking_reasons.push(format!(
            "active_incidents_remaining:{}",
            input.active_incidents
        ));
    }
    if input.pending_quarantines > 0 {
        blocking_reasons.push(format!(
            "pending_quarantines_remaining:{}",
            input.pending_quarantines
        ));
    }
    if !input.evidence_ledger_flushed {
        blocking_reasons.push("evidence_ledger_not_flushed".to_string());
    }

    let can_exit = blocking_reasons.is_empty();
    let event = SafeModeStartupEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "safe_mode_startup".to_string(),
        event: "safe_mode_exit_check".to_string(),
        outcome: if can_exit { "pass" } else { "fail" }.to_string(),
        error_code: if can_exit {
            None
        } else {
            Some("FE-SAFE-MODE-EXIT-BLOCKED".to_string())
        },
    };

    Ok(SafeModeExitCheckArtifact {
        can_exit,
        blocking_reasons,
        event,
    })
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

/// Input parameters for [`ForkDetector::record_checkpoint`].
pub struct RecordCheckpointInput<'a> {
    /// The trust zone to record the checkpoint in.
    pub zone: &'a str,
    /// The checkpoint to record.
    pub checkpoint: &'a PolicyCheckpoint,
    /// Whether this checkpoint was accepted into the frontier.
    pub accepted: bool,
    /// The current frontier sequence number.
    pub frontier_seq: u64,
    /// The current frontier epoch.
    pub frontier_epoch: SecurityEpoch,
    /// Deterministic tick at which this checkpoint was observed.
    pub tick: u64,
    /// Trace ID for correlation.
    pub trace_id: &'a str,
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
    /// Returns `Ok(())` if no fork is detected, or a boxed
    /// `ForkIncidentReport` if a divergent checkpoint is found.
    pub fn record_checkpoint(
        &mut self,
        input: &RecordCheckpointInput<'_>,
    ) -> Result<(), Box<ForkIncidentReport>> {
        let zone = input.zone;
        let checkpoint = input.checkpoint;
        let accepted = input.accepted;
        let frontier_seq = input.frontier_seq;
        let frontier_epoch = input.frontier_epoch;
        let tick = input.tick;
        let trace_id = input.trace_id;

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

                return Err(Box::new(report));
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
        if let Some(zone_state) = self.zones.get(zone)
            && zone_state.safe_mode.active
        {
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        // Record same checkpoint again (e.g., via gossip).
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: false,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();

        assert_eq!(detector.history_size("zone-a"), 1);
        assert!(!detector.is_safe_mode("zone-a"));
    }

    // -- Fork detection --

    #[test]
    fn fork_detected_on_divergent_checkpoint() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();

        // Record first seq=1 checkpoint.
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1a",
            })
            .unwrap();

        // Record divergent seq=1 checkpoint — should trigger fork.
        let report = detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_b,
                accepted: false,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 250,
                trace_id: "t-1b",
            })
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
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1a",
            })
            .unwrap();
        let _ = detector.record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_b,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 250,
            trace_id: "t-1b",
        });

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
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1a",
            })
            .unwrap();
        let _ = detector.record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_b,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 250,
            trace_id: "t-1b",
        });

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
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1a",
            })
            .unwrap();
        let report = detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_b,
                accepted: false,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 250,
                trace_id: "t-1b",
            })
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
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1a",
            })
            .unwrap();
        let _ = detector.record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_b,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 250,
            trace_id: "t-1b",
        });

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
        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let genesis_b = build_genesis(std::slice::from_ref(&sk), "zone-b");

        let cp1_a = build_after(
            &genesis_a,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let cp1_a_fork = build_divergent_at_seq(
            &genesis_a,
            1,
            SecurityEpoch::GENESIS,
            250,
            std::slice::from_ref(&sk),
            "zone-a",
            100,
        );

        let mut detector = ForkDetector::with_defaults();

        // Record zone-a genesis + checkpoint + fork.
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis_a,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-a0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-a1",
            })
            .unwrap();
        let _ = detector.record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_a_fork,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 250,
            trace_id: "t-a1-fork",
        });

        // Record zone-b genesis.
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-b",
                checkpoint: &genesis_b,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-b0",
            })
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
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );

        let mut detector = ForkDetector::with_defaults();

        // Accept genesis and cp1_a into frontier.
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_b,
                accepted: false,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 300,
                trace_id: "t-gossip",
            })
            .unwrap_err();

        assert!(report.existing_was_accepted);
        assert!(detector.is_safe_mode("zone-a"));
    }

    // -- History window --

    #[test]
    fn history_bounded_by_max() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        // Use a small history window.
        let mut detector = ForkDetector::new(5);

        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();

        let mut prev = genesis;
        for i in 1..=10u64 {
            let cp = build_after(
                &prev,
                i,
                SecurityEpoch::GENESIS,
                100 + i * 100,
                std::slice::from_ref(&sk),
                "zone-a",
            );
            let trace = format!("t-{i}");
            detector
                .record_checkpoint(&RecordCheckpointInput {
                    zone: "zone-a",
                    checkpoint: &cp,
                    accepted: true,
                    frontier_seq: i,
                    frontier_epoch: SecurityEpoch::GENESIS,
                    tick: 100 + i * 100,
                    trace_id: &trace,
                })
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
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();
        let _ = detector.record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_b,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 250,
            trace_id: "t-fork",
        });

        assert_eq!(detector.incidents("zone-a").len(), 1);
        assert_eq!(detector.unacknowledged_incidents("zone-a").len(), 1);
    }

    // -- Event counts --

    #[test]
    fn event_counts_accurate() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();
        let _ = detector.record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_b,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 250,
            trace_id: "t-fork",
        });

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
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();

        let exported = detector.export_state().clone();

        let mut detector2 = ForkDetector::with_defaults();
        detector2.import_state(exported);

        assert_eq!(detector2.history_size("zone-a"), 1);
    }

    #[test]
    fn safe_mode_persists_across_import() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let cp1_a = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_a,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();
        let _ = detector.record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_b,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 250,
            trace_id: "t-fork",
        });

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
        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let genesis_b = build_genesis(&[sk], "zone-b");

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis_a,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-a",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-b",
                checkpoint: &genesis_b,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-b",
            })
            .unwrap();

        let zones = detector.zones();
        assert_eq!(zones.len(), 2);
        assert!(zones.contains(&"zone-a"));
        assert!(zones.contains(&"zone-b"));
    }

    #[test]
    fn startup_cli_flag_forces_safe_mode() {
        let input = SafeModeStartupInput {
            trace_id: "trace-safe-startup-cli".to_string(),
            decision_id: "decision-safe-startup-cli".to_string(),
            policy_id: "policy-safe-startup-v1".to_string(),
            cli_safe_mode: true,
            environment: BTreeMap::new(),
        };
        let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
        assert!(artifact.safe_mode_active);
        assert_eq!(artifact.source, SafeModeStartupSource::CliFlag);
        assert!(artifact.restrictions.all_extensions_sandboxed);
        assert!(artifact.restrictions.auto_promotion_disabled);
        assert!(artifact.restrictions.adaptive_tuning_disabled);
        assert_eq!(
            artifact.startup_sequence,
            vec![
                "initialize_runtime_context",
                "force_all_extensions_sandboxed",
                "disable_auto_promotion",
                "apply_conservative_policy_defaults",
                "enable_enhanced_telemetry",
                "disable_adaptive_tuning",
                "persist_safe_mode_entry_evidence",
            ]
        );
    }

    #[test]
    fn startup_env_flag_forces_safe_mode() {
        let mut environment = BTreeMap::new();
        environment.insert("FRANKEN_SAFE_MODE".to_string(), "1".to_string());
        let input = SafeModeStartupInput {
            trace_id: "trace-safe-startup-env".to_string(),
            decision_id: "decision-safe-startup-env".to_string(),
            policy_id: "policy-safe-startup-v1".to_string(),
            cli_safe_mode: false,
            environment,
        };
        let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
        assert!(artifact.safe_mode_active);
        assert_eq!(artifact.source, SafeModeStartupSource::EnvironmentVariable);
    }

    #[test]
    fn startup_sequence_is_deterministic() {
        let input = SafeModeStartupInput {
            trace_id: "trace-safe-startup-deterministic".to_string(),
            decision_id: "decision-safe-startup-deterministic".to_string(),
            policy_id: "policy-safe-startup-v1".to_string(),
            cli_safe_mode: true,
            environment: BTreeMap::new(),
        };
        let a = evaluate_safe_mode_startup(&input).expect("artifact a");
        let b = evaluate_safe_mode_startup(&input).expect("artifact b");
        assert_eq!(a, b);
    }

    #[test]
    fn startup_events_have_required_stable_fields() {
        let mut environment = BTreeMap::new();
        environment.insert("FRANKENENGINE_SAFE_MODE".to_string(), "true".to_string());
        let input = SafeModeStartupInput {
            trace_id: "trace-safe-startup-events".to_string(),
            decision_id: "decision-safe-startup-events".to_string(),
            policy_id: "policy-safe-startup-v1".to_string(),
            cli_safe_mode: false,
            environment,
        };
        let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
        assert!(artifact.events.iter().all(|event| {
            event.trace_id == "trace-safe-startup-events"
                && event.decision_id == "decision-safe-startup-events"
                && event.policy_id == "policy-safe-startup-v1"
                && event.component == "safe_mode_startup"
                && !event.event.is_empty()
                && !event.outcome.is_empty()
        }));
    }

    #[test]
    fn safe_mode_exit_check_blocks_and_then_passes() {
        let blocked = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
            trace_id: "trace-safe-exit".to_string(),
            decision_id: "decision-safe-exit".to_string(),
            policy_id: "policy-safe-startup-v1".to_string(),
            active_incidents: 1,
            pending_quarantines: 2,
            evidence_ledger_flushed: false,
        })
        .expect("blocked exit check");
        assert!(!blocked.can_exit);
        assert_eq!(
            blocked.event.error_code.as_deref(),
            Some("FE-SAFE-MODE-EXIT-BLOCKED")
        );
        assert_eq!(
            blocked.blocking_reasons,
            vec![
                "active_incidents_remaining:1",
                "pending_quarantines_remaining:2",
                "evidence_ledger_not_flushed",
            ]
        );

        let pass = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
            trace_id: "trace-safe-exit".to_string(),
            decision_id: "decision-safe-exit".to_string(),
            policy_id: "policy-safe-startup-v1".to_string(),
            active_incidents: 0,
            pending_quarantines: 0,
            evidence_ledger_flushed: true,
        })
        .expect("pass exit check");
        assert!(pass.can_exit);
        assert!(pass.blocking_reasons.is_empty());
        assert_eq!(pass.event.outcome, "pass");
        assert_eq!(pass.event.error_code, None);
    }

    // -- ForkError Display for all variants --

    #[test]
    fn fork_error_display_all_variants() {
        let cases: Vec<(ForkError, &str)> = vec![
            (
                ForkError::SafeModeActive {
                    incident_seq: 3,
                    reason: "compromise".to_string(),
                },
                "compromise",
            ),
            (
                ForkError::AcknowledgmentRequired { incident_count: 2 },
                "2 fork incident",
            ),
            (
                ForkError::InvalidResolution {
                    fork_seq: 5,
                    resolution_seq: 3,
                },
                "does not advance",
            ),
            (
                ForkError::PersistenceFailed {
                    detail: "disk full".to_string(),
                },
                "disk full",
            ),
        ];
        for (err, substring) in cases {
            assert!(
                err.to_string().contains(substring),
                "'{}' should contain '{}'",
                err,
                substring
            );
        }
    }

    // -- ForkError::InvalidResolution serde --

    #[test]
    fn fork_error_invalid_resolution_serde() {
        let err = ForkError::InvalidResolution {
            fork_seq: 10,
            resolution_seq: 5,
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: ForkError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- ForkEventType Display for all variants --

    #[test]
    fn fork_event_type_display_all_variants() {
        let cases = vec![
            (
                ForkEventType::SafeModeEntered {
                    zone: "z".to_string(),
                    trigger_seq: 5,
                },
                "safe_mode_entered",
            ),
            (
                ForkEventType::SafeModeExited {
                    zone: "z".to_string(),
                    acknowledged_incidents: 2,
                },
                "safe_mode_exited",
            ),
            (
                ForkEventType::CheckpointRecorded {
                    zone: "z".to_string(),
                    checkpoint_seq: 7,
                },
                "checkpoint_recorded",
            ),
            (
                ForkEventType::OperationDenied {
                    zone: "z".to_string(),
                    operation: "grant".to_string(),
                },
                "operation_denied",
            ),
            (
                ForkEventType::HistoryTrimmed {
                    zone: "z".to_string(),
                    removed_count: 3,
                },
                "history_trimmed",
            ),
        ];
        for (et, substring) in cases {
            assert!(
                et.to_string().contains(substring),
                "'{}' should contain '{}'",
                et,
                substring
            );
        }
    }

    // -- SafeModeStartupSource Display --

    #[test]
    fn safe_mode_startup_source_display() {
        assert_eq!(
            SafeModeStartupSource::NotRequested.to_string(),
            "not-requested"
        );
        assert_eq!(SafeModeStartupSource::CliFlag.to_string(), "cli-flag");
        assert_eq!(
            SafeModeStartupSource::EnvironmentVariable.to_string(),
            "environment-variable"
        );
    }

    // -- SafeModeStartupError Display --

    #[test]
    fn safe_mode_startup_error_display() {
        let err = SafeModeStartupError::MissingField {
            field: "trace_id".to_string(),
        };
        assert!(err.to_string().contains("trace_id"));
    }

    // -- SafeModeState default --

    #[test]
    fn safe_mode_state_default() {
        let state = SafeModeState::default();
        assert!(!state.active);
        assert_eq!(state.trigger_seq, None);
        assert_eq!(state.unacknowledged_count, 0);
    }

    // -- SAFE_MODE_ENV_FLAGS --

    #[test]
    fn safe_mode_env_flags_constant() {
        assert_eq!(SAFE_MODE_ENV_FLAGS.len(), 2);
        assert_eq!(SAFE_MODE_ENV_FLAGS[0], "FRANKEN_SAFE_MODE");
        assert_eq!(SAFE_MODE_ENV_FLAGS[1], "FRANKENENGINE_SAFE_MODE");
    }

    // -- Normal startup (no flags) --

    #[test]
    fn startup_normal_mode_without_flags() {
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: false,
            environment: BTreeMap::new(),
        };
        let artifact = evaluate_safe_mode_startup(&input).unwrap();
        assert!(!artifact.safe_mode_active);
        assert_eq!(artifact.source, SafeModeStartupSource::NotRequested);
        assert!(!artifact.restrictions.all_extensions_sandboxed);
        assert!(!artifact.restrictions.auto_promotion_disabled);
        assert!(artifact.restricted_features.is_empty());
    }

    // -- Validation errors --

    #[test]
    fn startup_rejects_empty_trace_id() {
        let input = SafeModeStartupInput {
            trace_id: String::new(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: false,
            environment: BTreeMap::new(),
        };
        let err = evaluate_safe_mode_startup(&input).unwrap_err();
        assert!(matches!(
            err,
            SafeModeStartupError::MissingField { ref field } if field == "trace_id"
        ));
    }

    #[test]
    fn startup_rejects_empty_decision_id() {
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "  ".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: false,
            environment: BTreeMap::new(),
        };
        let err = evaluate_safe_mode_startup(&input).unwrap_err();
        assert!(matches!(
            err,
            SafeModeStartupError::MissingField { ref field } if field == "decision_id"
        ));
    }

    #[test]
    fn exit_check_rejects_empty_policy_id() {
        let input = SafeModeExitCheckInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: String::new(),
            active_incidents: 0,
            pending_quarantines: 0,
            evidence_ledger_flushed: true,
        };
        let err = evaluate_safe_mode_exit(&input).unwrap_err();
        assert!(matches!(
            err,
            SafeModeStartupError::MissingField { ref field } if field == "policy_id"
        ));
    }

    // -- Env value parsing edge cases --

    #[test]
    fn env_value_parsing_accepts_various_truthy_values() {
        for val in ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON", " 1 "] {
            let mut env = BTreeMap::new();
            env.insert("FRANKEN_SAFE_MODE".to_string(), val.to_string());
            let input = SafeModeStartupInput {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                cli_safe_mode: false,
                environment: env,
            };
            let artifact = evaluate_safe_mode_startup(&input).unwrap();
            assert!(
                artifact.safe_mode_active,
                "env value '{val}' should activate safe mode"
            );
        }
    }

    #[test]
    fn env_value_parsing_rejects_falsy_values() {
        for val in ["0", "false", "no", "off", ""] {
            let mut env = BTreeMap::new();
            env.insert("FRANKEN_SAFE_MODE".to_string(), val.to_string());
            let input = SafeModeStartupInput {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                cli_safe_mode: false,
                environment: env,
            };
            let artifact = evaluate_safe_mode_startup(&input).unwrap();
            assert!(
                !artifact.safe_mode_active,
                "env value '{val}' should NOT activate safe mode"
            );
        }
    }

    // -- is_safe_mode for unknown zone --

    #[test]
    fn is_safe_mode_returns_false_for_unknown_zone() {
        let detector = ForkDetector::with_defaults();
        assert!(!detector.is_safe_mode("nonexistent"));
    }

    // -- safe_mode_state for unknown zone --

    #[test]
    fn safe_mode_state_returns_none_for_unknown_zone() {
        let detector = ForkDetector::with_defaults();
        assert!(detector.safe_mode_state("nonexistent").is_none());
    }

    // -- enforce_safe_mode on non-safe zone --

    #[test]
    fn enforce_safe_mode_passes_on_normal_zone() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t",
            })
            .unwrap();

        detector
            .enforce_safe_mode("zone-a", "grant", "t-enforce")
            .expect("non-safe zone should pass");
    }

    // -- incidents for unknown zone --

    #[test]
    fn incidents_returns_empty_for_unknown_zone() {
        let detector = ForkDetector::with_defaults();
        assert!(detector.incidents("nonexistent").is_empty());
    }

    #[test]
    fn unacknowledged_incidents_returns_empty_for_unknown_zone() {
        let detector = ForkDetector::with_defaults();
        assert!(detector.unacknowledged_incidents("nonexistent").is_empty());
    }

    // -- acknowledge_incident for unknown zone --

    #[test]
    fn acknowledge_incident_returns_false_for_unknown_zone() {
        let mut detector = ForkDetector::with_defaults();
        assert!(!detector.acknowledge_incident("nonexistent", "fork-1"));
    }

    // -- history for unknown zone --

    #[test]
    fn history_returns_none_for_unknown_zone() {
        let detector = ForkDetector::with_defaults();
        assert!(detector.history("nonexistent").is_none());
    }

    #[test]
    fn history_size_returns_zero_for_unknown_zone() {
        let detector = ForkDetector::with_defaults();
        assert_eq!(detector.history_size("nonexistent"), 0);
    }

    // -- Serde roundtrips for remaining types --

    #[test]
    fn checkpoint_history_entry_serde_roundtrip() {
        let entry = CheckpointHistoryEntry {
            checkpoint_seq: 5,
            checkpoint_id: EngineObjectId([0xAA; 32]),
            epoch: SecurityEpoch::GENESIS,
            accepted: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: CheckpointHistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }

    #[test]
    fn safe_mode_startup_source_serde_roundtrip() {
        for source in [
            SafeModeStartupSource::NotRequested,
            SafeModeStartupSource::CliFlag,
            SafeModeStartupSource::EnvironmentVariable,
        ] {
            let json = serde_json::to_string(&source).unwrap();
            let restored: SafeModeStartupSource = serde_json::from_str(&json).unwrap();
            assert_eq!(source, restored);
        }
    }

    #[test]
    fn safe_mode_restrictions_serde_roundtrip() {
        let restrictions = SafeModeRestrictions::conservative();
        let json = serde_json::to_string(&restrictions).unwrap();
        let restored: SafeModeRestrictions = serde_json::from_str(&json).unwrap();
        assert_eq!(restrictions, restored);
    }

    #[test]
    fn safe_mode_startup_error_serde_roundtrip() {
        let err = SafeModeStartupError::MissingField {
            field: "trace_id".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: SafeModeStartupError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- exit_safe_mode on missing zone --

    #[test]
    fn exit_safe_mode_on_unknown_zone_returns_zero() {
        let mut detector = ForkDetector::with_defaults();
        let count = detector
            .exit_safe_mode("nonexistent", "t")
            .expect("unknown zone should return 0");
        assert_eq!(count, 0);
    }

    // -- exit_safe_mode on non-safe zone --

    // -- Enrichment: std::error --

    #[test]
    fn fork_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ForkError::ForkDetected {
                checkpoint_seq: 1,
                existing_id: EngineObjectId([0xAA; 32]),
                divergent_id: EngineObjectId([0xBB; 32]),
            }),
            Box::new(ForkError::SafeModeActive {
                incident_seq: 2,
                reason: "fork".into(),
            }),
            Box::new(ForkError::AcknowledgmentRequired { incident_count: 3 }),
            Box::new(ForkError::InvalidResolution {
                fork_seq: 4,
                resolution_seq: 1,
            }),
            Box::new(ForkError::PersistenceFailed {
                detail: "io".into(),
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
            5,
            "all 5 variants produce distinct messages"
        );
    }

    #[test]
    fn exit_safe_mode_on_non_safe_zone_returns_zero() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t",
            })
            .unwrap();

        let count = detector.exit_safe_mode("zone-a", "t").unwrap();
        assert_eq!(count, 0);
    }

    // -- Enrichment: ForkError serde roundtrip --

    #[test]
    fn fork_error_serde_roundtrip_all_variants() {
        let variants = vec![
            ForkError::ForkDetected {
                checkpoint_seq: 10,
                existing_id: EngineObjectId([0xAA; 32]),
                divergent_id: EngineObjectId([0xBB; 32]),
            },
            ForkError::SafeModeActive {
                incident_seq: 5,
                reason: "split-brain".to_string(),
            },
            ForkError::AcknowledgmentRequired { incident_count: 3 },
            ForkError::InvalidResolution {
                fork_seq: 7,
                resolution_seq: 2,
            },
            ForkError::PersistenceFailed {
                detail: "disk full".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ForkError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- Enrichment: ForkError Display contains key info --

    #[test]
    fn fork_error_display_fork_detected_contains_seq() {
        let err = ForkError::ForkDetected {
            checkpoint_seq: 42,
            existing_id: EngineObjectId([0x11; 32]),
            divergent_id: EngineObjectId([0x22; 32]),
        };
        let msg = err.to_string();
        assert!(msg.contains("42"), "should contain seq: {msg}");
        assert!(msg.contains("fork"), "should mention fork: {msg}");
    }

    #[test]
    fn fork_error_display_safe_mode_contains_reason() {
        let err = ForkError::SafeModeActive {
            incident_seq: 5,
            reason: "compromised signer".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("compromised signer"),
            "should contain reason: {msg}"
        );
        assert!(msg.contains("5"), "should contain seq: {msg}");
    }

    #[test]
    fn fork_error_display_acknowledgment_required_contains_count() {
        let err = ForkError::AcknowledgmentRequired { incident_count: 7 };
        let msg = err.to_string();
        assert!(msg.contains("7"), "should contain count: {msg}");
    }

    #[test]
    fn fork_error_display_invalid_resolution_contains_seqs() {
        let err = ForkError::InvalidResolution {
            fork_seq: 10,
            resolution_seq: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("10"), "should contain fork_seq: {msg}");
        assert!(msg.contains("3"), "should contain resolution_seq: {msg}");
    }

    #[test]
    fn fork_error_display_persistence_failed_contains_detail() {
        let err = ForkError::PersistenceFailed {
            detail: "io error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("io error"), "should contain detail: {msg}");
    }

    // -- Enrichment: ForkEventType Display distinctness --

    #[test]
    fn fork_event_type_display_all_distinct() {
        let variants = vec![
            ForkEventType::ForkDetected {
                zone: "z1".to_string(),
                checkpoint_seq: 1,
            },
            ForkEventType::SafeModeEntered {
                zone: "z2".to_string(),
                trigger_seq: 2,
            },
            ForkEventType::SafeModeExited {
                zone: "z3".to_string(),
                acknowledged_incidents: 3,
            },
            ForkEventType::CheckpointRecorded {
                zone: "z4".to_string(),
                checkpoint_seq: 4,
            },
            ForkEventType::OperationDenied {
                zone: "z5".to_string(),
                operation: "write".to_string(),
            },
            ForkEventType::HistoryTrimmed {
                zone: "z6".to_string(),
                removed_count: 5,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = v.to_string();
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 variants produce distinct messages"
        );
    }

    // -- Enrichment: ForkEventType serde roundtrip --

    #[test]
    fn fork_event_type_serde_roundtrip() {
        let evt = ForkEventType::ForkDetected {
            zone: "zone-a".to_string(),
            checkpoint_seq: 42,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: ForkEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    // -- Enrichment: ForkEvent serde roundtrip --

    #[test]
    fn fork_event_serde_roundtrip_enrichment() {
        let evt = ForkEvent {
            event_type: ForkEventType::SafeModeEntered {
                zone: "zone-b".to_string(),
                trigger_seq: 10,
            },
            trace_id: "t-42".to_string(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: ForkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    // -- Enrichment: ForkIncidentReport serde roundtrip --

    #[test]
    fn fork_incident_report_serde_roundtrip() {
        let report = ForkIncidentReport {
            incident_id: "inc-1".to_string(),
            fork_seq: 5,
            existing_checkpoint_id: EngineObjectId([0xAA; 32]),
            divergent_checkpoint_id: EngineObjectId([0xBB; 32]),
            existing_epoch: SecurityEpoch::GENESIS,
            divergent_epoch: SecurityEpoch::from_raw(2),
            zone: "zone-a".to_string(),
            frontier_seq_at_detection: 4,
            frontier_epoch_at_detection: SecurityEpoch::GENESIS,
            detected_at_tick: 1000,
            trace_id: "t-report".to_string(),
            existing_was_accepted: true,
            acknowledged: false,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: ForkIncidentReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -- Enrichment: SafeModeState default --

    #[test]
    fn safe_mode_state_default_is_inactive() {
        let state = SafeModeState::default();
        assert!(!state.active);
        assert!(state.trigger_seq.is_none());
        assert_eq!(state.unacknowledged_count, 0);
    }

    // -- Enrichment: SafeModeState serde roundtrip --

    #[test]
    fn safe_mode_state_serde_roundtrip() {
        let state = SafeModeState {
            active: true,
            trigger_seq: Some(42),
            unacknowledged_count: 3,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: SafeModeState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    // -- Enrichment: SafeModeStartupSource Display --

    #[test]
    fn safe_mode_startup_source_display_all_variants() {
        assert_eq!(
            SafeModeStartupSource::NotRequested.to_string(),
            "not-requested"
        );
        assert_eq!(SafeModeStartupSource::CliFlag.to_string(), "cli-flag");
        assert_eq!(
            SafeModeStartupSource::EnvironmentVariable.to_string(),
            "environment-variable"
        );
    }

    // -- Enrichment: SafeModeRestrictions conservative vs normal --

    #[test]
    fn safe_mode_restrictions_conservative_all_true() {
        let r = SafeModeRestrictions::conservative();
        assert!(r.all_extensions_sandboxed);
        assert!(r.auto_promotion_disabled);
        assert!(r.conservative_policy_defaults);
        assert!(r.enhanced_telemetry);
        assert!(r.adaptive_tuning_disabled);
    }

    #[test]
    fn safe_mode_restrictions_normal_all_false() {
        let r = SafeModeRestrictions::normal();
        assert!(!r.all_extensions_sandboxed);
        assert!(!r.auto_promotion_disabled);
        assert!(!r.conservative_policy_defaults);
        assert!(!r.enhanced_telemetry);
        assert!(!r.adaptive_tuning_disabled);
    }

    // -- Enrichment: evaluate_safe_mode_startup --

    #[test]
    fn evaluate_startup_normal_mode() {
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: false,
            environment: BTreeMap::new(),
        };
        let artifact = evaluate_safe_mode_startup(&input).unwrap();
        assert!(!artifact.safe_mode_active);
        assert_eq!(artifact.source, SafeModeStartupSource::NotRequested);
        assert!(artifact.restricted_features.is_empty());
    }

    #[test]
    fn evaluate_startup_cli_safe_mode() {
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: true,
            environment: BTreeMap::new(),
        };
        let artifact = evaluate_safe_mode_startup(&input).unwrap();
        assert!(artifact.safe_mode_active);
        assert_eq!(artifact.source, SafeModeStartupSource::CliFlag);
        assert!(!artifact.restricted_features.is_empty());
    }

    #[test]
    fn evaluate_startup_env_safe_mode() {
        let mut env = BTreeMap::new();
        env.insert("FRANKEN_SAFE_MODE".to_string(), "true".to_string());
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: false,
            environment: env,
        };
        let artifact = evaluate_safe_mode_startup(&input).unwrap();
        assert!(artifact.safe_mode_active);
        assert_eq!(artifact.source, SafeModeStartupSource::EnvironmentVariable);
    }

    #[test]
    fn evaluate_startup_missing_trace_id_fails() {
        let input = SafeModeStartupInput {
            trace_id: "".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: false,
            environment: BTreeMap::new(),
        };
        let err = evaluate_safe_mode_startup(&input).unwrap_err();
        assert!(err.to_string().contains("trace_id"));
    }

    // -- Enrichment: evaluate_safe_mode_exit --

    #[test]
    fn evaluate_exit_can_exit_when_clean() {
        let input = SafeModeExitCheckInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            active_incidents: 0,
            pending_quarantines: 0,
            evidence_ledger_flushed: true,
        };
        let artifact = evaluate_safe_mode_exit(&input).unwrap();
        assert!(artifact.can_exit);
        assert!(artifact.blocking_reasons.is_empty());
    }

    #[test]
    fn evaluate_exit_blocked_by_incidents() {
        let input = SafeModeExitCheckInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            active_incidents: 2,
            pending_quarantines: 0,
            evidence_ledger_flushed: true,
        };
        let artifact = evaluate_safe_mode_exit(&input).unwrap();
        assert!(!artifact.can_exit);
        assert!(
            artifact
                .blocking_reasons
                .iter()
                .any(|r| r.contains("active_incidents"))
        );
    }

    #[test]
    fn evaluate_exit_blocked_by_unflushed_ledger() {
        let input = SafeModeExitCheckInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            active_incidents: 0,
            pending_quarantines: 0,
            evidence_ledger_flushed: false,
        };
        let artifact = evaluate_safe_mode_exit(&input).unwrap();
        assert!(!artifact.can_exit);
        assert!(
            artifact
                .blocking_reasons
                .iter()
                .any(|r| r.contains("ledger"))
        );
    }

    // -- Enrichment: SafeModeStartupError Display --

    #[test]
    fn safe_mode_startup_error_display_contains_field() {
        let err = SafeModeStartupError::MissingField {
            field: "decision_id".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("decision_id"), "should name the field: {msg}");
    }

    // -- Enrichment: SafeModeStartupError implements std::error --

    #[test]
    fn safe_mode_startup_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(SafeModeStartupError::MissingField {
            field: "x".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment: SAFE_MODE_ENV_FLAGS --

    #[test]
    fn safe_mode_env_flags_contains_expected_keys() {
        assert!(SAFE_MODE_ENV_FLAGS.contains(&"FRANKEN_SAFE_MODE"));
        assert!(SAFE_MODE_ENV_FLAGS.contains(&"FRANKENENGINE_SAFE_MODE"));
        assert_eq!(SAFE_MODE_ENV_FLAGS.len(), 2);
    }

    // -- Enrichment: ForkDetector with_defaults fresh state --

    #[test]
    fn fresh_detector_is_not_safe_mode() {
        let detector = ForkDetector::with_defaults();
        assert!(!detector.is_safe_mode("any-zone"));
    }

    #[test]
    fn fresh_detector_has_no_events() {
        let mut detector = ForkDetector::with_defaults();
        assert!(detector.drain_events().is_empty());
    }

    // -- Enrichment: env parsing edge cases --

    #[test]
    fn env_safe_mode_various_true_values() {
        for val in ["1", "true", "yes", "on", "  TRUE  ", " Yes ", " ON "] {
            let mut env = BTreeMap::new();
            env.insert("FRANKENENGINE_SAFE_MODE".to_string(), val.to_string());
            let input = SafeModeStartupInput {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                cli_safe_mode: false,
                environment: env,
            };
            let artifact = evaluate_safe_mode_startup(&input).unwrap();
            assert!(
                artifact.safe_mode_active,
                "'{val}' should activate safe mode"
            );
        }
    }

    #[test]
    fn env_safe_mode_false_values_do_not_activate() {
        for val in ["0", "false", "no", "off", "maybe", ""] {
            let mut env = BTreeMap::new();
            env.insert("FRANKEN_SAFE_MODE".to_string(), val.to_string());
            let input = SafeModeStartupInput {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                cli_safe_mode: false,
                environment: env,
            };
            let artifact = evaluate_safe_mode_startup(&input).unwrap();
            assert!(
                !artifact.safe_mode_active,
                "'{val}' should NOT activate safe mode"
            );
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn duplicate_checkpoint_same_seq_same_id_is_not_fork() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();

        // Re-record the same checkpoint — should succeed (duplicate, not fork).
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 250,
                trace_id: "t-1-dup",
            })
            .unwrap();

        assert!(!detector.is_safe_mode("zone-a"));
    }

    #[test]
    fn multiple_fork_incidents_in_same_zone() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let cp2 = build_after(
            &cp1,
            2,
            SecurityEpoch::GENESIS,
            300,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let cp1_fork = build_divergent_at_seq(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            std::slice::from_ref(&sk),
            "zone-a",
            100,
        );
        let cp2_fork = build_divergent_at_seq(
            &cp1,
            2,
            SecurityEpoch::GENESIS,
            350,
            std::slice::from_ref(&sk),
            "zone-a",
            200,
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp2,
                accepted: true,
                frontier_seq: 2,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 300,
                trace_id: "t-2",
            })
            .unwrap();

        // First fork at seq=1.
        let r1 = detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_fork,
                accepted: false,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 350,
                trace_id: "t-fork1",
            })
            .unwrap_err();
        assert_eq!(r1.fork_seq, 1);

        // Second fork at seq=2.
        let r2 = detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp2_fork,
                accepted: false,
                frontier_seq: 2,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 400,
                trace_id: "t-fork2",
            })
            .unwrap_err();
        assert_eq!(r2.fork_seq, 2);

        assert_eq!(detector.incidents("zone-a").len(), 2);
        assert_eq!(detector.unacknowledged_incidents("zone-a").len(), 2);
        let sm = detector.safe_mode_state("zone-a").unwrap();
        assert_eq!(sm.unacknowledged_count, 2);
    }

    #[test]
    fn acknowledge_already_acknowledged_incident_returns_false() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let cp1_fork = build_divergent_at_seq(
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();
        let report = detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_fork,
                accepted: false,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 250,
                trace_id: "t-fork",
            })
            .unwrap_err();

        // First acknowledgment succeeds.
        assert!(detector.acknowledge_incident("zone-a", &report.incident_id));
        // Second acknowledgment fails (already acknowledged).
        assert!(!detector.acknowledge_incident("zone-a", &report.incident_id));
    }

    #[test]
    fn drain_events_clears_event_buffer() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();

        let events = detector.drain_events();
        assert!(!events.is_empty());
        // After drain, should be empty.
        assert!(detector.drain_events().is_empty());
    }

    #[test]
    fn exit_safe_mode_emits_safe_mode_exited_event() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let cp1_fork = build_divergent_at_seq(
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
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();
        let report = detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1_fork,
                accepted: false,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 250,
                trace_id: "t-fork",
            })
            .unwrap_err();

        // Clear prior events, acknowledge, and exit.
        detector.drain_events();
        detector.acknowledge_incident("zone-a", &report.incident_id);
        detector.exit_safe_mode("zone-a", "t-exit").unwrap();

        let counts = detector.event_counts();
        assert_eq!(counts.get("safe_mode_exited"), Some(&1));
    }

    #[test]
    fn history_returns_populated_map_after_checkpoints() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );

        let mut detector = ForkDetector::with_defaults();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &cp1,
                accepted: true,
                frontier_seq: 1,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 200,
                trace_id: "t-1",
            })
            .unwrap();

        let hist = detector.history("zone-a").unwrap();
        assert_eq!(hist.len(), 2);
        assert!(hist.contains_key(&0));
        assert!(hist.contains_key(&1));
        assert!(hist[&0].accepted);
        assert!(hist[&1].accepted);
        assert_eq!(hist[&1].checkpoint_id, cp1.checkpoint_id);
    }

    #[test]
    fn startup_rejects_empty_policy_id() {
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: String::new(),
            cli_safe_mode: false,
            environment: BTreeMap::new(),
        };
        let err = evaluate_safe_mode_startup(&input).unwrap_err();
        assert!(matches!(
            err,
            SafeModeStartupError::MissingField { ref field } if field == "policy_id"
        ));
    }

    #[test]
    fn safe_mode_startup_artifact_serde_roundtrip() {
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: true,
            environment: BTreeMap::new(),
        };
        let artifact = evaluate_safe_mode_startup(&input).unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        let back: SafeModeStartupArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn safe_mode_exit_check_artifact_serde_roundtrip() {
        let input = SafeModeExitCheckInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            active_incidents: 1,
            pending_quarantines: 0,
            evidence_ledger_flushed: false,
        };
        let artifact = evaluate_safe_mode_exit(&input).unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        let back: SafeModeExitCheckArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn safe_mode_startup_event_serde_roundtrip() {
        let event = SafeModeStartupEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "safe_mode_startup".to_string(),
            event: "test_event".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("FE-TEST".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SafeModeStartupEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn safe_mode_startup_input_serde_roundtrip() {
        let mut env = BTreeMap::new();
        env.insert("FRANKEN_SAFE_MODE".to_string(), "1".to_string());
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: true,
            environment: env,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: SafeModeStartupInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn safe_mode_exit_check_input_serde_roundtrip() {
        let input = SafeModeExitCheckInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            active_incidents: 3,
            pending_quarantines: 1,
            evidence_ledger_flushed: false,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: SafeModeExitCheckInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn safe_mode_startup_artifact_normal_mode_has_expected_fields() {
        let input = SafeModeStartupInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cli_safe_mode: false,
            environment: BTreeMap::new(),
        };
        let artifact = evaluate_safe_mode_startup(&input).unwrap();
        assert!(artifact.evidence_preserved);
        assert!(artifact.logs_preserved);
        assert!(artifact.state_preserved);
        assert!(!artifact.exit_procedure.is_empty());
        assert_eq!(artifact.events.len(), 2);
        assert!(artifact.events[1].error_code.is_none());
    }

    #[test]
    fn history_trimming_emits_event() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut detector = ForkDetector::new(3);
        detector
            .record_checkpoint(&RecordCheckpointInput {
                zone: "zone-a",
                checkpoint: &genesis,
                accepted: true,
                frontier_seq: 0,
                frontier_epoch: SecurityEpoch::GENESIS,
                tick: 100,
                trace_id: "t-0",
            })
            .unwrap();

        let mut prev = genesis;
        for i in 1..=5u64 {
            let cp = build_after(
                &prev,
                i,
                SecurityEpoch::GENESIS,
                100 + i * 100,
                std::slice::from_ref(&sk),
                "zone-a",
            );
            detector
                .record_checkpoint(&RecordCheckpointInput {
                    zone: "zone-a",
                    checkpoint: &cp,
                    accepted: true,
                    frontier_seq: i,
                    frontier_epoch: SecurityEpoch::GENESIS,
                    tick: 100 + i * 100,
                    trace_id: &format!("t-{i}"),
                })
                .unwrap();
            prev = cp;
        }

        let counts = detector.event_counts();
        assert!(
            counts.get("history_trimmed").unwrap_or(&0) > &0,
            "should have trimmed history events"
        );
        assert!(detector.history_size("zone-a") <= 3);
    }

    #[test]
    fn exit_blocked_by_quarantines() {
        let input = SafeModeExitCheckInput {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            active_incidents: 0,
            pending_quarantines: 5,
            evidence_ledger_flushed: true,
        };
        let artifact = evaluate_safe_mode_exit(&input).unwrap();
        assert!(!artifact.can_exit);
        assert!(
            artifact
                .blocking_reasons
                .iter()
                .any(|r| r.contains("quarantine"))
        );
    }

    // ── Enrichment: serde roundtrip tests ────────────────────────────

    #[test]
    fn safe_mode_state_serde_roundtrip_default() {
        let state = SafeModeState::default();
        let json = serde_json::to_string(&state).unwrap();
        let back: SafeModeState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
        assert!(!back.active);
        assert!(back.trigger_seq.is_none());
    }

    #[test]
    fn safe_mode_state_serde_roundtrip_active() {
        let state = SafeModeState {
            active: true,
            trigger_seq: Some(42),
            unacknowledged_count: 3,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: SafeModeState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn fork_event_type_serde_roundtrip_all_variants() {
        let variants = [
            ForkEventType::ForkDetected {
                zone: "z1".to_string(),
                checkpoint_seq: 10,
            },
            ForkEventType::SafeModeEntered {
                zone: "z2".to_string(),
                trigger_seq: 5,
            },
            ForkEventType::SafeModeExited {
                zone: "z3".to_string(),
                acknowledged_incidents: 2,
            },
            ForkEventType::CheckpointRecorded {
                zone: "z4".to_string(),
                checkpoint_seq: 20,
            },
            ForkEventType::OperationDenied {
                zone: "z5".to_string(),
                operation: "write".to_string(),
            },
            ForkEventType::HistoryTrimmed {
                zone: "z6".to_string(),
                removed_count: 100,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ForkEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn fork_event_serde_roundtrip() {
        let event = ForkEvent {
            event_type: ForkEventType::ForkDetected {
                zone: "main".to_string(),
                checkpoint_seq: 7,
            },
            trace_id: "trace-abc".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ForkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }
}
