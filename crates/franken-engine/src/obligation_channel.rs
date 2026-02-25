//! Obligation-tracked channels for safety-critical two-phase protocols.
//!
//! Every message sent on an `ObligationChannel` creates a linear obligation
//! that must be explicitly resolved (committed or aborted). Unresolved
//! obligations are detected and escalatable.
//!
//! Plan references: Section 10.11 item 6, 9G.3 (linear-obligation discipline),
//! Top-10 #3 (deterministic evidence graph), #10 (provenance + revocation).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ObligationState — lifecycle of an obligation
// ---------------------------------------------------------------------------

/// State of a tracked obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationState {
    Pending,
    Committed,
    Aborted,
    Leaked,
}

impl fmt::Display for ObligationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Committed => write!(f, "committed"),
            Self::Aborted => write!(f, "aborted"),
            Self::Leaked => write!(f, "leaked"),
        }
    }
}

// ---------------------------------------------------------------------------
// AbortReason — why an obligation was aborted
// ---------------------------------------------------------------------------

/// Reason for aborting an obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    /// Timeout during drain phase.
    DrainTimeout,
    /// Upstream failure.
    UpstreamFailure,
    /// Policy violation.
    PolicyViolation,
    /// Explicit operator abort.
    OperatorAbort,
    /// Custom reason.
    Custom(String),
}

impl fmt::Display for AbortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DrainTimeout => write!(f, "drain_timeout"),
            Self::UpstreamFailure => write!(f, "upstream_failure"),
            Self::PolicyViolation => write!(f, "policy_violation"),
            Self::OperatorAbort => write!(f, "operator_abort"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationError — errors in obligation operations
// ---------------------------------------------------------------------------

/// Error from obligation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationError {
    /// Obligation not found.
    NotFound { obligation_id: u64 },
    /// Obligation already resolved.
    AlreadyResolved { obligation_id: u64 },
    /// Channel at backpressure limit.
    Backpressure { max_pending: usize },
    /// Obligation leaked (detected on drop without resolution).
    Leaked { obligation_id: u64 },
}

impl fmt::Display for ObligationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { obligation_id } => {
                write!(f, "obligation {obligation_id} not found")
            }
            Self::AlreadyResolved { obligation_id } => {
                write!(f, "obligation {obligation_id} already resolved")
            }
            Self::Backpressure { max_pending } => {
                write!(f, "backpressure: max {max_pending} pending obligations")
            }
            Self::Leaked { obligation_id } => {
                write!(f, "obligation {obligation_id} leaked")
            }
        }
    }
}

impl std::error::Error for ObligationError {}

// ---------------------------------------------------------------------------
// ObligationRecord — registry entry
// ---------------------------------------------------------------------------

/// Registry entry for a tracked obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationRecord {
    pub obligation_id: u64,
    pub created_at_tick: u64,
    pub creator_trace_id: String,
    pub state: ObligationState,
    pub resolution_evidence_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// ObligationEvent — structured evidence
// ---------------------------------------------------------------------------

/// Structured event for obligation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationEvent {
    pub trace_id: String,
    pub channel_id: String,
    pub obligation_id: u64,
    pub state: ObligationState,
    pub resolution_type: Option<String>,
    pub evidence_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// ChannelConfig — configuration
// ---------------------------------------------------------------------------

/// Configuration for an obligation channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Maximum pending obligations before backpressure.
    pub max_pending: usize,
    /// If true, leaks are fatal (lab mode).
    pub lab_mode: bool,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            max_pending: 256,
            lab_mode: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationChannel — the channel itself
// ---------------------------------------------------------------------------

/// An obligation-tracked channel for two-phase protocols.
///
/// Every `send` creates a pending obligation that must be resolved
/// via `commit` or `abort`. Unresolved obligations are detectable.
#[derive(Debug)]
pub struct ObligationChannel {
    pub channel_id: String,
    config: ChannelConfig,
    trace_id: String,
    registry: BTreeMap<u64, ObligationRecord>,
    next_obligation_id: u64,
    current_tick: u64,
    events: Vec<ObligationEvent>,
    leak_count: usize,
}

impl ObligationChannel {
    /// Create a new obligation channel.
    pub fn new(
        channel_id: impl Into<String>,
        trace_id: impl Into<String>,
        config: ChannelConfig,
    ) -> Self {
        Self {
            channel_id: channel_id.into(),
            config,
            trace_id: trace_id.into(),
            registry: BTreeMap::new(),
            next_obligation_id: 1,
            current_tick: 0,
            events: Vec::new(),
            leak_count: 0,
        }
    }

    /// Set current virtual tick (for deterministic timestamps).
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Send a message, creating a pending obligation. Returns obligation_id.
    pub fn send(&mut self, creator_trace_id: &str) -> Result<u64, ObligationError> {
        if self.pending_count() >= self.config.max_pending {
            return Err(ObligationError::Backpressure {
                max_pending: self.config.max_pending,
            });
        }

        let id = self.next_obligation_id;
        self.next_obligation_id += 1;

        self.registry.insert(
            id,
            ObligationRecord {
                obligation_id: id,
                created_at_tick: self.current_tick,
                creator_trace_id: creator_trace_id.to_string(),
                state: ObligationState::Pending,
                resolution_evidence_hash: None,
            },
        );

        self.emit_event(id, ObligationState::Pending, None, None);
        Ok(id)
    }

    /// Commit an obligation (mark as successfully resolved).
    pub fn commit(
        &mut self,
        obligation_id: u64,
        evidence_hash: &str,
    ) -> Result<(), ObligationError> {
        let record = self
            .registry
            .get_mut(&obligation_id)
            .ok_or(ObligationError::NotFound { obligation_id })?;

        if record.state != ObligationState::Pending {
            return Err(ObligationError::AlreadyResolved { obligation_id });
        }

        record.state = ObligationState::Committed;
        record.resolution_evidence_hash = Some(evidence_hash.to_string());

        self.emit_event(
            obligation_id,
            ObligationState::Committed,
            Some("commit"),
            Some(evidence_hash),
        );
        Ok(())
    }

    /// Abort an obligation (mark as rolled back).
    pub fn abort(
        &mut self,
        obligation_id: u64,
        _reason: &AbortReason,
        evidence_hash: &str,
    ) -> Result<(), ObligationError> {
        let record = self
            .registry
            .get_mut(&obligation_id)
            .ok_or(ObligationError::NotFound { obligation_id })?;

        if record.state != ObligationState::Pending {
            return Err(ObligationError::AlreadyResolved { obligation_id });
        }

        record.state = ObligationState::Aborted;
        record.resolution_evidence_hash = Some(evidence_hash.to_string());

        self.emit_event(
            obligation_id,
            ObligationState::Aborted,
            Some("abort"),
            Some(evidence_hash),
        );
        Ok(())
    }

    /// Mark an obligation as leaked (detected on drop without resolution).
    pub fn mark_leaked(&mut self, obligation_id: u64) -> Result<(), ObligationError> {
        let record = self
            .registry
            .get_mut(&obligation_id)
            .ok_or(ObligationError::NotFound { obligation_id })?;

        if record.state != ObligationState::Pending {
            return Err(ObligationError::AlreadyResolved { obligation_id });
        }

        record.state = ObligationState::Leaked;
        self.leak_count += 1;

        self.emit_event(obligation_id, ObligationState::Leaked, Some("leak"), None);
        Ok(())
    }

    /// Count of pending (unresolved) obligations.
    pub fn pending_count(&self) -> usize {
        self.registry
            .values()
            .filter(|r| r.state == ObligationState::Pending)
            .count()
    }

    /// Oldest pending obligation (by creation tick).
    pub fn oldest_pending(&self) -> Option<&ObligationRecord> {
        self.registry
            .values()
            .filter(|r| r.state == ObligationState::Pending)
            .min_by_key(|r| r.created_at_tick)
    }

    /// Total obligations (all states).
    pub fn total_count(&self) -> usize {
        self.registry.len()
    }

    /// Number of leaks detected.
    pub fn leak_count(&self) -> usize {
        self.leak_count
    }

    /// Whether this channel is in lab mode (leaks are fatal).
    pub fn is_lab_mode(&self) -> bool {
        self.config.lab_mode
    }

    /// Wait for drain: returns true if all obligations resolved, false if pending remain.
    pub fn drain_check(&self) -> bool {
        self.pending_count() == 0
    }

    /// Force-abort all pending obligations (for drain timeout escalation).
    pub fn force_abort_all_pending(&mut self, evidence_hash: &str) -> usize {
        let pending_ids: Vec<u64> = self
            .registry
            .iter()
            .filter(|(_, r)| r.state == ObligationState::Pending)
            .map(|(&id, _)| id)
            .collect();

        let count = pending_ids.len();
        for id in pending_ids {
            let _ = self.abort(id, &AbortReason::DrainTimeout, evidence_hash);
        }
        count
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<ObligationEvent> {
        std::mem::take(&mut self.events)
    }

    fn emit_event(
        &mut self,
        obligation_id: u64,
        state: ObligationState,
        resolution_type: Option<&str>,
        evidence_hash: Option<&str>,
    ) {
        self.events.push(ObligationEvent {
            trace_id: self.trace_id.clone(),
            channel_id: self.channel_id.clone(),
            obligation_id,
            state,
            resolution_type: resolution_type.map(String::from),
            evidence_hash: evidence_hash.map(String::from),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_channel() -> ObligationChannel {
        ObligationChannel::new(
            "chan-1",
            "trace-1",
            ChannelConfig {
                max_pending: 10,
                lab_mode: false,
            },
        )
    }

    // -- ObligationState --

    #[test]
    fn state_display() {
        assert_eq!(ObligationState::Pending.to_string(), "pending");
        assert_eq!(ObligationState::Committed.to_string(), "committed");
        assert_eq!(ObligationState::Aborted.to_string(), "aborted");
        assert_eq!(ObligationState::Leaked.to_string(), "leaked");
    }

    // -- AbortReason --

    #[test]
    fn abort_reason_display() {
        assert_eq!(AbortReason::DrainTimeout.to_string(), "drain_timeout");
        assert_eq!(AbortReason::UpstreamFailure.to_string(), "upstream_failure");
        assert_eq!(AbortReason::Custom("x".to_string()).to_string(), "custom:x");
    }

    // -- Send / Commit / Abort --

    #[test]
    fn send_creates_pending_obligation() {
        let mut chan = test_channel();
        let id = chan.send("trace-a").unwrap();
        assert_eq!(id, 1);
        assert_eq!(chan.pending_count(), 1);
    }

    #[test]
    fn commit_resolves_obligation() {
        let mut chan = test_channel();
        let id = chan.send("trace-a").unwrap();
        chan.commit(id, "hash-1").unwrap();
        assert_eq!(chan.pending_count(), 0);
    }

    #[test]
    fn abort_resolves_obligation() {
        let mut chan = test_channel();
        let id = chan.send("trace-a").unwrap();
        chan.abort(id, &AbortReason::UpstreamFailure, "hash-2")
            .unwrap();
        assert_eq!(chan.pending_count(), 0);
    }

    #[test]
    fn double_commit_fails() {
        let mut chan = test_channel();
        let id = chan.send("trace-a").unwrap();
        chan.commit(id, "h").unwrap();
        let err = chan.commit(id, "h").unwrap_err();
        assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
    }

    #[test]
    fn commit_after_abort_fails() {
        let mut chan = test_channel();
        let id = chan.send("trace-a").unwrap();
        chan.abort(id, &AbortReason::DrainTimeout, "h").unwrap();
        assert!(chan.commit(id, "h").is_err());
    }

    #[test]
    fn commit_nonexistent_fails() {
        let mut chan = test_channel();
        let err = chan.commit(999, "h").unwrap_err();
        assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
    }

    // -- Backpressure --

    #[test]
    fn backpressure_at_limit() {
        let mut chan = ObligationChannel::new(
            "chan",
            "t",
            ChannelConfig {
                max_pending: 3,
                lab_mode: false,
            },
        );
        chan.send("t").unwrap();
        chan.send("t").unwrap();
        chan.send("t").unwrap();

        let err = chan.send("t").unwrap_err();
        assert_eq!(err, ObligationError::Backpressure { max_pending: 3 });
    }

    #[test]
    fn backpressure_clears_after_resolution() {
        let mut chan = ObligationChannel::new(
            "chan",
            "t",
            ChannelConfig {
                max_pending: 2,
                lab_mode: false,
            },
        );
        let id1 = chan.send("t").unwrap();
        chan.send("t").unwrap();
        assert!(chan.send("t").is_err());

        chan.commit(id1, "h").unwrap();
        assert!(chan.send("t").is_ok());
    }

    // -- Leak detection --

    #[test]
    fn mark_leaked() {
        let mut chan = test_channel();
        let id = chan.send("t").unwrap();
        chan.mark_leaked(id).unwrap();
        assert_eq!(chan.leak_count(), 1);
        assert_eq!(chan.pending_count(), 0);
    }

    #[test]
    fn leak_already_resolved_fails() {
        let mut chan = test_channel();
        let id = chan.send("t").unwrap();
        chan.commit(id, "h").unwrap();
        assert!(chan.mark_leaked(id).is_err());
    }

    // -- Oldest pending --

    #[test]
    fn oldest_pending_returns_earliest() {
        let mut chan = test_channel();
        chan.set_tick(10);
        chan.send("t").unwrap();
        chan.set_tick(20);
        chan.send("t").unwrap();

        let oldest = chan.oldest_pending().unwrap();
        assert_eq!(oldest.created_at_tick, 10);
    }

    #[test]
    fn oldest_pending_none_when_empty() {
        let chan = test_channel();
        assert!(chan.oldest_pending().is_none());
    }

    // -- Drain --

    #[test]
    fn drain_check_true_when_no_pending() {
        let mut chan = test_channel();
        let id = chan.send("t").unwrap();
        chan.commit(id, "h").unwrap();
        assert!(chan.drain_check());
    }

    #[test]
    fn drain_check_false_when_pending() {
        let mut chan = test_channel();
        chan.send("t").unwrap();
        assert!(!chan.drain_check());
    }

    #[test]
    fn force_abort_all_pending() {
        let mut chan = test_channel();
        chan.send("t").unwrap();
        chan.send("t").unwrap();
        let id3 = chan.send("t").unwrap();
        chan.commit(id3, "h").unwrap();

        let aborted = chan.force_abort_all_pending("timeout-hash");
        assert_eq!(aborted, 2);
        assert!(chan.drain_check());
    }

    // -- Events --

    #[test]
    fn events_emitted_on_lifecycle() {
        let mut chan = test_channel();
        let id = chan.send("t").unwrap();
        chan.commit(id, "h").unwrap();

        let events = chan.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].state, ObligationState::Pending);
        assert_eq!(events[1].state, ObligationState::Committed);
    }

    #[test]
    fn event_carries_correct_fields() {
        let mut chan = test_channel();
        let id = chan.send("t").unwrap();
        chan.commit(id, "evidence-hash").unwrap();

        let events = chan.drain_events();
        let commit_event = &events[1];
        assert_eq!(commit_event.trace_id, "trace-1");
        assert_eq!(commit_event.channel_id, "chan-1");
        assert_eq!(commit_event.obligation_id, 1);
        assert_eq!(commit_event.resolution_type, Some("commit".to_string()));
        assert_eq!(
            commit_event.evidence_hash,
            Some("evidence-hash".to_string())
        );
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<ObligationEvent> {
            let mut chan = test_channel();
            chan.set_tick(10);
            let id1 = chan.send("t").unwrap();
            chan.set_tick(20);
            let id2 = chan.send("t").unwrap();
            chan.commit(id1, "h1").unwrap();
            chan.abort(id2, &AbortReason::DrainTimeout, "h2").unwrap();
            chan.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- ObligationError display --

    #[test]
    fn error_display() {
        assert!(
            ObligationError::NotFound { obligation_id: 1 }
                .to_string()
                .contains("not found")
        );
        assert!(
            ObligationError::AlreadyResolved { obligation_id: 1 }
                .to_string()
                .contains("already resolved")
        );
        assert!(
            ObligationError::Backpressure { max_pending: 10 }
                .to_string()
                .contains("backpressure")
        );
        assert!(
            ObligationError::Leaked { obligation_id: 1 }
                .to_string()
                .contains("leaked")
        );
    }

    // -- Lab mode --

    #[test]
    fn lab_mode_flag() {
        let chan = ObligationChannel::new(
            "chan",
            "t",
            ChannelConfig {
                max_pending: 10,
                lab_mode: true,
            },
        );
        assert!(chan.is_lab_mode());
    }

    // -- Serialization --

    #[test]
    fn obligation_record_serialization_round_trip() {
        let record = ObligationRecord {
            obligation_id: 1,
            created_at_tick: 100,
            creator_trace_id: "t".to_string(),
            state: ObligationState::Committed,
            resolution_evidence_hash: Some("h".to_string()),
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let restored: ObligationRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, restored);
    }

    #[test]
    fn obligation_event_serialization_round_trip() {
        let event = ObligationEvent {
            trace_id: "t".to_string(),
            channel_id: "c".to_string(),
            obligation_id: 1,
            state: ObligationState::Committed,
            resolution_type: Some("commit".to_string()),
            evidence_hash: Some("h".to_string()),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ObligationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn channel_config_serialization_round_trip() {
        let config = ChannelConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ChannelConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    // -- Multiple obligations --

    // -- Enrichment: serde, std::error --

    #[test]
    fn obligation_state_serde_all_variants() {
        for state in [
            ObligationState::Pending,
            ObligationState::Committed,
            ObligationState::Aborted,
            ObligationState::Leaked,
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            let restored: ObligationState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, restored);
        }
    }

    #[test]
    fn abort_reason_serde_all_variants() {
        let reasons = vec![
            AbortReason::DrainTimeout,
            AbortReason::UpstreamFailure,
            AbortReason::PolicyViolation,
            AbortReason::OperatorAbort,
            AbortReason::Custom("custom-reason".to_string()),
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).expect("serialize");
            let restored: AbortReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*reason, restored);
        }
    }

    #[test]
    fn obligation_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ObligationError::NotFound { obligation_id: 1 }),
            Box::new(ObligationError::AlreadyResolved { obligation_id: 2 }),
            Box::new(ObligationError::Backpressure { max_pending: 10 }),
            Box::new(ObligationError::Leaked { obligation_id: 3 }),
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
    fn multiple_obligations_independent() {
        let mut chan = test_channel();
        let id1 = chan.send("t").unwrap();
        let id2 = chan.send("t").unwrap();
        let id3 = chan.send("t").unwrap();

        chan.commit(id1, "h1").unwrap();
        chan.abort(id2, &AbortReason::OperatorAbort, "h2").unwrap();
        chan.mark_leaked(id3).unwrap();

        assert_eq!(chan.pending_count(), 0);
        assert_eq!(chan.total_count(), 3);
        assert_eq!(chan.leak_count(), 1);
    }
}
