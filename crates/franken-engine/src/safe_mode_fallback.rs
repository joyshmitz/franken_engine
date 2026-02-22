//! Fallback validation proving control-plane failure degrades to deterministic
//! safe mode rather than undefined behavior.
//!
//! When the control plane itself fails (adapter layer unavailable, decision
//! contract evaluation errors, evidence ledger full, Cx corrupted,
//! cancellation protocol deadlock), the extension-host subsystem must degrade
//! to a deterministic safe mode: observable, bounded, and recoverable.
//!
//! ## Failure Types and Safe Modes
//!
//! | Failure | Safe-Mode Response |
//! |---|---|
//! | Adapter unavailable | Refuse extensions; emit diagnostic |
//! | Decision contract error | Default-deny; quarantine requester |
//! | Evidence ledger full | Ring buffer fallback; block high-impact |
//! | Cx corrupted (budget underflow) | Reject current op; fresh Cx next op |
//! | Cancellation deadlock | Force-finalize after timeout |
//!
//! Plan reference: Section 10.13 item 18, bd-jaqy.
//! Dependencies: bd-23om (adapter layer), bd-3a5e (decision contracts),
//!               bd-uvmm (evidence emission).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::{
    ControlPlaneAdapterError, DecisionAdapter, DecisionRequest, DecisionVerdict,
};

// ---------------------------------------------------------------------------
// FailureType — classification of control-plane failures
// ---------------------------------------------------------------------------

/// Classification of control-plane failure that triggers safe-mode activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailureType {
    /// Adapter layer is unavailable (e.g., crate version mismatch at startup).
    AdapterUnavailable,
    /// Decision contract evaluation returned an error or unexpected result.
    DecisionContractError,
    /// Evidence ledger is full or unavailable for emission.
    EvidenceLedgerFull,
    /// Cx is corrupted (budget underflow, invalid trace_id, etc.).
    CxCorrupted,
    /// Cancellation protocol is stuck (drain timeout exceeded with no progress).
    CancellationDeadlock,
}

impl fmt::Display for FailureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdapterUnavailable => write!(f, "adapter_unavailable"),
            Self::DecisionContractError => write!(f, "decision_contract_error"),
            Self::EvidenceLedgerFull => write!(f, "evidence_ledger_full"),
            Self::CxCorrupted => write!(f, "cx_corrupted"),
            Self::CancellationDeadlock => write!(f, "cancellation_deadlock"),
        }
    }
}

// ---------------------------------------------------------------------------
// SafeModeAction — deterministic response to each failure type
// ---------------------------------------------------------------------------

/// Deterministic safe-mode response taken when a control-plane failure occurs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeModeAction {
    /// Refuse to load or activate any extensions until adapter is restored.
    RefuseExtensions { diagnostic: String },
    /// Default-deny the action and quarantine the requesting extension.
    DefaultDenyAndQuarantine {
        extension_id: String,
        reason: String,
    },
    /// Switch to bounded in-memory ring buffer for evidence; block high-impact
    /// actions until the ledger is restored.
    RingBufferFallback {
        capacity: usize,
        high_impact_blocked: bool,
    },
    /// Reject the current operation; issue a fresh Cx for the next operation.
    RejectAndRefreshCx {
        rejected_operation: String,
        corruption_detail: String,
    },
    /// Force-finalize the stuck cancellation after timeout.
    ForceFinalize { cell_id: String, timeout_ticks: u64 },
}

impl SafeModeAction {
    /// Returns the failure type this action corresponds to.
    pub fn failure_type(&self) -> FailureType {
        match self {
            Self::RefuseExtensions { .. } => FailureType::AdapterUnavailable,
            Self::DefaultDenyAndQuarantine { .. } => FailureType::DecisionContractError,
            Self::RingBufferFallback { .. } => FailureType::EvidenceLedgerFull,
            Self::RejectAndRefreshCx { .. } => FailureType::CxCorrupted,
            Self::ForceFinalize { .. } => FailureType::CancellationDeadlock,
        }
    }
}

// ---------------------------------------------------------------------------
// SafeModeEvent — structured event for safe-mode activation/recovery
// ---------------------------------------------------------------------------

/// Structured event emitted when safe mode activates or recovers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeEvent {
    /// Trace ID of the operation that triggered safe mode.
    pub trace_id: String,
    /// Type of failure that triggered safe mode.
    pub failure_type: FailureType,
    /// Phase: "activate" or "recover".
    pub phase: String,
    /// Action taken in safe mode (serialized for evidence).
    pub action_summary: String,
    /// Component that detected the failure.
    pub component: String,
    /// Outcome: "safe_mode_active", "recovery_complete", etc.
    pub outcome: String,
    /// Optional error code from the underlying failure.
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// RingBuffer — bounded in-memory evidence fallback
// ---------------------------------------------------------------------------

/// Bounded ring buffer for evidence entries when the primary ledger is full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRingBuffer {
    entries: Vec<RingBufferEntry>,
    capacity: usize,
    write_pos: usize,
    total_written: u64,
}

/// A single entry in the ring buffer fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingBufferEntry {
    pub trace_id: String,
    pub event: String,
    pub outcome: String,
    pub component: String,
    pub sequence: u64,
}

impl EvidenceRingBuffer {
    /// Create a ring buffer with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            write_pos: 0,
            total_written: 0,
        }
    }

    /// Push an entry into the ring buffer (overwrites oldest on overflow).
    pub fn push(&mut self, entry: RingBufferEntry) {
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
        } else {
            self.entries[self.write_pos] = entry;
        }
        self.write_pos = (self.write_pos + 1) % self.capacity;
        self.total_written += 1;
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total entries ever written (including overwritten).
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// View stored entries in insertion order (oldest first).
    pub fn entries(&self) -> Vec<&RingBufferEntry> {
        if self.entries.len() < self.capacity {
            self.entries.iter().collect()
        } else {
            let mut result = Vec::with_capacity(self.capacity);
            for i in 0..self.capacity {
                let idx = (self.write_pos + i) % self.capacity;
                result.push(&self.entries[idx]);
            }
            result
        }
    }

    /// Drain all entries for recovery into primary ledger.
    pub fn drain(&mut self) -> Vec<RingBufferEntry> {
        self.write_pos = 0;
        std::mem::take(&mut self.entries)
    }
}

// ---------------------------------------------------------------------------
// SafeModeState — tracks current safe-mode activations
// ---------------------------------------------------------------------------

/// Current safe-mode state per failure type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SafeModeStatus {
    /// Normal operation (no safe mode active for this failure type).
    #[default]
    Normal,
    /// Safe mode is active for this failure type.
    Active,
    /// Recovering from safe mode (failure resolved, draining fallback state).
    Recovering,
}

// ---------------------------------------------------------------------------
// SafeModeManager — orchestrates safe-mode activation and recovery
// ---------------------------------------------------------------------------

/// Manager for deterministic safe-mode degradation and recovery.
///
/// Tracks active safe modes per failure type, manages evidence ring buffer
/// fallback, and records structured events for all transitions.
#[derive(Debug, Clone)]
pub struct SafeModeManager {
    /// Current status per failure type.
    status: BTreeMap<FailureType, SafeModeStatus>,
    /// Evidence ring buffer fallback (used when primary ledger is full).
    ring_buffer: EvidenceRingBuffer,
    /// Ring buffer capacity.
    ring_buffer_capacity: usize,
    /// Whether high-impact actions are blocked (evidence ledger full).
    high_impact_blocked: bool,
    /// Extensions refused (adapter unavailable).
    extensions_refused: bool,
    /// Quarantined extensions (decision contract errors).
    quarantined_extensions: BTreeMap<String, String>,
    /// Accumulated safe-mode events.
    events: Vec<SafeModeEvent>,
    /// Count of activations per failure type.
    activation_counts: BTreeMap<FailureType, u64>,
    /// Count of recoveries per failure type.
    recovery_counts: BTreeMap<FailureType, u64>,
}

/// Default ring buffer capacity for evidence fallback.
const DEFAULT_RING_BUFFER_CAPACITY: usize = 256;

impl Default for SafeModeManager {
    fn default() -> Self {
        Self::new(DEFAULT_RING_BUFFER_CAPACITY)
    }
}

impl SafeModeManager {
    /// Create a new manager with the specified ring buffer capacity.
    pub fn new(ring_buffer_capacity: usize) -> Self {
        Self {
            status: BTreeMap::new(),
            ring_buffer: EvidenceRingBuffer::new(ring_buffer_capacity),
            ring_buffer_capacity,
            high_impact_blocked: false,
            extensions_refused: false,
            quarantined_extensions: BTreeMap::new(),
            events: Vec::new(),
            activation_counts: BTreeMap::new(),
            recovery_counts: BTreeMap::new(),
        }
    }

    /// Current status for a given failure type.
    pub fn status(&self, failure_type: FailureType) -> SafeModeStatus {
        self.status
            .get(&failure_type)
            .copied()
            .unwrap_or(SafeModeStatus::Normal)
    }

    /// Whether any safe mode is currently active.
    pub fn any_active(&self) -> bool {
        self.status.values().any(|s| *s == SafeModeStatus::Active)
    }

    /// Whether extensions are currently refused.
    pub fn extensions_refused(&self) -> bool {
        self.extensions_refused
    }

    /// Whether high-impact actions are blocked.
    pub fn high_impact_blocked(&self) -> bool {
        self.high_impact_blocked
    }

    /// View quarantined extensions.
    pub fn quarantined_extensions(&self) -> &BTreeMap<String, String> {
        &self.quarantined_extensions
    }

    /// View the evidence ring buffer.
    pub fn ring_buffer(&self) -> &EvidenceRingBuffer {
        &self.ring_buffer
    }

    /// View accumulated events.
    pub fn events(&self) -> &[SafeModeEvent] {
        &self.events
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<SafeModeEvent> {
        std::mem::take(&mut self.events)
    }

    /// Total activation count for a failure type.
    pub fn activation_count(&self, failure_type: FailureType) -> u64 {
        self.activation_counts
            .get(&failure_type)
            .copied()
            .unwrap_or(0)
    }

    /// Total recovery count for a failure type.
    pub fn recovery_count(&self, failure_type: FailureType) -> u64 {
        self.recovery_counts
            .get(&failure_type)
            .copied()
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Failure handlers — each failure type activates its corresponding safe mode
    // -----------------------------------------------------------------------

    /// Handle adapter unavailable: refuse extensions, emit diagnostic.
    pub fn handle_adapter_unavailable(
        &mut self,
        trace_id: &str,
        diagnostic: &str,
    ) -> SafeModeAction {
        self.activate(FailureType::AdapterUnavailable, trace_id, diagnostic, None);
        self.extensions_refused = true;
        SafeModeAction::RefuseExtensions {
            diagnostic: diagnostic.to_string(),
        }
    }

    /// Handle decision contract error: default-deny and quarantine extension.
    pub fn handle_decision_contract_error(
        &mut self,
        trace_id: &str,
        extension_id: &str,
        error_code: &str,
    ) -> SafeModeAction {
        let reason = format!("decision contract error: {error_code}");
        self.activate(
            FailureType::DecisionContractError,
            trace_id,
            &reason,
            Some(error_code),
        );
        self.quarantined_extensions
            .insert(extension_id.to_string(), reason.clone());
        SafeModeAction::DefaultDenyAndQuarantine {
            extension_id: extension_id.to_string(),
            reason,
        }
    }

    /// Handle evidence ledger full: switch to ring buffer, block high-impact.
    pub fn handle_evidence_ledger_full(
        &mut self,
        trace_id: &str,
        error_code: &str,
    ) -> SafeModeAction {
        self.activate(
            FailureType::EvidenceLedgerFull,
            trace_id,
            "evidence ledger full; switching to ring buffer",
            Some(error_code),
        );
        self.high_impact_blocked = true;
        SafeModeAction::RingBufferFallback {
            capacity: self.ring_buffer_capacity,
            high_impact_blocked: true,
        }
    }

    /// Handle Cx corruption: reject current operation, prepare fresh Cx.
    pub fn handle_cx_corrupted(
        &mut self,
        trace_id: &str,
        operation: &str,
        corruption_detail: &str,
    ) -> SafeModeAction {
        self.activate(
            FailureType::CxCorrupted,
            trace_id,
            corruption_detail,
            Some("cx_corrupted"),
        );
        SafeModeAction::RejectAndRefreshCx {
            rejected_operation: operation.to_string(),
            corruption_detail: corruption_detail.to_string(),
        }
    }

    /// Handle cancellation deadlock: force-finalize after timeout.
    pub fn handle_cancellation_deadlock(
        &mut self,
        trace_id: &str,
        cell_id: &str,
        timeout_ticks: u64,
    ) -> SafeModeAction {
        let detail = format!("cancellation stuck after {timeout_ticks} ticks on cell {cell_id}");
        self.activate(
            FailureType::CancellationDeadlock,
            trace_id,
            &detail,
            Some("cancellation_deadlock"),
        );
        SafeModeAction::ForceFinalize {
            cell_id: cell_id.to_string(),
            timeout_ticks,
        }
    }

    /// Write a fallback evidence entry into the ring buffer.
    pub fn write_ring_buffer_entry(
        &mut self,
        trace_id: &str,
        event: &str,
        outcome: &str,
        component: &str,
    ) {
        let seq = self.ring_buffer.total_written();
        self.ring_buffer.push(RingBufferEntry {
            trace_id: trace_id.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            component: component.to_string(),
            sequence: seq,
        });
    }

    /// Check whether an extension is quarantined (returns deny reason if so).
    pub fn check_quarantine(&self, extension_id: &str) -> Option<&String> {
        self.quarantined_extensions.get(extension_id)
    }

    /// Check whether an action should be blocked due to safe mode.
    ///
    /// Returns `Some(reason)` if the action should be blocked, `None` if allowed.
    pub fn check_action_blocked(&self, is_high_impact: bool) -> Option<String> {
        if self.extensions_refused {
            return Some("extensions refused: adapter unavailable".to_string());
        }
        if is_high_impact && self.high_impact_blocked {
            return Some("high-impact actions blocked: evidence ledger unavailable".to_string());
        }
        None
    }

    // -----------------------------------------------------------------------
    // Recovery — resolve failure and exit safe mode
    // -----------------------------------------------------------------------

    /// Recover from adapter unavailable: re-enable extension loading.
    pub fn recover_adapter(&mut self, trace_id: &str) {
        self.extensions_refused = false;
        self.recover(FailureType::AdapterUnavailable, trace_id);
    }

    /// Recover from decision contract error: un-quarantine an extension.
    pub fn recover_decision_contract(&mut self, trace_id: &str, extension_id: &str) {
        self.quarantined_extensions.remove(extension_id);
        if self.quarantined_extensions.is_empty() {
            self.recover(FailureType::DecisionContractError, trace_id);
        }
    }

    /// Recover from evidence ledger full: drain ring buffer, unblock actions.
    pub fn recover_evidence_ledger(&mut self, trace_id: &str) -> Vec<RingBufferEntry> {
        self.high_impact_blocked = false;
        let entries = self.ring_buffer.drain();
        self.recover(FailureType::EvidenceLedgerFull, trace_id);
        entries
    }

    /// Recover from Cx corruption.
    pub fn recover_cx(&mut self, trace_id: &str) {
        self.recover(FailureType::CxCorrupted, trace_id);
    }

    /// Recover from cancellation deadlock.
    pub fn recover_cancellation(&mut self, trace_id: &str) {
        self.recover(FailureType::CancellationDeadlock, trace_id);
    }

    // -----------------------------------------------------------------------
    // Validate — check a decision against safe-mode constraints
    // -----------------------------------------------------------------------

    /// Validate a decision request against safe-mode constraints.
    ///
    /// If safe mode is active, returns `DecisionVerdict::Deny` with evidence
    /// written to the ring buffer. Otherwise delegates to the decision adapter.
    pub fn validate_decision<D: DecisionAdapter>(
        &mut self,
        adapter: &mut D,
        request: &DecisionRequest,
        extension_id: &str,
    ) -> Result<DecisionVerdict, ControlPlaneAdapterError> {
        // Check quarantine first (clone reason to release borrow)
        if let Some(reason) = self.check_quarantine(extension_id).cloned() {
            self.write_ring_buffer_entry(
                &request.trace_id.to_string(),
                "decision_denied_quarantine",
                "deny",
                "safe_mode_fallback",
            );
            self.emit_event(
                &request.trace_id.to_string(),
                FailureType::DecisionContractError,
                "validate_decision",
                &format!("quarantined: {reason}"),
                None,
            );
            return Ok(DecisionVerdict::Deny);
        }

        // Check extensions refused
        if self.extensions_refused {
            self.write_ring_buffer_entry(
                &request.trace_id.to_string(),
                "decision_denied_adapter_unavailable",
                "deny",
                "safe_mode_fallback",
            );
            return Ok(DecisionVerdict::Deny);
        }

        // Delegate to real adapter
        match adapter.evaluate(request) {
            Ok(verdict) => Ok(verdict),
            Err(err) => {
                // Decision contract failed — activate safe mode, default-deny
                let error_code = err.error_code();
                self.handle_decision_contract_error(
                    &request.trace_id.to_string(),
                    extension_id,
                    error_code,
                );
                Ok(DecisionVerdict::Deny)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn activate(
        &mut self,
        failure_type: FailureType,
        trace_id: &str,
        detail: &str,
        error_code: Option<&str>,
    ) {
        self.status.insert(failure_type, SafeModeStatus::Active);
        *self.activation_counts.entry(failure_type).or_insert(0) += 1;
        self.emit_event(trace_id, failure_type, "activate", detail, error_code);
    }

    fn recover(&mut self, failure_type: FailureType, trace_id: &str) {
        self.status.insert(failure_type, SafeModeStatus::Normal);
        *self.recovery_counts.entry(failure_type).or_insert(0) += 1;
        self.emit_event(trace_id, failure_type, "recover", "recovery_complete", None);
    }

    fn emit_event(
        &mut self,
        trace_id: &str,
        failure_type: FailureType,
        phase: &str,
        detail: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(SafeModeEvent {
            trace_id: trace_id.to_string(),
            failure_type,
            phase: phase.to_string(),
            action_summary: detail.to_string(),
            component: "safe_mode_fallback".to_string(),
            outcome: if phase == "activate" {
                "safe_mode_active".to_string()
            } else {
                "recovery_complete".to_string()
            },
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{
        MockBudget, MockCx, MockDecisionContract, MockFailureMode, trace_id_from_seed,
    };
    use crate::control_plane::mocks::{decision_id_from_seed, policy_id_from_seed};
    use crate::control_plane::{DecisionRequest, DecisionVerdict};

    fn mock_cx(seed: u64) -> MockCx {
        MockCx::new(trace_id_from_seed(seed), MockBudget::new(100_000))
    }

    fn mock_request(seed: u64) -> DecisionRequest {
        DecisionRequest {
            decision_id: decision_id_from_seed(seed),
            policy_id: policy_id_from_seed(seed),
            trace_id: trace_id_from_seed(seed),
            ts_unix_ms: 1_700_000_000_000 + seed,
            calibration_score_bps: 8000,
            e_process_milli: 50,
            ci_width_milli: 100,
        }
    }

    // -- FailureType tests --

    #[test]
    fn failure_type_display() {
        assert_eq!(
            FailureType::AdapterUnavailable.to_string(),
            "adapter_unavailable"
        );
        assert_eq!(
            FailureType::DecisionContractError.to_string(),
            "decision_contract_error"
        );
        assert_eq!(
            FailureType::EvidenceLedgerFull.to_string(),
            "evidence_ledger_full"
        );
        assert_eq!(FailureType::CxCorrupted.to_string(), "cx_corrupted");
        assert_eq!(
            FailureType::CancellationDeadlock.to_string(),
            "cancellation_deadlock"
        );
    }

    #[test]
    fn failure_type_ordering() {
        assert!(FailureType::AdapterUnavailable < FailureType::DecisionContractError);
        assert!(FailureType::DecisionContractError < FailureType::EvidenceLedgerFull);
        assert!(FailureType::EvidenceLedgerFull < FailureType::CxCorrupted);
        assert!(FailureType::CxCorrupted < FailureType::CancellationDeadlock);
    }

    #[test]
    fn failure_type_serde_roundtrip() {
        for ft in [
            FailureType::AdapterUnavailable,
            FailureType::DecisionContractError,
            FailureType::EvidenceLedgerFull,
            FailureType::CxCorrupted,
            FailureType::CancellationDeadlock,
        ] {
            let json = serde_json::to_string(&ft).unwrap();
            let parsed: FailureType = serde_json::from_str(&json).unwrap();
            assert_eq!(ft, parsed);
        }
    }

    // -- SafeModeAction tests --

    #[test]
    fn safe_mode_action_failure_type_mapping() {
        let action = SafeModeAction::RefuseExtensions {
            diagnostic: "test".to_string(),
        };
        assert_eq!(action.failure_type(), FailureType::AdapterUnavailable);

        let action = SafeModeAction::DefaultDenyAndQuarantine {
            extension_id: "ext1".to_string(),
            reason: "err".to_string(),
        };
        assert_eq!(action.failure_type(), FailureType::DecisionContractError);

        let action = SafeModeAction::RingBufferFallback {
            capacity: 128,
            high_impact_blocked: true,
        };
        assert_eq!(action.failure_type(), FailureType::EvidenceLedgerFull);

        let action = SafeModeAction::RejectAndRefreshCx {
            rejected_operation: "op".to_string(),
            corruption_detail: "bad".to_string(),
        };
        assert_eq!(action.failure_type(), FailureType::CxCorrupted);

        let action = SafeModeAction::ForceFinalize {
            cell_id: "c1".to_string(),
            timeout_ticks: 100,
        };
        assert_eq!(action.failure_type(), FailureType::CancellationDeadlock);
    }

    #[test]
    fn safe_mode_action_serde_roundtrip() {
        let actions = vec![
            SafeModeAction::RefuseExtensions {
                diagnostic: "version mismatch".to_string(),
            },
            SafeModeAction::DefaultDenyAndQuarantine {
                extension_id: "ext-abc".to_string(),
                reason: "contract panic".to_string(),
            },
            SafeModeAction::RingBufferFallback {
                capacity: 256,
                high_impact_blocked: true,
            },
            SafeModeAction::RejectAndRefreshCx {
                rejected_operation: "hostcall_read".to_string(),
                corruption_detail: "budget underflow".to_string(),
            },
            SafeModeAction::ForceFinalize {
                cell_id: "cell-42".to_string(),
                timeout_ticks: 5000,
            },
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: SafeModeAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, parsed);
        }
    }

    // -- SafeModeEvent tests --

    #[test]
    fn safe_mode_event_serde_roundtrip() {
        let event = SafeModeEvent {
            trace_id: "t1".to_string(),
            failure_type: FailureType::CxCorrupted,
            phase: "activate".to_string(),
            action_summary: "budget underflow".to_string(),
            component: "safe_mode_fallback".to_string(),
            outcome: "safe_mode_active".to_string(),
            error_code: Some("cx_corrupted".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: SafeModeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -- EvidenceRingBuffer tests --

    #[test]
    fn ring_buffer_basic_push_and_read() {
        let mut rb = EvidenceRingBuffer::new(3);
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
        assert_eq!(rb.total_written(), 0);

        rb.push(RingBufferEntry {
            trace_id: "t1".to_string(),
            event: "e1".to_string(),
            outcome: "ok".to_string(),
            component: "c".to_string(),
            sequence: 0,
        });
        assert_eq!(rb.len(), 1);
        assert_eq!(rb.total_written(), 1);
        assert_eq!(rb.entries()[0].trace_id, "t1");
    }

    #[test]
    fn ring_buffer_overflow_wraps() {
        let mut rb = EvidenceRingBuffer::new(2);
        for i in 0..5 {
            rb.push(RingBufferEntry {
                trace_id: format!("t{i}"),
                event: "e".to_string(),
                outcome: "ok".to_string(),
                component: "c".to_string(),
                sequence: i,
            });
        }
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.total_written(), 5);
        // Should have the two most recent entries in order
        let entries = rb.entries();
        assert_eq!(entries[0].trace_id, "t3");
        assert_eq!(entries[1].trace_id, "t4");
    }

    #[test]
    fn ring_buffer_drain_clears() {
        let mut rb = EvidenceRingBuffer::new(4);
        for i in 0..3 {
            rb.push(RingBufferEntry {
                trace_id: format!("t{i}"),
                event: "e".to_string(),
                outcome: "ok".to_string(),
                component: "c".to_string(),
                sequence: i,
            });
        }
        let drained = rb.drain();
        assert_eq!(drained.len(), 3);
        assert!(rb.is_empty());
    }

    #[test]
    fn ring_buffer_serde_roundtrip() {
        let mut rb = EvidenceRingBuffer::new(2);
        rb.push(RingBufferEntry {
            trace_id: "t1".to_string(),
            event: "e1".to_string(),
            outcome: "ok".to_string(),
            component: "c".to_string(),
            sequence: 0,
        });
        let json = serde_json::to_string(&rb).unwrap();
        let parsed: EvidenceRingBuffer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.total_written(), 1);
    }

    // -- SafeModeManager: adapter unavailable --

    #[test]
    fn adapter_unavailable_activates_safe_mode() {
        let mut mgr = SafeModeManager::default();
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Normal
        );
        assert!(!mgr.extensions_refused());

        let action =
            mgr.handle_adapter_unavailable("trace-1", "crate version mismatch v0.2 != v0.3");
        assert!(matches!(action, SafeModeAction::RefuseExtensions { .. }));
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Active
        );
        assert!(mgr.extensions_refused());
        assert!(mgr.any_active());
        assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 1);
    }

    #[test]
    fn adapter_unavailable_blocks_all_actions() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "unavailable");
        assert!(mgr.check_action_blocked(false).is_some());
        assert!(mgr.check_action_blocked(true).is_some());
    }

    #[test]
    fn adapter_unavailable_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "unavailable");
        assert!(mgr.extensions_refused());

        mgr.recover_adapter("trace-2");
        assert!(!mgr.extensions_refused());
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Normal
        );
        assert!(!mgr.any_active());
        assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 1);
    }

    // -- SafeModeManager: decision contract error --

    #[test]
    fn decision_contract_error_quarantines_extension() {
        let mut mgr = SafeModeManager::default();
        let action = mgr.handle_decision_contract_error("trace-1", "ext-bad", "unknown_action");
        assert!(matches!(
            action,
            SafeModeAction::DefaultDenyAndQuarantine { .. }
        ));
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Active
        );
        assert!(mgr.quarantined_extensions().contains_key("ext-bad"));
    }

    #[test]
    fn quarantined_extension_is_denied() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-1", "ext-bad", "err");
        assert!(mgr.check_quarantine("ext-bad").is_some());
        assert!(mgr.check_quarantine("ext-good").is_none());
    }

    #[test]
    fn decision_contract_recovery_unquarantines() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-1", "ext-bad", "err");
        mgr.recover_decision_contract("trace-2", "ext-bad");
        assert!(mgr.quarantined_extensions().is_empty());
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Normal
        );
    }

    #[test]
    fn multiple_quarantines_need_individual_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-1", "ext-a", "err1");
        mgr.handle_decision_contract_error("trace-2", "ext-b", "err2");
        assert_eq!(mgr.quarantined_extensions().len(), 2);

        mgr.recover_decision_contract("trace-3", "ext-a");
        // Still active because ext-b is still quarantined
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Active
        );

        mgr.recover_decision_contract("trace-4", "ext-b");
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Normal
        );
    }

    // -- SafeModeManager: evidence ledger full --

    #[test]
    fn evidence_ledger_full_activates_ring_buffer() {
        let mut mgr = SafeModeManager::new(64);
        let action = mgr.handle_evidence_ledger_full("trace-1", "ledger_capacity_exceeded");
        assert!(matches!(
            action,
            SafeModeAction::RingBufferFallback {
                capacity: 64,
                high_impact_blocked: true
            }
        ));
        assert!(mgr.high_impact_blocked());
        assert_eq!(
            mgr.status(FailureType::EvidenceLedgerFull),
            SafeModeStatus::Active
        );
    }

    #[test]
    fn evidence_ledger_full_blocks_high_impact_only() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("trace-1", "full");
        assert!(mgr.check_action_blocked(true).is_some());
        // Non-high-impact actions are still allowed
        assert!(mgr.check_action_blocked(false).is_none());
    }

    #[test]
    fn evidence_fallback_writes_to_ring_buffer() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("trace-1", "full");
        mgr.write_ring_buffer_entry("trace-1", "test_event", "ok", "test_component");
        assert_eq!(mgr.ring_buffer().len(), 1);
    }

    #[test]
    fn evidence_ledger_recovery_drains_ring_buffer() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("trace-1", "full");
        mgr.write_ring_buffer_entry("trace-1", "ev1", "ok", "comp");
        mgr.write_ring_buffer_entry("trace-2", "ev2", "ok", "comp");

        let drained = mgr.recover_evidence_ledger("trace-3");
        assert_eq!(drained.len(), 2);
        assert!(!mgr.high_impact_blocked());
        assert_eq!(
            mgr.status(FailureType::EvidenceLedgerFull),
            SafeModeStatus::Normal
        );
        assert!(mgr.ring_buffer().is_empty());
    }

    // -- SafeModeManager: Cx corrupted --

    #[test]
    fn cx_corrupted_rejects_operation() {
        let mut mgr = SafeModeManager::default();
        let action =
            mgr.handle_cx_corrupted("trace-1", "hostcall_write", "budget underflow: -42ms");
        assert!(matches!(action, SafeModeAction::RejectAndRefreshCx { .. }));
        if let SafeModeAction::RejectAndRefreshCx {
            rejected_operation,
            corruption_detail,
        } = action
        {
            assert_eq!(rejected_operation, "hostcall_write");
            assert_eq!(corruption_detail, "budget underflow: -42ms");
        }
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
    }

    #[test]
    fn cx_corrupted_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("trace-1", "op", "bad budget");
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);

        mgr.recover_cx("trace-2");
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Normal);
    }

    // -- SafeModeManager: cancellation deadlock --

    #[test]
    fn cancellation_deadlock_force_finalizes() {
        let mut mgr = SafeModeManager::default();
        let action = mgr.handle_cancellation_deadlock("trace-1", "cell-42", 10_000);
        assert!(matches!(action, SafeModeAction::ForceFinalize { .. }));
        if let SafeModeAction::ForceFinalize {
            cell_id,
            timeout_ticks,
        } = action
        {
            assert_eq!(cell_id, "cell-42");
            assert_eq!(timeout_ticks, 10_000);
        }
        assert_eq!(
            mgr.status(FailureType::CancellationDeadlock),
            SafeModeStatus::Active
        );
    }

    #[test]
    fn cancellation_deadlock_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cancellation_deadlock("trace-1", "cell-42", 10_000);
        mgr.recover_cancellation("trace-2");
        assert_eq!(
            mgr.status(FailureType::CancellationDeadlock),
            SafeModeStatus::Normal
        );
    }

    // -- SafeModeManager: validate_decision integration --

    #[test]
    fn validate_decision_allows_when_normal() {
        let mut mgr = SafeModeManager::default();
        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-good")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Allow);
    }

    #[test]
    fn validate_decision_denies_quarantined_extension() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-0", "ext-bad", "err");

        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-bad")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Deny);
    }

    #[test]
    fn validate_decision_denies_when_adapter_unavailable() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-0", "gone");

        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-good")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Deny);
    }

    #[test]
    fn validate_decision_auto_quarantines_on_adapter_error() {
        let mut mgr = SafeModeManager::default();
        let mut adapter =
            MockDecisionContract::new(vec![]).with_failure_mode(MockFailureMode::FailAlways {
                code: "gateway_down",
            });
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-flaky")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Deny);
        assert!(mgr.quarantined_extensions().contains_key("ext-flaky"));
    }

    // -- SafeModeManager: event tracking --

    #[test]
    fn events_emitted_for_activation_and_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "gone");
        mgr.recover_adapter("trace-2");

        let events = mgr.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].phase, "activate");
        assert_eq!(events[0].failure_type, FailureType::AdapterUnavailable);
        assert_eq!(events[0].outcome, "safe_mode_active");
        assert_eq!(events[1].phase, "recover");
        assert_eq!(events[1].outcome, "recovery_complete");
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("trace-1", "op", "bad");
        assert_eq!(mgr.events().len(), 1);
        let drained = mgr.drain_events();
        assert_eq!(drained.len(), 1);
        assert!(mgr.events().is_empty());
    }

    #[test]
    fn event_component_field_is_stable() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("trace-1", "op", "bad");
        assert_eq!(mgr.events()[0].component, "safe_mode_fallback");
    }

    // -- SafeModeManager: cascading failures --

    #[test]
    fn cascading_failure_two_simultaneous() {
        let mut mgr = SafeModeManager::default();
        // Both decision contract error and evidence ledger full at the same time
        mgr.handle_decision_contract_error("trace-1", "ext-1", "panic");
        mgr.handle_evidence_ledger_full("trace-1", "full");

        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Active
        );
        assert_eq!(
            mgr.status(FailureType::EvidenceLedgerFull),
            SafeModeStatus::Active
        );
        assert!(mgr.any_active());
        assert!(mgr.high_impact_blocked());
        assert!(mgr.quarantined_extensions().contains_key("ext-1"));

        // Ring buffer still works even with decision contract down
        mgr.write_ring_buffer_entry("trace-1", "cascade_event", "ok", "test");
        assert_eq!(mgr.ring_buffer().len(), 1);

        // Recover one at a time
        mgr.recover_decision_contract("trace-2", "ext-1");
        assert!(mgr.any_active()); // evidence ledger still active
        let drained = mgr.recover_evidence_ledger("trace-3");
        assert!(!mgr.any_active());
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn cascading_failure_all_five() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "unavailable");
        mgr.handle_decision_contract_error("trace-2", "ext-x", "err");
        mgr.handle_evidence_ledger_full("trace-3", "full");
        mgr.handle_cx_corrupted("trace-4", "op", "bad");
        mgr.handle_cancellation_deadlock("trace-5", "cell-1", 999);

        // All 5 failure types active
        for ft in [
            FailureType::AdapterUnavailable,
            FailureType::DecisionContractError,
            FailureType::EvidenceLedgerFull,
            FailureType::CxCorrupted,
            FailureType::CancellationDeadlock,
        ] {
            assert_eq!(
                mgr.status(ft),
                SafeModeStatus::Active,
                "expected {ft} active"
            );
        }
        assert_eq!(mgr.events().len(), 5);

        // Recover all
        mgr.recover_adapter("r1");
        mgr.recover_decision_contract("r2", "ext-x");
        mgr.recover_evidence_ledger("r3");
        mgr.recover_cx("r4");
        mgr.recover_cancellation("r5");
        assert!(!mgr.any_active());
        assert_eq!(mgr.events().len(), 10); // 5 activate + 5 recover
    }

    // -- SafeModeManager: determinism --

    #[test]
    fn deterministic_activation_100_times() {
        // Inject the same failure 100 times; verify identical safe-mode behavior.
        let mut results = Vec::new();
        for i in 0..100 {
            let mut mgr = SafeModeManager::new(16);
            let action =
                mgr.handle_adapter_unavailable(&format!("trace-{i}"), "crate version mismatch");
            results.push((
                action,
                mgr.extensions_refused(),
                mgr.status(FailureType::AdapterUnavailable),
                mgr.activation_count(FailureType::AdapterUnavailable),
            ));
        }

        // All 100 runs should produce identical results (except trace_id in action)
        for r in &results {
            assert!(matches!(r.0, SafeModeAction::RefuseExtensions { .. }));
            assert!(r.1); // extensions_refused
            assert_eq!(r.2, SafeModeStatus::Active);
            assert_eq!(r.3, 1);
        }
    }

    #[test]
    fn deterministic_decision_error_100_times() {
        let mut results = Vec::new();
        for i in 0..100 {
            let mut mgr = SafeModeManager::default();
            let action = mgr.handle_decision_contract_error(
                &format!("trace-{i}"),
                "ext-det",
                "gateway_panic",
            );
            results.push((
                action.failure_type(),
                mgr.quarantined_extensions().contains_key("ext-det"),
                mgr.status(FailureType::DecisionContractError),
            ));
        }
        for r in &results {
            assert_eq!(r.0, FailureType::DecisionContractError);
            assert!(r.1);
            assert_eq!(r.2, SafeModeStatus::Active);
        }
    }

    #[test]
    fn deterministic_cx_corruption_100_times() {
        let mut results = Vec::new();
        for i in 0..100 {
            let mut mgr = SafeModeManager::default();
            let action =
                mgr.handle_cx_corrupted(&format!("trace-{i}"), "hostcall_read", "budget underflow");
            results.push((action.failure_type(), mgr.status(FailureType::CxCorrupted)));
        }
        for r in &results {
            assert_eq!(r.0, FailureType::CxCorrupted);
            assert_eq!(r.1, SafeModeStatus::Active);
        }
    }

    #[test]
    fn deterministic_evidence_ledger_100_times() {
        for i in 0..100 {
            let mut mgr = SafeModeManager::new(8);
            mgr.handle_evidence_ledger_full(&format!("trace-{i}"), "full");
            assert!(mgr.high_impact_blocked());
            assert_eq!(
                mgr.status(FailureType::EvidenceLedgerFull),
                SafeModeStatus::Active
            );
            mgr.write_ring_buffer_entry(&format!("trace-{i}"), "ev", "ok", "c");
            assert_eq!(mgr.ring_buffer().len(), 1);
        }
    }

    #[test]
    fn deterministic_cancellation_deadlock_100_times() {
        for i in 0..100 {
            let mut mgr = SafeModeManager::default();
            let action = mgr.handle_cancellation_deadlock(&format!("trace-{i}"), "cell-99", 5000);
            assert_eq!(action.failure_type(), FailureType::CancellationDeadlock);
            assert_eq!(
                mgr.status(FailureType::CancellationDeadlock),
                SafeModeStatus::Active
            );
        }
    }

    // -- SafeModeManager: recovery round-trip --

    #[test]
    fn full_lifecycle_activate_recover_reactivate() {
        let mut mgr = SafeModeManager::default();

        // First activation
        mgr.handle_adapter_unavailable("t1", "down");
        assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 1);

        // Recovery
        mgr.recover_adapter("t2");
        assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 1);

        // Second activation
        mgr.handle_adapter_unavailable("t3", "down again");
        assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 2);
        assert!(mgr.extensions_refused());

        // Second recovery
        mgr.recover_adapter("t4");
        assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 2);
        assert!(!mgr.extensions_refused());
    }

    // -- SafeModeStatus tests --

    #[test]
    fn safe_mode_status_default_is_normal() {
        assert_eq!(SafeModeStatus::default(), SafeModeStatus::Normal);
    }

    #[test]
    fn safe_mode_status_serde_roundtrip() {
        for status in [
            SafeModeStatus::Normal,
            SafeModeStatus::Active,
            SafeModeStatus::Recovering,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: SafeModeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    // -- RingBufferEntry tests --

    #[test]
    fn ring_buffer_entry_serde_roundtrip() {
        let entry = RingBufferEntry {
            trace_id: "t1".to_string(),
            event: "safe_mode_activated".to_string(),
            outcome: "ok".to_string(),
            component: "safe_mode_fallback".to_string(),
            sequence: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RingBufferEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    // -- Manager default configuration --

    #[test]
    fn default_manager_starts_normal() {
        let mgr = SafeModeManager::default();
        assert!(!mgr.any_active());
        assert!(!mgr.extensions_refused());
        assert!(!mgr.high_impact_blocked());
        assert!(mgr.quarantined_extensions().is_empty());
        assert!(mgr.events().is_empty());
        assert!(mgr.ring_buffer().is_empty());
    }

    #[test]
    fn custom_ring_buffer_capacity() {
        let mgr = SafeModeManager::new(32);
        assert_eq!(mgr.ring_buffer_capacity, 32);
    }

    // -- check_action_blocked edge cases --

    #[test]
    fn normal_mode_allows_all_actions() {
        let mgr = SafeModeManager::default();
        assert!(mgr.check_action_blocked(false).is_none());
        assert!(mgr.check_action_blocked(true).is_none());
    }

    #[test]
    fn adapter_unavailable_takes_precedence_over_evidence_block() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("t1", "full");
        mgr.handle_adapter_unavailable("t2", "gone");
        // Adapter unavailable blocks everything, not just high-impact
        let reason = mgr.check_action_blocked(false).unwrap();
        assert!(reason.contains("adapter unavailable"));
    }

    // -- Idempotent handling --

    #[test]
    fn repeated_same_failure_increments_count() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("t1", "op1", "bad1");
        mgr.handle_cx_corrupted("t2", "op2", "bad2");
        mgr.handle_cx_corrupted("t3", "op3", "bad3");
        assert_eq!(mgr.activation_count(FailureType::CxCorrupted), 3);
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
        assert_eq!(mgr.events().len(), 3);
    }

    // -- Enrichment tests --

    #[test]
    fn cascading_recovery_partial_leaves_remaining_active() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("t1", "gone");
        mgr.handle_cx_corrupted("t2", "op", "bad");
        mgr.handle_cancellation_deadlock("t3", "cell-1", 100);

        // Recover adapter only
        mgr.recover_adapter("t4");
        assert!(mgr.any_active());
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Normal
        );
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
        assert_eq!(
            mgr.status(FailureType::CancellationDeadlock),
            SafeModeStatus::Active
        );

        // Recover cx
        mgr.recover_cx("t5");
        assert!(mgr.any_active());

        // Recover cancellation
        mgr.recover_cancellation("t6");
        assert!(!mgr.any_active());
    }

    #[test]
    fn ring_buffer_wrapping_under_evidence_safe_mode() {
        let mut mgr = SafeModeManager::new(3);
        mgr.handle_evidence_ledger_full("t1", "full");

        // Write 5 entries to a capacity-3 ring buffer
        for i in 0..5 {
            mgr.write_ring_buffer_entry(&format!("t-{i}"), &format!("ev-{i}"), "ok", "comp");
        }
        assert_eq!(mgr.ring_buffer().len(), 3);
        assert_eq!(mgr.ring_buffer().total_written(), 5);

        // Oldest entries should be the 3 most recent (2, 3, 4)
        let entries = mgr.ring_buffer().entries();
        assert_eq!(entries[0].trace_id, "t-2");
        assert_eq!(entries[1].trace_id, "t-3");
        assert_eq!(entries[2].trace_id, "t-4");

        // Recovery drains the 3 surviving entries
        let drained = mgr.recover_evidence_ledger("t-recover");
        assert_eq!(drained.len(), 3);
        assert!(mgr.ring_buffer().is_empty());
    }

    #[test]
    fn validate_decision_auto_quarantines_after_n_successes() {
        let mut mgr = SafeModeManager::default();
        let mut adapter =
            MockDecisionContract::new(vec![DecisionVerdict::Allow, DecisionVerdict::Allow])
                .with_failure_mode(MockFailureMode::FailAfterN {
                    remaining_successes: 2,
                    code: "gateway_crash",
                });

        // First two calls succeed
        let v1 = mgr
            .validate_decision(&mut adapter, &mock_request(1), "ext-1")
            .unwrap();
        assert_eq!(v1, DecisionVerdict::Allow);
        let v2 = mgr
            .validate_decision(&mut adapter, &mock_request(2), "ext-1")
            .unwrap();
        assert_eq!(v2, DecisionVerdict::Allow);

        // Third call fails → auto-quarantine
        let v3 = mgr
            .validate_decision(&mut adapter, &mock_request(3), "ext-1")
            .unwrap();
        assert_eq!(v3, DecisionVerdict::Deny);
        assert!(mgr.quarantined_extensions().contains_key("ext-1"));
    }

    #[test]
    fn safe_mode_events_trace_id_preserved() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-alpha", "version mismatch");
        mgr.handle_cx_corrupted("trace-beta", "write", "budget underflow");

        let events = mgr.events();
        assert_eq!(events[0].trace_id, "trace-alpha");
        assert_eq!(events[1].trace_id, "trace-beta");
    }

    #[test]
    fn recovery_count_independent_of_activation_count() {
        let mut mgr = SafeModeManager::default();
        // Activate 3 times (repeated activations without recovery between)
        mgr.handle_cx_corrupted("t1", "op1", "bad1");
        mgr.handle_cx_corrupted("t2", "op2", "bad2");
        mgr.handle_cx_corrupted("t3", "op3", "bad3");

        // Single recovery
        mgr.recover_cx("t4");
        assert_eq!(mgr.activation_count(FailureType::CxCorrupted), 3);
        assert_eq!(mgr.recovery_count(FailureType::CxCorrupted), 1);
    }

    #[test]
    fn validate_decision_good_ext_passes_when_other_quarantined() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("t1", "ext-bad", "err");

        // Good extension should still be allowed if adapter works
        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(2);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-good")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Allow);
    }

    #[test]
    fn evidence_ring_buffer_sequence_monotonic() {
        let mut mgr = SafeModeManager::new(256);
        mgr.handle_evidence_ledger_full("t1", "full");

        for i in 0..10 {
            mgr.write_ring_buffer_entry(&format!("t-{i}"), "ev", "ok", "comp");
        }

        let entries = mgr.ring_buffer().entries();
        for window in entries.windows(2) {
            assert!(
                window[0].sequence < window[1].sequence,
                "ring buffer sequence should be monotonically increasing"
            );
        }
    }

    #[test]
    fn deterministic_cascading_all_five_100_times() {
        let mut results = Vec::new();
        for _ in 0..100 {
            let mut mgr = SafeModeManager::default();
            mgr.handle_adapter_unavailable("t1", "gone");
            mgr.handle_decision_contract_error("t2", "ext-x", "err");
            mgr.handle_evidence_ledger_full("t3", "full");
            mgr.handle_cx_corrupted("t4", "op", "bad");
            mgr.handle_cancellation_deadlock("t5", "cell-1", 999);

            let event_count = mgr.events().len();
            let active_count = [
                FailureType::AdapterUnavailable,
                FailureType::DecisionContractError,
                FailureType::EvidenceLedgerFull,
                FailureType::CxCorrupted,
                FailureType::CancellationDeadlock,
            ]
            .iter()
            .filter(|ft| mgr.status(**ft) == SafeModeStatus::Active)
            .count();

            results.push((event_count, active_count));
        }

        let first = &results[0];
        for r in &results[1..] {
            assert_eq!(r, first, "cascading all-five must be deterministic");
        }
    }
}
