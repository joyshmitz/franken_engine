//! Append-only hash-linked decision marker stream for high-impact
//! security/policy transitions.
//!
//! Every critical decision (quarantine, revocation, epoch transition,
//! policy activation, emergency override) appends a tamper-evident marker
//! to a hash-linked stream that provides an immutable audit trail.
//!
//! Uses Tier 2 ContentHash for marker linking and Tier 3 AuthenticityHash
//! for signed integrity checkpoints.
//!
//! Plan references: Section 10.11 item 28, 9G.9 (three-tier integrity +
//! append-only decision stream), Top-10 #3, #10.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};

// ---------------------------------------------------------------------------
// DecisionType — types of decisions that produce markers
// ---------------------------------------------------------------------------

/// Types of high-impact decisions tracked in the marker stream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionType {
    /// Quarantine, suspend, or terminate decisions.
    SecurityAction { action: SecurityActionKind },
    /// Policy activation, deactivation, epoch advancement.
    PolicyTransition { transition: PolicyTransitionKind },
    /// Revocation issuance or propagation confirmation.
    RevocationEvent { revocation: RevocationKind },
    /// Security epoch change with before/after state.
    EpochTransition { from_epoch: u64, to_epoch: u64 },
    /// Operator override of automated decision.
    EmergencyOverride { override_reason: String },
    /// E-process guardrail activation.
    GuardrailTriggered { guardrail_id: String },
}

/// Sub-types of security actions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityActionKind {
    Quarantine,
    Suspend,
    Terminate,
}

impl fmt::Display for SecurityActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quarantine => write!(f, "quarantine"),
            Self::Suspend => write!(f, "suspend"),
            Self::Terminate => write!(f, "terminate"),
        }
    }
}

/// Sub-types of policy transitions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyTransitionKind {
    Activation,
    Deactivation,
    EpochAdvancement,
}

impl fmt::Display for PolicyTransitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Activation => write!(f, "activation"),
            Self::Deactivation => write!(f, "deactivation"),
            Self::EpochAdvancement => write!(f, "epoch_advancement"),
        }
    }
}

/// Sub-types of revocation events.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RevocationKind {
    Issuance,
    PropagationConfirmation,
}

impl fmt::Display for RevocationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Issuance => write!(f, "issuance"),
            Self::PropagationConfirmation => write!(f, "propagation_confirmation"),
        }
    }
}

impl fmt::Display for DecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityAction { action } => write!(f, "security_action:{action}"),
            Self::PolicyTransition { transition } => write!(f, "policy_transition:{transition}"),
            Self::RevocationEvent { revocation } => write!(f, "revocation_event:{revocation}"),
            Self::EpochTransition {
                from_epoch,
                to_epoch,
            } => write!(f, "epoch_transition:{from_epoch}->{to_epoch}"),
            Self::EmergencyOverride { .. } => write!(f, "emergency_override"),
            Self::GuardrailTriggered { guardrail_id } => {
                write!(f, "guardrail_triggered:{guardrail_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionMarker — a single marker in the stream
// ---------------------------------------------------------------------------

/// A single marker in the hash-linked decision stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionMarker {
    /// Unique marker identifier (monotonically increasing).
    pub marker_id: u64,
    /// Hash of the previous marker (genesis marker has all zeros).
    pub prev_marker_hash: ContentHash,
    /// Hash of this marker (computed over all fields except this one).
    pub marker_hash: ContentHash,
    /// Virtual timestamp (tick count for determinism).
    pub timestamp_ticks: u64,
    /// Security epoch at time of decision.
    pub epoch_id: u64,
    /// Type of decision that produced this marker.
    pub decision_type: DecisionType,
    /// Decision identifier for correlation with evidence entries.
    pub decision_id: String,
    /// Hash linking to the full evidence entry in the evidence ledger.
    pub evidence_entry_hash: ContentHash,
    /// Actor (agent, operator, or system component) that made the decision.
    pub actor: String,
    /// Concise payload summary (not the full decision payload).
    pub payload_summary: String,
}

// ---------------------------------------------------------------------------
// MarkerInput — input bundle for appending a marker (avoids too_many_arguments)
// ---------------------------------------------------------------------------

/// Input fields required to append a new decision marker.
#[derive(Debug, Clone)]
pub struct MarkerInput {
    /// Virtual timestamp (tick count for determinism).
    pub timestamp_ticks: u64,
    /// Security epoch at time of decision.
    pub epoch_id: u64,
    /// Type of decision that produced this marker.
    pub decision_type: DecisionType,
    /// Decision identifier for correlation with evidence entries.
    pub decision_id: String,
    /// Hash linking to the full evidence entry in the evidence ledger.
    pub evidence_entry_hash: ContentHash,
    /// Actor (agent, operator, or system component) that made the decision.
    pub actor: String,
    /// Concise payload summary (not the full decision payload).
    pub payload_summary: String,
    /// Trace identifier for structured audit events.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// ChainIntegrityError — hash chain verification failures
// ---------------------------------------------------------------------------

/// Error when hash chain integrity verification fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainIntegrityError {
    /// A marker's computed hash does not match its stored hash.
    MarkerHashMismatch {
        marker_id: u64,
        expected: ContentHash,
        computed: ContentHash,
    },
    /// A marker's prev_marker_hash does not match the preceding marker's hash.
    ChainLinkBroken {
        marker_id: u64,
        expected_prev: ContentHash,
        actual_prev: ContentHash,
    },
    /// The stream is empty (cannot verify an empty chain).
    EmptyStream,
    /// Marker IDs are not monotonically increasing.
    NonMonotonicId { marker_id: u64, prev_marker_id: u64 },
}

impl fmt::Display for ChainIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MarkerHashMismatch { marker_id, .. } => {
                write!(f, "marker {marker_id}: hash mismatch")
            }
            Self::ChainLinkBroken { marker_id, .. } => {
                write!(f, "marker {marker_id}: chain link broken")
            }
            Self::EmptyStream => write!(f, "empty stream"),
            Self::NonMonotonicId {
                marker_id,
                prev_marker_id,
            } => write!(f, "non-monotonic: {marker_id} after {prev_marker_id}"),
        }
    }
}

impl std::error::Error for ChainIntegrityError {}

// ---------------------------------------------------------------------------
// IntegrityCheckpoint — periodic signed checkpoint
// ---------------------------------------------------------------------------

/// A signed integrity checkpoint emitted every N markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityCheckpoint {
    /// Marker ID at which this checkpoint was created.
    pub at_marker_id: u64,
    /// Hash of the marker at the checkpoint position.
    pub marker_hash: ContentHash,
    /// Number of markers in the stream at checkpoint time.
    pub chain_length: u64,
    /// Signed hash (Tier 3) covering the checkpoint fields.
    pub signed_hash: AuthenticityHash,
}

// ---------------------------------------------------------------------------
// MarkerEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for marker stream operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkerEvent {
    pub marker_id: u64,
    pub marker_type: String,
    pub chain_length: u64,
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// DecisionMarkerStream — the append-only stream
// ---------------------------------------------------------------------------

/// Append-only hash-linked decision marker stream.
///
/// Markers can only be appended, never modified or deleted. The hash chain
/// ensures tamper detection.
#[derive(Debug)]
pub struct DecisionMarkerStream {
    markers: Vec<DecisionMarker>,
    next_marker_id: u64,
    checkpoints: Vec<IntegrityCheckpoint>,
    checkpoint_interval: u64,
    checkpoint_key: Vec<u8>,
    events: Vec<MarkerEvent>,
}

impl DecisionMarkerStream {
    /// Create a new empty marker stream.
    ///
    /// `checkpoint_interval`: emit a signed checkpoint every N markers.
    /// `checkpoint_key`: key material for Tier 3 signed checkpoints.
    pub fn new(checkpoint_interval: u64, checkpoint_key: Vec<u8>) -> Self {
        Self {
            markers: Vec::new(),
            next_marker_id: 1,
            checkpoints: Vec::new(),
            checkpoint_interval,
            checkpoint_key,
            events: Vec::new(),
        }
    }

    /// Number of markers in the stream.
    pub fn len(&self) -> usize {
        self.markers.len()
    }

    /// Whether the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
    }

    /// Append a new decision marker to the stream.
    pub fn append(&mut self, input: MarkerInput) -> &DecisionMarker {
        let marker_id = self.next_marker_id;
        self.next_marker_id += 1;

        // Previous marker hash (genesis = all zeros).
        let prev_marker_hash = self
            .markers
            .last()
            .map(|m| m.marker_hash.clone())
            .unwrap_or(ContentHash([0u8; 32]));

        let decision_type_str = input.decision_type.to_string();

        // Build marker with placeholder hash, then compute real hash.
        let mut marker = DecisionMarker {
            marker_id,
            prev_marker_hash,
            marker_hash: ContentHash([0u8; 32]), // placeholder
            timestamp_ticks: input.timestamp_ticks,
            epoch_id: input.epoch_id,
            decision_type: input.decision_type,
            decision_id: input.decision_id,
            evidence_entry_hash: input.evidence_entry_hash,
            actor: input.actor,
            payload_summary: input.payload_summary,
        };

        marker.marker_hash = compute_marker_hash(&marker);

        self.markers.push(marker);

        // Emit audit event.
        self.events.push(MarkerEvent {
            marker_id,
            marker_type: decision_type_str,
            chain_length: self.markers.len() as u64,
            trace_id: input.trace_id,
            component: "marker_stream".to_string(),
            event: "marker_appended".to_string(),
            outcome: "ok".to_string(),
        });

        // Check if we should emit a checkpoint.
        if self.checkpoint_interval > 0 && marker_id.is_multiple_of(self.checkpoint_interval) {
            self.emit_checkpoint(marker_id);
        }

        self.markers.last().expect("just pushed")
    }

    /// Get a marker by its ID.
    pub fn get(&self, marker_id: u64) -> Option<&DecisionMarker> {
        self.markers.iter().find(|m| m.marker_id == marker_id)
    }

    /// Verify the hash chain integrity of the entire stream.
    pub fn verify_chain(&self) -> Result<(), ChainIntegrityError> {
        if self.markers.is_empty() {
            return Err(ChainIntegrityError::EmptyStream);
        }

        let genesis_prev = ContentHash([0u8; 32]);

        for (i, marker) in self.markers.iter().enumerate() {
            // Verify monotonic IDs.
            if i > 0 {
                let prev = &self.markers[i - 1];
                if marker.marker_id <= prev.marker_id {
                    return Err(ChainIntegrityError::NonMonotonicId {
                        marker_id: marker.marker_id,
                        prev_marker_id: prev.marker_id,
                    });
                }
            }

            // Verify prev_marker_hash link.
            let expected_prev = if i == 0 {
                &genesis_prev
            } else {
                &self.markers[i - 1].marker_hash
            };

            if marker.prev_marker_hash != *expected_prev {
                return Err(ChainIntegrityError::ChainLinkBroken {
                    marker_id: marker.marker_id,
                    expected_prev: expected_prev.clone(),
                    actual_prev: marker.prev_marker_hash.clone(),
                });
            }

            // Verify marker hash.
            let computed = compute_marker_hash(marker);

            if marker.marker_hash != computed {
                return Err(ChainIntegrityError::MarkerHashMismatch {
                    marker_id: marker.marker_id,
                    expected: marker.marker_hash.clone(),
                    computed,
                });
            }
        }

        Ok(())
    }

    /// Verify chain integrity between two marker IDs (inclusive).
    pub fn verify_range(&self, from_id: u64, to_id: u64) -> Result<(), ChainIntegrityError> {
        let from_idx = self.markers.iter().position(|m| m.marker_id == from_id);
        let to_idx = self.markers.iter().position(|m| m.marker_id == to_id);

        let (from_idx, to_idx) = match (from_idx, to_idx) {
            (Some(f), Some(t)) => (f, t),
            _ => return Err(ChainIntegrityError::EmptyStream),
        };

        for i in from_idx..=to_idx {
            let marker = &self.markers[i];

            if i > from_idx {
                let prev = &self.markers[i - 1];
                if marker.prev_marker_hash != prev.marker_hash {
                    return Err(ChainIntegrityError::ChainLinkBroken {
                        marker_id: marker.marker_id,
                        expected_prev: prev.marker_hash.clone(),
                        actual_prev: marker.prev_marker_hash.clone(),
                    });
                }
            }

            let computed = compute_marker_hash(marker);

            if marker.marker_hash != computed {
                return Err(ChainIntegrityError::MarkerHashMismatch {
                    marker_id: marker.marker_id,
                    expected: marker.marker_hash.clone(),
                    computed,
                });
            }
        }

        Ok(())
    }

    /// All markers in the stream.
    pub fn markers(&self) -> &[DecisionMarker] {
        &self.markers
    }

    /// All checkpoints.
    pub fn checkpoints(&self) -> &[IntegrityCheckpoint] {
        &self.checkpoints
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<MarkerEvent> {
        std::mem::take(&mut self.events)
    }

    /// Emit a signed integrity checkpoint.
    fn emit_checkpoint(&mut self, marker_id: u64) {
        if let Some(marker) = self.get(marker_id) {
            let marker_hash = marker.marker_hash.clone();
            let chain_length = self.markers.len() as u64;

            // Build checkpoint preimage for signing.
            let mut preimage = Vec::new();
            preimage.extend_from_slice(&marker_id.to_be_bytes());
            preimage.extend_from_slice(marker_hash.as_bytes());
            preimage.extend_from_slice(&chain_length.to_be_bytes());

            let signed_hash = AuthenticityHash::compute_keyed(&self.checkpoint_key, &preimage);

            self.checkpoints.push(IntegrityCheckpoint {
                at_marker_id: marker_id,
                marker_hash,
                chain_length,
                signed_hash,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Hash computation
// ---------------------------------------------------------------------------

/// Compute the ContentHash for a marker from its content fields.
fn compute_marker_hash(marker: &DecisionMarker) -> ContentHash {
    let mut preimage = Vec::new();

    preimage.extend_from_slice(&marker.marker_id.to_be_bytes());
    preimage.extend_from_slice(marker.prev_marker_hash.as_bytes());
    preimage.extend_from_slice(&marker.timestamp_ticks.to_be_bytes());
    preimage.extend_from_slice(&marker.epoch_id.to_be_bytes());

    // Decision type as deterministic string.
    let dt_str = marker.decision_type.to_string();
    preimage.extend_from_slice(&(dt_str.len() as u32).to_be_bytes());
    preimage.extend_from_slice(dt_str.as_bytes());

    preimage.extend_from_slice(&(marker.decision_id.len() as u32).to_be_bytes());
    preimage.extend_from_slice(marker.decision_id.as_bytes());

    preimage.extend_from_slice(marker.evidence_entry_hash.as_bytes());

    preimage.extend_from_slice(&(marker.actor.len() as u32).to_be_bytes());
    preimage.extend_from_slice(marker.actor.as_bytes());

    preimage.extend_from_slice(&(marker.payload_summary.len() as u32).to_be_bytes());
    preimage.extend_from_slice(marker.payload_summary.as_bytes());

    ContentHash::compute(&preimage)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_evidence_hash() -> ContentHash {
        ContentHash::compute(b"evidence-entry-content")
    }

    fn make_stream() -> DecisionMarkerStream {
        DecisionMarkerStream::new(5, b"test-checkpoint-key".to_vec())
    }

    fn security_input(id_suffix: &str) -> MarkerInput {
        MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            decision_id: format!("decision-{id_suffix}"),
            evidence_entry_hash: test_evidence_hash(),
            actor: "operator".to_string(),
            payload_summary: "quarantine target-x".to_string(),
            trace_id: format!("trace-{id_suffix}"),
        }
    }

    fn append_security_marker(stream: &mut DecisionMarkerStream, id_suffix: &str) {
        stream.append(security_input(id_suffix));
    }

    // -- Basic append --

    #[test]
    fn append_creates_marker_with_correct_id() {
        let mut stream = make_stream();
        let marker = stream.append(MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            decision_id: "dec-1".to_string(),
            evidence_entry_hash: test_evidence_hash(),
            actor: "operator".to_string(),
            payload_summary: "quarantine ext-abc".to_string(),
            trace_id: "trace-1".to_string(),
        });
        assert_eq!(marker.marker_id, 1);
        assert_eq!(marker.epoch_id, 1);
        assert_eq!(marker.actor, "operator");
    }

    #[test]
    fn sequential_appends_increment_ids() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");
        append_security_marker(&mut stream, "3");
        assert_eq!(stream.len(), 3);
        assert_eq!(stream.markers()[0].marker_id, 1);
        assert_eq!(stream.markers()[1].marker_id, 2);
        assert_eq!(stream.markers()[2].marker_id, 3);
    }

    // -- Hash chain --

    #[test]
    fn genesis_marker_has_zero_prev_hash() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        assert_eq!(stream.markers()[0].prev_marker_hash, ContentHash([0u8; 32]));
    }

    #[test]
    fn subsequent_markers_chain_to_previous() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");

        let m1 = &stream.markers()[0];
        let m2 = &stream.markers()[1];
        assert_eq!(m2.prev_marker_hash, m1.marker_hash);
    }

    #[test]
    fn hash_chain_is_deterministic() {
        let run = || {
            let mut stream = make_stream();
            for i in 0..5 {
                append_security_marker(&mut stream, &i.to_string());
            }
            stream
                .markers()
                .iter()
                .map(|m| m.marker_hash.clone())
                .collect::<Vec<_>>()
        };

        let hashes1 = run();
        let hashes2 = run();
        assert_eq!(hashes1, hashes2);
    }

    // -- Chain verification --

    #[test]
    fn verify_chain_succeeds_on_valid_stream() {
        let mut stream = make_stream();
        for i in 0..10 {
            append_security_marker(&mut stream, &i.to_string());
        }
        assert!(stream.verify_chain().is_ok());
    }

    #[test]
    fn verify_chain_fails_on_empty_stream() {
        let stream = make_stream();
        assert!(matches!(
            stream.verify_chain(),
            Err(ChainIntegrityError::EmptyStream)
        ));
    }

    #[test]
    fn verify_chain_detects_tampered_marker() {
        let mut stream = make_stream();
        for i in 0..5 {
            append_security_marker(&mut stream, &i.to_string());
        }

        // Tamper with a marker's payload.
        stream.markers[2].payload_summary = "tampered!".to_string();

        let err = stream.verify_chain().unwrap_err();
        assert!(matches!(
            err,
            ChainIntegrityError::MarkerHashMismatch { marker_id: 3, .. }
        ));
    }

    #[test]
    fn verify_chain_detects_broken_link() {
        let mut stream = make_stream();
        for i in 0..5 {
            append_security_marker(&mut stream, &i.to_string());
        }

        // Break the chain link by modifying prev_marker_hash.
        stream.markers[3].prev_marker_hash = ContentHash([0xff; 32]);

        let err = stream.verify_chain().unwrap_err();
        assert!(matches!(
            err,
            ChainIntegrityError::ChainLinkBroken { marker_id: 4, .. }
        ));
    }

    // -- Range verification --

    #[test]
    fn verify_range_succeeds_on_valid_subrange() {
        let mut stream = make_stream();
        for i in 0..10 {
            append_security_marker(&mut stream, &i.to_string());
        }
        assert!(stream.verify_range(3, 7).is_ok());
    }

    // -- Checkpoints --

    #[test]
    fn checkpoint_emitted_at_interval() {
        let mut stream = DecisionMarkerStream::new(3, b"key".to_vec());
        for i in 0..6 {
            append_security_marker(&mut stream, &i.to_string());
        }
        // Checkpoints at markers 3 and 6.
        assert_eq!(stream.checkpoints().len(), 2);
        assert_eq!(stream.checkpoints()[0].at_marker_id, 3);
        assert_eq!(stream.checkpoints()[1].at_marker_id, 6);
    }

    #[test]
    fn checkpoint_contains_signed_hash() {
        let mut stream = DecisionMarkerStream::new(2, b"test-key".to_vec());
        for i in 0..4 {
            append_security_marker(&mut stream, &i.to_string());
        }
        assert!(!stream.checkpoints().is_empty());
        // Signed hash should not be all zeros.
        let cp = &stream.checkpoints()[0];
        assert_ne!(cp.signed_hash.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn checkpoint_is_deterministic() {
        let run = || {
            let mut stream = DecisionMarkerStream::new(2, b"key".to_vec());
            for i in 0..4 {
                append_security_marker(&mut stream, &i.to_string());
            }
            stream.checkpoints().to_vec()
        };
        let cp1 = run();
        let cp2 = run();
        assert_eq!(cp1, cp2);
    }

    // -- Decision types --

    #[test]
    fn all_decision_types_produce_valid_markers() {
        let mut stream = make_stream();
        let types = vec![
            DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            DecisionType::SecurityAction {
                action: SecurityActionKind::Suspend,
            },
            DecisionType::SecurityAction {
                action: SecurityActionKind::Terminate,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Activation,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Deactivation,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::EpochAdvancement,
            },
            DecisionType::RevocationEvent {
                revocation: RevocationKind::Issuance,
            },
            DecisionType::RevocationEvent {
                revocation: RevocationKind::PropagationConfirmation,
            },
            DecisionType::EpochTransition {
                from_epoch: 1,
                to_epoch: 2,
            },
            DecisionType::EmergencyOverride {
                override_reason: "critical".to_string(),
            },
            DecisionType::GuardrailTriggered {
                guardrail_id: "grd-1".to_string(),
            },
        ];

        for (i, dt) in types.into_iter().enumerate() {
            stream.append(MarkerInput {
                timestamp_ticks: i as u64 * 10,
                epoch_id: 1,
                decision_type: dt,
                decision_id: format!("dec-{i}"),
                evidence_entry_hash: test_evidence_hash(),
                actor: "system".to_string(),
                payload_summary: "test".to_string(),
                trace_id: format!("trace-{i}"),
            });
        }

        assert_eq!(stream.len(), 11);
        assert!(stream.verify_chain().is_ok());
    }

    // -- Decision type display --

    #[test]
    fn decision_type_display() {
        assert!(
            DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine
            }
            .to_string()
            .contains("quarantine")
        );
        assert!(
            DecisionType::EpochTransition {
                from_epoch: 1,
                to_epoch: 2
            }
            .to_string()
            .contains("1->2")
        );
    }

    // -- Events --

    #[test]
    fn append_emits_events() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");

        let events = stream.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].marker_id, 1);
        assert_eq!(events[0].event, "marker_appended");
        assert_eq!(events[1].marker_id, 2);
    }

    #[test]
    fn drain_events_clears() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        let events1 = stream.drain_events();
        assert_eq!(events1.len(), 1);
        let events2 = stream.drain_events();
        assert!(events2.is_empty());
    }

    // -- Get marker by ID --

    #[test]
    fn get_existing_marker() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");

        let m = stream.get(2).unwrap();
        assert_eq!(m.marker_id, 2);
    }

    #[test]
    fn get_nonexistent_marker_returns_none() {
        let stream = make_stream();
        assert!(stream.get(999).is_none());
    }

    // -- Serialization --

    #[test]
    fn decision_marker_serialization_round_trip() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");

        let marker = &stream.markers()[0];
        let json = serde_json::to_string(marker).expect("serialize");
        let restored: DecisionMarker = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*marker, restored);
    }

    #[test]
    fn integrity_checkpoint_serialization_round_trip() {
        let cp = IntegrityCheckpoint {
            at_marker_id: 10,
            marker_hash: ContentHash::compute(b"test"),
            chain_length: 10,
            signed_hash: AuthenticityHash::compute_keyed(b"key", b"data"),
        };
        let json = serde_json::to_string(&cp).expect("serialize");
        let restored: IntegrityCheckpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cp, restored);
    }

    #[test]
    fn chain_integrity_error_serialization_round_trip() {
        let errors = vec![
            ChainIntegrityError::EmptyStream,
            ChainIntegrityError::NonMonotonicId {
                marker_id: 5,
                prev_marker_id: 6,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ChainIntegrityError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn marker_event_serialization_round_trip() {
        let event = MarkerEvent {
            marker_id: 1,
            marker_type: "security_action".to_string(),
            chain_length: 1,
            trace_id: "trace-1".to_string(),
            component: "marker_stream".to_string(),
            event: "marker_appended".to_string(),
            outcome: "ok".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: MarkerEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Error display --

    #[test]
    fn chain_integrity_error_display() {
        assert_eq!(ChainIntegrityError::EmptyStream.to_string(), "empty stream");
        assert!(
            ChainIntegrityError::MarkerHashMismatch {
                marker_id: 5,
                expected: ContentHash([0; 32]),
                computed: ContentHash([1; 32]),
            }
            .to_string()
            .contains("5")
        );
    }
}
