//! Monotonic security-epoch model and validity-window checks.
//!
//! Every signed trust artifact (policy checkpoints, capability tokens,
//! evidence entries, decision receipts, key attestations) includes epoch
//! metadata.  The runtime validates artifacts against epoch-scoped
//! validity windows before acceptance.  Fail-closed: invalid artifacts
//! are rejected with a typed `EpochValidationError`.
//!
//! Plan references: Section 10.11 item 17, 9G.6 (epoch-scoped validity
//! + key derivation), Top-10 #5 (supply-chain trust), #10 (provenance
//! + revocation fabric).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SecurityEpoch — the monotonic counter
// ---------------------------------------------------------------------------

/// Monotonically increasing security-epoch counter.
///
/// Represents trust-state transitions: policy key rotation, revocation
/// frontier advancement, guardrail configuration changes, loss matrix
/// updates, remote durability or trust configuration changes.
///
/// The epoch value **never decreases** within a runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SecurityEpoch(u64);

impl SecurityEpoch {
    /// The initial epoch (epoch zero — boot state before first transition).
    pub const GENESIS: Self = Self(0);

    /// Create an epoch from a raw value (e.g. from persistence).
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw u64 value.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Advance to the next epoch (saturating — never wraps).
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for SecurityEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// TransitionReason — why the epoch advanced
// ---------------------------------------------------------------------------

/// Reason for an epoch transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransitionReason {
    /// Policy signing key was rotated.
    PolicyKeyRotation,
    /// Revocation frontier was advanced.
    RevocationFrontierAdvance,
    /// Guardrail configuration was changed.
    GuardrailConfigChange,
    /// Loss matrix was updated.
    LossMatrixUpdate,
    /// Remote durability or trust configuration changed.
    RemoteTrustConfigChange,
    /// Manual operator-initiated epoch bump.
    OperatorManualBump,
}

impl fmt::Display for TransitionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::PolicyKeyRotation => "policy_key_rotation",
            Self::RevocationFrontierAdvance => "revocation_frontier_advance",
            Self::GuardrailConfigChange => "guardrail_config_change",
            Self::LossMatrixUpdate => "loss_matrix_update",
            Self::RemoteTrustConfigChange => "remote_trust_config_change",
            Self::OperatorManualBump => "operator_manual_bump",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// EpochMetadata — stamp embedded in every signed trust artifact
// ---------------------------------------------------------------------------

/// Epoch metadata embedded in signed trust artifacts.
///
/// Every signed trust artifact must include this metadata for
/// validity-window checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochMetadata {
    /// Epoch in which the artifact was created.
    pub epoch_id: SecurityEpoch,
    /// Earliest epoch at which the artifact is valid.
    pub valid_from_epoch: SecurityEpoch,
    /// Latest epoch at which the artifact is valid (inclusive).
    /// `None` means valid until explicitly revoked.
    pub valid_until_epoch: Option<SecurityEpoch>,
}

impl EpochMetadata {
    /// Create metadata for an artifact valid starting now with no expiry.
    pub fn open_ended(current_epoch: SecurityEpoch) -> Self {
        Self {
            epoch_id: current_epoch,
            valid_from_epoch: current_epoch,
            valid_until_epoch: None,
        }
    }

    /// Create metadata valid for a specific epoch window.
    pub fn windowed(
        current_epoch: SecurityEpoch,
        valid_from: SecurityEpoch,
        valid_until: SecurityEpoch,
    ) -> Self {
        Self {
            epoch_id: current_epoch,
            valid_from_epoch: valid_from,
            valid_until_epoch: Some(valid_until),
        }
    }
}

// ---------------------------------------------------------------------------
// EpochValidationError — typed rejection reasons
// ---------------------------------------------------------------------------

/// Typed error for epoch validation failures.
///
/// Fail-closed: any validation failure rejects the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochValidationError {
    /// Artifact's `valid_from_epoch` is in the future relative to current.
    NotYetValid {
        current_epoch: SecurityEpoch,
        valid_from: SecurityEpoch,
    },
    /// Artifact's `valid_until_epoch` is in the past relative to current.
    Expired {
        current_epoch: SecurityEpoch,
        valid_until: SecurityEpoch,
    },
    /// Artifact was created in an epoch greater than the current epoch
    /// (future artifact — clock skew, corruption, or attack).
    FutureArtifact {
        current_epoch: SecurityEpoch,
        artifact_epoch: SecurityEpoch,
    },
    /// The validity window is inverted (`valid_from > valid_until`).
    InvertedWindow {
        valid_from: SecurityEpoch,
        valid_until: SecurityEpoch,
    },
}

impl fmt::Display for EpochValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotYetValid {
                current_epoch,
                valid_from,
            } => write!(
                f,
                "artifact not yet valid: current {current_epoch}, valid_from {valid_from}"
            ),
            Self::Expired {
                current_epoch,
                valid_until,
            } => write!(
                f,
                "artifact expired: current {current_epoch}, valid_until {valid_until}"
            ),
            Self::FutureArtifact {
                current_epoch,
                artifact_epoch,
            } => write!(
                f,
                "artifact from future epoch: current {current_epoch}, artifact {artifact_epoch}"
            ),
            Self::InvertedWindow {
                valid_from,
                valid_until,
            } => write!(
                f,
                "inverted validity window: from {valid_from} > until {valid_until}"
            ),
        }
    }
}

impl std::error::Error for EpochValidationError {}

// ---------------------------------------------------------------------------
// MonotonicityViolation — critical security incident
// ---------------------------------------------------------------------------

/// Error indicating an attempt to decrease the epoch counter.
///
/// This is a critical security incident: it means either a bug, an attack,
/// or state corruption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonotonicityViolation {
    /// The current (higher) epoch value.
    pub current: SecurityEpoch,
    /// The attempted (lower or equal) epoch value.
    pub attempted: SecurityEpoch,
}

impl fmt::Display for MonotonicityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "epoch monotonicity violation: current {}, attempted {}",
            self.current, self.attempted
        )
    }
}

impl std::error::Error for MonotonicityViolation {}

// ---------------------------------------------------------------------------
// TransitionRecord — audit trail for epoch transitions
// ---------------------------------------------------------------------------

/// Record of a single epoch transition, for audit and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionRecord {
    /// Epoch before the transition.
    pub previous_epoch: SecurityEpoch,
    /// Epoch after the transition.
    pub new_epoch: SecurityEpoch,
    /// Why the epoch was advanced.
    pub reason: TransitionReason,
    /// Opaque trace identifier for correlation.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// EpochTracker — runtime epoch state machine
// ---------------------------------------------------------------------------

/// Runtime state machine that tracks the current security epoch,
/// enforces monotonicity, validates artifact epoch windows, and
/// records transition history.
///
/// Uses `BTreeMap` for deterministic ordering of per-reason counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochTracker {
    current_epoch: SecurityEpoch,
    transitions: Vec<TransitionRecord>,
    transition_counts: BTreeMap<String, u64>,
}

impl EpochTracker {
    /// Create a tracker starting at the genesis epoch.
    pub fn new() -> Self {
        Self {
            current_epoch: SecurityEpoch::GENESIS,
            transitions: Vec::new(),
            transition_counts: BTreeMap::new(),
        }
    }

    /// Create a tracker restored from persisted epoch value.
    ///
    /// Used on startup: the persisted epoch becomes the floor.
    pub fn from_persisted(epoch: SecurityEpoch) -> Self {
        Self {
            current_epoch: epoch,
            transitions: Vec::new(),
            transition_counts: BTreeMap::new(),
        }
    }

    /// The current epoch value.
    pub fn current(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Advance the epoch for the given reason.
    ///
    /// Returns the new epoch on success, or `MonotonicityViolation` if
    /// the counter would saturate at `u64::MAX` (already at max — no
    /// room to advance, which is treated as a monotonicity failure since
    /// the epoch cannot change).
    pub fn advance(
        &mut self,
        reason: TransitionReason,
        trace_id: &str,
    ) -> Result<SecurityEpoch, MonotonicityViolation> {
        let next = self.current_epoch.next();
        if next == self.current_epoch {
            // saturating_add hit ceiling — cannot advance
            return Err(MonotonicityViolation {
                current: self.current_epoch,
                attempted: next,
            });
        }

        let record = TransitionRecord {
            previous_epoch: self.current_epoch,
            new_epoch: next,
            reason: reason.clone(),
            trace_id: trace_id.to_string(),
        };

        self.current_epoch = next;
        self.transitions.push(record);
        *self
            .transition_counts
            .entry(reason.to_string())
            .or_insert(0) += 1;

        Ok(next)
    }

    /// Attempt to restore from a persisted epoch.
    ///
    /// If the persisted value is higher than the current in-memory
    /// epoch, updates to the persisted value (stale binary detection
    /// succeeds — the persisted epoch is authoritative).
    ///
    /// If the persisted value is lower than the current in-memory
    /// epoch, returns an error (the runtime has a higher epoch than
    /// storage — possible state corruption or clock rollback).
    pub fn verify_persisted(
        &mut self,
        persisted: SecurityEpoch,
    ) -> Result<(), MonotonicityViolation> {
        if persisted >= self.current_epoch {
            self.current_epoch = persisted;
            Ok(())
        } else {
            Err(MonotonicityViolation {
                current: self.current_epoch,
                attempted: persisted,
            })
        }
    }

    /// Validate artifact epoch metadata against the current epoch.
    ///
    /// Fail-closed: returns `Err` on any validity-window violation.
    /// Collects all validation failures (not fail-fast).
    pub fn validate_artifact(
        &self,
        metadata: &EpochMetadata,
    ) -> Result<(), Vec<EpochValidationError>> {
        let mut errors = Vec::new();

        // Check for inverted window first.
        if let Some(valid_until) = metadata.valid_until_epoch
            && metadata.valid_from_epoch > valid_until
        {
            errors.push(EpochValidationError::InvertedWindow {
                valid_from: metadata.valid_from_epoch,
                valid_until,
            });
        }

        // Artifact cannot be from a future epoch.
        if metadata.epoch_id > self.current_epoch {
            errors.push(EpochValidationError::FutureArtifact {
                current_epoch: self.current_epoch,
                artifact_epoch: metadata.epoch_id,
            });
        }

        // Current epoch must be >= valid_from.
        if self.current_epoch < metadata.valid_from_epoch {
            errors.push(EpochValidationError::NotYetValid {
                current_epoch: self.current_epoch,
                valid_from: metadata.valid_from_epoch,
            });
        }

        // Current epoch must be <= valid_until (if set).
        if let Some(valid_until) = metadata.valid_until_epoch
            && self.current_epoch > valid_until
        {
            errors.push(EpochValidationError::Expired {
                current_epoch: self.current_epoch,
                valid_until,
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Create epoch metadata for a new artifact at the current epoch
    /// with no expiry.
    pub fn stamp_open_ended(&self) -> EpochMetadata {
        EpochMetadata::open_ended(self.current_epoch)
    }

    /// Create epoch metadata valid for a specific window.
    pub fn stamp_windowed(
        &self,
        valid_from: SecurityEpoch,
        valid_until: SecurityEpoch,
    ) -> EpochMetadata {
        EpochMetadata::windowed(self.current_epoch, valid_from, valid_until)
    }

    /// Number of transitions recorded.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Immutable view of the transition history.
    pub fn transitions(&self) -> &[TransitionRecord] {
        &self.transitions
    }

    /// Per-reason transition counts (deterministic ordering via BTreeMap).
    pub fn transition_counts(&self) -> &BTreeMap<String, u64> {
        &self.transition_counts
    }
}

impl Default for EpochTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SecurityEpoch basics --

    #[test]
    fn genesis_epoch_is_zero() {
        assert_eq!(SecurityEpoch::GENESIS.as_u64(), 0);
    }

    #[test]
    fn epoch_next_increments() {
        let e = SecurityEpoch::from_raw(5);
        assert_eq!(e.next().as_u64(), 6);
    }

    #[test]
    fn epoch_next_saturates_at_max() {
        let e = SecurityEpoch::from_raw(u64::MAX);
        assert_eq!(e.next().as_u64(), u64::MAX);
    }

    #[test]
    fn epoch_ordering() {
        let a = SecurityEpoch::from_raw(3);
        let b = SecurityEpoch::from_raw(7);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, SecurityEpoch::from_raw(3));
    }

    #[test]
    fn epoch_display() {
        assert_eq!(SecurityEpoch::from_raw(42).to_string(), "epoch:42");
    }

    // -- EpochTracker basics --

    #[test]
    fn tracker_starts_at_genesis() {
        let tracker = EpochTracker::new();
        assert_eq!(tracker.current(), SecurityEpoch::GENESIS);
        assert_eq!(tracker.transition_count(), 0);
    }

    #[test]
    fn tracker_from_persisted() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
        assert_eq!(tracker.current().as_u64(), 10);
    }

    // -- Epoch advancement --

    #[test]
    fn advance_increments_epoch() {
        let mut tracker = EpochTracker::new();
        let new = tracker
            .advance(TransitionReason::PolicyKeyRotation, "trace-001")
            .expect("advance");
        assert_eq!(new.as_u64(), 1);
        assert_eq!(tracker.current().as_u64(), 1);
        assert_eq!(tracker.transition_count(), 1);
    }

    #[test]
    fn multiple_advances_produce_sequential_epochs() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t1")
            .unwrap();
        tracker
            .advance(TransitionReason::RevocationFrontierAdvance, "t2")
            .unwrap();
        tracker
            .advance(TransitionReason::GuardrailConfigChange, "t3")
            .unwrap();
        assert_eq!(tracker.current().as_u64(), 3);
        assert_eq!(tracker.transition_count(), 3);
    }

    #[test]
    fn advance_records_transition() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::LossMatrixUpdate, "trace-abc")
            .unwrap();
        let records = tracker.transitions();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].previous_epoch, SecurityEpoch::GENESIS);
        assert_eq!(records[0].new_epoch, SecurityEpoch::from_raw(1));
        assert_eq!(records[0].reason, TransitionReason::LossMatrixUpdate);
        assert_eq!(records[0].trace_id, "trace-abc");
    }

    #[test]
    fn advance_updates_per_reason_counts() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t1")
            .unwrap();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t2")
            .unwrap();
        tracker
            .advance(TransitionReason::GuardrailConfigChange, "t3")
            .unwrap();

        let counts = tracker.transition_counts();
        assert_eq!(counts["policy_key_rotation"], 2);
        assert_eq!(counts["guardrail_config_change"], 1);
    }

    #[test]
    fn advance_at_u64_max_returns_error() {
        let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(u64::MAX));
        let err = tracker
            .advance(TransitionReason::OperatorManualBump, "overflow")
            .unwrap_err();
        assert_eq!(err.current, SecurityEpoch::from_raw(u64::MAX));
        assert_eq!(err.attempted, SecurityEpoch::from_raw(u64::MAX));
    }

    // -- Persistence verification --

    #[test]
    fn verify_persisted_accepts_higher_epoch() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t1")
            .unwrap();
        assert_eq!(tracker.current().as_u64(), 1);

        // Persisted epoch is higher — this means the persisted state
        // is authoritative (another instance advanced further).
        tracker
            .verify_persisted(SecurityEpoch::from_raw(5))
            .expect("should accept higher persisted");
        assert_eq!(tracker.current().as_u64(), 5);
    }

    #[test]
    fn verify_persisted_accepts_equal_epoch() {
        let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(3));
        tracker
            .verify_persisted(SecurityEpoch::from_raw(3))
            .expect("equal is fine");
        assert_eq!(tracker.current().as_u64(), 3);
    }

    #[test]
    fn verify_persisted_rejects_lower_epoch() {
        let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
        let err = tracker
            .verify_persisted(SecurityEpoch::from_raw(5))
            .unwrap_err();
        assert_eq!(err.current, SecurityEpoch::from_raw(10));
        assert_eq!(err.attempted, SecurityEpoch::from_raw(5));
        // Epoch remains unchanged after rejection.
        assert_eq!(tracker.current().as_u64(), 10);
    }

    // -- Artifact validation: happy paths --

    #[test]
    fn validate_accepts_current_epoch_open_ended() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t1")
            .unwrap();
        let meta = tracker.stamp_open_ended();
        assert!(tracker.validate_artifact(&meta).is_ok());
    }

    #[test]
    fn validate_accepts_past_epoch_open_ended() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t1")
            .unwrap();
        let meta = tracker.stamp_open_ended();

        // Advance further — the old artifact should still be valid (open-ended).
        tracker
            .advance(TransitionReason::RevocationFrontierAdvance, "t2")
            .unwrap();
        assert!(tracker.validate_artifact(&meta).is_ok());
    }

    #[test]
    fn validate_accepts_windowed_artifact_within_range() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
        let meta = EpochMetadata::windowed(
            SecurityEpoch::from_raw(5),
            SecurityEpoch::from_raw(3),
            SecurityEpoch::from_raw(10),
        );
        assert!(tracker.validate_artifact(&meta).is_ok());
    }

    #[test]
    fn validate_accepts_at_exact_valid_from_boundary() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(3));
        let meta = EpochMetadata::windowed(
            SecurityEpoch::from_raw(2),
            SecurityEpoch::from_raw(3),
            SecurityEpoch::from_raw(10),
        );
        assert!(tracker.validate_artifact(&meta).is_ok());
    }

    #[test]
    fn validate_accepts_at_exact_valid_until_boundary() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
        let meta = EpochMetadata::windowed(
            SecurityEpoch::from_raw(5),
            SecurityEpoch::from_raw(3),
            SecurityEpoch::from_raw(10),
        );
        assert!(tracker.validate_artifact(&meta).is_ok());
    }

    // -- Artifact validation: rejection paths --

    #[test]
    fn validate_rejects_future_artifact() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(3));
        let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(5));
        let errors = tracker.validate_artifact(&meta).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            EpochValidationError::FutureArtifact {
                current_epoch,
                artifact_epoch,
            } if current_epoch.as_u64() == 3 && artifact_epoch.as_u64() == 5
        )));
    }

    #[test]
    fn validate_rejects_not_yet_valid() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(2));
        let meta = EpochMetadata::windowed(
            SecurityEpoch::from_raw(2),
            SecurityEpoch::from_raw(5),
            SecurityEpoch::from_raw(10),
        );
        let errors = tracker.validate_artifact(&meta).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            EpochValidationError::NotYetValid {
                current_epoch,
                valid_from,
            } if current_epoch.as_u64() == 2 && valid_from.as_u64() == 5
        )));
    }

    #[test]
    fn validate_rejects_expired() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(15));
        let meta = EpochMetadata::windowed(
            SecurityEpoch::from_raw(5),
            SecurityEpoch::from_raw(3),
            SecurityEpoch::from_raw(10),
        );
        let errors = tracker.validate_artifact(&meta).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            EpochValidationError::Expired {
                current_epoch,
                valid_until,
            } if current_epoch.as_u64() == 15 && valid_until.as_u64() == 10
        )));
    }

    #[test]
    fn validate_rejects_inverted_window() {
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
        let meta = EpochMetadata::windowed(
            SecurityEpoch::from_raw(5),
            SecurityEpoch::from_raw(10),
            SecurityEpoch::from_raw(3),
        );
        let errors = tracker.validate_artifact(&meta).unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            EpochValidationError::InvertedWindow {
                valid_from,
                valid_until,
            } if valid_from.as_u64() == 10 && valid_until.as_u64() == 3
        )));
    }

    #[test]
    fn validate_collects_multiple_errors() {
        // Future artifact + expired window: should collect both errors.
        let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(20));
        let meta = EpochMetadata {
            epoch_id: SecurityEpoch::from_raw(25), // future
            valid_from_epoch: SecurityEpoch::from_raw(1),
            valid_until_epoch: Some(SecurityEpoch::from_raw(10)), // expired
        };
        let errors = tracker.validate_artifact(&meta).unwrap_err();
        assert!(errors.len() >= 2);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, EpochValidationError::FutureArtifact { .. }))
        );
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, EpochValidationError::Expired { .. }))
        );
    }

    // -- Genesis artifact at genesis epoch --

    #[test]
    fn genesis_artifact_at_genesis_epoch_is_valid() {
        let tracker = EpochTracker::new();
        let meta = EpochMetadata::open_ended(SecurityEpoch::GENESIS);
        assert!(tracker.validate_artifact(&meta).is_ok());
    }

    // -- Transition reason display --

    #[test]
    fn transition_reason_display() {
        assert_eq!(
            TransitionReason::PolicyKeyRotation.to_string(),
            "policy_key_rotation"
        );
        assert_eq!(
            TransitionReason::RevocationFrontierAdvance.to_string(),
            "revocation_frontier_advance"
        );
        assert_eq!(
            TransitionReason::GuardrailConfigChange.to_string(),
            "guardrail_config_change"
        );
        assert_eq!(
            TransitionReason::LossMatrixUpdate.to_string(),
            "loss_matrix_update"
        );
        assert_eq!(
            TransitionReason::RemoteTrustConfigChange.to_string(),
            "remote_trust_config_change"
        );
        assert_eq!(
            TransitionReason::OperatorManualBump.to_string(),
            "operator_manual_bump"
        );
    }

    // -- Error display --

    #[test]
    fn epoch_validation_error_display() {
        let err = EpochValidationError::Expired {
            current_epoch: SecurityEpoch::from_raw(10),
            valid_until: SecurityEpoch::from_raw(5),
        };
        assert_eq!(
            err.to_string(),
            "artifact expired: current epoch:10, valid_until epoch:5"
        );
    }

    #[test]
    fn monotonicity_violation_display() {
        let err = MonotonicityViolation {
            current: SecurityEpoch::from_raw(10),
            attempted: SecurityEpoch::from_raw(5),
        };
        assert_eq!(
            err.to_string(),
            "epoch monotonicity violation: current epoch:10, attempted epoch:5"
        );
    }

    // -- Serialization --

    #[test]
    fn epoch_metadata_serialization_round_trip() {
        let meta = EpochMetadata::windowed(
            SecurityEpoch::from_raw(3),
            SecurityEpoch::from_raw(1),
            SecurityEpoch::from_raw(10),
        );
        let json = serde_json::to_string(&meta).expect("serialize");
        let restored: EpochMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(meta, restored);
    }

    #[test]
    fn tracker_serialization_round_trip() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t1")
            .unwrap();
        tracker
            .advance(TransitionReason::GuardrailConfigChange, "t2")
            .unwrap();

        let json = serde_json::to_string(&tracker).expect("serialize");
        let restored: EpochTracker = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.current().as_u64(), 2);
        assert_eq!(restored.transition_count(), 2);
        assert_eq!(restored.transition_counts()["policy_key_rotation"], 1);
    }

    #[test]
    fn epoch_validation_error_serialization_round_trip() {
        let err = EpochValidationError::FutureArtifact {
            current_epoch: SecurityEpoch::from_raw(3),
            artifact_epoch: SecurityEpoch::from_raw(7),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: EpochValidationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    #[test]
    fn all_validation_error_variants_serialize() {
        let errors = vec![
            EpochValidationError::NotYetValid {
                current_epoch: SecurityEpoch::from_raw(1),
                valid_from: SecurityEpoch::from_raw(5),
            },
            EpochValidationError::Expired {
                current_epoch: SecurityEpoch::from_raw(10),
                valid_until: SecurityEpoch::from_raw(5),
            },
            EpochValidationError::FutureArtifact {
                current_epoch: SecurityEpoch::from_raw(3),
                artifact_epoch: SecurityEpoch::from_raw(7),
            },
            EpochValidationError::InvertedWindow {
                valid_from: SecurityEpoch::from_raw(10),
                valid_until: SecurityEpoch::from_raw(3),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: EpochValidationError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn deterministic_serialization() {
        let mut tracker = EpochTracker::new();
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t1")
            .unwrap();
        let json1 = serde_json::to_string(&tracker).expect("serialize");
        let json2 = serde_json::to_string(&tracker).expect("serialize");
        assert_eq!(json1, json2);
    }
}
