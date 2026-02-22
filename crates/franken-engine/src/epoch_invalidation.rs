//! Epoch-bound specialization invalidation and deterministic fallback.
//!
//! Deterministically revokes active specializations and falls back to baseline
//! execution paths whenever underlying proofs, policies, or security epochs
//! change.  No stale optimization survives a trust-state transition.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//! `BTreeSet` for deterministic iteration; `Vec` for serialization-friendly storage.
//!
//! Plan references: Section 10.12 item 4, 9H.1, 9H.14, 9I.8.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::proof_schema::OptimizationClass;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SPECIALIZATION_SCHEMA_DEF: &[u8] = b"EpochBoundSpecialization.v1";
const INVALIDATION_RECEIPT_SCHEMA_DEF: &[u8] = b"InvalidationReceipt.v1";

/// Zone for all epoch-invalidation objects.
const EPOCH_INVALIDATION_ZONE: &str = "epoch-invalidation";

// ---------------------------------------------------------------------------
// InvalidationReason — why a specialization was invalidated
// ---------------------------------------------------------------------------

/// Reason a specialization was invalidated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InvalidationReason {
    /// Security epoch advanced past validity window.
    EpochTransition {
        old_epoch: SecurityEpoch,
        new_epoch: SecurityEpoch,
    },
    /// Underlying policy was rotated.
    PolicyRotation { policy_id: String },
    /// Key rotation invalidated trust chain.
    KeyRotation { key_id: String },
    /// Capability was explicitly revoked.
    CapabilityRevocation { capability_id: String },
    /// Source proof was updated or invalidated.
    ProofUpdate { proof_id: EngineObjectId },
    /// Operator-initiated explicit invalidation.
    OperatorInvalidation { reason: String },
}

impl fmt::Display for InvalidationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochTransition {
                old_epoch,
                new_epoch,
            } => write!(f, "epoch-transition ({old_epoch} -> {new_epoch})"),
            Self::PolicyRotation { policy_id } => {
                write!(f, "policy-rotation ({policy_id})")
            }
            Self::KeyRotation { key_id } => write!(f, "key-rotation ({key_id})"),
            Self::CapabilityRevocation { capability_id } => {
                write!(f, "capability-revocation ({capability_id})")
            }
            Self::ProofUpdate { proof_id } => write!(f, "proof-update ({proof_id})"),
            Self::OperatorInvalidation { reason } => {
                write!(f, "operator-invalidation ({reason})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackState — state machine for specialization lifecycle
// ---------------------------------------------------------------------------

/// Lifecycle state of a specialization's fallback status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FallbackState {
    /// Specialization is active and serving optimized paths.
    Active,
    /// Invalidation in progress — transitioning to baseline.
    Invalidating,
    /// Fallback to baseline is complete and persistent.
    BaselineFallback,
    /// Re-specialization in progress through full staging pipeline.
    ReSpecializing,
}

impl fmt::Display for FallbackState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Invalidating => f.write_str("invalidating"),
            Self::BaselineFallback => f.write_str("baseline-fallback"),
            Self::ReSpecializing => f.write_str("re-specializing"),
        }
    }
}

// ---------------------------------------------------------------------------
// EpochBoundSpecialization — a registered active specialization
// ---------------------------------------------------------------------------

/// An active specialization with epoch-bound validity constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBoundSpecialization {
    /// Unique specialization identity.
    pub specialization_id: EngineObjectId,
    /// Optimization class.
    pub optimization_class: OptimizationClass,
    /// Earliest valid epoch (inclusive).
    pub valid_from_epoch: SecurityEpoch,
    /// Latest valid epoch (inclusive).
    pub valid_until_epoch: SecurityEpoch,
    /// Source proof IDs that justify this specialization.
    pub source_proof_ids: BTreeSet<EngineObjectId>,
    /// Linked policy ID at activation time.
    pub linked_policy_id: String,
    /// Content hash of the rollback token for baseline restoration.
    pub rollback_token_hash: ContentHash,
    /// Content hash of the baseline IR.
    pub baseline_ir_hash: ContentHash,
    /// Current fallback state.
    pub state: FallbackState,
    /// Epoch at which this specialization was activated.
    pub activated_epoch: SecurityEpoch,
    /// Timestamp of activation (nanoseconds).
    pub activated_at_ns: u64,
}

impl EpochBoundSpecialization {
    /// Check if this specialization is valid at the given epoch.
    pub fn is_valid_at(&self, epoch: SecurityEpoch) -> bool {
        epoch >= self.valid_from_epoch && epoch <= self.valid_until_epoch
    }

    /// Canonical bytes for deterministic ID derivation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.specialization_id.as_bytes());
        buf.extend_from_slice(&self.valid_from_epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.valid_until_epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(self.rollback_token_hash.as_bytes());
        buf.extend_from_slice(self.baseline_ir_hash.as_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// InvalidationReceipt — signed record of invalidation
// ---------------------------------------------------------------------------

/// Signed record of a specialization invalidation for audit/replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationReceipt {
    /// Unique receipt identity.
    pub receipt_id: EngineObjectId,
    /// ID of the invalidated specialization.
    pub specialization_id: EngineObjectId,
    /// Why it was invalidated.
    pub reason: InvalidationReason,
    /// Epoch before the invalidation.
    pub old_epoch: SecurityEpoch,
    /// Epoch after the invalidation.
    pub new_epoch: SecurityEpoch,
    /// Content hash of the rollback token consumed.
    pub rollback_token_hash: ContentHash,
    /// Content hash of the baseline restoration snapshot.
    pub baseline_restoration_hash: ContentHash,
    /// Timestamp of invalidation (nanoseconds).
    pub invalidated_at_ns: u64,
    /// Signature over the receipt.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// InvalidationEvent — audit trail entry
// ---------------------------------------------------------------------------

/// Structured audit event for the invalidation subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Nanosecond timestamp.
    pub timestamp_ns: u64,
    /// Event type.
    pub event_type: InvalidationEventType,
    /// Security epoch at event time.
    pub epoch: SecurityEpoch,
}

/// Type of invalidation event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationEventType {
    /// Specialization registered.
    SpecializationRegistered {
        specialization_id: EngineObjectId,
        optimization_class: OptimizationClass,
    },
    /// Epoch transition triggered.
    EpochTransitionTriggered {
        old_epoch: SecurityEpoch,
        new_epoch: SecurityEpoch,
    },
    /// Specialization invalidated.
    SpecializationInvalidated {
        specialization_id: EngineObjectId,
        reason: InvalidationReason,
    },
    /// Fallback to baseline completed.
    BaselineFallbackCompleted { specialization_id: EngineObjectId },
    /// Re-specialization started through full pipeline.
    ReSpecializationStarted { specialization_id: EngineObjectId },
    /// Churn dampening activated.
    ChurnDampeningActivated {
        invalidation_count: u64,
        window_ns: u64,
    },
    /// Churn dampening deactivated.
    ChurnDampeningDeactivated,
    /// Bulk invalidation completed.
    BulkInvalidationCompleted { count: u64, epoch: SecurityEpoch },
    /// Invalidation receipt emitted.
    InvalidationReceiptEmitted {
        receipt_id: EngineObjectId,
        specialization_id: EngineObjectId,
    },
}

// ---------------------------------------------------------------------------
// InvalidationError
// ---------------------------------------------------------------------------

/// Errors from the epoch-invalidation subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationError {
    /// Specialization not found in registry.
    SpecializationNotFound { id: EngineObjectId },
    /// Specialization is already in fallback state.
    AlreadyInFallback { id: EngineObjectId },
    /// Invalid epoch range (from > until).
    InvalidEpochRange {
        valid_from: SecurityEpoch,
        valid_until: SecurityEpoch,
    },
    /// ID derivation failed.
    IdDerivation(String),
    /// Churn dampening is active; extended canary required.
    ChurnDampeningActive {
        invalidation_count: u64,
        window_ns: u64,
    },
    /// Duplicate specialization ID.
    DuplicateSpecialization { id: EngineObjectId },
}

impl fmt::Display for InvalidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpecializationNotFound { id } => {
                write!(f, "specialization not found: {id}")
            }
            Self::AlreadyInFallback { id } => {
                write!(f, "specialization already in fallback: {id}")
            }
            Self::InvalidEpochRange {
                valid_from,
                valid_until,
            } => write!(f, "invalid epoch range: {valid_from} > {valid_until}"),
            Self::IdDerivation(msg) => write!(f, "id derivation: {msg}"),
            Self::ChurnDampeningActive {
                invalidation_count,
                window_ns,
            } => write!(
                f,
                "churn dampening active: {invalidation_count} in {window_ns}ns"
            ),
            Self::DuplicateSpecialization { id } => {
                write!(f, "duplicate specialization: {id}")
            }
        }
    }
}

impl std::error::Error for InvalidationError {}

// ---------------------------------------------------------------------------
// ChurnConfig — churn dampening parameters
// ---------------------------------------------------------------------------

/// Configuration for churn dampening behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChurnConfig {
    /// Maximum invalidations per sliding window before entering conservative mode.
    pub threshold: u64,
    /// Sliding window duration in nanoseconds.
    pub window_ns: u64,
    /// Extended canary burn-in multiplier (millionths: 2_000_000 = 2x).
    pub extended_canary_multiplier: u64,
    /// Cooldown period in nanoseconds after churn dampening deactivates.
    pub cooldown_ns: u64,
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self {
            threshold: 10,
            window_ns: 60_000_000_000,             // 60 seconds
            extended_canary_multiplier: 2_000_000, // 2x
            cooldown_ns: 30_000_000_000,           // 30 seconds
        }
    }
}

// ---------------------------------------------------------------------------
// InvalidationConfig — top-level configuration
// ---------------------------------------------------------------------------

/// Configuration for the epoch invalidation engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationConfig {
    /// Signing key for invalidation receipts.
    pub signing_key: [u8; 32],
    /// Churn dampening configuration.
    pub churn: ChurnConfig,
}

// ---------------------------------------------------------------------------
// EpochInvalidationEngine — the core engine
// ---------------------------------------------------------------------------

/// The epoch-bound invalidation engine.
///
/// Maintains a registry of active specializations, deterministically
/// invalidates them on epoch transitions, handles fallback to baseline,
/// and provides churn dampening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInvalidationEngine {
    /// Current security epoch.
    current_epoch: SecurityEpoch,
    /// Configuration.
    config: InvalidationConfig,
    /// Active specializations (Vec for JSON-serializable storage).
    specializations: Vec<EpochBoundSpecialization>,
    /// Emitted invalidation receipts.
    receipts: Vec<InvalidationReceipt>,
    /// Audit event log.
    events: Vec<InvalidationEvent>,
    /// Next event sequence number.
    event_seq: u64,
    /// Recent invalidation timestamps for churn dampening.
    recent_invalidation_timestamps: Vec<u64>,
    /// Whether conservative mode is active.
    conservative_mode: bool,
    /// Timestamp of last churn deactivation for cooldown tracking.
    churn_deactivated_at_ns: Option<u64>,
    /// Total invalidations performed.
    total_invalidations: u64,
}

impl EpochInvalidationEngine {
    /// Create a new invalidation engine.
    pub fn new(epoch: SecurityEpoch, config: InvalidationConfig) -> Self {
        Self {
            current_epoch: epoch,
            config,
            specializations: Vec::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            event_seq: 0,
            recent_invalidation_timestamps: Vec::new(),
            conservative_mode: false,
            churn_deactivated_at_ns: None,
            total_invalidations: 0,
        }
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Get the audit event log.
    pub fn events(&self) -> &[InvalidationEvent] {
        &self.events
    }

    /// Get all specializations.
    pub fn specializations(&self) -> &[EpochBoundSpecialization] {
        &self.specializations
    }

    /// Look up a specialization by ID.
    pub fn get_specialization(&self, id: &EngineObjectId) -> Option<&EpochBoundSpecialization> {
        self.specializations
            .iter()
            .find(|s| &s.specialization_id == id)
    }

    /// Get emitted invalidation receipts.
    pub fn receipts(&self) -> &[InvalidationReceipt] {
        &self.receipts
    }

    /// Whether conservative mode is currently active.
    pub fn is_conservative_mode(&self) -> bool {
        self.conservative_mode
    }

    /// Total invalidations performed.
    pub fn total_invalidations(&self) -> u64 {
        self.total_invalidations
    }

    /// Count of active specializations (state == Active).
    pub fn active_count(&self) -> usize {
        self.specializations
            .iter()
            .filter(|s| s.state == FallbackState::Active)
            .count()
    }

    /// Count of specializations in baseline fallback.
    pub fn fallback_count(&self) -> usize {
        self.specializations
            .iter()
            .filter(|s| s.state == FallbackState::BaselineFallback)
            .count()
    }

    // -----------------------------------------------------------------------
    // Specialization registration
    // -----------------------------------------------------------------------

    /// Register an active specialization.
    pub fn register_specialization(
        &mut self,
        spec: EpochBoundSpecialization,
        current_ns: u64,
    ) -> Result<(), InvalidationError> {
        if spec.valid_from_epoch > spec.valid_until_epoch {
            return Err(InvalidationError::InvalidEpochRange {
                valid_from: spec.valid_from_epoch,
                valid_until: spec.valid_until_epoch,
            });
        }

        if self
            .specializations
            .iter()
            .any(|s| s.specialization_id == spec.specialization_id)
        {
            return Err(InvalidationError::DuplicateSpecialization {
                id: spec.specialization_id,
            });
        }

        self.emit_event(
            current_ns,
            InvalidationEventType::SpecializationRegistered {
                specialization_id: spec.specialization_id.clone(),
                optimization_class: spec.optimization_class.clone(),
            },
        );

        self.specializations.push(spec);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Epoch transition and bulk invalidation
    // -----------------------------------------------------------------------

    /// Advance to a new epoch, deterministically invalidating expired
    /// specializations.
    ///
    /// Invalidation order is deterministic: specializations are sorted
    /// by specialization_id before processing.
    ///
    /// Returns the count of invalidated specializations.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch, current_ns: u64) -> u64 {
        let old_epoch = self.current_epoch;
        self.current_epoch = new_epoch;

        self.emit_event(
            current_ns,
            InvalidationEventType::EpochTransitionTriggered {
                old_epoch,
                new_epoch,
            },
        );

        // Collect IDs to invalidate, sorted for determinism.
        let mut to_invalidate: Vec<EngineObjectId> = self
            .specializations
            .iter()
            .filter(|s| s.state == FallbackState::Active && !s.is_valid_at(new_epoch))
            .map(|s| s.specialization_id.clone())
            .collect();
        to_invalidate.sort();

        let reason = InvalidationReason::EpochTransition {
            old_epoch,
            new_epoch,
        };
        let count = self.invalidate_batch(&to_invalidate, &reason, current_ns);

        if count > 0 {
            self.emit_event(
                current_ns,
                InvalidationEventType::BulkInvalidationCompleted {
                    count,
                    epoch: new_epoch,
                },
            );
        }

        count
    }

    /// Invalidate a specific specialization by ID.
    pub fn invalidate_specialization(
        &mut self,
        spec_id: &EngineObjectId,
        reason: InvalidationReason,
        current_ns: u64,
    ) -> Result<InvalidationReceipt, InvalidationError> {
        let spec = self
            .specializations
            .iter()
            .find(|s| &s.specialization_id == spec_id)
            .ok_or_else(|| InvalidationError::SpecializationNotFound {
                id: spec_id.clone(),
            })?;

        if spec.state == FallbackState::BaselineFallback
            || spec.state == FallbackState::Invalidating
        {
            return Err(InvalidationError::AlreadyInFallback {
                id: spec_id.clone(),
            });
        }

        let receipt = self.do_invalidate(spec_id, &reason, current_ns)?;
        self.track_invalidation(current_ns);
        Ok(receipt)
    }

    /// Invalidate all specializations linked to a specific proof ID.
    pub fn invalidate_by_proof(&mut self, proof_id: &EngineObjectId, current_ns: u64) -> u64 {
        let mut to_invalidate: Vec<EngineObjectId> = self
            .specializations
            .iter()
            .filter(|s| s.state == FallbackState::Active && s.source_proof_ids.contains(proof_id))
            .map(|s| s.specialization_id.clone())
            .collect();
        to_invalidate.sort();

        let reason = InvalidationReason::ProofUpdate {
            proof_id: proof_id.clone(),
        };
        self.invalidate_batch(&to_invalidate, &reason, current_ns)
    }

    /// Invalidate all specializations linked to a specific policy ID.
    pub fn invalidate_by_policy(&mut self, policy_id: &str, current_ns: u64) -> u64 {
        let mut to_invalidate: Vec<EngineObjectId> = self
            .specializations
            .iter()
            .filter(|s| s.state == FallbackState::Active && s.linked_policy_id == policy_id)
            .map(|s| s.specialization_id.clone())
            .collect();
        to_invalidate.sort();

        let reason = InvalidationReason::PolicyRotation {
            policy_id: policy_id.to_string(),
        };
        self.invalidate_batch(&to_invalidate, &reason, current_ns)
    }

    // -----------------------------------------------------------------------
    // Re-specialization
    // -----------------------------------------------------------------------

    /// Mark a specialization as entering re-specialization through the
    /// full staging pipeline. No shortcut re-activation allowed.
    pub fn begin_respecialization(
        &mut self,
        spec_id: &EngineObjectId,
        current_ns: u64,
    ) -> Result<(), InvalidationError> {
        let spec = self
            .specializations
            .iter_mut()
            .find(|s| &s.specialization_id == spec_id)
            .ok_or_else(|| InvalidationError::SpecializationNotFound {
                id: spec_id.clone(),
            })?;

        if spec.state != FallbackState::BaselineFallback {
            return Err(InvalidationError::AlreadyInFallback {
                id: spec_id.clone(),
            });
        }

        spec.state = FallbackState::ReSpecializing;

        self.emit_event(
            current_ns,
            InvalidationEventType::ReSpecializationStarted {
                specialization_id: spec_id.clone(),
            },
        );

        Ok(())
    }

    /// Complete re-specialization: update the specialization with new
    /// validity bounds and transition back to Active.
    pub fn complete_respecialization(
        &mut self,
        spec_id: &EngineObjectId,
        new_valid_from: SecurityEpoch,
        new_valid_until: SecurityEpoch,
        new_proof_ids: BTreeSet<EngineObjectId>,
        current_ns: u64,
    ) -> Result<(), InvalidationError> {
        if new_valid_from > new_valid_until {
            return Err(InvalidationError::InvalidEpochRange {
                valid_from: new_valid_from,
                valid_until: new_valid_until,
            });
        }

        let spec = self
            .specializations
            .iter_mut()
            .find(|s| &s.specialization_id == spec_id)
            .ok_or_else(|| InvalidationError::SpecializationNotFound {
                id: spec_id.clone(),
            })?;

        if spec.state != FallbackState::ReSpecializing {
            return Err(InvalidationError::AlreadyInFallback {
                id: spec_id.clone(),
            });
        }

        spec.valid_from_epoch = new_valid_from;
        spec.valid_until_epoch = new_valid_until;
        spec.source_proof_ids = new_proof_ids;
        spec.activated_epoch = self.current_epoch;
        spec.activated_at_ns = current_ns;
        spec.state = FallbackState::Active;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Get specializations by optimization class.
    pub fn specializations_by_class(
        &self,
        class: &OptimizationClass,
    ) -> Vec<&EpochBoundSpecialization> {
        self.specializations
            .iter()
            .filter(|s| &s.optimization_class == class)
            .collect()
    }

    /// Get specializations in a given state.
    pub fn specializations_by_state(&self, state: FallbackState) -> Vec<&EpochBoundSpecialization> {
        self.specializations
            .iter()
            .filter(|s| s.state == state)
            .collect()
    }

    /// Whether churn dampening requires extended canary burn-in.
    pub fn requires_extended_canary(&self) -> bool {
        self.conservative_mode
    }

    /// Get the extended canary multiplier (millionths) if churn dampening
    /// is active, else return the base multiplier (1_000_000 = 1.0x).
    pub fn canary_multiplier(&self) -> u64 {
        if self.conservative_mode {
            self.config.churn.extended_canary_multiplier
        } else {
            1_000_000
        }
    }

    // -----------------------------------------------------------------------
    // Internal: invalidation mechanics
    // -----------------------------------------------------------------------

    /// Invalidate a batch of specializations deterministically.
    fn invalidate_batch(
        &mut self,
        ids: &[EngineObjectId],
        reason: &InvalidationReason,
        current_ns: u64,
    ) -> u64 {
        let mut count = 0u64;
        for spec_id in ids {
            if self.do_invalidate(spec_id, reason, current_ns).is_ok() {
                count += 1;
            }
        }
        if count > 0 {
            self.track_invalidation(current_ns);
        }
        count
    }

    /// Perform a single invalidation: transition state, emit receipt, log events.
    fn do_invalidate(
        &mut self,
        spec_id: &EngineObjectId,
        reason: &InvalidationReason,
        current_ns: u64,
    ) -> Result<InvalidationReceipt, InvalidationError> {
        // Find the spec and extract fields we need for the receipt.
        let spec = self
            .specializations
            .iter()
            .find(|s| &s.specialization_id == spec_id)
            .ok_or_else(|| InvalidationError::SpecializationNotFound {
                id: spec_id.clone(),
            })?;
        let activated_epoch = spec.activated_epoch;
        let rollback_hash = spec.rollback_token_hash.clone();
        let baseline_hash = spec.baseline_ir_hash.clone();

        // Transition state.
        let spec_mut = self
            .specializations
            .iter_mut()
            .find(|s| &s.specialization_id == spec_id)
            .unwrap();
        spec_mut.state = FallbackState::BaselineFallback;

        // Build receipt.
        let receipt_id = self.derive_receipt_id(spec_id, current_ns)?;
        let sig_input = {
            let mut buf = Vec::new();
            buf.extend_from_slice(receipt_id.as_bytes());
            buf.extend_from_slice(spec_id.as_bytes());
            buf.extend_from_slice(&current_ns.to_be_bytes());
            buf
        };
        let signature = self.compute_signature(&sig_input);

        let receipt = InvalidationReceipt {
            receipt_id: receipt_id.clone(),
            specialization_id: spec_id.clone(),
            reason: reason.clone(),
            old_epoch: activated_epoch,
            new_epoch: self.current_epoch,
            rollback_token_hash: rollback_hash,
            baseline_restoration_hash: baseline_hash,
            invalidated_at_ns: current_ns,
            signature,
        };

        self.receipts.push(receipt.clone());
        self.total_invalidations += 1;

        self.emit_event(
            current_ns,
            InvalidationEventType::SpecializationInvalidated {
                specialization_id: spec_id.clone(),
                reason: reason.clone(),
            },
        );
        self.emit_event(
            current_ns,
            InvalidationEventType::BaselineFallbackCompleted {
                specialization_id: spec_id.clone(),
            },
        );
        self.emit_event(
            current_ns,
            InvalidationEventType::InvalidationReceiptEmitted {
                receipt_id,
                specialization_id: spec_id.clone(),
            },
        );

        Ok(receipt)
    }

    fn track_invalidation(&mut self, current_ns: u64) {
        self.recent_invalidation_timestamps.push(current_ns);
        self.update_churn_state(current_ns);
    }

    fn update_churn_state(&mut self, current_ns: u64) {
        let cutoff = current_ns.saturating_sub(self.config.churn.window_ns);
        self.recent_invalidation_timestamps
            .retain(|&ts| ts >= cutoff);

        let was_conservative = self.conservative_mode;
        self.conservative_mode =
            self.recent_invalidation_timestamps.len() as u64 >= self.config.churn.threshold;

        if !was_conservative && self.conservative_mode {
            self.emit_event(
                current_ns,
                InvalidationEventType::ChurnDampeningActivated {
                    invalidation_count: self.recent_invalidation_timestamps.len() as u64,
                    window_ns: self.config.churn.window_ns,
                },
            );
        } else if was_conservative && !self.conservative_mode {
            self.churn_deactivated_at_ns = Some(current_ns);
            self.emit_event(current_ns, InvalidationEventType::ChurnDampeningDeactivated);
        }
    }

    fn derive_receipt_id(
        &self,
        spec_id: &EngineObjectId,
        current_ns: u64,
    ) -> Result<EngineObjectId, InvalidationError> {
        let schema_id = SchemaId::from_definition(INVALIDATION_RECEIPT_SCHEMA_DEF);
        let mut canonical = spec_id.as_bytes().to_vec();
        canonical.extend_from_slice(&current_ns.to_be_bytes());
        canonical.extend_from_slice(&self.current_epoch.as_u64().to_be_bytes());
        engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            EPOCH_INVALIDATION_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| InvalidationError::IdDerivation(e.to_string()))
    }

    fn compute_signature(&self, data: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(32 + data.len());
        input.extend_from_slice(&self.config.signing_key);
        input.extend_from_slice(data);
        ContentHash::compute(&input).as_bytes().to_vec()
    }

    fn emit_event(&mut self, timestamp_ns: u64, event_type: InvalidationEventType) {
        let event = InvalidationEvent {
            seq: self.event_seq,
            timestamp_ns,
            event_type,
            epoch: self.current_epoch,
        };
        self.event_seq += 1;
        self.events.push(event);
    }
}

// ---------------------------------------------------------------------------
// Helper: create a specialization with proper ID derivation
// ---------------------------------------------------------------------------

/// Input for building an `EpochBoundSpecialization`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecializationInput {
    pub optimization_class: OptimizationClass,
    pub valid_from_epoch: SecurityEpoch,
    pub valid_until_epoch: SecurityEpoch,
    pub source_proof_ids: BTreeSet<EngineObjectId>,
    pub linked_policy_id: String,
    pub rollback_token_hash: ContentHash,
    pub baseline_ir_hash: ContentHash,
    pub activated_epoch: SecurityEpoch,
    pub activated_at_ns: u64,
}

/// Build an `EpochBoundSpecialization` with a deterministically derived ID.
pub fn create_specialization(
    input: SpecializationInput,
) -> Result<EpochBoundSpecialization, InvalidationError> {
    let schema_id = SchemaId::from_definition(SPECIALIZATION_SCHEMA_DEF);
    let mut canonical = Vec::new();
    canonical.extend_from_slice(input.optimization_class.to_string().as_bytes());
    canonical.extend_from_slice(&input.valid_from_epoch.as_u64().to_be_bytes());
    canonical.extend_from_slice(&input.valid_until_epoch.as_u64().to_be_bytes());
    for pid in &input.source_proof_ids {
        canonical.extend_from_slice(pid.as_bytes());
    }
    canonical.extend_from_slice(input.linked_policy_id.as_bytes());
    canonical.extend_from_slice(input.rollback_token_hash.as_bytes());
    canonical.extend_from_slice(input.baseline_ir_hash.as_bytes());

    let specialization_id = engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        EPOCH_INVALIDATION_ZONE,
        &schema_id,
        &canonical,
    )
    .map_err(|e| InvalidationError::IdDerivation(e.to_string()))?;

    Ok(EpochBoundSpecialization {
        specialization_id,
        optimization_class: input.optimization_class,
        valid_from_epoch: input.valid_from_epoch,
        valid_until_epoch: input.valid_until_epoch,
        source_proof_ids: input.source_proof_ids,
        linked_policy_id: input.linked_policy_id,
        rollback_token_hash: input.rollback_token_hash,
        baseline_ir_hash: input.baseline_ir_hash,
        state: FallbackState::Active,
        activated_epoch: input.activated_epoch,
        activated_at_ns: input.activated_at_ns,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(5);
        }
        key
    }

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn test_config() -> InvalidationConfig {
        InvalidationConfig {
            signing_key: test_key(),
            churn: ChurnConfig::default(),
        }
    }

    fn test_engine() -> EpochInvalidationEngine {
        EpochInvalidationEngine::new(test_epoch(), test_config())
    }

    fn make_proof_id(suffix: &str) -> EngineObjectId {
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"test-proof"),
            suffix.as_bytes(),
        )
        .unwrap()
    }

    fn make_spec(
        class: OptimizationClass,
        valid_from: u64,
        valid_until: u64,
        policy_id: &str,
        suffix: &str,
    ) -> EpochBoundSpecialization {
        let mut proofs = BTreeSet::new();
        proofs.insert(make_proof_id(suffix));
        create_specialization(SpecializationInput {
            optimization_class: class,
            valid_from_epoch: SecurityEpoch::from_raw(valid_from),
            valid_until_epoch: SecurityEpoch::from_raw(valid_until),
            source_proof_ids: proofs,
            linked_policy_id: policy_id.to_string(),
            rollback_token_hash: ContentHash::compute(format!("rollback-{suffix}").as_bytes()),
            baseline_ir_hash: ContentHash::compute(format!("baseline-{suffix}").as_bytes()),
            activated_epoch: SecurityEpoch::from_raw(valid_from),
            activated_at_ns: 1000,
        })
        .expect("create spec should succeed")
    }

    fn make_default_spec() -> EpochBoundSpecialization {
        make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "policy-001",
            "default",
        )
    }

    // --- Registration ---

    #[test]
    fn register_specialization_success() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        assert_eq!(engine.specializations().len(), 1);
        assert!(engine.get_specialization(&spec_id).is_some());
        assert_eq!(engine.active_count(), 1);
    }

    #[test]
    fn register_duplicate_fails() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        engine.register_specialization(spec.clone(), 1000).unwrap();

        let err = engine.register_specialization(spec, 2000).unwrap_err();
        assert!(matches!(
            err,
            InvalidationError::DuplicateSpecialization { .. }
        ));
    }

    #[test]
    fn register_invalid_epoch_range_fails() {
        let mut engine = test_engine();
        let spec = make_spec(
            OptimizationClass::Superinstruction,
            110,
            90, // inverted
            "policy-001",
            "inverted",
        );
        // The create_specialization helper doesn't validate, so it succeeds,
        // but register_specialization does validate.
        let err = engine.register_specialization(spec, 1000).unwrap_err();
        assert!(matches!(err, InvalidationError::InvalidEpochRange { .. }));
    }

    // --- Epoch validity ---

    #[test]
    fn specialization_valid_at_boundary_epochs() {
        let spec = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "p",
            "boundary",
        );
        assert!(spec.is_valid_at(SecurityEpoch::from_raw(90)));
        assert!(spec.is_valid_at(SecurityEpoch::from_raw(100)));
        assert!(spec.is_valid_at(SecurityEpoch::from_raw(110)));
        assert!(!spec.is_valid_at(SecurityEpoch::from_raw(89)));
        assert!(!spec.is_valid_at(SecurityEpoch::from_raw(111)));
    }

    // --- Epoch transition invalidation ---

    #[test]
    fn epoch_advance_invalidates_expired_specializations() {
        let mut engine = test_engine();
        let spec = make_default_spec(); // valid 90..=110
        engine.register_specialization(spec, 1000).unwrap();

        assert_eq!(engine.active_count(), 1);
        assert_eq!(engine.fallback_count(), 0);

        // Advance past valid_until.
        let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);
        assert_eq!(invalidated, 1);
        assert_eq!(engine.active_count(), 0);
        assert_eq!(engine.fallback_count(), 1);
    }

    #[test]
    fn epoch_advance_preserves_valid_specializations() {
        let mut engine = test_engine();
        let spec = make_default_spec(); // valid 90..=110
        engine.register_specialization(spec, 1000).unwrap();

        // Stay within validity window.
        let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(105), 2000);
        assert_eq!(invalidated, 0);
        assert_eq!(engine.active_count(), 1);
    }

    #[test]
    fn epoch_advance_mixed_validity() {
        let mut engine = test_engine();
        let s1 = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            105,
            "policy-001",
            "short-lived",
        );
        let s2 = make_spec(
            OptimizationClass::Superinstruction,
            90,
            120,
            "policy-001",
            "long-lived",
        );
        engine.register_specialization(s1, 1000).unwrap();
        engine.register_specialization(s2, 1000).unwrap();

        // Epoch 110: s1 expires (valid_until=105), s2 survives (valid_until=120).
        let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(110), 2000);
        assert_eq!(invalidated, 1);
        assert_eq!(engine.active_count(), 1);
        assert_eq!(engine.fallback_count(), 1);
    }

    #[test]
    fn epoch_advance_deterministic_order() {
        let mut engine = test_engine();
        // Register multiple specs with same validity.
        for i in 0..5 {
            let spec = make_spec(
                OptimizationClass::TraceSpecialization,
                90,
                100,
                "policy-001",
                &format!("spec-{i}"),
            );
            engine.register_specialization(spec, 1000).unwrap();
        }

        let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
        assert_eq!(invalidated, 5);

        // All receipts should have deterministic ordering.
        let receipt_ids: Vec<_> = engine
            .receipts()
            .iter()
            .map(|r| r.specialization_id.clone())
            .collect();
        let mut sorted = receipt_ids.clone();
        sorted.sort();
        assert_eq!(receipt_ids, sorted);
    }

    // --- Individual invalidation ---

    #[test]
    fn invalidate_specific_specialization() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        let receipt = engine
            .invalidate_specialization(
                &spec_id,
                InvalidationReason::OperatorInvalidation {
                    reason: "manual".to_string(),
                },
                2000,
            )
            .unwrap();

        assert_eq!(receipt.specialization_id, spec_id);
        assert!(!receipt.signature.is_empty());
        assert_eq!(engine.active_count(), 0);
        assert_eq!(engine.fallback_count(), 1);
    }

    #[test]
    fn invalidate_nonexistent_returns_error() {
        let mut engine = test_engine();
        let fake_id = make_proof_id("nonexistent");
        let err = engine
            .invalidate_specialization(
                &fake_id,
                InvalidationReason::OperatorInvalidation {
                    reason: "test".to_string(),
                },
                1000,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InvalidationError::SpecializationNotFound { .. }
        ));
    }

    #[test]
    fn double_invalidation_returns_error() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        engine
            .invalidate_specialization(
                &spec_id,
                InvalidationReason::OperatorInvalidation {
                    reason: "first".to_string(),
                },
                2000,
            )
            .unwrap();

        let err = engine
            .invalidate_specialization(
                &spec_id,
                InvalidationReason::OperatorInvalidation {
                    reason: "second".to_string(),
                },
                3000,
            )
            .unwrap_err();
        assert!(matches!(err, InvalidationError::AlreadyInFallback { .. }));
    }

    // --- Proof-based invalidation ---

    #[test]
    fn invalidate_by_proof() {
        let mut engine = test_engine();
        let proof_id = make_proof_id("shared-proof");
        let mut proofs = BTreeSet::new();
        proofs.insert(proof_id.clone());

        let spec = create_specialization(SpecializationInput {
            optimization_class: OptimizationClass::LayoutSpecialization,
            valid_from_epoch: SecurityEpoch::from_raw(90),
            valid_until_epoch: SecurityEpoch::from_raw(110),
            source_proof_ids: proofs,
            linked_policy_id: "policy-001".to_string(),
            rollback_token_hash: ContentHash::compute(b"rollback"),
            baseline_ir_hash: ContentHash::compute(b"baseline"),
            activated_epoch: SecurityEpoch::from_raw(90),
            activated_at_ns: 1000,
        })
        .unwrap();
        engine.register_specialization(spec, 1000).unwrap();

        let count = engine.invalidate_by_proof(&proof_id, 2000);
        assert_eq!(count, 1);
        assert_eq!(engine.fallback_count(), 1);
    }

    // --- Policy-based invalidation ---

    #[test]
    fn invalidate_by_policy() {
        let mut engine = test_engine();
        let s1 = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "policy-A",
            "pa-1",
        );
        let s2 = make_spec(
            OptimizationClass::Superinstruction,
            90,
            110,
            "policy-A",
            "pa-2",
        );
        let s3 = make_spec(
            OptimizationClass::LayoutSpecialization,
            90,
            110,
            "policy-B",
            "pb-1",
        );
        engine.register_specialization(s1, 1000).unwrap();
        engine.register_specialization(s2, 1000).unwrap();
        engine.register_specialization(s3, 1000).unwrap();

        let count = engine.invalidate_by_policy("policy-A", 2000);
        assert_eq!(count, 2);
        assert_eq!(engine.active_count(), 1); // policy-B survives
    }

    // --- Re-specialization ---

    #[test]
    fn respecialization_full_cycle() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        // Invalidate.
        engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);
        assert_eq!(engine.fallback_count(), 1);

        // Begin re-specialization.
        engine.begin_respecialization(&spec_id, 3000).unwrap();
        let spec = engine.get_specialization(&spec_id).unwrap();
        assert_eq!(spec.state, FallbackState::ReSpecializing);

        // Complete re-specialization with new bounds.
        let new_proofs = {
            let mut s = BTreeSet::new();
            s.insert(make_proof_id("new-proof"));
            s
        };
        engine
            .complete_respecialization(
                &spec_id,
                SecurityEpoch::from_raw(111),
                SecurityEpoch::from_raw(130),
                new_proofs,
                4000,
            )
            .unwrap();

        let spec = engine.get_specialization(&spec_id).unwrap();
        assert_eq!(spec.state, FallbackState::Active);
        assert_eq!(spec.valid_from_epoch, SecurityEpoch::from_raw(111));
        assert_eq!(spec.valid_until_epoch, SecurityEpoch::from_raw(130));
    }

    #[test]
    fn respecialization_requires_fallback_state() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        // Active spec can't begin re-specialization.
        let err = engine.begin_respecialization(&spec_id, 2000).unwrap_err();
        assert!(matches!(err, InvalidationError::AlreadyInFallback { .. }));
    }

    #[test]
    fn complete_respecialization_requires_respecializing_state() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        // Invalidate but don't begin re-specialization.
        engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);

        let err = engine
            .complete_respecialization(
                &spec_id,
                SecurityEpoch::from_raw(111),
                SecurityEpoch::from_raw(130),
                BTreeSet::new(),
                3000,
            )
            .unwrap_err();
        assert!(matches!(err, InvalidationError::AlreadyInFallback { .. }));
    }

    // --- Churn dampening ---

    #[test]
    fn churn_dampening_activates_on_rapid_invalidations() {
        let mut config = test_config();
        config.churn.threshold = 3;
        config.churn.window_ns = 10_000;
        let mut engine = EpochInvalidationEngine::new(test_epoch(), config);

        for i in 0..3 {
            let spec = make_spec(
                OptimizationClass::TraceSpecialization,
                90,
                110,
                "policy-001",
                &format!("churn-{i}"),
            );
            let spec_id = spec.specialization_id.clone();
            engine
                .register_specialization(spec, 1000 + i * 100)
                .unwrap();
            engine
                .invalidate_specialization(
                    &spec_id,
                    InvalidationReason::OperatorInvalidation {
                        reason: "churn-test".to_string(),
                    },
                    1050 + i * 100,
                )
                .unwrap();
        }

        assert!(engine.is_conservative_mode());
        assert!(engine.requires_extended_canary());
        assert_eq!(engine.canary_multiplier(), 2_000_000);
    }

    #[test]
    fn churn_dampening_deactivates_after_window() {
        let mut config = test_config();
        config.churn.threshold = 2;
        config.churn.window_ns = 1000;
        let mut engine = EpochInvalidationEngine::new(test_epoch(), config);

        // Two rapid invalidations.
        let s1 = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "policy-001",
            "damp-1",
        );
        let s1_id = s1.specialization_id.clone();
        engine.register_specialization(s1, 100).unwrap();
        engine
            .invalidate_specialization(
                &s1_id,
                InvalidationReason::OperatorInvalidation {
                    reason: "t".to_string(),
                },
                200,
            )
            .unwrap();

        let s2 = make_spec(
            OptimizationClass::Superinstruction,
            90,
            110,
            "policy-001",
            "damp-2",
        );
        let s2_id = s2.specialization_id.clone();
        engine.register_specialization(s2, 300).unwrap();
        engine
            .invalidate_specialization(
                &s2_id,
                InvalidationReason::OperatorInvalidation {
                    reason: "t".to_string(),
                },
                400,
            )
            .unwrap();

        assert!(engine.is_conservative_mode());

        // Invalidation way later (outside 1000ns window).
        let s3 = make_spec(
            OptimizationClass::LayoutSpecialization,
            90,
            110,
            "policy-001",
            "damp-3",
        );
        let s3_id = s3.specialization_id.clone();
        engine.register_specialization(s3, 5000).unwrap();
        engine
            .invalidate_specialization(
                &s3_id,
                InvalidationReason::OperatorInvalidation {
                    reason: "t".to_string(),
                },
                5100,
            )
            .unwrap();

        // Old timestamps pruned; only 5100 remains < threshold of 2.
        assert!(!engine.is_conservative_mode());
        assert_eq!(engine.canary_multiplier(), 1_000_000);
    }

    // --- Receipts ---

    #[test]
    fn invalidation_receipts_are_signed() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);

        let receipts = engine.receipts();
        assert_eq!(receipts.len(), 1);
        assert!(!receipts[0].signature.is_empty());
        assert_eq!(receipts[0].specialization_id, spec_id);
        assert_eq!(receipts[0].old_epoch, SecurityEpoch::from_raw(90));
        assert_eq!(receipts[0].new_epoch, SecurityEpoch::from_raw(111));
    }

    #[test]
    fn receipt_contains_rollback_and_baseline_hashes() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let expected_rollback = spec.rollback_token_hash.clone();
        let expected_baseline = spec.baseline_ir_hash.clone();
        engine.register_specialization(spec, 1000).unwrap();

        engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);

        let receipt = &engine.receipts()[0];
        assert_eq!(receipt.rollback_token_hash, expected_rollback);
        assert_eq!(receipt.baseline_restoration_hash, expected_baseline);
    }

    // --- Audit events ---

    #[test]
    fn events_have_monotonic_sequence() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        engine.register_specialization(spec, 1000).unwrap();
        engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);

        for (i, event) in engine.events().iter().enumerate() {
            assert_eq!(event.seq, i as u64);
        }
    }

    #[test]
    fn epoch_transition_emits_correct_events() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        engine.register_specialization(spec, 1000).unwrap();
        engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);

        let event_types: Vec<_> = engine
            .events()
            .iter()
            .map(|e| match &e.event_type {
                InvalidationEventType::SpecializationRegistered { .. } => "registered",
                InvalidationEventType::EpochTransitionTriggered { .. } => "epoch-transition",
                InvalidationEventType::SpecializationInvalidated { .. } => "invalidated",
                InvalidationEventType::BaselineFallbackCompleted { .. } => "fallback",
                InvalidationEventType::BulkInvalidationCompleted { .. } => "bulk-complete",
                InvalidationEventType::InvalidationReceiptEmitted { .. } => "receipt",
                InvalidationEventType::ReSpecializationStarted { .. } => "respec",
                InvalidationEventType::ChurnDampeningActivated { .. } => "churn-on",
                InvalidationEventType::ChurnDampeningDeactivated => "churn-off",
            })
            .collect();

        assert_eq!(event_types[0], "registered");
        assert_eq!(event_types[1], "epoch-transition");
        assert_eq!(event_types[2], "invalidated");
        assert_eq!(event_types[3], "fallback");
        assert_eq!(event_types[4], "receipt");
        assert_eq!(event_types[5], "bulk-complete");
    }

    // --- Query methods ---

    #[test]
    fn specializations_by_class() {
        let mut engine = test_engine();
        let s1 = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "policy-001",
            "class-ts",
        );
        let s2 = make_spec(
            OptimizationClass::Superinstruction,
            90,
            110,
            "policy-001",
            "class-si",
        );
        engine.register_specialization(s1, 1000).unwrap();
        engine.register_specialization(s2, 1000).unwrap();

        let trace_specs = engine.specializations_by_class(&OptimizationClass::TraceSpecialization);
        assert_eq!(trace_specs.len(), 1);
        let super_specs = engine.specializations_by_class(&OptimizationClass::Superinstruction);
        assert_eq!(super_specs.len(), 1);
    }

    #[test]
    fn specializations_by_state() {
        let mut engine = test_engine();
        let s1 = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            100,
            "policy-001",
            "state-1",
        );
        let s2 = make_spec(
            OptimizationClass::Superinstruction,
            90,
            120,
            "policy-001",
            "state-2",
        );
        engine.register_specialization(s1, 1000).unwrap();
        engine.register_specialization(s2, 1000).unwrap();

        // Invalidate s1 via epoch advance.
        engine.advance_epoch(SecurityEpoch::from_raw(105), 2000);

        let active = engine.specializations_by_state(FallbackState::Active);
        assert_eq!(active.len(), 1);
        let fallback = engine.specializations_by_state(FallbackState::BaselineFallback);
        assert_eq!(fallback.len(), 1);
    }

    // --- Display impls ---

    #[test]
    fn invalidation_reason_display() {
        let reasons = vec![
            InvalidationReason::EpochTransition {
                old_epoch: SecurityEpoch::from_raw(1),
                new_epoch: SecurityEpoch::from_raw(2),
            },
            InvalidationReason::PolicyRotation {
                policy_id: "p1".to_string(),
            },
            InvalidationReason::KeyRotation {
                key_id: "k1".to_string(),
            },
            InvalidationReason::CapabilityRevocation {
                capability_id: "c1".to_string(),
            },
            InvalidationReason::ProofUpdate {
                proof_id: make_proof_id("test"),
            },
            InvalidationReason::OperatorInvalidation {
                reason: "manual".to_string(),
            },
        ];
        for r in &reasons {
            let s = r.to_string();
            assert!(!s.is_empty(), "reason display should not be empty: {r:?}");
        }
    }

    #[test]
    fn fallback_state_display() {
        assert_eq!(FallbackState::Active.to_string(), "active");
        assert_eq!(FallbackState::Invalidating.to_string(), "invalidating");
        assert_eq!(
            FallbackState::BaselineFallback.to_string(),
            "baseline-fallback"
        );
        assert_eq!(FallbackState::ReSpecializing.to_string(), "re-specializing");
    }

    #[test]
    fn error_display_coverage() {
        let errors = vec![
            InvalidationError::SpecializationNotFound {
                id: make_proof_id("test"),
            },
            InvalidationError::AlreadyInFallback {
                id: make_proof_id("test"),
            },
            InvalidationError::InvalidEpochRange {
                valid_from: SecurityEpoch::from_raw(10),
                valid_until: SecurityEpoch::from_raw(5),
            },
            InvalidationError::IdDerivation("test".to_string()),
            InvalidationError::ChurnDampeningActive {
                invalidation_count: 5,
                window_ns: 1000,
            },
            InvalidationError::DuplicateSpecialization {
                id: make_proof_id("test"),
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "error display should not be empty: {e:?}");
        }
    }

    // --- Serde roundtrips ---

    #[test]
    fn specialization_serde_roundtrip() {
        let spec = make_default_spec();
        let json = serde_json::to_string(&spec).unwrap();
        let restored: EpochBoundSpecialization = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, restored);
    }

    #[test]
    fn invalidation_receipt_serde_roundtrip() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        let receipt = engine
            .invalidate_specialization(
                &spec_id,
                InvalidationReason::PolicyRotation {
                    policy_id: "test".to_string(),
                },
                2000,
            )
            .unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let restored: InvalidationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn invalidation_event_serde_roundtrip() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        engine.register_specialization(spec, 1000).unwrap();

        let event = &engine.events()[0];
        let json = serde_json::to_string(event).unwrap();
        let restored: InvalidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*event, restored);
    }

    #[test]
    fn engine_serde_roundtrip() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        engine.register_specialization(spec, 1000).unwrap();

        let json = serde_json::to_string(&engine).unwrap();
        let restored: EpochInvalidationEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.current_epoch(), engine.current_epoch());
        assert_eq!(
            restored.specializations().len(),
            engine.specializations().len()
        );
        assert_eq!(restored.events().len(), engine.events().len());
    }

    // --- Counters ---

    #[test]
    fn total_invalidations_counter() {
        let mut engine = test_engine();
        for i in 0..3 {
            let spec = make_spec(
                OptimizationClass::TraceSpecialization,
                90,
                100,
                "policy-001",
                &format!("count-{i}"),
            );
            engine.register_specialization(spec, 1000).unwrap();
        }

        engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
        assert_eq!(engine.total_invalidations(), 3);
    }

    // --- Persistent fallback on crash ---

    #[test]
    fn fallback_state_persists_across_serde() {
        let mut engine = test_engine();
        let spec = make_default_spec();
        let spec_id = spec.specialization_id.clone();
        engine.register_specialization(spec, 1000).unwrap();

        engine.advance_epoch(SecurityEpoch::from_raw(111), 2000);

        // Simulate crash/restart via serde roundtrip.
        let json = serde_json::to_string(&engine).unwrap();
        let restored: EpochInvalidationEngine = serde_json::from_str(&json).unwrap();

        let spec = restored.get_specialization(&spec_id).unwrap();
        assert_eq!(spec.state, FallbackState::BaselineFallback);
    }

    // --- create_specialization determinism ---

    #[test]
    fn create_specialization_deterministic() {
        let s1 = make_default_spec();
        let s2 = make_default_spec();
        assert_eq!(s1.specialization_id, s2.specialization_id);
    }

    #[test]
    fn different_params_different_ids() {
        let s1 = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "policy-001",
            "a",
        );
        let s2 = make_spec(
            OptimizationClass::TraceSpecialization,
            90,
            110,
            "policy-001",
            "b",
        );
        assert_ne!(s1.specialization_id, s2.specialization_id);
    }
}
