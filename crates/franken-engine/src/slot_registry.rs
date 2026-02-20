//! Typed execution-slot registry for the Verified Self-Replacement Architecture.
//!
//! Each slot is a replaceable runtime component that can run either a native
//! Rust cell or an explicitly untrusted delegate cell.  The registry tracks
//! current implementations, promotion lineage, and rollback targets so that
//! delegate-to-native replacement is incremental, evidence-backed, and
//! deterministic.
//!
//! Plan references: Section 10.2 item 7, Section 9I.6 (Verified Self-Replacement
//! Architecture), Section 8.8 (cell model and constitutional rules).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SlotId — unique, deterministic identifier for a replaceable runtime slot
// ---------------------------------------------------------------------------

/// Unique identifier for a replaceable runtime component.
///
/// Slot IDs are short kebab-case strings chosen from a fixed vocabulary
/// (see [`SlotKind`]).  They must be stable across releases so that
/// promotion lineage and rollback references remain valid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SlotId(String);

impl SlotId {
    /// Create a new `SlotId`.  Returns `Err` if the id is empty or
    /// contains characters outside `[a-z0-9-]`.
    pub fn new(id: impl Into<String>) -> Result<Self, SlotRegistryError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SlotRegistryError::InvalidSlotId {
                id: id.clone(),
                reason: "slot id must not be empty".into(),
            });
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(SlotRegistryError::InvalidSlotId {
                id: id.clone(),
                reason: "slot id must contain only [a-z0-9-]".into(),
            });
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// SlotKind — semantic boundary describing what a slot does
// ---------------------------------------------------------------------------

/// Describes the semantic boundary of a runtime slot — what the slot is
/// responsible for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlotKind {
    /// Source text → `IR0 SyntaxIR` (lossless parse representation).
    Parser,
    /// `IR0` → `IR1 SpecIR` (ECMAScript-semantics IR).
    IrLowering,
    /// `IR1` → `IR2 CapabilityIR` (capability/effect graph overlay).
    CapabilityLowering,
    /// `IR2` → `IR3 ExecIR` (execution-ready deterministic IR).
    ExecLowering,
    /// Core bytecode/IR interpreter execution loop.
    Interpreter,
    /// Object model, prototype chain, property semantics.
    ObjectModel,
    /// Closure and lexical scope management.
    ScopeModel,
    /// Promise/microtask queue and async execution.
    AsyncRuntime,
    /// Garbage collector.
    GarbageCollector,
    /// Module resolver and cache.
    ModuleLoader,
    /// Extension hostcall dispatch table.
    HostcallDispatch,
    /// Built-in function implementations (Math, JSON, etc.).
    Builtins,
}

impl fmt::Display for SlotKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Parser => "parser",
            Self::IrLowering => "ir-lowering",
            Self::CapabilityLowering => "capability-lowering",
            Self::ExecLowering => "exec-lowering",
            Self::Interpreter => "interpreter",
            Self::ObjectModel => "object-model",
            Self::ScopeModel => "scope-model",
            Self::AsyncRuntime => "async-runtime",
            Self::GarbageCollector => "garbage-collector",
            Self::ModuleLoader => "module-loader",
            Self::HostcallDispatch => "hostcall-dispatch",
            Self::Builtins => "builtins",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// AuthorityEnvelope — capabilities a slot requires and is permitted
// ---------------------------------------------------------------------------

/// Capabilities that a slot is authorized to exercise.
///
/// The authority envelope constrains what effects a slot implementation may
/// trigger.  Native cells must have an authority envelope `<=` the
/// corresponding delegate cell envelope (Section 8.8 promotion rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityEnvelope {
    /// Capabilities the slot requires to function.
    pub required: Vec<SlotCapability>,
    /// Maximum capabilities the slot is permitted to exercise.
    pub permitted: Vec<SlotCapability>,
}

impl AuthorityEnvelope {
    /// Verify that all required capabilities are within the permitted set.
    pub fn is_consistent(&self) -> bool {
        self.required.iter().all(|req| self.permitted.contains(req))
    }

    /// Check whether `candidate` envelope is `<=` this envelope (the
    /// candidate does not exceed our permitted set).
    pub fn subsumes(&self, candidate: &Self) -> bool {
        candidate
            .permitted
            .iter()
            .all(|cap| self.permitted.contains(cap))
    }
}

/// Individual capability a slot may exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlotCapability {
    /// Read from the source/IR pipeline.
    ReadSource,
    /// Write/emit IR artifacts.
    EmitIr,
    /// Allocate managed heap objects.
    HeapAlloc,
    /// Schedule microtasks or async continuations.
    ScheduleAsync,
    /// Invoke hostcall dispatch table.
    InvokeHostcall,
    /// Access module cache/resolver.
    ModuleAccess,
    /// Trigger GC cycles.
    TriggerGc,
    /// Emit evidence/telemetry artifacts.
    EmitEvidence,
}

// ---------------------------------------------------------------------------
// PromotionStatus — lifecycle state of a slot's implementation
// ---------------------------------------------------------------------------

/// Tracks where a slot implementation stands in the delegate → native
/// promotion lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionStatus {
    /// Running an explicitly untrusted delegate cell.
    Delegate,
    /// A native candidate is under evaluation (shadow/canary).
    PromotionCandidate {
        /// Digest of the candidate native implementation.
        candidate_digest: String,
    },
    /// Promoted to native after passing all gates.
    Promoted {
        /// Digest of the active native implementation.
        native_digest: String,
        /// ID of the signed replacement receipt.
        receipt_id: String,
    },
    /// Demoted back to delegate after a post-promotion failure.
    Demoted {
        /// Reason for demotion.
        reason: String,
        /// Digest of the rollback target that is now active.
        rollback_digest: String,
    },
}

impl PromotionStatus {
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Promoted { .. })
    }

    pub fn is_delegate(&self) -> bool {
        matches!(self, Self::Delegate | Self::Demoted { .. })
    }
}

impl fmt::Display for PromotionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delegate => write!(f, "delegate"),
            Self::PromotionCandidate { candidate_digest } => {
                write!(f, "promotion-candidate({})", candidate_digest)
            }
            Self::Promoted {
                native_digest,
                receipt_id,
            } => write!(f, "promoted({}, receipt={})", native_digest, receipt_id),
            Self::Demoted {
                reason,
                rollback_digest,
            } => write!(
                f,
                "demoted(reason={}, rollback={})",
                reason, rollback_digest
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// SlotEntry — full registration record for a single slot
// ---------------------------------------------------------------------------

/// Complete registration record for one execution slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEntry {
    pub id: SlotId,
    pub kind: SlotKind,
    pub authority: AuthorityEnvelope,
    pub status: PromotionStatus,
    /// Content-addressed digest of the current active implementation.
    pub implementation_digest: String,
    /// Ordered lineage of previous promotion/demotion events.
    pub promotion_lineage: Vec<LineageEvent>,
    /// Digest of the last-known-good implementation for rollback.
    pub rollback_target: Option<String>,
}

/// A single promotion or demotion event in a slot's lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEvent {
    /// What happened.
    pub transition: PromotionTransition,
    /// Digest of the implementation after this event.
    pub digest: String,
    /// ISO-8601 timestamp of the event.
    pub timestamp: String,
    /// Optional signed receipt ID (present for promotions).
    pub receipt_id: Option<String>,
}

/// The kind of transition recorded in lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionTransition {
    /// Initial registration as delegate.
    RegisteredDelegate,
    /// Entered promotion candidacy.
    EnteredCandidacy,
    /// Promoted to native.
    PromotedToNative,
    /// Demoted back to delegate.
    DemotedToDelegate,
    /// Rollback to a prior known-good state.
    RolledBack,
}

// ---------------------------------------------------------------------------
// SlotRegistryError — typed error contract
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotRegistryError {
    InvalidSlotId {
        id: String,
        reason: String,
    },
    DuplicateSlotId {
        id: String,
    },
    SlotNotFound {
        id: String,
    },
    InconsistentAuthority {
        id: String,
        detail: String,
    },
    InvalidTransition {
        id: String,
        from: String,
        to: String,
    },
    AuthorityBroadening {
        id: String,
        detail: String,
    },
}

impl fmt::Display for SlotRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSlotId { id, reason } => {
                write!(f, "invalid slot id '{}': {}", id, reason)
            }
            Self::DuplicateSlotId { id } => {
                write!(f, "duplicate slot id '{}'", id)
            }
            Self::SlotNotFound { id } => {
                write!(f, "slot '{}' not found", id)
            }
            Self::InconsistentAuthority { id, detail } => {
                write!(f, "inconsistent authority for '{}': {}", id, detail)
            }
            Self::InvalidTransition { id, from, to } => {
                write!(f, "invalid transition for '{}': {} -> {}", id, from, to)
            }
            Self::AuthorityBroadening { id, detail } => {
                write!(f, "authority broadening rejected for '{}': {}", id, detail)
            }
        }
    }
}

impl std::error::Error for SlotRegistryError {}

// ---------------------------------------------------------------------------
// SlotRegistry — the registry itself
// ---------------------------------------------------------------------------

/// Registry of all typed execution slots in the runtime.
///
/// Slots are stored in a `BTreeMap` for deterministic iteration order
/// (important for replay and evidence generation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotRegistry {
    slots: BTreeMap<SlotId, SlotEntry>,
}

impl SlotRegistry {
    pub fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }

    /// Register a new slot as a delegate.  Fails if the slot ID already
    /// exists or the authority envelope is inconsistent.
    pub fn register_delegate(
        &mut self,
        id: SlotId,
        kind: SlotKind,
        authority: AuthorityEnvelope,
        implementation_digest: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        if self.slots.contains_key(&id) {
            return Err(SlotRegistryError::DuplicateSlotId { id: id.to_string() });
        }
        if !authority.is_consistent() {
            return Err(SlotRegistryError::InconsistentAuthority {
                id: id.to_string(),
                detail: "required capabilities not within permitted set".into(),
            });
        }

        let entry = SlotEntry {
            id: id.clone(),
            kind,
            authority,
            status: PromotionStatus::Delegate,
            implementation_digest: implementation_digest.clone(),
            promotion_lineage: vec![LineageEvent {
                transition: PromotionTransition::RegisteredDelegate,
                digest: implementation_digest,
                timestamp,
                receipt_id: None,
            }],
            rollback_target: None,
        };

        self.slots.insert(id.clone(), entry);
        Ok(self.slots.get(&id).expect("just inserted"))
    }

    /// Look up a slot by ID.
    pub fn get(&self, id: &SlotId) -> Option<&SlotEntry> {
        self.slots.get(id)
    }

    /// Iterate all slots in deterministic (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &SlotEntry)> {
        self.slots.iter()
    }

    /// Count of registered slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Number of slots currently running native implementations.
    pub fn native_count(&self) -> usize {
        self.slots.values().filter(|e| e.status.is_native()).count()
    }

    /// Number of slots currently running delegate implementations.
    pub fn delegate_count(&self) -> usize {
        self.slots
            .values()
            .filter(|e| e.status.is_delegate())
            .count()
    }

    /// Native coverage ratio (0.0–1.0).
    pub fn native_coverage(&self) -> f64 {
        if self.slots.is_empty() {
            return 0.0;
        }
        self.native_count() as f64 / self.slots.len() as f64
    }

    /// Begin promotion candidacy for a slot.  The slot must currently be
    /// in `Delegate` or `Demoted` status.
    pub fn begin_candidacy(
        &mut self,
        id: &SlotId,
        candidate_digest: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        let entry = self
            .slots
            .get_mut(id)
            .ok_or_else(|| SlotRegistryError::SlotNotFound { id: id.to_string() })?;

        if !entry.status.is_delegate() {
            return Err(SlotRegistryError::InvalidTransition {
                id: id.to_string(),
                from: entry.status.to_string(),
                to: "promotion-candidate".into(),
            });
        }

        entry.status = PromotionStatus::PromotionCandidate {
            candidate_digest: candidate_digest.clone(),
        };
        entry.promotion_lineage.push(LineageEvent {
            transition: PromotionTransition::EnteredCandidacy,
            digest: candidate_digest,
            timestamp,
            receipt_id: None,
        });

        Ok(self.slots.get(id).expect("slot exists"))
    }

    /// Promote a candidate to native.  The slot must be in
    /// `PromotionCandidate` status.  The `native_authority` must not
    /// exceed the delegate's authority envelope.
    pub fn promote(
        &mut self,
        id: &SlotId,
        native_digest: String,
        native_authority: &AuthorityEnvelope,
        receipt_id: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        let entry = self
            .slots
            .get_mut(id)
            .ok_or_else(|| SlotRegistryError::SlotNotFound { id: id.to_string() })?;

        if !matches!(entry.status, PromotionStatus::PromotionCandidate { .. }) {
            return Err(SlotRegistryError::InvalidTransition {
                id: id.to_string(),
                from: entry.status.to_string(),
                to: "promoted".into(),
            });
        }

        // Authority preservation check (Section 8.8 rule 4):
        // native cell authority envelope must be <= delegate declared envelope.
        if !entry.authority.subsumes(native_authority) {
            return Err(SlotRegistryError::AuthorityBroadening {
                id: id.to_string(),
                detail: "native cell authority exceeds delegate envelope".into(),
            });
        }

        // Store current digest as rollback target.
        entry.rollback_target = Some(entry.implementation_digest.clone());
        entry.implementation_digest = native_digest.clone();
        entry.status = PromotionStatus::Promoted {
            native_digest: native_digest.clone(),
            receipt_id: receipt_id.clone(),
        };
        entry.promotion_lineage.push(LineageEvent {
            transition: PromotionTransition::PromotedToNative,
            digest: native_digest,
            timestamp,
            receipt_id: Some(receipt_id),
        });

        Ok(self.slots.get(id).expect("slot exists"))
    }

    /// Demote a promoted slot back to delegate status.
    pub fn demote(
        &mut self,
        id: &SlotId,
        reason: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        let entry = self
            .slots
            .get_mut(id)
            .ok_or_else(|| SlotRegistryError::SlotNotFound { id: id.to_string() })?;

        if !entry.status.is_native() {
            return Err(SlotRegistryError::InvalidTransition {
                id: id.to_string(),
                from: entry.status.to_string(),
                to: "demoted".into(),
            });
        }

        let rollback_digest = entry
            .rollback_target
            .clone()
            .unwrap_or_else(|| entry.implementation_digest.clone());

        entry.implementation_digest = rollback_digest.clone();
        entry.status = PromotionStatus::Demoted {
            reason,
            rollback_digest: rollback_digest.clone(),
        };
        entry.promotion_lineage.push(LineageEvent {
            transition: PromotionTransition::DemotedToDelegate,
            digest: rollback_digest,
            timestamp,
            receipt_id: None,
        });

        Ok(self.slots.get(id).expect("slot exists"))
    }

    /// Check whether all slots are native (GA readiness gate per
    /// Section 8.8 rule 5).
    pub fn is_ga_ready(&self) -> bool {
        !self.slots.is_empty() && self.delegate_count() == 0
    }
}

impl Default for SlotRegistry {
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

    fn test_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::EmitEvidence,
            ],
        }
    }

    fn narrower_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        }
    }

    fn broader_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::HeapAlloc,
                SlotCapability::InvokeHostcall,
            ],
        }
    }

    // -- SlotId validation --

    #[test]
    fn slot_id_rejects_empty() {
        assert!(matches!(
            SlotId::new(""),
            Err(SlotRegistryError::InvalidSlotId { .. })
        ));
    }

    #[test]
    fn slot_id_rejects_uppercase() {
        assert!(matches!(
            SlotId::new("Parser"),
            Err(SlotRegistryError::InvalidSlotId { .. })
        ));
    }

    #[test]
    fn slot_id_accepts_kebab_case() {
        let id = SlotId::new("ir-lowering").unwrap();
        assert_eq!(id.as_str(), "ir-lowering");
    }

    // -- Authority envelope --

    #[test]
    fn consistent_authority_validates() {
        assert!(test_authority().is_consistent());
    }

    #[test]
    fn inconsistent_authority_detected() {
        let bad = AuthorityEnvelope {
            required: vec![SlotCapability::HeapAlloc],
            permitted: vec![SlotCapability::ReadSource],
        };
        assert!(!bad.is_consistent());
    }

    #[test]
    fn authority_subsumes_narrower() {
        assert!(test_authority().subsumes(&narrower_authority()));
    }

    #[test]
    fn authority_does_not_subsume_broader() {
        assert!(!test_authority().subsumes(&broader_authority()));
    }

    // -- Registration --

    #[test]
    fn register_delegate_succeeds() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        let entry = reg
            .register_delegate(
                id.clone(),
                SlotKind::Parser,
                test_authority(),
                "sha256:abc123".into(),
                "2026-02-20T00:00:00Z".into(),
            )
            .unwrap();
        assert_eq!(entry.kind, SlotKind::Parser);
        assert!(entry.status.is_delegate());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:abc123".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();
        assert!(matches!(
            reg.register_delegate(
                id,
                SlotKind::Parser,
                test_authority(),
                "sha256:def456".into(),
                "2026-02-20T00:00:01Z".into(),
            ),
            Err(SlotRegistryError::DuplicateSlotId { .. })
        ));
    }

    #[test]
    fn inconsistent_authority_rejected_on_register() {
        let mut reg = SlotRegistry::new();
        let bad = AuthorityEnvelope {
            required: vec![SlotCapability::HeapAlloc],
            permitted: vec![SlotCapability::ReadSource],
        };
        assert!(matches!(
            reg.register_delegate(
                SlotId::new("parser").unwrap(),
                SlotKind::Parser,
                bad,
                "sha256:abc".into(),
                "2026-02-20T00:00:00Z".into(),
            ),
            Err(SlotRegistryError::InconsistentAuthority { .. })
        ));
    }

    // -- Promotion lifecycle --

    #[test]
    fn full_promotion_lifecycle() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        // Begin candidacy
        reg.begin_candidacy(
            &id,
            "sha256:native-candidate".into(),
            "2026-02-20T01:00:00Z".into(),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert!(matches!(
            entry.status,
            PromotionStatus::PromotionCandidate { .. }
        ));

        // Promote with narrower authority (allowed)
        reg.promote(
            &id,
            "sha256:native-v1".into(),
            &narrower_authority(),
            "receipt-001".into(),
            "2026-02-20T02:00:00Z".into(),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert!(entry.status.is_native());
        assert_eq!(entry.implementation_digest, "sha256:native-v1");
        assert_eq!(reg.native_count(), 1);
        assert_eq!(reg.delegate_count(), 0);

        // Demote
        reg.demote(
            &id,
            "regression detected".into(),
            "2026-02-20T03:00:00Z".into(),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert!(entry.status.is_delegate());
        assert_eq!(reg.native_count(), 0);
        assert_eq!(reg.delegate_count(), 1);

        // Lineage should have 4 events
        assert_eq!(entry.promotion_lineage.len(), 4);
    }

    #[test]
    fn promotion_rejects_authority_broadening() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();
        reg.begin_candidacy(
            &id,
            "sha256:candidate".into(),
            "2026-02-20T01:00:00Z".into(),
        )
        .unwrap();

        // Try to promote with broader authority — must fail
        assert!(matches!(
            reg.promote(
                &id,
                "sha256:native".into(),
                &broader_authority(),
                "receipt-bad".into(),
                "2026-02-20T02:00:00Z".into(),
            ),
            Err(SlotRegistryError::AuthorityBroadening { .. })
        ));
    }

    #[test]
    fn invalid_transition_from_delegate_to_promoted() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        // Skip candidacy — go straight to promote
        assert!(matches!(
            reg.promote(
                &id,
                "sha256:native".into(),
                &narrower_authority(),
                "receipt".into(),
                "2026-02-20T01:00:00Z".into(),
            ),
            Err(SlotRegistryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn demote_from_delegate_is_invalid() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        assert!(matches!(
            reg.demote(&id, "no reason".into(), "2026-02-20T01:00:00Z".into()),
            Err(SlotRegistryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn slot_not_found_errors() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("nonexistent").unwrap();
        assert!(matches!(
            reg.begin_candidacy(&id, "d".into(), "t".into()),
            Err(SlotRegistryError::SlotNotFound { .. })
        ));
    }

    // -- GA readiness --

    #[test]
    fn empty_registry_not_ga_ready() {
        let reg = SlotRegistry::new();
        assert!(!reg.is_ga_ready());
    }

    #[test]
    fn all_native_is_ga_ready() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d".into(),
            "t0".into(),
        )
        .unwrap();
        reg.begin_candidacy(&id, "sha256:c".into(), "t1".into())
            .unwrap();
        reg.promote(
            &id,
            "sha256:n".into(),
            &narrower_authority(),
            "r1".into(),
            "t2".into(),
        )
        .unwrap();
        assert!(reg.is_ga_ready());
    }

    #[test]
    fn native_coverage_calculation() {
        let mut reg = SlotRegistry::new();
        let id1 = SlotId::new("parser").unwrap();
        let id2 = SlotId::new("interpreter").unwrap();
        reg.register_delegate(
            id1.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d1".into(),
            "t0".into(),
        )
        .unwrap();
        reg.register_delegate(
            id2,
            SlotKind::Interpreter,
            test_authority(),
            "sha256:d2".into(),
            "t0".into(),
        )
        .unwrap();
        assert!((reg.native_coverage() - 0.0).abs() < f64::EPSILON);

        reg.begin_candidacy(&id1, "sha256:c1".into(), "t1".into())
            .unwrap();
        reg.promote(
            &id1,
            "sha256:n1".into(),
            &narrower_authority(),
            "r1".into(),
            "t2".into(),
        )
        .unwrap();
        assert!((reg.native_coverage() - 0.5).abs() < f64::EPSILON);
    }

    // -- Deterministic iteration order --

    #[test]
    fn slots_iterate_in_sorted_order() {
        let mut reg = SlotRegistry::new();
        for name in ["zz-last", "aa-first", "mm-middle"] {
            reg.register_delegate(
                SlotId::new(name).unwrap(),
                SlotKind::Builtins,
                test_authority(),
                format!("sha256:{name}"),
                "t0".into(),
            )
            .unwrap();
        }
        let ids: Vec<&str> = reg.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["aa-first", "mm-middle", "zz-last"]);
    }

    // -- Serialization round-trip --

    #[test]
    fn slot_entry_serialization_round_trip() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id,
            SlotKind::Parser,
            test_authority(),
            "sha256:abc".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        let json = serde_json::to_string(&reg).expect("serialize");
        let roundtrip: SlotRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reg.len(), roundtrip.len());

        let orig_id = SlotId::new("parser").unwrap();
        assert_eq!(
            reg.get(&orig_id).unwrap().kind,
            roundtrip.get(&orig_id).unwrap().kind
        );
    }
}
