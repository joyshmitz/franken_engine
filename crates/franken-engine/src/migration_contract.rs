//! Migration contract for explicit cutover boundaries on security-critical
//! formats and policies.
//!
//! When schemas, serialization formats, key types, or policy structures change
//! between versions, the migration must be an explicit, auditable, deterministic
//! cutover — not a hidden translator or compatibility shim.
//!
//! # Cutover types
//!
//! - **Hard cutover**: all objects must be in the new format after migration;
//!   old-format objects are rejected.
//! - **Soft migration**: both old and new formats are accepted during a
//!   transition window with a declared end.
//! - **Parallel run**: both old and new format pipelines run simultaneously
//!   with output comparison during validation; discrepancies abort the migration.
//!
//! # Execution steps
//!
//! 1. Pre-migration: validate all existing data can be converted (dry run).
//! 2. Checkpoint: create a checkpoint marking the migration epoch boundary.
//! 3. Execute: convert existing data or activate new-format acceptance.
//! 4. Verify: run conformance checks against migrated data.
//! 5. Commit: mark migration as complete; begin rejecting old format (hard cutover).
//!
//! Plan reference: Section 10.10 item 29, bd-29s.
//! Dependencies: bd-1p4 (activation lifecycle for rollback primitives).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT: &str = "migration_contract";

// ---------------------------------------------------------------------------
// Cutover types
// ---------------------------------------------------------------------------

/// Type of cutover strategy for a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CutoverType {
    /// All objects must be in the new format after migration.
    HardCutover,
    /// Both old and new formats accepted during a transition window.
    SoftMigration,
    /// Both pipelines run in parallel; discrepancies abort.
    ParallelRun,
}

impl fmt::Display for CutoverType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardCutover => write!(f, "hard_cutover"),
            Self::SoftMigration => write!(f, "soft_migration"),
            Self::ParallelRun => write!(f, "parallel_run"),
        }
    }
}

// ---------------------------------------------------------------------------
// Object classes affected by migrations
// ---------------------------------------------------------------------------

/// Security-critical object classes that may undergo format migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObjectClass {
    SerializationSchema,
    KeyFormat,
    TokenFormat,
    CheckpointFormat,
    RevocationFormat,
    PolicyStructure,
    EvidenceFormat,
    AttestationFormat,
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationSchema => write!(f, "serialization_schema"),
            Self::KeyFormat => write!(f, "key_format"),
            Self::TokenFormat => write!(f, "token_format"),
            Self::CheckpointFormat => write!(f, "checkpoint_format"),
            Self::RevocationFormat => write!(f, "revocation_format"),
            Self::PolicyStructure => write!(f, "policy_structure"),
            Self::EvidenceFormat => write!(f, "evidence_format"),
            Self::AttestationFormat => write!(f, "attestation_format"),
        }
    }
}

impl ObjectClass {
    pub const ALL: [ObjectClass; 8] = [
        Self::SerializationSchema,
        Self::KeyFormat,
        Self::TokenFormat,
        Self::CheckpointFormat,
        Self::RevocationFormat,
        Self::PolicyStructure,
        Self::EvidenceFormat,
        Self::AttestationFormat,
    ];
}

// ---------------------------------------------------------------------------
// Migration declaration
// ---------------------------------------------------------------------------

/// Declaration of a migration: what changes, how, and what is compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationDeclaration {
    /// Unique identifier for this migration.
    pub migration_id: String,
    /// Source format version.
    pub from_version: String,
    /// Target format version.
    pub to_version: String,
    /// Object classes affected by this migration.
    pub affected_objects: Vec<ObjectClass>,
    /// Cutover strategy.
    pub cutover_type: CutoverType,
    /// Human-readable description.
    pub description: String,
    /// Compatibility boundary: what IS compatible across the migration.
    pub compatible_across: Vec<String>,
    /// Compatibility boundary: what is NOT compatible.
    pub incompatible_across: Vec<String>,
    /// For soft migration: tick at which old format is rejected.
    pub transition_end_tick: Option<u64>,
}

// ---------------------------------------------------------------------------
// Migration execution steps
// ---------------------------------------------------------------------------

/// Steps in the migration execution pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MigrationStep {
    /// Validate all data can be converted (dry run).
    PreMigration,
    /// Create epoch-boundary checkpoint.
    Checkpoint,
    /// Convert or activate new-format acceptance.
    Execute,
    /// Run conformance checks on migrated data.
    Verify,
    /// Mark migration as complete.
    Commit,
    /// Rollback to pre-migration state.
    Rollback,
}

impl fmt::Display for MigrationStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreMigration => write!(f, "pre_migration"),
            Self::Checkpoint => write!(f, "checkpoint"),
            Self::Execute => write!(f, "execute"),
            Self::Verify => write!(f, "verify"),
            Self::Commit => write!(f, "commit"),
            Self::Rollback => write!(f, "rollback"),
        }
    }
}

impl MigrationStep {
    /// Normal forward pipeline order.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::PreMigration => Some(Self::Checkpoint),
            Self::Checkpoint => Some(Self::Execute),
            Self::Execute => Some(Self::Verify),
            Self::Verify => Some(Self::Commit),
            Self::Commit => None,
            Self::Rollback => None,
        }
    }

    pub const FORWARD_PIPELINE: [MigrationStep; 5] = [
        Self::PreMigration,
        Self::Checkpoint,
        Self::Execute,
        Self::Verify,
        Self::Commit,
    ];
}

// ---------------------------------------------------------------------------
// Migration state
// ---------------------------------------------------------------------------

/// Current state of a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MigrationState {
    /// Declared but not started.
    Declared,
    /// Pre-migration dry run in progress.
    DryRunning,
    /// Dry run passed, awaiting checkpoint.
    DryRunPassed,
    /// Dry run failed.
    DryRunFailed,
    /// Checkpoint created, executing migration.
    Executing,
    /// Execution complete, verifying.
    Verifying,
    /// Verification passed, awaiting commit.
    Verified,
    /// Verification failed.
    VerificationFailed,
    /// Migration committed (terminal success).
    Committed,
    /// Rolling back.
    RollingBack,
    /// Rolled back (terminal).
    RolledBack,
}

impl fmt::Display for MigrationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declared => write!(f, "declared"),
            Self::DryRunning => write!(f, "dry_running"),
            Self::DryRunPassed => write!(f, "dry_run_passed"),
            Self::DryRunFailed => write!(f, "dry_run_failed"),
            Self::Executing => write!(f, "executing"),
            Self::Verifying => write!(f, "verifying"),
            Self::Verified => write!(f, "verified"),
            Self::VerificationFailed => write!(f, "verification_failed"),
            Self::Committed => write!(f, "committed"),
            Self::RollingBack => write!(f, "rolling_back"),
            Self::RolledBack => write!(f, "rolled_back"),
        }
    }
}

impl MigrationState {
    /// Whether this is a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::RolledBack | Self::DryRunFailed
        )
    }
}

// ---------------------------------------------------------------------------
// Migration errors
// ---------------------------------------------------------------------------

/// Errors during migration execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationContractError {
    /// Migration not found.
    MigrationNotFound { migration_id: String },
    /// Invalid state transition.
    InvalidTransition {
        from: MigrationState,
        to: MigrationState,
    },
    /// Dry run found objects that cannot be converted.
    DryRunFailed {
        migration_id: String,
        unconvertible_count: usize,
        detail: String,
    },
    /// Verification found discrepancies.
    VerificationFailed {
        migration_id: String,
        discrepancy_count: usize,
        detail: String,
    },
    /// Old-format object rejected after hard cutover.
    OldFormatRejected {
        migration_id: String,
        object_class: ObjectClass,
        detail: String,
    },
    /// Migration already exists.
    DuplicateMigration { migration_id: String },
    /// Rollback failed.
    RollbackFailed {
        migration_id: String,
        detail: String,
    },
    /// Parallel run discrepancy detected.
    ParallelRunDiscrepancy {
        migration_id: String,
        discrepancy_count: usize,
    },
}

impl fmt::Display for MigrationContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MigrationNotFound { migration_id } => {
                write!(f, "migration not found: {migration_id}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} -> {to}")
            }
            Self::DryRunFailed {
                migration_id,
                unconvertible_count,
                detail,
            } => {
                write!(
                    f,
                    "dry run failed for {migration_id}: {unconvertible_count} unconvertible: {detail}"
                )
            }
            Self::VerificationFailed {
                migration_id,
                discrepancy_count,
                detail,
            } => {
                write!(
                    f,
                    "verification failed for {migration_id}: {discrepancy_count} discrepancies: {detail}"
                )
            }
            Self::OldFormatRejected {
                migration_id,
                object_class,
                detail,
            } => {
                write!(
                    f,
                    "old format {object_class} rejected after {migration_id}: {detail}"
                )
            }
            Self::DuplicateMigration { migration_id } => {
                write!(f, "duplicate migration: {migration_id}")
            }
            Self::RollbackFailed {
                migration_id,
                detail,
            } => {
                write!(f, "rollback failed for {migration_id}: {detail}")
            }
            Self::ParallelRunDiscrepancy {
                migration_id,
                discrepancy_count,
            } => {
                write!(
                    f,
                    "parallel run discrepancy for {migration_id}: {discrepancy_count}"
                )
            }
        }
    }
}

impl std::error::Error for MigrationContractError {}

/// Stable error codes.
pub fn error_code(err: &MigrationContractError) -> &'static str {
    match err {
        MigrationContractError::MigrationNotFound { .. } => "MC_MIGRATION_NOT_FOUND",
        MigrationContractError::InvalidTransition { .. } => "MC_INVALID_TRANSITION",
        MigrationContractError::DryRunFailed { .. } => "MC_DRY_RUN_FAILED",
        MigrationContractError::VerificationFailed { .. } => "MC_VERIFICATION_FAILED",
        MigrationContractError::OldFormatRejected { .. } => "MC_OLD_FORMAT_REJECTED",
        MigrationContractError::DuplicateMigration { .. } => "MC_DUPLICATE_MIGRATION",
        MigrationContractError::RollbackFailed { .. } => "MC_ROLLBACK_FAILED",
        MigrationContractError::ParallelRunDiscrepancy { .. } => "MC_PARALLEL_DISCREPANCY",
    }
}

// ---------------------------------------------------------------------------
// Migration audit events
// ---------------------------------------------------------------------------

/// Structured audit event emitted during migration operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub migration_id: Option<String>,
    pub step: Option<String>,
    pub affected_count: Option<usize>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub timestamp: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Dry run result
// ---------------------------------------------------------------------------

/// Result of a pre-migration dry run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunResult {
    pub migration_id: String,
    pub total_objects: usize,
    pub convertible: usize,
    pub unconvertible: usize,
    pub details: Vec<String>,
}

impl DryRunResult {
    pub fn passed(&self) -> bool {
        self.unconvertible == 0
    }
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/// Result of post-migration conformance verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub migration_id: String,
    pub objects_checked: usize,
    pub discrepancies: usize,
    pub details: Vec<String>,
}

impl VerificationResult {
    pub fn passed(&self) -> bool {
        self.discrepancies == 0
    }
}

// ---------------------------------------------------------------------------
// Migration entry (internal state)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationEntry {
    declaration: MigrationDeclaration,
    state: MigrationState,
    checkpoint_seq: Option<u64>,
    started_at: Option<DeterministicTimestamp>,
    completed_at: Option<DeterministicTimestamp>,
    dry_run_result: Option<DryRunResult>,
    verification_result: Option<VerificationResult>,
}

// ---------------------------------------------------------------------------
// Migration registry (persistent, ordered list of applied migrations)
// ---------------------------------------------------------------------------

/// Append-only record of a completed migration in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedMigrationRecord {
    pub migration_id: String,
    pub from_version: String,
    pub to_version: String,
    pub cutover_type: CutoverType,
    pub affected_objects: Vec<ObjectClass>,
    pub applied_at: DeterministicTimestamp,
    pub checkpoint_seq: u64,
}

// ---------------------------------------------------------------------------
// MigrationRunner — the orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the multi-step migration process with rollback support.
#[derive(Debug)]
pub struct MigrationRunner {
    migrations: Vec<MigrationEntry>,
    applied: Vec<AppliedMigrationRecord>,
    events: Vec<MigrationEvent>,
    current_tick: u64,
}

impl MigrationRunner {
    pub fn new() -> Self {
        Self {
            migrations: Vec::new(),
            applied: Vec::new(),
            events: Vec::new(),
            current_tick: 0,
        }
    }

    /// Set current logical tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Number of declared migrations.
    pub fn migration_count(&self) -> usize {
        self.migrations.len()
    }

    /// Number of applied (committed) migrations.
    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    /// Applied migration records.
    pub fn applied_migrations(&self) -> &[AppliedMigrationRecord] {
        &self.applied
    }

    /// Get the state of a migration.
    pub fn state(&self, migration_id: &str) -> Option<MigrationState> {
        self.find_entry(migration_id).map(|e| e.state)
    }

    // -- Declare ----------------------------------------------------------

    /// Declare a new migration.
    pub fn declare(
        &mut self,
        declaration: MigrationDeclaration,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        if self.find_entry(&declaration.migration_id).is_some() {
            return Err(MigrationContractError::DuplicateMigration {
                migration_id: declaration.migration_id.clone(),
            });
        }

        let mid = declaration.migration_id.clone();
        self.migrations.push(MigrationEntry {
            declaration,
            state: MigrationState::Declared,
            checkpoint_seq: None,
            started_at: None,
            completed_at: None,
            dry_run_result: None,
            verification_result: None,
        });

        self.push_event(trace_id, "migration_declared", "ok", None, Some(&mid), None);
        Ok(())
    }

    // -- Pre-migration (dry run) ------------------------------------------

    /// Execute a dry run to validate all data can be converted.
    pub fn dry_run(
        &mut self,
        migration_id: &str,
        result: DryRunResult,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Declared {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::DryRunning,
            });
        }

        let passed = result.passed();
        entry.dry_run_result = Some(result.clone());

        if passed {
            entry.state = MigrationState::DryRunPassed;
            let _ = entry;
            self.push_event(
                trace_id,
                "dry_run_complete",
                "pass",
                None,
                Some(migration_id),
                Some(result.total_objects),
            );
        } else {
            entry.state = MigrationState::DryRunFailed;
            let _ = entry;
            self.push_event(
                trace_id,
                "dry_run_complete",
                "fail",
                Some("MC_DRY_RUN_FAILED"),
                Some(migration_id),
                Some(result.unconvertible),
            );
            return Err(MigrationContractError::DryRunFailed {
                migration_id: migration_id.to_string(),
                unconvertible_count: result.unconvertible,
                detail: result.details.join("; "),
            });
        }

        Ok(())
    }

    // -- Checkpoint -------------------------------------------------------

    /// Record the epoch-boundary checkpoint and transition to Executing.
    pub fn create_checkpoint(
        &mut self,
        migration_id: &str,
        checkpoint_seq: u64,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let tick = self.current_tick;
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::DryRunPassed {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Executing,
            });
        }

        entry.state = MigrationState::Executing;
        entry.checkpoint_seq = Some(checkpoint_seq);
        entry.started_at = Some(DeterministicTimestamp(tick));
        let _ = entry;

        self.push_event(
            trace_id,
            "checkpoint_created",
            "ok",
            None,
            Some(migration_id),
            None,
        );
        Ok(())
    }

    // -- Execute ----------------------------------------------------------

    /// Mark execution as complete, transition to Verifying.
    pub fn complete_execution(
        &mut self,
        migration_id: &str,
        affected_count: usize,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Executing {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Verifying,
            });
        }

        entry.state = MigrationState::Verifying;
        let _ = entry;

        self.push_event(
            trace_id,
            "execution_complete",
            "ok",
            None,
            Some(migration_id),
            Some(affected_count),
        );
        Ok(())
    }

    // -- Verify -----------------------------------------------------------

    /// Submit verification result.
    pub fn verify(
        &mut self,
        migration_id: &str,
        result: VerificationResult,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Verifying {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Verified,
            });
        }

        let passed = result.passed();
        entry.verification_result = Some(result.clone());

        if passed {
            entry.state = MigrationState::Verified;
            let _ = entry;
            self.push_event(
                trace_id,
                "verification_complete",
                "pass",
                None,
                Some(migration_id),
                Some(result.objects_checked),
            );
        } else {
            entry.state = MigrationState::VerificationFailed;
            let _ = entry;
            self.push_event(
                trace_id,
                "verification_complete",
                "fail",
                Some("MC_VERIFICATION_FAILED"),
                Some(migration_id),
                Some(result.discrepancies),
            );
            return Err(MigrationContractError::VerificationFailed {
                migration_id: migration_id.to_string(),
                discrepancy_count: result.discrepancies,
                detail: result.details.join("; "),
            });
        }

        Ok(())
    }

    // -- Commit -----------------------------------------------------------

    /// Commit the migration. After this, old format may be rejected
    /// (for hard cutover).
    pub fn commit(
        &mut self,
        migration_id: &str,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let tick = self.current_tick;
        let entry = self.find_entry_mut(migration_id)?;

        if entry.state != MigrationState::Verified {
            return Err(MigrationContractError::InvalidTransition {
                from: entry.state,
                to: MigrationState::Committed,
            });
        }

        entry.state = MigrationState::Committed;
        entry.completed_at = Some(DeterministicTimestamp(tick));

        let record = AppliedMigrationRecord {
            migration_id: entry.declaration.migration_id.clone(),
            from_version: entry.declaration.from_version.clone(),
            to_version: entry.declaration.to_version.clone(),
            cutover_type: entry.declaration.cutover_type,
            affected_objects: entry.declaration.affected_objects.clone(),
            applied_at: DeterministicTimestamp(tick),
            checkpoint_seq: entry.checkpoint_seq.unwrap_or(0),
        };
        let _ = entry;

        self.applied.push(record);
        self.push_event(
            trace_id,
            "migration_committed",
            "ok",
            None,
            Some(migration_id),
            None,
        );
        Ok(())
    }

    // -- Rollback ---------------------------------------------------------

    /// Roll back a migration to its pre-migration state.
    pub fn rollback(
        &mut self,
        migration_id: &str,
        trace_id: &str,
    ) -> Result<(), MigrationContractError> {
        let tick = self.current_tick;
        let entry = self.find_entry_mut(migration_id)?;
        let old_state = entry.state;

        // Can only rollback from non-terminal, non-declared, non-committed states.
        if old_state.is_terminal() || old_state == MigrationState::Declared {
            return Err(MigrationContractError::InvalidTransition {
                from: old_state,
                to: MigrationState::RollingBack,
            });
        }

        entry.state = MigrationState::RollingBack;

        self.push_event(
            trace_id,
            "rollback_started",
            "ok",
            None,
            Some(migration_id),
            None,
        );

        let entry = self.find_entry_mut(migration_id)?;
        entry.state = MigrationState::RolledBack;
        entry.completed_at = Some(DeterministicTimestamp(tick));

        self.push_event(
            trace_id,
            "rollback_complete",
            "ok",
            None,
            Some(migration_id),
            None,
        );
        Ok(())
    }

    // -- Format enforcement -----------------------------------------------

    /// Check if an old-format object should be rejected based on committed
    /// hard-cutover migrations. Returns `Ok(())` if accepted, or an error
    /// if a committed hard cutover rejects the old format.
    pub fn check_format_acceptance(
        &self,
        object_class: ObjectClass,
        format_version: &str,
    ) -> Result<(), MigrationContractError> {
        for record in &self.applied {
            if record.cutover_type == CutoverType::HardCutover
                && record.affected_objects.contains(&object_class)
                && record.from_version == format_version
            {
                return Err(MigrationContractError::OldFormatRejected {
                    migration_id: record.migration_id.clone(),
                    object_class,
                    detail: format!(
                        "hard cutover {} -> {} rejects old format {}",
                        record.from_version, record.to_version, format_version
                    ),
                });
            }
        }
        Ok(())
    }

    /// Check format acceptance for soft migration with transition window.
    pub fn check_soft_migration_window(&self, migration_id: &str) -> Option<bool> {
        let entry = self.find_entry(migration_id)?;
        if entry.declaration.cutover_type != CutoverType::SoftMigration {
            return None;
        }
        if entry.state != MigrationState::Committed {
            return Some(true); // Not committed yet, old format still accepted.
        }
        let end_tick = entry.declaration.transition_end_tick?;
        Some(self.current_tick < end_tick)
    }

    // -- Accessors --------------------------------------------------------

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<MigrationEvent> {
        std::mem::take(&mut self.events)
    }

    /// Accumulated events.
    pub fn events(&self) -> &[MigrationEvent] {
        &self.events
    }

    /// Get the declaration for a migration.
    pub fn declaration(&self, migration_id: &str) -> Option<&MigrationDeclaration> {
        self.find_entry(migration_id).map(|e| &e.declaration)
    }

    /// Summary of all migrations and their states.
    pub fn summary(&self) -> BTreeMap<String, MigrationState> {
        let mut result = BTreeMap::new();
        for entry in &self.migrations {
            result.insert(entry.declaration.migration_id.clone(), entry.state);
        }
        result
    }

    // -- Internal ---------------------------------------------------------

    fn find_entry(&self, migration_id: &str) -> Option<&MigrationEntry> {
        self.migrations
            .iter()
            .find(|e| e.declaration.migration_id == migration_id)
    }

    fn find_entry_mut(
        &mut self,
        migration_id: &str,
    ) -> Result<&mut MigrationEntry, MigrationContractError> {
        self.migrations
            .iter_mut()
            .find(|e| e.declaration.migration_id == migration_id)
            .ok_or_else(|| MigrationContractError::MigrationNotFound {
                migration_id: migration_id.to_string(),
            })
    }

    fn push_event(
        &mut self,
        trace_id: &str,
        event: &str,
        outcome: &str,
        err_code: Option<&str>,
        migration_id: Option<&str>,
        affected_count: Option<usize>,
    ) {
        let (from_ver, to_ver) = migration_id
            .and_then(|mid| self.find_entry(mid))
            .map(|e| {
                (
                    Some(e.declaration.from_version.clone()),
                    Some(e.declaration.to_version.clone()),
                )
            })
            .unwrap_or((None, None));

        self.events.push(MigrationEvent {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: err_code.map(str::to_string),
            migration_id: migration_id.map(str::to_string),
            step: None,
            affected_count,
            from_version: from_ver,
            to_version: to_ver,
            timestamp: DeterministicTimestamp(self.current_tick),
        });
    }
}

impl Default for MigrationRunner {
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

    // -- helpers ----------------------------------------------------------

    fn make_declaration(id: &str, cutover: CutoverType) -> MigrationDeclaration {
        MigrationDeclaration {
            migration_id: id.to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            affected_objects: vec![ObjectClass::SerializationSchema, ObjectClass::KeyFormat],
            cutover_type: cutover,
            description: format!("test migration {id}"),
            compatible_across: vec!["wire_format".to_string()],
            incompatible_across: vec!["storage_format".to_string()],
            transition_end_tick: if cutover == CutoverType::SoftMigration {
                Some(1000)
            } else {
                None
            },
        }
    }

    fn passing_dry_run(mid: &str) -> DryRunResult {
        DryRunResult {
            migration_id: mid.to_string(),
            total_objects: 100,
            convertible: 100,
            unconvertible: 0,
            details: Vec::new(),
        }
    }

    fn failing_dry_run(mid: &str) -> DryRunResult {
        DryRunResult {
            migration_id: mid.to_string(),
            total_objects: 100,
            convertible: 90,
            unconvertible: 10,
            details: vec!["10 objects have incompatible field X".to_string()],
        }
    }

    fn passing_verification(mid: &str) -> VerificationResult {
        VerificationResult {
            migration_id: mid.to_string(),
            objects_checked: 100,
            discrepancies: 0,
            details: Vec::new(),
        }
    }

    fn failing_verification(mid: &str) -> VerificationResult {
        VerificationResult {
            migration_id: mid.to_string(),
            objects_checked: 100,
            discrepancies: 5,
            details: vec!["5 objects failed conformance".to_string()],
        }
    }

    fn run_full_pipeline(runner: &mut MigrationRunner, mid: &str, cutover: CutoverType) {
        runner
            .declare(make_declaration(mid, cutover), "trace-1")
            .unwrap();
        runner
            .dry_run(mid, passing_dry_run(mid), "trace-1")
            .unwrap();
        runner.create_checkpoint(mid, 42, "trace-1").unwrap();
        runner.complete_execution(mid, 100, "trace-1").unwrap();
        runner
            .verify(mid, passing_verification(mid), "trace-1")
            .unwrap();
        runner.commit(mid, "trace-1").unwrap();
    }

    // -- declaration ------------------------------------------------------

    #[test]
    fn declare_migration() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        assert_eq!(runner.migration_count(), 1);
        assert_eq!(runner.state("m-1"), Some(MigrationState::Declared));
    }

    #[test]
    fn reject_duplicate_declaration() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        let err = runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::DuplicateMigration { .. }
        ));
    }

    // -- dry run ----------------------------------------------------------

    #[test]
    fn dry_run_pass() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        assert_eq!(runner.state("m-1"), Some(MigrationState::DryRunPassed));
    }

    #[test]
    fn dry_run_fail() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        let err = runner
            .dry_run("m-1", failing_dry_run("m-1"), "t")
            .unwrap_err();
        assert!(matches!(err, MigrationContractError::DryRunFailed { .. }));
        assert_eq!(runner.state("m-1"), Some(MigrationState::DryRunFailed));
    }

    #[test]
    fn dry_run_requires_declared_state() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        let err = runner
            .dry_run("m-1", passing_dry_run("m-1"), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- checkpoint -------------------------------------------------------

    #[test]
    fn checkpoint_after_dry_run() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 42, "t").unwrap();
        assert_eq!(runner.state("m-1"), Some(MigrationState::Executing));
    }

    #[test]
    fn checkpoint_requires_dry_run_passed() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        let err = runner.create_checkpoint("m-1", 42, "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- execute ----------------------------------------------------------

    #[test]
    fn complete_execution_transitions_to_verifying() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 42, "t").unwrap();
        runner.complete_execution("m-1", 100, "t").unwrap();
        assert_eq!(runner.state("m-1"), Some(MigrationState::Verifying));
    }

    // -- verify -----------------------------------------------------------

    #[test]
    fn verification_pass() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 42, "t").unwrap();
        runner.complete_execution("m-1", 100, "t").unwrap();
        runner
            .verify("m-1", passing_verification("m-1"), "t")
            .unwrap();
        assert_eq!(runner.state("m-1"), Some(MigrationState::Verified));
    }

    #[test]
    fn verification_fail() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 42, "t").unwrap();
        runner.complete_execution("m-1", 100, "t").unwrap();
        let err = runner
            .verify("m-1", failing_verification("m-1"), "t")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::VerificationFailed { .. }
        ));
        assert_eq!(
            runner.state("m-1"),
            Some(MigrationState::VerificationFailed)
        );
    }

    // -- commit -----------------------------------------------------------

    #[test]
    fn commit_migration() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
        assert_eq!(runner.state("m-1"), Some(MigrationState::Committed));
        assert_eq!(runner.applied_count(), 1);
        assert_eq!(runner.applied_migrations()[0].migration_id, "m-1");
    }

    #[test]
    fn commit_requires_verified() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        let err = runner.commit("m-1", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- rollback ---------------------------------------------------------

    #[test]
    fn rollback_from_executing() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 42, "t").unwrap();
        runner.rollback("m-1", "t").unwrap();
        assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
    }

    #[test]
    fn rollback_from_verifying() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 42, "t").unwrap();
        runner.complete_execution("m-1", 100, "t").unwrap();
        runner.rollback("m-1", "t").unwrap();
        assert_eq!(runner.state("m-1"), Some(MigrationState::RolledBack));
    }

    #[test]
    fn rollback_from_declared_fails() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        let err = runner.rollback("m-1", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn rollback_from_committed_fails() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
        let err = runner.rollback("m-1", "t").unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::InvalidTransition { .. }
        ));
    }

    // -- format enforcement -----------------------------------------------

    #[test]
    fn hard_cutover_rejects_old_format() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        let err = runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
            .unwrap_err();
        assert!(matches!(
            err,
            MigrationContractError::OldFormatRejected { .. }
        ));
    }

    #[test]
    fn hard_cutover_accepts_new_format() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v2")
            .unwrap();
    }

    #[test]
    fn hard_cutover_only_rejects_affected_classes() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        // TokenFormat is NOT in affected_objects, so old version should be fine.
        runner
            .check_format_acceptance(ObjectClass::TokenFormat, "v1")
            .unwrap();
    }

    #[test]
    fn soft_migration_does_not_reject_old_format() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);

        // Soft migration doesn't reject old format via check_format_acceptance.
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
            .unwrap();
    }

    // -- soft migration window --------------------------------------------

    #[test]
    fn soft_migration_window_open_before_end() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);

        runner.set_tick(500);
        assert_eq!(runner.check_soft_migration_window("m-1"), Some(true));
    }

    #[test]
    fn soft_migration_window_closed_after_end() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);
        run_full_pipeline(&mut runner, "m-1", CutoverType::SoftMigration);

        runner.set_tick(1000);
        assert_eq!(runner.check_soft_migration_window("m-1"), Some(false));
    }

    // -- events -----------------------------------------------------------

    #[test]
    fn events_emitted_for_full_pipeline() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);

        let events = runner.drain_events();
        assert!(events.len() >= 5); // declare, dry_run, checkpoint, execution, verify, commit

        let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
        assert!(event_names.contains(&"migration_declared"));
        assert!(event_names.contains(&"dry_run_complete"));
        assert!(event_names.contains(&"checkpoint_created"));
        assert!(event_names.contains(&"execution_complete"));
        assert!(event_names.contains(&"verification_complete"));
        assert!(event_names.contains(&"migration_committed"));

        assert!(events.iter().all(|e| e.component == "migration_contract"));
    }

    #[test]
    fn rollback_events_emitted() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 42, "t").unwrap();
        runner.rollback("m-1", "t").unwrap();

        let events = runner.drain_events();
        let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
        assert!(event_names.contains(&"rollback_started"));
        assert!(event_names.contains(&"rollback_complete"));
    }

    // -- migration not found ----------------------------------------------

    #[test]
    fn operations_on_missing_migration_fail() {
        let mut runner = MigrationRunner::new();
        assert!(matches!(
            runner.dry_run("missing", passing_dry_run("missing"), "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
        assert!(matches!(
            runner.create_checkpoint("missing", 42, "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
        assert!(matches!(
            runner.commit("missing", "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
        assert!(matches!(
            runner.rollback("missing", "t"),
            Err(MigrationContractError::MigrationNotFound { .. })
        ));
    }

    // -- summary ----------------------------------------------------------

    #[test]
    fn summary_shows_all_migrations() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        run_full_pipeline(&mut runner, "m-2", CutoverType::SoftMigration);

        let summary = runner.summary();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary["m-1"], MigrationState::Declared);
        assert_eq!(summary["m-2"], MigrationState::Committed);
    }

    // -- serde roundtrips -------------------------------------------------

    #[test]
    fn cutover_type_serde_roundtrip() {
        for ct in [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ] {
            let json = serde_json::to_string(&ct).unwrap();
            let deser: CutoverType = serde_json::from_str(&json).unwrap();
            assert_eq!(ct, deser);
        }
    }

    #[test]
    fn object_class_serde_roundtrip() {
        for oc in ObjectClass::ALL {
            let json = serde_json::to_string(&oc).unwrap();
            let deser: ObjectClass = serde_json::from_str(&json).unwrap();
            assert_eq!(oc, deser);
        }
    }

    #[test]
    fn migration_state_serde_roundtrip() {
        for state in [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let deser: MigrationState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, deser);
        }
    }

    #[test]
    fn migration_declaration_serde_roundtrip() {
        let decl = make_declaration("m-1", CutoverType::HardCutover);
        let json = serde_json::to_string(&decl).unwrap();
        let deser: MigrationDeclaration = serde_json::from_str(&json).unwrap();
        assert_eq!(decl, deser);
    }

    #[test]
    fn migration_event_serde_roundtrip() {
        let event = MigrationEvent {
            trace_id: "t-1".to_string(),
            component: COMPONENT.to_string(),
            event: "migration_declared".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            migration_id: Some("m-1".to_string()),
            step: None,
            affected_count: Some(100),
            from_version: Some("v1".to_string()),
            to_version: Some("v2".to_string()),
            timestamp: DeterministicTimestamp(42),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deser: MigrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deser);
    }

    #[test]
    fn migration_error_serde_roundtrip() {
        let errors = vec![
            MigrationContractError::MigrationNotFound {
                migration_id: "x".to_string(),
            },
            MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            },
            MigrationContractError::DryRunFailed {
                migration_id: "x".to_string(),
                unconvertible_count: 10,
                detail: "d".to_string(),
            },
            MigrationContractError::OldFormatRejected {
                migration_id: "x".to_string(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".to_string(),
            },
            MigrationContractError::DuplicateMigration {
                migration_id: "x".to_string(),
            },
            MigrationContractError::RollbackFailed {
                migration_id: "x".to_string(),
                detail: "d".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(&err).unwrap();
            let deser: MigrationContractError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, deser);
        }
    }

    #[test]
    fn applied_migration_record_serde_roundtrip() {
        let record = AppliedMigrationRecord {
            migration_id: "m-1".to_string(),
            from_version: "v1".to_string(),
            to_version: "v2".to_string(),
            cutover_type: CutoverType::HardCutover,
            affected_objects: vec![ObjectClass::KeyFormat],
            applied_at: DeterministicTimestamp(42),
            checkpoint_seq: 10,
        };
        let json = serde_json::to_string(&record).unwrap();
        let deser: AppliedMigrationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deser);
    }

    // -- display coverage -------------------------------------------------

    #[test]
    fn cutover_type_display() {
        assert_eq!(CutoverType::HardCutover.to_string(), "hard_cutover");
        assert_eq!(CutoverType::SoftMigration.to_string(), "soft_migration");
        assert_eq!(CutoverType::ParallelRun.to_string(), "parallel_run");
    }

    #[test]
    fn object_class_display() {
        assert_eq!(
            ObjectClass::SerializationSchema.to_string(),
            "serialization_schema"
        );
        assert_eq!(ObjectClass::KeyFormat.to_string(), "key_format");
    }

    #[test]
    fn migration_state_display() {
        assert_eq!(MigrationState::Declared.to_string(), "declared");
        assert_eq!(MigrationState::Committed.to_string(), "committed");
        assert_eq!(MigrationState::RolledBack.to_string(), "rolled_back");
    }

    #[test]
    fn migration_step_display() {
        assert_eq!(MigrationStep::PreMigration.to_string(), "pre_migration");
        assert_eq!(MigrationStep::Commit.to_string(), "commit");
    }

    #[test]
    fn migration_state_terminal() {
        assert!(MigrationState::Committed.is_terminal());
        assert!(MigrationState::RolledBack.is_terminal());
        assert!(MigrationState::DryRunFailed.is_terminal());
        assert!(!MigrationState::VerificationFailed.is_terminal());
        assert!(!MigrationState::Declared.is_terminal());
        assert!(!MigrationState::Executing.is_terminal());
    }

    #[test]
    fn migration_step_next() {
        assert_eq!(
            MigrationStep::PreMigration.next(),
            Some(MigrationStep::Checkpoint)
        );
        assert_eq!(
            MigrationStep::Checkpoint.next(),
            Some(MigrationStep::Execute)
        );
        assert_eq!(MigrationStep::Execute.next(), Some(MigrationStep::Verify));
        assert_eq!(MigrationStep::Verify.next(), Some(MigrationStep::Commit));
        assert_eq!(MigrationStep::Commit.next(), None);
        assert_eq!(MigrationStep::Rollback.next(), None);
    }

    #[test]
    fn migration_step_forward_pipeline() {
        assert_eq!(MigrationStep::FORWARD_PIPELINE.len(), 5);
    }

    // -- error codes ------------------------------------------------------

    #[test]
    fn error_codes_stable() {
        assert_eq!(
            error_code(&MigrationContractError::MigrationNotFound {
                migration_id: "x".to_string()
            }),
            "MC_MIGRATION_NOT_FOUND"
        );
        assert_eq!(
            error_code(&MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            }),
            "MC_INVALID_TRANSITION"
        );
        assert_eq!(
            error_code(&MigrationContractError::DryRunFailed {
                migration_id: "x".to_string(),
                unconvertible_count: 5,
                detail: "d".to_string()
            }),
            "MC_DRY_RUN_FAILED"
        );
        assert_eq!(
            error_code(&MigrationContractError::OldFormatRejected {
                migration_id: "x".to_string(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".to_string()
            }),
            "MC_OLD_FORMAT_REJECTED"
        );
        assert_eq!(
            error_code(&MigrationContractError::ParallelRunDiscrepancy {
                migration_id: "x".to_string(),
                discrepancy_count: 3
            }),
            "MC_PARALLEL_DISCREPANCY"
        );
    }

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<MigrationContractError> = vec![
            MigrationContractError::MigrationNotFound {
                migration_id: "x".to_string(),
            },
            MigrationContractError::InvalidTransition {
                from: MigrationState::Declared,
                to: MigrationState::Executing,
            },
            MigrationContractError::DryRunFailed {
                migration_id: "x".to_string(),
                unconvertible_count: 5,
                detail: "d".to_string(),
            },
            MigrationContractError::VerificationFailed {
                migration_id: "x".to_string(),
                discrepancy_count: 3,
                detail: "d".to_string(),
            },
            MigrationContractError::OldFormatRejected {
                migration_id: "x".to_string(),
                object_class: ObjectClass::KeyFormat,
                detail: "d".to_string(),
            },
            MigrationContractError::DuplicateMigration {
                migration_id: "x".to_string(),
            },
            MigrationContractError::RollbackFailed {
                migration_id: "x".to_string(),
                detail: "d".to_string(),
            },
            MigrationContractError::ParallelRunDiscrepancy {
                migration_id: "x".to_string(),
                discrepancy_count: 2,
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    // -- declaration accessor ---------------------------------------------

    #[test]
    fn declaration_accessor() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-1", CutoverType::HardCutover), "t")
            .unwrap();
        let decl = runner.declaration("m-1").unwrap();
        assert_eq!(decl.migration_id, "m-1");
        assert_eq!(decl.cutover_type, CutoverType::HardCutover);
    }

    // -- deterministic replay ---------------------------------------------

    #[test]
    fn full_pipeline_deterministic() {
        let run = || {
            let mut runner = MigrationRunner::new();
            runner.set_tick(0);
            run_full_pipeline(&mut runner, "m-1", CutoverType::HardCutover);
            let events = runner.drain_events();
            serde_json::to_string(&events).unwrap()
        };
        assert_eq!(run(), run());
    }

    // -- multiple migrations in order -------------------------------------

    #[test]
    fn multiple_migrations_applied_in_order() {
        let mut runner = MigrationRunner::new();
        runner.set_tick(0);

        let mut d1 = make_declaration("m-1", CutoverType::HardCutover);
        d1.from_version = "v1".to_string();
        d1.to_version = "v2".to_string();
        runner.declare(d1, "t").unwrap();
        runner.dry_run("m-1", passing_dry_run("m-1"), "t").unwrap();
        runner.create_checkpoint("m-1", 10, "t").unwrap();
        runner.complete_execution("m-1", 50, "t").unwrap();
        runner
            .verify("m-1", passing_verification("m-1"), "t")
            .unwrap();
        runner.commit("m-1", "t").unwrap();

        runner.set_tick(100);
        let mut d2 = make_declaration("m-2", CutoverType::SoftMigration);
        d2.from_version = "v2".to_string();
        d2.to_version = "v3".to_string();
        runner.declare(d2, "t").unwrap();
        runner.dry_run("m-2", passing_dry_run("m-2"), "t").unwrap();
        runner.create_checkpoint("m-2", 20, "t").unwrap();
        runner.complete_execution("m-2", 50, "t").unwrap();
        runner
            .verify("m-2", passing_verification("m-2"), "t")
            .unwrap();
        runner.commit("m-2", "t").unwrap();

        assert_eq!(runner.applied_count(), 2);
        assert_eq!(runner.applied_migrations()[0].from_version, "v1");
        assert_eq!(runner.applied_migrations()[0].to_version, "v2");
        assert_eq!(runner.applied_migrations()[1].from_version, "v2");
        assert_eq!(runner.applied_migrations()[1].to_version, "v3");
    }

    // -- dry run / verification result helpers ----------------------------

    #[test]
    fn dry_run_result_passed() {
        assert!(passing_dry_run("m-1").passed());
        assert!(!failing_dry_run("m-1").passed());
    }

    #[test]
    fn verification_result_passed() {
        assert!(passing_verification("m-1").passed());
        assert!(!failing_verification("m-1").passed());
    }

    // -- object class ALL constant ----------------------------------------

    #[test]
    fn object_class_all_has_eight() {
        assert_eq!(ObjectClass::ALL.len(), 8);
    }

    // -- default -----------------------------------------------------------

    #[test]
    fn runner_default() {
        let runner = MigrationRunner::default();
        assert_eq!(runner.migration_count(), 0);
        assert_eq!(runner.applied_count(), 0);
    }

    // -- Enrichment: Display uniqueness via BTreeSet --------------------

    #[test]
    fn cutover_type_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            CutoverType::HardCutover,
            CutoverType::SoftMigration,
            CutoverType::ParallelRun,
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn migration_state_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            MigrationState::Declared,
            MigrationState::DryRunning,
            MigrationState::DryRunPassed,
            MigrationState::DryRunFailed,
            MigrationState::Executing,
            MigrationState::Verifying,
            MigrationState::Verified,
            MigrationState::VerificationFailed,
            MigrationState::Committed,
            MigrationState::RollingBack,
            MigrationState::RolledBack,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 11);
    }

    // -- Enrichment: std::error::Error impl --------------------------

    #[test]
    fn migration_contract_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(MigrationContractError::MigrationNotFound {
            migration_id: "test".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment: parallel run cutover behavior ------------------

    #[test]
    fn parallel_run_full_pipeline() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-par", CutoverType::ParallelRun);
        assert_eq!(runner.state("m-par"), Some(MigrationState::Committed));
        assert_eq!(runner.applied_count(), 1);
    }

    // -- Enrichment: soft migration window for non-soft cutover -----

    #[test]
    fn soft_migration_window_none_for_hard_cutover() {
        let mut runner = MigrationRunner::new();
        run_full_pipeline(&mut runner, "m-hard", CutoverType::HardCutover);
        // Hard cutover has no transition_end_tick, so window check returns None
        assert_eq!(runner.check_soft_migration_window("m-hard"), None);
    }

    // -- Enrichment: check_format_acceptance for unaffected class ----

    #[test]
    fn format_acceptance_for_unregistered_migration_passes() {
        let runner = MigrationRunner::new();
        // No migrations registered, so any format is accepted
        runner
            .check_format_acceptance(ObjectClass::SerializationSchema, "v1")
            .unwrap();
    }

    // -- Enrichment: MigrationStep ordering -------------------------

    #[test]
    fn migration_step_ordering() {
        assert!(MigrationStep::PreMigration < MigrationStep::Checkpoint);
        assert!(MigrationStep::Checkpoint < MigrationStep::Execute);
        assert!(MigrationStep::Execute < MigrationStep::Verify);
        assert!(MigrationStep::Verify < MigrationStep::Commit);
    }

    // -- Enrichment: rollback after verification failed -------------

    #[test]
    fn rollback_from_verification_failed() {
        let mut runner = MigrationRunner::new();
        runner
            .declare(make_declaration("m-vf", CutoverType::HardCutover), "t")
            .unwrap();
        runner
            .dry_run("m-vf", passing_dry_run("m-vf"), "t")
            .unwrap();
        runner.create_checkpoint("m-vf", 42, "t").unwrap();
        runner.complete_execution("m-vf", 100, "t").unwrap();
        let _ = runner.verify("m-vf", failing_verification("m-vf"), "t");
        assert_eq!(
            runner.state("m-vf"),
            Some(MigrationState::VerificationFailed)
        );
        // VerificationFailed is not terminal — rollback should succeed
        runner.rollback("m-vf", "t").unwrap();
        assert_eq!(runner.state("m-vf"), Some(MigrationState::RollingBack));
    }
}
