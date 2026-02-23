//! Saga orchestrator for multi-step publish/evict/quarantine workflows
//! with deterministic compensation.
//!
//! Multi-step distributed operations (quarantine, revocation, eviction,
//! publish) are modeled as sagas with explicit forward steps and
//! compensating actions. Each step is backed by idempotency keys for
//! retry safety, leases for liveness, and named computations for type
//! safety.
//!
//! When a forward step fails, compensation runs in reverse order for
//! all previously completed steps. Compensation state is persisted so
//! partially-compensated sagas can resume after crashes.
//!
//! Plan references: Section 10.11 item 24, 9G.7 (remote-effects contract),
//! Top-10 #5 (supply-chain trust), #10 (provenance + revocation fabric).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// SagaId — unique saga identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a saga instance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SagaId(String);

impl SagaId {
    /// Create a saga ID from a trace context string.
    pub fn from_trace(trace_id: &str) -> Self {
        Self(trace_id.to_string())
    }

    /// Access the raw string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SagaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "saga:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// SagaType — classification of saga workflows
// ---------------------------------------------------------------------------

/// Type of saga workflow, determining the sequence of steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SagaType {
    /// Suspend extension -> flush evidence -> propagate quarantine -> confirm.
    Quarantine,
    /// Emit revocation -> propagate to peers -> confirm convergence -> update frontier.
    Revocation,
    /// Mark for eviction -> drain active references -> delete artifacts -> confirm cleanup.
    Eviction,
    /// Validate artifact -> stage -> commit -> notify subscribers.
    Publish,
}

impl fmt::Display for SagaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quarantine => f.write_str("quarantine"),
            Self::Revocation => f.write_str("revocation"),
            Self::Eviction => f.write_str("eviction"),
            Self::Publish => f.write_str("publish"),
        }
    }
}

// ---------------------------------------------------------------------------
// SagaState — current state of a saga
// ---------------------------------------------------------------------------

/// Current state of a saga.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaState {
    /// Not yet started.
    Pending,
    /// Executing forward step at the given index.
    InProgress { step_index: usize },
    /// A forward step failed; running compensation in reverse from the given index.
    Compensating { step_index: usize },
    /// All forward steps completed successfully.
    Completed,
    /// Saga failed (all compensations ran or terminal failure).
    Failed { diagnostic: String },
}

impl fmt::Display for SagaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::InProgress { step_index } => write!(f, "in_progress(step={step_index})"),
            Self::Compensating { step_index } => write!(f, "compensating(step={step_index})"),
            Self::Completed => f.write_str("completed"),
            Self::Failed { diagnostic } => write!(f, "failed({diagnostic})"),
        }
    }
}

// ---------------------------------------------------------------------------
// StepOutcome — result of executing a saga step
// ---------------------------------------------------------------------------

/// Result of executing a single saga step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepOutcome {
    /// Step completed successfully with a result value.
    Success { result: String },
    /// Step failed with a diagnostic message.
    Failure { diagnostic: String },
    /// Step was cancelled (e.g., lease expired).
    Cancelled { reason: String },
}

impl fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success { result } => write!(f, "success({result})"),
            Self::Failure { diagnostic } => write!(f, "failure({diagnostic})"),
            Self::Cancelled { reason } => write!(f, "cancelled({reason})"),
        }
    }
}

// ---------------------------------------------------------------------------
// SagaStep — a single step in a saga
// ---------------------------------------------------------------------------

/// A single step in a saga with forward and compensating actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaStep {
    /// Name of this step (maps to a named computation).
    pub step_name: String,
    /// Name of the forward action computation.
    pub forward_action: String,
    /// Name of the compensating action computation.
    pub compensating_action: String,
    /// Maximum ticks for step completion.
    pub timeout_ticks: u64,
}

// ---------------------------------------------------------------------------
// StepRecord — persisted state for a completed step
// ---------------------------------------------------------------------------

/// Persisted record of a step that has been executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    /// Step index.
    pub step_index: usize,
    /// Step name.
    pub step_name: String,
    /// Whether this was a forward or compensating execution.
    pub action_type: ActionType,
    /// Outcome of the execution.
    pub outcome: StepOutcome,
    /// Tick at which the step completed.
    pub completed_at: u64,
    /// Idempotency key hex used for this step.
    pub idempotency_key_hex: String,
}

/// Whether an action is a forward step or a compensation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Forward,
    Compensate,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward => f.write_str("forward"),
            Self::Compensate => f.write_str("compensate"),
        }
    }
}

// ---------------------------------------------------------------------------
// Saga — the full saga record
// ---------------------------------------------------------------------------

/// A saga: an ordered sequence of steps with compensation semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saga {
    /// Unique saga identifier.
    pub saga_id: SagaId,
    /// Type of saga workflow.
    pub saga_type: SagaType,
    /// Ordered list of steps.
    pub steps: Vec<SagaStep>,
    /// Current state.
    pub state: SagaState,
    /// Epoch in which the saga was created.
    pub epoch: SecurityEpoch,
    /// Trace identifier for observability.
    pub trace_id: String,
    /// Persisted step execution records.
    pub step_records: Vec<StepRecord>,
    /// Tick at which the saga was created.
    pub created_at: u64,
}

impl Saga {
    /// Check if the saga is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, SagaState::Completed | SagaState::Failed { .. })
    }

    /// Get the index of the highest successfully completed forward step.
    pub fn last_completed_forward_step(&self) -> Option<usize> {
        self.step_records
            .iter()
            .filter(|r| {
                r.action_type == ActionType::Forward
                    && matches!(r.outcome, StepOutcome::Success { .. })
            })
            .map(|r| r.step_index)
            .max()
    }
}

// ---------------------------------------------------------------------------
// SagaEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for saga state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaEvent {
    /// Saga identifier.
    pub saga_id: String,
    /// Saga type.
    pub saga_type: String,
    /// Step name.
    pub step_name: String,
    /// Step index.
    pub step_index: usize,
    /// Forward or compensate.
    pub action: String,
    /// Result of the step.
    pub result: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Epoch at time of event.
    pub epoch_id: u64,
    /// Event type.
    pub event: String,
}

// ---------------------------------------------------------------------------
// SagaError — typed errors
// ---------------------------------------------------------------------------

/// Errors from saga operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaError {
    /// Saga not found.
    SagaNotFound { saga_id: String },
    /// Saga is already in a terminal state.
    SagaAlreadyTerminal { saga_id: String, state: String },
    /// Step index out of bounds.
    StepIndexOutOfBounds {
        saga_id: String,
        step_index: usize,
        step_count: usize,
    },
    /// Epoch mismatch.
    EpochMismatch {
        saga_id: String,
        saga_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    /// No steps defined.
    EmptySteps,
    /// Invalid saga ID.
    InvalidSagaId { reason: String },
    /// Compensation failed.
    CompensationFailed {
        saga_id: String,
        step_index: usize,
        diagnostic: String,
    },
}

impl fmt::Display for SagaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SagaNotFound { saga_id } => write!(f, "saga {saga_id} not found"),
            Self::SagaAlreadyTerminal { saga_id, state } => {
                write!(f, "saga {saga_id} already terminal ({state})")
            }
            Self::StepIndexOutOfBounds {
                saga_id,
                step_index,
                step_count,
            } => {
                write!(
                    f,
                    "saga {saga_id} step {step_index} out of bounds ({step_count} steps)"
                )
            }
            Self::EpochMismatch {
                saga_id,
                saga_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "saga {saga_id} epoch mismatch: saga at {saga_epoch}, current {current_epoch}"
                )
            }
            Self::EmptySteps => f.write_str("saga must have at least one step"),
            Self::InvalidSagaId { reason } => write!(f, "invalid saga ID: {reason}"),
            Self::CompensationFailed {
                saga_id,
                step_index,
                diagnostic,
            } => {
                write!(
                    f,
                    "saga {saga_id} compensation failed at step {step_index}: {diagnostic}"
                )
            }
        }
    }
}

impl std::error::Error for SagaError {}

// ---------------------------------------------------------------------------
// SagaOrchestrator — the saga execution engine
// ---------------------------------------------------------------------------

/// Orchestrator that manages saga lifecycle: creation, step execution,
/// failure detection, compensation, and crash recovery.
#[derive(Debug)]
pub struct SagaOrchestrator {
    /// Current security epoch.
    current_epoch: SecurityEpoch,
    /// Active sagas by ID.
    sagas: BTreeMap<String, Saga>,
    /// Maximum concurrent sagas (bulkhead).
    max_concurrent: usize,
    /// Accumulated audit events.
    events: Vec<SagaEvent>,
    /// Event counters.
    event_counts: BTreeMap<String, u64>,
}

impl SagaOrchestrator {
    /// Create a new saga orchestrator.
    pub fn new(epoch: SecurityEpoch, max_concurrent: usize) -> Self {
        Self {
            current_epoch: epoch,
            sagas: BTreeMap::new(),
            max_concurrent,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Current epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Number of active (non-terminal) sagas.
    pub fn active_count(&self) -> usize {
        self.sagas.values().filter(|s| !s.is_terminal()).count()
    }

    /// Total number of tracked sagas.
    pub fn total_count(&self) -> usize {
        self.sagas.len()
    }

    /// Create a new saga.
    pub fn create_saga(
        &mut self,
        saga_id: &str,
        saga_type: SagaType,
        steps: Vec<SagaStep>,
        trace_id: &str,
        current_ticks: u64,
    ) -> Result<SagaId, SagaError> {
        if saga_id.is_empty() {
            return Err(SagaError::InvalidSagaId {
                reason: "empty saga ID".to_string(),
            });
        }
        if steps.is_empty() {
            return Err(SagaError::EmptySteps);
        }
        if self.active_count() >= self.max_concurrent {
            return Err(SagaError::SagaAlreadyTerminal {
                saga_id: saga_id.to_string(),
                state: format!("concurrency limit reached ({})", self.max_concurrent),
            });
        }

        let id = SagaId::from_trace(saga_id);
        let saga = Saga {
            saga_id: id.clone(),
            saga_type,
            steps,
            state: SagaState::Pending,
            epoch: self.current_epoch,
            trace_id: trace_id.to_string(),
            step_records: Vec::new(),
            created_at: current_ticks,
        };

        self.emit_event(SagaEvent {
            saga_id: saga_id.to_string(),
            saga_type: saga_type.to_string(),
            step_name: String::new(),
            step_index: 0,
            action: "create".to_string(),
            result: "pending".to_string(),
            trace_id: trace_id.to_string(),
            epoch_id: self.current_epoch.as_u64(),
            event: "saga_created".to_string(),
        });
        self.record_count("saga_created");

        self.sagas.insert(saga_id.to_string(), saga);
        Ok(id)
    }

    /// Begin executing the next forward step of a saga.
    ///
    /// Returns the step index and step definition to execute.
    pub fn begin_step(&mut self, saga_id: &str) -> Result<(usize, SagaStep), SagaError> {
        let saga = self.sagas.get_mut(saga_id).ok_or(SagaError::SagaNotFound {
            saga_id: saga_id.to_string(),
        })?;

        if saga.is_terminal() {
            return Err(SagaError::SagaAlreadyTerminal {
                saga_id: saga_id.to_string(),
                state: saga.state.to_string(),
            });
        }

        // Epoch check.
        if saga.epoch != self.current_epoch {
            return Err(SagaError::EpochMismatch {
                saga_id: saga_id.to_string(),
                saga_epoch: saga.epoch,
                current_epoch: self.current_epoch,
            });
        }

        let step_index = match &saga.state {
            SagaState::Pending => 0,
            SagaState::InProgress { step_index } => *step_index,
            SagaState::Compensating { .. } | SagaState::Completed | SagaState::Failed { .. } => {
                return Err(SagaError::SagaAlreadyTerminal {
                    saga_id: saga_id.to_string(),
                    state: saga.state.to_string(),
                });
            }
        };

        if step_index >= saga.steps.len() {
            return Err(SagaError::StepIndexOutOfBounds {
                saga_id: saga_id.to_string(),
                step_index,
                step_count: saga.steps.len(),
            });
        }

        let step = saga.steps[step_index].clone();
        saga.state = SagaState::InProgress { step_index };

        // Extract for event.
        let saga_type_str = saga.saga_type.to_string();
        let trace_id = saga.trace_id.clone();
        let step_name = step.step_name.clone();

        self.emit_event(SagaEvent {
            saga_id: saga_id.to_string(),
            saga_type: saga_type_str,
            step_name,
            step_index,
            action: "forward".to_string(),
            result: "begin".to_string(),
            trace_id,
            epoch_id: self.current_epoch.as_u64(),
            event: "step_begin".to_string(),
        });
        self.record_count("step_begin");

        Ok((step_index, step))
    }

    /// Record the outcome of a forward step.
    ///
    /// On success, advances to the next step (or completes the saga).
    /// On failure, transitions to compensating state.
    pub fn complete_step(
        &mut self,
        saga_id: &str,
        step_index: usize,
        outcome: StepOutcome,
        idempotency_key_hex: &str,
        current_ticks: u64,
    ) -> Result<SagaState, SagaError> {
        let saga = self.sagas.get_mut(saga_id).ok_or(SagaError::SagaNotFound {
            saga_id: saga_id.to_string(),
        })?;

        if step_index >= saga.steps.len() {
            return Err(SagaError::StepIndexOutOfBounds {
                saga_id: saga_id.to_string(),
                step_index,
                step_count: saga.steps.len(),
            });
        }

        // Idempotency check.
        if saga.step_records.iter().any(|r| {
            r.action_type == ActionType::Forward
                && r.step_index == step_index
                && r.idempotency_key_hex == idempotency_key_hex
        }) {
            return Ok(saga.state.clone());
        }

        // Validate state
        match saga.state {
            SagaState::InProgress {
                step_index: current_step,
            } if current_step == step_index => {}
            _ => {
                return Err(SagaError::SagaAlreadyTerminal {
                    saga_id: saga_id.to_string(),
                    state: saga.state.to_string(),
                });
            }
        }

        let step_name = saga.steps[step_index].step_name.clone();

        saga.step_records.push(StepRecord {
            step_index,
            step_name: step_name.clone(),
            action_type: ActionType::Forward,
            outcome: outcome.clone(),
            completed_at: current_ticks,
            idempotency_key_hex: idempotency_key_hex.to_string(),
        });

        let new_state = match &outcome {
            StepOutcome::Success { .. } => {
                if step_index + 1 >= saga.steps.len() {
                    SagaState::Completed
                } else {
                    SagaState::InProgress {
                        step_index: step_index + 1,
                    }
                }
            }
            StepOutcome::Failure { .. } | StepOutcome::Cancelled { .. } => {
                if step_index == 0 {
                    // Nothing to compensate.
                    SagaState::Failed {
                        diagnostic: outcome.to_string(),
                    }
                } else {
                    SagaState::Compensating {
                        step_index: step_index - 1,
                    }
                }
            }
        };

        saga.state = new_state.clone();

        // Extract for event.
        let saga_type_str = saga.saga_type.to_string();
        let trace_id = saga.trace_id.clone();

        self.emit_event(SagaEvent {
            saga_id: saga_id.to_string(),
            saga_type: saga_type_str,
            step_name,
            step_index,
            action: "forward".to_string(),
            result: outcome.to_string(),
            trace_id,
            epoch_id: self.current_epoch.as_u64(),
            event: "step_complete".to_string(),
        });
        self.record_count("step_complete");

        Ok(new_state)
    }

    /// Get the next compensation step to execute.
    ///
    /// Returns None if compensation is complete or not in compensating state.
    pub fn next_compensation_step(
        &self,
        saga_id: &str,
    ) -> Result<Option<(usize, SagaStep)>, SagaError> {
        let saga = self.sagas.get(saga_id).ok_or(SagaError::SagaNotFound {
            saga_id: saga_id.to_string(),
        })?;

        match &saga.state {
            SagaState::Compensating { step_index } => {
                let step = saga.steps[*step_index].clone();
                Ok(Some((*step_index, step)))
            }
            _ => Ok(None),
        }
    }

    /// Record the outcome of a compensation step.
    ///
    /// Advances compensation to the previous step, or completes with failure.
    pub fn complete_compensation(
        &mut self,
        saga_id: &str,
        step_index: usize,
        outcome: StepOutcome,
        idempotency_key_hex: &str,
        current_ticks: u64,
    ) -> Result<SagaState, SagaError> {
        let saga = self.sagas.get_mut(saga_id).ok_or(SagaError::SagaNotFound {
            saga_id: saga_id.to_string(),
        })?;

        if step_index >= saga.steps.len() {
            return Err(SagaError::StepIndexOutOfBounds {
                saga_id: saga_id.to_string(),
                step_index,
                step_count: saga.steps.len(),
            });
        }

        // Idempotency check.
        if saga.step_records.iter().any(|r| {
            r.action_type == ActionType::Compensate
                && r.step_index == step_index
                && r.idempotency_key_hex == idempotency_key_hex
        }) {
            return Ok(saga.state.clone());
        }

        // Validate state
        match saga.state {
            SagaState::Compensating {
                step_index: current_step,
            } if current_step == step_index => {}
            _ => {
                return Err(SagaError::SagaAlreadyTerminal {
                    saga_id: saga_id.to_string(),
                    state: saga.state.to_string(),
                });
            }
        }

        let step_name = saga.steps[step_index].step_name.clone();

        saga.step_records.push(StepRecord {
            step_index,
            step_name: step_name.clone(),
            action_type: ActionType::Compensate,
            outcome: outcome.clone(),
            completed_at: current_ticks,
            idempotency_key_hex: idempotency_key_hex.to_string(),
        });

        let new_state = match &outcome {
            StepOutcome::Success { .. } => {
                if step_index == 0 {
                    // All compensations complete.
                    SagaState::Failed {
                        diagnostic: "compensated".to_string(),
                    }
                } else {
                    SagaState::Compensating {
                        step_index: step_index - 1,
                    }
                }
            }
            StepOutcome::Failure { diagnostic } => {
                // Compensation itself failed — terminal failure.
                SagaState::Failed {
                    diagnostic: format!("compensation_failed at step {step_index}: {diagnostic}"),
                }
            }
            StepOutcome::Cancelled { reason } => SagaState::Failed {
                diagnostic: format!("compensation_cancelled at step {step_index}: {reason}"),
            },
        };

        saga.state = new_state.clone();

        // Extract for event.
        let saga_type_str = saga.saga_type.to_string();
        let trace_id = saga.trace_id.clone();

        self.emit_event(SagaEvent {
            saga_id: saga_id.to_string(),
            saga_type: saga_type_str,
            step_name,
            step_index,
            action: "compensate".to_string(),
            result: outcome.to_string(),
            trace_id,
            epoch_id: self.current_epoch.as_u64(),
            event: "compensation_complete".to_string(),
        });
        self.record_count("compensation_complete");

        Ok(new_state)
    }

    /// Look up a saga by ID.
    pub fn get(&self, saga_id: &str) -> Option<&Saga> {
        self.sagas.get(saga_id)
    }

    /// Advance to a new epoch. Sagas from old epochs are failed.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch, trace_id: &str) -> Vec<String> {
        let mut invalidated = Vec::new();
        let mut pending_events = Vec::new();

        for (id, saga) in &mut self.sagas {
            if !saga.is_terminal() && saga.epoch != new_epoch {
                saga.state = SagaState::Failed {
                    diagnostic: format!(
                        "epoch_invalidated: saga epoch {}, new epoch {}",
                        saga.epoch, new_epoch
                    ),
                };

                pending_events.push(SagaEvent {
                    saga_id: id.clone(),
                    saga_type: saga.saga_type.to_string(),
                    step_name: String::new(),
                    step_index: 0,
                    action: "epoch_invalidation".to_string(),
                    result: "failed".to_string(),
                    trace_id: trace_id.to_string(),
                    epoch_id: new_epoch.as_u64(),
                    event: "saga_epoch_invalidated".to_string(),
                });

                invalidated.push(id.clone());
            }
        }

        for event in pending_events {
            self.emit_event(event);
            self.record_count("saga_epoch_invalidated");
        }

        self.current_epoch = new_epoch;
        invalidated
    }

    /// Find all sagas in a non-terminal state that can be resumed.
    pub fn resumable_sagas(&self) -> Vec<&Saga> {
        self.sagas.values().filter(|s| !s.is_terminal()).collect()
    }

    /// Remove terminal sagas older than the given tick.
    pub fn gc_terminal(&mut self, older_than_ticks: u64) -> usize {
        let to_remove: Vec<String> = self
            .sagas
            .iter()
            .filter(|(_, s)| s.is_terminal() && s.created_at < older_than_ticks)
            .map(|(id, _)| id.clone())
            .collect();
        let count = to_remove.len();
        for id in to_remove {
            self.sagas.remove(&id);
        }
        count
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<SagaEvent> {
        std::mem::take(&mut self.events)
    }

    /// Per-event-type counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn emit_event(&mut self, event: SagaEvent) {
        self.events.push(event);
    }

    fn record_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// Builder helpers for common saga types
// ---------------------------------------------------------------------------

/// Build a quarantine saga: suspend -> flush_evidence -> propagate -> confirm.
pub fn quarantine_saga_steps(target: &str) -> Vec<SagaStep> {
    vec![
        SagaStep {
            step_name: format!("suspend_{target}"),
            forward_action: "extension.suspend".to_string(),
            compensating_action: "extension.resume".to_string(),
            timeout_ticks: 1000,
        },
        SagaStep {
            step_name: format!("flush_evidence_{target}"),
            forward_action: "evidence.flush".to_string(),
            compensating_action: "evidence.rollback_flush".to_string(),
            timeout_ticks: 2000,
        },
        SagaStep {
            step_name: format!("propagate_quarantine_{target}"),
            forward_action: "quarantine.propagate".to_string(),
            compensating_action: "quarantine.retract".to_string(),
            timeout_ticks: 5000,
        },
        SagaStep {
            step_name: format!("confirm_quarantine_{target}"),
            forward_action: "quarantine.confirm".to_string(),
            compensating_action: "quarantine.unconfirm".to_string(),
            timeout_ticks: 1000,
        },
    ]
}

/// Build a revocation saga: emit -> propagate -> confirm_convergence -> update_frontier.
pub fn revocation_saga_steps(target: &str) -> Vec<SagaStep> {
    vec![
        SagaStep {
            step_name: format!("emit_revocation_{target}"),
            forward_action: "revocation.emit".to_string(),
            compensating_action: "revocation.retract".to_string(),
            timeout_ticks: 1000,
        },
        SagaStep {
            step_name: format!("propagate_revocation_{target}"),
            forward_action: "revocation.propagate".to_string(),
            compensating_action: "revocation.retract_propagation".to_string(),
            timeout_ticks: 5000,
        },
        SagaStep {
            step_name: format!("confirm_convergence_{target}"),
            forward_action: "revocation.confirm_convergence".to_string(),
            compensating_action: "revocation.rollback_convergence".to_string(),
            timeout_ticks: 3000,
        },
        SagaStep {
            step_name: format!("update_frontier_{target}"),
            forward_action: "revocation.update_frontier".to_string(),
            compensating_action: "revocation.rollback_frontier".to_string(),
            timeout_ticks: 1000,
        },
    ]
}

/// Build an eviction saga: mark -> drain -> delete -> confirm_cleanup.
pub fn eviction_saga_steps(target: &str) -> Vec<SagaStep> {
    vec![
        SagaStep {
            step_name: format!("mark_eviction_{target}"),
            forward_action: "eviction.mark".to_string(),
            compensating_action: "eviction.unmark".to_string(),
            timeout_ticks: 500,
        },
        SagaStep {
            step_name: format!("drain_references_{target}"),
            forward_action: "eviction.drain".to_string(),
            compensating_action: "eviction.restore_references".to_string(),
            timeout_ticks: 3000,
        },
        SagaStep {
            step_name: format!("delete_artifacts_{target}"),
            forward_action: "eviction.delete".to_string(),
            compensating_action: "eviction.restore_artifacts".to_string(),
            timeout_ticks: 2000,
        },
        SagaStep {
            step_name: format!("confirm_cleanup_{target}"),
            forward_action: "eviction.confirm".to_string(),
            compensating_action: "eviction.rollback_confirm".to_string(),
            timeout_ticks: 500,
        },
    ]
}

/// Build a publish saga: validate -> stage -> commit -> notify.
pub fn publish_saga_steps(artifact: &str) -> Vec<SagaStep> {
    vec![
        SagaStep {
            step_name: format!("validate_{artifact}"),
            forward_action: "publish.validate".to_string(),
            compensating_action: "publish.invalidate".to_string(),
            timeout_ticks: 1000,
        },
        SagaStep {
            step_name: format!("stage_{artifact}"),
            forward_action: "publish.stage".to_string(),
            compensating_action: "publish.unstage".to_string(),
            timeout_ticks: 2000,
        },
        SagaStep {
            step_name: format!("commit_{artifact}"),
            forward_action: "publish.commit".to_string(),
            compensating_action: "publish.rollback".to_string(),
            timeout_ticks: 1000,
        },
        SagaStep {
            step_name: format!("notify_{artifact}"),
            forward_action: "publish.notify".to_string(),
            compensating_action: "publish.retract_notification".to_string(),
            timeout_ticks: 3000,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn simple_steps() -> Vec<SagaStep> {
        vec![
            SagaStep {
                step_name: "step_a".to_string(),
                forward_action: "do_a".to_string(),
                compensating_action: "undo_a".to_string(),
                timeout_ticks: 100,
            },
            SagaStep {
                step_name: "step_b".to_string(),
                forward_action: "do_b".to_string(),
                compensating_action: "undo_b".to_string(),
                timeout_ticks: 200,
            },
            SagaStep {
                step_name: "step_c".to_string(),
                forward_action: "do_c".to_string(),
                compensating_action: "undo_c".to_string(),
                timeout_ticks: 100,
            },
        ]
    }

    // -- SagaId --

    #[test]
    fn saga_id_display() {
        let id = SagaId::from_trace("trace-42");
        assert_eq!(id.to_string(), "saga:trace-42");
        assert_eq!(id.as_str(), "trace-42");
    }

    // -- SagaType --

    #[test]
    fn saga_type_display() {
        assert_eq!(SagaType::Quarantine.to_string(), "quarantine");
        assert_eq!(SagaType::Revocation.to_string(), "revocation");
        assert_eq!(SagaType::Eviction.to_string(), "eviction");
        assert_eq!(SagaType::Publish.to_string(), "publish");
    }

    // -- SagaState --

    #[test]
    fn saga_state_display() {
        assert_eq!(SagaState::Pending.to_string(), "pending");
        assert_eq!(
            SagaState::InProgress { step_index: 2 }.to_string(),
            "in_progress(step=2)"
        );
        assert_eq!(
            SagaState::Compensating { step_index: 1 }.to_string(),
            "compensating(step=1)"
        );
        assert_eq!(SagaState::Completed.to_string(), "completed");
        assert_eq!(
            SagaState::Failed {
                diagnostic: "oops".to_string()
            }
            .to_string(),
            "failed(oops)"
        );
    }

    // -- Create saga --

    #[test]
    fn create_saga() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        let id = orch
            .create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();
        assert_eq!(id.as_str(), "s1");
        assert_eq!(orch.active_count(), 1);
        assert_eq!(orch.total_count(), 1);

        let saga = orch.get("s1").unwrap();
        assert_eq!(saga.state, SagaState::Pending);
        assert_eq!(saga.steps.len(), 3);
    }

    #[test]
    fn create_rejects_empty_id() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        assert!(matches!(
            orch.create_saga("", SagaType::Publish, simple_steps(), "t", 0),
            Err(SagaError::InvalidSagaId { .. })
        ));
    }

    #[test]
    fn create_rejects_empty_steps() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        assert!(matches!(
            orch.create_saga("s1", SagaType::Publish, vec![], "t", 0),
            Err(SagaError::EmptySteps)
        ));
    }

    #[test]
    fn create_respects_concurrency_limit() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 2);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();
        orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
            .unwrap();
        assert!(
            orch.create_saga("s3", SagaType::Eviction, simple_steps(), "t3", 0)
                .is_err()
        );
    }

    // -- Forward step execution --

    #[test]
    fn begin_step_returns_first_step() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();

        let (idx, step) = orch.begin_step("s1").unwrap();
        assert_eq!(idx, 0);
        assert_eq!(step.step_name, "step_a");
    }

    #[test]
    fn complete_step_success_advances() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();
        orch.begin_step("s1").unwrap();

        let state = orch
            .complete_step(
                "s1",
                0,
                StepOutcome::Success {
                    result: "ok".to_string(),
                },
                "key-0",
                100,
            )
            .unwrap();
        assert_eq!(state, SagaState::InProgress { step_index: 1 });
    }

    #[test]
    fn complete_all_steps_completes_saga() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();

        for i in 0..3 {
            orch.begin_step("s1").unwrap();
            orch.complete_step(
                "s1",
                i,
                StepOutcome::Success {
                    result: format!("ok-{i}"),
                },
                &format!("key-{i}"),
                (i as u64 + 1) * 100,
            )
            .unwrap();
        }

        let saga = orch.get("s1").unwrap();
        assert_eq!(saga.state, SagaState::Completed);
        assert!(saga.is_terminal());
        assert_eq!(saga.step_records.len(), 3);
    }

    // -- Failure triggers compensation --

    #[test]
    fn failure_at_step_1_triggers_compensation_at_step_0() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();

        // Step 0 succeeds.
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();

        // Step 1 fails.
        orch.begin_step("s1").unwrap();
        let state = orch
            .complete_step(
                "s1",
                1,
                StepOutcome::Failure {
                    diagnostic: "network_error".to_string(),
                },
                "key-1",
                200,
            )
            .unwrap();
        assert_eq!(state, SagaState::Compensating { step_index: 0 });
    }

    #[test]
    fn failure_at_step_0_goes_directly_to_failed() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();

        orch.begin_step("s1").unwrap();
        let state = orch
            .complete_step(
                "s1",
                0,
                StepOutcome::Failure {
                    diagnostic: "crash".to_string(),
                },
                "key-0",
                100,
            )
            .unwrap();
        assert!(matches!(state, SagaState::Failed { .. }));
    }

    // -- Compensation execution --

    #[test]
    fn compensation_runs_in_reverse() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();

        // Steps 0, 1 succeed.
        for i in 0..2 {
            orch.begin_step("s1").unwrap();
            orch.complete_step(
                "s1",
                i,
                StepOutcome::Success {
                    result: "ok".to_string(),
                },
                &format!("key-{i}"),
                (i as u64 + 1) * 100,
            )
            .unwrap();
        }

        // Step 2 fails.
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            2,
            StepOutcome::Failure {
                diagnostic: "timeout".to_string(),
            },
            "key-2",
            300,
        )
        .unwrap();

        // Compensation should start at step 1 (reverse from last completed).
        let (idx, step) = orch.next_compensation_step("s1").unwrap().unwrap();
        assert_eq!(idx, 1);
        assert_eq!(step.compensating_action, "undo_b");

        // Compensate step 1.
        let state = orch
            .complete_compensation(
                "s1",
                1,
                StepOutcome::Success {
                    result: "undone_b".to_string(),
                },
                "comp-key-1",
                400,
            )
            .unwrap();
        assert_eq!(state, SagaState::Compensating { step_index: 0 });

        // Compensate step 0.
        let state = orch
            .complete_compensation(
                "s1",
                0,
                StepOutcome::Success {
                    result: "undone_a".to_string(),
                },
                "comp-key-0",
                500,
            )
            .unwrap();
        assert!(matches!(state, SagaState::Failed { .. }));

        let saga = orch.get("s1").unwrap();
        assert!(saga.is_terminal());
        // 2 forward + 1 failed forward + 2 compensation = 5 records
        assert_eq!(saga.step_records.len(), 5);
    }

    #[test]
    fn compensation_failure_is_terminal() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();

        // Step 0 succeeds, step 1 fails.
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();

        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            1,
            StepOutcome::Failure {
                diagnostic: "err".to_string(),
            },
            "key-1",
            200,
        )
        .unwrap();

        // Compensation at step 0 also fails.
        let state = orch
            .complete_compensation(
                "s1",
                0,
                StepOutcome::Failure {
                    diagnostic: "comp_crash".to_string(),
                },
                "comp-key-0",
                300,
            )
            .unwrap();
        assert!(
            matches!(state, SagaState::Failed { diagnostic } if diagnostic.contains("compensation_failed"))
        );
    }

    // -- Epoch binding --

    #[test]
    fn epoch_advance_invalidates_active_sagas() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();
        orch.begin_step("s1").unwrap();

        let invalidated = orch.advance_epoch(SecurityEpoch::from_raw(2), "t-epoch");
        assert_eq!(invalidated.len(), 1);
        assert_eq!(invalidated[0], "s1");

        let saga = orch.get("s1").unwrap();
        assert!(saga.is_terminal());
    }

    #[test]
    fn begin_step_rejects_old_epoch_saga() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();

        orch.current_epoch = SecurityEpoch::from_raw(2);
        let err = orch.begin_step("s1").unwrap_err();
        assert!(matches!(err, SagaError::EpochMismatch { .. }));
    }

    // -- Resumable sagas --

    #[test]
    fn resumable_sagas_filters_terminal() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();
        orch.create_saga("s2", SagaType::Revocation, simple_steps(), "t2", 0)
            .unwrap();

        // Complete s1.
        for i in 0..3 {
            orch.begin_step("s1").unwrap();
            orch.complete_step(
                "s1",
                i,
                StepOutcome::Success {
                    result: "ok".to_string(),
                },
                &format!("key-{i}"),
                (i as u64 + 1) * 100,
            )
            .unwrap();
        }

        let resumable = orch.resumable_sagas();
        assert_eq!(resumable.len(), 1);
        assert_eq!(resumable[0].saga_id.as_str(), "s2");
    }

    // -- GC terminal --

    #[test]
    fn gc_removes_old_terminal_sagas() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 100)
            .unwrap();
        // Complete it.
        for i in 0..3 {
            orch.begin_step("s1").unwrap();
            orch.complete_step(
                "s1",
                i,
                StepOutcome::Success {
                    result: "ok".to_string(),
                },
                &format!("key-{i}"),
                200,
            )
            .unwrap();
        }

        assert_eq!(orch.total_count(), 1);
        let removed = orch.gc_terminal(200);
        assert_eq!(removed, 1);
        assert_eq!(orch.total_count(), 0);
    }

    #[test]
    fn gc_preserves_active_sagas() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 100)
            .unwrap();

        let removed = orch.gc_terminal(200);
        assert_eq!(removed, 0);
        assert_eq!(orch.total_count(), 1);
    }

    // -- Audit events --

    #[test]
    fn create_emits_event() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();

        let events = orch.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "saga_created");
        assert_eq!(events[0].saga_type, "quarantine");
    }

    #[test]
    fn step_begin_and_complete_emit_events() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();
        orch.drain_events();

        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();

        let events = orch.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "step_begin");
        assert_eq!(events[0].step_name, "step_a");
        assert_eq!(events[1].event, "step_complete");
        assert_eq!(events[1].action, "forward");
    }

    #[test]
    fn compensation_emits_events() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
            .unwrap();

        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            1,
            StepOutcome::Failure {
                diagnostic: "err".to_string(),
            },
            "key-1",
            200,
        )
        .unwrap();
        orch.drain_events();

        orch.complete_compensation(
            "s1",
            0,
            StepOutcome::Success {
                result: "undone".to_string(),
            },
            "comp-key-0",
            300,
        )
        .unwrap();

        let events = orch.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "compensation_complete");
        assert_eq!(events[0].action, "compensate");
    }

    #[test]
    fn event_counts_track() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();
        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();

        assert_eq!(orch.event_counts().get("saga_created"), Some(&1));
        assert_eq!(orch.event_counts().get("step_begin"), Some(&1));
        assert_eq!(orch.event_counts().get("step_complete"), Some(&1));
    }

    // -- Builder helpers --

    #[test]
    fn quarantine_saga_has_four_steps() {
        let steps = quarantine_saga_steps("ext-1");
        assert_eq!(steps.len(), 4);
        assert!(steps[0].step_name.contains("suspend"));
        assert!(steps[1].step_name.contains("flush_evidence"));
        assert!(steps[2].step_name.contains("propagate_quarantine"));
        assert!(steps[3].step_name.contains("confirm_quarantine"));
    }

    #[test]
    fn revocation_saga_has_four_steps() {
        let steps = revocation_saga_steps("key-1");
        assert_eq!(steps.len(), 4);
        assert!(steps[0].step_name.contains("emit_revocation"));
        assert!(steps[3].step_name.contains("update_frontier"));
    }

    #[test]
    fn eviction_saga_has_four_steps() {
        let steps = eviction_saga_steps("artifact-1");
        assert_eq!(steps.len(), 4);
        assert!(steps[0].step_name.contains("mark_eviction"));
        assert!(steps[2].step_name.contains("delete_artifacts"));
    }

    #[test]
    fn publish_saga_has_four_steps() {
        let steps = publish_saga_steps("pkg-1");
        assert_eq!(steps.len(), 4);
        assert!(steps[0].step_name.contains("validate"));
        assert!(steps[2].step_name.contains("commit"));
    }

    // -- Serialization round-trips --

    #[test]
    fn saga_id_serialization_round_trip() {
        let id = SagaId::from_trace("test-123");
        let json = serde_json::to_string(&id).expect("serialize");
        let restored: SagaId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, restored);
    }

    #[test]
    fn saga_state_serialization_round_trip() {
        let states = vec![
            SagaState::Pending,
            SagaState::InProgress { step_index: 2 },
            SagaState::Compensating { step_index: 1 },
            SagaState::Completed,
            SagaState::Failed {
                diagnostic: "test".to_string(),
            },
        ];
        for state in &states {
            let json = serde_json::to_string(state).expect("serialize");
            let restored: SagaState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, restored);
        }
    }

    #[test]
    fn saga_step_serialization_round_trip() {
        let step = SagaStep {
            step_name: "step_a".to_string(),
            forward_action: "do_a".to_string(),
            compensating_action: "undo_a".to_string(),
            timeout_ticks: 100,
        };
        let json = serde_json::to_string(&step).expect("serialize");
        let restored: SagaStep = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(step, restored);
    }

    #[test]
    fn saga_event_serialization_round_trip() {
        let event = SagaEvent {
            saga_id: "s1".to_string(),
            saga_type: "quarantine".to_string(),
            step_name: "step_a".to_string(),
            step_index: 0,
            action: "forward".to_string(),
            result: "success(ok)".to_string(),
            trace_id: "t1".to_string(),
            epoch_id: 1,
            event: "step_complete".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: SagaEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn saga_error_serialization_round_trip() {
        let errors = vec![
            SagaError::SagaNotFound {
                saga_id: "s1".to_string(),
            },
            SagaError::EmptySteps,
            SagaError::InvalidSagaId {
                reason: "empty".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: SagaError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn step_outcome_serialization_round_trip() {
        let outcomes = vec![
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            StepOutcome::Failure {
                diagnostic: "err".to_string(),
            },
            StepOutcome::Cancelled {
                reason: "timeout".to_string(),
            },
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).expect("serialize");
            let restored: StepOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*o, restored);
        }
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert!(
            SagaError::EmptySteps
                .to_string()
                .contains("at least one step")
        );
        assert!(
            SagaError::SagaNotFound {
                saga_id: "x".to_string()
            }
            .to_string()
            .contains("x")
        );
        assert!(
            SagaError::InvalidSagaId {
                reason: "empty".to_string()
            }
            .to_string()
            .contains("empty")
        );
    }

    // -- last_completed_forward_step --

    #[test]
    fn last_completed_forward_step_tracking() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        orch.create_saga("s1", SagaType::Publish, simple_steps(), "t1", 0)
            .unwrap();

        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            0,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-0",
            100,
        )
        .unwrap();

        let saga = orch.get("s1").unwrap();
        assert_eq!(saga.last_completed_forward_step(), Some(0));

        orch.begin_step("s1").unwrap();
        orch.complete_step(
            "s1",
            1,
            StepOutcome::Success {
                result: "ok".to_string(),
            },
            "key-1",
            200,
        )
        .unwrap();

        let saga = orch.get("s1").unwrap();
        assert_eq!(saga.last_completed_forward_step(), Some(1));
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<SagaEvent> {
            let mut orch = SagaOrchestrator::new(SecurityEpoch::from_raw(1), 10);
            orch.create_saga("s1", SagaType::Quarantine, simple_steps(), "t1", 0)
                .unwrap();
            orch.begin_step("s1").unwrap();
            orch.complete_step(
                "s1",
                0,
                StepOutcome::Success {
                    result: "ok".to_string(),
                },
                "key-0",
                100,
            )
            .unwrap();
            orch.begin_step("s1").unwrap();
            orch.complete_step(
                "s1",
                1,
                StepOutcome::Failure {
                    diagnostic: "err".to_string(),
                },
                "key-1",
                200,
            )
            .unwrap();
            orch.complete_compensation(
                "s1",
                0,
                StepOutcome::Success {
                    result: "undone".to_string(),
                },
                "comp-key-0",
                300,
            )
            .unwrap();
            orch.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- Full lifecycle --

    #[test]
    fn full_lifecycle_success() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        let steps = quarantine_saga_steps("ext-malicious");
        orch.create_saga("q1", SagaType::Quarantine, steps, "trace-q1", 0)
            .unwrap();

        for i in 0..4 {
            orch.begin_step("q1").unwrap();
            orch.complete_step(
                "q1",
                i,
                StepOutcome::Success {
                    result: format!("done-{i}"),
                },
                &format!("idem-{i}"),
                (i as u64 + 1) * 100,
            )
            .unwrap();
        }

        let saga = orch.get("q1").unwrap();
        assert_eq!(saga.state, SagaState::Completed);
        assert_eq!(saga.step_records.len(), 4);
        assert_eq!(orch.active_count(), 0);
    }

    #[test]
    fn full_lifecycle_failure_and_compensation() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        let steps = publish_saga_steps("pkg-1");
        orch.create_saga("p1", SagaType::Publish, steps, "trace-p1", 0)
            .unwrap();

        // Steps 0, 1 succeed.
        for i in 0..2 {
            orch.begin_step("p1").unwrap();
            orch.complete_step(
                "p1",
                i,
                StepOutcome::Success {
                    result: format!("ok-{i}"),
                },
                &format!("idem-{i}"),
                (i as u64 + 1) * 100,
            )
            .unwrap();
        }

        // Step 2 fails (commit fails).
        orch.begin_step("p1").unwrap();
        orch.complete_step(
            "p1",
            2,
            StepOutcome::Failure {
                diagnostic: "commit_rejected".to_string(),
            },
            "idem-2",
            300,
        )
        .unwrap();

        // Compensate in reverse: step 1, then step 0.
        for i in (0..2).rev() {
            let (comp_idx, _step) = orch.next_compensation_step("p1").unwrap().unwrap();
            assert_eq!(comp_idx, i);
            orch.complete_compensation(
                "p1",
                i,
                StepOutcome::Success {
                    result: format!("undone-{i}"),
                },
                &format!("comp-idem-{i}"),
                (4 + i as u64) * 100,
            )
            .unwrap();
        }

        let saga = orch.get("p1").unwrap();
        assert!(saga.is_terminal());
        // 2 success + 1 fail + 2 compensations = 5 records
        assert_eq!(saga.step_records.len(), 5);
    }

    // -- Nonexistent saga --

    #[test]
    fn operations_on_nonexistent_saga() {
        let mut orch = SagaOrchestrator::new(test_epoch(), 10);
        assert!(matches!(
            orch.begin_step("ghost"),
            Err(SagaError::SagaNotFound { .. })
        ));
        assert!(matches!(
            orch.complete_step(
                "ghost",
                0,
                StepOutcome::Success {
                    result: "ok".to_string()
                },
                "k",
                0
            ),
            Err(SagaError::SagaNotFound { .. })
        ));
    }
}
