//! Deterministic lab runtime harness with virtual time, schedule replay,
//! and cancellation/fault injection.
//!
//! Replaces the production async runtime in test/lab environments for
//! full control over task scheduling, time, and fault injection.
//! Given the same seed and schedule, produces byte-identical event sequences.
//!
//! Plan references: Section 10.11 item 9, 9G.4 (deterministic lab runtime),
//! Top-10 #3 (deterministic evidence graph), #9 (adversarial corpus).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// VirtualClock — deterministic time source
// ---------------------------------------------------------------------------

/// Deterministic virtual clock for lab runtime.
/// Advances only when explicitly stepped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClock {
    /// Current virtual time in ticks.
    now_ticks: u64,
}

impl VirtualClock {
    /// Create a new clock starting at tick 0.
    pub fn new() -> Self {
        Self { now_ticks: 0 }
    }

    /// Current virtual time.
    pub fn now(&self) -> u64 {
        self.now_ticks
    }

    /// Advance by a given number of ticks.
    pub fn advance(&mut self, ticks: u64) {
        self.now_ticks += ticks;
    }

    /// Advance to a specific tick (must be >= current).
    pub fn advance_to(&mut self, tick: u64) -> bool {
        if tick >= self.now_ticks {
            self.now_ticks = tick;
            true
        } else {
            false
        }
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TaskId — deterministic task identifier
// ---------------------------------------------------------------------------

/// Deterministic task identifier.
pub type TaskId = u64;

// ---------------------------------------------------------------------------
// ScheduleAction — actions in a schedule transcript
// ---------------------------------------------------------------------------

/// An action in the deterministic schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleAction {
    /// Execute a task step.
    RunTask { task_id: TaskId },
    /// Advance virtual time.
    AdvanceTime { ticks: u64 },
    /// Inject cancellation for a region.
    InjectCancel { region_id: String },
    /// Inject a task fault (panic/disconnect).
    InjectFault { task_id: TaskId, fault: FaultKind },
    /// Fire a pending timer.
    FireTimer { timer_id: u64 },
}

// ---------------------------------------------------------------------------
// FaultKind — injectable faults
// ---------------------------------------------------------------------------

/// Types of faults that can be injected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// Task panic at next step.
    Panic,
    /// Channel disconnection.
    ChannelDisconnect,
    /// Obligation leak (obligation not resolved).
    ObligationLeak,
    /// Deadline expiration.
    DeadlineExpired,
    /// Region close request.
    RegionClose,
}

impl fmt::Display for FaultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panic => write!(f, "panic"),
            Self::ChannelDisconnect => write!(f, "channel_disconnect"),
            Self::ObligationLeak => write!(f, "obligation_leak"),
            Self::DeadlineExpired => write!(f, "deadline_expired"),
            Self::RegionClose => write!(f, "region_close"),
        }
    }
}

// ---------------------------------------------------------------------------
// ScheduleTranscript — ordered list of schedule actions
// ---------------------------------------------------------------------------

/// Ordered list of schedule actions for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleTranscript {
    pub seed: u64,
    pub actions: Vec<ScheduleAction>,
}

impl ScheduleTranscript {
    /// Create a new transcript with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            actions: Vec::new(),
        }
    }

    /// Append an action.
    pub fn push(&mut self, action: ScheduleAction) {
        self.actions.push(action);
    }

    /// Number of actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether the transcript is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TaskState — state of a lab runtime task
// ---------------------------------------------------------------------------

/// State of a task in the lab runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Ready,
    Running,
    Completed,
    Faulted,
    Cancelled,
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => write!(f, "ready"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Faulted => write!(f, "faulted"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// LabEvent — structured event from lab runtime
// ---------------------------------------------------------------------------

/// Structured event emitted by the lab runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabEvent {
    pub virtual_time: u64,
    pub step_index: u64,
    pub action: String,
    pub task_id: Option<TaskId>,
    pub region_id: Option<String>,
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// Verdict — pass/fail result
// ---------------------------------------------------------------------------

/// Pass/fail verdict for a lab run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail { reason: String },
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reason } => write!(f, "FAIL: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LabRunResult — output artifact bundle
// ---------------------------------------------------------------------------

/// Output artifact bundle from a lab run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabRunResult {
    pub seed: u64,
    pub transcript: ScheduleTranscript,
    pub events: Vec<LabEvent>,
    pub final_time: u64,
    pub tasks_completed: usize,
    pub tasks_faulted: usize,
    pub tasks_cancelled: usize,
    pub verdict: Verdict,
}

// ---------------------------------------------------------------------------
// LabRuntime — deterministic lab runtime harness
// ---------------------------------------------------------------------------

/// Deterministic lab runtime for testing and replay.
#[derive(Debug)]
pub struct LabRuntime {
    clock: VirtualClock,
    seed: u64,
    tasks: BTreeMap<TaskId, TaskState>,
    next_task_id: TaskId,
    /// Regions that have been cancelled.
    cancelled_regions: BTreeMap<String, bool>,
    /// Recorded transcript (for replay).
    transcript: ScheduleTranscript,
    events: Vec<LabEvent>,
    step_index: u64,
}

impl LabRuntime {
    /// Create a new lab runtime with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            clock: VirtualClock::new(),
            seed,
            tasks: BTreeMap::new(),
            next_task_id: 1,
            cancelled_regions: BTreeMap::new(),
            transcript: ScheduleTranscript::new(seed),
            events: Vec::new(),
            step_index: 0,
        }
    }

    /// Current virtual time.
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Register a new task. Returns task ID.
    pub fn spawn_task(&mut self) -> TaskId {
        let id = self.next_task_id;
        self.next_task_id += 1;
        self.tasks.insert(id, TaskState::Ready);
        id
    }

    /// Execute one step of a task.
    pub fn run_task(&mut self, task_id: TaskId) -> Option<TaskState> {
        let state = self.tasks.get_mut(&task_id)?;
        if *state != TaskState::Ready && *state != TaskState::Running {
            return Some(*state);
        }

        *state = TaskState::Running;
        self.transcript.push(ScheduleAction::RunTask { task_id });
        self.emit_event("run_task", Some(task_id), None, "running");
        Some(TaskState::Running)
    }

    /// Complete a task.
    pub fn complete_task(&mut self, task_id: TaskId) -> bool {
        if let Some(state) = self.tasks.get_mut(&task_id)
            && *state == TaskState::Running
        {
            *state = TaskState::Completed;
            self.emit_event("complete_task", Some(task_id), None, "completed");
            return true;
        }
        false
    }

    /// Advance virtual time.
    pub fn advance_time(&mut self, ticks: u64) {
        self.clock.advance(ticks);
        self.transcript.push(ScheduleAction::AdvanceTime { ticks });
        self.emit_event("advance_time", None, None, &format!("ticks={ticks}"));
    }

    /// Inject cancellation for a region.
    pub fn inject_cancel(&mut self, region_id: &str) {
        self.cancelled_regions.insert(region_id.to_string(), true);
        self.transcript.push(ScheduleAction::InjectCancel {
            region_id: region_id.to_string(),
        });
        self.emit_event(
            "inject_cancel",
            None,
            Some(region_id.to_string()),
            "cancel_injected",
        );
    }

    /// Check if a region has been cancelled.
    pub fn is_region_cancelled(&self, region_id: &str) -> bool {
        self.cancelled_regions
            .get(region_id)
            .copied()
            .unwrap_or(false)
    }

    /// Inject a fault on a task.
    pub fn inject_fault(&mut self, task_id: TaskId, fault: FaultKind) -> bool {
        if let Some(state) = self.tasks.get_mut(&task_id) {
            *state = TaskState::Faulted;
            self.transcript.push(ScheduleAction::InjectFault {
                task_id,
                fault: fault.clone(),
            });
            self.emit_event(
                "inject_fault",
                Some(task_id),
                None,
                &format!("fault={fault}"),
            );
            true
        } else {
            false
        }
    }

    /// Cancel a task.
    pub fn cancel_task(&mut self, task_id: TaskId) -> bool {
        if let Some(state) = self.tasks.get_mut(&task_id)
            && *state != TaskState::Completed
            && *state != TaskState::Faulted
        {
            *state = TaskState::Cancelled;
            self.emit_event("cancel_task", Some(task_id), None, "cancelled");
            return true;
        }
        false
    }

    /// Get task state.
    pub fn task_state(&self, task_id: TaskId) -> Option<TaskState> {
        self.tasks.get(&task_id).copied()
    }

    /// Number of registered tasks.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Produce the run result.
    pub fn finalize(self) -> LabRunResult {
        let tasks_completed = self
            .tasks
            .values()
            .filter(|&&s| s == TaskState::Completed)
            .count();
        let tasks_faulted = self
            .tasks
            .values()
            .filter(|&&s| s == TaskState::Faulted)
            .count();
        let tasks_cancelled = self
            .tasks
            .values()
            .filter(|&&s| s == TaskState::Cancelled)
            .count();

        let verdict = if tasks_faulted > 0 {
            Verdict::Fail {
                reason: format!("{tasks_faulted} tasks faulted"),
            }
        } else {
            Verdict::Pass
        };

        LabRunResult {
            seed: self.seed,
            transcript: self.transcript,
            events: self.events,
            final_time: self.clock.now(),
            tasks_completed,
            tasks_faulted,
            tasks_cancelled,
            verdict,
        }
    }

    fn emit_event(
        &mut self,
        action: &str,
        task_id: Option<TaskId>,
        region_id: Option<String>,
        outcome: &str,
    ) {
        self.step_index += 1;
        self.events.push(LabEvent {
            virtual_time: self.clock.now(),
            step_index: self.step_index,
            action: action.to_string(),
            task_id,
            region_id,
            outcome: outcome.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Replay — replay a transcript on a fresh runtime
// ---------------------------------------------------------------------------

/// Replay a transcript on a fresh runtime, producing events for comparison.
pub fn replay_transcript(transcript: &ScheduleTranscript) -> Vec<LabEvent> {
    let mut rt = LabRuntime::new(transcript.seed);

    // Pre-spawn enough tasks to cover all task IDs in the transcript.
    let max_task_id = transcript
        .actions
        .iter()
        .filter_map(|a| match a {
            ScheduleAction::RunTask { task_id } | ScheduleAction::InjectFault { task_id, .. } => {
                Some(*task_id)
            }
            _ => None,
        })
        .max()
        .unwrap_or(0);

    for _ in 0..max_task_id {
        rt.spawn_task();
    }

    for action in &transcript.actions {
        match action {
            ScheduleAction::RunTask { task_id } => {
                rt.run_task(*task_id);
            }
            ScheduleAction::AdvanceTime { ticks } => {
                rt.advance_time(*ticks);
            }
            ScheduleAction::InjectCancel { region_id } => {
                rt.inject_cancel(region_id);
            }
            ScheduleAction::InjectFault { task_id, fault } => {
                rt.inject_fault(*task_id, fault.clone());
            }
            ScheduleAction::FireTimer { timer_id: _ } => {
                // Timer firing is a no-op in the basic harness
            }
        }
    }

    rt.finalize().events
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- VirtualClock --

    #[test]
    fn clock_starts_at_zero() {
        let clock = VirtualClock::new();
        assert_eq!(clock.now(), 0);
    }

    #[test]
    fn clock_advance() {
        let mut clock = VirtualClock::new();
        clock.advance(100);
        assert_eq!(clock.now(), 100);
        clock.advance(50);
        assert_eq!(clock.now(), 150);
    }

    #[test]
    fn clock_advance_to() {
        let mut clock = VirtualClock::new();
        assert!(clock.advance_to(500));
        assert_eq!(clock.now(), 500);
        // Cannot go backward
        assert!(!clock.advance_to(100));
        assert_eq!(clock.now(), 500);
    }

    // -- Task lifecycle --

    #[test]
    fn spawn_and_run_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        assert_eq!(id, 1);
        assert_eq!(rt.task_state(id), Some(TaskState::Ready));

        rt.run_task(id);
        assert_eq!(rt.task_state(id), Some(TaskState::Running));
    }

    #[test]
    fn complete_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        assert!(rt.complete_task(id));
        assert_eq!(rt.task_state(id), Some(TaskState::Completed));
    }

    #[test]
    fn complete_non_running_task_fails() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        assert!(!rt.complete_task(id)); // still Ready, not Running
    }

    #[test]
    fn cancel_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        assert!(rt.cancel_task(id));
        assert_eq!(rt.task_state(id), Some(TaskState::Cancelled));
    }

    #[test]
    fn cannot_cancel_completed_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
        assert!(!rt.cancel_task(id));
    }

    // -- Virtual time --

    #[test]
    fn advance_time_updates_clock() {
        let mut rt = LabRuntime::new(42);
        rt.advance_time(100);
        assert_eq!(rt.now(), 100);
        rt.advance_time(50);
        assert_eq!(rt.now(), 150);
    }

    // -- Cancellation injection --

    #[test]
    fn inject_cancel_marks_region() {
        let mut rt = LabRuntime::new(42);
        assert!(!rt.is_region_cancelled("region-1"));
        rt.inject_cancel("region-1");
        assert!(rt.is_region_cancelled("region-1"));
    }

    // -- Fault injection --

    #[test]
    fn inject_fault_marks_task_faulted() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        assert!(rt.inject_fault(id, FaultKind::Panic));
        assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
    }

    #[test]
    fn inject_fault_nonexistent_returns_false() {
        let mut rt = LabRuntime::new(42);
        assert!(!rt.inject_fault(999, FaultKind::Panic));
    }

    // -- Transcript --

    #[test]
    fn transcript_records_actions() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.advance_time(10);
        rt.inject_cancel("r");

        let result = rt.finalize();
        assert_eq!(result.transcript.len(), 3);
        assert_eq!(result.transcript.seed, 42);
    }

    // -- Deterministic replay --

    #[test]
    fn replay_produces_identical_events() {
        let run = || {
            let mut rt = LabRuntime::new(42);
            let t1 = rt.spawn_task();
            let t2 = rt.spawn_task();
            rt.run_task(t1);
            rt.advance_time(10);
            rt.run_task(t2);
            rt.inject_cancel("region-a");
            rt.complete_task(t1);
            rt.advance_time(5);
            rt.inject_fault(t2, FaultKind::ChannelDisconnect);
            rt.finalize()
        };

        let result1 = run();
        let result2 = run();
        assert_eq!(result1.events, result2.events);
        assert_eq!(result1.transcript, result2.transcript);
    }

    #[test]
    fn replay_transcript_produces_same_events() {
        let mut rt = LabRuntime::new(99);
        let t1 = rt.spawn_task();
        let t2 = rt.spawn_task();
        rt.run_task(t1);
        rt.advance_time(5);
        rt.run_task(t2);
        rt.inject_cancel("r1");
        let result = rt.finalize();

        let replayed_events = replay_transcript(&result.transcript);
        assert_eq!(result.events, replayed_events);
    }

    // -- Finalize / Verdict --

    #[test]
    fn pass_verdict_when_no_faults() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
        let result = rt.finalize();
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.tasks_completed, 1);
    }

    #[test]
    fn fail_verdict_when_faults() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.inject_fault(id, FaultKind::Panic);
        let result = rt.finalize();
        assert!(matches!(result.verdict, Verdict::Fail { .. }));
        assert_eq!(result.tasks_faulted, 1);
    }

    #[test]
    fn cancelled_tasks_counted() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.cancel_task(id);
        let result = rt.finalize();
        assert_eq!(result.tasks_cancelled, 1);
    }

    // -- Events --

    #[test]
    fn events_carry_virtual_time() {
        let mut rt = LabRuntime::new(42);
        rt.advance_time(100);
        let id = rt.spawn_task();
        rt.run_task(id);

        let result = rt.finalize();
        let run_event = result
            .events
            .iter()
            .find(|e| e.action == "run_task")
            .unwrap();
        assert_eq!(run_event.virtual_time, 100);
    }

    #[test]
    fn events_have_monotone_step_index() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.advance_time(10);
        rt.complete_task(id);

        let result = rt.finalize();
        for window in result.events.windows(2) {
            assert!(window[0].step_index < window[1].step_index);
        }
    }

    // -- Serialization --

    #[test]
    fn virtual_clock_serialization_round_trip() {
        let mut clock = VirtualClock::new();
        clock.advance(42);
        let json = serde_json::to_string(&clock).expect("serialize");
        let restored: VirtualClock = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(clock, restored);
    }

    #[test]
    fn schedule_transcript_serialization_round_trip() {
        let mut transcript = ScheduleTranscript::new(42);
        transcript.push(ScheduleAction::RunTask { task_id: 1 });
        transcript.push(ScheduleAction::AdvanceTime { ticks: 10 });
        transcript.push(ScheduleAction::InjectCancel {
            region_id: "r".to_string(),
        });
        let json = serde_json::to_string(&transcript).expect("serialize");
        let restored: ScheduleTranscript = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(transcript, restored);
    }

    #[test]
    fn lab_run_result_serialization_round_trip() {
        let result = LabRunResult {
            seed: 42,
            transcript: ScheduleTranscript::new(42),
            events: Vec::new(),
            final_time: 100,
            tasks_completed: 1,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: LabRunResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn fault_kind_display() {
        assert_eq!(FaultKind::Panic.to_string(), "panic");
        assert_eq!(
            FaultKind::ChannelDisconnect.to_string(),
            "channel_disconnect"
        );
        assert_eq!(FaultKind::ObligationLeak.to_string(), "obligation_leak");
        assert_eq!(FaultKind::DeadlineExpired.to_string(), "deadline_expired");
        assert_eq!(FaultKind::RegionClose.to_string(), "region_close");
    }

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::Pass.to_string(), "PASS");
        assert!(
            Verdict::Fail {
                reason: "boom".to_string()
            }
            .to_string()
            .contains("boom")
        );
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn lab_event_serde_roundtrip() {
        let event = LabEvent {
            virtual_time: 1000,
            step_index: 5,
            action: "spawn".to_string(),
            task_id: Some(42),
            region_id: Some("region-1".to_string()),
            outcome: "ok".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: LabEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn fault_kind_serde_all_variants() {
        for kind in [
            FaultKind::Panic,
            FaultKind::ChannelDisconnect,
            FaultKind::ObligationLeak,
            FaultKind::DeadlineExpired,
            FaultKind::RegionClose,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: FaultKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn nonexistent_task_returns_none() {
        let rt = LabRuntime::new(42);
        assert!(rt.task_state(999).is_none());
    }
}
