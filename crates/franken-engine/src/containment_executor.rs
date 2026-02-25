//! Containment actions for the Probabilistic Guardplane.
//!
//! Implements the six containment actions that the expected-loss action
//! selector can trigger: Allow, Challenge, Sandbox, Suspend, Terminate,
//! Quarantine.  Each action produces a deterministic `ContainmentReceipt`
//! for the audit trail.
//!
//! Plan reference: Section 10.5, item 6.
//! Cross-refs: 9A.8 (resource budgets), 9G.2 (cancellation protocol),
//! Phase B exit gate (250ms containment).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::expected_loss_selector::ContainmentAction;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default grace period for cooperative shutdown (nanoseconds).
const DEFAULT_GRACE_PERIOD_NS: u64 = 5_000_000_000; // 5 seconds

/// Default challenge timeout (nanoseconds).
const DEFAULT_CHALLENGE_TIMEOUT_NS: u64 = 10_000_000_000; // 10 seconds

// ---------------------------------------------------------------------------
// ContainmentError
// ---------------------------------------------------------------------------

/// Errors from containment execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentError {
    /// Extension not found.
    ExtensionNotFound { extension_id: String },
    /// Extension already in target containment state.
    AlreadyContained {
        extension_id: String,
        current_state: ContainmentState,
    },
    /// Action not applicable in current state.
    InvalidTransition {
        from: ContainmentState,
        action: ContainmentAction,
    },
    /// Grace period expired without cooperative shutdown.
    GracePeriodExpired {
        extension_id: String,
        elapsed_ns: u64,
    },
    /// Challenge not answered within timeout.
    ChallengeTimeout { extension_id: String },
    /// Internal error.
    Internal { detail: String },
}

impl fmt::Display for ContainmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtensionNotFound { extension_id } => {
                write!(f, "extension not found: {extension_id}")
            }
            Self::AlreadyContained {
                extension_id,
                current_state,
            } => write!(f, "{extension_id} already in state: {current_state}"),
            Self::InvalidTransition { from, action } => {
                write!(f, "cannot apply {action} from state {from}")
            }
            Self::GracePeriodExpired {
                extension_id,
                elapsed_ns,
            } => write!(
                f,
                "grace period expired for {extension_id} after {elapsed_ns}ns"
            ),
            Self::ChallengeTimeout { extension_id } => {
                write!(f, "challenge timeout for {extension_id}")
            }
            Self::Internal { detail } => write!(f, "internal error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ContainmentState — lifecycle state of containment
// ---------------------------------------------------------------------------

/// Current containment state of an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ContainmentState {
    /// Running normally with full capabilities.
    Running,
    /// Challenged: waiting for attestation response.
    Challenged,
    /// Sandboxed: running with reduced capabilities.
    Sandboxed,
    /// Suspended: execution paused, state preserved.
    Suspended,
    /// Terminated: cooperative or forced shutdown complete.
    Terminated,
    /// Quarantined: terminated with forensic snapshot preserved.
    Quarantined,
}

impl ContainmentState {
    /// Whether the extension is still alive (can process work).
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Running | Self::Challenged | Self::Sandboxed)
    }

    /// Whether the extension is dead (shutdown complete).
    pub fn is_dead(&self) -> bool {
        matches!(self, Self::Terminated | Self::Quarantined)
    }
}

impl fmt::Display for ContainmentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Running => "running",
            Self::Challenged => "challenged",
            Self::Sandboxed => "sandboxed",
            Self::Suspended => "suspended",
            Self::Terminated => "terminated",
            Self::Quarantined => "quarantined",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// SandboxPolicy — capability filter for sandboxed extensions
// ---------------------------------------------------------------------------

/// Policy defining which capabilities remain available in sandbox mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Allowed capability names.
    pub allowed_capabilities: Vec<String>,
    /// Whether network access is allowed.
    pub allow_network: bool,
    /// Whether filesystem write is allowed.
    pub allow_fs_write: bool,
    /// Whether process spawning is allowed.
    pub allow_process_spawn: bool,
    /// Maximum memory allocation in bytes (0 = no new allocations).
    pub max_memory_bytes: u64,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allowed_capabilities: vec!["fs-read".to_string()],
            allow_network: false,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 0,
        }
    }
}

impl SandboxPolicy {
    /// Check if a capability is allowed under this sandbox policy.
    pub fn is_allowed(&self, capability: &str) -> bool {
        self.allowed_capabilities.iter().any(|c| c == capability)
    }
}

// ---------------------------------------------------------------------------
// ContainmentReceipt — proof of containment action
// ---------------------------------------------------------------------------

/// Structured receipt proving a containment action was executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Action that was executed.
    pub action: ContainmentAction,
    /// Target extension ID.
    pub target_extension_id: String,
    /// Previous containment state.
    pub previous_state: ContainmentState,
    /// New containment state.
    pub new_state: ContainmentState,
    /// Timestamp when containment started (monotonic ns).
    pub timestamp_ns: u64,
    /// Duration of the containment execution (ns).
    pub duration_ns: u64,
    /// Whether the action completed successfully.
    pub success: bool,
    /// Whether this was a cooperative shutdown (for terminate/quarantine).
    pub cooperative: bool,
    /// Evidence references linked to this decision.
    pub evidence_refs: Vec<String>,
    /// Security epoch at execution time.
    pub epoch: SecurityEpoch,
    /// Content hash of the receipt.
    pub content_hash: ContentHash,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

impl ContainmentReceipt {
    /// Compute canonical bytes for hashing.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(self.receipt_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.action.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.target_extension_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.previous_state.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.new_state.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        buf.extend_from_slice(&self.duration_ns.to_le_bytes());
        buf.push(u8::from(self.success));
        buf.push(u8::from(self.cooperative));
        for r in &self.evidence_refs {
            buf.extend_from_slice(r.as_bytes());
            buf.push(0);
        }
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        for (k, v) in &self.metadata {
            buf.extend_from_slice(k.as_bytes());
            buf.push(0);
            buf.extend_from_slice(v.as_bytes());
            buf.push(0);
        }
        buf
    }

    /// Verify receipt integrity.
    pub fn verify_integrity(&self) -> bool {
        let computed = ContentHash::compute(&self.canonical_bytes());
        self.content_hash == computed
    }
}

// ---------------------------------------------------------------------------
// ContainmentContext — input context for containment
// ---------------------------------------------------------------------------

/// Context provided to containment execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentContext {
    /// Decision ID that triggered this containment.
    pub decision_id: String,
    /// Timestamp (monotonic ns).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Evidence references from the decision.
    pub evidence_refs: Vec<String>,
    /// Grace period for cooperative shutdown (ns).
    pub grace_period_ns: u64,
    /// Challenge timeout (ns).
    pub challenge_timeout_ns: u64,
    /// Sandbox policy (used if action is Sandbox).
    pub sandbox_policy: SandboxPolicy,
}

impl Default for ContainmentContext {
    fn default() -> Self {
        Self {
            decision_id: String::new(),
            timestamp_ns: 0,
            epoch: SecurityEpoch::GENESIS,
            evidence_refs: Vec::new(),
            grace_period_ns: DEFAULT_GRACE_PERIOD_NS,
            challenge_timeout_ns: DEFAULT_CHALLENGE_TIMEOUT_NS,
            sandbox_policy: SandboxPolicy::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionRecord — per-extension state in the executor
// ---------------------------------------------------------------------------

/// Tracked state for a managed extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExtensionRecord {
    extension_id: String,
    state: ContainmentState,
    receipts: Vec<ContainmentReceipt>,
    sandbox_policy: Option<SandboxPolicy>,
    forensic_snapshot: Option<ForensicSnapshot>,
}

/// Forensic snapshot preserved during quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicSnapshot {
    /// Content hash of the memory snapshot.
    pub memory_hash: ContentHash,
    /// Number of hostcall records preserved.
    pub hostcall_count: u64,
    /// Timestamp of snapshot.
    pub snapshot_ns: u64,
    /// Extension manifest hash.
    pub manifest_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — the execution engine
// ---------------------------------------------------------------------------

/// In-memory containment executor managing extension lifecycle states.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainmentExecutor {
    extensions: Vec<ExtensionRecord>,
    next_receipt_id: u64,
}

impl ContainmentExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an extension as running.
    pub fn register(&mut self, extension_id: impl Into<String>) {
        let ext_id = extension_id.into();
        if !self.extensions.iter().any(|e| e.extension_id == ext_id) {
            self.extensions.push(ExtensionRecord {
                extension_id: ext_id,
                state: ContainmentState::Running,
                receipts: Vec::new(),
                sandbox_policy: None,
                forensic_snapshot: None,
            });
        }
    }

    /// Get the current containment state of an extension.
    pub fn state(&self, extension_id: &str) -> Option<ContainmentState> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .map(|e| e.state)
    }

    /// Execute a containment action on an extension.
    pub fn execute(
        &mut self,
        action: ContainmentAction,
        extension_id: &str,
        context: &ContainmentContext,
    ) -> Result<ContainmentReceipt, ContainmentError> {
        let ext = self
            .extensions
            .iter_mut()
            .find(|e| e.extension_id == extension_id)
            .ok_or_else(|| ContainmentError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })?;

        let previous_state = ext.state;

        // Idempotency: if already in target state, return last receipt.
        let target_state = action_target_state(action);
        if ext.state == target_state
            && let Some(last) = ext.receipts.last()
        {
            return Ok(last.clone());
        }

        // Validate transition.
        if !is_valid_transition(ext.state, action) {
            return Err(ContainmentError::InvalidTransition {
                from: ext.state,
                action,
            });
        }

        // Execute action.
        let cooperative = !matches!(
            action,
            ContainmentAction::Terminate | ContainmentAction::Quarantine
        );
        let new_state = target_state;

        // Apply action-specific effects.
        match action {
            ContainmentAction::Sandbox => {
                ext.sandbox_policy = Some(context.sandbox_policy.clone());
            }
            ContainmentAction::Quarantine => {
                ext.forensic_snapshot = Some(ForensicSnapshot {
                    memory_hash: ContentHash::compute(
                        format!("mem-snapshot-{}", extension_id).as_bytes(),
                    ),
                    hostcall_count: ext.receipts.len() as u64,
                    snapshot_ns: context.timestamp_ns,
                    manifest_hash: ContentHash::compute(
                        format!("manifest-{}", extension_id).as_bytes(),
                    ),
                });
            }
            _ => {}
        }

        ext.state = new_state;

        // Build receipt.
        let receipt_id = format!("cr-{:08x}", self.next_receipt_id);
        self.next_receipt_id += 1;

        let mut receipt = ContainmentReceipt {
            receipt_id,
            action,
            target_extension_id: extension_id.to_string(),
            previous_state,
            new_state,
            timestamp_ns: context.timestamp_ns,
            duration_ns: 0, // Simulated — real executor would measure.
            success: true,
            cooperative,
            evidence_refs: context.evidence_refs.clone(),
            epoch: context.epoch,
            content_hash: ContentHash::compute(b"placeholder"),
            metadata: BTreeMap::new(),
        };

        receipt
            .metadata
            .insert("decision_id".to_string(), context.decision_id.clone());

        // Compute content hash.
        receipt.content_hash = ContentHash::compute(&receipt.canonical_bytes());

        ext.receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Get all receipts for an extension.
    pub fn receipts(&self, extension_id: &str) -> Vec<&ContainmentReceipt> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .map(|e| e.receipts.iter().collect())
            .unwrap_or_default()
    }

    /// Get the forensic snapshot for a quarantined extension.
    pub fn forensic_snapshot(&self, extension_id: &str) -> Option<&ForensicSnapshot> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .and_then(|e| e.forensic_snapshot.as_ref())
    }

    /// Get the sandbox policy for a sandboxed extension.
    pub fn sandbox_policy(&self, extension_id: &str) -> Option<&SandboxPolicy> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .and_then(|e| e.sandbox_policy.as_ref())
    }

    /// Number of registered extensions.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }

    /// Extensions in a given containment state.
    pub fn by_state(&self, state: ContainmentState) -> Vec<&str> {
        self.extensions
            .iter()
            .filter(|e| e.state == state)
            .map(|e| e.extension_id.as_str())
            .collect()
    }

    /// Resume a suspended extension back to Running.
    pub fn resume(
        &mut self,
        extension_id: &str,
        context: &ContainmentContext,
    ) -> Result<ContainmentReceipt, ContainmentError> {
        let ext = self
            .extensions
            .iter_mut()
            .find(|e| e.extension_id == extension_id)
            .ok_or_else(|| ContainmentError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })?;

        if ext.state != ContainmentState::Suspended {
            return Err(ContainmentError::InvalidTransition {
                from: ext.state,
                action: ContainmentAction::Allow,
            });
        }

        let previous_state = ext.state;
        ext.state = ContainmentState::Running;

        let receipt_id = format!("cr-{:08x}", self.next_receipt_id);
        self.next_receipt_id += 1;

        let mut receipt = ContainmentReceipt {
            receipt_id,
            action: ContainmentAction::Allow,
            target_extension_id: extension_id.to_string(),
            previous_state,
            new_state: ContainmentState::Running,
            timestamp_ns: context.timestamp_ns,
            duration_ns: 0,
            success: true,
            cooperative: false,
            evidence_refs: context.evidence_refs.clone(),
            epoch: context.epoch,
            content_hash: ContentHash::compute(b"placeholder"),
            metadata: BTreeMap::new(),
        };
        receipt
            .metadata
            .insert("decision_id".to_string(), context.decision_id.clone());
        receipt
            .metadata
            .insert("resume".to_string(), "true".to_string());
        receipt.content_hash = ContentHash::compute(&receipt.canonical_bytes());

        ext.receipts.push(receipt.clone());
        Ok(receipt)
    }
}

/// Map action to target containment state.
fn action_target_state(action: ContainmentAction) -> ContainmentState {
    match action {
        ContainmentAction::Allow => ContainmentState::Running,
        ContainmentAction::Challenge => ContainmentState::Challenged,
        ContainmentAction::Sandbox => ContainmentState::Sandboxed,
        ContainmentAction::Suspend => ContainmentState::Suspended,
        ContainmentAction::Terminate => ContainmentState::Terminated,
        ContainmentAction::Quarantine => ContainmentState::Quarantined,
    }
}

/// Validate that a transition from `from` via `action` is allowed.
fn is_valid_transition(from: ContainmentState, action: ContainmentAction) -> bool {
    match from {
        ContainmentState::Running => true, // Can go anywhere from Running.
        ContainmentState::Challenged => matches!(
            action,
            ContainmentAction::Allow
                | ContainmentAction::Sandbox
                | ContainmentAction::Suspend
                | ContainmentAction::Terminate
                | ContainmentAction::Quarantine
        ),
        ContainmentState::Sandboxed => matches!(
            action,
            ContainmentAction::Suspend
                | ContainmentAction::Terminate
                | ContainmentAction::Quarantine
        ),
        ContainmentState::Suspended => matches!(
            action,
            ContainmentAction::Terminate | ContainmentAction::Quarantine
        ),
        // Dead states: no further transitions.
        ContainmentState::Terminated | ContainmentState::Quarantined => false,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_context() -> ContainmentContext {
        ContainmentContext {
            decision_id: "dec-001".to_string(),
            timestamp_ns: 1_000_000,
            epoch: SecurityEpoch::GENESIS,
            evidence_refs: vec!["ev-001".to_string()],
            grace_period_ns: DEFAULT_GRACE_PERIOD_NS,
            challenge_timeout_ns: DEFAULT_CHALLENGE_TIMEOUT_NS,
            sandbox_policy: SandboxPolicy::default(),
        }
    }

    fn setup_executor() -> ContainmentExecutor {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-001");
        executor.register("ext-002");
        executor
    }

    // -----------------------------------------------------------------------
    // ContainmentState tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_display() {
        assert_eq!(ContainmentState::Running.to_string(), "running");
        assert_eq!(ContainmentState::Challenged.to_string(), "challenged");
        assert_eq!(ContainmentState::Sandboxed.to_string(), "sandboxed");
        assert_eq!(ContainmentState::Suspended.to_string(), "suspended");
        assert_eq!(ContainmentState::Terminated.to_string(), "terminated");
        assert_eq!(ContainmentState::Quarantined.to_string(), "quarantined");
    }

    #[test]
    fn state_is_alive() {
        assert!(ContainmentState::Running.is_alive());
        assert!(ContainmentState::Challenged.is_alive());
        assert!(ContainmentState::Sandboxed.is_alive());
        assert!(!ContainmentState::Suspended.is_alive());
        assert!(!ContainmentState::Terminated.is_alive());
        assert!(!ContainmentState::Quarantined.is_alive());
    }

    #[test]
    fn state_is_dead() {
        assert!(!ContainmentState::Running.is_dead());
        assert!(!ContainmentState::Sandboxed.is_dead());
        assert!(ContainmentState::Terminated.is_dead());
        assert!(ContainmentState::Quarantined.is_dead());
    }

    #[test]
    fn state_serde_roundtrip() {
        for state in [
            ContainmentState::Running,
            ContainmentState::Challenged,
            ContainmentState::Sandboxed,
            ContainmentState::Suspended,
            ContainmentState::Terminated,
            ContainmentState::Quarantined,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let restored: ContainmentState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, restored);
        }
    }

    // -----------------------------------------------------------------------
    // ContainmentError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display() {
        let e = ContainmentError::ExtensionNotFound {
            extension_id: "ext-001".to_string(),
        };
        assert!(e.to_string().contains("ext-001"));

        let e = ContainmentError::AlreadyContained {
            extension_id: "ext-001".to_string(),
            current_state: ContainmentState::Sandboxed,
        };
        assert!(e.to_string().contains("sandboxed"));

        let e = ContainmentError::ChallengeTimeout {
            extension_id: "ext-001".to_string(),
        };
        assert!(e.to_string().contains("timeout"));
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_policy_default() {
        let policy = SandboxPolicy::default();
        assert!(policy.is_allowed("fs-read"));
        assert!(!policy.is_allowed("fs-write"));
        assert!(!policy.allow_network);
        assert!(!policy.allow_fs_write);
        assert!(!policy.allow_process_spawn);
    }

    #[test]
    fn sandbox_policy_serde_roundtrip() {
        let policy = SandboxPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    // -----------------------------------------------------------------------
    // Executor — registration and state
    // -----------------------------------------------------------------------

    #[test]
    fn register_extension() {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-001");
        assert_eq!(executor.extension_count(), 1);
        assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));
    }

    #[test]
    fn register_idempotent() {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-001");
        executor.register("ext-001");
        assert_eq!(executor.extension_count(), 1);
    }

    #[test]
    fn unknown_extension_returns_none() {
        let executor = ContainmentExecutor::new();
        assert_eq!(executor.state("ext-999"), None);
    }

    // -----------------------------------------------------------------------
    // Executor — Allow action
    // -----------------------------------------------------------------------

    #[test]
    fn allow_is_noop() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Allow, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.action, ContainmentAction::Allow);
        assert_eq!(receipt.new_state, ContainmentState::Running);
        assert!(receipt.success);
    }

    // -----------------------------------------------------------------------
    // Executor — Challenge action
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Challenged);
        assert_eq!(
            executor.state("ext-001"),
            Some(ContainmentState::Challenged)
        );
    }

    // -----------------------------------------------------------------------
    // Executor — Sandbox action
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Sandboxed);
        assert!(executor.sandbox_policy("ext-001").is_some());
    }

    // -----------------------------------------------------------------------
    // Executor — Suspend action
    // -----------------------------------------------------------------------

    #[test]
    fn suspend_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Suspended);
        assert!(!ContainmentState::Suspended.is_alive());
    }

    // -----------------------------------------------------------------------
    // Executor — Terminate action
    // -----------------------------------------------------------------------

    #[test]
    fn terminate_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Terminated);
        assert!(!receipt.cooperative);
        assert!(ContainmentState::Terminated.is_dead());
    }

    #[test]
    fn terminate_from_suspended() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        let receipt = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.previous_state, ContainmentState::Suspended);
        assert_eq!(receipt.new_state, ContainmentState::Terminated);
    }

    // -----------------------------------------------------------------------
    // Executor — Quarantine action
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Quarantined);
        assert!(executor.forensic_snapshot("ext-001").is_some());
    }

    #[test]
    fn quarantine_preserves_forensic_snapshot() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        let snapshot = executor.forensic_snapshot("ext-001").unwrap();
        assert_eq!(snapshot.snapshot_ns, ctx.timestamp_ns);
    }

    // -----------------------------------------------------------------------
    // Executor — invalid transitions
    // -----------------------------------------------------------------------

    #[test]
    fn cannot_transition_from_terminated() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        let err = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    #[test]
    fn cannot_sandbox_from_suspended() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        let err = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // Executor — idempotency
    // -----------------------------------------------------------------------

    #[test]
    fn idempotent_sandbox() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let r1 = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let r2 = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        // Second call returns existing receipt.
        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn idempotent_terminate() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let r1 = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        let r2 = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    // -----------------------------------------------------------------------
    // Executor — extension not found
    // -----------------------------------------------------------------------

    #[test]
    fn extension_not_found() {
        let mut executor = ContainmentExecutor::new();
        let ctx = test_context();
        let err = executor
            .execute(ContainmentAction::Sandbox, "nonexistent", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::ExtensionNotFound { .. }));
    }

    // -----------------------------------------------------------------------
    // Executor — receipt integrity
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_integrity_passes() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert!(receipt.verify_integrity());
    }

    #[test]
    fn receipt_integrity_detects_tampering() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let mut receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        receipt.duration_ns = 999_999;
        assert!(!receipt.verify_integrity());
    }

    // -----------------------------------------------------------------------
    // Executor — receipts list
    // -----------------------------------------------------------------------

    #[test]
    fn receipts_accumulated() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(executor.receipts("ext-001").len(), 2);
    }

    // -----------------------------------------------------------------------
    // Executor — by_state query
    // -----------------------------------------------------------------------

    #[test]
    fn by_state_query() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let sandboxed = executor.by_state(ContainmentState::Sandboxed);
        assert_eq!(sandboxed, vec!["ext-001"]);
        let running = executor.by_state(ContainmentState::Running);
        assert_eq!(running, vec!["ext-002"]);
    }

    // -----------------------------------------------------------------------
    // Executor — resume from suspended
    // -----------------------------------------------------------------------

    #[test]
    fn resume_from_suspended() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        let receipt = executor.resume("ext-001", &ctx).unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Running);
        assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));
    }

    #[test]
    fn resume_from_running_fails() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let err = executor.resume("ext-001", &ctx).unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // Executor — escalation path
    // -----------------------------------------------------------------------

    #[test]
    fn escalation_challenged_to_sandbox_to_terminate() {
        let mut executor = setup_executor();
        let ctx = test_context();

        executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert_eq!(
            executor.state("ext-001"),
            Some(ContainmentState::Challenged)
        );

        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(executor.state("ext-001"), Some(ContainmentState::Sandboxed));

        executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(
            executor.state("ext-001"),
            Some(ContainmentState::Terminated)
        );

        assert_eq!(executor.receipts("ext-001").len(), 3);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_serde_roundtrip() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn executor_serde_roundtrip() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&executor).unwrap();
        let restored: ContainmentExecutor = serde_json::from_str(&json).unwrap();
        assert_eq!(executor.extension_count(), restored.extension_count());
    }

    #[test]
    fn forensic_snapshot_serde_roundtrip() {
        let snapshot = ForensicSnapshot {
            memory_hash: ContentHash::compute(b"mem"),
            hostcall_count: 42,
            snapshot_ns: 1_000_000,
            manifest_hash: ContentHash::compute(b"manifest"),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: ForensicSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, restored);
    }

    #[test]
    fn context_serde_roundtrip() {
        let ctx = test_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: ContainmentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx.decision_id, restored.decision_id);
    }

    // -----------------------------------------------------------------------
    // Receipt metadata
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_contains_decision_id() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(
            receipt.metadata.get("decision_id"),
            Some(&"dec-001".to_string())
        );
    }

    #[test]
    // -- Enrichment: Ord --

    #[test]
    fn containment_state_ordering() {
        assert!(ContainmentState::Running < ContainmentState::Challenged);
        assert!(ContainmentState::Challenged < ContainmentState::Sandboxed);
        assert!(ContainmentState::Sandboxed < ContainmentState::Suspended);
        assert!(ContainmentState::Suspended < ContainmentState::Terminated);
        assert!(ContainmentState::Terminated < ContainmentState::Quarantined);
    }

    #[test]
    fn receipt_contains_evidence_refs() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.evidence_refs, vec!["ev-001".to_string()]);
    }
}
