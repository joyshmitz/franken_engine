//! Narrow control-plane adapter surface for `/dp/asupersync` primitives.
//!
//! This module is the only approved import boundary for control-plane crates:
//! - `franken-kernel` (`franken_kernel`)
//! - `franken-decision` (`franken_decision`)
//! - `franken-evidence` (`franken_evidence`)
//!
//! It intentionally exposes a constrained API for extension-host integration:
//! context/budget threading, decision contract evaluation, and evidence
//! emission. Callers should import these symbols from this module rather than
//! directly from upstream crates.

use serde::{Deserialize, Serialize};

pub use franken_decision::{
    DecisionContract, DecisionOutcome, EvalContext, FallbackPolicy, LossMatrix, Posterior,
};
pub use franken_evidence::{EvidenceLedger, EvidenceLedgerBuilder};
pub use franken_kernel::{
    Budget, CapabilitySet, Cx, DecisionId, NoCaps, PolicyId, SchemaVersion, TraceId,
};

const ADAPTER_COMPONENT: &str = "control_plane_adapter";

/// Runtime verdict expected by extension-host policy boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionVerdict {
    Allow,
    Deny,
    Timeout,
}

impl DecisionVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Timeout => "timeout",
        }
    }
}

/// Structured decision request routed through the adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub decision_id: DecisionId,
    pub policy_id: PolicyId,
    pub trace_id: TraceId,
    pub ts_unix_ms: u64,
    pub calibration_score_bps: u16,
    pub e_process_milli: u32,
    pub ci_width_milli: u32,
}

impl DecisionRequest {
    #[allow(clippy::cast_precision_loss)]
    fn calibration_score(&self) -> f64 {
        f64::from(self.calibration_score_bps) / 10_000.0
    }

    #[allow(clippy::cast_precision_loss)]
    fn e_process(&self) -> f64 {
        f64::from(self.e_process_milli) / 1_000.0
    }

    #[allow(clippy::cast_precision_loss)]
    fn ci_width(&self) -> f64 {
        f64::from(self.ci_width_milli) / 1_000.0
    }
}

/// Structured event emitted by adapter operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Adapter-level errors exposed to extension-host callers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneAdapterError {
    #[error("budget exhausted while consuming {requested_ms}ms")]
    BudgetExhausted { requested_ms: u64 },
    #[error("decision gateway failure ({code})")]
    DecisionGateway { code: &'static str },
    #[error("evidence emission failure ({code})")]
    EvidenceEmission { code: &'static str },
}

impl ControlPlaneAdapterError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::DecisionGateway { code } => code,
            Self::EvidenceEmission { code } => code,
        }
    }
}

/// Adapter boundary for threaded context and budget operations.
pub trait ContextAdapter {
    fn trace_id(&self) -> TraceId;
    fn budget(&self) -> Budget;
    fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError>;
}

/// Wrapper over canonical `franken_kernel::Cx` to keep imports centralized.
#[derive(Debug)]
pub struct KernelContext<'a, C: CapabilitySet = NoCaps> {
    cx: Cx<'a, C>,
}

impl<'a, C: CapabilitySet> KernelContext<'a, C> {
    pub fn new(cx: Cx<'a, C>) -> Self {
        Self { cx }
    }

    pub fn as_cx(&self) -> &Cx<'a, C> {
        &self.cx
    }

    pub fn into_inner(self) -> Cx<'a, C> {
        self.cx
    }
}

impl<C: CapabilitySet> ContextAdapter for KernelContext<'_, C> {
    fn trace_id(&self) -> TraceId {
        self.cx.trace_id()
    }

    fn budget(&self) -> Budget {
        self.cx.budget()
    }

    fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
        if self.cx.consume_budget(requested_ms) {
            Ok(())
        } else {
            Err(ControlPlaneAdapterError::BudgetExhausted { requested_ms })
        }
    }
}

/// Adapter boundary for decision contract evaluation.
pub trait DecisionAdapter {
    fn evaluate(
        &mut self,
        request: &DecisionRequest,
    ) -> Result<DecisionVerdict, ControlPlaneAdapterError>;
    fn events(&self) -> &[AdapterEvent];
}

/// Canonical decision adapter backed by `franken_decision::evaluate`.
#[derive(Debug, Clone)]
pub struct ContractDecisionAdapter<C: DecisionContract> {
    contract: C,
    posterior: Posterior,
    events: Vec<AdapterEvent>,
}

impl<C: DecisionContract> ContractDecisionAdapter<C> {
    pub fn new(contract: C, posterior: Posterior) -> Self {
        Self {
            contract,
            posterior,
            events: Vec::new(),
        }
    }
}

impl<C: DecisionContract> DecisionAdapter for ContractDecisionAdapter<C> {
    fn evaluate(
        &mut self,
        request: &DecisionRequest,
    ) -> Result<DecisionVerdict, ControlPlaneAdapterError> {
        let ctx = EvalContext {
            calibration_score: request.calibration_score(),
            e_process: request.e_process(),
            ci_width: request.ci_width(),
            decision_id: request.decision_id,
            trace_id: request.trace_id,
            ts_unix_ms: request.ts_unix_ms,
        };
        let outcome = franken_decision::evaluate(&self.contract, &self.posterior, &ctx);
        let verdict = action_to_verdict(&outcome.action_name).ok_or_else(|| {
            self.events.push(new_event(
                request,
                "decision_eval",
                "error",
                Some("unknown_action"),
            ));
            ControlPlaneAdapterError::DecisionGateway {
                code: "unknown_action",
            }
        })?;
        self.events
            .push(new_event(request, "decision_eval", verdict.as_str(), None));
        Ok(verdict)
    }

    fn events(&self) -> &[AdapterEvent] {
        &self.events
    }
}

/// Adapter boundary for evidence emission.
pub trait EvidenceEmitter {
    fn emit(
        &mut self,
        request: &DecisionRequest,
        entry: EvidenceLedger,
    ) -> Result<(), ControlPlaneAdapterError>;
    fn events(&self) -> &[AdapterEvent];
}

/// Minimal in-memory evidence sink used by integration and test harnesses.
#[derive(Debug, Clone, Default)]
pub struct InMemoryEvidenceEmitter {
    entries: Vec<EvidenceLedger>,
    events: Vec<AdapterEvent>,
}

impl InMemoryEvidenceEmitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[EvidenceLedger] {
        &self.entries
    }
}

impl EvidenceEmitter for InMemoryEvidenceEmitter {
    fn emit(
        &mut self,
        request: &DecisionRequest,
        entry: EvidenceLedger,
    ) -> Result<(), ControlPlaneAdapterError> {
        self.entries.push(entry);
        self.events
            .push(new_event(request, "evidence_emit", "ok", None));
        Ok(())
    }

    fn events(&self) -> &[AdapterEvent] {
        &self.events
    }
}

fn new_event(
    request: &DecisionRequest,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
) -> AdapterEvent {
    AdapterEvent {
        trace_id: request.trace_id.to_string(),
        decision_id: request.decision_id.to_string(),
        policy_id: request.policy_id.to_string(),
        component: ADAPTER_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(std::string::ToString::to_string),
    }
}

fn action_to_verdict(action: &str) -> Option<DecisionVerdict> {
    match action.to_ascii_lowercase().as_str() {
        "allow" | "permit" | "continue" => Some(DecisionVerdict::Allow),
        "deny" | "reject" | "block" => Some(DecisionVerdict::Deny),
        "timeout" | "challenge" | "defer" => Some(DecisionVerdict::Timeout),
        _ => None,
    }
}

/// Test helper mock types used by integration suites without reaching into
/// upstream control-plane crates directly.
pub mod mocks {
    use std::collections::VecDeque;
    use std::thread;
    use std::time::Duration;

    use super::*;

    const MOCK_TS_MS: u64 = 1_700_000_000_000;

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub enum MockFailureMode {
        #[default]
        Never,
        FailAlways {
            code: &'static str,
        },
        FailAfterN {
            remaining_successes: u32,
            code: &'static str,
        },
        LatencyInjection {
            millis: u64,
        },
        PanicOnCall,
    }

    fn apply_failure_mode(mode: &mut MockFailureMode) -> Result<(), &'static str> {
        match mode {
            MockFailureMode::Never => Ok(()),
            MockFailureMode::FailAlways { code } => Err(code),
            MockFailureMode::FailAfterN {
                remaining_successes,
                code,
            } => {
                if *remaining_successes == 0 {
                    Err(code)
                } else {
                    *remaining_successes -= 1;
                    Ok(())
                }
            }
            MockFailureMode::LatencyInjection { millis } => {
                thread::sleep(Duration::from_millis(*millis));
                Ok(())
            }
            MockFailureMode::PanicOnCall => panic!("mock configured to panic"),
        }
    }

    /// Deterministic test-only trace-id constructor.
    pub fn trace_id_from_seed(seed: u64) -> TraceId {
        TraceId::from_parts(MOCK_TS_MS + seed, u128::from(seed))
    }

    /// Deterministic test-only decision-id constructor.
    pub fn decision_id_from_seed(seed: u64) -> DecisionId {
        DecisionId::from_parts(MOCK_TS_MS + seed, u128::from(seed) << 1)
    }

    /// Deterministic test-only policy-id constructor.
    pub fn policy_id_from_seed(seed: u64) -> PolicyId {
        PolicyId::new(format!("mock.policy.{seed}"), 1)
    }

    /// Deterministic test-only schema-version constructor.
    pub fn schema_version_from_seed(seed: u64) -> SchemaVersion {
        SchemaVersion::new(1, (seed % 10) as u32, (seed % 1_000) as u32)
    }

    /// Mutable mock budget with deterministic consumption tracking.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MockBudget {
        remaining_ms: u64,
        consumed_ms: u64,
        panic_on_overspend: bool,
    }

    impl MockBudget {
        pub fn new(remaining_ms: u64) -> Self {
            Self {
                remaining_ms,
                consumed_ms: 0,
                panic_on_overspend: false,
            }
        }

        pub fn panic_on_overspend(mut self, enabled: bool) -> Self {
            self.panic_on_overspend = enabled;
            self
        }

        pub fn remaining_ms(&self) -> u64 {
            self.remaining_ms
        }

        pub fn consumed_ms(&self) -> u64 {
            self.consumed_ms
        }

        pub fn consume(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
            if requested_ms > self.remaining_ms {
                if self.panic_on_overspend {
                    panic!("mock budget overspend requested={requested_ms}");
                }
                return Err(ControlPlaneAdapterError::BudgetExhausted { requested_ms });
            }
            self.remaining_ms -= requested_ms;
            self.consumed_ms += requested_ms;
            Ok(())
        }

        pub fn as_budget(&self) -> Budget {
            Budget::new(self.remaining_ms)
        }
    }

    /// Mock context (`Cx`) that can panic on overspend if requested.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MockCx {
        trace_id: TraceId,
        budget: MockBudget,
    }

    impl MockCx {
        pub fn new(trace_id: TraceId, budget: MockBudget) -> Self {
            Self { trace_id, budget }
        }

        pub fn budget_state(&self) -> &MockBudget {
            &self.budget
        }
    }

    impl ContextAdapter for MockCx {
        fn trace_id(&self) -> TraceId {
            self.trace_id
        }

        fn budget(&self) -> Budget {
            self.budget.as_budget()
        }

        fn consume_budget(&mut self, requested_ms: u64) -> Result<(), ControlPlaneAdapterError> {
            self.budget.consume(requested_ms)
        }
    }

    /// Mock decision adapter with configurable allow/deny/timeout responses.
    #[derive(Debug, Clone)]
    pub struct MockDecisionContract {
        responses: VecDeque<DecisionVerdict>,
        failure_mode: MockFailureMode,
        events: Vec<AdapterEvent>,
    }

    impl MockDecisionContract {
        pub fn new(responses: impl IntoIterator<Item = DecisionVerdict>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                failure_mode: MockFailureMode::Never,
                events: Vec::new(),
            }
        }

        pub fn with_failure_mode(mut self, failure_mode: MockFailureMode) -> Self {
            self.failure_mode = failure_mode;
            self
        }
    }

    impl DecisionAdapter for MockDecisionContract {
        fn evaluate(
            &mut self,
            request: &DecisionRequest,
        ) -> Result<DecisionVerdict, ControlPlaneAdapterError> {
            if let Err(code) = apply_failure_mode(&mut self.failure_mode) {
                self.events.push(new_event(
                    request,
                    "mock_decision_eval",
                    "error",
                    Some(code),
                ));
                return Err(ControlPlaneAdapterError::DecisionGateway { code });
            }

            let verdict = self
                .responses
                .pop_front()
                .unwrap_or(DecisionVerdict::Timeout);
            self.events.push(new_event(
                request,
                "mock_decision_eval",
                verdict.as_str(),
                None,
            ));
            Ok(verdict)
        }

        fn events(&self) -> &[AdapterEvent] {
            &self.events
        }
    }

    /// Mock evidence emitter with deterministic in-memory sink and failure
    /// injection support.
    #[derive(Debug, Clone, Default)]
    pub struct MockEvidenceEmitter {
        entries: Vec<EvidenceLedger>,
        failure_mode: MockFailureMode,
        events: Vec<AdapterEvent>,
    }

    impl MockEvidenceEmitter {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_failure_mode(mut self, failure_mode: MockFailureMode) -> Self {
            self.failure_mode = failure_mode;
            self
        }

        pub fn entries(&self) -> &[EvidenceLedger] {
            &self.entries
        }
    }

    impl EvidenceEmitter for MockEvidenceEmitter {
        fn emit(
            &mut self,
            request: &DecisionRequest,
            entry: EvidenceLedger,
        ) -> Result<(), ControlPlaneAdapterError> {
            if let Err(code) = apply_failure_mode(&mut self.failure_mode) {
                self.events.push(new_event(
                    request,
                    "mock_evidence_emit",
                    "error",
                    Some(code),
                ));
                return Err(ControlPlaneAdapterError::EvidenceEmission { code });
            }

            self.entries.push(entry);
            self.events
                .push(new_event(request, "mock_evidence_emit", "ok", None));
            Ok(())
        }

        fn events(&self) -> &[AdapterEvent] {
            &self.events
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};

    use super::mocks::{
        MockBudget, MockCx, MockDecisionContract, MockEvidenceEmitter, MockFailureMode,
        decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
    };
    use super::*;

    fn request(seed: u64) -> DecisionRequest {
        DecisionRequest {
            decision_id: decision_id_from_seed(seed),
            policy_id: policy_id_from_seed(seed),
            trace_id: trace_id_from_seed(seed),
            ts_unix_ms: 1_700_000_000_000 + seed,
            calibration_score_bps: 9_400,
            e_process_milli: 110,
            ci_width_milli: 45,
        }
    }

    fn evidence(ts: u64, action: &str) -> EvidenceLedger {
        EvidenceLedgerBuilder::new()
            .ts_unix_ms(ts)
            .component("control_plane_adapter_test")
            .action(action)
            .posterior(vec![0.7, 0.3])
            .expected_loss("allow", 0.1)
            .expected_loss("deny", 0.2)
            .expected_loss("timeout", 0.3)
            .chosen_expected_loss(0.1)
            .calibration_score(0.94)
            .fallback_active(false)
            .build()
            .expect("valid evidence")
    }

    #[test]
    fn mock_context_tracks_budget_and_can_panic_on_overspend() {
        let trace_id = trace_id_from_seed(1);
        let mut cx = MockCx::new(trace_id, MockBudget::new(20));
        cx.consume_budget(5).expect("consume");
        assert_eq!(cx.trace_id(), trace_id);
        assert_eq!(cx.budget().remaining_ms(), 15);

        let mut panic_cx = MockCx::new(
            trace_id_from_seed(2),
            MockBudget::new(1).panic_on_overspend(true),
        );
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = panic_cx.consume_budget(2);
        }));
        assert!(panicked.is_err(), "overspend panic mode must panic");
    }

    #[test]
    fn mock_decision_contract_supports_allow_deny_timeout_and_fail_after_n() {
        let req = request(10);
        let mut decision = MockDecisionContract::new([
            DecisionVerdict::Allow,
            DecisionVerdict::Deny,
            DecisionVerdict::Timeout,
        ]);
        assert_eq!(
            decision.evaluate(&req).expect("allow"),
            DecisionVerdict::Allow
        );
        assert_eq!(
            decision.evaluate(&req).expect("deny"),
            DecisionVerdict::Deny
        );
        assert_eq!(
            decision.evaluate(&req).expect("timeout"),
            DecisionVerdict::Timeout
        );

        let mut fail_after_n = MockDecisionContract::new([DecisionVerdict::Allow])
            .with_failure_mode(MockFailureMode::FailAfterN {
                remaining_successes: 1,
                code: "mock_fail_after_n",
            });
        assert_eq!(
            fail_after_n.evaluate(&req).expect("first call passes"),
            DecisionVerdict::Allow
        );
        let err = fail_after_n
            .evaluate(&req)
            .expect_err("second call should fail");
        assert!(matches!(
            err,
            ControlPlaneAdapterError::DecisionGateway {
                code: "mock_fail_after_n"
            }
        ));
    }

    #[test]
    fn mock_evidence_emitter_supports_fail_always_and_records_events() {
        let req = request(20);
        let mut emitter = MockEvidenceEmitter::new();
        emitter
            .emit(&req, evidence(req.ts_unix_ms, "allow"))
            .expect("emit success");
        assert_eq!(emitter.entries().len(), 1);
        assert_eq!(emitter.events().len(), 1);
        assert_eq!(emitter.events()[0].outcome, "ok");

        let mut fail_always =
            MockEvidenceEmitter::new().with_failure_mode(MockFailureMode::FailAlways {
                code: "mock_evidence_fail_always",
            });
        let err = fail_always
            .emit(&req, evidence(req.ts_unix_ms + 1, "deny"))
            .expect_err("fail always should error");
        assert!(matches!(
            err,
            ControlPlaneAdapterError::EvidenceEmission {
                code: "mock_evidence_fail_always"
            }
        ));
    }

    // ── DecisionVerdict ────────────────────────────────────────────

    #[test]
    fn decision_verdict_as_str() {
        assert_eq!(DecisionVerdict::Allow.as_str(), "allow");
        assert_eq!(DecisionVerdict::Deny.as_str(), "deny");
        assert_eq!(DecisionVerdict::Timeout.as_str(), "timeout");
    }

    #[test]
    fn decision_verdict_serde_round_trip() {
        for variant in [
            DecisionVerdict::Allow,
            DecisionVerdict::Deny,
            DecisionVerdict::Timeout,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: DecisionVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ── DecisionRequest conversion helpers ─────────────────────────

    #[test]
    fn decision_request_calibration_score() {
        let req = request(1);
        assert!((req.calibration_score() - 0.94).abs() < 1e-9);
    }

    #[test]
    fn decision_request_e_process() {
        let req = request(1);
        assert!((req.e_process() - 0.110).abs() < 1e-9);
    }

    #[test]
    fn decision_request_ci_width() {
        let req = request(1);
        assert!((req.ci_width() - 0.045).abs() < 1e-9);
    }

    #[test]
    fn decision_request_serde_round_trip() {
        let req = request(42);
        let json = serde_json::to_string(&req).unwrap();
        let back: DecisionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    // ── ControlPlaneAdapterError ───────────────────────────────────

    #[test]
    fn error_code_values() {
        assert_eq!(
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 10 }.error_code(),
            "budget_exhausted"
        );
        assert_eq!(
            ControlPlaneAdapterError::DecisionGateway { code: "gw_fail" }.error_code(),
            "gw_fail"
        );
        assert_eq!(
            ControlPlaneAdapterError::EvidenceEmission { code: "emit_fail" }.error_code(),
            "emit_fail"
        );
    }

    #[test]
    fn error_display_budget_exhausted() {
        let err = ControlPlaneAdapterError::BudgetExhausted { requested_ms: 50 };
        assert!(err.to_string().contains("50"));
    }

    #[test]
    fn error_display_decision_gateway() {
        let err = ControlPlaneAdapterError::DecisionGateway {
            code: "gateway_err",
        };
        assert!(err.to_string().contains("gateway_err"));
    }

    #[test]
    fn error_display_evidence_emission() {
        let err = ControlPlaneAdapterError::EvidenceEmission { code: "emit_err" };
        assert!(err.to_string().contains("emit_err"));
    }

    // ── action_to_verdict ──────────────────────────────────────────

    #[test]
    fn action_to_verdict_allow_synonyms() {
        assert_eq!(action_to_verdict("allow"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("permit"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("continue"), Some(DecisionVerdict::Allow));
        assert_eq!(action_to_verdict("ALLOW"), Some(DecisionVerdict::Allow));
    }

    #[test]
    fn action_to_verdict_deny_synonyms() {
        assert_eq!(action_to_verdict("deny"), Some(DecisionVerdict::Deny));
        assert_eq!(action_to_verdict("reject"), Some(DecisionVerdict::Deny));
        assert_eq!(action_to_verdict("block"), Some(DecisionVerdict::Deny));
    }

    #[test]
    fn action_to_verdict_timeout_synonyms() {
        assert_eq!(action_to_verdict("timeout"), Some(DecisionVerdict::Timeout));
        assert_eq!(
            action_to_verdict("challenge"),
            Some(DecisionVerdict::Timeout)
        );
        assert_eq!(action_to_verdict("defer"), Some(DecisionVerdict::Timeout));
    }

    #[test]
    fn action_to_verdict_unknown_returns_none() {
        assert_eq!(action_to_verdict("unknown_action"), None);
        assert_eq!(action_to_verdict(""), None);
    }

    // ── InMemoryEvidenceEmitter ────────────────────────────────────

    #[test]
    fn in_memory_evidence_emitter_records_entries_and_events() {
        let req = request(30);
        let mut emitter = InMemoryEvidenceEmitter::new();
        assert!(emitter.entries().is_empty());
        assert!(emitter.events().is_empty());

        emitter
            .emit(&req, evidence(req.ts_unix_ms, "allow"))
            .unwrap();
        assert_eq!(emitter.entries().len(), 1);
        assert_eq!(emitter.events().len(), 1);
        assert_eq!(emitter.events()[0].event, "evidence_emit");
        assert_eq!(emitter.events()[0].outcome, "ok");
        assert_eq!(emitter.events()[0].component, ADAPTER_COMPONENT);
    }

    // ── AdapterEvent serde ─────────────────────────────────────────

    #[test]
    fn adapter_event_serde_round_trip() {
        let event = AdapterEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "test".to_string(),
            event: "eval".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // ── MockDecisionContract exhausted responses ───────────────────

    #[test]
    fn mock_decision_contract_defaults_to_timeout_when_exhausted() {
        let req = request(40);
        let mut decision = MockDecisionContract::new([DecisionVerdict::Allow]);
        assert_eq!(decision.evaluate(&req).unwrap(), DecisionVerdict::Allow);
        // Second call exhausts the queue, should default to Timeout
        assert_eq!(decision.evaluate(&req).unwrap(), DecisionVerdict::Timeout);
    }

    // -- Enrichment: error trait --

    #[test]
    fn control_plane_adapter_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ControlPlaneAdapterError::BudgetExhausted { requested_ms: 100 }),
            Box::new(ControlPlaneAdapterError::DecisionGateway { code: "DG_TIMEOUT" }),
            Box::new(ControlPlaneAdapterError::EvidenceEmission { code: "EE_FAIL" }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: default --

    #[test]
    fn mock_failure_mode_default_is_never() {
        assert_eq!(MockFailureMode::default(), MockFailureMode::Never);
    }

    #[test]
    fn in_memory_evidence_emitter_default_is_empty() {
        let emitter = InMemoryEvidenceEmitter::default();
        assert_eq!(emitter.entries().len(), 0);
        assert_eq!(emitter.events().len(), 0);
    }

    // -- Enrichment: error code uniqueness --

    #[test]
    fn error_codes_are_distinct() {
        let codes = [
            ControlPlaneAdapterError::BudgetExhausted { requested_ms: 1 }.error_code(),
            ControlPlaneAdapterError::DecisionGateway { code: "x" }.error_code(),
            ControlPlaneAdapterError::EvidenceEmission { code: "y" }.error_code(),
        ];
        let set: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(set.len(), codes.len());
    }

    // -- Enrichment: adapter event with error_code --

    #[test]
    fn adapter_event_with_error_code_serde() {
        let event = AdapterEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "test".to_string(),
            event: "eval".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("DG_TIMEOUT".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(back.error_code.as_deref(), Some("DG_TIMEOUT"));
    }
}
