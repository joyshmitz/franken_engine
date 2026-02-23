#![forbid(unsafe_code)]

pub mod activation_lifecycle;
pub mod adversarial_campaign;
pub mod alloc_domain;
pub mod ambient_authority;
pub mod anti_entropy;
pub mod ast;
pub mod attestation_handshake;
pub mod attested_execution_cell;
pub mod baseline_interpreter;
pub mod bayesian_posterior;
pub mod benchmark_denominator;
pub mod benchmark_e2e;
pub mod bulkhead;
pub mod cancel_mask;
pub mod cancellation_lifecycle;
pub mod canonical_encoding;
pub mod canonical_evidence_emitter;
pub mod capability;
pub mod capability_token;
pub mod capability_witness;
pub mod causal_replay;
pub mod checkpoint;
pub mod checkpoint_frontier;
pub mod closure_model;
pub mod compiler_policy;
pub mod conformance_catalog;
pub mod conformance_harness;
pub mod conformance_vector_gen;
pub mod constrained_ambient_benchmark_lane;
pub mod containment_executor;
pub mod control_plane;
pub mod control_plane_benchmark_split_gate;
pub mod controller_interference_guard;
pub mod counterexample_synthesizer;
pub mod cross_repo_contract;
pub mod cx_threading;
pub mod declassification_pipeline;
pub mod delegate_cell_harness;
pub mod delegation_chain;
pub mod demotion_rollback;
pub mod deterministic_serde;
pub mod dp_budget_accountant;
pub mod e2e_harness;
pub mod engine_object_id;
pub mod epoch_barrier;
pub mod epoch_invalidation;
pub mod eprocess_guardrail;
pub mod error_code;
pub mod evidence_contract;
pub mod evidence_emission;
pub mod evidence_ledger;
pub mod evidence_ordering;
pub mod evidence_replay_checker;
pub mod execution_cell;
pub mod execution_orchestrator;
pub mod expected_loss_selector;
pub mod extension_host_authority_guard;
pub mod extension_host_lifecycle;
pub mod extension_lifecycle_manager;
pub mod feature_parity_tracker;
pub mod flamegraph_pipeline;
pub mod fleet_convergence;
pub mod fleet_immune_protocol;
pub mod flow_envelope;
pub mod flow_lattice;
pub mod forensic_replayer;
pub mod fork_detection;
pub mod frankenlab_extension_lifecycle;
pub mod frankenlab_release_gate;
pub mod frankentui_adapter;
pub mod gc;
pub mod gc_pause;
pub mod golden_vectors;
pub mod governance_scorecard;
pub mod guardplane_calibration;
pub mod hash_tiers;
pub mod hostcall_telemetry;
pub mod idempotency_key;
pub mod ifc_artifacts;
pub mod ifc_provenance_index;
pub mod incident_replay_bundle;
pub mod interleaving_explorer;
pub mod ir_contract;
pub mod key_attestation;
pub mod key_derivation;
pub mod lab_runtime;
pub mod lease_tracker;
pub mod lowering_pipeline;
pub mod marker_stream;
pub mod migration_compatibility;
pub mod migration_contract;
pub mod mmr_proof;
pub mod module_cache;
pub mod module_compatibility_matrix;
pub mod module_resolver;
pub mod monitor_scheduler;
pub mod moonshot_contract;
pub mod object_model;
pub mod obligation_channel;
pub mod obligation_integration;
pub mod obligation_leak_policy;
pub mod one_lever_policy;
pub mod opportunity_matrix;
pub mod parser;
pub mod phase_gate;
pub mod plas_benchmark_bundle;
pub mod plas_burn_in_gate;
pub mod plas_lockstep;
pub mod plas_release_gate;
pub mod policy_checkpoint;
pub mod policy_controller;
pub mod policy_theorem_compiler;
pub mod portfolio_governor;
pub mod principal_key_roles;
pub mod privacy_learning_contract;
pub mod promotion_gate_runner;
pub mod proof_ingestion;
pub mod proof_release_gate;
pub mod proof_schema;
pub mod proof_specialization_linkage;
pub mod promise_model;
pub mod proof_specialization_receipt;
pub mod quarantine_mesh_gate;
pub mod receipt_verifier_pipeline;
pub mod recovery_artifact;
pub mod regime_detector;
pub mod region_lifecycle;
pub mod release_checklist_gate;
pub mod release_gate;
pub mod remote_capability_gate;
pub mod remote_computation_registry;
pub mod replacement_lineage_log;
pub mod reputation;
pub mod revocation_chain;
pub mod revocation_enforcement;
pub mod revocation_freshness;
pub mod runtime_diagnostics_cli;
pub mod runtime_observability;
pub mod safe_mode_fallback;
pub mod safety_decision_router;
pub mod saga_orchestrator;
pub mod scheduler_lane;
pub mod security_e2e;
pub mod security_epoch;
pub mod self_replacement;
pub mod session_hostcall_channel;
pub mod shadow_ablation_engine;
pub mod sibling_integration_benchmark_gate;
pub mod signature_preimage;
pub mod slot_registry;
pub mod sorted_multisig;
pub mod specialization_index;
pub mod static_authority_analyzer;
pub mod storage_adapter;
pub mod supervision;
pub mod synthesis_budget;
pub mod tee_attestation_policy;
pub mod test262_release_gate;
pub mod third_party_verifier;
pub mod threshold_signing;
pub mod translation_validation;
pub mod trust_card;
pub mod trust_economics;
pub mod trust_zone;
pub mod ts_normalization;
pub mod version_matrix_lane;

use std::{cmp::Ordering, error::Error, fmt};

use serde::{Deserialize, Serialize};

/// Canonical error classes for deterministic VM semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvalErrorClass {
    Parse,
    Resolution,
    Policy,
    Capability,
    Runtime,
    Hostcall,
    Invariant,
}

impl EvalErrorClass {
    const fn sort_rank(self) -> u8 {
        match self {
            Self::Parse => 0,
            Self::Resolution => 1,
            Self::Policy => 2,
            Self::Capability => 3,
            Self::Runtime => 4,
            Self::Hostcall => 5,
            Self::Invariant => 6,
        }
    }

    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Resolution => "resolution",
            Self::Policy => "policy",
            Self::Capability => "capability",
            Self::Runtime => "runtime",
            Self::Hostcall => "hostcall",
            Self::Invariant => "invariant",
        }
    }
}

impl fmt::Display for EvalErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvalErrorCode {
    EmptySource,
    ParseFailure,
    ResolutionFailure,
    PolicyDenied,
    CapabilityDenied,
    RuntimeFault,
    HostcallFault,
    InvariantViolation,
}

impl EvalErrorCode {
    const fn sort_rank(self) -> u8 {
        match self {
            Self::EmptySource => 0,
            Self::ParseFailure => 1,
            Self::ResolutionFailure => 2,
            Self::PolicyDenied => 3,
            Self::CapabilityDenied => 4,
            Self::RuntimeFault => 5,
            Self::HostcallFault => 6,
            Self::InvariantViolation => 7,
        }
    }

    pub const fn class(self) -> EvalErrorClass {
        match self {
            Self::EmptySource | Self::ParseFailure => EvalErrorClass::Parse,
            Self::ResolutionFailure => EvalErrorClass::Resolution,
            Self::PolicyDenied => EvalErrorClass::Policy,
            Self::CapabilityDenied => EvalErrorClass::Capability,
            Self::RuntimeFault => EvalErrorClass::Runtime,
            Self::HostcallFault => EvalErrorClass::Hostcall,
            Self::InvariantViolation => EvalErrorClass::Invariant,
        }
    }

    pub const fn stable_namespace(self) -> &'static str {
        match self {
            Self::EmptySource => "eval.parse.empty_source",
            Self::ParseFailure => "eval.parse.failure",
            Self::ResolutionFailure => "eval.resolution.failure",
            Self::PolicyDenied => "eval.policy.denied",
            Self::CapabilityDenied => "eval.capability.denied",
            Self::RuntimeFault => "eval.runtime.fault",
            Self::HostcallFault => "eval.hostcall.fault",
            Self::InvariantViolation => "eval.invariant.violation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalError {
    pub code: EvalErrorCode,
    pub message: String,
}

impl EvalError {
    pub fn new(code: EvalErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn empty_source() -> Self {
        Self::new(EvalErrorCode::EmptySource, "source is empty")
    }

    pub fn parse_failure(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::ParseFailure, message)
    }

    pub fn resolution_failure(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::ResolutionFailure, message)
    }

    pub fn policy_denied(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::PolicyDenied, message)
    }

    pub fn capability_denied(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::CapabilityDenied, message)
    }

    pub fn runtime_fault(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::RuntimeFault, message)
    }

    pub fn hostcall_fault(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::HostcallFault, message)
    }

    pub fn invariant_violation(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::InvariantViolation, message)
    }

    pub fn class(&self) -> EvalErrorClass {
        self.code.class()
    }

    pub fn stable_namespace(&self) -> &'static str {
        self.code.stable_namespace()
    }
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}]: {}",
            self.stable_namespace(),
            self.class(),
            self.message
        )
    }
}

impl Error for EvalError {}

pub type EvalResult<T> = std::result::Result<T, EvalError>;

/// Migration note for deterministic error semantics in bd-2tx.
pub const EVAL_ERROR_MIGRATION_NOTES: &str = "Migrated from ad-hoc eval string failures to a \
typed deterministic taxonomy (`EvalErrorClass` + `EvalErrorCode`) with stable namespace codes, \
stable sorting for multi-error contexts, and explicit propagation helpers for sync/async/hostcall \
boundaries.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExceptionBoundary {
    SyncCallframe,
    AsyncJob,
    Hostcall,
}

impl ExceptionBoundary {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::SyncCallframe => "sync_callframe",
            Self::AsyncJob => "async_job",
            Self::Hostcall => "hostcall",
        }
    }
}

impl fmt::Display for ExceptionBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionTransitionEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub boundary: ExceptionBoundary,
    pub message: String,
}

pub fn emit_exception_transition_event(
    trace_id: impl Into<String>,
    decision_id: Option<String>,
    policy_id: Option<String>,
    component: impl Into<String>,
    boundary: ExceptionBoundary,
    error: &EvalError,
) -> ExceptionTransitionEvent {
    ExceptionTransitionEvent {
        trace_id: trace_id.into(),
        decision_id,
        policy_id,
        component: component.into(),
        event: "exception_transition".to_string(),
        outcome: "error".to_string(),
        error_code: error.stable_namespace().to_string(),
        boundary,
        message: error.message.clone(),
    }
}

fn compare_eval_errors(lhs: &EvalError, rhs: &EvalError) -> Ordering {
    lhs.class()
        .sort_rank()
        .cmp(&rhs.class().sort_rank())
        .then(lhs.code.sort_rank().cmp(&rhs.code.sort_rank()))
        .then(lhs.message.as_bytes().cmp(rhs.message.as_bytes()))
}

pub fn stable_sort_eval_errors(errors: &mut [EvalError]) {
    errors.sort_by(compare_eval_errors);
}

pub fn sorted_eval_errors(mut errors: Vec<EvalError>) -> Vec<EvalError> {
    stable_sort_eval_errors(&mut errors);
    errors
}

pub fn propagate_error_across_boundary(error: EvalError, boundary: ExceptionBoundary) -> EvalError {
    let mut message = error.message;
    if !message.is_empty() {
        message.push_str(" | ");
    }
    message.push_str("boundary=");
    message.push_str(boundary.stable_label());
    EvalError::new(error.code, message)
}

pub fn propagate_result_across_boundary<T>(
    result: EvalResult<T>,
    boundary: ExceptionBoundary,
) -> EvalResult<T> {
    result.map_err(|error| propagate_error_across_boundary(error, boundary))
}

/// Execution lanes are de novo native Rust implementations inspired by
/// proven ideas from QuickJS and V8, not FFI wrappers over external engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineKind {
    QuickJsInspiredNative,
    V8InspiredNative,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteReason {
    DirectEngineInvocation,
    ContainsImportKeyword,
    ContainsAwaitKeyword,
    DefaultQuickJsPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalOutcome {
    pub engine: EngineKind,
    pub value: String,
    pub route_reason: RouteReason,
}

pub trait JsEngine {
    fn kind(&self) -> EngineKind;
    fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome>;
}

#[derive(Debug, Default)]
pub struct QuickJsInspiredNativeEngine;

#[derive(Debug, Default)]
pub struct V8InspiredNativeEngine;

impl JsEngine for QuickJsInspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::QuickJsInspiredNative
    }

    fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let normalized = normalize_source(source)?;
        Ok(EvalOutcome {
            engine: EngineKind::QuickJsInspiredNative,
            value: normalized.to_string(),
            route_reason: RouteReason::DirectEngineInvocation,
        })
    }
}

impl JsEngine for V8InspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::V8InspiredNative
    }

    fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let normalized = normalize_source(source)?;
        Ok(EvalOutcome {
            engine: EngineKind::V8InspiredNative,
            value: normalized.to_string(),
            route_reason: RouteReason::DirectEngineInvocation,
        })
    }
}

#[derive(Debug)]
pub struct HybridRouter {
    quickjs_lineage: QuickJsInspiredNativeEngine,
    v8_lineage: V8InspiredNativeEngine,
}

impl Default for HybridRouter {
    fn default() -> Self {
        Self {
            quickjs_lineage: QuickJsInspiredNativeEngine,
            v8_lineage: V8InspiredNativeEngine,
        }
    }
}

impl HybridRouter {
    pub fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let route_reason = if source.contains("import ") {
            RouteReason::ContainsImportKeyword
        } else if source.contains("await ") {
            RouteReason::ContainsAwaitKeyword
        } else {
            RouteReason::DefaultQuickJsPath
        };

        let mut outcome = match route_reason {
            RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword => {
                self.v8_lineage.eval(source)?
            }
            RouteReason::DefaultQuickJsPath => self.quickjs_lineage.eval(source)?,
            RouteReason::DirectEngineInvocation => unreachable!("router never emits direct route"),
        };

        outcome.route_reason = route_reason;
        Ok(outcome)
    }
}

fn normalize_source(source: &str) -> EvalResult<&str> {
    let normalized = source.trim();
    if normalized.is_empty() {
        return Err(EvalError::empty_source());
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    #[test]
    fn hybrid_routes_simple_input_to_quickjs() {
        let mut router = HybridRouter::default();
        let out = router.eval("1 + 1").expect("eval");
        assert_eq!(out.engine, EngineKind::QuickJsInspiredNative);
        assert_eq!(out.route_reason, RouteReason::DefaultQuickJsPath);
    }

    #[test]
    fn hybrid_routes_import_to_v8() {
        let mut router = HybridRouter::default();
        let out = router.eval("import x from 'y'").expect("eval");
        assert_eq!(out.engine, EngineKind::V8InspiredNative);
        assert_eq!(out.route_reason, RouteReason::ContainsImportKeyword);
    }

    #[test]
    fn hybrid_routes_await_to_v8() {
        let mut router = HybridRouter::default();
        let out = router.eval("await job()").expect("eval");
        assert_eq!(out.engine, EngineKind::V8InspiredNative);
        assert_eq!(out.route_reason, RouteReason::ContainsAwaitKeyword);
    }

    #[test]
    fn direct_lanes_reject_empty_source_with_stable_error_code() {
        let mut quickjs = QuickJsInspiredNativeEngine;
        let mut v8 = V8InspiredNativeEngine;

        let quickjs_err = quickjs.eval(" ").expect_err("expected empty source error");
        let v8_err = v8.eval("\t").expect_err("expected empty source error");

        assert_eq!(quickjs_err.code, EvalErrorCode::EmptySource);
        assert_eq!(v8_err.code, EvalErrorCode::EmptySource);
        assert_eq!(quickjs_err.class(), EvalErrorClass::Parse);
        assert_eq!(v8_err.class(), EvalErrorClass::Parse);
        assert_eq!(quickjs_err.stable_namespace(), "eval.parse.empty_source");
        assert_eq!(v8_err.stable_namespace(), "eval.parse.empty_source");
    }

    #[test]
    fn hybrid_rejects_empty_source_with_stable_error_code() {
        let mut router = HybridRouter::default();
        let err = router.eval(" ").expect_err("expected empty source error");
        assert_eq!(err.code, EvalErrorCode::EmptySource);
        assert_eq!(err.class(), EvalErrorClass::Parse);
        assert_eq!(err.stable_namespace(), "eval.parse.empty_source");
    }

    #[test]
    fn equivalent_empty_source_failures_are_identical_across_lanes() {
        let mut quickjs = QuickJsInspiredNativeEngine;
        let mut v8 = V8InspiredNativeEngine;
        let mut hybrid = HybridRouter::default();

        let quickjs_err = quickjs
            .eval("")
            .expect_err("quickjs must reject empty source");
        let v8_err = v8.eval(" ").expect_err("v8 must reject empty source");
        let hybrid_err = hybrid
            .eval("\n\t")
            .expect_err("hybrid must reject empty source");

        let quickjs_shape = (
            quickjs_err.code,
            quickjs_err.class(),
            quickjs_err.stable_namespace(),
            quickjs_err.message,
        );
        let v8_shape = (
            v8_err.code,
            v8_err.class(),
            v8_err.stable_namespace(),
            v8_err.message,
        );
        let hybrid_shape = (
            hybrid_err.code,
            hybrid_err.class(),
            hybrid_err.stable_namespace(),
            hybrid_err.message,
        );

        assert_eq!(quickjs_shape, v8_shape);
        assert_eq!(v8_shape, hybrid_shape);
    }

    #[test]
    fn eval_error_code_class_mappings_are_deterministic() {
        let expected = [
            (EvalErrorCode::EmptySource, EvalErrorClass::Parse),
            (EvalErrorCode::ParseFailure, EvalErrorClass::Parse),
            (EvalErrorCode::ResolutionFailure, EvalErrorClass::Resolution),
            (EvalErrorCode::PolicyDenied, EvalErrorClass::Policy),
            (EvalErrorCode::CapabilityDenied, EvalErrorClass::Capability),
            (EvalErrorCode::RuntimeFault, EvalErrorClass::Runtime),
            (EvalErrorCode::HostcallFault, EvalErrorClass::Hostcall),
            (EvalErrorCode::InvariantViolation, EvalErrorClass::Invariant),
        ];

        for (code, class) in expected {
            assert_eq!(code.class(), class);
            assert!(
                code.stable_namespace().starts_with("eval."),
                "stable namespace must be in eval.* namespace"
            );
        }
    }

    #[test]
    fn stable_sort_for_multi_error_context_is_deterministic() {
        let mut errors = vec![
            EvalError::runtime_fault("panic in optimizer"),
            EvalError::capability_denied("fs_write not granted"),
            EvalError::parse_failure("unexpected token `}`"),
            EvalError::empty_source(),
            EvalError::hostcall_fault("bridge timeout"),
            EvalError::policy_denied("policy denied extension"),
        ];

        stable_sort_eval_errors(&mut errors);

        let namespaces: Vec<&str> = errors.iter().map(EvalError::stable_namespace).collect();
        assert_eq!(
            namespaces,
            vec![
                "eval.parse.empty_source",
                "eval.parse.failure",
                "eval.policy.denied",
                "eval.capability.denied",
                "eval.runtime.fault",
                "eval.hostcall.fault"
            ]
        );
    }

    #[test]
    fn propagation_across_sync_async_hostcall_boundaries_is_stable() {
        let parse_error = EvalError::parse_failure("unexpected token");

        let propagated =
            propagate_error_across_boundary(parse_error, ExceptionBoundary::SyncCallframe);
        let propagated = propagate_error_across_boundary(propagated, ExceptionBoundary::AsyncJob);
        let propagated = propagate_error_across_boundary(propagated, ExceptionBoundary::Hostcall);

        assert_eq!(propagated.code, EvalErrorCode::ParseFailure);
        assert_eq!(
            propagated.message,
            "unexpected token | boundary=sync_callframe | boundary=async_job | boundary=hostcall"
        );
    }

    #[test]
    fn exception_transition_event_emits_structured_deterministic_fields() {
        let err = EvalError::policy_denied("policy denied extension");
        let event = emit_exception_transition_event(
            "trace-01",
            Some("decision-17".to_string()),
            Some("policy-main".to_string()),
            "hybrid_router",
            ExceptionBoundary::SyncCallframe,
            &err,
        );

        assert_eq!(event.trace_id, "trace-01");
        assert_eq!(event.decision_id.as_deref(), Some("decision-17"));
        assert_eq!(event.policy_id.as_deref(), Some("policy-main"));
        assert_eq!(event.component, "hybrid_router");
        assert_eq!(event.event, "exception_transition");
        assert_eq!(event.outcome, "error");
        assert_eq!(event.error_code, "eval.policy.denied");
        assert_eq!(event.boundary, ExceptionBoundary::SyncCallframe);
        assert_eq!(event.message, "policy denied extension");

        let encoded = serde_json::to_string(&event).expect("serialize event");
        let decoded: ExceptionTransitionEvent =
            serde_json::from_str(&encoded).expect("deserialize event");
        assert_eq!(decoded, event);
    }

    // -----------------------------------------------------------------------
    // EvalError factory methods
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_factory_methods_produce_correct_codes() {
        let cases: Vec<(EvalError, EvalErrorCode)> = vec![
            (EvalError::parse_failure("x"), EvalErrorCode::ParseFailure),
            (
                EvalError::resolution_failure("x"),
                EvalErrorCode::ResolutionFailure,
            ),
            (EvalError::policy_denied("x"), EvalErrorCode::PolicyDenied),
            (
                EvalError::capability_denied("x"),
                EvalErrorCode::CapabilityDenied,
            ),
            (EvalError::runtime_fault("x"), EvalErrorCode::RuntimeFault),
            (EvalError::hostcall_fault("x"), EvalErrorCode::HostcallFault),
            (
                EvalError::invariant_violation("x"),
                EvalErrorCode::InvariantViolation,
            ),
        ];
        for (error, expected_code) in cases {
            assert_eq!(error.code, expected_code, "factory for {:?}", expected_code);
        }
    }

    // -----------------------------------------------------------------------
    // EvalError Display format
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_display_format_includes_namespace_class_message() {
        let err = EvalError::runtime_fault("stack overflow");
        let display = format!("{err}");
        assert!(display.contains("eval.runtime.fault"));
        assert!(display.contains("runtime"));
        assert!(display.contains("stack overflow"));
    }

    // -----------------------------------------------------------------------
    // Serde round-trips for core types
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_class_serde_round_trip() {
        let classes = [
            EvalErrorClass::Parse,
            EvalErrorClass::Resolution,
            EvalErrorClass::Policy,
            EvalErrorClass::Capability,
            EvalErrorClass::Runtime,
            EvalErrorClass::Hostcall,
            EvalErrorClass::Invariant,
        ];
        for class in &classes {
            let json = serde_json::to_string(class).expect("serialize");
            let decoded: EvalErrorClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, class);
        }
    }

    #[test]
    fn eval_error_code_serde_round_trip() {
        let codes = [
            EvalErrorCode::EmptySource,
            EvalErrorCode::ParseFailure,
            EvalErrorCode::ResolutionFailure,
            EvalErrorCode::PolicyDenied,
            EvalErrorCode::CapabilityDenied,
            EvalErrorCode::RuntimeFault,
            EvalErrorCode::HostcallFault,
            EvalErrorCode::InvariantViolation,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serialize");
            let decoded: EvalErrorCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn engine_kind_serde_round_trip() {
        for kind in &[
            EngineKind::QuickJsInspiredNative,
            EngineKind::V8InspiredNative,
            EngineKind::Hybrid,
        ] {
            let json = serde_json::to_string(kind).expect("serialize");
            let decoded: EngineKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, kind);
        }
    }

    #[test]
    fn route_reason_serde_round_trip() {
        let reasons = [
            RouteReason::DirectEngineInvocation,
            RouteReason::ContainsImportKeyword,
            RouteReason::ContainsAwaitKeyword,
            RouteReason::DefaultQuickJsPath,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).expect("serialize");
            let decoded: RouteReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, reason);
        }
    }

    #[test]
    fn eval_error_serde_round_trip() {
        let err = EvalError::policy_denied("extension blocked");
        let json = serde_json::to_string(&err).expect("serialize");
        let decoded: EvalError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, err);
    }

    #[test]
    fn eval_outcome_serde_round_trip() {
        let outcome = EvalOutcome {
            engine: EngineKind::V8InspiredNative,
            value: "42".to_string(),
            route_reason: RouteReason::ContainsAwaitKeyword,
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        let decoded: EvalOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, outcome);
    }

    // -----------------------------------------------------------------------
    // sorted_eval_errors (non-in-place variant)
    // -----------------------------------------------------------------------

    #[test]
    fn sorted_eval_errors_returns_new_sorted_vec() {
        let errors = vec![EvalError::runtime_fault("b"), EvalError::parse_failure("a")];
        let sorted = sorted_eval_errors(errors);
        assert_eq!(sorted[0].code, EvalErrorCode::ParseFailure);
        assert_eq!(sorted[1].code, EvalErrorCode::RuntimeFault);
    }

    // -----------------------------------------------------------------------
    // propagate_result_across_boundary
    // -----------------------------------------------------------------------

    #[test]
    fn propagate_result_ok_passes_through() {
        let result: EvalResult<i32> = Ok(42);
        let propagated = propagate_result_across_boundary(result, ExceptionBoundary::AsyncJob);
        assert_eq!(propagated.unwrap(), 42);
    }

    #[test]
    fn propagate_result_err_annotates_boundary() {
        let result: EvalResult<i32> = Err(EvalError::runtime_fault("oops"));
        let propagated = propagate_result_across_boundary(result, ExceptionBoundary::Hostcall);
        let err = propagated.unwrap_err();
        assert!(err.message.contains("boundary=hostcall"));
        assert_eq!(err.code, EvalErrorCode::RuntimeFault);
    }

    // -----------------------------------------------------------------------
    // ExceptionBoundary
    // -----------------------------------------------------------------------

    #[test]
    fn exception_boundary_stable_labels() {
        assert_eq!(
            ExceptionBoundary::SyncCallframe.stable_label(),
            "sync_callframe"
        );
        assert_eq!(ExceptionBoundary::AsyncJob.stable_label(), "async_job");
        assert_eq!(ExceptionBoundary::Hostcall.stable_label(), "hostcall");
    }

    #[test]
    fn exception_boundary_display_matches_stable_label() {
        for boundary in &[
            ExceptionBoundary::SyncCallframe,
            ExceptionBoundary::AsyncJob,
            ExceptionBoundary::Hostcall,
        ] {
            assert_eq!(format!("{boundary}"), boundary.stable_label());
        }
    }

    #[test]
    fn exception_boundary_serde_round_trip() {
        for boundary in &[
            ExceptionBoundary::SyncCallframe,
            ExceptionBoundary::AsyncJob,
            ExceptionBoundary::Hostcall,
        ] {
            let json = serde_json::to_string(boundary).expect("serialize");
            let decoded: ExceptionBoundary = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, boundary);
        }
    }

    // -----------------------------------------------------------------------
    // EvalErrorClass stable_label
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_class_stable_labels_are_all_lowercase() {
        let classes = [
            EvalErrorClass::Parse,
            EvalErrorClass::Resolution,
            EvalErrorClass::Policy,
            EvalErrorClass::Capability,
            EvalErrorClass::Runtime,
            EvalErrorClass::Hostcall,
            EvalErrorClass::Invariant,
        ];
        for class in &classes {
            let label = class.stable_label();
            assert_eq!(
                label,
                label.to_lowercase(),
                "stable_label must be lowercase: {label}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // EvalErrorCode stable_namespace uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_code_stable_namespaces_are_unique() {
        use std::collections::BTreeSet;
        let codes = [
            EvalErrorCode::EmptySource,
            EvalErrorCode::ParseFailure,
            EvalErrorCode::ResolutionFailure,
            EvalErrorCode::PolicyDenied,
            EvalErrorCode::CapabilityDenied,
            EvalErrorCode::RuntimeFault,
            EvalErrorCode::HostcallFault,
            EvalErrorCode::InvariantViolation,
        ];
        let namespaces: BTreeSet<&str> = codes.iter().map(|c| c.stable_namespace()).collect();
        assert_eq!(
            namespaces.len(),
            codes.len(),
            "all stable namespaces must be unique"
        );
    }

    // -----------------------------------------------------------------------
    // Direct engine eval preserves trimmed source
    // -----------------------------------------------------------------------

    #[test]
    fn quickjs_engine_trims_and_returns_source() {
        let mut engine = QuickJsInspiredNativeEngine;
        let out = engine.eval("  hello  ").unwrap();
        assert_eq!(out.value, "hello");
        assert_eq!(out.engine, EngineKind::QuickJsInspiredNative);
    }

    #[test]
    fn v8_engine_trims_and_returns_source() {
        let mut engine = V8InspiredNativeEngine;
        let out = engine.eval("  world  ").unwrap();
        assert_eq!(out.value, "world");
        assert_eq!(out.engine, EngineKind::V8InspiredNative);
    }

    #[test]
    fn control_plane_adoption_adr_contains_required_sections() {
        let adr_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/adr/ADR-0001-control-plane-adoption-asupersync.md");
        let adr = fs::read_to_string(&adr_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

        let required_sections = [
            "## Canonical Imported Types",
            "## Version Policy",
            "## Escalation Path for Missing APIs",
        ];
        for section in required_sections {
            assert!(
                adr.contains(section),
                "ADR must contain required section: {section}"
            );
        }

        let required_types = [
            "Cx",
            "TraceId",
            "DecisionId",
            "PolicyId",
            "SchemaVersion",
            "Budget",
        ];
        for type_name in required_types {
            assert!(
                adr.contains(&format!("`{type_name}`")),
                "ADR must reference canonical type `{type_name}`"
            );
        }
    }
}
