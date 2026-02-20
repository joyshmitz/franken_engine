#![forbid(unsafe_code)]

pub mod alloc_domain;
pub mod ambient_authority;
pub mod anti_entropy;
pub mod bulkhead;
pub mod cancel_mask;
pub mod canonical_encoding;
pub mod capability;
pub mod capability_token;
pub mod checkpoint;
pub mod checkpoint_frontier;
pub mod deterministic_serde;
pub mod engine_object_id;
pub mod epoch_barrier;
pub mod eprocess_guardrail;
pub mod evidence_contract;
pub mod evidence_ledger;
pub mod evidence_ordering;
pub mod fork_detection;
pub mod gc;
pub mod gc_pause;
pub mod hash_tiers;
pub mod idempotency_key;
pub mod interleaving_explorer;
pub mod key_derivation;
pub mod lab_runtime;
pub mod lease_tracker;
pub mod marker_stream;
pub mod mmr_proof;
pub mod monitor_scheduler;
pub mod obligation_channel;
pub mod obligation_leak_policy;
pub mod phase_gate;
pub mod policy_checkpoint;
pub mod policy_controller;
pub mod proof_schema;
pub mod recovery_artifact;
pub mod regime_detector;
pub mod region_lifecycle;
pub mod remote_capability_gate;
pub mod remote_computation_registry;
pub mod saga_orchestrator;
pub mod scheduler_lane;
pub mod security_epoch;
pub mod signature_preimage;
pub mod slot_registry;
pub mod sorted_multisig;
pub mod supervision;

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvalErrorCode {
    EmptySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalError {
    pub code: EvalErrorCode,
    pub message: String,
}

impl EvalError {
    fn empty_source() -> Self {
        Self {
            code: EvalErrorCode::EmptySource,
            message: "source is empty".to_string(),
        }
    }
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl Error for EvalError {}

pub type EvalResult<T> = std::result::Result<T, EvalError>;

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

        assert_eq!(
            quickjs
                .eval(" ")
                .expect_err("expected empty source error")
                .code,
            EvalErrorCode::EmptySource
        );
        assert_eq!(
            v8.eval("\t").expect_err("expected empty source error").code,
            EvalErrorCode::EmptySource
        );
    }

    #[test]
    fn hybrid_rejects_empty_source_with_stable_error_code() {
        let mut router = HybridRouter::default();
        assert_eq!(
            router
                .eval(" ")
                .expect_err("expected empty source error")
                .code,
            EvalErrorCode::EmptySource
        );
    }
}
