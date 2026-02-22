#![forbid(unsafe_code)]

pub mod activation_lifecycle;
pub mod adversarial_campaign;
pub mod alloc_domain;
pub mod ambient_authority;
pub mod anti_entropy;
pub mod ast;
pub mod attestation_handshake;
pub mod attested_execution_cell;
pub mod bayesian_posterior;
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
pub mod compiler_policy;
pub mod conformance_catalog;
pub mod conformance_harness;
pub mod conformance_vector_gen;
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
pub mod expected_loss_selector;
pub mod extension_host_authority_guard;
pub mod extension_host_lifecycle;
pub mod feature_parity_tracker;
pub mod fleet_convergence;
pub mod fleet_immune_protocol;
pub mod flow_envelope;
pub mod forensic_replayer;
pub mod fork_detection;
pub mod frankenlab_extension_lifecycle;
pub mod frankenlab_release_gate;
pub mod frankentui_adapter;
pub mod gc;
pub mod gc_pause;
pub mod golden_vectors;
pub mod guardplane_calibration;
pub mod hash_tiers;
pub mod hostcall_telemetry;
pub mod idempotency_key;
pub mod ifc_artifacts;
pub mod ifc_provenance_index;
pub mod incident_replay_bundle;
pub mod interleaving_explorer;
pub mod key_attestation;
pub mod key_derivation;
pub mod lab_runtime;
pub mod lease_tracker;
pub mod marker_stream;
pub mod migration_compatibility;
pub mod migration_contract;
pub mod mmr_proof;
pub mod monitor_scheduler;
pub mod moonshot_contract;
pub mod obligation_channel;
pub mod obligation_integration;
pub mod obligation_leak_policy;
pub mod parser;
pub mod phase_gate;
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
pub mod proof_specialization_receipt;
pub mod quarantine_mesh_gate;
pub mod recovery_artifact;
pub mod regime_detector;
pub mod region_lifecycle;
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
pub mod threshold_signing;
pub mod translation_validation;
pub mod trust_card;
pub mod trust_economics;
pub mod trust_zone;
pub mod version_matrix_lane;

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
