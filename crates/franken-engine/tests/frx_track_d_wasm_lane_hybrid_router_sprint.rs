use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_track_d_charter_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TRACK_D_WASM_LANE_HYBRID_ROUTER_SPRINT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Track D WASM Lane + Hybrid Router Sprint Charter v1",
        "## Charter Scope",
        "## Decision Rights",
        "## Responsibilities",
        "## Inputs",
        "## Outputs",
        "## WASM Scheduler and ABI Contract",
        "## Hybrid Router Calibration and Safety Override Contract",
        "## Deterministic Replay and Failover Contract",
        "## Interface Contracts",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "track D charter missing section: {section}"
        );
    }

    let required_clauses = [
        "wasm scheduler determinism",
        "abi overhead budget",
        "hybrid router calibration",
        "conservative override",
        "fallback events",
        "replay linkage",
        "fail closed",
        "verification and governance signoff artifacts",
    ];

    let doc_lower = doc.to_ascii_lowercase();
    for clause in required_clauses {
        assert!(
            doc_lower.contains(clause),
            "track D charter missing clause: {clause}"
        );
    }
}

#[test]
fn frx_track_d_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_track_d_wasm_lane_hybrid_router_sprint_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.track-d.wasm-lane-hybrid-router.contract.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.11.4"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.11.4"));
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-11.4"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_calibration_evidence"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_failover_replay_linkage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["requires_verification_and_governance_signoff"].as_bool(),
        Some(true)
    );

    let required_fields = value["outputs"]["router_decision_artifact"]["required_fields"]
        .as_array()
        .expect("router required fields must be an array");

    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "lane_choice",
        "calibration_snapshot_id",
        "override_reason",
        "failover_event_id",
        "abi_overhead_us",
    ] {
        assert!(
            required_fields
                .iter()
                .any(|entry| entry.as_str() == Some(field)),
            "router decision field missing: {field}"
        );
    }
}

#[test]
fn frx_track_d_runtime_sources_expose_required_surfaces() {
    let wasm_path = repo_root().join("crates/franken-engine/src/wasm_runtime_lane.rs");
    let wasm = fs::read_to_string(&wasm_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", wasm_path.display()));

    for snippet in [
        "pub struct WasmRuntimeLane",
        "pub enum SafeModeReason",
        "pub struct WasmFlushResult",
        "pub fn flush(&mut self) -> WasmFlushResult",
        "pub fn derive_id(&self) -> EngineObjectId",
    ] {
        assert!(
            wasm.contains(snippet),
            "wasm runtime lane missing required surface: {snippet}"
        );
    }

    let router_path = repo_root().join("crates/franken-engine/src/hybrid_lane_router.rs");
    let router = fs::read_to_string(&router_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", router_path.display()));

    for snippet in [
        "pub struct HybridLaneRouter",
        "pub struct RoutingDecisionTrace",
        "pub enum DemotionReason",
        "pub fn observe(",
        "pub fn manual_demote(&mut self) -> Result<(), RouterError>",
    ] {
        assert!(
            router.contains(snippet),
            "hybrid lane router missing required surface: {snippet}"
        );
    }
}

#[test]
fn frx_track_d_readme_gate_instructions_present() {
    let path = repo_root().join("README.md");
    let readme = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    assert!(
        readme.contains("## FRX Track D WASM Lane + Hybrid Router Sprint Gate"),
        "README missing track D gate heading"
    );
    assert!(
        readme.contains("./scripts/run_frx_track_d_wasm_lane_hybrid_router_sprint_suite.sh ci"),
        "README missing track D gate command"
    );
    assert!(
        readme.contains("./scripts/e2e/frx_track_d_wasm_lane_hybrid_router_sprint_replay.sh"),
        "README missing track D replay command"
    );
}
