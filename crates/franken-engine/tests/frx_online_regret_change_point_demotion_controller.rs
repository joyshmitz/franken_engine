#![forbid(unsafe_code)]

use std::{collections::BTreeMap, fs, path::PathBuf};

use frankenengine_engine::hybrid_lane_router::{
    ChangePointConfig, ConformalConfig, DemotionReason, HybridLaneRouter, LaneChoice,
    LaneObservation, RiskBudget, RouterConfig, RoutingPolicy,
};
use frankenengine_engine::runtime_decision_core::{
    FallbackReason, LaneId, RegimeEstimate, RoutingDecisionInput, RuntimeDecisionCore,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn default_risk_posteriors() -> BTreeMap<String, i64> {
    let mut risk = BTreeMap::new();
    risk.insert("compatibility".to_string(), 100_000);
    risk.insert("latency".to_string(), 100_000);
    risk.insert("memory".to_string(), 100_000);
    risk.insert("incident_severity".to_string(), 100_000);
    risk
}

fn make_input(
    observed_latency_us: u64,
    calibration_covered: bool,
    timestamp_ns: u64,
) -> RoutingDecisionInput {
    RoutingDecisionInput {
        observed_latency_us,
        risk_posteriors: default_risk_posteriors(),
        regime: RegimeEstimate::Normal,
        confidence_millionths: 950_000,
        is_adverse: false,
        nonconformity_score_millionths: 100_000,
        calibration_covered,
        compute_ms: 1,
        memory_mb: 32,
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns,
    }
}

fn neutral_observation(lane: LaneChoice) -> LaneObservation {
    LaneObservation {
        lane,
        latency_us: 1_000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 10,
        safe_mode_entered: false,
        compatibility_errors: 0,
    }
}

#[test]
fn frx_15_3_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_ONLINE_REGRET_CHANGE_POINT_DEMOTION_CONTROLLER_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Online Regret + Change-Point Demotion Controller v1",
        "## Scope",
        "## Inputs",
        "## Deterministic Threshold Policy",
        "## Demotion Semantics",
        "## Structured Event Contract",
        "## Incident Artifact Requirements",
        "## Gate Commands",
        "## Failure Policy",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing FRX-15.3 contract section: {section}"
        );
    }

    for clause in [
        "Fail-closed",
        "CVaR",
        "Calibration",
        "change-point",
        "regret",
    ] {
        assert!(
            doc.contains(clause),
            "missing FRX-15.3 contract clause: {clause}"
        );
    }
}

#[test]
fn frx_15_3_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_online_regret_change_point_demotion_controller_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.online-regret-change-point-demotion-controller.v1")
    );
    assert_eq!(value["generated_by"].as_str(), Some("bd-mjh3.15.3"));
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.15.3"));
    assert_eq!(
        value["demotion_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["integration"]["runtime_decision_core"]["requires_cvar_gate"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["integration"]["runtime_decision_core"]["requires_calibration_gate"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["artifacts"]["suite_script"].as_str(),
        Some("scripts/run_frx_online_regret_change_point_demotion_controller_suite.sh")
    );
    assert_eq!(
        value["artifacts"]["replay_script"].as_str(),
        Some("scripts/e2e/frx_online_regret_change_point_demotion_controller_replay.sh")
    );

    let fields = value["logging"]["required_fields"]
        .as_array()
        .expect("logging.required_fields must be an array");
    for required in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            fields.iter().any(|entry| entry.as_str() == Some(required)),
            "missing required structured log field: {required}"
        );
    }
}

#[test]
fn frx_15_3_readme_registers_gate_commands() {
    let readme_path = repo_root().join("README.md");
    let readme = fs::read_to_string(&readme_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", readme_path.display()));

    assert!(readme.contains("## FRX Online Regret + Change-Point Demotion Controller Gate"));
    assert!(
        readme.contains(
            "./scripts/run_frx_online_regret_change_point_demotion_controller_suite.sh ci"
        )
    );
    assert!(
        readme.contains(
            "./scripts/e2e/frx_online_regret_change_point_demotion_controller_replay.sh ci"
        )
    );
    assert!(readme.contains(
        "artifacts/frx_online_regret_change_point_demotion_controller/<timestamp>/run_manifest.json"
    ));
}

#[test]
fn frx_15_3_runtime_core_integrates_tail_risk_and_calibration_fallbacks() {
    let lanes = vec![LaneId::quickjs_native(), LaneId::v8_native()];
    let mut cvar_core = RuntimeDecisionCore::new(
        "frx-15-3-cvar",
        lanes.clone(),
        LaneId::quickjs_native(),
        SecurityEpoch::from_raw(1),
    )
    .expect("runtime decision core should construct");

    cvar_core.cvar_constraint.max_cvar_us = 500;
    let cvar_out = cvar_core
        .decide(&make_input(20_000, true, 1))
        .expect("cvar decision should execute");
    assert!(cvar_out.fallback_triggered);
    assert!(matches!(
        cvar_out.fallback_reason,
        Some(FallbackReason::CVaRViolation { .. })
    ));

    let mut calibration_core = RuntimeDecisionCore::new(
        "frx-15-3-calibration",
        lanes,
        LaneId::quickjs_native(),
        SecurityEpoch::from_raw(1),
    )
    .expect("runtime decision core should construct");

    calibration_core.cvar_constraint.max_cvar_us = u64::MAX;

    let mut last = None;
    for idx in 0..24u64 {
        let out = calibration_core
            .decide(&make_input(100, false, idx + 10))
            .expect("calibration decision should execute");
        last = Some(out);
    }

    let last = last.expect("at least one decision output expected");
    assert!(last.fallback_triggered);
    assert!(matches!(
        last.fallback_reason,
        Some(FallbackReason::CalibrationUndercoverage { .. })
    ));
    assert!(
        !calibration_core.fallback_events.is_empty(),
        "fallback events must record calibration-triggered demotion"
    );
}

#[test]
fn frx_15_3_hybrid_router_regret_budget_breach_demotes_deterministically() {
    let mut config = RouterConfig::default_config();
    config.risk_budget = RiskBudget {
        tail_latency_budget_us: u64::MAX,
        compatibility_error_budget: u64::MAX,
        regret_budget_millionths: 5,
    };
    config.change_point = ChangePointConfig {
        threshold_millionths: i64::MAX,
        drift_millionths: 50_000,
        min_observations: u64::MAX,
    };
    config.conformal = ConformalConfig {
        target_coverage_millionths: 0,
        min_observations: u64::MAX,
        window_size: 1,
    };

    let mut router = HybridLaneRouter::new(config);
    router
        .promote_to_adaptive()
        .expect("router should promote to adaptive");

    router.risk.cumulative_regret_millionths = 10;

    let trace = router.observe(
        LaneChoice::Js,
        &neutral_observation(LaneChoice::Js),
        Some(42_000),
    );

    assert!(matches!(
        trace.demotion_reason,
        Some(DemotionReason::RegretExceeded { .. })
    ));
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn frx_15_3_hybrid_router_change_point_breach_demotes_deterministically() {
    let mut config = RouterConfig::default_config();
    config.risk_budget = RiskBudget {
        tail_latency_budget_us: u64::MAX,
        compatibility_error_budget: u64::MAX,
        regret_budget_millionths: i64::MAX,
    };
    config.change_point = ChangePointConfig {
        threshold_millionths: 100,
        drift_millionths: 0,
        min_observations: 1,
    };
    config.conformal = ConformalConfig {
        target_coverage_millionths: 0,
        min_observations: u64::MAX,
        window_size: 1,
    };

    let mut router = HybridLaneRouter::new(config);
    router
        .promote_to_adaptive()
        .expect("router should promote to adaptive");

    router.change_point.observation_count = 1;
    router.change_point.cusum_upper_millionths = 101;

    let trace = router.observe(
        LaneChoice::Wasm,
        &neutral_observation(LaneChoice::Wasm),
        Some(99_000),
    );

    assert!(matches!(
        trace.demotion_reason,
        Some(DemotionReason::ChangePointDetected { .. })
    ));
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn frx_15_3_deterministic_sequence_replays_identically() {
    fn run_sequence() -> Vec<Option<DemotionReason>> {
        let mut config = RouterConfig::default_config();
        config.risk_budget = RiskBudget {
            tail_latency_budget_us: u64::MAX,
            compatibility_error_budget: u64::MAX,
            regret_budget_millionths: 20,
        };
        config.change_point = ChangePointConfig {
            threshold_millionths: i64::MAX,
            drift_millionths: 50_000,
            min_observations: u64::MAX,
        };
        config.conformal = ConformalConfig {
            target_coverage_millionths: 0,
            min_observations: u64::MAX,
            window_size: 1,
        };

        let mut router = HybridLaneRouter::new(config);
        router
            .promote_to_adaptive()
            .expect("router should promote to adaptive");

        let mut traces = Vec::new();

        // Round 0: no breach
        traces.push(
            router
                .observe(
                    LaneChoice::Js,
                    &neutral_observation(LaneChoice::Js),
                    Some(10_000),
                )
                .demotion_reason,
        );

        // Round 1: deterministic regret breach
        router.risk.cumulative_regret_millionths = 25;
        traces.push(
            router
                .observe(
                    LaneChoice::Js,
                    &neutral_observation(LaneChoice::Js),
                    Some(20_000),
                )
                .demotion_reason,
        );

        traces
    }

    let a = run_sequence();
    let b = run_sequence();

    assert_eq!(
        a, b,
        "deterministic replay must produce identical demotion traces"
    );
}
