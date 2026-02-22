use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::shadow_ablation_engine::{
    AblationFailureClass, AblationSearchStrategy, ShadowAblationConfig, ShadowAblationEngine,
    ShadowAblationError, ShadowAblationObservation,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::static_authority_analyzer::{
    AnalysisConfig, Capability, EffectEdge, EffectGraph, EffectNode, EffectNodeKind,
    ManifestIntents, StaticAnalysisReport, StaticAuthorityAnalyzer,
};
use frankenengine_engine::synthesis_budget::{PhaseConsumption, SynthesisBudgetContract};

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn cap_set(names: &[&str]) -> BTreeSet<Capability> {
    names.iter().map(|name| cap(name)).collect()
}

fn make_static_report(extension_id: &str, capabilities: &[&str]) -> StaticAnalysisReport {
    let mut graph = EffectGraph::new(extension_id);
    graph.add_node(EffectNode {
        node_id: "entry".to_string(),
        kind: EffectNodeKind::Entry,
        source_location: Some("main.rs:1".to_string()),
    });

    let mut previous = "entry".to_string();
    for (index, capability) in capabilities.iter().enumerate() {
        let node_id = format!("hostcall-{index}");
        graph.add_node(EffectNode {
            node_id: node_id.clone(),
            kind: EffectNodeKind::HostcallSite {
                capability: cap(capability),
            },
            source_location: Some(format!("main.rs:{}", index + 2)),
        });
        graph.add_edge(EffectEdge {
            from: previous.clone(),
            to: node_id.clone(),
            provably_dead: false,
        });
        previous = node_id;
    }

    graph.add_node(EffectNode {
        node_id: "exit".to_string(),
        kind: EffectNodeKind::Exit,
        source_location: Some("main.rs:999".to_string()),
    });
    graph.add_edge(EffectEdge {
        from: previous,
        to: "exit".to_string(),
        provably_dead: false,
    });

    let manifest = ManifestIntents {
        extension_id: extension_id.to_string(),
        declared_capabilities: cap_set(capabilities),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(AnalysisConfig {
        time_budget_ns: 1_000_000,
        path_sensitive: true,
        zone: "test-zone".to_string(),
    });
    analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(7), 99)
        .expect("static analysis report")
}

fn base_config(extension_id: &str, seed: u64) -> ShadowAblationConfig {
    ShadowAblationConfig {
        trace_id: format!("trace-{extension_id}"),
        decision_id: format!("decision-{extension_id}"),
        policy_id: format!("policy-{extension_id}"),
        extension_id: extension_id.to_string(),
        replay_corpus_id: "replay-corpus-v1".to_string(),
        randomness_snapshot_id: "rng-snapshot-v1".to_string(),
        deterministic_seed: seed,
        strategy: AblationSearchStrategy::LatticeGreedy,
        required_invariants: BTreeSet::from([
            "no_exfiltration".to_string(),
            "deterministic_replay".to_string(),
        ]),
        max_pair_trials: 64,
        max_block_trials: 64,
        zone: "test-zone".to_string(),
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([0x2Au8; 32])
}

#[test]
fn finds_minimal_capability_set_and_signs_transcript() {
    let extension_id = "ext-minimal";
    let report = make_static_report(extension_id, &["clock", "env", "fs_read", "net_outbound"]);
    let config = base_config(extension_id, 4242);
    let engine = ShadowAblationEngine::new(config.clone(), SynthesisBudgetContract::default())
        .expect("engine construction");

    let required = cap_set(&["clock", "net_outbound"]);
    let result = engine
        .run(&report, &signing_key(), move |request| {
            let has_required = required.is_subset(&request.candidate_capabilities);
            Ok(ShadowAblationObservation {
                correctness_score_millionths: if has_required { 992_000 } else { 410_000 },
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::from([
                    ("no_exfiltration".to_string(), has_required),
                    ("deterministic_replay".to_string(), true),
                ]),
                risk_score_millionths: if has_required { 180_000 } else { 880_000 },
                risk_threshold_millionths: 300_000,
                consumed: PhaseConsumption {
                    time_ns: 15_000,
                    compute: 8,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", request.candidate_id),
                evidence_pointer: format!("evidence://{}", request.candidate_id),
                execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                failure_detail: if has_required {
                    None
                } else {
                    Some("required capability missing".to_string())
                },
            })
        })
        .expect("ablation run");

    assert_eq!(
        result.minimal_capabilities,
        cap_set(&["clock", "net_outbound"])
    );
    assert!(!result.budget_exhausted);
    assert!(result.fallback.is_none());
    assert!(!result.evaluations.is_empty());

    assert!(result.logs.iter().all(|event| {
        event.trace_id == config.trace_id
            && event.decision_id == config.decision_id
            && event.policy_id == config.policy_id
            && event.component == "shadow_ablation_engine"
    }));

    result
        .transcript
        .verify_signature()
        .expect("signed transcript must verify");
}

#[test]
fn deterministic_ordering_replays_identically_for_same_seed() {
    let extension_id = "ext-deterministic";
    let report = make_static_report(
        extension_id,
        &["clock", "env", "fs_read", "net_outbound", "telemetry_emit"],
    );
    let mut config = base_config(extension_id, 77);
    config.max_pair_trials = 0;
    config.required_invariants = BTreeSet::new();

    let run_once = |cfg: ShadowAblationConfig| {
        let engine = ShadowAblationEngine::new(cfg, SynthesisBudgetContract::default())
            .expect("engine construction");
        engine
            .run(&report, &signing_key(), |request| {
                Ok(ShadowAblationObservation {
                    correctness_score_millionths: 500_000,
                    correctness_threshold_millionths: 900_000,
                    invariants: BTreeMap::new(),
                    risk_score_millionths: 900_000,
                    risk_threshold_millionths: 300_000,
                    consumed: PhaseConsumption {
                        time_ns: 5_000,
                        compute: 2,
                        depth: 1,
                    },
                    replay_pointer: format!("replay://{}", request.candidate_id),
                    evidence_pointer: format!("evidence://{}", request.candidate_id),
                    execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                    failure_detail: Some("candidate fails deterministically".to_string()),
                })
            })
            .expect("ablation run")
    };

    let first = run_once(config.clone());
    let second = run_once(config.clone());
    let mut different_seed = config.clone();
    different_seed.deterministic_seed = 78;
    let third = run_once(different_seed);

    let first_ids = first
        .evaluations
        .iter()
        .map(|evaluation| evaluation.candidate_id.clone())
        .collect::<Vec<_>>();
    let second_ids = second
        .evaluations
        .iter()
        .map(|evaluation| evaluation.candidate_id.clone())
        .collect::<Vec<_>>();
    let third_ids = third
        .evaluations
        .iter()
        .map(|evaluation| evaluation.candidate_id.clone())
        .collect::<Vec<_>>();

    assert_eq!(first_ids, second_ids);
    assert_ne!(first_ids, third_ids);
    assert_eq!(
        first.transcript.transcript_hash,
        second.transcript.transcript_hash
    );
    assert_eq!(
        first.transcript.unsigned_bytes(),
        second.transcript.unsigned_bytes()
    );
}

#[test]
fn adversarial_probe_behavior_forces_capability_retention() {
    let extension_id = "ext-adversarial";
    let report = make_static_report(extension_id, &["clock", "net_outbound", "env_probe"]);
    let mut config = base_config(extension_id, 101);
    config.required_invariants = BTreeSet::from([
        "no_exfiltration".to_string(),
        "anti_probe_tamper".to_string(),
    ]);
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");

    let required = cap_set(&["clock", "net_outbound"]);
    let result = engine
        .run(&report, &signing_key(), move |request| {
            let has_required = required.is_subset(&request.candidate_capabilities);
            let anti_probe = request.candidate_capabilities.contains(&cap("env_probe"));
            Ok(ShadowAblationObservation {
                correctness_score_millionths: if has_required { 970_000 } else { 300_000 },
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::from([
                    ("no_exfiltration".to_string(), has_required),
                    ("anti_probe_tamper".to_string(), anti_probe),
                ]),
                risk_score_millionths: if anti_probe { 190_000 } else { 760_000 },
                risk_threshold_millionths: 320_000,
                consumed: PhaseConsumption {
                    time_ns: 20_000,
                    compute: 9,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", request.candidate_id),
                evidence_pointer: format!("evidence://{}", request.candidate_id),
                execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                failure_detail: if anti_probe {
                    None
                } else {
                    Some("capability-probe evasion detected".to_string())
                },
            })
        })
        .expect("ablation run");

    assert_eq!(
        result.minimal_capabilities,
        cap_set(&["clock", "net_outbound", "env_probe"])
    );
    assert!(result.evaluations.iter().any(|evaluation| {
        evaluation.failure_class == Some(AblationFailureClass::InvariantViolation)
    }));
}

#[test]
fn budget_exhaustion_returns_fail_closed_fallback() {
    let extension_id = "ext-budget";
    let report = make_static_report(extension_id, &["clock", "net_outbound", "fs_read"]);
    let mut config = base_config(extension_id, 88);
    config.max_pair_trials = 0;

    let tight_budget = SynthesisBudgetContract {
        version: 1,
        global_time_cap_ns: 1_000,
        global_compute_cap: 3,
        global_depth_cap: 1,
        phase_budgets: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
    };
    let engine = ShadowAblationEngine::new(config, tight_budget).expect("engine construction");

    let result = engine
        .run(&report, &signing_key(), |request| {
            Ok(ShadowAblationObservation {
                correctness_score_millionths: 960_000,
                correctness_threshold_millionths: 900_000,
                invariants: BTreeMap::from([
                    ("no_exfiltration".to_string(), true),
                    ("deterministic_replay".to_string(), true),
                ]),
                risk_score_millionths: 180_000,
                risk_threshold_millionths: 300_000,
                consumed: PhaseConsumption {
                    time_ns: 2_000,
                    compute: 5,
                    depth: 1,
                },
                replay_pointer: format!("replay://{}", request.candidate_id),
                evidence_pointer: format!("evidence://{}", request.candidate_id),
                execution_trace_hash: ContentHash::compute(request.candidate_id.as_bytes()),
                failure_detail: None,
            })
        })
        .expect("ablation run");

    assert!(result.budget_exhausted);
    assert_eq!(result.minimal_capabilities, report.upper_bound_capabilities);
    let fallback = result.fallback.expect("fallback must exist");
    assert_eq!(
        fallback.quality.to_string(),
        frankenengine_engine::synthesis_budget::FallbackQuality::StaticBound.to_string()
    );
    assert!(
        result
            .logs
            .iter()
            .any(|event| { event.error_code.as_deref() == Some("ablation_budget_exhausted") })
    );
    result
        .transcript
        .verify_signature()
        .expect("signed transcript must verify");
}

#[test]
fn engine_rejects_extension_mismatch() {
    let report = make_static_report("ext-report", &["clock"]);
    let config = base_config("ext-config", 1);
    let engine = ShadowAblationEngine::new(config, SynthesisBudgetContract::default())
        .expect("engine construction");
    let err = engine
        .run(&report, &signing_key(), |_request| {
            Err(ShadowAblationError::InvalidOracleResult {
                detail: "not used".to_string(),
            })
        })
        .expect_err("mismatch must fail");
    assert!(err.to_string().contains("extension mismatch"));
}
