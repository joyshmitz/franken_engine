#[path = "../src/adversarial_campaign.rs"]
mod adversarial_campaign;

use adversarial_campaign::{
    AdversarialCampaign, AttackGrammar, CampaignComplexity, CampaignExecutionResult,
    CampaignGenerator, CampaignGeneratorConfig, CampaignRuntime, CampaignSuppressionSample,
    CampaignTrendPoint, ContainmentDifficulty, ExploitEscalationRecord, ExploitObjectiveScore,
    MutationEngine, MutationOperator, MutationRequest, SuppressionGateConfig, SuppressionGateInput,
    evaluate_compromise_suppression_gate,
};

#[test]
fn adversarial_campaign_lifecycle_generation_scoring_mutation_and_promotion() {
    let grammar = AttackGrammar::default();
    let config = CampaignGeneratorConfig {
        policy_id: "policy-lifecycle".to_string(),
        campaigns_per_hour: 1,
        max_backpressure_queue: 4,
        promotion_threshold_millionths: 500_000,
    };
    let mut generator = CampaignGenerator::new(grammar.clone(), config, 0xABCD).expect("generator");

    let campaign = generator
        .generate_campaign(CampaignComplexity::MultiStage)
        .expect("campaign");
    campaign.validate().expect("valid campaign");

    let score = generator
        .score_campaign(
            &campaign,
            &CampaignExecutionResult {
                undetected_steps: campaign.steps.len(),
                total_steps: campaign.steps.len(),
                objective_achieved_before_containment: true,
                damage_potential_millionths: 900_000,
                evidence_atoms_before_detection: 70,
                novel_technique: true,
            },
        )
        .expect("score");
    assert_eq!(score.difficulty, ContainmentDifficulty::Critical);

    generator
        .record_campaign_outcome(&campaign, &score)
        .expect("record score");

    let mutated = MutationEngine::mutate(
        &campaign,
        &grammar,
        MutationRequest {
            operator: MutationOperator::PointMutation,
            seed: 0x7777,
            donor_campaign: None,
        },
    )
    .expect("mutate");
    mutated.validate().expect("mutated campaign valid");

    let fixture = generator
        .promote_failure_fixture(&mutated, "containment", "evasion", |candidate| {
            candidate.steps.len() >= 2
        })
        .expect("promote fixture");

    assert_eq!(generator.regression_corpus().len(), 1);
    assert!(
        generator
            .regression_corpus()
            .fixture(&fixture.campaign_id)
            .is_some()
    );
    assert!(generator.score(&campaign.campaign_id).is_some());
}

#[test]
fn adversarial_campaign_events_expose_required_stable_fields() {
    let mut generator = CampaignGenerator::new(
        AttackGrammar::default(),
        CampaignGeneratorConfig {
            policy_id: "policy-events".to_string(),
            campaigns_per_hour: 2,
            max_backpressure_queue: 6,
            promotion_threshold_millionths: 300_000,
        },
        0x1234,
    )
    .expect("generator");

    let outputs = generator
        .run_cycle(
            CampaignComplexity::Probe,
            0,
            |campaign: &AdversarialCampaign| CampaignExecutionResult {
                undetected_steps: campaign.steps.len().saturating_sub(1),
                total_steps: campaign.steps.len(),
                objective_achieved_before_containment: true,
                damage_potential_millionths: 700_000,
                evidence_atoms_before_detection: 42,
                novel_technique: true,
            },
        )
        .expect("run cycle");

    assert_eq!(outputs.len(), 2);
    for (_, score) in &outputs {
        assert!(score.composite_score_millionths > 0);
    }

    let events = generator.drain_events();
    assert!(!events.is_empty());
    for event in events {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert_eq!(event.component, "adversarial_campaign_generator");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
        if event.event == "campaign_minimization" {
            assert!(event.error_code.is_some());
        }
    }
}

#[test]
fn exploit_objective_scoring_is_replay_deterministic() {
    let baseline = CampaignExecutionResult {
        undetected_steps: 3,
        total_steps: 5,
        objective_achieved_before_containment: false,
        damage_potential_millionths: 450_000,
        evidence_atoms_before_detection: 17,
        novel_technique: false,
    };

    let score_a = ExploitObjectiveScore::from_result(&baseline).expect("score a");
    let score_b = ExploitObjectiveScore::from_result(&baseline).expect("score b");
    assert_eq!(score_a, score_b);
}

#[test]
fn suppression_gate_surface_exposes_required_structured_fields() {
    let sample = |campaign_id: &str,
                  category: adversarial_campaign::CampaignAttackCategory,
                  runtime: CampaignRuntime,
                  attempts: u64,
                  successes: u64| CampaignSuppressionSample {
        campaign_id: campaign_id.to_string(),
        attack_category: category,
        target_runtime: runtime,
        attempt_count: attempts,
        success_count: successes,
        raw_log_ref: format!("artifacts/raw/{campaign_id}.jsonl"),
        repro_script_ref: format!("artifacts/repro/{campaign_id}.sh"),
    };

    let categories = adversarial_campaign::CampaignAttackCategory::ALL;
    let mut samples = Vec::new();
    for category in categories {
        samples.push(sample(
            &format!("fe-{category}"),
            category,
            CampaignRuntime::FrankenEngine,
            180,
            1,
        ));
        samples.push(sample(
            &format!("node-{category}"),
            category,
            CampaignRuntime::NodeLts,
            180,
            28,
        ));
        samples.push(sample(
            &format!("bun-{category}"),
            category,
            CampaignRuntime::BunStable,
            180,
            23,
        ));
    }

    let gate_input = SuppressionGateInput {
        release_candidate_id: "rc-structured-fields".to_string(),
        continuous_run: true,
        samples,
        trend_points: vec![
            CampaignTrendPoint {
                release_candidate_id: "rc-prev-1".to_string(),
                timestamp_ns: 1_700_000_300_000,
                samples_evaluated: 540,
            },
            CampaignTrendPoint {
                release_candidate_id: "rc-prev-2".to_string(),
                timestamp_ns: 1_700_000_400_000,
                samples_evaluated: 560,
            },
        ],
        escalations: vec![ExploitEscalationRecord {
            campaign_id: "fe-injection".to_string(),
            attack_category: adversarial_campaign::CampaignAttackCategory::Injection,
            target_runtime: CampaignRuntime::FrankenEngine,
            successful_exploit: true,
            escalation_triggered: true,
            escalation_latency_seconds: Some(60),
        }],
    };

    let result =
        evaluate_compromise_suppression_gate(&gate_input, &SuppressionGateConfig::default())
            .expect("suppression gate evaluation");

    assert!(result.passed);
    let summary = result
        .events
        .iter()
        .find(|event| event.event == "suppression_gate_evaluated")
        .expect("summary event");
    assert!(!summary.trace_id.is_empty());
    assert!(!summary.decision_id.is_empty());
    assert!(!summary.policy_id.is_empty());
    assert!(!summary.component.is_empty());
    assert!(!summary.event.is_empty());
    assert!(!summary.outcome.is_empty());

    let comparison = result
        .events
        .iter()
        .find(|event| event.event == "suppression_comparison")
        .expect("comparison event");
    assert!(!comparison.attack_category.is_empty());
    assert!(!comparison.target_runtime.is_empty());
    assert!(comparison.attempt_count > 0);
    assert!(comparison.p_value_millionths.is_some());
    assert!(!comparison.confidence_interval.is_empty());
}
