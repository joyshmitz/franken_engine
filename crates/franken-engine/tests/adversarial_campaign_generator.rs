#[path = "../src/adversarial_campaign.rs"]
mod adversarial_campaign;

use adversarial_campaign::{
    AdversarialCampaign, AttackGrammar, CampaignComplexity, CampaignExecutionResult,
    CampaignGenerator, CampaignGeneratorConfig, ContainmentDifficulty, ExploitObjectiveScore,
    MutationEngine, MutationOperator, MutationRequest,
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
