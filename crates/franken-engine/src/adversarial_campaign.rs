//! Continuous adversarial campaign generator.
//!
//! Plan references:
//! - 10.12 item 13 (continuous adversarial campaign generator)
//! - 9F.7 (autonomous red-team generator)
//!
//! The module is deterministic-by-construction:
//! - seeded PRNG (`DeterministicRng`)
//! - stable collections (`BTreeMap`)
//! - stable campaign IDs and event fields
//! - reproducible minimization fixtures

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const COMPONENT: &str = "adversarial_campaign_generator";
const ERR_INVALID_GRAMMAR: &str = "FE-ADV-CAMP-0001";
const ERR_INVALID_CAMPAIGN: &str = "FE-ADV-CAMP-0002";
const ERR_INVALID_RESULT: &str = "FE-ADV-CAMP-0003";
const ERR_INVALID_MUTATION: &str = "FE-ADV-CAMP-0004";
const ERR_INVALID_SEED: &str = "FE-ADV-CAMP-0005";

fn clamp_millionths(value: u64) -> u64 {
    value.min(1_000_000)
}

fn short_hash(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CampaignError {
    InvalidGrammar { detail: String },
    InvalidCampaign { detail: String },
    InvalidExecutionResult { detail: String },
    InvalidMutation { detail: String },
    InvalidSeed,
}

impl CampaignError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidGrammar { .. } => ERR_INVALID_GRAMMAR,
            Self::InvalidCampaign { .. } => ERR_INVALID_CAMPAIGN,
            Self::InvalidExecutionResult { .. } => ERR_INVALID_RESULT,
            Self::InvalidMutation { .. } => ERR_INVALID_MUTATION,
            Self::InvalidSeed => ERR_INVALID_SEED,
        }
    }
}

impl fmt::Display for CampaignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrammar { detail } => write!(f, "invalid grammar: {detail}"),
            Self::InvalidCampaign { detail } => write!(f, "invalid campaign: {detail}"),
            Self::InvalidExecutionResult { detail } => {
                write!(f, "invalid execution result: {detail}")
            }
            Self::InvalidMutation { detail } => write!(f, "invalid mutation: {detail}"),
            Self::InvalidSeed => write!(f, "seed must be non-zero"),
        }
    }
}

impl std::error::Error for CampaignError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn new(seed: u64) -> Result<Self, CampaignError> {
        if seed == 0 {
            return Err(CampaignError::InvalidSeed);
        }
        Ok(Self { state: seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    pub fn choose_index(&mut self, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        (self.next_u64() as usize) % len
    }

    pub fn range_u64(&mut self, start: u64, end_exclusive: u64) -> u64 {
        if end_exclusive <= start {
            return start;
        }
        start + (self.next_u64() % (end_exclusive - start))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CampaignComplexity {
    Probe,
    MultiStage,
    Apt,
}

impl CampaignComplexity {
    fn target_steps(self) -> usize {
        match self {
            Self::Probe => 4,
            Self::MultiStage => 8,
            Self::Apt => 12,
        }
    }
}

impl fmt::Display for CampaignComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe => f.write_str("probe"),
            Self::MultiStage => f.write_str("multi_stage"),
            Self::Apt => f.write_str("apt"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttackDimension {
    HostcallSequence,
    TemporalPayload,
    PrivilegeEscalation,
    PolicyEvasion,
    Exfiltration,
}

impl fmt::Display for AttackDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostcallSequence => f.write_str("hostcall_sequence"),
            Self::TemporalPayload => f.write_str("temporal_payload"),
            Self::PrivilegeEscalation => f.write_str("privilege_escalation"),
            Self::PolicyEvasion => f.write_str("policy_evasion"),
            Self::Exfiltration => f.write_str("exfiltration"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightedProduction {
    pub label: String,
    pub weight: u32,
}

impl WeightedProduction {
    fn validate(&self, bucket: &str) -> Result<(), CampaignError> {
        if self.label.trim().is_empty() {
            return Err(CampaignError::InvalidGrammar {
                detail: format!("{bucket} contains empty production label"),
            });
        }
        if self.weight == 0 {
            return Err(CampaignError::InvalidGrammar {
                detail: format!("{bucket} contains zero-weight production {}", self.label),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackGrammar {
    pub version: u32,
    pub hostcall_motifs: Vec<WeightedProduction>,
    pub temporal_staging: Vec<WeightedProduction>,
    pub privilege_escalation: Vec<WeightedProduction>,
    pub policy_evasion: Vec<WeightedProduction>,
    pub exfiltration: Vec<WeightedProduction>,
}

impl Default for AttackGrammar {
    fn default() -> Self {
        Self {
            version: 1,
            hostcall_motifs: vec![
                WeightedProduction {
                    label: "credential_theft_chain".to_string(),
                    weight: 10,
                },
                WeightedProduction {
                    label: "resource_exhaustion_ladder".to_string(),
                    weight: 8,
                },
                WeightedProduction {
                    label: "covert_channel_hostcalls".to_string(),
                    weight: 6,
                },
            ],
            temporal_staging: vec![
                WeightedProduction {
                    label: "dormant_then_burst".to_string(),
                    weight: 8,
                },
                WeightedProduction {
                    label: "delayed_trigger_wave".to_string(),
                    weight: 6,
                },
            ],
            privilege_escalation: vec![
                WeightedProduction {
                    label: "capability_probe_chain".to_string(),
                    weight: 9,
                },
                WeightedProduction {
                    label: "delegation_boundary_abuse".to_string(),
                    weight: 7,
                },
            ],
            policy_evasion: vec![
                WeightedProduction {
                    label: "benign_mimicry_burst".to_string(),
                    weight: 9,
                },
                WeightedProduction {
                    label: "threshold_edge_dancing".to_string(),
                    weight: 8,
                },
            ],
            exfiltration: vec![
                WeightedProduction {
                    label: "label_covert_egress".to_string(),
                    weight: 9,
                },
                WeightedProduction {
                    label: "staged_fragment_exfil".to_string(),
                    weight: 7,
                },
            ],
        }
    }
}

impl AttackGrammar {
    pub fn validate(&self) -> Result<(), CampaignError> {
        if self.version == 0 {
            return Err(CampaignError::InvalidGrammar {
                detail: "version must be > 0".to_string(),
            });
        }
        Self::validate_bucket(&self.hostcall_motifs, "hostcall_motifs")?;
        Self::validate_bucket(&self.temporal_staging, "temporal_staging")?;
        Self::validate_bucket(&self.privilege_escalation, "privilege_escalation")?;
        Self::validate_bucket(&self.policy_evasion, "policy_evasion")?;
        Self::validate_bucket(&self.exfiltration, "exfiltration")?;
        Ok(())
    }

    fn validate_bucket(bucket: &[WeightedProduction], name: &str) -> Result<(), CampaignError> {
        if bucket.is_empty() {
            return Err(CampaignError::InvalidGrammar {
                detail: format!("{name} must not be empty"),
            });
        }
        for prod in bucket {
            prod.validate(name)?;
        }
        Ok(())
    }

    fn choose_weighted_label(
        productions: &[WeightedProduction],
        rng: &mut DeterministicRng,
    ) -> String {
        let total = productions
            .iter()
            .fold(0u64, |acc, production| acc + production.weight as u64);
        let mut cursor = rng.range_u64(0, total.max(1));
        for production in productions {
            let weight = production.weight as u64;
            if cursor < weight {
                return production.label.clone();
            }
            cursor = cursor.saturating_sub(weight);
        }
        productions
            .last()
            .map(|production| production.label.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn random_dimension(rng: &mut DeterministicRng) -> AttackDimension {
        match rng.choose_index(5) {
            0 => AttackDimension::HostcallSequence,
            1 => AttackDimension::TemporalPayload,
            2 => AttackDimension::PrivilegeEscalation,
            3 => AttackDimension::PolicyEvasion,
            _ => AttackDimension::Exfiltration,
        }
    }

    pub fn generate_step(
        &self,
        step_id: u32,
        rng: &mut DeterministicRng,
    ) -> Result<AttackStep, CampaignError> {
        self.validate()?;
        let dimension = Self::random_dimension(rng);
        let step = match dimension {
            AttackDimension::HostcallSequence => {
                let motif = Self::choose_weighted_label(&self.hostcall_motifs, rng);
                AttackStep {
                    step_id,
                    dimension,
                    production_label: motif.clone(),
                    kind: AttackStepKind::HostcallSequence {
                        motif,
                        hostcall_count: rng.range_u64(2, 9),
                    },
                }
            }
            AttackDimension::TemporalPayload => {
                let stage = Self::choose_weighted_label(&self.temporal_staging, rng);
                AttackStep {
                    step_id,
                    dimension,
                    production_label: stage.clone(),
                    kind: AttackStepKind::TemporalPayload {
                        stage,
                        delay_ms: rng.range_u64(25, 2_000),
                    },
                }
            }
            AttackDimension::PrivilegeEscalation => {
                let probe = Self::choose_weighted_label(&self.privilege_escalation, rng);
                AttackStep {
                    step_id,
                    dimension,
                    production_label: probe.clone(),
                    kind: AttackStepKind::PrivilegeEscalation {
                        probe,
                        escalation_depth: rng.range_u64(1, 5),
                    },
                }
            }
            AttackDimension::PolicyEvasion => {
                let motif = Self::choose_weighted_label(&self.policy_evasion, rng);
                AttackStep {
                    step_id,
                    dimension,
                    production_label: motif.clone(),
                    kind: AttackStepKind::PolicyEvasion {
                        motif,
                        threshold_margin_millionths: rng.range_u64(1, 50_000),
                    },
                }
            }
            AttackDimension::Exfiltration => {
                let strategy = Self::choose_weighted_label(&self.exfiltration, rng);
                AttackStep {
                    step_id,
                    dimension,
                    production_label: strategy.clone(),
                    kind: AttackStepKind::Exfiltration {
                        strategy,
                        chunk_count: rng.range_u64(1, 10),
                    },
                }
            }
        };
        Ok(step)
    }

    pub fn apply_campaign_feedback(
        &mut self,
        campaign: &AdversarialCampaign,
        score: &ExploitObjectiveScore,
    ) {
        let mut per_label_hits: BTreeMap<String, u32> = BTreeMap::new();
        for step in &campaign.steps {
            *per_label_hits
                .entry(step.production_label.clone())
                .or_default() += 1;
        }

        let amplification = if score.evasion_score_millionths >= 700_000 {
            2
        } else {
            0
        };
        let decay = if score.evasion_score_millionths <= 250_000 {
            1
        } else {
            0
        };

        for (label, hits) in per_label_hits {
            let delta = (amplification * hits as i32) - (decay * hits as i32);
            Self::adjust_bucket(&mut self.hostcall_motifs, &label, delta);
            Self::adjust_bucket(&mut self.temporal_staging, &label, delta);
            Self::adjust_bucket(&mut self.privilege_escalation, &label, delta);
            Self::adjust_bucket(&mut self.policy_evasion, &label, delta);
            Self::adjust_bucket(&mut self.exfiltration, &label, delta);
        }
    }

    fn adjust_bucket(bucket: &mut [WeightedProduction], label: &str, delta: i32) {
        for production in bucket {
            if production.label == label {
                let next = (production.weight as i32 + delta).max(1) as u32;
                production.weight = next;
                break;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackStepKind {
    HostcallSequence {
        motif: String,
        hostcall_count: u64,
    },
    TemporalPayload {
        stage: String,
        delay_ms: u64,
    },
    PrivilegeEscalation {
        probe: String,
        escalation_depth: u64,
    },
    PolicyEvasion {
        motif: String,
        threshold_margin_millionths: u64,
    },
    Exfiltration {
        strategy: String,
        chunk_count: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackStep {
    pub step_id: u32,
    pub dimension: AttackDimension,
    pub production_label: String,
    pub kind: AttackStepKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialCampaign {
    pub campaign_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub grammar_version: u32,
    pub seed: u64,
    pub complexity: CampaignComplexity,
    pub steps: Vec<AttackStep>,
}

impl AdversarialCampaign {
    pub fn validate(&self) -> Result<(), CampaignError> {
        if self.campaign_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "campaign_id must not be empty".to_string(),
            });
        }
        if self.trace_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.grammar_version == 0 {
            return Err(CampaignError::InvalidCampaign {
                detail: "grammar_version must be > 0".to_string(),
            });
        }
        if self.seed == 0 {
            return Err(CampaignError::InvalidCampaign {
                detail: "seed must be non-zero".to_string(),
            });
        }
        if self.steps.is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "campaign must contain at least one step".to_string(),
            });
        }
        for (index, step) in self.steps.iter().enumerate() {
            if step.step_id as usize != index {
                return Err(CampaignError::InvalidCampaign {
                    detail: format!(
                        "step_id must be contiguous and 0-based (expected {index}, got {})",
                        step.step_id
                    ),
                });
            }
            if step.production_label.trim().is_empty() {
                return Err(CampaignError::InvalidCampaign {
                    detail: format!("step {index} has empty production_label"),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignExecutionResult {
    pub undetected_steps: usize,
    pub total_steps: usize,
    pub objective_achieved_before_containment: bool,
    pub damage_potential_millionths: u64,
    pub evidence_atoms_before_detection: u64,
    pub novel_technique: bool,
}

impl CampaignExecutionResult {
    pub fn validate(&self) -> Result<(), CampaignError> {
        if self.total_steps == 0 {
            return Err(CampaignError::InvalidExecutionResult {
                detail: "total_steps must be > 0".to_string(),
            });
        }
        if self.undetected_steps > self.total_steps {
            return Err(CampaignError::InvalidExecutionResult {
                detail: "undetected_steps cannot exceed total_steps".to_string(),
            });
        }
        if self.damage_potential_millionths > 1_000_000 {
            return Err(CampaignError::InvalidExecutionResult {
                detail: "damage_potential_millionths cannot exceed 1_000_000".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentDifficulty {
    Easy,
    Moderate,
    Hard,
    Critical,
}

impl fmt::Display for ContainmentDifficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Easy => f.write_str("easy"),
            Self::Moderate => f.write_str("moderate"),
            Self::Hard => f.write_str("hard"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitObjectiveScore {
    pub evasion_score_millionths: u64,
    pub containment_escape_score_millionths: u64,
    pub damage_potential_millionths: u64,
    pub detection_difficulty_millionths: u64,
    pub novel_technique_bonus_millionths: u64,
    pub composite_score_millionths: u64,
    pub difficulty: ContainmentDifficulty,
}

impl ExploitObjectiveScore {
    pub fn from_result(result: &CampaignExecutionResult) -> Result<Self, CampaignError> {
        result.validate()?;

        let evasion_score = clamp_millionths(
            ((result.undetected_steps as u128 * 1_000_000u128) / result.total_steps as u128) as u64,
        );
        let containment_escape = if result.objective_achieved_before_containment {
            1_000_000
        } else {
            0
        };
        let detection_difficulty = clamp_millionths(
            (result
                .evidence_atoms_before_detection
                .saturating_mul(20_000))
            .min(1_000_000),
        );
        let novel_bonus = if result.novel_technique { 150_000 } else { 0 };

        let composite = clamp_millionths(
            ((evasion_score as u128 * 35
                + containment_escape as u128 * 25
                + result.damage_potential_millionths as u128 * 20
                + detection_difficulty as u128 * 15
                + novel_bonus as u128 * 5)
                / 100) as u64,
        );

        let difficulty = if composite >= 850_000 {
            ContainmentDifficulty::Critical
        } else if composite >= 650_000 {
            ContainmentDifficulty::Hard
        } else if composite >= 400_000 {
            ContainmentDifficulty::Moderate
        } else {
            ContainmentDifficulty::Easy
        };

        Ok(Self {
            evasion_score_millionths: evasion_score,
            containment_escape_score_millionths: containment_escape,
            damage_potential_millionths: result.damage_potential_millionths,
            detection_difficulty_millionths: detection_difficulty,
            novel_technique_bonus_millionths: novel_bonus,
            composite_score_millionths: composite,
            difficulty,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationOperator {
    PointMutation,
    Crossover,
    Insertion,
    Deletion,
    TemporalShift,
}

impl fmt::Display for MutationOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PointMutation => f.write_str("point_mutation"),
            Self::Crossover => f.write_str("crossover"),
            Self::Insertion => f.write_str("insertion"),
            Self::Deletion => f.write_str("deletion"),
            Self::TemporalShift => f.write_str("temporal_shift"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationRequest {
    pub operator: MutationOperator,
    pub seed: u64,
    pub donor_campaign: Option<AdversarialCampaign>,
}

pub struct MutationEngine;

impl MutationEngine {
    pub fn mutate(
        base: &AdversarialCampaign,
        grammar: &AttackGrammar,
        request: MutationRequest,
    ) -> Result<AdversarialCampaign, CampaignError> {
        base.validate()?;
        grammar.validate()?;
        let mut rng = DeterministicRng::new(request.seed)?;
        let mut mutated = base.clone();

        match request.operator {
            MutationOperator::PointMutation => {
                let index = rng.choose_index(mutated.steps.len());
                mutated.steps[index] = grammar.generate_step(index as u32, &mut rng)?;
            }
            MutationOperator::Crossover => {
                let donor =
                    request
                        .donor_campaign
                        .ok_or_else(|| CampaignError::InvalidMutation {
                            detail: "crossover requires donor_campaign".to_string(),
                        })?;
                donor.validate()?;
                let split_left = rng.range_u64(1, mutated.steps.len() as u64) as usize;
                let split_right = rng.range_u64(0, donor.steps.len() as u64) as usize;
                let mut merged = Vec::with_capacity(mutated.steps.len() + donor.steps.len());
                merged.extend_from_slice(&mutated.steps[..split_left]);
                merged.extend_from_slice(&donor.steps[split_right..]);
                if merged.is_empty() {
                    merged.push(grammar.generate_step(0, &mut rng)?);
                }
                mutated.steps = merged;
            }
            MutationOperator::Insertion => {
                let index = rng.choose_index(mutated.steps.len() + 1);
                let step = grammar.generate_step(index as u32, &mut rng)?;
                mutated.steps.insert(index, step);
            }
            MutationOperator::Deletion => {
                if mutated.steps.len() == 1 {
                    return Err(CampaignError::InvalidMutation {
                        detail: "cannot delete the last step".to_string(),
                    });
                }
                let index = rng.choose_index(mutated.steps.len());
                mutated.steps.remove(index);
            }
            MutationOperator::TemporalShift => {
                let mut shifted = false;
                for _ in 0..mutated.steps.len() {
                    let index = rng.choose_index(mutated.steps.len());
                    if let AttackStepKind::TemporalPayload { stage, delay_ms } =
                        &mut mutated.steps[index].kind
                    {
                        let base_delay = *delay_ms;
                        let delta = rng.range_u64(5, 250);
                        *delay_ms = if rng.next_u64() & 1 == 0 {
                            base_delay.saturating_add(delta)
                        } else {
                            base_delay.saturating_sub(delta).max(1)
                        };
                        mutated.steps[index].production_label = stage.clone();
                        shifted = true;
                        break;
                    }
                }
                if !shifted {
                    return Err(CampaignError::InvalidMutation {
                        detail: "temporal_shift requires at least one temporal payload step"
                            .to_string(),
                    });
                }
            }
        }

        Self::reindex(&mut mutated.steps);
        mutated.seed = request.seed;
        mutated.campaign_id = format!(
            "camp-{}",
            short_hash(&format!(
                "{}:{}:{}:{}",
                mutated.policy_id, mutated.grammar_version, mutated.seed, request.operator
            ))
        );
        mutated.trace_id = format!("trace-{}", short_hash(&mutated.campaign_id));
        mutated.decision_id = format!("decision-{}", short_hash(&mutated.trace_id));

        mutated.validate()?;
        Ok(mutated)
    }

    fn reindex(steps: &mut [AttackStep]) {
        for (idx, step) in steps.iter_mut().enumerate() {
            step.step_id = idx as u32;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizationProof {
    pub rounds: u32,
    pub removed_steps: u32,
    pub is_fixed_point: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicReproFixture {
    pub campaign_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub seed: u64,
    pub attack_sequence: Vec<AttackStep>,
    pub expected_defense_response: String,
    pub actual_defense_response: String,
    pub minimality_proof: MinimizationProof,
}

pub struct AutoMinimizer;

impl AutoMinimizer {
    pub fn minimize_with<F>(
        campaign: &AdversarialCampaign,
        still_fails: F,
    ) -> Result<(AdversarialCampaign, MinimizationProof), CampaignError>
    where
        F: Fn(&AdversarialCampaign) -> bool,
    {
        campaign.validate()?;

        if !still_fails(campaign) {
            return Err(CampaignError::InvalidCampaign {
                detail: "minimizer requires an initially failing campaign".to_string(),
            });
        }

        let mut current = campaign.clone();
        let mut rounds = 0u32;
        let mut removed_steps = 0u32;
        let mut chunk = (current.steps.len() / 2).max(1);

        while chunk > 0 {
            rounds += 1;
            let mut changed = false;
            let mut start = 0usize;
            while start < current.steps.len() {
                if current.steps.len() <= 1 {
                    break;
                }
                let end = (start + chunk).min(current.steps.len());
                if start == end {
                    break;
                }

                let mut candidate = current.clone();
                let removed = end - start;
                candidate.steps.drain(start..end);
                if candidate.steps.is_empty() {
                    start += chunk;
                    continue;
                }
                MutationEngine::reindex(&mut candidate.steps);
                candidate.campaign_id = format!("{}-min", current.campaign_id);
                candidate.trace_id = current.trace_id.clone();
                candidate.decision_id = current.decision_id.clone();

                if still_fails(&candidate) {
                    removed_steps += removed as u32;
                    current = candidate;
                    changed = true;
                } else {
                    start += chunk;
                }
            }

            if !changed {
                if chunk == 1 {
                    break;
                }
                chunk /= 2;
            }
        }

        let proof = MinimizationProof {
            rounds,
            removed_steps,
            is_fixed_point: true,
        };

        Ok((current, proof))
    }

    pub fn build_fixture(
        minimized: &AdversarialCampaign,
        expected_defense_response: &str,
        actual_defense_response: &str,
        minimality_proof: MinimizationProof,
    ) -> DeterministicReproFixture {
        DeterministicReproFixture {
            campaign_id: minimized.campaign_id.clone(),
            trace_id: minimized.trace_id.clone(),
            decision_id: minimized.decision_id.clone(),
            policy_id: minimized.policy_id.clone(),
            seed: minimized.seed,
            attack_sequence: minimized.steps.clone(),
            expected_defense_response: expected_defense_response.to_string(),
            actual_defense_response: actual_defense_response.to_string(),
            minimality_proof,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCorpus {
    fixtures: BTreeMap<String, DeterministicReproFixture>,
}

impl RegressionCorpus {
    pub fn promote(&mut self, fixture: DeterministicReproFixture) {
        self.fixtures.insert(fixture.campaign_id.clone(), fixture);
    }

    pub fn fixture(&self, campaign_id: &str) -> Option<&DeterministicReproFixture> {
        self.fixtures.get(campaign_id)
    }

    pub fn len(&self) -> usize {
        self.fixtures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fixtures.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub campaign_id: String,
    pub composite_score_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignGeneratorConfig {
    pub policy_id: String,
    pub campaigns_per_hour: u32,
    pub max_backpressure_queue: usize,
    pub promotion_threshold_millionths: u64,
}

impl Default for CampaignGeneratorConfig {
    fn default() -> Self {
        Self {
            policy_id: "policy-adversarial-default".to_string(),
            campaigns_per_hour: 12,
            max_backpressure_queue: 24,
            promotion_threshold_millionths: 700_000,
        }
    }
}

pub struct CampaignGenerator {
    grammar: AttackGrammar,
    config: CampaignGeneratorConfig,
    rng: DeterministicRng,
    sequence: u64,
    regression_corpus: RegressionCorpus,
    events: Vec<CampaignEvent>,
    scorebook: BTreeMap<String, ExploitObjectiveScore>,
}

impl CampaignGenerator {
    pub fn new(
        grammar: AttackGrammar,
        config: CampaignGeneratorConfig,
        seed: u64,
    ) -> Result<Self, CampaignError> {
        grammar.validate()?;
        if config.policy_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "config.policy_id must not be empty".to_string(),
            });
        }
        if config.campaigns_per_hour == 0 {
            return Err(CampaignError::InvalidCampaign {
                detail: "config.campaigns_per_hour must be > 0".to_string(),
            });
        }
        let rng = DeterministicRng::new(seed)?;
        Ok(Self {
            grammar,
            config,
            rng,
            sequence: 0,
            regression_corpus: RegressionCorpus::default(),
            events: Vec::new(),
            scorebook: BTreeMap::new(),
        })
    }

    pub fn plan_campaign_count(&self, backlog: usize) -> usize {
        if backlog >= self.config.max_backpressure_queue {
            return 0;
        }
        let capacity = self.config.max_backpressure_queue - backlog;
        (self.config.campaigns_per_hour as usize).min(capacity)
    }

    pub fn generate_campaign(
        &mut self,
        complexity: CampaignComplexity,
    ) -> Result<AdversarialCampaign, CampaignError> {
        self.sequence += 1;
        let campaign_seed = self.rng.next_u64();
        let mut local_rng = DeterministicRng::new(campaign_seed.max(1))?;

        let step_count = complexity.target_steps();
        let mut steps = Vec::with_capacity(step_count);
        for idx in 0..step_count {
            steps.push(self.grammar.generate_step(idx as u32, &mut local_rng)?);
        }

        let campaign_id = format!(
            "camp-{}",
            short_hash(&format!(
                "{}:{}:{}:{}",
                self.config.policy_id, self.grammar.version, campaign_seed, self.sequence
            ))
        );
        let trace_id = format!("trace-{}", short_hash(&campaign_id));
        let decision_id = format!("decision-{}", short_hash(&trace_id));

        let campaign = AdversarialCampaign {
            campaign_id,
            trace_id,
            decision_id,
            policy_id: self.config.policy_id.clone(),
            grammar_version: self.grammar.version,
            seed: campaign_seed.max(1),
            complexity,
            steps,
        };
        campaign.validate()?;
        Ok(campaign)
    }

    pub fn score_campaign(
        &self,
        campaign: &AdversarialCampaign,
        result: &CampaignExecutionResult,
    ) -> Result<ExploitObjectiveScore, CampaignError> {
        campaign.validate()?;
        ExploitObjectiveScore::from_result(result)
    }

    pub fn record_campaign_outcome(
        &mut self,
        campaign: &AdversarialCampaign,
        score: &ExploitObjectiveScore,
    ) -> Result<(), CampaignError> {
        campaign.validate()?;
        self.grammar.apply_campaign_feedback(campaign, score);
        self.scorebook
            .insert(campaign.campaign_id.clone(), score.clone());

        let outcome = if score.containment_escape_score_millionths > 0 {
            "escape"
        } else {
            "contained"
        };
        self.events.push(CampaignEvent {
            trace_id: campaign.trace_id.clone(),
            decision_id: campaign.decision_id.clone(),
            policy_id: campaign.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "campaign_scored".to_string(),
            outcome: outcome.to_string(),
            error_code: None,
            campaign_id: campaign.campaign_id.clone(),
            composite_score_millionths: score.composite_score_millionths,
        });

        Ok(())
    }

    pub fn promote_failure_fixture<F>(
        &mut self,
        campaign: &AdversarialCampaign,
        expected_defense_response: &str,
        actual_defense_response: &str,
        still_fails: F,
    ) -> Result<DeterministicReproFixture, CampaignError>
    where
        F: Fn(&AdversarialCampaign) -> bool,
    {
        let (minimized, proof) =
            AutoMinimizer::minimize_with(campaign, still_fails).inspect_err(|err| {
                self.events.push(CampaignEvent {
                    trace_id: campaign.trace_id.clone(),
                    decision_id: campaign.decision_id.clone(),
                    policy_id: campaign.policy_id.clone(),
                    component: COMPONENT.to_string(),
                    event: "campaign_minimization".to_string(),
                    outcome: "error".to_string(),
                    error_code: Some(err.error_code().to_string()),
                    campaign_id: campaign.campaign_id.clone(),
                    composite_score_millionths: 0,
                });
            })?;

        let fixture = AutoMinimizer::build_fixture(
            &minimized,
            expected_defense_response,
            actual_defense_response,
            proof,
        );
        self.regression_corpus.promote(fixture.clone());

        self.events.push(CampaignEvent {
            trace_id: minimized.trace_id.clone(),
            decision_id: minimized.decision_id.clone(),
            policy_id: minimized.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "failure_promoted".to_string(),
            outcome: "promoted".to_string(),
            error_code: None,
            campaign_id: minimized.campaign_id.clone(),
            composite_score_millionths: self
                .scorebook
                .get(&campaign.campaign_id)
                .map(|score| score.composite_score_millionths)
                .unwrap_or(0),
        });

        Ok(fixture)
    }

    pub fn run_cycle<F>(
        &mut self,
        complexity: CampaignComplexity,
        backlog: usize,
        mut execute: F,
    ) -> Result<Vec<(AdversarialCampaign, ExploitObjectiveScore)>, CampaignError>
    where
        F: FnMut(&AdversarialCampaign) -> CampaignExecutionResult,
    {
        let count = self.plan_campaign_count(backlog);
        let mut outputs = Vec::with_capacity(count);

        for _ in 0..count {
            let campaign = self.generate_campaign(complexity)?;
            let result = execute(&campaign);
            let score = self.score_campaign(&campaign, &result)?;
            self.record_campaign_outcome(&campaign, &score)?;
            if score.composite_score_millionths >= self.config.promotion_threshold_millionths {
                let _ = self.promote_failure_fixture(
                    &campaign,
                    "containment",
                    "evasion",
                    |_candidate| true,
                )?;
            }
            outputs.push((campaign, score));
        }

        Ok(outputs)
    }

    pub fn regression_corpus(&self) -> &RegressionCorpus {
        &self.regression_corpus
    }

    pub fn drain_events(&mut self) -> Vec<CampaignEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn score(&self, campaign_id: &str) -> Option<&ExploitObjectiveScore> {
        self.scorebook.get(campaign_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_result() -> CampaignExecutionResult {
        CampaignExecutionResult {
            undetected_steps: 3,
            total_steps: 5,
            objective_achieved_before_containment: false,
            damage_potential_millionths: 420_000,
            evidence_atoms_before_detection: 14,
            novel_technique: true,
        }
    }

    #[test]
    fn grammar_validation_rejects_empty_bucket() {
        let grammar = AttackGrammar {
            hostcall_motifs: vec![],
            ..AttackGrammar::default()
        };
        let err = grammar.validate().expect_err("must reject");
        assert!(err.to_string().contains("hostcall_motifs"));
        assert_eq!(err.error_code(), ERR_INVALID_GRAMMAR);
    }

    #[test]
    fn campaign_generation_is_deterministic() {
        let grammar = AttackGrammar::default();
        let config = CampaignGeneratorConfig::default();

        let mut a = CampaignGenerator::new(grammar.clone(), config.clone(), 0xA11CE).unwrap();
        let mut b = CampaignGenerator::new(grammar, config, 0xA11CE).unwrap();

        let first = a.generate_campaign(CampaignComplexity::MultiStage).unwrap();
        let second = b.generate_campaign(CampaignComplexity::MultiStage).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn mutation_engine_preserves_well_formed_steps() {
        let grammar = AttackGrammar::default();
        let mut generator =
            CampaignGenerator::new(grammar.clone(), CampaignGeneratorConfig::default(), 0xA11CE)
                .unwrap();
        let base = generator
            .generate_campaign(CampaignComplexity::Probe)
            .unwrap();

        let mutated = MutationEngine::mutate(
            &base,
            &grammar,
            MutationRequest {
                operator: MutationOperator::Insertion,
                seed: 0xBEEFu64,
                donor_campaign: None,
            },
        )
        .unwrap();

        mutated.validate().unwrap();
        for (idx, step) in mutated.steps.iter().enumerate() {
            assert_eq!(step.step_id as usize, idx);
        }
    }

    #[test]
    fn exploit_scoring_is_deterministic() {
        let score_a = ExploitObjectiveScore::from_result(&sample_result()).unwrap();
        let score_b = ExploitObjectiveScore::from_result(&sample_result()).unwrap();
        assert_eq!(score_a, score_b);
        assert_eq!(score_a.difficulty, ContainmentDifficulty::Easy);
    }

    #[test]
    fn minimizer_reduces_campaign() {
        let mut generator = CampaignGenerator::new(
            AttackGrammar::default(),
            CampaignGeneratorConfig::default(),
            0xA11CE,
        )
        .unwrap();
        let campaign = generator
            .generate_campaign(CampaignComplexity::Apt)
            .unwrap();
        let original_len = campaign.steps.len();

        let (minimized, proof) =
            AutoMinimizer::minimize_with(&campaign, |candidate| candidate.steps.len() >= 3)
                .unwrap();

        assert!(minimized.steps.len() < original_len);
        assert!(minimized.steps.len() >= 3);
        assert!(proof.removed_steps > 0);
    }

    #[test]
    fn run_cycle_emits_stable_event_fields_and_promotes_fixture() {
        let mut generator = CampaignGenerator::new(
            AttackGrammar::default(),
            CampaignGeneratorConfig {
                campaigns_per_hour: 1,
                max_backpressure_queue: 3,
                promotion_threshold_millionths: 300_000,
                ..CampaignGeneratorConfig::default()
            },
            0xD00D,
        )
        .unwrap();

        let outputs = generator
            .run_cycle(CampaignComplexity::Probe, 0, |_campaign| {
                CampaignExecutionResult {
                    undetected_steps: 4,
                    total_steps: 4,
                    objective_achieved_before_containment: true,
                    damage_potential_millionths: 800_000,
                    evidence_atoms_before_detection: 60,
                    novel_technique: true,
                }
            })
            .unwrap();

        assert_eq!(outputs.len(), 1);
        assert!(!generator.regression_corpus().is_empty());

        let events = generator.drain_events();
        assert!(!events.is_empty());
        for event in events {
            assert!(!event.trace_id.is_empty());
            assert!(!event.decision_id.is_empty());
            assert!(!event.policy_id.is_empty());
            assert_eq!(event.component, COMPONENT);
            assert!(!event.event.is_empty());
            assert!(!event.outcome.is_empty());
            if event.event == "campaign_minimization" {
                assert!(event.error_code.is_some());
            }
        }
    }

    #[test]
    fn backpressure_stops_generation_when_queue_full() {
        let generator = CampaignGenerator::new(
            AttackGrammar::default(),
            CampaignGeneratorConfig {
                campaigns_per_hour: 9,
                max_backpressure_queue: 5,
                ..CampaignGeneratorConfig::default()
            },
            0xFACE,
        )
        .unwrap();

        assert_eq!(generator.plan_campaign_count(5), 0);
        assert_eq!(generator.plan_campaign_count(4), 1);
    }
}
