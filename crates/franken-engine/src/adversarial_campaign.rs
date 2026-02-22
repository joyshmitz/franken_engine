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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const COMPONENT: &str = "adversarial_campaign_generator";
const RED_BLUE_COMPONENT: &str = "red_blue_feedback_loop";
const ERR_INVALID_GRAMMAR: &str = "FE-ADV-CAMP-0001";
const ERR_INVALID_CAMPAIGN: &str = "FE-ADV-CAMP-0002";
const ERR_INVALID_RESULT: &str = "FE-ADV-CAMP-0003";
const ERR_INVALID_MUTATION: &str = "FE-ADV-CAMP-0004";
const ERR_INVALID_SEED: &str = "FE-ADV-CAMP-0005";
const ERR_INVALID_CALIBRATION: &str = "FE-ADV-CAMP-0006";
const ERR_GATE_INVALID_INPUT: &str = "FE-ADV-GATE-0001";
const ERR_GATE_MISSING_RUNTIME_COVERAGE: &str = "FE-ADV-GATE-0002";
const ERR_GATE_STATISTICAL_SIGNIFICANCE: &str = "FE-ADV-GATE-0003";
const ERR_GATE_CONTINUITY: &str = "FE-ADV-GATE-0004";
const ERR_GATE_ESCALATION_SLA: &str = "FE-ADV-GATE-0005";

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
    InvalidCalibration { detail: String },
}

impl CampaignError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidGrammar { .. } => ERR_INVALID_GRAMMAR,
            Self::InvalidCampaign { .. } => ERR_INVALID_CAMPAIGN,
            Self::InvalidExecutionResult { .. } => ERR_INVALID_RESULT,
            Self::InvalidMutation { .. } => ERR_INVALID_MUTATION,
            Self::InvalidSeed => ERR_INVALID_SEED,
            Self::InvalidCalibration { .. } => ERR_INVALID_CALIBRATION,
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
            Self::InvalidCalibration { detail } => write!(f, "invalid calibration: {detail}"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DefenseSubsystem {
    Sentinel,
    Containment,
    EvidenceAccumulation,
    FleetConvergence,
}

impl fmt::Display for DefenseSubsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sentinel => f.write_str("sentinel"),
            Self::Containment => f.write_str("containment"),
            Self::EvidenceAccumulation => f.write_str("evidence_accumulation"),
            Self::FleetConvergence => f.write_str("fleet_convergence"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatCategory {
    CredentialTheft,
    PrivilegeEscalation,
    Persistence,
    Exfiltration,
    PolicyEvasion,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialTheft => f.write_str("credential_theft"),
            Self::PrivilegeEscalation => f.write_str("privilege_escalation"),
            Self::Persistence => f.write_str("persistence"),
            Self::Exfiltration => f.write_str("exfiltration"),
            Self::PolicyEvasion => f.write_str("policy_evasion"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CampaignSeverity {
    Advisory,
    Moderate,
    Critical,
    Blocking,
}

impl fmt::Display for CampaignSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Advisory => f.write_str("advisory"),
            Self::Moderate => f.write_str("moderate"),
            Self::Critical => f.write_str("critical"),
            Self::Blocking => f.write_str("blocking"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignOutcomeRecord {
    pub campaign: AdversarialCampaign,
    pub result: CampaignExecutionResult,
    pub score: ExploitObjectiveScore,
    pub benign_control: bool,
    pub false_positive: bool,
    pub timestamp_ns: u64,
}

impl CampaignOutcomeRecord {
    pub fn validate(&self) -> Result<(), CampaignError> {
        self.campaign.validate()?;
        self.result.validate()?;
        let expected = ExploitObjectiveScore::from_result(&self.result)?;
        if self.score != expected {
            return Err(CampaignError::InvalidExecutionResult {
                detail: "score/result mismatch in campaign outcome record".to_string(),
            });
        }
        if self.false_positive && !self.benign_control {
            return Err(CampaignError::InvalidExecutionResult {
                detail: "false_positive requires benign_control=true".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignClassification {
    pub campaign_id: String,
    pub subsystem: DefenseSubsystem,
    pub threat_category: ThreatCategory,
    pub severity: CampaignSeverity,
    pub evasion_report: bool,
    pub containment_escape_report: bool,
    pub near_miss_report: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueEffectiveness {
    pub attempts: u64,
    pub detected: u64,
    pub escaped: u64,
    pub near_miss: u64,
    pub detection_rate_millionths: u64,
    pub escape_rate_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationSnapshot {
    pub detection_threshold_millionths: u64,
    pub evidence_weights_millionths: BTreeMap<AttackDimension, u64>,
    pub loss_matrix_millionths: BTreeMap<ThreatCategory, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardplaneCalibrationState {
    pub detection_threshold_millionths: u64,
    pub evidence_weights_millionths: BTreeMap<AttackDimension, u64>,
    pub loss_matrix_millionths: BTreeMap<ThreatCategory, u64>,
    pub calibration_epoch: u64,
}

impl GuardplaneCalibrationState {
    fn ensure_defaults(&mut self) {
        for dimension in [
            AttackDimension::HostcallSequence,
            AttackDimension::TemporalPayload,
            AttackDimension::PrivilegeEscalation,
            AttackDimension::PolicyEvasion,
            AttackDimension::Exfiltration,
        ] {
            self.evidence_weights_millionths
                .entry(dimension)
                .or_insert(500_000);
        }
        for category in [
            ThreatCategory::CredentialTheft,
            ThreatCategory::PrivilegeEscalation,
            ThreatCategory::Persistence,
            ThreatCategory::Exfiltration,
            ThreatCategory::PolicyEvasion,
        ] {
            self.loss_matrix_millionths
                .entry(category)
                .or_insert(200_000);
        }
        self.detection_threshold_millionths =
            clamp_millionths(self.detection_threshold_millionths.max(1));
    }

    fn snapshot(&self) -> CalibrationSnapshot {
        CalibrationSnapshot {
            detection_threshold_millionths: self.detection_threshold_millionths,
            evidence_weights_millionths: self.evidence_weights_millionths.clone(),
            loss_matrix_millionths: self.loss_matrix_millionths.clone(),
        }
    }
}

impl Default for GuardplaneCalibrationState {
    fn default() -> Self {
        let mut state = Self {
            detection_threshold_millionths: 700_000,
            evidence_weights_millionths: BTreeMap::new(),
            loss_matrix_millionths: BTreeMap::new(),
            calibration_epoch: 0,
        };
        state.ensure_defaults();
        state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedBlueCalibrationConfig {
    pub target_false_negative_millionths: u64,
    pub target_false_positive_millionths: u64,
    pub max_threshold_delta_millionths: u64,
    pub evidence_weight_delta_millionths: u64,
    pub max_evidence_weight_millionths: u64,
}

impl Default for RedBlueCalibrationConfig {
    fn default() -> Self {
        Self {
            target_false_negative_millionths: 10_000,
            target_false_positive_millionths: 10_000,
            max_threshold_delta_millionths: 50_000,
            evidence_weight_delta_millionths: 20_000,
            max_evidence_weight_millionths: 950_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationJustificationMetrics {
    pub false_negative_millionths: u64,
    pub false_positive_millionths: u64,
    pub attack_escape_count: u64,
    pub benign_false_positive_count: u64,
    pub near_miss_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationReceipt {
    pub calibration_id: String,
    pub campaign_ids: Vec<String>,
    pub old_parameters: CalibrationSnapshot,
    pub new_parameters: CalibrationSnapshot,
    pub justification_metrics: CalibrationJustificationMetrics,
    pub timestamp_ns: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedBlueIntegrationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub campaign_id: Option<String>,
    pub calibration_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRegressionEntry {
    pub campaign_id: String,
    pub fixture: DeterministicReproFixture,
    pub subsystem: DefenseSubsystem,
    pub threat_category: ThreatCategory,
    pub severity: CampaignSeverity,
    pub discovered_at_ns: u64,
    pub calibration_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRegressionSuite {
    entries: BTreeMap<String, PolicyRegressionEntry>,
}

impl PolicyRegressionSuite {
    pub fn upsert(&mut self, entry: PolicyRegressionEntry) {
        self.entries.insert(entry.campaign_id.clone(), entry);
    }

    #[allow(dead_code)]
    pub fn get(&self, campaign_id: &str) -> Option<&PolicyRegressionEntry> {
        self.entries.get(campaign_id)
    }

    pub fn entries(&self) -> &BTreeMap<String, PolicyRegressionEntry> {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionReplayResult {
    pub campaign_id: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionGateDecision {
    pub passed: bool,
    pub failed_campaign_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualHint {
    pub campaign_id: String,
    pub description: String,
    pub threshold_adjustment_needed_millionths: i64,
    pub would_previous_week_detect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedBlueLoopIntegrator {
    config: RedBlueCalibrationConfig,
    calibration_state: GuardplaneCalibrationState,
    outcomes: Vec<CampaignOutcomeRecord>,
    classifications: BTreeMap<String, CampaignClassification>,
    regression_suite: PolicyRegressionSuite,
    events: Vec<RedBlueIntegrationEvent>,
}

impl RedBlueLoopIntegrator {
    pub fn new(
        config: RedBlueCalibrationConfig,
        mut calibration_state: GuardplaneCalibrationState,
    ) -> Self {
        calibration_state.ensure_defaults();
        Self {
            config,
            calibration_state,
            outcomes: Vec::new(),
            classifications: BTreeMap::new(),
            regression_suite: PolicyRegressionSuite::default(),
            events: Vec::new(),
        }
    }

    pub fn calibration_state(&self) -> &GuardplaneCalibrationState {
        &self.calibration_state
    }

    pub fn regression_suite(&self) -> &PolicyRegressionSuite {
        &self.regression_suite
    }

    pub fn ingest_outcome(
        &mut self,
        outcome: CampaignOutcomeRecord,
    ) -> Result<CampaignClassification, CampaignError> {
        outcome.validate()?;
        let classification = self.classify(&outcome);
        self.push_campaign_event(
            &outcome.campaign,
            "campaign_ingested",
            "classified",
            None,
            None,
        );
        self.classifications
            .insert(outcome.campaign.campaign_id.clone(), classification.clone());
        self.outcomes.push(outcome);
        Ok(classification)
    }

    #[allow(dead_code)]
    pub fn ingest_outcomes(
        &mut self,
        outcomes: &[CampaignOutcomeRecord],
    ) -> Result<Vec<CampaignClassification>, CampaignError> {
        let mut classifications = Vec::with_capacity(outcomes.len());
        for outcome in outcomes {
            classifications.push(self.ingest_outcome(outcome.clone())?);
        }
        Ok(classifications)
    }

    pub fn classify(&self, outcome: &CampaignOutcomeRecord) -> CampaignClassification {
        let near_miss = Self::is_near_miss(&outcome.result);
        CampaignClassification {
            campaign_id: outcome.campaign.campaign_id.clone(),
            subsystem: Self::infer_subsystem(outcome),
            threat_category: Self::infer_threat_category(outcome),
            severity: Self::infer_severity(outcome, near_miss),
            evasion_report: outcome.result.undetected_steps > 0,
            containment_escape_report: outcome.result.objective_achieved_before_containment,
            near_miss_report: near_miss,
        }
    }

    pub fn technique_effectiveness(&self) -> BTreeMap<AttackDimension, TechniqueEffectiveness> {
        let mut map: BTreeMap<AttackDimension, TechniqueEffectiveness> = BTreeMap::new();

        for outcome in &self.outcomes {
            let mut seen = BTreeSet::new();
            for step in &outcome.campaign.steps {
                if !seen.insert(step.dimension) {
                    continue;
                }
                let entry = map.entry(step.dimension).or_insert(TechniqueEffectiveness {
                    attempts: 0,
                    detected: 0,
                    escaped: 0,
                    near_miss: 0,
                    detection_rate_millionths: 0,
                    escape_rate_millionths: 0,
                });
                entry.attempts += 1;
                if outcome.result.undetected_steps == 0 {
                    entry.detected += 1;
                }
                if outcome.result.objective_achieved_before_containment {
                    entry.escaped += 1;
                }
                if Self::is_near_miss(&outcome.result) {
                    entry.near_miss += 1;
                }
            }
        }

        for entry in map.values_mut() {
            if entry.attempts == 0 {
                continue;
            }
            entry.detection_rate_millionths =
                clamp_millionths((entry.detected * 1_000_000) / entry.attempts);
            entry.escape_rate_millionths =
                clamp_millionths((entry.escaped * 1_000_000) / entry.attempts);
        }
        map
    }

    pub fn calibrate(
        &mut self,
        signing_key: &[u8; 32],
        timestamp_ns: u64,
    ) -> Result<Option<CalibrationReceipt>, CampaignError> {
        if self.outcomes.is_empty() {
            return Ok(None);
        }

        let old_snapshot = self.calibration_state.snapshot();
        let metrics = self.compute_justification_metrics();

        let target_fn = self.config.target_false_negative_millionths;
        let target_fp = self.config.target_false_positive_millionths;
        let max_delta = self.config.max_threshold_delta_millionths;

        if metrics.false_negative_millionths > target_fn {
            let delta = (metrics.false_negative_millionths - target_fn).min(max_delta);
            self.calibration_state.detection_threshold_millionths = self
                .calibration_state
                .detection_threshold_millionths
                .saturating_sub(delta)
                .max(1);
        } else if metrics.false_positive_millionths > target_fp {
            let delta = (metrics.false_positive_millionths - target_fp).min(max_delta);
            self.calibration_state.detection_threshold_millionths = clamp_millionths(
                self.calibration_state
                    .detection_threshold_millionths
                    .saturating_add(delta),
            )
            .max(1);
        }

        let effectiveness = self.technique_effectiveness();
        let false_positive_dims = self.false_positive_by_dimension();
        for dimension in [
            AttackDimension::HostcallSequence,
            AttackDimension::TemporalPayload,
            AttackDimension::PrivilegeEscalation,
            AttackDimension::PolicyEvasion,
            AttackDimension::Exfiltration,
        ] {
            let escaped = effectiveness
                .get(&dimension)
                .map(|e| e.escaped)
                .unwrap_or(0);
            let false_positives = false_positive_dims.get(&dimension).copied().unwrap_or(0);
            let current = *self
                .calibration_state
                .evidence_weights_millionths
                .entry(dimension)
                .or_insert(500_000);
            let up_delta = self
                .config
                .evidence_weight_delta_millionths
                .saturating_mul(escaped.min(5));
            let down_delta = self
                .config
                .evidence_weight_delta_millionths
                .saturating_mul(false_positives.min(5));
            let raised = current.saturating_add(up_delta);
            let lowered = raised.saturating_sub(down_delta);
            let bounded = lowered
                .max(50_000)
                .min(self.config.max_evidence_weight_millionths);
            self.calibration_state
                .evidence_weights_millionths
                .insert(dimension, bounded);
        }

        for outcome in &self.outcomes {
            let Some(classification) = self.classifications.get(&outcome.campaign.campaign_id)
            else {
                continue;
            };
            if !classification.containment_escape_report
                && classification.severity != CampaignSeverity::Critical
                && classification.severity != CampaignSeverity::Blocking
            {
                continue;
            }
            let current = *self
                .calibration_state
                .loss_matrix_millionths
                .entry(classification.threat_category)
                .or_insert(200_000);
            let updated = current.max(outcome.result.damage_potential_millionths);
            self.calibration_state
                .loss_matrix_millionths
                .insert(classification.threat_category, updated);
        }

        let new_snapshot = self.calibration_state.snapshot();
        if new_snapshot == old_snapshot {
            return Ok(None);
        }
        self.calibration_state.calibration_epoch += 1;

        let mut campaign_ids = self
            .outcomes
            .iter()
            .map(|outcome| outcome.campaign.campaign_id.clone())
            .collect::<Vec<_>>();
        campaign_ids.sort();
        campaign_ids.dedup();

        let calibration_id = format!(
            "calibration-{}",
            short_hash(&format!(
                "{}:{}:{}",
                self.calibration_state.calibration_epoch,
                timestamp_ns,
                campaign_ids.join(",")
            ))
        );

        let canonical = serde_json::to_vec(&(
            &calibration_id,
            &campaign_ids,
            &old_snapshot,
            &new_snapshot,
            &metrics,
            timestamp_ns,
        ))
        .map_err(|err| CampaignError::InvalidCalibration {
            detail: format!("calibration receipt canonicalization failed: {err}"),
        })?;
        let mut signer = Sha256::new();
        signer.update(signing_key);
        signer.update(&canonical);
        let first = signer.finalize();
        let second = Sha256::digest(first);
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(first.as_slice());
        signature.extend_from_slice(second.as_slice());

        let receipt = CalibrationReceipt {
            calibration_id: calibration_id.clone(),
            campaign_ids,
            old_parameters: old_snapshot,
            new_parameters: new_snapshot,
            justification_metrics: metrics,
            timestamp_ns,
            signature,
        };

        self.push_system_event(
            "guardplane_calibration_adjusted",
            "applied",
            None,
            Some(calibration_id),
        );

        Ok(Some(receipt))
    }

    pub fn promote_regression_fixture(
        &mut self,
        campaign_id: &str,
        expected_defense_response: &str,
        actual_defense_response: &str,
        calibration_id: Option<String>,
    ) -> Result<PolicyRegressionEntry, CampaignError> {
        let outcome = self
            .outcomes
            .iter()
            .find(|outcome| outcome.campaign.campaign_id == campaign_id)
            .ok_or_else(|| CampaignError::InvalidCampaign {
                detail: format!("unknown campaign_id for regression promotion: {campaign_id}"),
            })?
            .clone();
        let classification = self
            .classifications
            .get(campaign_id)
            .ok_or_else(|| CampaignError::InvalidCampaign {
                detail: format!("campaign not classified: {campaign_id}"),
            })?
            .clone();

        let fixture = AutoMinimizer::build_fixture(
            &outcome.campaign,
            expected_defense_response,
            actual_defense_response,
            MinimizationProof {
                rounds: 0,
                removed_steps: 0,
                is_fixed_point: true,
            },
        );
        let entry = PolicyRegressionEntry {
            campaign_id: outcome.campaign.campaign_id.clone(),
            fixture,
            subsystem: classification.subsystem,
            threat_category: classification.threat_category,
            severity: classification.severity,
            discovered_at_ns: outcome.timestamp_ns,
            calibration_id: calibration_id.clone(),
        };
        self.regression_suite.upsert(entry.clone());
        self.push_campaign_event(
            &outcome.campaign,
            "policy_regression_promoted",
            "promoted",
            None,
            calibration_id,
        );
        Ok(entry)
    }

    pub fn evaluate_regression_gate(
        &mut self,
        replay_results: &[RegressionReplayResult],
    ) -> RegressionGateDecision {
        let replay_map = replay_results
            .iter()
            .map(|result| (result.campaign_id.clone(), result.passed))
            .collect::<BTreeMap<_, _>>();

        let mut failed_campaign_ids = Vec::new();
        for campaign_id in self.regression_suite.entries().keys() {
            if replay_map.get(campaign_id).copied().unwrap_or(false) {
                continue;
            }
            failed_campaign_ids.push(campaign_id.clone());
        }
        let passed = failed_campaign_ids.is_empty();
        self.push_system_event(
            "policy_regression_gate",
            if passed { "pass" } else { "fail" },
            if passed {
                None
            } else {
                Some(ERR_INVALID_CALIBRATION.to_string())
            },
            None,
        );
        RegressionGateDecision {
            passed,
            failed_campaign_ids,
        }
    }

    pub fn critical_counterfactual_hints(&self) -> Vec<CounterfactualHint> {
        let mut hints = Vec::new();
        let previous_threshold = clamp_millionths(
            self.calibration_state
                .detection_threshold_millionths
                .saturating_add(self.config.max_threshold_delta_millionths),
        )
        .max(1);

        for outcome in &self.outcomes {
            let Some(classification) = self.classifications.get(&outcome.campaign.campaign_id)
            else {
                continue;
            };
            if classification.severity != CampaignSeverity::Critical
                && classification.severity != CampaignSeverity::Blocking
            {
                continue;
            }
            let current_threshold = self.calibration_state.detection_threshold_millionths as i64;
            let score = outcome.score.composite_score_millionths as i64;
            let threshold_adjustment_needed_millionths = (score - current_threshold).min(0);
            hints.push(CounterfactualHint {
                campaign_id: outcome.campaign.campaign_id.clone(),
                description: format!(
                    "threshold delta {} would have changed guardplane decision margin for {}",
                    threshold_adjustment_needed_millionths, outcome.campaign.campaign_id
                ),
                threshold_adjustment_needed_millionths,
                would_previous_week_detect: outcome.score.composite_score_millionths
                    >= previous_threshold,
            });
        }

        hints.sort_by(|left, right| left.campaign_id.cmp(&right.campaign_id));
        hints
    }

    pub fn drain_events(&mut self) -> Vec<RedBlueIntegrationEvent> {
        std::mem::take(&mut self.events)
    }

    fn compute_justification_metrics(&self) -> CalibrationJustificationMetrics {
        let mut attack_total = 0u64;
        let mut attack_escapes = 0u64;
        let mut benign_total = 0u64;
        let mut benign_false_positive = 0u64;
        let mut near_miss = 0u64;

        for outcome in &self.outcomes {
            let classification = self.classifications.get(&outcome.campaign.campaign_id);
            if outcome.benign_control {
                benign_total += 1;
                if outcome.false_positive {
                    benign_false_positive += 1;
                }
                continue;
            }
            attack_total += 1;
            if outcome.result.objective_achieved_before_containment {
                attack_escapes += 1;
            }
            if classification.map(|c| c.near_miss_report).unwrap_or(false) {
                near_miss += 1;
            }
        }

        let fn_rate = (attack_escapes * 1_000_000)
            .checked_div(attack_total)
            .map(clamp_millionths)
            .unwrap_or(0);
        let fp_rate = (benign_false_positive * 1_000_000)
            .checked_div(benign_total)
            .map(clamp_millionths)
            .unwrap_or(0);

        CalibrationJustificationMetrics {
            false_negative_millionths: fn_rate,
            false_positive_millionths: fp_rate,
            attack_escape_count: attack_escapes,
            benign_false_positive_count: benign_false_positive,
            near_miss_count: near_miss,
        }
    }

    fn false_positive_by_dimension(&self) -> BTreeMap<AttackDimension, u64> {
        let mut counts = BTreeMap::new();
        for outcome in &self.outcomes {
            if !(outcome.benign_control && outcome.false_positive) {
                continue;
            }
            let mut seen = BTreeSet::new();
            for step in &outcome.campaign.steps {
                if !seen.insert(step.dimension) {
                    continue;
                }
                *counts.entry(step.dimension).or_insert(0) += 1;
            }
        }
        counts
    }

    fn is_near_miss(result: &CampaignExecutionResult) -> bool {
        if result.objective_achieved_before_containment {
            return false;
        }
        result.undetected_steps.saturating_add(1) >= result.total_steps
    }

    fn infer_subsystem(outcome: &CampaignOutcomeRecord) -> DefenseSubsystem {
        if outcome.result.objective_achieved_before_containment {
            DefenseSubsystem::Containment
        } else if outcome.result.undetected_steps > 0 {
            DefenseSubsystem::Sentinel
        } else if outcome.result.evidence_atoms_before_detection > 24 {
            DefenseSubsystem::EvidenceAccumulation
        } else {
            DefenseSubsystem::FleetConvergence
        }
    }

    fn infer_threat_category(outcome: &CampaignOutcomeRecord) -> ThreatCategory {
        let mut counts: BTreeMap<AttackDimension, u64> = BTreeMap::new();
        for step in &outcome.campaign.steps {
            *counts.entry(step.dimension).or_insert(0) += 1;
        }

        let mut dominant = AttackDimension::HostcallSequence;
        let mut dominant_count = 0u64;
        for (dimension, count) in counts {
            if count > dominant_count || (count == dominant_count && dimension < dominant) {
                dominant = dimension;
                dominant_count = count;
            }
        }

        match dominant {
            AttackDimension::HostcallSequence => ThreatCategory::CredentialTheft,
            AttackDimension::TemporalPayload => ThreatCategory::Persistence,
            AttackDimension::PrivilegeEscalation => ThreatCategory::PrivilegeEscalation,
            AttackDimension::PolicyEvasion => ThreatCategory::PolicyEvasion,
            AttackDimension::Exfiltration => ThreatCategory::Exfiltration,
        }
    }

    fn infer_severity(outcome: &CampaignOutcomeRecord, near_miss: bool) -> CampaignSeverity {
        if outcome.result.objective_achieved_before_containment
            && outcome.result.damage_potential_millionths >= 800_000
        {
            return CampaignSeverity::Blocking;
        }
        if outcome.result.objective_achieved_before_containment
            || outcome.score.composite_score_millionths >= 800_000
        {
            return CampaignSeverity::Critical;
        }
        if near_miss || outcome.score.composite_score_millionths >= 500_000 {
            return CampaignSeverity::Moderate;
        }
        CampaignSeverity::Advisory
    }

    fn push_campaign_event(
        &mut self,
        campaign: &AdversarialCampaign,
        event: &str,
        outcome: &str,
        error_code: Option<String>,
        calibration_id: Option<String>,
    ) {
        self.events.push(RedBlueIntegrationEvent {
            trace_id: campaign.trace_id.clone(),
            decision_id: campaign.decision_id.clone(),
            policy_id: campaign.policy_id.clone(),
            component: RED_BLUE_COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code,
            campaign_id: Some(campaign.campaign_id.clone()),
            calibration_id,
        });
    }

    fn push_system_event(
        &mut self,
        event: &str,
        outcome: &str,
        error_code: Option<String>,
        calibration_id: Option<String>,
    ) {
        self.events.push(RedBlueIntegrationEvent {
            trace_id: "trace-red-blue-system".to_string(),
            decision_id: "decision-red-blue-system".to_string(),
            policy_id: "policy-red-blue-system".to_string(),
            component: RED_BLUE_COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code,
            campaign_id: None,
            calibration_id,
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CampaignRuntime {
    FrankenEngine,
    NodeLts,
    BunStable,
}

impl CampaignRuntime {
    #[allow(dead_code)]
    pub fn is_baseline(self) -> bool {
        !matches!(self, Self::FrankenEngine)
    }
}

impl fmt::Display for CampaignRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrankenEngine => f.write_str("franken_engine"),
            Self::NodeLts => f.write_str("node_lts"),
            Self::BunStable => f.write_str("bun_stable"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CampaignAttackCategory {
    Injection,
    PrototypePollution,
    SupplyChain,
    CapabilityEscape,
    TimingSideChannel,
}

impl CampaignAttackCategory {
    pub const ALL: [Self; 5] = [
        Self::Injection,
        Self::PrototypePollution,
        Self::SupplyChain,
        Self::CapabilityEscape,
        Self::TimingSideChannel,
    ];
}

impl fmt::Display for CampaignAttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Injection => f.write_str("injection"),
            Self::PrototypePollution => f.write_str("prototype_pollution"),
            Self::SupplyChain => f.write_str("supply_chain"),
            Self::CapabilityEscape => f.write_str("capability_escape"),
            Self::TimingSideChannel => f.write_str("timing_side_channel"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignSuppressionSample {
    pub campaign_id: String,
    pub attack_category: CampaignAttackCategory,
    pub target_runtime: CampaignRuntime,
    pub attempt_count: u64,
    pub success_count: u64,
    pub raw_log_ref: String,
    pub repro_script_ref: String,
}

impl CampaignSuppressionSample {
    pub fn validate(&self) -> Result<(), CampaignError> {
        if self.campaign_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "campaign_id must not be empty".to_string(),
            });
        }
        if self.attempt_count == 0 {
            return Err(CampaignError::InvalidCampaign {
                detail: format!(
                    "attempt_count must be > 0 for campaign {}",
                    self.campaign_id
                ),
            });
        }
        if self.success_count > self.attempt_count {
            return Err(CampaignError::InvalidCampaign {
                detail: format!(
                    "success_count ({}) exceeds attempt_count ({}) for campaign {}",
                    self.success_count, self.attempt_count, self.campaign_id
                ),
            });
        }
        if self.raw_log_ref.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: format!("raw_log_ref must not be empty for {}", self.campaign_id),
            });
        }
        if self.repro_script_ref.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: format!(
                    "repro_script_ref must not be empty for {}",
                    self.campaign_id
                ),
            });
        }
        Ok(())
    }

    pub fn compromise_rate_millionths(&self) -> u64 {
        compromise_rate_millionths(self.success_count, self.attempt_count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignTrendPoint {
    pub release_candidate_id: String,
    pub timestamp_ns: u64,
    pub samples_evaluated: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitEscalationRecord {
    pub campaign_id: String,
    pub attack_category: CampaignAttackCategory,
    pub target_runtime: CampaignRuntime,
    pub successful_exploit: bool,
    pub escalation_triggered: bool,
    pub escalation_latency_seconds: Option<u64>,
}

impl ExploitEscalationRecord {
    pub fn validate(&self) -> Result<(), CampaignError> {
        if self.campaign_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "escalation campaign_id must not be empty".to_string(),
            });
        }
        if self.successful_exploit
            && self.escalation_triggered
            && self.escalation_latency_seconds.is_none()
        {
            return Err(CampaignError::InvalidCampaign {
                detail: format!(
                    "escalation latency required when escalation was triggered for {}",
                    self.campaign_id
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionGateConfig {
    pub required_categories: Vec<CampaignAttackCategory>,
    pub minimum_baseline_runtimes: usize,
    pub max_p_value_millionths: u64,
    pub require_continuous_run: bool,
    pub minimum_trend_points: usize,
    pub max_escalation_latency_seconds: u64,
}

impl Default for SuppressionGateConfig {
    fn default() -> Self {
        Self {
            required_categories: CampaignAttackCategory::ALL.to_vec(),
            minimum_baseline_runtimes: 2,
            max_p_value_millionths: 50_000, // p <= 0.05
            require_continuous_run: true,
            minimum_trend_points: 2,
            max_escalation_latency_seconds: 3_600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionGateInput {
    pub release_candidate_id: String,
    pub continuous_run: bool,
    pub samples: Vec<CampaignSuppressionSample>,
    pub trend_points: Vec<CampaignTrendPoint>,
    pub escalations: Vec<ExploitEscalationRecord>,
}

impl SuppressionGateInput {
    pub fn validate(&self) -> Result<(), CampaignError> {
        if self.release_candidate_id.trim().is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "release_candidate_id must not be empty".to_string(),
            });
        }
        if self.samples.is_empty() {
            return Err(CampaignError::InvalidCampaign {
                detail: "at least one campaign suppression sample is required".to_string(),
            });
        }
        for sample in &self.samples {
            sample.validate()?;
        }
        for escalation in &self.escalations {
            escalation.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionComparison {
    pub attack_category: CampaignAttackCategory,
    pub baseline_runtime: CampaignRuntime,
    pub frankenengine_compromise_rate_millionths: u64,
    pub baseline_compromise_rate_millionths: u64,
    pub frankenengine_confidence_interval_millionths: (u64, u64),
    pub baseline_confidence_interval_millionths: (u64, u64),
    pub p_value_millionths: u64,
    pub statistically_significant: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionGateFailure {
    pub error_code: String,
    pub detail: String,
    pub attack_category: Option<CampaignAttackCategory>,
    pub baseline_runtime: Option<CampaignRuntime>,
    pub campaign_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignSuppressionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub campaign_id: String,
    pub attack_category: String,
    pub target_runtime: String,
    pub attempt_count: u64,
    pub success_count: u64,
    pub compromise_rate_millionths: u64,
    pub p_value_millionths: Option<u64>,
    pub confidence_interval: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionGateResult {
    pub release_candidate_id: String,
    pub passed: bool,
    pub comparisons: Vec<SuppressionComparison>,
    pub failures: Vec<SuppressionGateFailure>,
    pub trend_points_analyzed: usize,
    pub events: Vec<CampaignSuppressionEvent>,
}

pub fn evaluate_compromise_suppression_gate(
    input: &SuppressionGateInput,
    config: &SuppressionGateConfig,
) -> Result<SuppressionGateResult, CampaignError> {
    input.validate()?;

    if config.minimum_baseline_runtimes == 0 {
        return Err(CampaignError::InvalidCampaign {
            detail: "minimum_baseline_runtimes must be > 0".to_string(),
        });
    }

    let trace_id = format!("trace-{}", short_hash(&input.release_candidate_id));
    let decision_id = format!(
        "decision-{}",
        short_hash(&format!("{}:suppression", input.release_candidate_id))
    );
    let policy_id = "policy-adversarial-campaign-gate-v1".to_string();

    let mut events = Vec::new();
    let mut failures = Vec::new();
    let mut aggregated: BTreeMap<(CampaignAttackCategory, CampaignRuntime), (u64, u64)> =
        BTreeMap::new();

    for sample in &input.samples {
        let key = (sample.attack_category, sample.target_runtime);
        let entry = aggregated.entry(key).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(sample.attempt_count);
        entry.1 = entry.1.saturating_add(sample.success_count);

        let ci = wilson_interval_millionths(sample.success_count, sample.attempt_count);
        events.push(CampaignSuppressionEvent {
            trace_id: trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: policy_id.clone(),
            component: RED_BLUE_COMPONENT.to_string(),
            event: "campaign_sample_ingested".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            campaign_id: sample.campaign_id.clone(),
            attack_category: sample.attack_category.to_string(),
            target_runtime: sample.target_runtime.to_string(),
            attempt_count: sample.attempt_count,
            success_count: sample.success_count,
            compromise_rate_millionths: sample.compromise_rate_millionths(),
            p_value_millionths: None,
            confidence_interval: format!("[{},{}]", ci.0, ci.1),
        });
    }

    if config.require_continuous_run && !input.continuous_run {
        failures.push(SuppressionGateFailure {
            error_code: ERR_GATE_CONTINUITY.to_string(),
            detail: "continuous_run must be true for release gating".to_string(),
            attack_category: None,
            baseline_runtime: None,
            campaign_id: None,
        });
    }
    if input.trend_points.len() < config.minimum_trend_points {
        failures.push(SuppressionGateFailure {
            error_code: ERR_GATE_CONTINUITY.to_string(),
            detail: format!(
                "trend history too short: have {}, need at least {}",
                input.trend_points.len(),
                config.minimum_trend_points
            ),
            attack_category: None,
            baseline_runtime: None,
            campaign_id: None,
        });
    }

    let mut escalation_index = BTreeMap::new();
    for escalation in &input.escalations {
        escalation_index.insert(
            (
                escalation.campaign_id.clone(),
                escalation.attack_category,
                escalation.target_runtime,
            ),
            escalation,
        );
    }

    for sample in &input.samples {
        if sample.target_runtime != CampaignRuntime::FrankenEngine || sample.success_count == 0 {
            continue;
        }
        let key = (
            sample.campaign_id.clone(),
            sample.attack_category,
            sample.target_runtime,
        );
        let escalation = escalation_index.get(&key);
        let mut escalation_ok = false;
        let mut escalation_code = None;
        if let Some(record) = escalation {
            escalation_ok = record.successful_exploit
                && record.escalation_triggered
                && record
                    .escalation_latency_seconds
                    .is_some_and(|latency| latency <= config.max_escalation_latency_seconds);
            if !escalation_ok {
                escalation_code = Some(ERR_GATE_ESCALATION_SLA.to_string());
            }
        } else {
            escalation_code = Some(ERR_GATE_ESCALATION_SLA.to_string());
        }

        if !escalation_ok {
            failures.push(SuppressionGateFailure {
                error_code: ERR_GATE_ESCALATION_SLA.to_string(),
                detail: format!(
                    "missing or invalid escalation workflow for successful exploit {}",
                    sample.campaign_id
                ),
                attack_category: Some(sample.attack_category),
                baseline_runtime: Some(sample.target_runtime),
                campaign_id: Some(sample.campaign_id.clone()),
            });
        }

        events.push(CampaignSuppressionEvent {
            trace_id: trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: policy_id.clone(),
            component: RED_BLUE_COMPONENT.to_string(),
            event: "escalation_sla_check".to_string(),
            outcome: if escalation_ok { "pass" } else { "fail" }.to_string(),
            error_code: escalation_code,
            campaign_id: sample.campaign_id.clone(),
            attack_category: sample.attack_category.to_string(),
            target_runtime: sample.target_runtime.to_string(),
            attempt_count: sample.attempt_count,
            success_count: sample.success_count,
            compromise_rate_millionths: sample.compromise_rate_millionths(),
            p_value_millionths: None,
            confidence_interval: String::new(),
        });
    }

    let mut comparisons = Vec::new();
    for category in &config.required_categories {
        let franken = aggregated
            .get(&(*category, CampaignRuntime::FrankenEngine))
            .copied();
        let Some((franken_attempts, franken_successes)) = franken else {
            failures.push(SuppressionGateFailure {
                error_code: ERR_GATE_MISSING_RUNTIME_COVERAGE.to_string(),
                detail: format!("missing franken_engine sample for category {}", category),
                attack_category: Some(*category),
                baseline_runtime: Some(CampaignRuntime::FrankenEngine),
                campaign_id: None,
            });
            continue;
        };

        let baseline_runtimes = [CampaignRuntime::NodeLts, CampaignRuntime::BunStable];
        let available_baselines = baseline_runtimes
            .iter()
            .filter(|runtime| aggregated.contains_key(&(*category, **runtime)))
            .count();
        if available_baselines < config.minimum_baseline_runtimes {
            failures.push(SuppressionGateFailure {
                error_code: ERR_GATE_MISSING_RUNTIME_COVERAGE.to_string(),
                detail: format!(
                    "category {} has {} baseline runtimes, requires {}",
                    category, available_baselines, config.minimum_baseline_runtimes
                ),
                attack_category: Some(*category),
                baseline_runtime: None,
                campaign_id: None,
            });
            continue;
        }

        for baseline_runtime in baseline_runtimes {
            let Some((baseline_attempts, baseline_successes)) =
                aggregated.get(&(*category, baseline_runtime)).copied()
            else {
                continue;
            };

            let franken_rate = compromise_rate_millionths(franken_successes, franken_attempts);
            let baseline_rate = compromise_rate_millionths(baseline_successes, baseline_attempts);
            let p_value_millionths = one_sided_p_value_millionths(
                franken_successes,
                franken_attempts,
                baseline_successes,
                baseline_attempts,
            );
            let statistically_significant =
                franken_rate < baseline_rate && p_value_millionths <= config.max_p_value_millionths;
            let franken_ci = wilson_interval_millionths(franken_successes, franken_attempts);
            let baseline_ci = wilson_interval_millionths(baseline_successes, baseline_attempts);

            comparisons.push(SuppressionComparison {
                attack_category: *category,
                baseline_runtime,
                frankenengine_compromise_rate_millionths: franken_rate,
                baseline_compromise_rate_millionths: baseline_rate,
                frankenengine_confidence_interval_millionths: franken_ci,
                baseline_confidence_interval_millionths: baseline_ci,
                p_value_millionths,
                statistically_significant,
            });

            if !statistically_significant {
                failures.push(SuppressionGateFailure {
                    error_code: ERR_GATE_STATISTICAL_SIGNIFICANCE.to_string(),
                    detail: format!(
                        "category {} vs {} did not pass suppression threshold \
                         (franken_rate={} baseline_rate={} p={})",
                        category, baseline_runtime, franken_rate, baseline_rate, p_value_millionths
                    ),
                    attack_category: Some(*category),
                    baseline_runtime: Some(baseline_runtime),
                    campaign_id: None,
                });
            }

            events.push(CampaignSuppressionEvent {
                trace_id: trace_id.clone(),
                decision_id: decision_id.clone(),
                policy_id: policy_id.clone(),
                component: RED_BLUE_COMPONENT.to_string(),
                event: "suppression_comparison".to_string(),
                outcome: if statistically_significant {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                },
                error_code: if statistically_significant {
                    None
                } else {
                    Some(ERR_GATE_STATISTICAL_SIGNIFICANCE.to_string())
                },
                campaign_id: input.release_candidate_id.clone(),
                attack_category: category.to_string(),
                target_runtime: baseline_runtime.to_string(),
                attempt_count: baseline_attempts,
                success_count: baseline_successes,
                compromise_rate_millionths: baseline_rate,
                p_value_millionths: Some(p_value_millionths),
                confidence_interval: format!(
                    "[{},{}];franken=[{},{}]",
                    baseline_ci.0, baseline_ci.1, franken_ci.0, franken_ci.1
                ),
            });
        }
    }

    let passed = failures.is_empty();
    events.push(CampaignSuppressionEvent {
        trace_id,
        decision_id,
        policy_id,
        component: RED_BLUE_COMPONENT.to_string(),
        event: "suppression_gate_evaluated".to_string(),
        outcome: if passed {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if passed {
            None
        } else if failures
            .iter()
            .any(|failure| failure.error_code == ERR_GATE_ESCALATION_SLA)
        {
            Some(ERR_GATE_ESCALATION_SLA.to_string())
        } else if failures
            .iter()
            .any(|failure| failure.error_code == ERR_GATE_STATISTICAL_SIGNIFICANCE)
        {
            Some(ERR_GATE_STATISTICAL_SIGNIFICANCE.to_string())
        } else if failures
            .iter()
            .any(|failure| failure.error_code == ERR_GATE_MISSING_RUNTIME_COVERAGE)
        {
            Some(ERR_GATE_MISSING_RUNTIME_COVERAGE.to_string())
        } else if failures
            .iter()
            .any(|failure| failure.error_code == ERR_GATE_CONTINUITY)
        {
            Some(ERR_GATE_CONTINUITY.to_string())
        } else {
            Some(ERR_GATE_INVALID_INPUT.to_string())
        },
        campaign_id: input.release_candidate_id.clone(),
        attack_category: "gate_summary".to_string(),
        target_runtime: "release_gate".to_string(),
        attempt_count: input
            .samples
            .iter()
            .map(|sample| sample.attempt_count)
            .sum(),
        success_count: input
            .samples
            .iter()
            .map(|sample| sample.success_count)
            .sum(),
        compromise_rate_millionths: compromise_rate_millionths(
            input
                .samples
                .iter()
                .map(|sample| sample.success_count)
                .sum(),
            input
                .samples
                .iter()
                .map(|sample| sample.attempt_count)
                .sum(),
        ),
        p_value_millionths: None,
        confidence_interval: String::new(),
    });

    Ok(SuppressionGateResult {
        release_candidate_id: input.release_candidate_id.clone(),
        passed,
        comparisons,
        failures,
        trend_points_analyzed: input.trend_points.len(),
        events,
    })
}

fn compromise_rate_millionths(success_count: u64, attempt_count: u64) -> u64 {
    if attempt_count == 0 {
        return 0;
    }
    clamp_millionths((success_count.saturating_mul(1_000_000)) / attempt_count)
}

fn wilson_interval_millionths(success_count: u64, attempt_count: u64) -> (u64, u64) {
    if attempt_count == 0 {
        return (0, 1_000_000);
    }
    let n = attempt_count as f64;
    let p_hat = success_count as f64 / n;
    let z = 1.959_963_984_540_054_f64; // 95% CI
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p_hat + z2 / (2.0 * n)) / denom;
    let margin = z * ((p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n)).sqrt()) / denom;
    let lower = (center - margin).clamp(0.0, 1.0);
    let upper = (center + margin).clamp(0.0, 1.0);
    (
        clamp_millionths((lower * 1_000_000.0).round() as u64),
        clamp_millionths((upper * 1_000_000.0).round() as u64),
    )
}

fn one_sided_p_value_millionths(
    franken_successes: u64,
    franken_attempts: u64,
    baseline_successes: u64,
    baseline_attempts: u64,
) -> u64 {
    if franken_attempts == 0 || baseline_attempts == 0 {
        return 1_000_000;
    }
    let p_franken = franken_successes as f64 / franken_attempts as f64;
    let p_baseline = baseline_successes as f64 / baseline_attempts as f64;
    let pooled = (franken_successes + baseline_successes) as f64
        / (franken_attempts + baseline_attempts) as f64;
    let variance = pooled
        * (1.0 - pooled)
        * ((1.0 / franken_attempts as f64) + (1.0 / baseline_attempts as f64));
    if variance <= f64::EPSILON {
        return if p_baseline > p_franken { 0 } else { 1_000_000 };
    }
    let z = (p_baseline - p_franken) / variance.sqrt();
    let p_value = (1.0 - normal_cdf(z)).clamp(0.0, 1.0);
    clamp_millionths((p_value * 1_000_000.0).round() as u64)
}

fn normal_cdf(value: f64) -> f64 {
    0.5 * (1.0 + erf_approx(value / std::f64::consts::SQRT_2))
}

fn erf_approx(value: f64) -> f64 {
    // Abramowitz and Stegun 7.1.26 approximation.
    let sign = if value < 0.0 { -1.0 } else { 1.0 };
    let x = value.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let y = 1.0
        - (((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t - 0.284_496_736) * t
            + 0.254_829_592)
            * t
            * (-x * x).exp();
    sign * y
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

    fn sample_campaign(complexity: CampaignComplexity, seed: u64) -> AdversarialCampaign {
        let mut generator = CampaignGenerator::new(
            AttackGrammar::default(),
            CampaignGeneratorConfig::default(),
            seed,
        )
        .unwrap();
        generator.generate_campaign(complexity).unwrap()
    }

    fn outcome_record(
        campaign: AdversarialCampaign,
        result: CampaignExecutionResult,
        benign_control: bool,
        false_positive: bool,
        timestamp_ns: u64,
    ) -> CampaignOutcomeRecord {
        let score = ExploitObjectiveScore::from_result(&result).unwrap();
        CampaignOutcomeRecord {
            campaign,
            result,
            score,
            benign_control,
            false_positive,
            timestamp_ns,
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

    #[test]
    fn red_blue_ingest_classifies_escape_as_blocking() {
        let campaign = sample_campaign(CampaignComplexity::Apt, 0xABCD);
        let result = CampaignExecutionResult {
            undetected_steps: campaign.steps.len(),
            total_steps: campaign.steps.len(),
            objective_achieved_before_containment: true,
            damage_potential_millionths: 900_000,
            evidence_atoms_before_detection: 48,
            novel_technique: true,
        };
        let outcome = outcome_record(campaign, result, false, false, 1_700_000_000_100);

        let mut integrator =
            RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
        let classification = integrator.ingest_outcome(outcome).unwrap();

        assert_eq!(classification.severity, CampaignSeverity::Blocking);
        assert_eq!(classification.subsystem, DefenseSubsystem::Containment);
        assert!(classification.containment_escape_report);
        assert!(classification.evasion_report);

        let events = integrator.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].component, RED_BLUE_COMPONENT);
        assert_eq!(events[0].event, "campaign_ingested");
    }

    #[test]
    fn red_blue_calibration_lowers_threshold_when_false_negatives_high() {
        let mut integrator = RedBlueLoopIntegrator::new(
            RedBlueCalibrationConfig {
                target_false_negative_millionths: 100_000,
                max_threshold_delta_millionths: 40_000,
                ..RedBlueCalibrationConfig::default()
            },
            GuardplaneCalibrationState::default(),
        );

        for idx in 0..3u64 {
            let campaign = sample_campaign(CampaignComplexity::Probe, 0x1111 + idx);
            let result = CampaignExecutionResult {
                undetected_steps: campaign.steps.len(),
                total_steps: campaign.steps.len(),
                objective_achieved_before_containment: true,
                damage_potential_millionths: 700_000 + (idx * 10_000),
                evidence_atoms_before_detection: 50,
                novel_technique: false,
            };
            integrator
                .ingest_outcome(outcome_record(
                    campaign,
                    result,
                    false,
                    false,
                    1_700_000_000_200 + idx,
                ))
                .unwrap();
        }

        let signing_key = [21u8; 32];
        let old_threshold = integrator
            .calibration_state()
            .detection_threshold_millionths;
        let receipt = integrator
            .calibrate(&signing_key, 1_700_000_010_000)
            .unwrap()
            .unwrap();
        let new_threshold = integrator
            .calibration_state()
            .detection_threshold_millionths;

        assert!(new_threshold < old_threshold);
        assert!(old_threshold - new_threshold <= 40_000);
        assert_eq!(receipt.signature.len(), 64);
        assert_ne!(receipt.old_parameters, receipt.new_parameters);
        assert!(!receipt.campaign_ids.is_empty());
    }

    #[test]
    fn red_blue_calibration_raises_threshold_on_false_positive_pressure() {
        let mut integrator = RedBlueLoopIntegrator::new(
            RedBlueCalibrationConfig {
                target_false_positive_millionths: 200_000,
                max_threshold_delta_millionths: 30_000,
                ..RedBlueCalibrationConfig::default()
            },
            GuardplaneCalibrationState::default(),
        );

        for idx in 0..4u64 {
            let campaign = sample_campaign(CampaignComplexity::Probe, 0x2222 + idx);
            let result = CampaignExecutionResult {
                undetected_steps: 0,
                total_steps: campaign.steps.len(),
                objective_achieved_before_containment: false,
                damage_potential_millionths: 50_000,
                evidence_atoms_before_detection: 3,
                novel_technique: false,
            };
            integrator
                .ingest_outcome(outcome_record(
                    campaign,
                    result,
                    true,
                    true,
                    1_700_000_000_300 + idx,
                ))
                .unwrap();
        }

        let signing_key = [22u8; 32];
        let old_threshold = integrator
            .calibration_state()
            .detection_threshold_millionths;
        let _receipt = integrator
            .calibrate(&signing_key, 1_700_000_020_000)
            .unwrap()
            .unwrap();
        let new_threshold = integrator
            .calibration_state()
            .detection_threshold_millionths;

        assert!(new_threshold > old_threshold);
        assert!(new_threshold - old_threshold <= 30_000);
    }

    #[test]
    fn red_blue_regression_promotion_and_gate_enforcement() {
        let campaign = sample_campaign(CampaignComplexity::Probe, 0x3333);
        let campaign_id = campaign.campaign_id.clone();
        let result = CampaignExecutionResult {
            undetected_steps: campaign.steps.len().saturating_sub(1),
            total_steps: campaign.steps.len(),
            objective_achieved_before_containment: false,
            damage_potential_millionths: 450_000,
            evidence_atoms_before_detection: 18,
            novel_technique: true,
        };

        let mut integrator =
            RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
        integrator
            .ingest_outcome(outcome_record(
                campaign,
                result,
                false,
                false,
                1_700_000_000_400,
            ))
            .unwrap();

        let entry = integrator
            .promote_regression_fixture(&campaign_id, "containment", "late-detect", None)
            .unwrap();
        assert_eq!(entry.campaign_id, campaign_id);
        assert_eq!(integrator.regression_suite().len(), 1);

        let pass_decision = integrator.evaluate_regression_gate(&[RegressionReplayResult {
            campaign_id: entry.campaign_id.clone(),
            passed: true,
        }]);
        assert!(pass_decision.passed);

        let fail_decision = integrator.evaluate_regression_gate(&[]);
        assert!(!fail_decision.passed);
        assert_eq!(fail_decision.failed_campaign_ids, vec![entry.campaign_id]);
    }

    #[test]
    fn red_blue_critical_counterfactual_hints_are_emitted() {
        let campaign = sample_campaign(CampaignComplexity::MultiStage, 0x4444);
        let campaign_id = campaign.campaign_id.clone();
        let result = CampaignExecutionResult {
            undetected_steps: campaign.steps.len(),
            total_steps: campaign.steps.len(),
            objective_achieved_before_containment: true,
            damage_potential_millionths: 810_000,
            evidence_atoms_before_detection: 60,
            novel_technique: true,
        };
        let mut integrator =
            RedBlueLoopIntegrator::new(RedBlueCalibrationConfig::default(), Default::default());
        integrator
            .ingest_outcome(outcome_record(
                campaign,
                result,
                false,
                false,
                1_700_000_000_500,
            ))
            .unwrap();

        let hints = integrator.critical_counterfactual_hints();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].campaign_id, campaign_id);
        assert!(hints[0].description.contains("threshold delta"));
    }

    fn suppression_sample(
        campaign_id: &str,
        attack_category: CampaignAttackCategory,
        target_runtime: CampaignRuntime,
        attempt_count: u64,
        success_count: u64,
    ) -> CampaignSuppressionSample {
        CampaignSuppressionSample {
            campaign_id: campaign_id.to_string(),
            attack_category,
            target_runtime,
            attempt_count,
            success_count,
            raw_log_ref: format!("artifacts/raw/{campaign_id}.jsonl"),
            repro_script_ref: format!("artifacts/repro/{campaign_id}.sh"),
        }
    }

    fn required_category_triples(
        franken_success: u64,
        baseline_node_success: u64,
        baseline_bun_success: u64,
    ) -> Vec<CampaignSuppressionSample> {
        CampaignAttackCategory::ALL
            .iter()
            .flat_map(|category| {
                [
                    suppression_sample(
                        &format!("camp-fe-{category}"),
                        *category,
                        CampaignRuntime::FrankenEngine,
                        250,
                        franken_success,
                    ),
                    suppression_sample(
                        &format!("camp-node-{category}"),
                        *category,
                        CampaignRuntime::NodeLts,
                        250,
                        baseline_node_success,
                    ),
                    suppression_sample(
                        &format!("camp-bun-{category}"),
                        *category,
                        CampaignRuntime::BunStable,
                        250,
                        baseline_bun_success,
                    ),
                ]
            })
            .collect()
    }

    #[test]
    fn suppression_gate_passes_with_significant_multibaseline_advantage() {
        let input = SuppressionGateInput {
            release_candidate_id: "rc-2026-02-22".to_string(),
            continuous_run: true,
            samples: required_category_triples(0, 45, 38),
            trend_points: vec![
                CampaignTrendPoint {
                    release_candidate_id: "rc-2026-02-20".to_string(),
                    timestamp_ns: 1_700_000_000_000,
                    samples_evaluated: 600,
                },
                CampaignTrendPoint {
                    release_candidate_id: "rc-2026-02-21".to_string(),
                    timestamp_ns: 1_700_000_100_000,
                    samples_evaluated: 620,
                },
            ],
            escalations: Vec::new(),
        };

        let result =
            evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default())
                .expect("suppression gate");

        assert!(result.passed);
        assert!(result.failures.is_empty());
        assert_eq!(
            result.comparisons.len(),
            CampaignAttackCategory::ALL.len() * 2
        );
        assert!(
            result
                .comparisons
                .iter()
                .all(|comparison| comparison.statistically_significant)
        );

        let comparison_events = result
            .events
            .iter()
            .filter(|event| event.event == "suppression_comparison")
            .collect::<Vec<_>>();
        assert_eq!(
            comparison_events.len(),
            CampaignAttackCategory::ALL.len() * 2
        );
        for event in comparison_events {
            assert!(!event.trace_id.is_empty());
            assert!(!event.decision_id.is_empty());
            assert!(!event.policy_id.is_empty());
            assert_eq!(event.component, RED_BLUE_COMPONENT);
            assert!(!event.attack_category.is_empty());
            assert!(!event.target_runtime.is_empty());
            assert!(event.p_value_millionths.is_some());
        }
    }

    #[test]
    fn suppression_gate_fails_on_continuity_significance_and_escalation_sla() {
        let mut samples = required_category_triples(24, 25, 26);
        samples.push(suppression_sample(
            "camp-fe-success",
            CampaignAttackCategory::Injection,
            CampaignRuntime::FrankenEngine,
            80,
            10,
        ));

        let input = SuppressionGateInput {
            release_candidate_id: "rc-2026-02-23".to_string(),
            continuous_run: false,
            samples,
            trend_points: vec![CampaignTrendPoint {
                release_candidate_id: "rc-2026-02-22".to_string(),
                timestamp_ns: 1_700_000_200_000,
                samples_evaluated: 400,
            }],
            escalations: vec![ExploitEscalationRecord {
                campaign_id: "camp-fe-success".to_string(),
                attack_category: CampaignAttackCategory::Injection,
                target_runtime: CampaignRuntime::FrankenEngine,
                successful_exploit: true,
                escalation_triggered: true,
                escalation_latency_seconds: Some(7_200),
            }],
        };

        let result =
            evaluate_compromise_suppression_gate(&input, &SuppressionGateConfig::default())
                .expect("suppression gate");

        assert!(!result.passed);
        assert!(result.failures.iter().any(|failure| {
            failure.error_code == ERR_GATE_CONTINUITY && failure.detail.contains("continuous_run")
        }));
        assert!(
            result
                .failures
                .iter()
                .any(|failure| failure.error_code == ERR_GATE_STATISTICAL_SIGNIFICANCE)
        );
        assert!(
            result
                .failures
                .iter()
                .any(|failure| failure.error_code == ERR_GATE_ESCALATION_SLA)
        );
        assert!(result.events.iter().any(|event| {
            event.event == "suppression_gate_evaluated" && event.outcome == "fail"
        }));
    }
}
