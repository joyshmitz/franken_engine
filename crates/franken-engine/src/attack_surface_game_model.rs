//! Attack-Surface Game Model and Asymmetric Loss Formalization.
//!
//! Models compiler/runtime/control-plane attack-defense interactions as
//! sequential games with explicit asymmetric losses and action constraints.
//!
//! Deliverables:
//! - strategic attacker/defender action spaces by subsystem,
//! - payoff/loss tensors (user harm, performance cost, false-positive cost),
//! - admissible defense actions with hard constraints,
//! - machine-readable game model artifacts for simulation and policy synthesis.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Plan reference: FRX-18.1 (Attack-Surface Game Model).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for game model artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.attack-surface-game.v1";

// ---------------------------------------------------------------------------
// Subsystem — which engine subsystem is being modeled
// ---------------------------------------------------------------------------

/// Engine subsystem that defines an attack surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    /// Compiler front-end (parser, binder, type checker).
    Compiler,
    /// Runtime execution (JS lane, WASM lane, scheduler).
    Runtime,
    /// Control plane (policy evaluation, epoch management).
    ControlPlane,
    /// Extension host (loading, sandboxing, lifecycle).
    ExtensionHost,
    /// Evidence pipeline (emission, storage, verification).
    EvidencePipeline,
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compiler => f.write_str("compiler"),
            Self::Runtime => f.write_str("runtime"),
            Self::ControlPlane => f.write_str("control_plane"),
            Self::ExtensionHost => f.write_str("extension_host"),
            Self::EvidencePipeline => f.write_str("evidence_pipeline"),
        }
    }
}

// ---------------------------------------------------------------------------
// Player — attacker vs defender
// ---------------------------------------------------------------------------

/// Player role in the game.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Player {
    /// Attacker: tries to compromise integrity, availability, or performance.
    Attacker,
    /// Defender: the engine's security/governance system.
    Defender,
}

impl fmt::Display for Player {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attacker => f.write_str("attacker"),
            Self::Defender => f.write_str("defender"),
        }
    }
}

// ---------------------------------------------------------------------------
// ActionId + ActionSpace — strategic actions available to each player
// ---------------------------------------------------------------------------

/// Identifier for a strategic action.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ActionId(pub String);

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single action in a player's action space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategicAction {
    /// Action identifier.
    pub action_id: ActionId,
    /// Which player owns this action.
    pub player: Player,
    /// Subsystem this action targets.
    pub subsystem: Subsystem,
    /// Human-readable description.
    pub description: String,
    /// Whether this action is admissible (defender-only constraint).
    pub admissible: bool,
    /// Hard constraints that must hold if this action is taken.
    pub constraints: Vec<String>,
}

/// Action space for a given (player, subsystem) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSpace {
    /// Player.
    pub player: Player,
    /// Subsystem.
    pub subsystem: Subsystem,
    /// Available actions.
    pub actions: Vec<StrategicAction>,
}

impl ActionSpace {
    /// Number of actions.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Admissible actions only (defender actions that satisfy constraints).
    pub fn admissible_actions(&self) -> Vec<&StrategicAction> {
        self.actions.iter().filter(|a| a.admissible).collect()
    }
}

// ---------------------------------------------------------------------------
// LossDimension — categories of loss
// ---------------------------------------------------------------------------

/// Dimension of loss in the payoff tensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossDimension {
    /// Direct user harm (data loss, incorrect behavior).
    UserHarm,
    /// Performance degradation (latency, throughput).
    PerformanceCost,
    /// False-positive containment (unnecessary quarantine/restriction).
    FalsePositiveCost,
    /// Availability impact (service disruption).
    AvailabilityCost,
    /// Evidence integrity compromise.
    EvidenceIntegrityCost,
}

impl fmt::Display for LossDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserHarm => f.write_str("user_harm"),
            Self::PerformanceCost => f.write_str("performance_cost"),
            Self::FalsePositiveCost => f.write_str("false_positive_cost"),
            Self::AvailabilityCost => f.write_str("availability_cost"),
            Self::EvidenceIntegrityCost => f.write_str("evidence_integrity_cost"),
        }
    }
}

// ---------------------------------------------------------------------------
// LossTensor — payoff structure for (attacker_action, defender_action) pairs
// ---------------------------------------------------------------------------

/// A loss entry for a specific (attacker, defender) action pair and dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossEntry {
    /// Attacker action.
    pub attacker_action: ActionId,
    /// Defender action.
    pub defender_action: ActionId,
    /// Loss dimension.
    pub dimension: LossDimension,
    /// Loss value (millionths; positive = harm, negative = benefit).
    pub loss_millionths: i64,
}

/// Loss tensor: collection of loss entries forming the game payoff structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossTensor {
    /// Subsystem this tensor models.
    pub subsystem: Subsystem,
    /// All loss entries.
    pub entries: Vec<LossEntry>,
    /// Content hash.
    pub content_hash: String,
}

impl LossTensor {
    /// Build a tensor from entries, computing the content hash.
    pub fn from_entries(subsystem: Subsystem, mut entries: Vec<LossEntry>) -> Self {
        entries.sort_by(|a, b| {
            a.attacker_action
                .cmp(&b.attacker_action)
                .then(a.defender_action.cmp(&b.defender_action))
                .then(a.dimension.cmp(&b.dimension))
        });

        let mut hasher = Sha256::new();
        hasher.update(subsystem.to_string().as_bytes());
        for e in &entries {
            hasher.update(e.attacker_action.0.as_bytes());
            hasher.update(e.defender_action.0.as_bytes());
            hasher.update(e.dimension.to_string().as_bytes());
            hasher.update(e.loss_millionths.to_le_bytes());
        }
        let content_hash = hex::encode(&hasher.finalize()[..16]);

        Self {
            subsystem,
            entries,
            content_hash,
        }
    }

    /// Look up loss for a specific (attacker, defender, dimension) triple.
    pub fn lookup(
        &self,
        attacker: &ActionId,
        defender: &ActionId,
        dimension: LossDimension,
    ) -> Option<i64> {
        self.entries
            .iter()
            .find(|e| {
                e.attacker_action == *attacker
                    && e.defender_action == *defender
                    && e.dimension == dimension
            })
            .map(|e| e.loss_millionths)
    }

    /// Compute total loss for a (attacker, defender) pair across all dimensions.
    pub fn total_loss(&self, attacker: &ActionId, defender: &ActionId) -> i64 {
        self.entries
            .iter()
            .filter(|e| e.attacker_action == *attacker && e.defender_action == *defender)
            .map(|e| e.loss_millionths)
            .sum()
    }

    /// Find the minimax defender action: minimize the maximum attacker payoff.
    pub fn minimax_defender(&self) -> Option<ActionId> {
        let defender_ids: BTreeSet<&ActionId> =
            self.entries.iter().map(|e| &e.defender_action).collect();
        let attacker_ids: BTreeSet<&ActionId> =
            self.entries.iter().map(|e| &e.attacker_action).collect();

        defender_ids
            .into_iter()
            .map(|d| {
                let max_loss = attacker_ids
                    .iter()
                    .map(|a| self.total_loss(a, d))
                    .max()
                    .unwrap_or(0);
                (d, max_loss)
            })
            .min_by_key(|(_, loss)| *loss)
            .map(|(d, _)| d.clone())
    }
}

// ---------------------------------------------------------------------------
// AdmissibleActionAutomaton — hard constraints on defender moves
// ---------------------------------------------------------------------------

/// A constraint on defender actions (hard, cannot be violated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardConstraint {
    /// Constraint identifier.
    pub constraint_id: String,
    /// Human-readable description.
    pub description: String,
    /// Defender actions forbidden by this constraint.
    pub forbidden_actions: BTreeSet<ActionId>,
    /// Conditions under which this constraint is active.
    pub active_conditions: Vec<String>,
}

/// Automaton encoding admissible defender actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissibleActionAutomaton {
    /// Subsystem.
    pub subsystem: Subsystem,
    /// All hard constraints.
    pub constraints: Vec<HardConstraint>,
    /// Full defender action set.
    pub all_defender_actions: BTreeSet<ActionId>,
}

impl AdmissibleActionAutomaton {
    /// Compute admissible actions (all actions minus forbidden ones).
    pub fn admissible_actions(&self) -> BTreeSet<ActionId> {
        let mut forbidden = BTreeSet::new();
        for c in &self.constraints {
            for a in &c.forbidden_actions {
                forbidden.insert(a.clone());
            }
        }
        self.all_defender_actions
            .iter()
            .filter(|a| !forbidden.contains(a))
            .cloned()
            .collect()
    }

    /// Check if a specific action is admissible.
    pub fn is_admissible(&self, action: &ActionId) -> bool {
        self.all_defender_actions.contains(action)
            && !self
                .constraints
                .iter()
                .any(|c| c.forbidden_actions.contains(action))
    }

    /// Number of total constraints.
    pub fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
}

// ---------------------------------------------------------------------------
// GameModel — complete game specification for a subsystem
// ---------------------------------------------------------------------------

/// Complete game model for an attack-defense interaction on a subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameModel {
    /// Model identifier (content-addressed).
    pub model_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Subsystem being modeled.
    pub subsystem: Subsystem,
    /// Attacker action space.
    pub attacker_actions: ActionSpace,
    /// Defender action space.
    pub defender_actions: ActionSpace,
    /// Loss tensor.
    pub loss_tensor: LossTensor,
    /// Admissible action automaton.
    pub automaton: AdmissibleActionAutomaton,
    /// Model content hash.
    pub content_hash: String,
}

impl GameModel {
    /// Compute a content-addressed model ID.
    pub fn compute_model_id(subsystem: &Subsystem, epoch: &SecurityEpoch) -> String {
        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(subsystem.to_string().as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        format!("game-{}", hex::encode(&hasher.finalize()[..12]))
    }

    /// Minimax recommended defender action.
    pub fn minimax_recommendation(&self) -> Option<ActionId> {
        self.loss_tensor.minimax_defender()
    }

    /// Number of attacker actions.
    pub fn attacker_action_count(&self) -> usize {
        self.attacker_actions.action_count()
    }

    /// Number of defender actions.
    pub fn defender_action_count(&self) -> usize {
        self.defender_actions.action_count()
    }

    /// Number of admissible defender actions.
    pub fn admissible_count(&self) -> usize {
        self.automaton.admissible_actions().len()
    }
}

// ---------------------------------------------------------------------------
// GameModelBuilder — fluent builder
// ---------------------------------------------------------------------------

/// Builder for constructing a `GameModel`.
#[derive(Debug, Clone)]
pub struct GameModelBuilder {
    epoch: SecurityEpoch,
    subsystem: Subsystem,
    attacker_actions: Vec<StrategicAction>,
    defender_actions: Vec<StrategicAction>,
    loss_entries: Vec<LossEntry>,
    constraints: Vec<HardConstraint>,
}

impl GameModelBuilder {
    /// Create a new builder.
    pub fn new(subsystem: Subsystem, epoch: SecurityEpoch) -> Self {
        Self {
            epoch,
            subsystem,
            attacker_actions: Vec::new(),
            defender_actions: Vec::new(),
            loss_entries: Vec::new(),
            constraints: Vec::new(),
        }
    }

    /// Add an attacker action.
    pub fn attacker_action(mut self, action: StrategicAction) -> Self {
        self.attacker_actions.push(action);
        self
    }

    /// Add a defender action.
    pub fn defender_action(mut self, action: StrategicAction) -> Self {
        self.defender_actions.push(action);
        self
    }

    /// Add a loss entry.
    pub fn loss(mut self, entry: LossEntry) -> Self {
        self.loss_entries.push(entry);
        self
    }

    /// Add a hard constraint.
    pub fn constraint(mut self, constraint: HardConstraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Build the game model.
    pub fn build(self) -> GameModel {
        let model_id = GameModel::compute_model_id(&self.subsystem, &self.epoch);

        let attacker_space = ActionSpace {
            player: Player::Attacker,
            subsystem: self.subsystem,
            actions: self.attacker_actions,
        };

        let all_defender_ids: BTreeSet<ActionId> = self
            .defender_actions
            .iter()
            .map(|a| a.action_id.clone())
            .collect();

        let defender_space = ActionSpace {
            player: Player::Defender,
            subsystem: self.subsystem,
            actions: self.defender_actions,
        };

        let loss_tensor = LossTensor::from_entries(self.subsystem, self.loss_entries);

        let automaton = AdmissibleActionAutomaton {
            subsystem: self.subsystem,
            constraints: self.constraints,
            all_defender_actions: all_defender_ids,
        };

        let mut hasher = Sha256::new();
        hasher.update(model_id.as_bytes());
        hasher.update(loss_tensor.content_hash.as_bytes());
        hasher.update((attacker_space.action_count() as u64).to_le_bytes());
        hasher.update((defender_space.action_count() as u64).to_le_bytes());
        let content_hash = hex::encode(&hasher.finalize()[..16]);

        GameModel {
            model_id,
            schema_version: SCHEMA_VERSION.to_string(),
            epoch: self.epoch,
            subsystem: self.subsystem,
            attacker_actions: attacker_space,
            defender_actions: defender_space,
            loss_tensor,
            automaton,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// GameModelReport — CI-readable summary
// ---------------------------------------------------------------------------

/// CI-readable report of game model analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameModelReport {
    /// Schema version.
    pub schema_version: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Per-subsystem summary.
    pub subsystem_summaries: BTreeMap<String, SubsystemSummary>,
    /// Total models.
    pub total_models: usize,
    /// Total attacker actions across all models.
    pub total_attacker_actions: usize,
    /// Total defender actions across all models.
    pub total_defender_actions: usize,
    /// Total constraints across all models.
    pub total_constraints: usize,
    /// Report content hash.
    pub report_hash: String,
}

/// Summary for a single subsystem's game model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemSummary {
    /// Subsystem name.
    pub subsystem: String,
    /// Attacker action count.
    pub attacker_actions: usize,
    /// Defender action count.
    pub defender_actions: usize,
    /// Admissible defender actions.
    pub admissible_actions: usize,
    /// Hard constraint count.
    pub constraints: usize,
    /// Minimax recommended action, if any.
    pub minimax_recommendation: Option<String>,
}

/// Generate a `GameModelReport` from a collection of game models.
pub fn generate_report(models: &[GameModel], epoch: &SecurityEpoch) -> GameModelReport {
    let mut summaries = BTreeMap::new();
    let mut total_attacker = 0usize;
    let mut total_defender = 0usize;
    let mut total_constraints = 0usize;

    for model in models {
        let minimax = model.minimax_recommendation().map(|a| a.0);
        let admissible = model.admissible_count();
        let summary = SubsystemSummary {
            subsystem: model.subsystem.to_string(),
            attacker_actions: model.attacker_action_count(),
            defender_actions: model.defender_action_count(),
            admissible_actions: admissible,
            constraints: model.automaton.constraint_count(),
            minimax_recommendation: minimax,
        };
        total_attacker += summary.attacker_actions;
        total_defender += summary.defender_actions;
        total_constraints += summary.constraints;
        summaries.insert(model.subsystem.to_string(), summary);
    }

    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update((models.len() as u64).to_le_bytes());
    hasher.update((total_attacker as u64).to_le_bytes());
    let report_hash = hex::encode(&hasher.finalize()[..16]);

    GameModelReport {
        schema_version: SCHEMA_VERSION.to_string(),
        epoch: *epoch,
        subsystem_summaries: summaries,
        total_models: models.len(),
        total_attacker_actions: total_attacker,
        total_defender_actions: total_defender,
        total_constraints,
        report_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(7)
    }

    fn atk(name: &str) -> ActionId {
        ActionId(name.to_string())
    }

    fn make_attacker_action(name: &str, sub: Subsystem) -> StrategicAction {
        StrategicAction {
            action_id: atk(name),
            player: Player::Attacker,
            subsystem: sub,
            description: format!("Attack: {name}"),
            admissible: true,
            constraints: Vec::new(),
        }
    }

    fn make_defender_action(name: &str, sub: Subsystem) -> StrategicAction {
        StrategicAction {
            action_id: atk(name),
            player: Player::Defender,
            subsystem: sub,
            description: format!("Defend: {name}"),
            admissible: true,
            constraints: Vec::new(),
        }
    }

    // -- Subsystem tests --

    #[test]
    fn subsystem_display_all_five() {
        let subs = [
            Subsystem::Compiler,
            Subsystem::Runtime,
            Subsystem::ControlPlane,
            Subsystem::ExtensionHost,
            Subsystem::EvidencePipeline,
        ];
        let names: Vec<String> = subs.iter().map(|s| s.to_string()).collect();
        let unique: BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn subsystem_serde_roundtrip() {
        for s in [
            Subsystem::Compiler,
            Subsystem::Runtime,
            Subsystem::ControlPlane,
            Subsystem::ExtensionHost,
            Subsystem::EvidencePipeline,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: Subsystem = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    // -- Player tests --

    #[test]
    fn player_display() {
        assert_eq!(Player::Attacker.to_string(), "attacker");
        assert_eq!(Player::Defender.to_string(), "defender");
    }

    #[test]
    fn player_serde_roundtrip() {
        for p in [Player::Attacker, Player::Defender] {
            let json = serde_json::to_string(&p).unwrap();
            let back: Player = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    // -- LossDimension tests --

    #[test]
    fn loss_dimension_display_all() {
        let dims = [
            LossDimension::UserHarm,
            LossDimension::PerformanceCost,
            LossDimension::FalsePositiveCost,
            LossDimension::AvailabilityCost,
            LossDimension::EvidenceIntegrityCost,
        ];
        let names: Vec<String> = dims.iter().map(|d| d.to_string()).collect();
        let unique: BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn loss_dimension_serde_roundtrip() {
        for d in [
            LossDimension::UserHarm,
            LossDimension::PerformanceCost,
            LossDimension::FalsePositiveCost,
            LossDimension::AvailabilityCost,
            LossDimension::EvidenceIntegrityCost,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: LossDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    // -- LossTensor tests --

    #[test]
    fn tensor_lookup() {
        let entries = vec![
            LossEntry {
                attacker_action: atk("inject"),
                defender_action: atk("block"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 100_000,
            },
            LossEntry {
                attacker_action: atk("inject"),
                defender_action: atk("block"),
                dimension: LossDimension::PerformanceCost,
                loss_millionths: 50_000,
            },
        ];
        let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);

        assert_eq!(
            tensor.lookup(&atk("inject"), &atk("block"), LossDimension::UserHarm),
            Some(100_000),
        );
        assert_eq!(
            tensor.lookup(
                &atk("inject"),
                &atk("block"),
                LossDimension::FalsePositiveCost
            ),
            None,
        );
    }

    #[test]
    fn tensor_total_loss() {
        let entries = vec![
            LossEntry {
                attacker_action: atk("a1"),
                defender_action: atk("d1"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 300_000,
            },
            LossEntry {
                attacker_action: atk("a1"),
                defender_action: atk("d1"),
                dimension: LossDimension::PerformanceCost,
                loss_millionths: 200_000,
            },
        ];
        let tensor = LossTensor::from_entries(Subsystem::Compiler, entries);
        assert_eq!(tensor.total_loss(&atk("a1"), &atk("d1")), 500_000);
    }

    #[test]
    fn tensor_content_hash_deterministic() {
        let entries = vec![LossEntry {
            attacker_action: atk("a"),
            defender_action: atk("d"),
            dimension: LossDimension::UserHarm,
            loss_millionths: 100_000,
        }];
        let t1 = LossTensor::from_entries(Subsystem::Runtime, entries.clone());
        let t2 = LossTensor::from_entries(Subsystem::Runtime, entries);
        assert_eq!(t1.content_hash, t2.content_hash);
    }

    #[test]
    fn tensor_serde_roundtrip() {
        let entries = vec![LossEntry {
            attacker_action: atk("a"),
            defender_action: atk("d"),
            dimension: LossDimension::UserHarm,
            loss_millionths: 100_000,
        }];
        let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
        let json = serde_json::to_string(&tensor).unwrap();
        let back: LossTensor = serde_json::from_str(&json).unwrap();
        assert_eq!(tensor, back);
    }

    #[test]
    fn tensor_minimax_defender() {
        // d1 has max-loss 500k (from a1), d2 has max-loss 300k (from a1).
        // Minimax picks d2.
        let entries = vec![
            LossEntry {
                attacker_action: atk("a1"),
                defender_action: atk("d1"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 500_000,
            },
            LossEntry {
                attacker_action: atk("a1"),
                defender_action: atk("d2"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 300_000,
            },
            LossEntry {
                attacker_action: atk("a2"),
                defender_action: atk("d1"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 200_000,
            },
            LossEntry {
                attacker_action: atk("a2"),
                defender_action: atk("d2"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 250_000,
            },
        ];
        let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
        let minimax = tensor.minimax_defender().unwrap();
        assert_eq!(minimax, atk("d2"));
    }

    // -- AdmissibleActionAutomaton tests --

    #[test]
    fn automaton_admissible_with_no_constraints() {
        let automaton = AdmissibleActionAutomaton {
            subsystem: Subsystem::Runtime,
            constraints: Vec::new(),
            all_defender_actions: BTreeSet::from([atk("d1"), atk("d2")]),
        };
        assert_eq!(automaton.admissible_actions().len(), 2);
        assert!(automaton.is_admissible(&atk("d1")));
    }

    #[test]
    fn automaton_filters_forbidden() {
        let automaton = AdmissibleActionAutomaton {
            subsystem: Subsystem::Runtime,
            constraints: vec![HardConstraint {
                constraint_id: "c1".to_string(),
                description: "no kill".to_string(),
                forbidden_actions: BTreeSet::from([atk("kill")]),
                active_conditions: vec!["always".to_string()],
            }],
            all_defender_actions: BTreeSet::from([atk("block"), atk("kill"), atk("sandbox")]),
        };
        let admissible = automaton.admissible_actions();
        assert_eq!(admissible.len(), 2);
        assert!(!automaton.is_admissible(&atk("kill")));
        assert!(automaton.is_admissible(&atk("block")));
    }

    #[test]
    fn automaton_serde_roundtrip() {
        let automaton = AdmissibleActionAutomaton {
            subsystem: Subsystem::ControlPlane,
            constraints: vec![HardConstraint {
                constraint_id: "c1".to_string(),
                description: "test".to_string(),
                forbidden_actions: BTreeSet::from([atk("x")]),
                active_conditions: vec!["always".to_string()],
            }],
            all_defender_actions: BTreeSet::from([atk("x"), atk("y")]),
        };
        let json = serde_json::to_string(&automaton).unwrap();
        let back: AdmissibleActionAutomaton = serde_json::from_str(&json).unwrap();
        assert_eq!(automaton, back);
    }

    // -- GameModelBuilder tests --

    #[test]
    fn builder_creates_model() {
        let model = GameModelBuilder::new(Subsystem::Runtime, test_epoch())
            .attacker_action(make_attacker_action("inject", Subsystem::Runtime))
            .defender_action(make_defender_action("block", Subsystem::Runtime))
            .loss(LossEntry {
                attacker_action: atk("inject"),
                defender_action: atk("block"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 100_000,
            })
            .build();

        assert!(model.model_id.starts_with("game-"));
        assert_eq!(model.subsystem, Subsystem::Runtime);
        assert_eq!(model.attacker_action_count(), 1);
        assert_eq!(model.defender_action_count(), 1);
    }

    #[test]
    fn model_id_deterministic() {
        let id1 = GameModel::compute_model_id(&Subsystem::Compiler, &test_epoch());
        let id2 = GameModel::compute_model_id(&Subsystem::Compiler, &test_epoch());
        assert_eq!(id1, id2);
    }

    #[test]
    fn model_id_differs_by_subsystem() {
        let id1 = GameModel::compute_model_id(&Subsystem::Compiler, &test_epoch());
        let id2 = GameModel::compute_model_id(&Subsystem::Runtime, &test_epoch());
        assert_ne!(id1, id2);
    }

    #[test]
    fn builder_with_constraint() {
        let model = GameModelBuilder::new(Subsystem::ControlPlane, test_epoch())
            .attacker_action(make_attacker_action("a1", Subsystem::ControlPlane))
            .defender_action(make_defender_action("d1", Subsystem::ControlPlane))
            .defender_action(make_defender_action("d2", Subsystem::ControlPlane))
            .constraint(HardConstraint {
                constraint_id: "safe-mode".to_string(),
                description: "Must maintain safe-mode guarantee".to_string(),
                forbidden_actions: BTreeSet::from([atk("d1")]),
                active_conditions: vec!["always".to_string()],
            })
            .build();

        assert_eq!(model.defender_action_count(), 2);
        assert_eq!(model.admissible_count(), 1);
    }

    #[test]
    fn model_serde_roundtrip() {
        let model = GameModelBuilder::new(Subsystem::ExtensionHost, test_epoch())
            .attacker_action(make_attacker_action("escape", Subsystem::ExtensionHost))
            .defender_action(make_defender_action("sandbox", Subsystem::ExtensionHost))
            .loss(LossEntry {
                attacker_action: atk("escape"),
                defender_action: atk("sandbox"),
                dimension: LossDimension::AvailabilityCost,
                loss_millionths: 200_000,
            })
            .build();

        let json = serde_json::to_string(&model).unwrap();
        let back: GameModel = serde_json::from_str(&json).unwrap();
        assert_eq!(model, back);
    }

    // -- GameModelReport tests --

    #[test]
    fn report_empty() {
        let report = generate_report(&[], &test_epoch());
        assert_eq!(report.total_models, 0);
        assert_eq!(report.total_attacker_actions, 0);
    }

    #[test]
    fn report_with_models() {
        let m1 = GameModelBuilder::new(Subsystem::Runtime, test_epoch())
            .attacker_action(make_attacker_action("a1", Subsystem::Runtime))
            .attacker_action(make_attacker_action("a2", Subsystem::Runtime))
            .defender_action(make_defender_action("d1", Subsystem::Runtime))
            .loss(LossEntry {
                attacker_action: atk("a1"),
                defender_action: atk("d1"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 100_000,
            })
            .build();

        let m2 = GameModelBuilder::new(Subsystem::Compiler, test_epoch())
            .attacker_action(make_attacker_action("a3", Subsystem::Compiler))
            .defender_action(make_defender_action("d2", Subsystem::Compiler))
            .build();

        let report = generate_report(&[m1, m2], &test_epoch());
        assert_eq!(report.total_models, 2);
        assert_eq!(report.total_attacker_actions, 3);
        assert_eq!(report.total_defender_actions, 2);
        assert!(report.subsystem_summaries.contains_key("runtime"));
        assert!(report.subsystem_summaries.contains_key("compiler"));
    }

    #[test]
    fn report_hash_deterministic() {
        let r1 = generate_report(&[], &test_epoch());
        let r2 = generate_report(&[], &test_epoch());
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn report_serde_roundtrip() {
        let report = generate_report(&[], &test_epoch());
        let json = serde_json::to_string(&report).unwrap();
        let back: GameModelReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -- ActionSpace tests --

    #[test]
    fn action_space_count() {
        let space = ActionSpace {
            player: Player::Attacker,
            subsystem: Subsystem::Runtime,
            actions: vec![
                make_attacker_action("a1", Subsystem::Runtime),
                make_attacker_action("a2", Subsystem::Runtime),
            ],
        };
        assert_eq!(space.action_count(), 2);
    }

    #[test]
    fn action_space_admissible_filter() {
        let mut action = make_defender_action("d1", Subsystem::Runtime);
        action.admissible = false;
        let space = ActionSpace {
            player: Player::Defender,
            subsystem: Subsystem::Runtime,
            actions: vec![make_defender_action("d2", Subsystem::Runtime), action],
        };
        assert_eq!(space.admissible_actions().len(), 1);
    }

    // -- HardConstraint tests --

    #[test]
    fn hard_constraint_serde_roundtrip() {
        let c = HardConstraint {
            constraint_id: "c1".to_string(),
            description: "test".to_string(),
            forbidden_actions: BTreeSet::from([atk("x")]),
            active_conditions: vec!["always".to_string()],
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: HardConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -- StrategicAction tests --

    #[test]
    fn strategic_action_serde_roundtrip() {
        let a = make_attacker_action("test", Subsystem::Compiler);
        let json = serde_json::to_string(&a).unwrap();
        let back: StrategicAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- enrichment tests ---

    #[test]
    fn tensor_lookup_nonexistent_pair_returns_none() {
        let entries = vec![LossEntry {
            attacker_action: atk("a1"),
            defender_action: atk("d1"),
            dimension: LossDimension::UserHarm,
            loss_millionths: 100_000,
        }];
        let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
        assert_eq!(
            tensor.lookup(&atk("a1"), &atk("d2"), LossDimension::UserHarm),
            None
        );
        assert_eq!(
            tensor.lookup(&atk("a2"), &atk("d1"), LossDimension::UserHarm),
            None
        );
    }

    #[test]
    fn tensor_from_empty_entries() {
        let tensor = LossTensor::from_entries(Subsystem::Compiler, vec![]);
        assert!(tensor.entries.is_empty());
        assert!(!tensor.content_hash.is_empty());
    }

    #[test]
    fn tensor_minimax_empty_returns_none() {
        let tensor = LossTensor::from_entries(Subsystem::Compiler, vec![]);
        assert!(tensor.minimax_defender().is_none());
    }

    #[test]
    fn tensor_total_loss_nonexistent_pair_is_zero() {
        let tensor = LossTensor::from_entries(Subsystem::Runtime, vec![]);
        assert_eq!(tensor.total_loss(&atk("a"), &atk("d")), 0);
    }

    #[test]
    fn automaton_is_admissible_unknown_action_returns_false() {
        let automaton = AdmissibleActionAutomaton {
            subsystem: Subsystem::Runtime,
            constraints: vec![],
            all_defender_actions: BTreeSet::from([atk("d1")]),
        };
        assert!(!automaton.is_admissible(&atk("unknown")));
    }

    #[test]
    fn automaton_multiple_constraints_accumulate_forbidden() {
        let automaton = AdmissibleActionAutomaton {
            subsystem: Subsystem::Runtime,
            constraints: vec![
                HardConstraint {
                    constraint_id: "c1".to_string(),
                    description: "no kill".to_string(),
                    forbidden_actions: BTreeSet::from([atk("kill")]),
                    active_conditions: vec![],
                },
                HardConstraint {
                    constraint_id: "c2".to_string(),
                    description: "no nuke".to_string(),
                    forbidden_actions: BTreeSet::from([atk("nuke")]),
                    active_conditions: vec![],
                },
            ],
            all_defender_actions: BTreeSet::from([atk("block"), atk("kill"), atk("nuke")]),
        };
        let admissible = automaton.admissible_actions();
        assert_eq!(admissible.len(), 1);
        assert!(admissible.contains(&atk("block")));
    }

    #[test]
    fn model_id_differs_by_epoch() {
        let id1 = GameModel::compute_model_id(&Subsystem::Compiler, &SecurityEpoch::from_raw(1));
        let id2 = GameModel::compute_model_id(&Subsystem::Compiler, &SecurityEpoch::from_raw(2));
        assert_ne!(id1, id2);
    }

    #[test]
    fn action_id_display() {
        let id = ActionId("inject_malicious_extension".to_string());
        assert_eq!(id.to_string(), "inject_malicious_extension");
    }

    #[test]
    fn report_hash_changes_with_epoch() {
        let r1 = generate_report(&[], &SecurityEpoch::from_raw(1));
        let r2 = generate_report(&[], &SecurityEpoch::from_raw(2));
        assert_ne!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn tensor_entries_sorted_deterministically() {
        let entries = vec![
            LossEntry {
                attacker_action: atk("a2"),
                defender_action: atk("d1"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 200_000,
            },
            LossEntry {
                attacker_action: atk("a1"),
                defender_action: atk("d1"),
                dimension: LossDimension::UserHarm,
                loss_millionths: 100_000,
            },
        ];
        let tensor = LossTensor::from_entries(Subsystem::Runtime, entries);
        assert_eq!(tensor.entries[0].attacker_action, atk("a1"));
        assert_eq!(tensor.entries[1].attacker_action, atk("a2"));
    }

    #[test]
    fn subsystem_ordering() {
        assert!(Subsystem::Compiler < Subsystem::Runtime);
        assert!(Subsystem::Runtime < Subsystem::ControlPlane);
    }

    #[test]
    fn loss_dimension_ordering() {
        assert!(LossDimension::UserHarm < LossDimension::PerformanceCost);
        assert!(LossDimension::PerformanceCost < LossDimension::FalsePositiveCost);
    }

    #[test]
    fn automaton_constraint_count() {
        let automaton = AdmissibleActionAutomaton {
            subsystem: Subsystem::Runtime,
            constraints: vec![
                HardConstraint {
                    constraint_id: "c1".to_string(),
                    description: "test".to_string(),
                    forbidden_actions: BTreeSet::new(),
                    active_conditions: vec![],
                },
                HardConstraint {
                    constraint_id: "c2".to_string(),
                    description: "test2".to_string(),
                    forbidden_actions: BTreeSet::new(),
                    active_conditions: vec![],
                },
            ],
            all_defender_actions: BTreeSet::new(),
        };
        assert_eq!(automaton.constraint_count(), 2);
    }
}
