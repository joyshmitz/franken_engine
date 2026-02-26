//! Controller Composition Matrix, Timescale Separation, and Interference Gates.
//!
//! Defines and enforces controller composition compatibility for deployments
//! involving multiple controllers (router, optimizer, fallback, etc.).
//!
//! Key concepts:
//! - **Interference matrix**: pairwise interaction classification between
//!   controller roles (Router, Optimizer, Fallback, Monitor, Custom).
//! - **Timescale-separation requirements**: per-pair minimum temporal separation
//!   that must hold for safe concurrent operation.
//! - **Microbench harness**: deterministic harness that measures interference
//!   cost as fixed-point millionths and records evidence.
//! - **Acceptance gate**: evaluates a proposed composed deployment against the
//!   matrix and emits a pass/fail verdict with findings.
//!
//! Plan reference: FRX-13.4 (bd-mjh3.13.4).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPOSITION_MATRIX_DOMAIN: &[u8] = b"FrankenEngine.ControllerCompositionMatrix.v1";

fn matrix_schema() -> SchemaId {
    SchemaId::from_definition(COMPOSITION_MATRIX_DOMAIN)
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Controller Role taxonomy
// ---------------------------------------------------------------------------

/// Role that a controller occupies in a composed deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ControllerRole {
    /// Routes requests to specialization lanes.
    Router,
    /// Optimizes runtime parameters (e-graph, partial eval, etc.).
    Optimizer,
    /// Handles degraded-mode fallback when primary paths fail.
    Fallback,
    /// Observes metrics and publishes diagnostics (read-only).
    Monitor,
    /// Extension-defined custom role.
    Custom,
}

impl ControllerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Optimizer => "optimizer",
            Self::Fallback => "fallback",
            Self::Monitor => "monitor",
            Self::Custom => "custom",
        }
    }

    /// All built-in roles.
    pub fn all() -> &'static [ControllerRole] {
        &[
            Self::Router,
            Self::Optimizer,
            Self::Fallback,
            Self::Monitor,
            Self::Custom,
        ]
    }
}

impl fmt::Display for ControllerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Interaction classification
// ---------------------------------------------------------------------------

/// Classification of a pairwise interaction between two controller roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InteractionClass {
    /// No interaction: controllers operate on disjoint state.
    Independent,
    /// Controllers share read access to common metrics.
    ReadShared,
    /// One controller reads what another writes (observer pattern).
    ProducerConsumer,
    /// Both controllers write overlapping metrics — potential conflict.
    WriteConflict,
    /// Controllers are mutually exclusive and must not co-deploy.
    MutuallyExclusive,
}

impl InteractionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Independent => "independent",
            Self::ReadShared => "read_shared",
            Self::ProducerConsumer => "producer_consumer",
            Self::WriteConflict => "write_conflict",
            Self::MutuallyExclusive => "mutually_exclusive",
        }
    }

    /// Whether this classification requires timescale separation.
    pub fn requires_timescale_separation(self) -> bool {
        matches!(self, Self::ProducerConsumer | Self::WriteConflict)
    }

    /// Whether this classification blocks composition unconditionally.
    pub fn blocks_composition(self) -> bool {
        matches!(self, Self::MutuallyExclusive)
    }
}

impl fmt::Display for InteractionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Matrix entry
// ---------------------------------------------------------------------------

/// A single cell in the composition matrix — the interaction between
/// controller role A and controller role B.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixEntry {
    pub role_a: ControllerRole,
    pub role_b: ControllerRole,
    pub interaction: InteractionClass,
    /// Minimum timescale separation in millionths of one second.
    /// Only meaningful when `interaction.requires_timescale_separation()`.
    pub min_timescale_separation_millionths: i64,
    /// Human-readable rationale for this classification.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Timescale separation requirement
// ---------------------------------------------------------------------------

/// Per-controller timescale declaration for a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerTimescale {
    pub controller_name: String,
    pub role: ControllerRole,
    /// Observation cadence in millionths of one second.
    pub observation_interval_millionths: i64,
    /// Write cadence in millionths of one second.
    pub write_interval_millionths: i64,
    /// Human-readable timescale statement.
    pub statement: String,
}

// ---------------------------------------------------------------------------
// Composition matrix
// ---------------------------------------------------------------------------

/// The full NxN interaction matrix across all controller roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerCompositionMatrix {
    /// Pairwise entries keyed by `(min(role_a, role_b), max(role_a, role_b))`.
    /// Stored as a Vec because ControllerRole pairs don't impl string key.
    pub entries: Vec<MatrixEntry>,
    /// Schema version for forward compatibility.
    pub schema_version: String,
}

impl ControllerCompositionMatrix {
    /// Create a new matrix with default classifications.
    pub fn default_matrix() -> Self {
        let mut entries = Vec::new();
        let roles = ControllerRole::all();
        for (i, &role_a) in roles.iter().enumerate() {
            for &role_b in &roles[i..] {
                let (interaction, min_sep, rationale) = default_interaction(role_a, role_b);
                entries.push(MatrixEntry {
                    role_a,
                    role_b,
                    interaction,
                    min_timescale_separation_millionths: min_sep,
                    rationale,
                });
            }
        }
        Self {
            entries,
            schema_version: "1.0.0".to_string(),
        }
    }

    /// Look up the interaction class between two roles.
    pub fn lookup(&self, a: ControllerRole, b: ControllerRole) -> Option<&MatrixEntry> {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        self.entries
            .iter()
            .find(|entry| entry.role_a == lo && entry.role_b == hi)
    }

    /// Override or insert a matrix entry.
    pub fn set_entry(&mut self, entry: MatrixEntry) {
        let (lo, hi) = if entry.role_a <= entry.role_b {
            (entry.role_a, entry.role_b)
        } else {
            (entry.role_b, entry.role_a)
        };
        let normalized = MatrixEntry {
            role_a: lo,
            role_b: hi,
            ..entry
        };
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.role_a == lo && e.role_b == hi)
        {
            *existing = normalized;
        } else {
            self.entries.push(normalized);
        }
    }

    /// All entries where composition is blocked.
    pub fn blocked_pairs(&self) -> Vec<&MatrixEntry> {
        self.entries
            .iter()
            .filter(|e| e.interaction.blocks_composition())
            .collect()
    }

    /// All entries requiring timescale separation.
    pub fn separation_required_pairs(&self) -> Vec<&MatrixEntry> {
        self.entries
            .iter()
            .filter(|e| e.interaction.requires_timescale_separation())
            .collect()
    }

    /// Derive a deterministic ID for this matrix snapshot.
    pub fn derive_matrix_id(&self) -> EngineObjectId {
        let canonical = deterministic_serde::encode_value(&self.to_canonical_value());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "composition-matrix",
            &matrix_schema(),
            &canonical,
        )
        .expect("derive_id for composition matrix")
    }

    fn to_canonical_value(&self) -> CanonicalValue {
        let entries: Vec<CanonicalValue> = self
            .entries
            .iter()
            .map(|entry| {
                let mut m = BTreeMap::new();
                m.insert(
                    "role_a".to_string(),
                    CanonicalValue::String(entry.role_a.to_string()),
                );
                m.insert(
                    "role_b".to_string(),
                    CanonicalValue::String(entry.role_b.to_string()),
                );
                m.insert(
                    "interaction".to_string(),
                    CanonicalValue::String(entry.interaction.to_string()),
                );
                m.insert(
                    "min_timescale_separation_millionths".to_string(),
                    CanonicalValue::I64(entry.min_timescale_separation_millionths),
                );
                m.insert(
                    "rationale".to_string(),
                    CanonicalValue::String(entry.rationale.clone()),
                );
                CanonicalValue::Map(m)
            })
            .collect();
        let mut root = BTreeMap::new();
        root.insert("entries".to_string(), CanonicalValue::Array(entries));
        root.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        CanonicalValue::Map(root)
    }
}

/// Default interaction classifications.
fn default_interaction(a: ControllerRole, b: ControllerRole) -> (InteractionClass, i64, String) {
    use ControllerRole::*;
    use InteractionClass::*;
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    match (lo, hi) {
        // Self-interactions
        (Router, Router) => (
            MutuallyExclusive,
            0,
            "only one router per deployment".into(),
        ),
        (Optimizer, Optimizer) => (
            WriteConflict,
            500_000,
            "optimizers may write overlapping tuning knobs".into(),
        ),
        (Fallback, Fallback) => (
            MutuallyExclusive,
            0,
            "only one fallback controller per deployment".into(),
        ),
        (Monitor, Monitor) => (ReadShared, 0, "monitors share read access safely".into()),
        (Custom, Custom) => (
            WriteConflict,
            200_000,
            "custom controllers may conflict with each other".into(),
        ),
        // Cross-role
        (Router, Optimizer) => (
            ProducerConsumer,
            100_000,
            "router produces routing decisions consumed by optimizer".into(),
        ),
        (Router, Fallback) => (
            ProducerConsumer,
            100_000,
            "router triggers fallback on lane failure".into(),
        ),
        (Router, Monitor) => (
            ReadShared,
            0,
            "monitor observes router metrics read-only".into(),
        ),
        (Router, Custom) => (
            WriteConflict,
            200_000,
            "custom controller may conflict with router writes".into(),
        ),
        (Optimizer, Fallback) => (
            ProducerConsumer,
            200_000,
            "optimizer tunes parameters, fallback overrides on failure".into(),
        ),
        (Optimizer, Monitor) => (
            ReadShared,
            0,
            "monitor observes optimizer metrics read-only".into(),
        ),
        (Optimizer, Custom) => (
            WriteConflict,
            300_000,
            "custom may conflict with optimizer tuning writes".into(),
        ),
        (Fallback, Monitor) => (
            ReadShared,
            0,
            "monitor observes fallback status read-only".into(),
        ),
        (Fallback, Custom) => (
            WriteConflict,
            200_000,
            "custom may conflict with fallback writes".into(),
        ),
        (Monitor, Custom) => (
            ProducerConsumer,
            100_000,
            "monitor feeds metrics, custom consumes".into(),
        ),
        _ => (Independent, 0, "no known interaction".into()),
    }
}

// ---------------------------------------------------------------------------
// Microbench entry and harness
// ---------------------------------------------------------------------------

/// A single microbench measurement of interference cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrobenchEntry {
    pub controller_a: String,
    pub role_a: ControllerRole,
    pub controller_b: String,
    pub role_b: ControllerRole,
    /// Interference cost in millionths of one second.
    pub interference_cost_millionths: i64,
    /// Number of iterations measured.
    pub iterations: u64,
    /// Whether the measurement exceeded the budget.
    pub budget_exceeded: bool,
}

/// Configuration for the interference microbench harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrobenchConfig {
    /// Maximum iterations per pairwise test.
    pub max_iterations: u64,
    /// Budget cap in millionths of one second per pair.
    pub budget_cap_millionths: i64,
    /// Minimum iterations before reporting.
    pub min_iterations: u64,
}

impl Default for MicrobenchConfig {
    fn default() -> Self {
        Self {
            max_iterations: 1_000,
            budget_cap_millionths: 10_000_000, // 10 seconds
            min_iterations: 10,
        }
    }
}

/// Result of running the microbench harness over a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrobenchResult {
    pub entries: Vec<MicrobenchEntry>,
    pub total_cost_millionths: i64,
    pub max_pair_cost_millionths: i64,
    pub pairs_measured: usize,
    pub pairs_over_budget: usize,
}

/// Run deterministic interference microbench.
///
/// Since we do not have real hardware timers in the engine, the harness
/// computes a deterministic cost proxy based on shared metric overlap
/// and timescale proximity.
pub fn run_microbench(
    controllers: &[ControllerTimescale],
    matrix: &ControllerCompositionMatrix,
    config: &MicrobenchConfig,
) -> MicrobenchResult {
    let mut entries = Vec::new();
    let mut total_cost: i64 = 0;
    let mut max_cost: i64 = 0;
    let mut over_budget: usize = 0;

    for (i, ctrl_a) in controllers.iter().enumerate() {
        for ctrl_b in &controllers[i + 1..] {
            let interaction = matrix
                .lookup(ctrl_a.role, ctrl_b.role)
                .map(|e| e.interaction)
                .unwrap_or(InteractionClass::Independent);

            // Deterministic cost proxy: base cost from interaction class +
            // proximity penalty based on timescale difference.
            let base_cost: i64 = match interaction {
                InteractionClass::Independent => 0,
                InteractionClass::ReadShared => 1_000,
                InteractionClass::ProducerConsumer => 5_000,
                InteractionClass::WriteConflict => 50_000,
                InteractionClass::MutuallyExclusive => 1_000_000,
            };

            let timescale_diff = ctrl_a
                .write_interval_millionths
                .abs_diff(ctrl_b.write_interval_millionths) as i64;
            let proximity_penalty: i64 = if timescale_diff > 0 {
                1_000_000_i64.checked_div(timescale_diff).unwrap_or(0)
            } else {
                100_000_i64 // same timescale = high proximity penalty
            };

            let cost: i64 = base_cost.saturating_add(proximity_penalty);
            let iterations = config.max_iterations.min(config.min_iterations.max(100));
            let budget_exceeded = cost > config.budget_cap_millionths;

            if budget_exceeded {
                over_budget += 1;
            }
            total_cost = total_cost.saturating_add(cost);
            if cost > max_cost {
                max_cost = cost;
            }

            entries.push(MicrobenchEntry {
                controller_a: ctrl_a.controller_name.clone(),
                role_a: ctrl_a.role,
                controller_b: ctrl_b.controller_name.clone(),
                role_b: ctrl_b.role,
                interference_cost_millionths: cost,
                iterations,
                budget_exceeded,
            });
        }
    }

    MicrobenchResult {
        pairs_measured: entries.len(),
        entries,
        total_cost_millionths: total_cost,
        max_pair_cost_millionths: max_cost,
        pairs_over_budget: over_budget,
    }
}

// ---------------------------------------------------------------------------
// Acceptance gate
// ---------------------------------------------------------------------------

/// Reason a composition gate rejected a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateFailureReason {
    /// Two mutually exclusive roles co-deployed.
    MutuallyExclusiveRoles {
        role_a: ControllerRole,
        role_b: ControllerRole,
        controller_a: String,
        controller_b: String,
    },
    /// Timescale separation insufficient for the required interaction.
    InsufficientTimescaleSeparation {
        controller_a: String,
        controller_b: String,
        required_millionths: i64,
        actual_millionths: i64,
    },
    /// Microbench cost exceeds deployment budget.
    MicrobenchBudgetExceeded {
        pair: String,
        cost_millionths: i64,
        budget_millionths: i64,
    },
    /// Invalid timescale declaration (zero or negative intervals).
    InvalidTimescale {
        controller_name: String,
        detail: String,
    },
    /// Duplicate controller name in a single deployment.
    DuplicateController { controller_name: String },
    /// Empty deployment (no controllers).
    EmptyDeployment,
}

impl fmt::Display for GateFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MutuallyExclusiveRoles {
                role_a,
                role_b,
                controller_a,
                controller_b,
            } => write!(
                f,
                "mutually exclusive: {controller_a}({role_a}) vs {controller_b}({role_b})"
            ),
            Self::InsufficientTimescaleSeparation {
                controller_a,
                controller_b,
                required_millionths,
                actual_millionths,
            } => write!(
                f,
                "timescale separation: {controller_a} vs {controller_b} ({actual_millionths} < {required_millionths} ppm)"
            ),
            Self::MicrobenchBudgetExceeded {
                pair,
                cost_millionths,
                budget_millionths,
            } => write!(
                f,
                "microbench budget exceeded: {pair} ({cost_millionths} > {budget_millionths} ppm)"
            ),
            Self::InvalidTimescale {
                controller_name,
                detail,
            } => write!(f, "invalid timescale for {controller_name}: {detail}"),
            Self::DuplicateController { controller_name } => {
                write!(f, "duplicate controller: {controller_name}")
            }
            Self::EmptyDeployment => f.write_str("empty deployment"),
        }
    }
}

/// Gate verdict for a composed deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Deployment approved.
    Approved,
    /// Deployment rejected with reasons.
    Rejected,
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => f.write_str("approved"),
            Self::Rejected => f.write_str("rejected"),
        }
    }
}

/// Log event for the acceptance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLogEvent {
    pub trace_id: String,
    pub gate_id: String,
    pub event: String,
    pub detail: String,
}

/// Full result of the composition acceptance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    pub gate_id: String,
    pub verdict: GateVerdict,
    pub failures: Vec<GateFailureReason>,
    pub microbench: Option<MicrobenchResult>,
    pub controllers_evaluated: usize,
    pub pairs_evaluated: usize,
    pub logs: Vec<GateLogEvent>,
}

impl GateResult {
    pub fn is_approved(&self) -> bool {
        self.verdict == GateVerdict::Approved
    }

    /// Derive a deterministic evidence ID.
    pub fn derive_evidence_id(&self) -> EngineObjectId {
        let canonical = format!("gate-{}-{}", self.gate_id, self.verdict);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "composition-gate",
            &matrix_schema(),
            canonical.as_bytes(),
        )
        .expect("derive_id for gate result")
    }
}

/// Configuration for the acceptance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Whether to run the microbench harness.
    pub run_microbench: bool,
    /// Microbench configuration (used only if `run_microbench` is true).
    pub microbench_config: MicrobenchConfig,
    /// Per-pair microbench budget cap (used to generate failures).
    pub per_pair_budget_millionths: i64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            run_microbench: true,
            microbench_config: MicrobenchConfig::default(),
            per_pair_budget_millionths: 500_000,
        }
    }
}

/// Evaluate a proposed controller deployment against the composition matrix.
pub fn evaluate_composition_gate(
    trace_id: &str,
    controllers: &[ControllerTimescale],
    matrix: &ControllerCompositionMatrix,
    config: &GateConfig,
) -> GateResult {
    let input_bytes = format!(
        "{trace_id}:{}",
        controllers
            .iter()
            .map(|c| c.controller_name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    let input_hash = hash_bytes(input_bytes.as_bytes());
    let gate_id = format!("comp-gate-{}", to_hex(&input_hash[..12]));

    let mut failures = Vec::new();
    let mut logs = Vec::new();

    logs.push(GateLogEvent {
        trace_id: trace_id.to_string(),
        gate_id: gate_id.clone(),
        event: "gate_start".to_string(),
        detail: format!("{} controllers", controllers.len()),
    });

    // Check empty deployment.
    if controllers.is_empty() {
        failures.push(GateFailureReason::EmptyDeployment);
        return GateResult {
            gate_id,
            verdict: GateVerdict::Rejected,
            failures,
            microbench: None,
            controllers_evaluated: 0,
            pairs_evaluated: 0,
            logs,
        };
    }

    // Check duplicate controller names.
    let mut seen_names = BTreeSet::new();
    for ctrl in controllers {
        if !seen_names.insert(&ctrl.controller_name) {
            failures.push(GateFailureReason::DuplicateController {
                controller_name: ctrl.controller_name.clone(),
            });
        }
    }

    // Validate timescale declarations.
    for ctrl in controllers {
        if ctrl.observation_interval_millionths <= 0 || ctrl.write_interval_millionths <= 0 {
            failures.push(GateFailureReason::InvalidTimescale {
                controller_name: ctrl.controller_name.clone(),
                detail: "observation and write intervals must be positive".to_string(),
            });
        }
    }

    // Pairwise checks.
    let mut pairs_evaluated = 0;
    for (i, ctrl_a) in controllers.iter().enumerate() {
        for ctrl_b in &controllers[i + 1..] {
            pairs_evaluated += 1;

            if let Some(entry) = matrix.lookup(ctrl_a.role, ctrl_b.role) {
                // Check mutually exclusive.
                if entry.interaction.blocks_composition() {
                    failures.push(GateFailureReason::MutuallyExclusiveRoles {
                        role_a: ctrl_a.role,
                        role_b: ctrl_b.role,
                        controller_a: ctrl_a.controller_name.clone(),
                        controller_b: ctrl_b.controller_name.clone(),
                    });
                    logs.push(GateLogEvent {
                        trace_id: trace_id.to_string(),
                        gate_id: gate_id.clone(),
                        event: "mutually_exclusive".to_string(),
                        detail: format!("{} vs {}", ctrl_a.controller_name, ctrl_b.controller_name),
                    });
                }

                // Check timescale separation.
                if entry.interaction.requires_timescale_separation()
                    && entry.min_timescale_separation_millionths > 0
                {
                    let actual_sep = ctrl_a
                        .write_interval_millionths
                        .abs_diff(ctrl_b.write_interval_millionths)
                        as i64;
                    if actual_sep < entry.min_timescale_separation_millionths {
                        failures.push(GateFailureReason::InsufficientTimescaleSeparation {
                            controller_a: ctrl_a.controller_name.clone(),
                            controller_b: ctrl_b.controller_name.clone(),
                            required_millionths: entry.min_timescale_separation_millionths,
                            actual_millionths: actual_sep,
                        });
                        logs.push(GateLogEvent {
                            trace_id: trace_id.to_string(),
                            gate_id: gate_id.clone(),
                            event: "timescale_violation".to_string(),
                            detail: format!(
                                "{} vs {}: {} < {}",
                                ctrl_a.controller_name,
                                ctrl_b.controller_name,
                                actual_sep,
                                entry.min_timescale_separation_millionths
                            ),
                        });
                    }
                }
            }
        }
    }

    // Run microbench if configured.
    let microbench = if config.run_microbench {
        let result = run_microbench(controllers, matrix, &config.microbench_config);
        for entry in &result.entries {
            if entry.interference_cost_millionths > config.per_pair_budget_millionths {
                failures.push(GateFailureReason::MicrobenchBudgetExceeded {
                    pair: format!("{} vs {}", entry.controller_a, entry.controller_b),
                    cost_millionths: entry.interference_cost_millionths,
                    budget_millionths: config.per_pair_budget_millionths,
                });
            }
        }
        Some(result)
    } else {
        None
    };

    let verdict = if failures.is_empty() {
        GateVerdict::Approved
    } else {
        GateVerdict::Rejected
    };

    logs.push(GateLogEvent {
        trace_id: trace_id.to_string(),
        gate_id: gate_id.clone(),
        event: "gate_end".to_string(),
        detail: format!("{verdict}: {} failures", failures.len()),
    });

    GateResult {
        gate_id,
        verdict,
        failures,
        microbench,
        controllers_evaluated: controllers.len(),
        pairs_evaluated,
        logs,
    }
}

// ---------------------------------------------------------------------------
// Operator summary
// ---------------------------------------------------------------------------

/// Human-readable summary of a gate result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub gate_id: String,
    pub verdict: String,
    pub failure_count: usize,
    pub controllers: usize,
    pub pairs: usize,
    pub microbench_total_cost: Option<i64>,
    pub lines: Vec<String>,
}

pub fn render_operator_summary(result: &GateResult) -> OperatorSummary {
    let mut lines = Vec::new();
    lines.push(format!("Gate: {}", result.gate_id));
    lines.push(format!("Verdict: {}", result.verdict));
    lines.push(format!(
        "Controllers: {}, Pairs: {}",
        result.controllers_evaluated, result.pairs_evaluated
    ));

    if !result.failures.is_empty() {
        lines.push(format!("Failures ({})", result.failures.len()));
        for failure in &result.failures {
            lines.push(format!("  - {failure}"));
        }
    }

    let microbench_total = result.microbench.as_ref().map(|m| {
        lines.push(format!(
            "Microbench: {} pairs, total cost {} ppm",
            m.pairs_measured, m.total_cost_millionths
        ));
        m.total_cost_millionths
    });

    OperatorSummary {
        gate_id: result.gate_id.clone(),
        verdict: result.verdict.to_string(),
        failure_count: result.failures.len(),
        controllers: result.controllers_evaluated,
        pairs: result.pairs_evaluated,
        microbench_total_cost: microbench_total,
        lines,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctrl(name: &str, role: ControllerRole, obs: i64, write: i64) -> ControllerTimescale {
        ControllerTimescale {
            controller_name: name.to_string(),
            role,
            observation_interval_millionths: obs,
            write_interval_millionths: write,
            statement: format!("{name} timescale"),
        }
    }

    // --- ControllerRole ---

    #[test]
    fn controller_role_as_str_all_variants() {
        assert_eq!(ControllerRole::Router.as_str(), "router");
        assert_eq!(ControllerRole::Optimizer.as_str(), "optimizer");
        assert_eq!(ControllerRole::Fallback.as_str(), "fallback");
        assert_eq!(ControllerRole::Monitor.as_str(), "monitor");
        assert_eq!(ControllerRole::Custom.as_str(), "custom");
    }

    #[test]
    fn controller_role_display() {
        assert_eq!(format!("{}", ControllerRole::Router), "router");
        assert_eq!(format!("{}", ControllerRole::Custom), "custom");
    }

    #[test]
    fn controller_role_all_returns_five() {
        assert_eq!(ControllerRole::all().len(), 5);
    }

    #[test]
    fn controller_role_serde_roundtrip() {
        for role in ControllerRole::all() {
            let json = serde_json::to_string(role).unwrap();
            let back: ControllerRole = serde_json::from_str(&json).unwrap();
            assert_eq!(*role, back);
        }
    }

    #[test]
    fn controller_role_ordering() {
        assert!(ControllerRole::Router < ControllerRole::Optimizer);
        assert!(ControllerRole::Monitor < ControllerRole::Custom);
    }

    // --- InteractionClass ---

    #[test]
    fn interaction_class_as_str_all() {
        assert_eq!(InteractionClass::Independent.as_str(), "independent");
        assert_eq!(InteractionClass::ReadShared.as_str(), "read_shared");
        assert_eq!(
            InteractionClass::ProducerConsumer.as_str(),
            "producer_consumer"
        );
        assert_eq!(InteractionClass::WriteConflict.as_str(), "write_conflict");
        assert_eq!(
            InteractionClass::MutuallyExclusive.as_str(),
            "mutually_exclusive"
        );
    }

    #[test]
    fn interaction_class_display() {
        assert_eq!(
            format!("{}", InteractionClass::WriteConflict),
            "write_conflict"
        );
    }

    #[test]
    fn interaction_class_requires_timescale_separation() {
        assert!(!InteractionClass::Independent.requires_timescale_separation());
        assert!(!InteractionClass::ReadShared.requires_timescale_separation());
        assert!(InteractionClass::ProducerConsumer.requires_timescale_separation());
        assert!(InteractionClass::WriteConflict.requires_timescale_separation());
        assert!(!InteractionClass::MutuallyExclusive.requires_timescale_separation());
    }

    #[test]
    fn interaction_class_blocks_composition() {
        assert!(!InteractionClass::Independent.blocks_composition());
        assert!(!InteractionClass::WriteConflict.blocks_composition());
        assert!(InteractionClass::MutuallyExclusive.blocks_composition());
    }

    #[test]
    fn interaction_class_serde_roundtrip() {
        let classes = [
            InteractionClass::Independent,
            InteractionClass::ReadShared,
            InteractionClass::ProducerConsumer,
            InteractionClass::WriteConflict,
            InteractionClass::MutuallyExclusive,
        ];
        for class in &classes {
            let json = serde_json::to_string(class).unwrap();
            let back: InteractionClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*class, back);
        }
    }

    // --- ControllerCompositionMatrix ---

    #[test]
    fn default_matrix_has_expected_entry_count() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        // 5 roles: C(5,2) + 5 diagonal = 10 + 5 = 15 entries
        assert_eq!(matrix.entries.len(), 15);
    }

    #[test]
    fn default_matrix_router_router_mutually_exclusive() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Router, ControllerRole::Router)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::MutuallyExclusive);
    }

    #[test]
    fn default_matrix_fallback_fallback_mutually_exclusive() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Fallback, ControllerRole::Fallback)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::MutuallyExclusive);
    }

    #[test]
    fn default_matrix_monitor_monitor_read_shared() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Monitor, ControllerRole::Monitor)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::ReadShared);
    }

    #[test]
    fn default_matrix_router_optimizer_producer_consumer() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Router, ControllerRole::Optimizer)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::ProducerConsumer);
    }

    #[test]
    fn lookup_symmetric() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let ab = matrix
            .lookup(ControllerRole::Router, ControllerRole::Optimizer)
            .unwrap();
        let ba = matrix
            .lookup(ControllerRole::Optimizer, ControllerRole::Router)
            .unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn set_entry_overrides_existing() {
        let mut matrix = ControllerCompositionMatrix::default_matrix();
        let entry = MatrixEntry {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Optimizer,
            interaction: InteractionClass::Independent,
            min_timescale_separation_millionths: 0,
            rationale: "overridden".to_string(),
        };
        matrix.set_entry(entry);
        let lookup = matrix
            .lookup(ControllerRole::Router, ControllerRole::Optimizer)
            .unwrap();
        assert_eq!(lookup.interaction, InteractionClass::Independent);
        assert_eq!(lookup.rationale, "overridden");
    }

    #[test]
    fn set_entry_normalizes_order() {
        let mut matrix = ControllerCompositionMatrix::default_matrix();
        let entry = MatrixEntry {
            role_a: ControllerRole::Optimizer,
            role_b: ControllerRole::Router,
            interaction: InteractionClass::Independent,
            min_timescale_separation_millionths: 0,
            rationale: "reversed input".to_string(),
        };
        matrix.set_entry(entry);
        let lookup = matrix
            .lookup(ControllerRole::Router, ControllerRole::Optimizer)
            .unwrap();
        assert_eq!(lookup.role_a, ControllerRole::Router);
        assert_eq!(lookup.role_b, ControllerRole::Optimizer);
    }

    #[test]
    fn blocked_pairs_finds_mutually_exclusive() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let blocked = matrix.blocked_pairs();
        assert!(blocked.len() >= 2); // Router-Router and Fallback-Fallback
        assert!(
            blocked
                .iter()
                .any(|e| e.role_a == ControllerRole::Router && e.role_b == ControllerRole::Router)
        );
    }

    #[test]
    fn separation_required_pairs_finds_producer_consumer_and_write_conflict() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let sep = matrix.separation_required_pairs();
        assert!(sep.len() >= 2);
        assert!(
            sep.iter()
                .any(|e| e.interaction == InteractionClass::ProducerConsumer)
        );
        assert!(
            sep.iter()
                .any(|e| e.interaction == InteractionClass::WriteConflict)
        );
    }

    #[test]
    fn matrix_id_deterministic() {
        let m1 = ControllerCompositionMatrix::default_matrix();
        let m2 = ControllerCompositionMatrix::default_matrix();
        assert_eq!(m1.derive_matrix_id(), m2.derive_matrix_id());
    }

    #[test]
    fn matrix_id_changes_with_override() {
        let m1 = ControllerCompositionMatrix::default_matrix();
        let mut m2 = ControllerCompositionMatrix::default_matrix();
        m2.set_entry(MatrixEntry {
            role_a: ControllerRole::Monitor,
            role_b: ControllerRole::Monitor,
            interaction: InteractionClass::Independent,
            min_timescale_separation_millionths: 0,
            rationale: "changed".to_string(),
        });
        assert_ne!(m1.derive_matrix_id(), m2.derive_matrix_id());
    }

    #[test]
    fn matrix_serde_roundtrip() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let json = serde_json::to_string(&matrix).unwrap();
        let back: ControllerCompositionMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(matrix, back);
    }

    #[test]
    fn matrix_schema_version() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        assert_eq!(matrix.schema_version, "1.0.0");
    }

    // --- Microbench ---

    #[test]
    fn microbench_independent_pair_low_cost() {
        let controllers = vec![
            ctrl("mon1", ControllerRole::Monitor, 100_000, 1_000_000),
            ctrl("mon2", ControllerRole::Monitor, 200_000, 2_000_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
        assert_eq!(result.pairs_measured, 1);
        // ReadShared base = 1000, plus proximity from timescale diff
        assert!(result.total_cost_millionths > 0);
        assert_eq!(result.pairs_over_budget, 0);
    }

    #[test]
    fn microbench_write_conflict_high_cost() {
        let controllers = vec![
            ctrl("opt1", ControllerRole::Optimizer, 100_000, 100_000),
            ctrl("opt2", ControllerRole::Optimizer, 100_000, 100_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
        assert_eq!(result.pairs_measured, 1);
        // WriteConflict base=50000, same timescale = proximity penalty 100000
        assert!(result.max_pair_cost_millionths >= 150_000);
    }

    #[test]
    fn microbench_mutually_exclusive_very_high_cost() {
        let controllers = vec![
            ctrl("router1", ControllerRole::Router, 100_000, 100_000),
            ctrl("router2", ControllerRole::Router, 100_000, 100_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
        assert!(result.max_pair_cost_millionths >= 1_000_000);
    }

    #[test]
    fn microbench_empty_controllers() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let result = run_microbench(&[], &matrix, &MicrobenchConfig::default());
        assert_eq!(result.pairs_measured, 0);
        assert_eq!(result.total_cost_millionths, 0);
    }

    #[test]
    fn microbench_single_controller_no_pairs() {
        let controllers = vec![ctrl("router", ControllerRole::Router, 100_000, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
        assert_eq!(result.pairs_measured, 0);
    }

    #[test]
    fn microbench_three_controllers() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("optimizer", ControllerRole::Optimizer, 200_000, 2_000_000),
            ctrl("monitor", ControllerRole::Monitor, 50_000, 500_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let result = run_microbench(&controllers, &matrix, &MicrobenchConfig::default());
        assert_eq!(result.pairs_measured, 3);
    }

    #[test]
    fn microbench_config_default() {
        let config = MicrobenchConfig::default();
        assert_eq!(config.max_iterations, 1_000);
        assert_eq!(config.budget_cap_millionths, 10_000_000);
        assert_eq!(config.min_iterations, 10);
    }

    #[test]
    fn microbench_config_serde_roundtrip() {
        let config = MicrobenchConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: MicrobenchConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn microbench_entry_serde_roundtrip() {
        let entry = MicrobenchEntry {
            controller_a: "a".to_string(),
            role_a: ControllerRole::Router,
            controller_b: "b".to_string(),
            role_b: ControllerRole::Optimizer,
            interference_cost_millionths: 42_000,
            iterations: 100,
            budget_exceeded: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: MicrobenchEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn microbench_result_serde_roundtrip() {
        let result = MicrobenchResult {
            entries: Vec::new(),
            total_cost_millionths: 0,
            max_pair_cost_millionths: 0,
            pairs_measured: 0,
            pairs_over_budget: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: MicrobenchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn microbench_budget_exceeded_flag() {
        let controllers = vec![
            ctrl("router1", ControllerRole::Router, 100_000, 100_000),
            ctrl("router2", ControllerRole::Router, 100_000, 100_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = MicrobenchConfig {
            budget_cap_millionths: 100, // very low budget
            ..MicrobenchConfig::default()
        };
        let result = run_microbench(&controllers, &matrix, &config);
        assert!(result.pairs_over_budget > 0);
        assert!(result.entries[0].budget_exceeded);
    }

    // --- Gate ---

    #[test]
    fn gate_approves_compatible_deployment() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("optimizer", ControllerRole::Optimizer, 200_000, 2_000_000),
            ctrl("monitor", ControllerRole::Monitor, 50_000, 500_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-1", &controllers, &matrix, &config);
        assert!(result.is_approved());
        assert_eq!(result.failures.len(), 0);
        assert_eq!(result.controllers_evaluated, 3);
        assert_eq!(result.pairs_evaluated, 3);
    }

    #[test]
    fn gate_rejects_empty_deployment() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig::default();
        let result = evaluate_composition_gate("trace-empty", &[], &matrix, &config);
        assert!(!result.is_approved());
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, GateFailureReason::EmptyDeployment))
        );
    }

    #[test]
    fn gate_rejects_duplicate_router() {
        let controllers = vec![
            ctrl("router-a", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("router-b", ControllerRole::Router, 200_000, 2_000_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-dup", &controllers, &matrix, &config);
        assert!(!result.is_approved());
        assert!(result.failures.iter().any(|f| matches!(
            f,
            GateFailureReason::MutuallyExclusiveRoles {
                role_a: ControllerRole::Router,
                role_b: ControllerRole::Router,
                ..
            }
        )));
    }

    #[test]
    fn gate_rejects_duplicate_fallback() {
        let controllers = vec![
            ctrl("fb-a", ControllerRole::Fallback, 100_000, 1_000_000),
            ctrl("fb-b", ControllerRole::Fallback, 200_000, 2_000_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-fb", &controllers, &matrix, &config);
        assert!(!result.is_approved());
    }

    #[test]
    fn gate_rejects_insufficient_timescale_separation() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 100_000),
            ctrl("optimizer", ControllerRole::Optimizer, 100_000, 100_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-sep", &controllers, &matrix, &config);
        assert!(!result.is_approved());
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, GateFailureReason::InsufficientTimescaleSeparation { .. }))
        );
    }

    #[test]
    fn gate_accepts_sufficient_timescale_separation() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 100_000),
            ctrl("optimizer", ControllerRole::Optimizer, 200_000, 500_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-ok", &controllers, &matrix, &config);
        // Router-Optimizer requires 100_000 separation; actual = |500000 - 100000| = 400_000 >= 100_000
        assert!(result.is_approved());
    }

    #[test]
    fn gate_rejects_invalid_timescale_zero_observation() {
        let controllers = vec![ctrl("bad", ControllerRole::Monitor, 0, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-bad", &controllers, &matrix, &config);
        assert!(!result.is_approved());
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, GateFailureReason::InvalidTimescale { .. }))
        );
    }

    #[test]
    fn gate_rejects_invalid_timescale_negative_write() {
        let controllers = vec![ctrl("neg", ControllerRole::Monitor, 100_000, -1)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-neg", &controllers, &matrix, &config);
        assert!(!result.is_approved());
    }

    #[test]
    fn gate_rejects_duplicate_controller_name() {
        let controllers = vec![
            ctrl("same-name", ControllerRole::Monitor, 100_000, 1_000_000),
            ctrl("same-name", ControllerRole::Monitor, 200_000, 2_000_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-dup-name", &controllers, &matrix, &config);
        assert!(!result.is_approved());
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, GateFailureReason::DuplicateController { .. }))
        );
    }

    #[test]
    fn gate_with_microbench_includes_results() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("monitor", ControllerRole::Monitor, 50_000, 500_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: true,
            per_pair_budget_millionths: 100_000_000, // very high budget
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-bench", &controllers, &matrix, &config);
        assert!(result.microbench.is_some());
        let mb = result.microbench.as_ref().unwrap();
        assert_eq!(mb.pairs_measured, 1);
    }

    #[test]
    fn gate_microbench_budget_exceeded_fails() {
        let controllers = vec![
            ctrl("opt1", ControllerRole::Optimizer, 100_000, 100_000),
            ctrl("opt2", ControllerRole::Optimizer, 100_000, 100_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: true,
            per_pair_budget_millionths: 1, // impossibly low
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-mbf", &controllers, &matrix, &config);
        assert!(!result.is_approved());
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, GateFailureReason::MicrobenchBudgetExceeded { .. }))
        );
    }

    #[test]
    fn gate_id_deterministic() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("monitor", ControllerRole::Monitor, 50_000, 500_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let r1 = evaluate_composition_gate("trace-det", &controllers, &matrix, &config);
        let r2 = evaluate_composition_gate("trace-det", &controllers, &matrix, &config);
        assert_eq!(r1.gate_id, r2.gate_id);
    }

    #[test]
    fn gate_id_changes_with_trace() {
        let controllers = vec![ctrl("router", ControllerRole::Router, 100_000, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let r1 = evaluate_composition_gate("trace-a", &controllers, &matrix, &config);
        let r2 = evaluate_composition_gate("trace-b", &controllers, &matrix, &config);
        assert_ne!(r1.gate_id, r2.gate_id);
    }

    #[test]
    fn gate_logs_have_start_and_end() {
        let controllers = vec![ctrl("mon", ControllerRole::Monitor, 100_000, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-log", &controllers, &matrix, &config);
        assert!(result.logs.iter().any(|l| l.event == "gate_start"));
        assert!(result.logs.iter().any(|l| l.event == "gate_end"));
    }

    #[test]
    fn gate_logs_carry_trace_id() {
        let controllers = vec![ctrl("mon", ControllerRole::Monitor, 100_000, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("my-trace", &controllers, &matrix, &config);
        for log in &result.logs {
            assert_eq!(log.trace_id, "my-trace");
        }
    }

    #[test]
    fn gate_result_evidence_id_deterministic() {
        let controllers = vec![ctrl("mon", ControllerRole::Monitor, 100_000, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let r1 = evaluate_composition_gate("trace-eid", &controllers, &matrix, &config);
        let r2 = evaluate_composition_gate("trace-eid", &controllers, &matrix, &config);
        assert_eq!(r1.derive_evidence_id(), r2.derive_evidence_id());
    }

    #[test]
    fn gate_single_controller_passes() {
        let controllers = vec![ctrl("solo", ControllerRole::Router, 100_000, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-solo", &controllers, &matrix, &config);
        assert!(result.is_approved());
        assert_eq!(result.pairs_evaluated, 0);
    }

    // --- GateFailureReason ---

    #[test]
    fn gate_failure_reason_display_all_variants() {
        let reasons = [
            GateFailureReason::MutuallyExclusiveRoles {
                role_a: ControllerRole::Router,
                role_b: ControllerRole::Router,
                controller_a: "a".to_string(),
                controller_b: "b".to_string(),
            },
            GateFailureReason::InsufficientTimescaleSeparation {
                controller_a: "x".to_string(),
                controller_b: "y".to_string(),
                required_millionths: 100_000,
                actual_millionths: 50_000,
            },
            GateFailureReason::MicrobenchBudgetExceeded {
                pair: "a vs b".to_string(),
                cost_millionths: 200_000,
                budget_millionths: 100_000,
            },
            GateFailureReason::InvalidTimescale {
                controller_name: "bad".to_string(),
                detail: "zero interval".to_string(),
            },
            GateFailureReason::DuplicateController {
                controller_name: "dup".to_string(),
            },
            GateFailureReason::EmptyDeployment,
        ];
        for reason in &reasons {
            let display = format!("{reason}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn gate_failure_reason_serde_roundtrip() {
        let reason = GateFailureReason::MutuallyExclusiveRoles {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Router,
            controller_a: "a".to_string(),
            controller_b: "b".to_string(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let back: GateFailureReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }

    // --- GateVerdict ---

    #[test]
    fn gate_verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Approved), "approved");
        assert_eq!(format!("{}", GateVerdict::Rejected), "rejected");
    }

    #[test]
    fn gate_verdict_serde_roundtrip() {
        for verdict in &[GateVerdict::Approved, GateVerdict::Rejected] {
            let json = serde_json::to_string(verdict).unwrap();
            let back: GateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*verdict, back);
        }
    }

    // --- GateConfig ---

    #[test]
    fn gate_config_default() {
        let config = GateConfig::default();
        assert!(config.run_microbench);
        assert_eq!(config.per_pair_budget_millionths, 500_000);
    }

    #[test]
    fn gate_config_serde_roundtrip() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- Operator summary ---

    #[test]
    fn operator_summary_for_approved_deployment() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("monitor", ControllerRole::Monitor, 50_000, 500_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-sum", &controllers, &matrix, &config);
        let summary = render_operator_summary(&result);
        assert_eq!(summary.verdict, "approved");
        assert_eq!(summary.failure_count, 0);
        assert_eq!(summary.controllers, 2);
        assert_eq!(summary.pairs, 1);
        assert!(summary.microbench_total_cost.is_none());
    }

    #[test]
    fn operator_summary_for_rejected_deployment() {
        let controllers = vec![
            ctrl("router-a", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("router-b", ControllerRole::Router, 200_000, 2_000_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-sum-r", &controllers, &matrix, &config);
        let summary = render_operator_summary(&result);
        assert_eq!(summary.verdict, "rejected");
        assert!(summary.failure_count > 0);
        assert!(summary.lines.iter().any(|l| l.contains("Failures")));
    }

    #[test]
    fn operator_summary_with_microbench() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("monitor", ControllerRole::Monitor, 50_000, 500_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: true,
            per_pair_budget_millionths: 100_000_000,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-sum-mb", &controllers, &matrix, &config);
        let summary = render_operator_summary(&result);
        assert!(summary.microbench_total_cost.is_some());
        assert!(summary.lines.iter().any(|l| l.contains("Microbench")));
    }

    #[test]
    fn operator_summary_serde_roundtrip() {
        let summary = OperatorSummary {
            gate_id: "gate-1".to_string(),
            verdict: "approved".to_string(),
            failure_count: 0,
            controllers: 2,
            pairs: 1,
            microbench_total_cost: None,
            lines: vec!["test".to_string()],
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: OperatorSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // --- GateLogEvent ---

    #[test]
    fn gate_log_event_serde_roundtrip() {
        let event = GateLogEvent {
            trace_id: "t".to_string(),
            gate_id: "g".to_string(),
            event: "gate_start".to_string(),
            detail: "1 controller".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: GateLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // --- GateResult ---

    #[test]
    fn gate_result_serde_roundtrip() {
        let controllers = vec![ctrl("mon", ControllerRole::Monitor, 100_000, 1_000_000)];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-serde", &controllers, &matrix, &config);
        let json = serde_json::to_string(&result).unwrap();
        let back: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // --- MatrixEntry ---

    #[test]
    fn matrix_entry_serde_roundtrip() {
        let entry = MatrixEntry {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Optimizer,
            interaction: InteractionClass::ProducerConsumer,
            min_timescale_separation_millionths: 100_000,
            rationale: "test".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: MatrixEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // --- ControllerTimescale ---

    #[test]
    fn controller_timescale_serde_roundtrip() {
        let ts = ctrl("test", ControllerRole::Router, 100_000, 200_000);
        let json = serde_json::to_string(&ts).unwrap();
        let back: ControllerTimescale = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, back);
    }

    // --- Edge cases ---

    #[test]
    fn five_controllers_full_composition() {
        let controllers = vec![
            ctrl("router", ControllerRole::Router, 100_000, 100_000),
            ctrl("optimizer", ControllerRole::Optimizer, 200_000, 1_000_000),
            ctrl("fallback", ControllerRole::Fallback, 300_000, 2_000_000),
            ctrl("monitor", ControllerRole::Monitor, 50_000, 500_000),
            ctrl("custom", ControllerRole::Custom, 400_000, 3_000_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-full", &controllers, &matrix, &config);
        assert_eq!(result.controllers_evaluated, 5);
        assert_eq!(result.pairs_evaluated, 10);
    }

    #[test]
    fn override_mutually_exclusive_to_independent_allows_composition() {
        let mut matrix = ControllerCompositionMatrix::default_matrix();
        matrix.set_entry(MatrixEntry {
            role_a: ControllerRole::Router,
            role_b: ControllerRole::Router,
            interaction: InteractionClass::Independent,
            min_timescale_separation_millionths: 0,
            rationale: "override for testing".to_string(),
        });
        let controllers = vec![
            ctrl("router-a", ControllerRole::Router, 100_000, 1_000_000),
            ctrl("router-b", ControllerRole::Router, 200_000, 2_000_000),
        ];
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-override", &controllers, &matrix, &config);
        assert!(result.is_approved());
    }

    #[test]
    fn gate_multiple_failures_accumulate() {
        let controllers = vec![
            ctrl("router-a", ControllerRole::Router, 0, 1_000_000),
            ctrl("router-b", ControllerRole::Router, 200_000, 2_000_000),
        ];
        let matrix = ControllerCompositionMatrix::default_matrix();
        let config = GateConfig {
            run_microbench: false,
            ..GateConfig::default()
        };
        let result = evaluate_composition_gate("trace-multi", &controllers, &matrix, &config);
        assert!(!result.is_approved());
        // Should have: invalid timescale (router-a obs=0) + mutually exclusive
        assert!(result.failures.len() >= 2);
    }

    #[test]
    fn to_hex_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_known_bytes() {
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn hash_bytes_deterministic() {
        let a = hash_bytes(b"test input");
        let b = hash_bytes(b"test input");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_bytes_different_inputs_differ() {
        let a = hash_bytes(b"input-a");
        let b = hash_bytes(b"input-b");
        assert_ne!(a, b);
    }

    #[test]
    fn matrix_lookup_nonexistent_returns_none() {
        let matrix = ControllerCompositionMatrix {
            entries: Vec::new(),
            schema_version: "1.0.0".to_string(),
        };
        assert!(
            matrix
                .lookup(ControllerRole::Router, ControllerRole::Monitor)
                .is_none()
        );
    }

    #[test]
    fn default_interaction_optimizer_optimizer_write_conflict() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Optimizer, ControllerRole::Optimizer)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::WriteConflict);
        assert_eq!(entry.min_timescale_separation_millionths, 500_000);
    }

    #[test]
    fn default_interaction_optimizer_fallback_producer_consumer() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Optimizer, ControllerRole::Fallback)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::ProducerConsumer);
    }

    #[test]
    fn default_interaction_router_monitor_read_shared() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Router, ControllerRole::Monitor)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::ReadShared);
    }

    #[test]
    fn default_interaction_monitor_custom_producer_consumer() {
        let matrix = ControllerCompositionMatrix::default_matrix();
        let entry = matrix
            .lookup(ControllerRole::Monitor, ControllerRole::Custom)
            .unwrap();
        assert_eq!(entry.interaction, InteractionClass::ProducerConsumer);
    }
}
