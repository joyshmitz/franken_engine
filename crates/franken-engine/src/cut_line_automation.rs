//! Cut-line automation: gate evaluator and promotion decision recorder.
//!
//! Automates C0-C5 gate evaluation and records promotion decisions as
//! content-addressed, replayable artifacts.  Enforces fail-closed semantics
//! when gate inputs are stale, missing, or schema-incompatible.
//!
//! Plan reference: FRX-12.7 (`bd-mjh3.12.7`).
//! Dependencies: FRX-12.1 (cut-line definitions), FRX-11.7 (handoff
//! protocol), FRX-08.1 (evidence ledger schema).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::self_replacement::{GateResult, GateVerdict, RiskLevel};

// ---------------------------------------------------------------------------
// CutLine — the six milestone gates
// ---------------------------------------------------------------------------

/// The six milestone cut lines from C0 (constitution freeze) to C5
/// (FrankenBrowser integration readiness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CutLine {
    /// C0: Constitution and semantic contract freeze.
    C0,
    /// C1: Compiler + JS lane parity prototype.
    C1,
    /// C2: Route-scale alpha (deterministic replay + safe fallback).
    C2,
    /// C3: Hybrid JS/WASM beta (calibrated router + evidence ledger).
    C3,
    /// C4: GA readiness and evidence-bound claim publication.
    C4,
    /// C5: FrankenBrowser integration readiness.
    C5,
}

impl CutLine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C0 => "C0",
            Self::C1 => "C1",
            Self::C2 => "C2",
            Self::C3 => "C3",
            Self::C4 => "C4",
            Self::C5 => "C5",
        }
    }

    pub fn all() -> &'static [CutLine] {
        &[Self::C0, Self::C1, Self::C2, Self::C3, Self::C4, Self::C5]
    }

    /// Return the predecessor cut line (C0 has no predecessor).
    pub fn predecessor(self) -> Option<CutLine> {
        match self {
            Self::C0 => None,
            Self::C1 => Some(Self::C0),
            Self::C2 => Some(Self::C1),
            Self::C3 => Some(Self::C2),
            Self::C4 => Some(Self::C3),
            Self::C5 => Some(Self::C4),
        }
    }
}

impl fmt::Display for CutLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// InputValidity — fail-closed input classification
// ---------------------------------------------------------------------------

/// Result of validating a gate input against freshness, presence, and
/// schema requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputValidity {
    /// Input is fresh, present, and schema-compatible.
    Valid,
    /// Input exists but is too old.
    Stale { age_ns: u64, max_age_ns: u64 },
    /// A required input field is missing entirely.
    Missing { field: String },
    /// Input is present but schema-incompatible.
    Incompatible { reason: String },
}

impl InputValidity {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl fmt::Display for InputValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => f.write_str("valid"),
            Self::Stale { age_ns, max_age_ns } => {
                write!(f, "stale (age {age_ns}ns > max {max_age_ns}ns)")
            }
            Self::Missing { field } => write!(f, "missing field: {field}"),
            Self::Incompatible { reason } => write!(f, "incompatible: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateCategory — categories of evidence a cut line may require
// ---------------------------------------------------------------------------

/// Categories of evidence that a cut-line gate may evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateCategory {
    /// Semantic contract compliance.
    SemanticContract,
    /// Compiler and FRIR correctness evidence.
    CompilerCorrectness,
    /// Runtime lane parity evidence.
    RuntimeParity,
    /// Performance benchmark evidence.
    PerformanceBenchmark,
    /// Security and adversarial survival evidence.
    SecuritySurvival,
    /// Deterministic replay evidence.
    DeterministicReplay,
    /// Observability and witness integrity evidence.
    ObservabilityIntegrity,
    /// Flake burden and test health evidence.
    FlakeBurden,
    /// Governance and policy compliance evidence.
    GovernanceCompliance,
    /// Cross-track handoff readiness.
    HandoffReadiness,
}

impl GateCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SemanticContract => "semantic_contract",
            Self::CompilerCorrectness => "compiler_correctness",
            Self::RuntimeParity => "runtime_parity",
            Self::PerformanceBenchmark => "performance_benchmark",
            Self::SecuritySurvival => "security_survival",
            Self::DeterministicReplay => "deterministic_replay",
            Self::ObservabilityIntegrity => "observability_integrity",
            Self::FlakeBurden => "flake_burden",
            Self::GovernanceCompliance => "governance_compliance",
            Self::HandoffReadiness => "handoff_readiness",
        }
    }
}

impl fmt::Display for GateCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateRequirement — what a cut line demands
// ---------------------------------------------------------------------------

/// A single gate requirement within a cut line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRequirement {
    /// Category of evidence this requirement evaluates.
    pub category: GateCategory,
    /// Whether this requirement is mandatory (fail-closed) or advisory.
    pub mandatory: bool,
    /// Human-readable description of what must hold.
    pub description: String,
    /// Minimum score in millionths (1_000_000 = 1.0). None means boolean.
    pub min_score_millionths: Option<i64>,
}

// ---------------------------------------------------------------------------
// CutLineSpec — full specification for one cut line
// ---------------------------------------------------------------------------

/// Complete specification of a cut-line milestone gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutLineSpec {
    /// Which cut line this specifies.
    pub cut_line: CutLine,
    /// The individual gate requirements.
    pub requirements: Vec<GateRequirement>,
    /// Maximum staleness (nanoseconds) before inputs are rejected.
    pub max_input_staleness_ns: u64,
    /// Minimum schema version accepted for gate inputs.
    pub min_schema_major: u32,
    /// Whether predecessor cut line must already be promoted.
    pub requires_predecessor: bool,
}

impl CutLineSpec {
    /// Build the default C0 spec (constitution freeze).
    pub fn default_c0() -> Self {
        Self {
            cut_line: CutLine::C0,
            requirements: vec![
                GateRequirement {
                    category: GateCategory::SemanticContract,
                    mandatory: true,
                    description: "Constitution and forbidden-regression matrix frozen".into(),
                    min_score_millionths: None,
                },
                GateRequirement {
                    category: GateCategory::GovernanceCompliance,
                    mandatory: true,
                    description: "Governance policy signed and sealed".into(),
                    min_score_millionths: None,
                },
            ],
            max_input_staleness_ns: 86_400_000_000_000, // 24 hours
            min_schema_major: 1,
            requires_predecessor: false,
        }
    }

    /// Build the default C1 spec (compiler + JS lane parity).
    pub fn default_c1() -> Self {
        Self {
            cut_line: CutLine::C1,
            requirements: vec![
                GateRequirement {
                    category: GateCategory::CompilerCorrectness,
                    mandatory: true,
                    description: "Compiler passes produce valid FRIR witnesses".into(),
                    min_score_millionths: Some(1_000_000), // 1.0 (100%)
                },
                GateRequirement {
                    category: GateCategory::RuntimeParity,
                    mandatory: true,
                    description: "JS lane output matches reference for fixture corpus".into(),
                    min_score_millionths: Some(990_000), // 0.99
                },
                GateRequirement {
                    category: GateCategory::FlakeBurden,
                    mandatory: true,
                    description: "Flake rate below 1% of test suite".into(),
                    min_score_millionths: Some(990_000),
                },
            ],
            max_input_staleness_ns: 3_600_000_000_000, // 1 hour
            min_schema_major: 1,
            requires_predecessor: true,
        }
    }

    /// Number of mandatory requirements.
    pub fn mandatory_count(&self) -> usize {
        self.requirements.iter().filter(|r| r.mandatory).count()
    }
}

// ---------------------------------------------------------------------------
// GateInput — evidence submitted to a gate
// ---------------------------------------------------------------------------

/// A single piece of evidence submitted to the gate evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateInput {
    /// Which category of evidence this provides.
    pub category: GateCategory,
    /// Score in millionths (1_000_000 = 1.0) for metric-based requirements.
    /// None for boolean pass/fail.
    pub score_millionths: Option<i64>,
    /// Whether this evidence indicates a pass.
    pub passed: bool,
    /// Content hash of the evidence artifact.
    pub evidence_hash: ContentHash,
    /// Human-readable evidence references.
    pub evidence_refs: Vec<String>,
    /// Timestamp when this evidence was collected (nanoseconds).
    pub collected_at_ns: u64,
    /// Schema major version of the evidence producer.
    pub schema_major: u32,
    /// Arbitrary metadata.
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// GateEvaluationInput — full input to the evaluator
// ---------------------------------------------------------------------------

/// Full input bundle for evaluating a single cut-line gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluationInput {
    /// Which cut line to evaluate.
    pub cut_line: CutLine,
    /// Current wall-clock timestamp in nanoseconds (for staleness).
    pub now_ns: u64,
    /// Security epoch of this evaluation.
    pub epoch: SecurityEpoch,
    /// Collected evidence inputs.
    pub inputs: Vec<GateInput>,
    /// Whether the predecessor cut line has been promoted.
    pub predecessor_promoted: bool,
    /// Zone scoping.
    pub zone: String,
}

// ---------------------------------------------------------------------------
// GateEvaluation — per-requirement evaluation result
// ---------------------------------------------------------------------------

/// Result of evaluating a single gate requirement against the inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluation {
    /// The requirement that was evaluated.
    pub category: GateCategory,
    /// Whether the requirement was mandatory.
    pub mandatory: bool,
    /// Whether the requirement was satisfied.
    pub passed: bool,
    /// Score (if metric-based), in millionths.
    pub score_millionths: Option<i64>,
    /// Evidence references contributing to this evaluation.
    pub evidence_refs: Vec<String>,
    /// Human-readable summary of the evaluation.
    pub summary: String,
    /// Validity of the input used (fail-closed on non-Valid).
    pub input_validity: InputValidity,
}

impl GateEvaluation {
    /// Convert to a `GateResult` for integration with `PromotionDecision`.
    pub fn to_gate_result(&self) -> GateResult {
        GateResult {
            gate_name: self.category.to_string(),
            passed: self.passed,
            evidence_refs: self.evidence_refs.clone(),
            summary: self.summary.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// PromotionRecord — the audit artifact
// ---------------------------------------------------------------------------

/// A recorded promotion decision for a single cut-line evaluation.
///
/// Content-addressed and deterministic: given the same inputs and spec,
/// the same record (including `record_hash`) is produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionRecord {
    /// Content hash of this entire record.
    pub record_hash: ContentHash,
    /// Which cut line was evaluated.
    pub cut_line: CutLine,
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Risk level assessment.
    pub risk_level: RiskLevel,
    /// Per-requirement evaluation results.
    pub evaluations: Vec<GateEvaluation>,
    /// Security epoch of this decision.
    pub epoch: SecurityEpoch,
    /// Timestamp of the decision in nanoseconds.
    pub timestamp_ns: u64,
    /// Zone scoping.
    pub zone: String,
    /// Rationale string summarizing the decision.
    pub rationale: String,
    /// Metadata for audit trail.
    pub metadata: BTreeMap<String, String>,
    /// Optional predecessor record hash for chain linking.
    pub predecessor_hash: Option<ContentHash>,
}

impl PromotionRecord {
    /// Compute the content hash from the record's deterministic fields.
    fn compute_hash(
        cut_line: CutLine,
        verdict: &GateVerdict,
        evaluations: &[GateEvaluation],
        epoch: &SecurityEpoch,
        timestamp_ns: u64,
        zone: &str,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"cut-line-promotion-record|");
        canonical.extend_from_slice(cut_line.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(format!("{verdict}").as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&epoch.as_u64().to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(zone.as_bytes());
        canonical.push(b'|');
        for eval in evaluations {
            canonical.extend_from_slice(eval.category.as_str().as_bytes());
            canonical.push(if eval.passed { b'1' } else { b'0' });
        }
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// CutLineEvaluator — stateful gate evaluator
// ---------------------------------------------------------------------------

/// Stateful evaluator for cut-line milestone gates.
///
/// Evaluates gate inputs against a set of cut-line specifications and
/// records promotion decisions as content-addressed artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutLineEvaluator {
    /// Cut-line specifications indexed by cut line.
    specs: BTreeMap<CutLine, CutLineSpec>,
    /// History of promotion records.
    history: Vec<PromotionRecord>,
    /// Promoted cut lines.
    promoted: BTreeMap<CutLine, ContentHash>,
}

impl CutLineEvaluator {
    /// Create a new evaluator with the given specs.
    pub fn new(specs: Vec<CutLineSpec>) -> Self {
        let specs = specs.into_iter().map(|s| (s.cut_line, s)).collect();
        Self {
            specs,
            history: Vec::new(),
            promoted: BTreeMap::new(),
        }
    }

    /// Create an evaluator pre-loaded with default C0 and C1 specs.
    pub fn with_defaults() -> Self {
        Self::new(vec![CutLineSpec::default_c0(), CutLineSpec::default_c1()])
    }

    /// Register (or replace) a spec for a cut line.
    pub fn register_spec(&mut self, spec: CutLineSpec) {
        self.specs.insert(spec.cut_line, spec);
    }

    /// Whether a cut line has been promoted.
    pub fn is_promoted(&self, cut_line: CutLine) -> bool {
        self.promoted.contains_key(&cut_line)
    }

    /// Get the promotion record hash for a promoted cut line.
    pub fn promotion_hash(&self, cut_line: CutLine) -> Option<&ContentHash> {
        self.promoted.get(&cut_line)
    }

    /// Return the full history of promotion records.
    pub fn history(&self) -> &[PromotionRecord] {
        &self.history
    }

    /// Number of promotion records in history.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Validate a single gate input against the spec's freshness and
    /// schema requirements.
    fn validate_input(&self, input: &GateInput, spec: &CutLineSpec, now_ns: u64) -> InputValidity {
        // Check staleness.
        let age_ns = now_ns.saturating_sub(input.collected_at_ns);
        if age_ns > spec.max_input_staleness_ns {
            return InputValidity::Stale {
                age_ns,
                max_age_ns: spec.max_input_staleness_ns,
            };
        }
        // Check schema compatibility.
        if input.schema_major < spec.min_schema_major {
            return InputValidity::Incompatible {
                reason: format!(
                    "schema major {} < required {}",
                    input.schema_major, spec.min_schema_major
                ),
            };
        }
        InputValidity::Valid
    }

    /// Evaluate a gate requirement against the available inputs.
    fn evaluate_requirement(
        &self,
        req: &GateRequirement,
        inputs: &[GateInput],
        spec: &CutLineSpec,
        now_ns: u64,
    ) -> GateEvaluation {
        // Find matching inputs for this category.
        let matching: Vec<&GateInput> = inputs
            .iter()
            .filter(|i| i.category == req.category)
            .collect();

        if matching.is_empty() {
            // Fail-closed: missing evidence.
            return GateEvaluation {
                category: req.category,
                mandatory: req.mandatory,
                passed: false,
                score_millionths: None,
                evidence_refs: vec![format!("no evidence for {}", req.category)],
                summary: format!("no {} evidence provided", req.category),
                input_validity: InputValidity::Missing {
                    field: req.category.to_string(),
                },
            };
        }

        // Validate inputs; fail-closed on any invalid input.
        for input in &matching {
            let validity = self.validate_input(input, spec, now_ns);
            if !validity.is_valid() {
                return GateEvaluation {
                    category: req.category,
                    mandatory: req.mandatory,
                    passed: false,
                    score_millionths: input.score_millionths,
                    evidence_refs: input.evidence_refs.clone(),
                    summary: format!("input rejected: {validity}"),
                    input_validity: validity,
                };
            }
        }

        // Evaluate: all matching inputs must pass.
        let all_passed = matching.iter().all(|i| i.passed);

        // If there's a score threshold, check the best score meets it.
        let best_score = matching.iter().filter_map(|i| i.score_millionths).max();

        let score_ok = match (req.min_score_millionths, best_score) {
            (Some(min), Some(actual)) => actual >= min,
            (Some(_), None) => false, // Required score but none provided.
            (None, _) => true,        // No score requirement.
        };

        let passed = all_passed && score_ok;
        let all_refs: Vec<String> = matching
            .iter()
            .flat_map(|i| i.evidence_refs.iter().cloned())
            .collect();

        let summary = if passed {
            format!("{} gate passed", req.category)
        } else if !all_passed {
            format!("{} gate failed: evidence indicates failure", req.category)
        } else {
            format!(
                "{} gate failed: score {} < required {}",
                req.category,
                best_score.unwrap_or(0),
                req.min_score_millionths.unwrap_or(0)
            )
        };

        GateEvaluation {
            category: req.category,
            mandatory: req.mandatory,
            passed,
            score_millionths: best_score,
            evidence_refs: all_refs,
            summary,
            input_validity: InputValidity::Valid,
        }
    }

    /// Aggregate evaluations into a verdict (fail-closed).
    fn aggregate_verdict(evaluations: &[GateEvaluation]) -> GateVerdict {
        if evaluations.is_empty() {
            return GateVerdict::Inconclusive;
        }

        let has_mandatory_fail = evaluations.iter().any(|e| e.mandatory && !e.passed);

        let any_missing = evaluations
            .iter()
            .any(|e| e.mandatory && matches!(e.input_validity, InputValidity::Missing { .. }));

        if has_mandatory_fail {
            GateVerdict::Denied
        } else if any_missing {
            GateVerdict::Inconclusive
        } else {
            GateVerdict::Approved
        }
    }

    /// Assess risk level from evaluations.
    fn assess_risk(evaluations: &[GateEvaluation]) -> RiskLevel {
        let failed_mandatory = evaluations
            .iter()
            .filter(|e| e.mandatory && !e.passed)
            .count();
        let failed_advisory = evaluations
            .iter()
            .filter(|e| !e.mandatory && !e.passed)
            .count();

        match (failed_mandatory, failed_advisory) {
            (0, 0) => RiskLevel::Low,
            (0, _) => RiskLevel::Medium,
            (1, _) => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    /// Build a rationale string from the evaluations.
    fn build_rationale(
        cut_line: CutLine,
        verdict: &GateVerdict,
        evaluations: &[GateEvaluation],
    ) -> String {
        let total = evaluations.len();
        let passed = evaluations.iter().filter(|e| e.passed).count();
        format!("{cut_line} gate evaluation: {verdict} ({passed}/{total} requirements satisfied)")
    }

    /// Evaluate a complete set of gate inputs against a cut-line spec.
    ///
    /// Returns `None` if no spec is registered for the requested cut line.
    pub fn evaluate(&mut self, input: GateEvaluationInput) -> Option<PromotionRecord> {
        let spec = self.specs.get(&input.cut_line)?.clone();

        // Predecessor check (fail-closed).
        if spec.requires_predecessor
            && let Some(pred) = input.cut_line.predecessor()
            && !self.is_promoted(pred)
            && !input.predecessor_promoted
        {
            let eval = GateEvaluation {
                category: GateCategory::GovernanceCompliance,
                mandatory: true,
                passed: false,
                score_millionths: None,
                evidence_refs: vec![format!("predecessor {pred} not promoted")],
                summary: format!("predecessor {pred} must be promoted first"),
                input_validity: InputValidity::Missing {
                    field: format!("predecessor_{pred}_promotion"),
                },
            };

            let verdict = GateVerdict::Denied;
            let risk_level = RiskLevel::Critical;
            let rationale =
                Self::build_rationale(input.cut_line, &verdict, std::slice::from_ref(&eval));
            let record_hash = PromotionRecord::compute_hash(
                input.cut_line,
                &verdict,
                std::slice::from_ref(&eval),
                &input.epoch,
                input.now_ns,
                &input.zone,
            );

            let record = PromotionRecord {
                record_hash,
                cut_line: input.cut_line,
                verdict,
                risk_level,
                evaluations: vec![eval],
                epoch: input.epoch,
                timestamp_ns: input.now_ns,
                zone: input.zone,
                rationale,
                metadata: BTreeMap::new(),
                predecessor_hash: None,
            };

            self.history.push(record.clone());
            return Some(record);
        }

        // Evaluate each requirement.
        let evaluations: Vec<GateEvaluation> = spec
            .requirements
            .iter()
            .map(|req| self.evaluate_requirement(req, &input.inputs, &spec, input.now_ns))
            .collect();

        let verdict = Self::aggregate_verdict(&evaluations);
        let risk_level = Self::assess_risk(&evaluations);
        let rationale = Self::build_rationale(input.cut_line, &verdict, &evaluations);

        let predecessor_hash = input
            .cut_line
            .predecessor()
            .and_then(|p| self.promoted.get(&p).cloned());

        let record_hash = PromotionRecord::compute_hash(
            input.cut_line,
            &verdict,
            &evaluations,
            &input.epoch,
            input.now_ns,
            &input.zone,
        );

        let record = PromotionRecord {
            record_hash,
            cut_line: input.cut_line,
            verdict,
            risk_level,
            evaluations,
            epoch: input.epoch,
            timestamp_ns: input.now_ns,
            zone: input.zone,
            rationale,
            metadata: BTreeMap::new(),
            predecessor_hash,
        };

        // If approved, mark as promoted.
        if verdict == GateVerdict::Approved {
            self.promoted
                .insert(input.cut_line, record.record_hash.clone());
        }

        self.history.push(record.clone());
        Some(record)
    }

    /// Query the current promotion status summary.
    pub fn promotion_summary(&self) -> PromotionSummary {
        let promoted_lines: Vec<CutLine> = self.promoted.keys().copied().collect();
        let next_line = CutLine::all()
            .iter()
            .find(|c| !self.promoted.contains_key(c))
            .copied();
        let total_evaluations = self.history.len();
        let approved_count = self
            .history
            .iter()
            .filter(|r| r.verdict == GateVerdict::Approved)
            .count();
        let denied_count = self
            .history
            .iter()
            .filter(|r| r.verdict == GateVerdict::Denied)
            .count();

        PromotionSummary {
            promoted_lines,
            next_line,
            total_evaluations,
            approved_count,
            denied_count,
        }
    }

    /// Reset a previously promoted cut line (for rollback scenarios).
    pub fn revoke_promotion(&mut self, cut_line: CutLine) -> bool {
        self.promoted.remove(&cut_line).is_some()
    }
}

// ---------------------------------------------------------------------------
// PromotionSummary — high-level status
// ---------------------------------------------------------------------------

/// High-level summary of cut-line promotion status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionSummary {
    /// Cut lines that have been promoted.
    pub promoted_lines: Vec<CutLine>,
    /// Next cut line to be evaluated (first non-promoted).
    pub next_line: Option<CutLine>,
    /// Total gate evaluations performed.
    pub total_evaluations: usize,
    /// Number of approved evaluations.
    pub approved_count: usize,
    /// Number of denied evaluations.
    pub denied_count: usize,
}

impl PromotionSummary {
    /// Whether all six cut lines are promoted.
    pub fn all_promoted(&self) -> bool {
        self.promoted_lines.len() == CutLine::all().len()
    }

    /// Fraction promoted as millionths (1_000_000 = all promoted).
    pub fn progress_millionths(&self) -> i64 {
        let total = CutLine::all().len() as i64;
        if total == 0 {
            return 0;
        }
        (self.promoted_lines.len() as i64 * 1_000_000) / total
    }
}

// ---------------------------------------------------------------------------
// GateHistory — serializable audit export
// ---------------------------------------------------------------------------

/// Serializable audit export of the full gate evaluation history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateHistory {
    /// All promotion records in chronological order.
    pub records: Vec<PromotionRecord>,
    /// Content hash of the entire history (for integrity verification).
    pub history_hash: ContentHash,
}

impl GateHistory {
    /// Build a gate history from the evaluator.
    pub fn from_evaluator(evaluator: &CutLineEvaluator) -> Self {
        let records = evaluator.history().to_vec();
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"gate-history|");
        for record in &records {
            canonical.extend_from_slice(record.record_hash.to_hex().as_bytes());
            canonical.push(b'|');
        }
        let history_hash = ContentHash::compute(&canonical);
        Self {
            records,
            history_hash,
        }
    }

    /// Verify the history hash.
    pub fn verify(&self) -> bool {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"gate-history|");
        for record in &self.records {
            canonical.extend_from_slice(record.record_hash.to_hex().as_bytes());
            canonical.push(b'|');
        }
        ContentHash::compute(&canonical) == self.history_hash
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn make_passing_input(category: GateCategory, now_ns: u64) -> GateInput {
        GateInput {
            category,
            score_millionths: Some(1_000_000),
            passed: true,
            evidence_hash: ContentHash::compute(category.as_str().as_bytes()),
            evidence_refs: vec![format!("{}_evidence_1", category)],
            collected_at_ns: now_ns,
            schema_major: 1,
            metadata: BTreeMap::new(),
        }
    }

    fn make_failing_input(category: GateCategory, now_ns: u64) -> GateInput {
        GateInput {
            category,
            score_millionths: Some(500_000),
            passed: false,
            evidence_hash: ContentHash::compute(b"fail"),
            evidence_refs: vec![format!("{}_evidence_fail", category)],
            collected_at_ns: now_ns,
            schema_major: 1,
            metadata: BTreeMap::new(),
        }
    }

    // -- CutLine --

    #[test]
    fn cut_line_display_all() {
        assert_eq!(CutLine::C0.to_string(), "C0");
        assert_eq!(CutLine::C5.to_string(), "C5");
    }

    #[test]
    fn cut_line_all_six() {
        assert_eq!(CutLine::all().len(), 6);
    }

    #[test]
    fn cut_line_predecessor_chain() {
        assert_eq!(CutLine::C0.predecessor(), None);
        assert_eq!(CutLine::C1.predecessor(), Some(CutLine::C0));
        assert_eq!(CutLine::C2.predecessor(), Some(CutLine::C1));
        assert_eq!(CutLine::C3.predecessor(), Some(CutLine::C2));
        assert_eq!(CutLine::C4.predecessor(), Some(CutLine::C3));
        assert_eq!(CutLine::C5.predecessor(), Some(CutLine::C4));
    }

    #[test]
    fn cut_line_ordering() {
        assert!(CutLine::C0 < CutLine::C1);
        assert!(CutLine::C4 < CutLine::C5);
    }

    #[test]
    fn cut_line_serde_roundtrip() {
        let original = CutLine::C3;
        let json = serde_json::to_string(&original).unwrap();
        let restored: CutLine = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    // -- InputValidity --

    #[test]
    fn input_validity_display() {
        assert_eq!(InputValidity::Valid.to_string(), "valid");
        let stale = InputValidity::Stale {
            age_ns: 100,
            max_age_ns: 50,
        };
        assert!(stale.to_string().contains("stale"));
    }

    #[test]
    fn input_validity_is_valid() {
        assert!(InputValidity::Valid.is_valid());
        assert!(!InputValidity::Missing { field: "x".into() }.is_valid());
    }

    // -- GateCategory --

    #[test]
    fn gate_category_display_all() {
        let categories = [
            GateCategory::SemanticContract,
            GateCategory::CompilerCorrectness,
            GateCategory::RuntimeParity,
            GateCategory::PerformanceBenchmark,
            GateCategory::SecuritySurvival,
            GateCategory::DeterministicReplay,
            GateCategory::ObservabilityIntegrity,
            GateCategory::FlakeBurden,
            GateCategory::GovernanceCompliance,
            GateCategory::HandoffReadiness,
        ];
        for cat in &categories {
            let s = cat.to_string();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn gate_category_serde_roundtrip() {
        let original = GateCategory::SecuritySurvival;
        let json = serde_json::to_string(&original).unwrap();
        let restored: GateCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    // -- CutLineSpec --

    #[test]
    fn default_c0_spec() {
        let spec = CutLineSpec::default_c0();
        assert_eq!(spec.cut_line, CutLine::C0);
        assert!(!spec.requires_predecessor);
        assert_eq!(spec.mandatory_count(), 2);
    }

    #[test]
    fn default_c1_spec() {
        let spec = CutLineSpec::default_c1();
        assert_eq!(spec.cut_line, CutLine::C1);
        assert!(spec.requires_predecessor);
        assert_eq!(spec.mandatory_count(), 3);
    }

    #[test]
    fn spec_serde_roundtrip() {
        let spec = CutLineSpec::default_c0();
        let json = serde_json::to_string(&spec).unwrap();
        let restored: CutLineSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, restored);
    }

    // -- GateInput --

    #[test]
    fn gate_input_serde_roundtrip() {
        let input = make_passing_input(GateCategory::SemanticContract, 1000);
        let json = serde_json::to_string(&input).unwrap();
        let restored: GateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, restored);
    }

    // -- GateEvaluation --

    #[test]
    fn evaluation_to_gate_result() {
        let eval = GateEvaluation {
            category: GateCategory::SemanticContract,
            mandatory: true,
            passed: true,
            score_millionths: None,
            evidence_refs: vec!["ref1".into()],
            summary: "passed".into(),
            input_validity: InputValidity::Valid,
        };
        let result = eval.to_gate_result();
        assert_eq!(result.gate_name, "semantic_contract");
        assert!(result.passed);
        assert_eq!(result.evidence_refs, vec!["ref1"]);
    }

    // -- CutLineEvaluator: C0 evaluation --

    #[test]
    fn evaluate_c0_all_pass() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Approved);
        assert_eq!(record.risk_level, RiskLevel::Low);
        assert!(evaluator.is_promoted(CutLine::C0));
    }

    #[test]
    fn evaluate_c0_missing_evidence() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        // Only provide one of two required categories.
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![make_passing_input(GateCategory::SemanticContract, now)],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Denied);
        assert!(!evaluator.is_promoted(CutLine::C0));
    }

    #[test]
    fn evaluate_c0_no_inputs() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: 1_000_000_000,
            epoch: test_epoch(),
            inputs: vec![],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Denied);
    }

    #[test]
    fn evaluate_c0_stale_input() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 200_000_000_000_000; // 200 trillion ns
        // Input collected 100 trillion ns ago — exceeds 24h max staleness.
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                GateInput {
                    category: GateCategory::SemanticContract,
                    score_millionths: None,
                    passed: true,
                    evidence_hash: ContentHash::compute(b"old"),
                    evidence_refs: vec!["old_ref".into()],
                    collected_at_ns: 100_000_000_000_000,
                    schema_major: 1,
                    metadata: BTreeMap::new(),
                },
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Denied);
        // Check that staleness is mentioned in evaluations.
        let stale_eval = record
            .evaluations
            .iter()
            .find(|e| e.category == GateCategory::SemanticContract)
            .unwrap();
        assert!(!stale_eval.passed);
        assert!(matches!(
            stale_eval.input_validity,
            InputValidity::Stale { .. }
        ));
    }

    #[test]
    fn evaluate_c0_incompatible_schema() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                GateInput {
                    category: GateCategory::SemanticContract,
                    score_millionths: None,
                    passed: true,
                    evidence_hash: ContentHash::compute(b"old_schema"),
                    evidence_refs: vec!["old_ref".into()],
                    collected_at_ns: now,
                    schema_major: 0, // Below min_schema_major=1.
                    metadata: BTreeMap::new(),
                },
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Denied);
        let incompat_eval = record
            .evaluations
            .iter()
            .find(|e| e.category == GateCategory::SemanticContract)
            .unwrap();
        assert!(matches!(
            incompat_eval.input_validity,
            InputValidity::Incompatible { .. }
        ));
    }

    // -- CutLineEvaluator: C1 with predecessor --

    #[test]
    fn evaluate_c1_without_predecessor() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::CompilerCorrectness, now),
                make_passing_input(GateCategory::RuntimeParity, now),
                make_passing_input(GateCategory::FlakeBurden, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Denied);
        assert_eq!(record.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn evaluate_c1_with_predecessor_promoted() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;

        // First promote C0.
        let c0_input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(c0_input);

        // Now evaluate C1.
        let c1_input = GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::CompilerCorrectness, now),
                make_passing_input(GateCategory::RuntimeParity, now),
                make_passing_input(GateCategory::FlakeBurden, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(c1_input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Approved);
        assert!(evaluator.is_promoted(CutLine::C1));
        assert!(record.predecessor_hash.is_some());
    }

    #[test]
    fn evaluate_c1_with_external_predecessor_flag() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;

        // C1 with predecessor_promoted=true bypasses internal check.
        let input = GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::CompilerCorrectness, now),
                make_passing_input(GateCategory::RuntimeParity, now),
                make_passing_input(GateCategory::FlakeBurden, now),
            ],
            predecessor_promoted: true,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Approved);
    }

    #[test]
    fn evaluate_c1_score_below_threshold() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;

        // Promote C0 first.
        let c0_input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(c0_input);

        // C1 with runtime parity below threshold (0.5 < 0.99).
        let mut low_score_input = make_passing_input(GateCategory::RuntimeParity, now);
        low_score_input.score_millionths = Some(500_000);

        let c1_input = GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::CompilerCorrectness, now),
                low_score_input,
                make_passing_input(GateCategory::FlakeBurden, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(c1_input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Denied);
    }

    // -- Evaluator: no spec --

    #[test]
    fn evaluate_unknown_cut_line_returns_none() {
        let mut evaluator = CutLineEvaluator::new(vec![]);
        let input = GateEvaluationInput {
            cut_line: CutLine::C3,
            now_ns: 1_000_000_000,
            epoch: test_epoch(),
            inputs: vec![],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        assert!(evaluator.evaluate(input).is_none());
    }

    // -- Evaluator: history and summary --

    #[test]
    fn history_tracks_evaluations() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);
        assert_eq!(evaluator.history_len(), 1);
    }

    #[test]
    fn promotion_summary_initial() {
        let evaluator = CutLineEvaluator::with_defaults();
        let summary = evaluator.promotion_summary();
        assert!(summary.promoted_lines.is_empty());
        assert_eq!(summary.next_line, Some(CutLine::C0));
        assert_eq!(summary.total_evaluations, 0);
        assert!(!summary.all_promoted());
    }

    #[test]
    fn promotion_summary_after_c0() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);

        let summary = evaluator.promotion_summary();
        assert_eq!(summary.promoted_lines, vec![CutLine::C0]);
        assert_eq!(summary.next_line, Some(CutLine::C1));
        assert_eq!(summary.approved_count, 1);
        assert!(!summary.all_promoted());
    }

    #[test]
    fn progress_millionths() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let summary = evaluator.promotion_summary();
        assert_eq!(summary.progress_millionths(), 0);

        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);

        let summary = evaluator.promotion_summary();
        // 1/6 * 1_000_000 = 166_666
        assert_eq!(summary.progress_millionths(), 166_666);
    }

    // -- Revoke --

    #[test]
    fn revoke_promotion() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);
        assert!(evaluator.is_promoted(CutLine::C0));

        assert!(evaluator.revoke_promotion(CutLine::C0));
        assert!(!evaluator.is_promoted(CutLine::C0));
        // Revoking again returns false.
        assert!(!evaluator.revoke_promotion(CutLine::C0));
    }

    // -- PromotionRecord --

    #[test]
    fn record_hash_deterministic() {
        let mut e1 = CutLineEvaluator::with_defaults();
        let mut e2 = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let make_input = || GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let r1 = e1.evaluate(make_input()).unwrap();
        let r2 = e2.evaluate(make_input()).unwrap();
        assert_eq!(r1.record_hash, r2.record_hash);
    }

    #[test]
    fn record_serde_roundtrip() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        let record = evaluator.evaluate(input).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        let restored: PromotionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, restored);
    }

    #[test]
    fn record_rationale_contains_cut_line() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        let record = evaluator.evaluate(input).unwrap();
        assert!(record.rationale.contains("C0"));
    }

    // -- GateHistory --

    #[test]
    fn gate_history_from_evaluator() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);

        let history = GateHistory::from_evaluator(&evaluator);
        assert_eq!(history.records.len(), 1);
        assert!(history.verify());
    }

    #[test]
    fn gate_history_verify_detects_tampering() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);

        let mut history = GateHistory::from_evaluator(&evaluator);
        // Tamper with the history.
        history.records.clear();
        assert!(!history.verify());
    }

    #[test]
    fn gate_history_serde_roundtrip() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);

        let history = GateHistory::from_evaluator(&evaluator);
        let json = serde_json::to_string(&history).unwrap();
        let restored: GateHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(history, restored);
    }

    // -- Custom spec --

    #[test]
    fn custom_spec_advisory_gate() {
        let spec = CutLineSpec {
            cut_line: CutLine::C2,
            requirements: vec![
                GateRequirement {
                    category: GateCategory::DeterministicReplay,
                    mandatory: true,
                    description: "Replay passes".into(),
                    min_score_millionths: None,
                },
                GateRequirement {
                    category: GateCategory::PerformanceBenchmark,
                    mandatory: false, // Advisory only.
                    description: "Performance target".into(),
                    min_score_millionths: Some(900_000),
                },
            ],
            max_input_staleness_ns: 3_600_000_000_000,
            min_schema_major: 1,
            requires_predecessor: false,
        };

        let mut evaluator = CutLineEvaluator::new(vec![spec]);
        let now = 1_000_000_000;

        // Mandatory passes, advisory fails.
        let input = GateEvaluationInput {
            cut_line: CutLine::C2,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::DeterministicReplay, now),
                make_failing_input(GateCategory::PerformanceBenchmark, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        // Approved because only advisory gate failed.
        assert_eq!(record.verdict, GateVerdict::Approved);
        assert_eq!(record.risk_level, RiskLevel::Medium);
    }

    // -- Register spec --

    #[test]
    fn register_spec_replaces_existing() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let custom = CutLineSpec {
            cut_line: CutLine::C0,
            requirements: vec![GateRequirement {
                category: GateCategory::HandoffReadiness,
                mandatory: true,
                description: "Custom C0".into(),
                min_score_millionths: None,
            }],
            max_input_staleness_ns: 1_000_000_000,
            min_schema_major: 1,
            requires_predecessor: false,
        };
        evaluator.register_spec(custom);

        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![make_passing_input(GateCategory::HandoffReadiness, now)],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Approved);
    }

    // -- Aggregate verdict edge cases --

    #[test]
    fn aggregate_verdict_empty_is_inconclusive() {
        assert_eq!(
            CutLineEvaluator::aggregate_verdict(&[]),
            GateVerdict::Inconclusive
        );
    }

    #[test]
    fn aggregate_verdict_all_pass() {
        let evals = vec![GateEvaluation {
            category: GateCategory::SemanticContract,
            mandatory: true,
            passed: true,
            score_millionths: None,
            evidence_refs: vec![],
            summary: "ok".into(),
            input_validity: InputValidity::Valid,
        }];
        assert_eq!(
            CutLineEvaluator::aggregate_verdict(&evals),
            GateVerdict::Approved
        );
    }

    #[test]
    fn aggregate_verdict_mandatory_fail() {
        let evals = vec![GateEvaluation {
            category: GateCategory::SemanticContract,
            mandatory: true,
            passed: false,
            score_millionths: None,
            evidence_refs: vec![],
            summary: "fail".into(),
            input_validity: InputValidity::Valid,
        }];
        assert_eq!(
            CutLineEvaluator::aggregate_verdict(&evals),
            GateVerdict::Denied
        );
    }

    // -- Risk assessment --

    #[test]
    fn risk_assessment_levels() {
        let make_eval = |mandatory: bool, passed: bool| GateEvaluation {
            category: GateCategory::SemanticContract,
            mandatory,
            passed,
            score_millionths: None,
            evidence_refs: vec![],
            summary: String::new(),
            input_validity: InputValidity::Valid,
        };

        assert_eq!(
            CutLineEvaluator::assess_risk(&[make_eval(true, true)]),
            RiskLevel::Low
        );
        assert_eq!(
            CutLineEvaluator::assess_risk(&[make_eval(false, false)]),
            RiskLevel::Medium
        );
        assert_eq!(
            CutLineEvaluator::assess_risk(&[make_eval(true, false)]),
            RiskLevel::High
        );
        assert_eq!(
            CutLineEvaluator::assess_risk(&[make_eval(true, false), make_eval(true, false)]),
            RiskLevel::Critical
        );
    }

    // -- Promotion hash --

    #[test]
    fn promotion_hash_available_after_approval() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        assert!(evaluator.promotion_hash(CutLine::C0).is_none());

        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(
            evaluator.promotion_hash(CutLine::C0),
            Some(&record.record_hash)
        );
    }

    // -- Failing input --

    #[test]
    fn failing_input_denies_gate() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_failing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };

        let record = evaluator.evaluate(input).unwrap();
        assert_eq!(record.verdict, GateVerdict::Denied);
    }

    // -- Multiple evaluations --

    #[test]
    fn multiple_evaluations_in_history() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;

        // First: denied.
        let input1 = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input1);

        // Second: approved.
        let input2 = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input2);

        assert_eq!(evaluator.history_len(), 2);
        let summary = evaluator.promotion_summary();
        assert_eq!(summary.approved_count, 1);
        assert_eq!(summary.denied_count, 1);
    }

    // -- Evaluator serde roundtrip --

    #[test]
    fn evaluator_serde_roundtrip() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;
        let input = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "test".into(),
        };
        evaluator.evaluate(input);

        let json = serde_json::to_string(&evaluator).unwrap();
        let restored: CutLineEvaluator = serde_json::from_str(&json).unwrap();
        assert_eq!(evaluator.history_len(), restored.history_len());
        assert_eq!(
            evaluator.is_promoted(CutLine::C0),
            restored.is_promoted(CutLine::C0)
        );
    }

    // -- Full C0 → C1 promotion chain --

    #[test]
    fn full_c0_c1_promotion_chain() {
        let mut evaluator = CutLineEvaluator::with_defaults();
        let now = 1_000_000_000;

        // Promote C0.
        let c0 = GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, now),
                make_passing_input(GateCategory::GovernanceCompliance, now),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        };
        let r0 = evaluator.evaluate(c0).unwrap();
        assert_eq!(r0.verdict, GateVerdict::Approved);

        // Promote C1.
        let c1 = GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now,
            epoch: test_epoch(),
            inputs: vec![
                make_passing_input(GateCategory::CompilerCorrectness, now),
                make_passing_input(GateCategory::RuntimeParity, now),
                make_passing_input(GateCategory::FlakeBurden, now),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        };
        let r1 = evaluator.evaluate(c1).unwrap();
        assert_eq!(r1.verdict, GateVerdict::Approved);
        assert_eq!(r1.predecessor_hash, Some(r0.record_hash));
        assert!(evaluator.is_promoted(CutLine::C0));
        assert!(evaluator.is_promoted(CutLine::C1));

        let summary = evaluator.promotion_summary();
        assert_eq!(summary.promoted_lines.len(), 2);
        assert_eq!(summary.next_line, Some(CutLine::C2));
    }

    // -- Metadata on inputs --

    #[test]
    fn input_metadata_preserved() {
        let mut input = make_passing_input(GateCategory::SemanticContract, 1000);
        input.metadata.insert("ci_run".into(), "12345".into());
        assert_eq!(input.metadata.get("ci_run"), Some(&"12345".to_string()));
    }

    // -- Empty history --

    #[test]
    fn gate_history_empty() {
        let evaluator = CutLineEvaluator::with_defaults();
        let history = GateHistory::from_evaluator(&evaluator);
        assert!(history.records.is_empty());
        assert!(history.verify());
    }
}
