//! Demo-to-claim linkage gate for production-facing milestones.
//!
//! Requires every milestone claim to map to a runnable demo specification,
//! evidence IDs, expected outputs, and verification commands. Claims without
//! complete linkage are rejected by the gate.
//!
//! Plan reference: FRX-16.3

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ── Constants ────────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for demo-claim linkage gate artifacts.
pub const LINKAGE_GATE_SCHEMA_VERSION: &str = "franken-engine.demo-claim-linkage-gate.v1";

/// Maximum number of claims per evaluation.
const MAX_CLAIMS: usize = 256;

/// Maximum number of evidence links per claim.
const MAX_EVIDENCE_PER_CLAIM: usize = 64;

/// Maximum number of verification commands per demo.
const MAX_COMMANDS_PER_DEMO: usize = 32;

// ── Demo Specification ──────────────────────────────────────────────────

/// A runnable demo specification that demonstrates a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoSpecification {
    /// Unique demo identifier.
    pub demo_id: String,
    /// Human-readable title.
    pub title: String,
    /// Description of what the demo shows.
    pub description: String,
    /// Milestone ID this demo belongs to.
    pub milestone_id: String,
    /// Whether the demo is runnable (has verification commands).
    pub runnable: bool,
    /// Verification commands to run the demo.
    pub verification_commands: Vec<VerificationCommand>,
    /// Expected outputs (keyed by output name).
    pub expected_outputs: BTreeMap<String, ExpectedOutput>,
    /// Tags for classification.
    pub tags: BTreeSet<String>,
}

impl DemoSpecification {
    /// Whether the demo is complete (has verification commands and expected outputs).
    pub fn is_complete(&self) -> bool {
        self.runnable && !self.verification_commands.is_empty() && !self.expected_outputs.is_empty()
    }

    /// Number of verification commands.
    pub fn command_count(&self) -> usize {
        self.verification_commands.len()
    }
}

impl fmt::Display for DemoSpecification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.is_complete() {
            "complete"
        } else {
            "incomplete"
        };
        write!(f, "demo({}, {}, {})", self.demo_id, self.title, status)
    }
}

/// A verification command for a demo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCommand {
    /// Command identifier.
    pub command_id: String,
    /// The command to execute.
    pub command: String,
    /// Expected exit code (0 = success).
    pub expected_exit_code: i32,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether this command is deterministic.
    pub deterministic: bool,
}

impl fmt::Display for VerificationCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cmd({}, exit={})",
            self.command_id, self.expected_exit_code
        )
    }
}

/// Expected output from a demo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedOutput {
    /// Output name.
    pub name: String,
    /// Expected content hash (deterministic outputs).
    pub expected_hash: Option<ContentHash>,
    /// Whether the output must exactly match.
    pub exact_match: bool,
    /// Acceptable tolerance for numeric outputs (millionths).
    pub tolerance_millionths: i64,
}

// ── Claim ───────────────────────────────────────────────────────────────

/// A production-facing milestone claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MilestoneClaim {
    /// Unique claim identifier.
    pub claim_id: String,
    /// Human-readable claim statement.
    pub statement: String,
    /// Milestone ID this claim belongs to.
    pub milestone_id: String,
    /// Category of the claim.
    pub category: ClaimCategory,
    /// Evidence links supporting this claim.
    pub evidence_links: Vec<EvidenceLink>,
    /// Demo specifications demonstrating this claim.
    pub demos: Vec<String>,
}

impl fmt::Display for MilestoneClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "claim({}, {}, evidence={}, demos={})",
            self.claim_id,
            self.category,
            self.evidence_links.len(),
            self.demos.len()
        )
    }
}

/// Category of a milestone claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimCategory {
    /// Performance claim (throughput, latency, etc.).
    Performance,
    /// Correctness claim (behavior, semantics).
    Correctness,
    /// Security claim (isolation, containment).
    Security,
    /// Compatibility claim (API, protocol).
    Compatibility,
    /// Reliability claim (availability, recovery).
    Reliability,
    /// Developer experience claim.
    DeveloperExperience,
}

impl fmt::Display for ClaimCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Performance => write!(f, "performance"),
            Self::Correctness => write!(f, "correctness"),
            Self::Security => write!(f, "security"),
            Self::Compatibility => write!(f, "compatibility"),
            Self::Reliability => write!(f, "reliability"),
            Self::DeveloperExperience => write!(f, "developer-experience"),
        }
    }
}

/// A link from a claim to supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLink {
    /// Evidence identifier.
    pub evidence_id: String,
    /// Kind of evidence.
    pub kind: EvidenceKind,
    /// Artifact hash for the evidence.
    pub artifact_hash: ContentHash,
    /// Brief description of what this evidence shows.
    pub description: String,
}

impl fmt::Display for EvidenceLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "evidence({}, {})", self.evidence_id, self.kind)
    }
}

/// Kind of evidence supporting a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Test suite result.
    TestResult,
    /// Benchmark result.
    BenchmarkResult,
    /// Security audit.
    SecurityAudit,
    /// Formal verification proof.
    FormalProof,
    /// Code review.
    CodeReview,
    /// Demo replay artifact.
    DemoReplay,
    /// Third-party verification.
    ThirdPartyVerification,
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TestResult => write!(f, "test-result"),
            Self::BenchmarkResult => write!(f, "benchmark-result"),
            Self::SecurityAudit => write!(f, "security-audit"),
            Self::FormalProof => write!(f, "formal-proof"),
            Self::CodeReview => write!(f, "code-review"),
            Self::DemoReplay => write!(f, "demo-replay"),
            Self::ThirdPartyVerification => write!(f, "third-party-verification"),
        }
    }
}

// ── Linkage Check Result ────────────────────────────────────────────────

/// Result of checking a single claim's linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimLinkageResult {
    /// Claim ID that was checked.
    pub claim_id: String,
    /// Whether all linkage requirements are met.
    pub linked: bool,
    /// Whether the claim has at least one runnable demo.
    pub has_runnable_demo: bool,
    /// Whether the claim has evidence links.
    pub has_evidence: bool,
    /// Whether all referenced demos have expected outputs.
    pub demos_have_outputs: bool,
    /// Whether all referenced demos have verification commands.
    pub demos_have_commands: bool,
    /// Missing linkage details.
    pub missing: Vec<String>,
    /// Completeness score (millionths, 0 = nothing, MILLION = fully linked).
    pub completeness_millionths: i64,
}

// ── Gate Decision ───────────────────────────────────────────────────────

/// Gate decision for a milestone's demo-claim linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageGateDecision {
    /// Decision ID.
    pub decision_id: String,
    /// Milestone ID that was evaluated.
    pub milestone_id: String,
    /// Epoch of evaluation.
    pub epoch: SecurityEpoch,
    /// Verdict.
    pub verdict: LinkageVerdict,
    /// Per-claim linkage results.
    pub claim_results: Vec<ClaimLinkageResult>,
    /// Total claims evaluated.
    pub total_claims: u64,
    /// Claims with complete linkage.
    pub linked_claims: u64,
    /// Claims missing linkage.
    pub unlinked_claims: u64,
    /// Aggregate completeness (millionths).
    pub aggregate_completeness_millionths: i64,
    /// Rationale.
    pub rationale: String,
    /// Artifact hash.
    pub artifact_hash: ContentHash,
}

impl LinkageGateDecision {
    /// Whether the gate passes.
    pub fn is_pass(&self) -> bool {
        self.verdict == LinkageVerdict::Pass
    }

    /// Fraction of claims that are linked (millionths).
    pub fn linkage_rate_millionths(&self) -> i64 {
        if self.total_claims == 0 {
            return 0;
        }
        (self.linked_claims as i64 * MILLION) / self.total_claims as i64
    }
}

impl fmt::Display for LinkageGateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "linkage-gate({}, {}, linked={}/{}, completeness={})",
            self.milestone_id,
            self.verdict,
            self.linked_claims,
            self.total_claims,
            self.aggregate_completeness_millionths
        )
    }
}

/// Verdict of a linkage gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageVerdict {
    /// All claims are fully linked.
    Pass,
    /// Some claims are missing linkage.
    Fail,
    /// No claims to evaluate.
    Empty,
}

impl fmt::Display for LinkageVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Empty => write!(f, "empty"),
        }
    }
}

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the linkage gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageGateConfig {
    /// Epoch for evaluation.
    pub epoch: SecurityEpoch,
    /// Minimum completeness to pass (millionths). Default = MILLION (100%).
    pub min_completeness_millionths: i64,
    /// Whether every claim must have at least one runnable demo.
    pub require_runnable_demo: bool,
    /// Whether every claim must have at least one evidence link.
    pub require_evidence: bool,
    /// Whether every demo must have expected outputs.
    pub require_expected_outputs: bool,
    /// Whether every demo must have verification commands.
    pub require_verification_commands: bool,
}

impl Default for LinkageGateConfig {
    fn default() -> Self {
        Self {
            epoch: SecurityEpoch::from_raw(1),
            min_completeness_millionths: MILLION,
            require_runnable_demo: true,
            require_evidence: true,
            require_expected_outputs: true,
            require_verification_commands: true,
        }
    }
}

// ── Error ───────────────────────────────────────────────────────────────

/// Errors from the linkage gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageGateError {
    /// No claims provided.
    NoClaims,
    /// Too many claims.
    TooManyClaims { count: usize, max: usize },
    /// Duplicate claim ID.
    DuplicateClaim { claim_id: String },
    /// Duplicate demo ID.
    DuplicateDemo { demo_id: String },
    /// Too many evidence links on a claim.
    TooManyEvidenceLinks {
        claim_id: String,
        count: usize,
        max: usize,
    },
    /// Too many verification commands on a demo.
    TooManyCommands {
        demo_id: String,
        count: usize,
        max: usize,
    },
    /// Claim references unknown demo.
    UnknownDemo { claim_id: String, demo_id: String },
    /// Invalid configuration.
    InvalidConfig { detail: String },
}

impl fmt::Display for LinkageGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoClaims => write!(f, "no claims provided"),
            Self::TooManyClaims { count, max } => {
                write!(f, "too many claims: {} exceeds max {}", count, max)
            }
            Self::DuplicateClaim { claim_id } => {
                write!(f, "duplicate claim ID: {}", claim_id)
            }
            Self::DuplicateDemo { demo_id } => {
                write!(f, "duplicate demo ID: {}", demo_id)
            }
            Self::TooManyEvidenceLinks {
                claim_id,
                count,
                max,
            } => {
                write!(
                    f,
                    "claim {} has {} evidence links, max {}",
                    claim_id, count, max
                )
            }
            Self::TooManyCommands {
                demo_id,
                count,
                max,
            } => {
                write!(f, "demo {} has {} commands, max {}", demo_id, count, max)
            }
            Self::UnknownDemo { claim_id, demo_id } => {
                write!(f, "claim {} references unknown demo {}", claim_id, demo_id)
            }
            Self::InvalidConfig { detail } => {
                write!(f, "invalid config: {}", detail)
            }
        }
    }
}

impl std::error::Error for LinkageGateError {}

// ── Main Gate ───────────────────────────────────────────────────────────

/// Demo-to-claim linkage gate.
///
/// Evaluates whether all milestone claims have proper linkage to demos,
/// evidence, and verification commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoClaimLinkageGate {
    config: LinkageGateConfig,
    evaluation_count: u64,
}

impl DemoClaimLinkageGate {
    /// Create a new linkage gate.
    pub fn new(config: LinkageGateConfig) -> Result<Self, LinkageGateError> {
        if config.min_completeness_millionths < 0 || config.min_completeness_millionths > MILLION {
            return Err(LinkageGateError::InvalidConfig {
                detail: format!(
                    "min_completeness_millionths {} out of range [0, {}]",
                    config.min_completeness_millionths, MILLION
                ),
            });
        }
        Ok(Self {
            config,
            evaluation_count: 0,
        })
    }

    /// Access the configuration.
    pub fn config(&self) -> &LinkageGateConfig {
        &self.config
    }

    /// Number of evaluations performed.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Evaluate milestone claims against demo specifications.
    pub fn evaluate(
        &mut self,
        milestone_id: &str,
        claims: &[MilestoneClaim],
        demos: &[DemoSpecification],
    ) -> Result<LinkageGateDecision, LinkageGateError> {
        if claims.is_empty() {
            return Err(LinkageGateError::NoClaims);
        }
        if claims.len() > MAX_CLAIMS {
            return Err(LinkageGateError::TooManyClaims {
                count: claims.len(),
                max: MAX_CLAIMS,
            });
        }

        // Check duplicate claim IDs.
        let mut seen_claims = BTreeSet::new();
        for claim in claims {
            if !seen_claims.insert(&claim.claim_id) {
                return Err(LinkageGateError::DuplicateClaim {
                    claim_id: claim.claim_id.clone(),
                });
            }
            if claim.evidence_links.len() > MAX_EVIDENCE_PER_CLAIM {
                return Err(LinkageGateError::TooManyEvidenceLinks {
                    claim_id: claim.claim_id.clone(),
                    count: claim.evidence_links.len(),
                    max: MAX_EVIDENCE_PER_CLAIM,
                });
            }
        }

        // Build demo index and check duplicates.
        let mut demo_index: BTreeMap<&str, &DemoSpecification> = BTreeMap::new();
        for demo in demos {
            if demo_index.contains_key(demo.demo_id.as_str()) {
                return Err(LinkageGateError::DuplicateDemo {
                    demo_id: demo.demo_id.clone(),
                });
            }
            if demo.verification_commands.len() > MAX_COMMANDS_PER_DEMO {
                return Err(LinkageGateError::TooManyCommands {
                    demo_id: demo.demo_id.clone(),
                    count: demo.verification_commands.len(),
                    max: MAX_COMMANDS_PER_DEMO,
                });
            }
            demo_index.insert(&demo.demo_id, demo);
        }

        // Validate claim → demo references.
        for claim in claims {
            for demo_id in &claim.demos {
                if !demo_index.contains_key(demo_id.as_str()) {
                    return Err(LinkageGateError::UnknownDemo {
                        claim_id: claim.claim_id.clone(),
                        demo_id: demo_id.clone(),
                    });
                }
            }
        }

        self.evaluation_count += 1;

        // Evaluate each claim.
        let mut claim_results = Vec::new();
        let mut linked_count: u64 = 0;
        let mut total_completeness: i64 = 0;

        for claim in claims {
            let result = self.check_claim(claim, &demo_index);
            total_completeness += result.completeness_millionths;
            if result.linked {
                linked_count += 1;
            }
            claim_results.push(result);
        }

        let total_claims = claims.len() as u64;
        let aggregate_completeness = total_completeness / total_claims as i64;

        let verdict = if linked_count == total_claims {
            LinkageVerdict::Pass
        } else {
            LinkageVerdict::Fail
        };

        let rationale = match verdict {
            LinkageVerdict::Pass => format!(
                "All {} claims fully linked, completeness {}",
                total_claims, aggregate_completeness
            ),
            LinkageVerdict::Fail => {
                let unlinked: Vec<_> = claim_results
                    .iter()
                    .filter(|r| !r.linked)
                    .map(|r| r.claim_id.clone())
                    .collect();
                format!(
                    "{}/{} claims unlinked: {}",
                    unlinked.len(),
                    total_claims,
                    unlinked.join(", ")
                )
            }
            LinkageVerdict::Empty => "no claims to evaluate".to_string(),
        };

        // Compute artifact hash.
        let mut hash_buf = Vec::new();
        hash_buf.extend_from_slice(LINKAGE_GATE_SCHEMA_VERSION.as_bytes());
        hash_buf.extend_from_slice(milestone_id.as_bytes());
        hash_buf.extend_from_slice(&self.config.epoch.as_u64().to_le_bytes());
        hash_buf.extend_from_slice(&total_claims.to_le_bytes());
        hash_buf.extend_from_slice(&linked_count.to_le_bytes());
        for r in &claim_results {
            hash_buf.extend_from_slice(r.claim_id.as_bytes());
            hash_buf.extend_from_slice(&r.completeness_millionths.to_le_bytes());
        }

        let decision_id = format!(
            "linkage-{}-{}-{}",
            milestone_id,
            self.config.epoch.as_u64(),
            self.evaluation_count
        );

        Ok(LinkageGateDecision {
            decision_id,
            milestone_id: milestone_id.to_string(),
            epoch: self.config.epoch,
            verdict,
            claim_results,
            total_claims,
            linked_claims: linked_count,
            unlinked_claims: total_claims - linked_count,
            aggregate_completeness_millionths: aggregate_completeness,
            rationale,
            artifact_hash: ContentHash::compute(&hash_buf),
        })
    }

    // ── Claim Checking ──────────────────────────────────────────────

    fn check_claim(
        &self,
        claim: &MilestoneClaim,
        demo_index: &BTreeMap<&str, &DemoSpecification>,
    ) -> ClaimLinkageResult {
        let mut missing = Vec::new();
        let mut score: i64 = 0;
        let mut max_score: i64 = 0;

        // Check evidence links.
        let has_evidence = !claim.evidence_links.is_empty();
        if self.config.require_evidence {
            max_score += MILLION / 4;
            if has_evidence {
                score += MILLION / 4;
            } else {
                missing.push("no evidence links".to_string());
            }
        }

        // Check demo references.
        let has_runnable_demo = claim
            .demos
            .iter()
            .any(|d| demo_index.get(d.as_str()).is_some_and(|demo| demo.runnable));
        if self.config.require_runnable_demo {
            max_score += MILLION / 4;
            if has_runnable_demo {
                score += MILLION / 4;
            } else {
                missing.push("no runnable demo".to_string());
            }
        }

        // Check expected outputs.
        let demos_have_outputs = claim.demos.iter().all(|d| {
            demo_index
                .get(d.as_str())
                .is_some_and(|demo| !demo.expected_outputs.is_empty())
        }) && !claim.demos.is_empty();
        if self.config.require_expected_outputs {
            max_score += MILLION / 4;
            if demos_have_outputs {
                score += MILLION / 4;
            } else {
                missing.push("demos missing expected outputs".to_string());
            }
        }

        // Check verification commands.
        let demos_have_commands = claim.demos.iter().all(|d| {
            demo_index
                .get(d.as_str())
                .is_some_and(|demo| !demo.verification_commands.is_empty())
        }) && !claim.demos.is_empty();
        if self.config.require_verification_commands {
            max_score += MILLION / 4;
            if demos_have_commands {
                score += MILLION / 4;
            } else {
                missing.push("demos missing verification commands".to_string());
            }
        }

        let completeness = if max_score > 0 {
            (score * MILLION) / max_score
        } else {
            MILLION
        };

        let linked = missing.is_empty();

        ClaimLinkageResult {
            claim_id: claim.claim_id.clone(),
            linked,
            has_runnable_demo,
            has_evidence,
            demos_have_outputs,
            demos_have_commands,
            missing,
            completeness_millionths: completeness,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_evidence(id: &str) -> EvidenceLink {
        EvidenceLink {
            evidence_id: id.to_string(),
            kind: EvidenceKind::TestResult,
            artifact_hash: ContentHash::compute(id.as_bytes()),
            description: format!("Evidence {}", id),
        }
    }

    fn make_command(id: &str) -> VerificationCommand {
        VerificationCommand {
            command_id: id.to_string(),
            command: format!("cargo test {}", id),
            expected_exit_code: 0,
            timeout_ms: 60_000,
            deterministic: true,
        }
    }

    fn make_output(name: &str) -> ExpectedOutput {
        ExpectedOutput {
            name: name.to_string(),
            expected_hash: Some(ContentHash::compute(name.as_bytes())),
            exact_match: true,
            tolerance_millionths: 0,
        }
    }

    fn make_demo(id: &str, runnable: bool) -> DemoSpecification {
        let commands = if runnable {
            vec![make_command(&format!("cmd-{}", id))]
        } else {
            Vec::new()
        };
        let mut outputs = BTreeMap::new();
        if runnable {
            outputs.insert("out1".to_string(), make_output("out1"));
        }
        DemoSpecification {
            demo_id: id.to_string(),
            title: format!("Demo {}", id),
            description: format!("Demo {} description", id),
            milestone_id: "m1".to_string(),
            runnable,
            verification_commands: commands,
            expected_outputs: outputs,
            tags: BTreeSet::new(),
        }
    }

    fn make_claim(
        id: &str,
        category: ClaimCategory,
        demos: Vec<&str>,
        evidence: Vec<&str>,
    ) -> MilestoneClaim {
        MilestoneClaim {
            claim_id: id.to_string(),
            statement: format!("Claim {}", id),
            milestone_id: "m1".to_string(),
            category,
            evidence_links: evidence.into_iter().map(make_evidence).collect(),
            demos: demos.into_iter().map(String::from).collect(),
        }
    }

    fn default_gate() -> DemoClaimLinkageGate {
        DemoClaimLinkageGate::new(LinkageGateConfig::default()).unwrap()
    }

    // ── Constructor Tests ───────────────────────────────────────────

    #[test]
    fn new_creates_gate() {
        let gate = default_gate();
        assert_eq!(gate.evaluation_count(), 0);
    }

    #[test]
    fn new_rejects_invalid_completeness_high() {
        let config = LinkageGateConfig {
            min_completeness_millionths: MILLION + 1,
            ..Default::default()
        };
        let result = DemoClaimLinkageGate::new(config);
        assert!(matches!(
            result,
            Err(LinkageGateError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn new_rejects_invalid_completeness_negative() {
        let config = LinkageGateConfig {
            min_completeness_millionths: -1,
            ..Default::default()
        };
        let result = DemoClaimLinkageGate::new(config);
        assert!(matches!(
            result,
            Err(LinkageGateError::InvalidConfig { .. })
        ));
    }

    // ── Evaluation Tests ────────────────────────────────────────────

    #[test]
    fn evaluate_rejects_no_claims() {
        let mut gate = default_gate();
        let result = gate.evaluate("m1", &[], &[]);
        assert!(matches!(result, Err(LinkageGateError::NoClaims)));
    }

    #[test]
    fn evaluate_rejects_too_many_claims() {
        let mut gate = default_gate();
        let demo = make_demo("d1", true);
        let claims: Vec<_> = (0..257)
            .map(|i| {
                make_claim(
                    &format!("c{}", i),
                    ClaimCategory::Performance,
                    vec!["d1"],
                    vec!["e1"],
                )
            })
            .collect();
        let result = gate.evaluate("m1", &claims, &[demo]);
        assert!(matches!(
            result,
            Err(LinkageGateError::TooManyClaims {
                count: 257,
                max: 256
            })
        ));
    }

    #[test]
    fn evaluate_rejects_duplicate_claims() {
        let mut gate = default_gate();
        let demo = make_demo("d1", true);
        let claims = vec![
            make_claim("dup", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("dup", ClaimCategory::Security, vec!["d1"], vec!["e2"]),
        ];
        let result = gate.evaluate("m1", &claims, &[demo]);
        assert!(matches!(
            result,
            Err(LinkageGateError::DuplicateClaim { .. })
        ));
    }

    #[test]
    fn evaluate_rejects_duplicate_demos() {
        let mut gate = default_gate();
        let demos = vec![make_demo("dup", true), make_demo("dup", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["dup"],
            vec!["e1"],
        )];
        let result = gate.evaluate("m1", &claims, &demos);
        assert!(matches!(
            result,
            Err(LinkageGateError::DuplicateDemo { .. })
        ));
    }

    #[test]
    fn evaluate_rejects_unknown_demo() {
        let mut gate = default_gate();
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["nonexistent"],
            vec!["e1"],
        )];
        let result = gate.evaluate("m1", &claims, &[]);
        assert!(matches!(result, Err(LinkageGateError::UnknownDemo { .. })));
    }

    #[test]
    fn evaluate_passes_fully_linked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
        assert!(decision.is_pass());
        assert_eq!(decision.linked_claims, 1);
        assert_eq!(decision.unlinked_claims, 0);
    }

    #[test]
    fn evaluate_fails_missing_evidence() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec![], // No evidence
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
        assert!(!decision.is_pass());
    }

    #[test]
    fn evaluate_fails_missing_demo() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec![], // No demos
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
    }

    #[test]
    fn evaluate_fails_non_runnable_demo() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", false)]; // Not runnable
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
    }

    #[test]
    fn evaluate_increments_count() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let _ = gate.evaluate("m1", &claims, &demos);
        assert_eq!(gate.evaluation_count(), 1);
        let _ = gate.evaluate("m1", &claims, &demos);
        assert_eq!(gate.evaluation_count(), 2);
    }

    // ── Completeness Scoring ────────────────────────────────────────

    #[test]
    fn fully_linked_has_million_completeness() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.aggregate_completeness_millionths, MILLION);
    }

    #[test]
    fn partial_linkage_has_partial_completeness() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec![], // Missing evidence → 75% complete
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert!(decision.aggregate_completeness_millionths > 0);
        assert!(decision.aggregate_completeness_millionths < MILLION);
    }

    #[test]
    fn linkage_rate_computed() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec![], vec![]),
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.linkage_rate_millionths(), 500_000); // 1/2
    }

    // ── Multiple Claims ─────────────────────────────────────────────

    #[test]
    fn multiple_claims_all_linked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true), make_demo("d2", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec!["d2"], vec!["e2"]),
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
        assert_eq!(decision.linked_claims, 2);
    }

    #[test]
    fn some_claims_linked_fails() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec![], vec![]), // Incomplete
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
        assert_eq!(decision.linked_claims, 1);
        assert_eq!(decision.unlinked_claims, 1);
    }

    // ── Relaxed Configuration ───────────────────────────────────────

    #[test]
    fn passes_without_evidence_when_not_required() {
        let config = LinkageGateConfig {
            require_evidence: false,
            ..Default::default()
        };
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();

        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec![],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    #[test]
    fn passes_without_runnable_when_not_required() {
        let mut config = LinkageGateConfig {
            require_runnable_demo: false,
            ..Default::default()
        };
        config.require_expected_outputs = false;
        config.require_verification_commands = false;
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();

        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec![],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &[]).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    // ── Display / Serde ─────────────────────────────────────────────

    #[test]
    fn claim_category_display() {
        assert_eq!(format!("{}", ClaimCategory::Performance), "performance");
        assert_eq!(format!("{}", ClaimCategory::Correctness), "correctness");
        assert_eq!(format!("{}", ClaimCategory::Security), "security");
        assert_eq!(format!("{}", ClaimCategory::Compatibility), "compatibility");
        assert_eq!(format!("{}", ClaimCategory::Reliability), "reliability");
        assert_eq!(
            format!("{}", ClaimCategory::DeveloperExperience),
            "developer-experience"
        );
    }

    #[test]
    fn evidence_kind_display() {
        assert_eq!(format!("{}", EvidenceKind::TestResult), "test-result");
        assert_eq!(
            format!("{}", EvidenceKind::BenchmarkResult),
            "benchmark-result"
        );
        assert_eq!(format!("{}", EvidenceKind::SecurityAudit), "security-audit");
        assert_eq!(format!("{}", EvidenceKind::FormalProof), "formal-proof");
        assert_eq!(format!("{}", EvidenceKind::CodeReview), "code-review");
        assert_eq!(format!("{}", EvidenceKind::DemoReplay), "demo-replay");
        assert_eq!(
            format!("{}", EvidenceKind::ThirdPartyVerification),
            "third-party-verification"
        );
    }

    #[test]
    fn linkage_verdict_display() {
        assert_eq!(format!("{}", LinkageVerdict::Pass), "pass");
        assert_eq!(format!("{}", LinkageVerdict::Fail), "fail");
        assert_eq!(format!("{}", LinkageVerdict::Empty), "empty");
    }

    #[test]
    fn demo_display() {
        let demo = make_demo("d1", true);
        let display = format!("{}", demo);
        assert!(display.contains("d1"));
        assert!(display.contains("complete"));
    }

    #[test]
    fn demo_incomplete_display() {
        let demo = make_demo("d1", false);
        let display = format!("{}", demo);
        assert!(display.contains("incomplete"));
    }

    #[test]
    fn claim_display() {
        let claim = make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]);
        let display = format!("{}", claim);
        assert!(display.contains("c1"));
        assert!(display.contains("performance"));
    }

    #[test]
    fn decision_display() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let display = format!("{}", decision);
        assert!(display.contains("m1"));
        assert!(display.contains("pass"));
    }

    #[test]
    fn verification_command_display() {
        let cmd = make_command("cmd1");
        let display = format!("{}", cmd);
        assert!(display.contains("cmd1"));
    }

    #[test]
    fn evidence_link_display() {
        let ev = make_evidence("e1");
        let display = format!("{}", ev);
        assert!(display.contains("e1"));
    }

    #[test]
    fn error_display() {
        assert_eq!(
            format!("{}", LinkageGateError::NoClaims),
            "no claims provided"
        );
        assert!(
            format!(
                "{}",
                LinkageGateError::TooManyClaims {
                    count: 300,
                    max: 256
                }
            )
            .contains("300")
        );
        assert!(
            format!(
                "{}",
                LinkageGateError::UnknownDemo {
                    claim_id: "c1".to_string(),
                    demo_id: "x".to_string()
                }
            )
            .contains("x")
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err = LinkageGateError::NoClaims;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn serde_roundtrip_claim() {
        let claim = make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]);
        let json = serde_json::to_string(&claim).unwrap();
        let back: MilestoneClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, back);
    }

    #[test]
    fn serde_roundtrip_demo() {
        let demo = make_demo("d1", true);
        let json = serde_json::to_string(&demo).unwrap();
        let back: DemoSpecification = serde_json::from_str(&json).unwrap();
        assert_eq!(demo, back);
    }

    #[test]
    fn serde_roundtrip_decision() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        let back: LinkageGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn serde_roundtrip_config() {
        let config = LinkageGateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: LinkageGateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // ── Artifact Hash ───────────────────────────────────────────────

    #[test]
    fn artifact_hash_deterministic() {
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];

        let mut g1 = default_gate();
        let d1 = g1.evaluate("m1", &claims, &demos).unwrap();

        let mut g2 = default_gate();
        let d2 = g2.evaluate("m1", &claims, &demos).unwrap();

        assert_eq!(d1.artifact_hash, d2.artifact_hash);
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    #[test]
    fn config_accessor() {
        let gate = default_gate();
        assert_eq!(gate.config().min_completeness_millionths, MILLION);
    }

    #[test]
    fn config_default_values() {
        let config = LinkageGateConfig::default();
        assert_eq!(config.min_completeness_millionths, MILLION);
        assert!(config.require_runnable_demo);
        assert!(config.require_evidence);
        assert!(config.require_expected_outputs);
        assert!(config.require_verification_commands);
    }

    #[test]
    fn demo_is_complete() {
        let demo = make_demo("d1", true);
        assert!(demo.is_complete());

        let demo2 = make_demo("d2", false);
        assert!(!demo2.is_complete());
    }

    #[test]
    fn demo_command_count() {
        let demo = make_demo("d1", true);
        assert_eq!(demo.command_count(), 1);
    }

    #[test]
    fn linkage_rate_zero_claims() {
        let decision = LinkageGateDecision {
            decision_id: "test".to_string(),
            milestone_id: "m1".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            verdict: LinkageVerdict::Empty,
            claim_results: Vec::new(),
            total_claims: 0,
            linked_claims: 0,
            unlinked_claims: 0,
            aggregate_completeness_millionths: 0,
            rationale: "empty".to_string(),
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(decision.linkage_rate_millionths(), 0);
    }

    #[test]
    fn claim_with_multiple_demos() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true), make_demo("d2", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1", "d2"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    #[test]
    fn rationale_mentions_unlinked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec![], vec![]),
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert!(decision.rationale.contains("c2"));
    }

    #[test]
    fn pass_rationale_mentions_all_linked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert!(decision.rationale.contains("All"));
    }

    // ── Enrichment: Clone Equality ─────────────────────────────────

    #[test]
    fn clone_eq_demo_specification() {
        let demo = make_demo("d1", true);
        let cloned = demo.clone();
        assert_eq!(demo, cloned);
    }

    #[test]
    fn clone_eq_verification_command() {
        let cmd = make_command("cmd1");
        let cloned = cmd.clone();
        assert_eq!(cmd, cloned);
    }

    #[test]
    fn clone_eq_expected_output() {
        let out = make_output("out1");
        let cloned = out.clone();
        assert_eq!(out, cloned);
    }

    #[test]
    fn clone_eq_milestone_claim() {
        let claim = make_claim("c1", ClaimCategory::Correctness, vec!["d1"], vec!["e1"]);
        let cloned = claim.clone();
        assert_eq!(claim, cloned);
    }

    #[test]
    fn clone_eq_claim_linkage_result() {
        let result = ClaimLinkageResult {
            claim_id: "c1".to_string(),
            linked: true,
            has_runnable_demo: true,
            has_evidence: true,
            demos_have_outputs: true,
            demos_have_commands: true,
            missing: Vec::new(),
            completeness_millionths: MILLION,
        };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    // ── Enrichment: JSON Field Presence ────────────────────────────

    #[test]
    fn json_fields_demo_specification() {
        let demo = make_demo("d1", true);
        let json = serde_json::to_string(&demo).unwrap();
        assert!(json.contains("\"demo_id\""));
        assert!(json.contains("\"title\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"milestone_id\""));
        assert!(json.contains("\"runnable\""));
        assert!(json.contains("\"verification_commands\""));
        assert!(json.contains("\"expected_outputs\""));
        assert!(json.contains("\"tags\""));
    }

    #[test]
    fn json_fields_linkage_gate_decision() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"milestone_id\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"claim_results\""));
        assert!(json.contains("\"total_claims\""));
        assert!(json.contains("\"linked_claims\""));
        assert!(json.contains("\"unlinked_claims\""));
        assert!(json.contains("\"aggregate_completeness_millionths\""));
        assert!(json.contains("\"rationale\""));
        assert!(json.contains("\"artifact_hash\""));
    }

    #[test]
    fn json_fields_linkage_gate_config() {
        let config = LinkageGateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"min_completeness_millionths\""));
        assert!(json.contains("\"require_runnable_demo\""));
        assert!(json.contains("\"require_evidence\""));
        assert!(json.contains("\"require_expected_outputs\""));
        assert!(json.contains("\"require_verification_commands\""));
    }

    // ── Enrichment: Serde, Display, Boundary, Error ────────────────

    #[test]
    fn serde_roundtrip_error() {
        let err = LinkageGateError::TooManyEvidenceLinks {
            claim_id: "c1".to_string(),
            count: 100,
            max: 64,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: LinkageGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn display_uniqueness_all_claim_categories() {
        let categories = [
            ClaimCategory::Performance,
            ClaimCategory::Correctness,
            ClaimCategory::Security,
            ClaimCategory::Compatibility,
            ClaimCategory::Reliability,
            ClaimCategory::DeveloperExperience,
        ];
        let displays: BTreeSet<String> = categories.iter().map(|c| format!("{}", c)).collect();
        assert_eq!(displays.len(), categories.len());
    }

    #[test]
    fn zero_completeness_config_passes_any_claim() {
        let mut config = LinkageGateConfig {
            min_completeness_millionths: 0,
            ..Default::default()
        };
        config.require_runnable_demo = false;
        config.require_evidence = false;
        config.require_expected_outputs = false;
        config.require_verification_commands = false;
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();
        let claims = vec![make_claim("c1", ClaimCategory::Reliability, vec![], vec![])];
        let decision = gate.evaluate("m1", &claims, &[]).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
        assert_eq!(decision.aggregate_completeness_millionths, MILLION);
    }

    #[test]
    fn error_source_is_none() {
        let err = LinkageGateError::NoClaims;
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }
}
