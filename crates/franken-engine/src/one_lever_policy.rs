//! Deterministic one-lever performance policy gate for Section 10.6 (`bd-2l6`).
//!
//! This module enforces optimization hygiene:
//! - exactly one optimization lever per change unless explicitly overridden
//! - required baseline/after and semantic-equivalence evidence
//! - opportunity-score threshold (`>= 2.0`)
//! - rollback and post-merge re-profile readiness

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ONE_LEVER_POLICY_COMPONENT: &str = "one_lever_policy_gate";
pub const ONE_LEVER_POLICY_SCHEMA_VERSION: &str = "franken-engine.one-lever-policy.v1";
pub const ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS: i64 = 2_000_000; // 2.0

pub const ERROR_INVALID_REQUEST: &str = "FE-1LEV-1001";
pub const ERROR_MULTI_LEVER_VIOLATION: &str = "FE-1LEV-1002";
pub const ERROR_MISSING_EVIDENCE: &str = "FE-1LEV-1003";
pub const ERROR_SCORE_BELOW_THRESHOLD: &str = "FE-1LEV-1004";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeverCategory {
    Execution,
    Memory,
    Security,
    Benchmark,
    Config,
}

impl LeverCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Memory => "memory",
            Self::Security => "security",
            Self::Benchmark => "benchmark",
            Self::Config => "config",
        }
    }
}

impl fmt::Display for LeverCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OneLeverEvidenceRefs {
    pub baseline_benchmark_run_id: Option<String>,
    pub post_change_benchmark_run_id: Option<String>,
    pub delta_report_ref: Option<String>,
    pub semantic_equivalence_ref: Option<String>,
    pub trace_replay_ref: Option<String>,
    pub isomorphism_ledger_ref: Option<String>,
    pub rollback_instructions_ref: Option<String>,
    pub reprofile_after_merge_ref: Option<String>,
    pub opportunity_score_millionths: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneLeverPolicyRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub commit_sha: String,
    pub commit_message: String,
    pub changed_paths: Vec<String>,
    pub evidence: OneLeverEvidenceRefs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathLeverClassification {
    pub path: String,
    pub category: Option<LeverCategory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneLeverPolicyEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub change_id: Option<String>,
    pub path: Option<String>,
    pub lever_category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneLeverPolicyDecision {
    pub schema_version: String,
    pub change_id: Option<String>,
    pub outcome: String,
    pub blocked: bool,
    pub error_code: Option<String>,
    pub optimization_change: bool,
    pub is_multi_lever: bool,
    pub override_reason: Option<String>,
    pub lever_categories: Vec<LeverCategory>,
    pub lever_classification: Vec<PathLeverClassification>,
    pub missing_requirements: Vec<String>,
    pub opportunity_score_millionths: Option<i64>,
    pub score_threshold_millionths: i64,
    pub events: Vec<OneLeverPolicyEvent>,
}

impl OneLeverPolicyDecision {
    pub fn allows_change(&self) -> bool {
        self.outcome == "allow"
    }
}

#[derive(Debug)]
struct EvaluationContext {
    lever_classification: Vec<PathLeverClassification>,
    lever_categories: Vec<LeverCategory>,
    optimization_change: bool,
    is_multi_lever: bool,
    override_reason: Option<String>,
    missing_requirements: Vec<String>,
    opportunity_score_millionths: Option<i64>,
}

/// Evaluate one-lever performance policy constraints for a change.
pub fn evaluate_one_lever_policy(request: &OneLeverPolicyRequest) -> OneLeverPolicyDecision {
    let mut normalized = request.clone();
    normalize_request(&mut normalized);

    let mut events = vec![make_event(
        &normalized,
        "one_lever_policy_started",
        "pass",
        None,
        None,
        None,
        None,
    )];

    if let Some(validation_error) = validate_request(&normalized) {
        events.push(make_event(
            &normalized,
            "one_lever_policy_completed",
            "fail",
            Some(ERROR_INVALID_REQUEST.to_string()),
            None,
            None,
            None,
        ));

        return OneLeverPolicyDecision {
            schema_version: ONE_LEVER_POLICY_SCHEMA_VERSION.to_string(),
            change_id: None,
            outcome: "fail".to_string(),
            blocked: true,
            error_code: Some(ERROR_INVALID_REQUEST.to_string()),
            optimization_change: false,
            is_multi_lever: false,
            override_reason: None,
            lever_categories: Vec::new(),
            lever_classification: Vec::new(),
            missing_requirements: vec![validation_error],
            opportunity_score_millionths: None,
            score_threshold_millionths: ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS,
            events,
        };
    }

    let change_id = build_change_id(&normalized);
    let eval = evaluate_policy(&normalized);

    for path in &eval.lever_classification {
        events.push(make_event(
            &normalized,
            "changed_path_classified",
            "pass",
            None,
            Some(change_id.clone()),
            Some(path.path.clone()),
            path.category.map(|c| c.to_string()),
        ));
    }

    let mut error_code = None;
    let outcome = if eval.is_multi_lever && eval.override_reason.is_none() {
        error_code = Some(ERROR_MULTI_LEVER_VIOLATION.to_string());
        "deny"
    } else if !eval.missing_requirements.is_empty() {
        error_code = Some(ERROR_MISSING_EVIDENCE.to_string());
        "deny"
    } else if let Some(score) = eval.opportunity_score_millionths {
        if eval.optimization_change && score < ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS {
            error_code = Some(ERROR_SCORE_BELOW_THRESHOLD.to_string());
            "deny"
        } else {
            "allow"
        }
    } else if eval.optimization_change {
        error_code = Some(ERROR_MISSING_EVIDENCE.to_string());
        "deny"
    } else {
        "allow"
    };

    events.push(make_event(
        &normalized,
        "one_lever_policy_completed",
        outcome,
        error_code.clone(),
        Some(change_id.clone()),
        None,
        None,
    ));

    OneLeverPolicyDecision {
        schema_version: ONE_LEVER_POLICY_SCHEMA_VERSION.to_string(),
        change_id: Some(change_id),
        outcome: outcome.to_string(),
        blocked: outcome != "allow",
        error_code,
        optimization_change: eval.optimization_change,
        is_multi_lever: eval.is_multi_lever,
        override_reason: eval.override_reason,
        lever_categories: eval.lever_categories,
        lever_classification: eval.lever_classification,
        missing_requirements: eval.missing_requirements,
        opportunity_score_millionths: eval.opportunity_score_millionths,
        score_threshold_millionths: ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS,
        events,
    }
}

fn evaluate_policy(request: &OneLeverPolicyRequest) -> EvaluationContext {
    let mut classification = request
        .changed_paths
        .iter()
        .map(|path| PathLeverClassification {
            path: path.clone(),
            category: classify_changed_path(path),
        })
        .collect::<Vec<_>>();

    classification.sort_by(|left, right| left.path.cmp(&right.path));

    let mut categories = classification
        .iter()
        .filter_map(|entry| entry.category)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    categories.sort();

    let optimization_change = !categories.is_empty();
    let is_multi_lever = categories.len() > 1;
    let override_reason = if is_multi_lever {
        extract_override_reason(&request.commit_message)
    } else {
        None
    };

    let mut missing_requirements = Vec::new();
    if optimization_change {
        if request.evidence.baseline_benchmark_run_id.is_none() {
            missing_requirements.push("baseline_benchmark_run_id".to_string());
        }
        if request.evidence.post_change_benchmark_run_id.is_none() {
            missing_requirements.push("post_change_benchmark_run_id".to_string());
        }
        if request.evidence.delta_report_ref.is_none() {
            missing_requirements.push("delta_report_ref".to_string());
        }
        if request.evidence.semantic_equivalence_ref.is_none() {
            missing_requirements.push("semantic_equivalence_ref".to_string());
        }
        if request.evidence.trace_replay_ref.is_none() {
            missing_requirements.push("trace_replay_ref".to_string());
        }
        if request.evidence.isomorphism_ledger_ref.is_none() {
            missing_requirements.push("isomorphism_ledger_ref".to_string());
        }
        if request.evidence.rollback_instructions_ref.is_none() {
            missing_requirements.push("rollback_instructions_ref".to_string());
        }
        if request.evidence.reprofile_after_merge_ref.is_none() {
            missing_requirements.push("reprofile_after_merge_ref".to_string());
        }
        if request.evidence.opportunity_score_millionths.is_none() {
            missing_requirements.push("opportunity_score_millionths".to_string());
        }
    }

    EvaluationContext {
        lever_classification: classification,
        lever_categories: categories,
        optimization_change,
        is_multi_lever,
        override_reason,
        missing_requirements,
        opportunity_score_millionths: request.evidence.opportunity_score_millionths,
    }
}

fn validate_request(request: &OneLeverPolicyRequest) -> Option<String> {
    if request.trace_id.is_empty() {
        return Some("trace_id must not be empty".to_string());
    }
    if request.decision_id.is_empty() {
        return Some("decision_id must not be empty".to_string());
    }
    if request.policy_id.is_empty() {
        return Some("policy_id must not be empty".to_string());
    }
    if request.commit_sha.is_empty() {
        return Some("commit_sha must not be empty".to_string());
    }
    if request.changed_paths.is_empty() {
        return Some("changed_paths must include at least one path".to_string());
    }
    None
}

fn make_event(
    request: &OneLeverPolicyRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    change_id: Option<String>,
    path: Option<String>,
    lever_category: Option<String>,
) -> OneLeverPolicyEvent {
    OneLeverPolicyEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: ONE_LEVER_POLICY_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        change_id,
        path,
        lever_category,
    }
}

fn normalize_request(request: &mut OneLeverPolicyRequest) {
    request.trace_id = request.trace_id.trim().to_string();
    request.decision_id = request.decision_id.trim().to_string();
    request.policy_id = request.policy_id.trim().to_string();
    request.commit_sha = request.commit_sha.trim().to_string();
    request.commit_message = request.commit_message.trim().to_string();

    request.changed_paths = request
        .changed_paths
        .iter()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    normalize_opt_field(&mut request.evidence.baseline_benchmark_run_id);
    normalize_opt_field(&mut request.evidence.post_change_benchmark_run_id);
    normalize_opt_field(&mut request.evidence.delta_report_ref);
    normalize_opt_field(&mut request.evidence.semantic_equivalence_ref);
    normalize_opt_field(&mut request.evidence.trace_replay_ref);
    normalize_opt_field(&mut request.evidence.isomorphism_ledger_ref);
    normalize_opt_field(&mut request.evidence.rollback_instructions_ref);
    normalize_opt_field(&mut request.evidence.reprofile_after_merge_ref);
}

fn normalize_opt_field(field: &mut Option<String>) {
    let Some(value) = field.as_ref() else {
        return;
    };
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        *field = None;
    } else {
        *field = Some(normalized);
    }
}

fn classify_changed_path(path: &str) -> Option<LeverCategory> {
    let lower = path.to_ascii_lowercase();

    if lower.starts_with("docs/")
        || lower.starts_with("artifacts/")
        || lower.starts_with(".beads/")
        || lower.starts_with(".github/workflows/")
        || lower.ends_with(".md")
        || lower.ends_with("/readme")
        || lower.contains("/tests/")
        || lower.starts_with("scripts/check_")
        || lower.contains("workflow")
    {
        return None;
    }

    if lower.starts_with("scripts/") {
        if lower.contains("benchmark")
            || lower.contains("flamegraph")
            || lower.contains("performance")
            || lower.contains("opportunity")
        {
            return Some(LeverCategory::Benchmark);
        }
        return None;
    }

    if lower.contains("benchmark")
        || lower.contains("flamegraph")
        || lower.contains("opportunity")
        || lower.contains("performance")
    {
        return Some(LeverCategory::Benchmark);
    }

    if lower.contains("gc")
        || lower.contains("alloc")
        || lower.contains("memory")
        || lower.contains("heap")
    {
        return Some(LeverCategory::Memory);
    }

    if lower.contains("policy")
        || lower.contains("guard")
        || lower.contains("security")
        || lower.contains("ifc")
        || lower.contains("capability")
        || lower.contains("revocation")
        || lower.contains("quarantine")
        || lower.contains("attestation")
        || lower.contains("declassification")
    {
        return Some(LeverCategory::Security);
    }

    if lower.ends_with(".toml")
        || lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".ron")
    {
        return Some(LeverCategory::Config);
    }

    if lower.starts_with("crates/franken-engine/src/")
        || lower.starts_with("crates/franken-extension-host/src/")
        || lower.contains("parser")
        || lower.contains("interpreter")
        || lower.contains("ir_")
        || lower.contains("execution")
        || lower.contains("scheduler")
        || lower.contains("object_model")
    {
        return Some(LeverCategory::Execution);
    }

    None
}

fn extract_override_reason(commit_message: &str) -> Option<String> {
    let lowered = commit_message.to_ascii_lowercase();
    let marker = "[multi-lever:";
    let start = lowered.find(marker)? + marker.len();
    let end = lowered[start..].find(']')? + start;
    let reason = commit_message.get(start..end)?.trim();
    if reason.is_empty() {
        None
    } else {
        Some(reason.to_string())
    }
}

fn build_change_id(request: &OneLeverPolicyRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.trace_id.as_bytes());
    hasher.update(request.decision_id.as_bytes());
    hasher.update(request.policy_id.as_bytes());
    hasher.update(request.commit_sha.as_bytes());
    hasher.update(request.commit_message.as_bytes());

    for path in &request.changed_paths {
        hasher.update(path.as_bytes());
    }

    hash_optional_field(&mut hasher, &request.evidence.baseline_benchmark_run_id);
    hash_optional_field(&mut hasher, &request.evidence.post_change_benchmark_run_id);
    hash_optional_field(&mut hasher, &request.evidence.delta_report_ref);
    hash_optional_field(&mut hasher, &request.evidence.semantic_equivalence_ref);
    hash_optional_field(&mut hasher, &request.evidence.trace_replay_ref);
    hash_optional_field(&mut hasher, &request.evidence.isomorphism_ledger_ref);
    hash_optional_field(&mut hasher, &request.evidence.rollback_instructions_ref);
    hash_optional_field(&mut hasher, &request.evidence.reprofile_after_merge_ref);

    if let Some(score) = request.evidence.opportunity_score_millionths {
        hasher.update(score.to_le_bytes());
    }

    format!("olp-{:x}", hasher.finalize())
}

fn hash_optional_field(hasher: &mut Sha256, field: &Option<String>) {
    if let Some(value) = field {
        hasher.update(value.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_docs_and_tests_as_exempt() {
        assert_eq!(classify_changed_path("docs/design.md"), None);
        assert_eq!(
            classify_changed_path("crates/franken-engine/tests/one_lever_policy.rs"),
            None
        );
    }

    #[test]
    fn classify_execution_memory_security_benchmark() {
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/baseline_interpreter.rs"),
            Some(LeverCategory::Execution)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/gc_pause.rs"),
            Some(LeverCategory::Memory)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/policy_controller.rs"),
            Some(LeverCategory::Security)
        );
        assert_eq!(
            classify_changed_path("crates/franken-engine/src/opportunity_matrix.rs"),
            Some(LeverCategory::Benchmark)
        );
    }

    #[test]
    fn extract_override_reason_parses_tag() {
        let message = "perf: coupled fix [multi-lever: scheduler and gc are inseparable]";
        assert_eq!(
            extract_override_reason(message),
            Some("scheduler and gc are inseparable".to_string())
        );
        assert_eq!(extract_override_reason("perf: single lever"), None);
    }
}
