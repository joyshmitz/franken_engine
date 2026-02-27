use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::relation::{
    GeneratedPair, MetamorphicRelation, OracleKind, RelationRunOutcome, Subsystem,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub seed: u64,
    pub environment_fingerprint: String,
}

impl RunContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        component: impl Into<String>,
        relation_catalog_hash: impl Into<String>,
        seed: u64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            component: component.into(),
            relation_catalog_hash: relation_catalog_hash.into(),
            seed,
            environment_fingerprint: environment_fingerprint(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimizerConfig {
    pub max_iterations: usize,
    pub max_duration: Duration,
    pub target_ast_nodes: usize,
}

impl Default for MinimizerConfig {
    fn default() -> Self {
        Self {
            max_iterations: 256,
            max_duration: Duration::from_secs(60),
            target_ast_nodes: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureArtifact {
    pub relation_id: String,
    pub seed: u64,
    pub input_source: String,
    pub variant_source: String,
    pub expected_equivalence: String,
    pub actual_divergence: String,
    pub minimized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationExecution {
    pub relation_id: String,
    pub subsystem: Subsystem,
    pub oracle: OracleKind,
    pub pairs_tested: u32,
    pub violations_found: u32,
    pub min_failure_size: Option<usize>,
    pub duration_us: u64,
    pub outcomes: Vec<RelationRunOutcome>,
    pub failure_files: Vec<String>,
    pub log_event: RelationLogEvent,
}

impl RelationExecution {
    pub fn outcome(&self) -> &'static str {
        if self.violations_found == 0 {
            "pass"
        } else {
            "fail"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: String,
    pub pairs_tested: u32,
    pub violations_found: u32,
    pub min_failure_size: Option<usize>,
    pub duration_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteExecution {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub relation_catalog_hash: String,
    pub environment_fingerprint: String,
    pub seed: u64,
    pub total_pairs: u32,
    pub total_violations: u32,
    pub relation_executions: Vec<RelationExecution>,
}

impl SuiteExecution {
    pub fn outcome(&self) -> &'static str {
        if self.total_violations == 0 {
            "pass"
        } else {
            "fail"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationEvidenceEntry {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: String,
    pub oracle: String,
    pub pairs_tested: u32,
    pub violations_found: u32,
    pub min_failure_size: Option<usize>,
    pub duration_us: u64,
    pub relation_catalog_hash: String,
    pub seed: u64,
    pub total_violations: Option<u32>,
    pub environment_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedTranscriptEntry {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: String,
    pub pair_index: u32,
    pub run_seed: u64,
}

impl RelationEvidenceEntry {
    pub fn from_execution(execution: &RelationExecution, context: &RunContext) -> Self {
        Self {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: context.component.clone(),
            event: "relation_completed".to_string(),
            outcome: execution.outcome().to_string(),
            error_code: if execution.violations_found == 0 {
                None
            } else {
                Some("FE-META-0001".to_string())
            },
            relation_id: execution.relation_id.clone(),
            subsystem: execution.subsystem.as_str().to_string(),
            oracle: execution.oracle.as_str().to_string(),
            pairs_tested: execution.pairs_tested,
            violations_found: execution.violations_found,
            min_failure_size: execution.min_failure_size,
            duration_us: execution.duration_us,
            relation_catalog_hash: context.relation_catalog_hash.clone(),
            seed: context.seed,
            total_violations: None,
            environment_fingerprint: context.environment_fingerprint.clone(),
        }
    }

    pub fn summary_from_suite(suite: &SuiteExecution) -> Self {
        Self {
            trace_id: suite.trace_id.clone(),
            decision_id: suite.decision_id.clone(),
            policy_id: suite.policy_id.clone(),
            component: suite.component.clone(),
            event: "suite_summary".to_string(),
            outcome: suite.outcome().to_string(),
            error_code: if suite.total_violations == 0 {
                None
            } else {
                Some("FE-META-0001".to_string())
            },
            relation_id: "__summary__".to_string(),
            subsystem: "all".to_string(),
            oracle: "all".to_string(),
            pairs_tested: suite.total_pairs,
            violations_found: suite.total_violations,
            min_failure_size: suite
                .relation_executions
                .iter()
                .filter_map(|entry| entry.min_failure_size)
                .min(),
            duration_us: suite
                .relation_executions
                .iter()
                .map(|entry| entry.duration_us)
                .sum(),
            relation_catalog_hash: suite.relation_catalog_hash.clone(),
            seed: suite.seed,
            total_violations: Some(suite.total_violations),
            environment_fingerprint: suite.environment_fingerprint.clone(),
        }
    }
}

pub fn run_relation_with_budget(
    relation: &dyn MetamorphicRelation,
    context: &RunContext,
    pairs: u32,
    failure_output_dir: Option<&Path>,
    minimizer: MinimizerConfig,
) -> std::io::Result<RelationExecution> {
    let start = Instant::now();
    let mut outcomes = Vec::with_capacity(pairs as usize);
    let mut violations_found = 0u32;
    let mut min_failure_size = None::<usize>;
    let mut failure_files = Vec::<String>::new();

    if let Some(path) = failure_output_dir {
        fs::create_dir_all(path)?;
    }

    for offset in 0..pairs {
        let run_seed = context.seed.wrapping_add(u64::from(offset));
        let outcome = relation.run_once(
            &context.trace_id,
            &context.decision_id,
            &context.policy_id,
            &context.component,
            run_seed,
        );

        if !outcome.equivalence.is_equivalent() {
            violations_found = violations_found.saturating_add(1);
            let minimized_pair = minimize_failure_pair(relation, &outcome.pair, minimizer);
            let minimized = minimized_pair.size_metric() < outcome.pair.size_metric();
            let pair_size = minimized_pair.ast_node_metric();
            min_failure_size = Some(match min_failure_size {
                Some(existing) => existing.min(pair_size),
                None => pair_size,
            });

            if let Some(path) = failure_output_dir {
                let artifact = FailureArtifact {
                    relation_id: relation.spec().id.clone(),
                    seed: run_seed,
                    input_source: minimized_pair.input_source.clone(),
                    variant_source: minimized_pair.variant_source.clone(),
                    expected_equivalence: "equivalent".to_string(),
                    actual_divergence: outcome
                        .equivalence
                        .detail()
                        .unwrap_or("unknown divergence")
                        .to_string(),
                    minimized,
                };

                let file = write_failure_artifact(path, &artifact)?;
                failure_files.push(file.display().to_string());
            }
        }

        outcomes.push(outcome);
    }

    let duration_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let log_event = RelationLogEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: context.component.clone(),
        event: "relation_completed".to_string(),
        outcome: if violations_found == 0 {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if violations_found == 0 {
            None
        } else {
            Some("FE-META-0001".to_string())
        },
        relation_id: relation.spec().id.clone(),
        subsystem: relation.spec().subsystem.as_str().to_string(),
        pairs_tested: pairs,
        violations_found,
        min_failure_size,
        duration_us,
    };

    Ok(RelationExecution {
        relation_id: relation.spec().id.clone(),
        subsystem: relation.spec().subsystem,
        oracle: relation.spec().oracle,
        pairs_tested: pairs,
        violations_found,
        min_failure_size,
        duration_us,
        outcomes,
        failure_files,
        log_event,
    })
}

pub fn run_suite(
    relations: &[&dyn MetamorphicRelation],
    context: &RunContext,
    pairs_override: Option<u32>,
    failure_output_dir: Option<&Path>,
    minimizer: MinimizerConfig,
) -> std::io::Result<SuiteExecution> {
    let mut relation_executions = Vec::with_capacity(relations.len());
    let mut total_pairs = 0u32;
    let mut total_violations = 0u32;

    for relation in relations {
        let budget = pairs_override.unwrap_or(relation.spec().budget_pairs);
        let relation_execution =
            run_relation_with_budget(*relation, context, budget, failure_output_dir, minimizer)?;

        total_pairs = total_pairs.saturating_add(relation_execution.pairs_tested);
        total_violations = total_violations.saturating_add(relation_execution.violations_found);
        relation_executions.push(relation_execution);
    }

    Ok(SuiteExecution {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: context.component.clone(),
        relation_catalog_hash: context.relation_catalog_hash.clone(),
        environment_fingerprint: context.environment_fingerprint.clone(),
        seed: context.seed,
        total_pairs,
        total_violations,
        relation_executions,
    })
}

pub fn write_evidence_jsonl(path: &Path, entries: &[RelationEvidenceEntry]) -> std::io::Result<()> {
    let mut lines = String::new();
    for entry in entries {
        let json =
            serde_json::to_string(entry).expect("evidence entry serialization should succeed");
        lines.push_str(&json);
        lines.push('\n');
    }
    fs::write(path, lines)
}

pub fn evidence_entries_for_suite(suite: &SuiteExecution) -> Vec<RelationEvidenceEntry> {
    let base_context = RunContext {
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        relation_catalog_hash: suite.relation_catalog_hash.clone(),
        seed: suite.seed,
        environment_fingerprint: suite.environment_fingerprint.clone(),
    };

    let mut entries = suite
        .relation_executions
        .iter()
        .map(|execution| RelationEvidenceEntry::from_execution(execution, &base_context))
        .collect::<Vec<_>>();
    entries.push(RelationEvidenceEntry::summary_from_suite(suite));
    entries
}

pub fn relation_log_events_for_suite(suite: &SuiteExecution) -> Vec<RelationLogEvent> {
    let mut events = suite
        .relation_executions
        .iter()
        .map(|execution| execution.log_event.clone())
        .collect::<Vec<_>>();

    events.push(RelationLogEvent {
        trace_id: suite.trace_id.clone(),
        decision_id: suite.decision_id.clone(),
        policy_id: suite.policy_id.clone(),
        component: suite.component.clone(),
        event: "suite_completed".to_string(),
        outcome: suite.outcome().to_string(),
        error_code: if suite.total_violations == 0 {
            None
        } else {
            Some("FE-META-0001".to_string())
        },
        relation_id: "__summary__".to_string(),
        subsystem: "all".to_string(),
        pairs_tested: suite.total_pairs,
        violations_found: suite.total_violations,
        min_failure_size: suite
            .relation_executions
            .iter()
            .filter_map(|entry| entry.min_failure_size)
            .min(),
        duration_us: suite
            .relation_executions
            .iter()
            .map(|entry| entry.duration_us)
            .sum(),
    });

    events
}

pub fn seed_transcript_entries_for_suite(suite: &SuiteExecution) -> Vec<SeedTranscriptEntry> {
    suite
        .relation_executions
        .iter()
        .flat_map(|execution| {
            execution
                .outcomes
                .iter()
                .enumerate()
                .map(|(pair_index, outcome)| SeedTranscriptEntry {
                    trace_id: outcome.trace_id.clone(),
                    decision_id: outcome.decision_id.clone(),
                    policy_id: outcome.policy_id.clone(),
                    component: outcome.component.clone(),
                    event: "pair_seed_evaluated".to_string(),
                    outcome: outcome.outcome.clone(),
                    error_code: outcome.error_code.clone(),
                    relation_id: execution.relation_id.clone(),
                    subsystem: execution.subsystem.as_str().to_string(),
                    pair_index: pair_index as u32,
                    run_seed: outcome.seed,
                })
        })
        .collect()
}

pub fn write_seed_transcript_jsonl(
    path: &Path,
    entries: &[SeedTranscriptEntry],
) -> std::io::Result<()> {
    let mut lines = String::new();
    for entry in entries {
        let json = serde_json::to_string(entry).expect("seed transcript serialization should pass");
        lines.push_str(&json);
        lines.push('\n');
    }

    fs::write(path, lines)
}

pub fn minimize_failure_pair(
    relation: &dyn MetamorphicRelation,
    pair: &GeneratedPair,
    config: MinimizerConfig,
) -> GeneratedPair {
    if relation.oracle(pair).is_equivalent() {
        return pair.clone();
    }

    let start = Instant::now();
    let mut best = pair.clone();

    best.input_source =
        ddmin_reduce_tokens(&best.input_source, config, start, &mut |candidate_input| {
            if !relation.validate_program(candidate_input) {
                return false;
            }

            let candidate_pair = GeneratedPair {
                input_source: candidate_input.to_string(),
                variant_source: best.variant_source.clone(),
            };

            if !relation.validate_program(&candidate_pair.variant_source) {
                return false;
            }

            !relation.oracle(&candidate_pair).is_equivalent()
        });

    best.input_source = ddmin_reduce(&best.input_source, config, start, &mut |candidate_input| {
        if !relation.validate_program(candidate_input) {
            return false;
        }

        let candidate_pair = GeneratedPair {
            input_source: candidate_input.to_string(),
            variant_source: best.variant_source.clone(),
        };

        if !relation.validate_program(&candidate_pair.variant_source) {
            return false;
        }

        !relation.oracle(&candidate_pair).is_equivalent()
    });

    best.variant_source = ddmin_reduce_tokens(
        &best.variant_source,
        config,
        start,
        &mut |candidate_variant| {
            if !relation.validate_program(candidate_variant) {
                return false;
            }

            let candidate_pair = GeneratedPair {
                input_source: best.input_source.clone(),
                variant_source: candidate_variant.to_string(),
            };

            if !relation.validate_program(&candidate_pair.input_source) {
                return false;
            }

            !relation.oracle(&candidate_pair).is_equivalent()
        },
    );

    best.variant_source = ddmin_reduce(
        &best.variant_source,
        config,
        start,
        &mut |candidate_variant| {
            if !relation.validate_program(candidate_variant) {
                return false;
            }

            let candidate_pair = GeneratedPair {
                input_source: best.input_source.clone(),
                variant_source: candidate_variant.to_string(),
            };

            if !relation.validate_program(&candidate_pair.input_source) {
                return false;
            }

            !relation.oracle(&candidate_pair).is_equivalent()
        },
    );

    best = trim_pair_to_target(relation, best, config, start);

    if relation.oracle(&best).is_equivalent() {
        pair.clone()
    } else {
        best
    }
}

fn trim_pair_to_target(
    relation: &dyn MetamorphicRelation,
    mut pair: GeneratedPair,
    config: MinimizerConfig,
    start: Instant,
) -> GeneratedPair {
    while pair.ast_node_metric() > config.target_ast_nodes && start.elapsed() <= config.max_duration
    {
        let mut improved = false;
        let input_tokens = pair
            .input_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let variant_tokens = pair
            .variant_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        let input_first = input_tokens.len() >= variant_tokens.len();
        let sides = if input_first {
            [Side::Input, Side::Variant]
        } else {
            [Side::Variant, Side::Input]
        };

        for side in sides {
            let tokens = match side {
                Side::Input => &input_tokens,
                Side::Variant => &variant_tokens,
            };

            if tokens.len() <= 1 {
                continue;
            }

            for index in 0..tokens.len() {
                let candidate_tokens = tokens
                    .iter()
                    .take(index)
                    .chain(tokens.iter().skip(index + 1))
                    .cloned()
                    .collect::<Vec<_>>();
                let candidate_source = candidate_tokens.join(" ");
                if candidate_source.trim().is_empty() {
                    continue;
                }

                let candidate_pair = match side {
                    Side::Input => GeneratedPair {
                        input_source: candidate_source,
                        variant_source: pair.variant_source.clone(),
                    },
                    Side::Variant => GeneratedPair {
                        input_source: pair.input_source.clone(),
                        variant_source: candidate_source,
                    },
                };

                if !relation.validate_program(&candidate_pair.input_source)
                    || !relation.validate_program(&candidate_pair.variant_source)
                {
                    continue;
                }

                if relation.oracle(&candidate_pair).is_equivalent() {
                    continue;
                }

                pair = candidate_pair;
                improved = true;
                break;
            }

            if improved {
                break;
            }
        }

        if !improved {
            break;
        }
    }

    pair
}

#[derive(Clone, Copy)]
enum Side {
    Input,
    Variant,
}

fn ddmin_reduce_tokens(
    input: &str,
    config: MinimizerConfig,
    start: Instant,
    predicate: &mut dyn FnMut(&str) -> bool,
) -> String {
    let mut tokens = input
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if tokens.len() <= 1 {
        return input.to_string();
    }

    let mut granularity = 2usize;
    let mut iterations = 0usize;

    while tokens.len() > 1
        && iterations < config.max_iterations
        && start.elapsed() <= config.max_duration
    {
        let length = tokens.len();
        let chunk_size = length.div_ceil(granularity);
        let mut reduced = false;

        for chunk in 0..granularity {
            let begin = chunk * chunk_size;
            if begin >= length {
                break;
            }
            let end = (begin + chunk_size).min(length);

            let candidate_tokens = tokens
                .iter()
                .take(begin)
                .chain(tokens.iter().skip(end))
                .cloned()
                .collect::<Vec<_>>();

            if candidate_tokens.is_empty() {
                continue;
            }

            let candidate = candidate_tokens.join(" ");
            if !predicate(&candidate) {
                continue;
            }

            tokens = candidate_tokens;
            reduced = true;
            break;
        }

        iterations = iterations.saturating_add(1);

        if tokens.len() <= config.target_ast_nodes {
            break;
        }

        if reduced {
            granularity = granularity.saturating_sub(1).max(2);
        } else if granularity >= length {
            break;
        } else {
            granularity = (granularity * 2).min(length);
        }
    }

    tokens.join(" ")
}

fn ddmin_reduce(
    input: &str,
    config: MinimizerConfig,
    start: Instant,
    predicate: &mut dyn FnMut(&str) -> bool,
) -> String {
    let mut best = input.to_string();
    let mut granularity = 2usize;
    let mut iterations = 0usize;

    while best.chars().count() > 1
        && iterations < config.max_iterations
        && start.elapsed() <= config.max_duration
    {
        let chars = best.chars().collect::<Vec<_>>();
        let length = chars.len();
        let chunk_size = length.div_ceil(granularity);
        let mut reduced = false;

        for chunk in 0..granularity {
            let begin = chunk * chunk_size;
            if begin >= length {
                break;
            }
            let end = (begin + chunk_size).min(length);

            let candidate = chars
                .iter()
                .take(begin)
                .chain(chars.iter().skip(end))
                .copied()
                .collect::<String>();

            if candidate.trim().is_empty() {
                continue;
            }

            if !predicate(&candidate) {
                continue;
            }

            best = candidate;
            reduced = true;
            break;
        }

        iterations = iterations.saturating_add(1);

        if best
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .count()
            <= config.target_ast_nodes
        {
            break;
        }

        if reduced {
            granularity = granularity.saturating_sub(1).max(2);
        } else if granularity >= length {
            break;
        } else {
            granularity = (granularity * 2).min(length);
        }
    }

    best
}

fn write_failure_artifact(path: &Path, artifact: &FailureArtifact) -> std::io::Result<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(artifact.relation_id.as_bytes());
    hasher.update(artifact.seed.to_le_bytes());
    hasher.update(artifact.input_source.as_bytes());
    hasher.update(artifact.variant_source.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let short_hash = &digest[..12];
    let file_name = format!(
        "metamorphic_failure_{}_{}.json",
        sanitize_relation_id(&artifact.relation_id),
        short_hash
    );

    let path = path.join(file_name);
    let payload =
        serde_json::to_vec_pretty(artifact).expect("failure artifact serialization should succeed");
    fs::write(&path, payload)?;
    Ok(path)
}

fn sanitize_relation_id(relation_id: &str) -> String {
    relation_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

pub fn environment_fingerprint() -> String {
    let toolchain = std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string());
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "default".to_string());

    format!(
        "os={} arch={} family={} toolchain={} target_dir={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY,
        toolchain,
        target_dir
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::catalog::RelationCatalog;
    use crate::relation::{
        Equivalence, GeneratedPair, MetamorphicRelation, OracleKind, RelationSpec, Subsystem,
    };
    use crate::{build_enabled_relations, build_relation};

    use super::{
        evidence_entries_for_suite, minimize_failure_pair, relation_log_events_for_suite,
        run_relation_with_budget, run_suite, seed_transcript_entries_for_suite, MinimizerConfig,
        RelationEvidenceEntry, RunContext,
    };

    struct AlwaysPassRelation {
        spec: RelationSpec,
    }

    impl MetamorphicRelation for AlwaysPassRelation {
        fn spec(&self) -> &RelationSpec {
            &self.spec
        }

        fn generate_pair(&self, seed: u64) -> GeneratedPair {
            GeneratedPair {
                input_source: format!("let alpha = {seed} + 1; return alpha;"),
                variant_source: format!("let alpha = {seed} + 1; return alpha;"),
            }
        }

        fn oracle(&self, _pair: &GeneratedPair) -> Equivalence {
            Equivalence::Equivalent
        }

        fn validate_program(&self, source: &str) -> bool {
            !source.trim().is_empty()
        }
    }

    struct SyntheticViolationRelation {
        spec: RelationSpec,
    }

    impl MetamorphicRelation for SyntheticViolationRelation {
        fn spec(&self) -> &RelationSpec {
            &self.spec
        }

        fn generate_pair(&self, _seed: u64) -> GeneratedPair {
            let mut input_tokens = Vec::new();
            let mut variant_tokens = Vec::new();
            for index in 0..80 {
                input_tokens.push(format!("node_{index}"));
                variant_tokens.push(format!("node_{index}"));
            }
            variant_tokens.push("bad".to_string());

            GeneratedPair {
                input_source: input_tokens.join(" "),
                variant_source: variant_tokens.join(" "),
            }
        }

        fn oracle(&self, pair: &GeneratedPair) -> Equivalence {
            if pair.variant_source.contains("bad") {
                Equivalence::Diverged {
                    detail: "synthetic divergence".to_string(),
                }
            } else {
                Equivalence::Equivalent
            }
        }

        fn validate_program(&self, source: &str) -> bool {
            !source.trim().is_empty()
        }
    }

    fn test_context() -> RunContext {
        RunContext::new(
            "trace-test",
            "decision-test",
            "policy-test",
            "metamorphic_suite",
            "sha256:test",
            7,
        )
    }

    #[test]
    fn budget_is_enforced_exactly() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "test_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "test".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 10,
                enabled: true,
            },
        };

        let execution = run_relation_with_budget(
            &relation,
            &test_context(),
            10,
            None,
            MinimizerConfig::default(),
        )
        .expect("relation should execute");

        assert_eq!(execution.pairs_tested, 10);
        assert_eq!(execution.outcomes.len(), 10);
        assert_eq!(execution.violations_found, 0);
    }

    #[test]
    fn evidence_marks_failure_with_error_code() {
        let execution = super::RelationExecution {
            relation_id: "r".to_string(),
            subsystem: Subsystem::Ir,
            oracle: OracleKind::IrEquality,
            pairs_tested: 3,
            violations_found: 1,
            min_failure_size: Some(5),
            duration_us: 100,
            outcomes: Vec::new(),
            failure_files: Vec::new(),
            log_event: super::RelationLogEvent {
                trace_id: "trace".to_string(),
                decision_id: "decision".to_string(),
                policy_id: "policy".to_string(),
                component: "metamorphic_suite".to_string(),
                event: "relation_completed".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-META-0001".to_string()),
                relation_id: "r".to_string(),
                subsystem: "ir".to_string(),
                pairs_tested: 3,
                violations_found: 1,
                min_failure_size: Some(5),
                duration_us: 100,
            },
        };

        let entry = RelationEvidenceEntry::from_execution(&execution, &test_context());
        assert_eq!(entry.error_code.as_deref(), Some("FE-META-0001"));
        assert_eq!(entry.outcome, "fail");
        assert_eq!(entry.event, "relation_completed");
    }

    #[test]
    fn relation_soundness_meta_test_for_curated_seed_set() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relations = build_enabled_relations(&catalog);

        for relation in &relations {
            for seed in 0..20u64 {
                let pair = relation.generate_pair(seed);
                assert!(
                    relation.oracle(&pair).is_equivalent(),
                    "relation {} failed soundness at seed {}",
                    relation.spec().id,
                    seed
                );
            }
        }
    }

    #[test]
    fn generator_coverage_meta_test_exceeds_ninety_nine_percent() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relations = build_enabled_relations(&catalog);

        for relation in &relations {
            let mut valid = 0usize;
            let total = 500usize;
            for seed in 0..total as u64 {
                let pair = relation.generate_pair(seed);
                if relation.validate_program(&pair.input_source)
                    && relation.validate_program(&pair.variant_source)
                {
                    valid += 1;
                }
            }

            let pass_rate = (valid as f64) / (total as f64);
            assert!(
                pass_rate >= 0.99,
                "relation {} coverage {:.3} below threshold",
                relation.spec().id,
                pass_rate
            );
        }
    }

    #[test]
    fn minimizer_effectiveness_meta_test_reduces_to_target_budget() {
        let relation = SyntheticViolationRelation {
            spec: RelationSpec {
                id: "synthetic_violation".to_string(),
                subsystem: Subsystem::Parser,
                description: "synthetic".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 1,
                enabled: true,
            },
        };

        let pair = relation.generate_pair(1);
        let minimized = minimize_failure_pair(
            &relation,
            &pair,
            MinimizerConfig {
                max_iterations: 512,
                max_duration: Duration::from_secs(60),
                target_ast_nodes: 20,
            },
        );

        assert!(!relation.oracle(&minimized).is_equivalent());
        assert!(
            minimized.ast_node_metric() <= 20,
            "expected <= 20 nodes, got {}",
            minimized.ast_node_metric()
        );
    }

    #[test]
    fn determinism_meta_test_for_same_seed() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relation =
            build_relation(&catalog, "ir_lowering_determinism").expect("relation should exist");
        let context = test_context();

        let first =
            run_relation_with_budget(&relation, &context, 50, None, MinimizerConfig::default())
                .expect("first run should pass");
        let second =
            run_relation_with_budget(&relation, &context, 50, None, MinimizerConfig::default())
                .expect("second run should pass");

        assert_eq!(first.outcomes, second.outcomes);
        assert_eq!(first.violations_found, second.violations_found);
    }

    #[test]
    fn suite_logging_contains_required_fields() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relation = build_relation(&catalog, "execution_gc_timing_independence")
            .expect("relation should exist");
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let suite = run_suite(
            &relation_refs,
            &context,
            Some(10),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite run should pass");

        let events = relation_log_events_for_suite(&suite);
        assert!(events.iter().all(|event| !event.trace_id.is_empty()));
        assert!(events.iter().all(|event| !event.decision_id.is_empty()));
        assert!(events.iter().all(|event| !event.policy_id.is_empty()));
        assert!(events.iter().all(|event| !event.component.is_empty()));
        assert!(events.iter().all(|event| !event.event.is_empty()));
        assert!(events.iter().all(|event| !event.outcome.is_empty()));
    }

    #[test]
    fn evidence_entries_include_suite_summary() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "summary_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "summary".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let suite = run_suite(
            &relation_refs,
            &context,
            Some(2),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");

        let entries = evidence_entries_for_suite(&suite);
        assert!(entries.iter().any(|entry| entry.event == "suite_summary"));
        assert!(entries
            .iter()
            .filter(|entry| entry.event == "suite_summary")
            .all(|entry| entry.total_violations.is_some()));
    }

    #[test]
    fn seed_transcript_rows_are_ordered_and_seeded_deterministically() {
        let relation_left = AlwaysPassRelation {
            spec: RelationSpec {
                id: "left_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "left".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let relation_right = AlwaysPassRelation {
            spec: RelationSpec {
                id: "right_relation".to_string(),
                subsystem: Subsystem::Execution,
                description: "right".to_string(),
                oracle: OracleKind::CanonicalOutputEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation_left, &relation_right];

        let suite = run_suite(
            &relation_refs,
            &context,
            Some(2),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");
        let transcript = seed_transcript_entries_for_suite(&suite);

        let relation_order = transcript
            .iter()
            .map(|entry| entry.relation_id.as_str())
            .collect::<Vec<_>>();
        let seed_order = transcript
            .iter()
            .map(|entry| entry.run_seed)
            .collect::<Vec<_>>();
        let pair_indexes = transcript
            .iter()
            .map(|entry| entry.pair_index)
            .collect::<Vec<_>>();

        assert_eq!(
            relation_order,
            vec![
                "left_relation",
                "left_relation",
                "right_relation",
                "right_relation"
            ]
        );
        assert_eq!(seed_order, vec![7, 8, 7, 8]);
        assert_eq!(pair_indexes, vec![0, 1, 0, 1]);
        assert!(transcript
            .iter()
            .all(|entry| entry.event == "pair_seed_evaluated"));
    }

    #[test]
    fn seed_transcript_is_stable_for_identical_suite_inputs() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "stable_seed_relation".to_string(),
                subsystem: Subsystem::Ir,
                description: "stable".to_string(),
                oracle: OracleKind::IrEquality,
                budget_pairs: 3,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];

        let first = run_suite(
            &relation_refs,
            &context,
            Some(3),
            None,
            MinimizerConfig::default(),
        )
        .expect("first suite should run");
        let second = run_suite(
            &relation_refs,
            &context,
            Some(3),
            None,
            MinimizerConfig::default(),
        )
        .expect("second suite should run");

        assert_eq!(
            seed_transcript_entries_for_suite(&first),
            seed_transcript_entries_for_suite(&second)
        );
    }

    #[test]
    fn seed_transcript_writer_emits_jsonl_rows() {
        let relation = AlwaysPassRelation {
            spec: RelationSpec {
                id: "writer_relation".to_string(),
                subsystem: Subsystem::Parser,
                description: "writer".to_string(),
                oracle: OracleKind::AstEquality,
                budget_pairs: 2,
                enabled: true,
            },
        };
        let context = test_context();
        let relation_refs: Vec<&dyn MetamorphicRelation> = vec![&relation];
        let suite = run_suite(
            &relation_refs,
            &context,
            Some(2),
            None,
            MinimizerConfig::default(),
        )
        .expect("suite should run");
        let transcript = seed_transcript_entries_for_suite(&suite);

        let file_name = format!(
            "seed_transcript_writer_test_{}_{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        );
        let output_path = std::env::temp_dir().join(file_name);

        super::write_seed_transcript_jsonl(&output_path, &transcript)
            .expect("writer should serialize transcript");
        let payload =
            std::fs::read_to_string(&output_path).expect("seed transcript file should exist");
        let _ = std::fs::remove_file(&output_path);

        let lines = payload.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), transcript.len());
        assert_eq!(lines.len(), 2);
        assert!(lines
            .iter()
            .all(|line| line.contains("\"event\":\"pair_seed_evaluated\"")));
    }
}
