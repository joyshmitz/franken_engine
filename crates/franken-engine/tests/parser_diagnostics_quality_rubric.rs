use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseBudgetKind, ParseDiagnosticEnvelope, ParseErrorCode, ParserBudget,
    ParserOptions,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ScoreDimension {
    dimension_id: String,
    description: String,
    weight_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct BudgetOverride {
    max_source_bytes: u64,
    max_token_count: u64,
    max_recursion_depth: u64,
}

#[derive(Debug, Deserialize)]
struct RubricCase {
    case_id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_error_code: String,
    expected_diagnostic_code: String,
    expected_budget_kind: Option<String>,
    require_span: bool,
    budget_override: Option<BudgetOverride>,
    replay_command: String,
}

#[derive(Debug, Deserialize)]
struct DiagnosticsQualityRubricFixture {
    schema_version: String,
    rubric_version: String,
    max_allowed_regression_millionths: u32,
    score_dimensions: Vec<ScoreDimension>,
    baseline_scores_millionths: BTreeMap<String, u32>,
    structured_log_required_keys: Vec<String>,
    cases: Vec<RubricCase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseEvaluation {
    case_id: String,
    family_id: String,
    expected_error_code: String,
    diagnostic_hash: String,
    budget_kind: Option<String>,
    score_by_dimension: BTreeMap<String, u32>,
    composite_score_millionths: u32,
    replay_command: String,
}

fn load_fixture() -> DiagnosticsQualityRubricFixture {
    let path = Path::new("tests/fixtures/parser_diagnostics_quality_rubric_v1.json");
    let bytes = fs::read(path).expect("read diagnostics quality fixture");
    serde_json::from_slice(&bytes).expect("deserialize diagnostics quality fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_DIAGNOSTICS_QUALITY_RUBRIC.md");
    fs::read_to_string(path).expect("read diagnostics quality rubric doc")
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown parse goal: {other}"),
    }
}

fn parse_error_code(raw: &str) -> ParseErrorCode {
    match raw {
        "empty_source" => ParseErrorCode::EmptySource,
        "invalid_goal" => ParseErrorCode::InvalidGoal,
        "unsupported_syntax" => ParseErrorCode::UnsupportedSyntax,
        "io_read_failed" => ParseErrorCode::IoReadFailed,
        "invalid_utf8" => ParseErrorCode::InvalidUtf8,
        "source_too_large" => ParseErrorCode::SourceTooLarge,
        "budget_exceeded" => ParseErrorCode::BudgetExceeded,
        other => panic!("unknown parse error code: {other}"),
    }
}

fn parse_budget_kind(raw: &str) -> ParseBudgetKind {
    match raw {
        "source_bytes" => ParseBudgetKind::SourceBytes,
        "token_count" => ParseBudgetKind::TokenCount,
        "recursion_depth" => ParseBudgetKind::RecursionDepth,
        other => panic!("unknown budget kind: {other}"),
    }
}

fn parser_options(case: &RubricCase) -> ParserOptions {
    let mut options = ParserOptions::default();
    if let Some(budget) = case.budget_override.as_ref() {
        options.budget = ParserBudget {
            max_source_bytes: budget.max_source_bytes,
            max_token_count: budget.max_token_count,
            max_recursion_depth: budget.max_recursion_depth,
        };
    }
    options
}

fn score_dimension(
    dimension_id: &str,
    case: &RubricCase,
    envelope: &ParseDiagnosticEnvelope,
    expected_error_code: ParseErrorCode,
    diagnostic_hash: &str,
) -> u32 {
    match dimension_id {
        "location_precision" => {
            if envelope.span.is_some() {
                1_000_000
            } else if case.require_span {
                0
            } else {
                500_000
            }
        }
        "message_clarity" => {
            if envelope.message_template.trim().len() >= 8 {
                1_000_000
            } else {
                0
            }
        }
        "actionable_hints" => {
            if envelope.message_template.split_whitespace().count() >= 3 {
                1_000_000
            } else {
                250_000
            }
        }
        "deterministic_wording" => {
            if envelope.parse_error_code == expected_error_code
                && envelope.diagnostic_code == case.expected_diagnostic_code
                && diagnostic_hash.starts_with("sha256:")
            {
                1_000_000
            } else {
                0
            }
        }
        other => panic!("unknown rubric dimension: {other}"),
    }
}

fn weighted_composite_score(
    score_by_dimension: &BTreeMap<String, u32>,
    dimensions: &[ScoreDimension],
) -> u32 {
    let mut numerator = 0_u128;
    for dimension in dimensions {
        let score = score_by_dimension
            .get(&dimension.dimension_id)
            .unwrap_or_else(|| panic!("missing score for dimension `{}`", dimension.dimension_id));
        numerator = numerator.saturating_add(
            u128::from(*score).saturating_mul(u128::from(dimension.weight_millionths)),
        );
    }
    (numerator / 1_000_000_u128) as u32
}

fn evaluate_case(
    parser: &CanonicalEs2020Parser,
    fixture_case: &RubricCase,
    fixture: &DiagnosticsQualityRubricFixture,
) -> CaseEvaluation {
    let goal = parse_goal(fixture_case.goal.as_str());
    let options = parser_options(fixture_case);
    let expected_error_code = parse_error_code(fixture_case.expected_error_code.as_str());

    let parse_error = parser
        .parse_with_options(fixture_case.source.as_str(), goal, &options)
        .expect_err("fixture case should produce parser diagnostic");

    assert_eq!(
        parse_error.code, expected_error_code,
        "unexpected parse error code for case `{}`",
        fixture_case.case_id
    );

    let envelope = parse_error.normalized_diagnostic();
    assert_eq!(
        envelope.diagnostic_code, fixture_case.expected_diagnostic_code,
        "unexpected diagnostic code for case `{}`",
        fixture_case.case_id
    );

    let expected_budget_kind = fixture_case
        .expected_budget_kind
        .as_deref()
        .map(parse_budget_kind);
    assert_eq!(
        envelope.budget_kind, expected_budget_kind,
        "unexpected budget kind for case `{}`",
        fixture_case.case_id
    );

    let diagnostic_hash = envelope.canonical_hash();
    let score_by_dimension = fixture
        .score_dimensions
        .iter()
        .map(|dimension| {
            (
                dimension.dimension_id.clone(),
                score_dimension(
                    dimension.dimension_id.as_str(),
                    fixture_case,
                    &envelope,
                    expected_error_code,
                    diagnostic_hash.as_str(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let composite_score_millionths =
        weighted_composite_score(&score_by_dimension, &fixture.score_dimensions);

    CaseEvaluation {
        case_id: fixture_case.case_id.clone(),
        family_id: fixture_case.family_id.clone(),
        expected_error_code: fixture_case.expected_error_code.clone(),
        diagnostic_hash,
        budget_kind: envelope.budget_kind.map(|kind| kind.as_str().to_string()),
        score_by_dimension,
        composite_score_millionths,
        replay_command: fixture_case.replay_command.clone(),
    }
}

fn evaluate_all_cases(fixture: &DiagnosticsQualityRubricFixture) -> Vec<CaseEvaluation> {
    let parser = CanonicalEs2020Parser;
    fixture
        .cases
        .iter()
        .map(|case| evaluate_case(&parser, case, fixture))
        .collect()
}

fn aggregate_scores(
    evaluations: &[CaseEvaluation],
    dimensions: &[ScoreDimension],
) -> BTreeMap<String, u32> {
    assert!(!evaluations.is_empty(), "evaluation set must not be empty");
    let count = evaluations.len() as u64;

    let mut aggregate = BTreeMap::new();
    for dimension in dimensions {
        let total = evaluations
            .iter()
            .map(|evaluation| {
                *evaluation
                    .score_by_dimension
                    .get(&dimension.dimension_id)
                    .unwrap_or_else(|| {
                        panic!(
                            "missing dimension score `{}` in case `{}`",
                            dimension.dimension_id, evaluation.case_id
                        )
                    })
            })
            .map(u64::from)
            .sum::<u64>();
        aggregate.insert(dimension.dimension_id.clone(), (total / count) as u32);
    }

    let composite_total = evaluations
        .iter()
        .map(|evaluation| u64::from(evaluation.composite_score_millionths))
        .sum::<u64>();
    aggregate.insert("composite".to_string(), (composite_total / count) as u32);

    aggregate
}

fn build_structured_log(evaluation: &CaseEvaluation) -> serde_json::Value {
    serde_json::json!({
        "trace_id": format!("trace-parser-diagnostics-rubric-{}", evaluation.case_id),
        "decision_id": format!("decision-parser-diagnostics-rubric-{}", evaluation.case_id),
        "policy_id": "policy-parser-diagnostics-rubric-v1",
        "component": "parser_diagnostics_quality_rubric",
        "event": "diagnostics_case_evaluated",
        "outcome": "pass",
        "error_code": null,
        "case_id": evaluation.case_id,
        "family_id": evaluation.family_id,
        "expected_error_code": evaluation.expected_error_code,
        "diagnostic_hash": evaluation.diagnostic_hash,
        "budget_kind": evaluation.budget_kind,
        "scores_millionths": evaluation.score_by_dimension,
        "composite_score_millionths": evaluation.composite_score_millionths,
        "replay_command": evaluation.replay_command,
    })
}

#[test]
fn diagnostics_rubric_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "## Scope",
        "## Contract Version",
        "## Rubric Dimensions",
        "## Golden Diagnostics Corpus Families",
        "## Baseline Delta and Regression Alarm Policy",
        "## Structured Log Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing diagnostics rubric doc section: {section}"
        );
    }
}

#[test]
fn diagnostics_rubric_fixture_contract_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-diagnostics-quality-rubric.v1"
    );
    assert_eq!(fixture.rubric_version, "1.0.0");
    assert!(!fixture.cases.is_empty());
    assert!(!fixture.score_dimensions.is_empty());

    let total_weight = fixture
        .score_dimensions
        .iter()
        .map(|dimension| {
            assert!(!dimension.description.trim().is_empty());
            u64::from(dimension.weight_millionths)
        })
        .sum::<u64>();
    assert_eq!(total_weight, 1_000_000);

    let required_baselines = [
        "location_precision",
        "message_clarity",
        "actionable_hints",
        "deterministic_wording",
        "composite",
    ];
    for key in required_baselines {
        assert!(
            fixture.baseline_scores_millionths.contains_key(key),
            "missing baseline score key `{key}`"
        );
    }

    let required_log_keys = [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ];
    let declared_keys = fixture
        .structured_log_required_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for key in required_log_keys {
        assert!(
            declared_keys.contains(key),
            "missing required structured log key `{key}`"
        );
    }
}

#[test]
fn diagnostics_rubric_cases_cover_major_families() {
    let fixture = load_fixture();
    let families = fixture
        .cases
        .iter()
        .map(|case| {
            case.family_id
                .split('.')
                .next()
                .unwrap_or_else(|| panic!("invalid family id `{}`", case.family_id))
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    let expected = ["goal", "input", "resource", "syntax"]
        .into_iter()
        .map(String::from)
        .collect::<BTreeSet<_>>();
    assert_eq!(families, expected);
}

#[test]
fn diagnostics_rubric_scores_are_deterministic_and_regression_bounded() {
    let fixture = load_fixture();

    let left = evaluate_all_cases(&fixture);
    let right = evaluate_all_cases(&fixture);
    assert_eq!(left, right);

    let aggregate = aggregate_scores(&left, &fixture.score_dimensions);
    for (metric, baseline) in &fixture.baseline_scores_millionths {
        let current = *aggregate
            .get(metric)
            .unwrap_or_else(|| panic!("missing aggregate metric `{metric}`"));
        let delta = i64::from(current) - i64::from(*baseline);
        assert!(
            delta >= -i64::from(fixture.max_allowed_regression_millionths),
            "diagnostics quality regression for `{metric}`: baseline={} current={} delta={} allowed={}",
            baseline,
            current,
            delta,
            fixture.max_allowed_regression_millionths,
        );
    }
}

#[test]
fn diagnostics_rubric_user_journey_logs_are_structured_and_replayable() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);

    let left_logs = evaluations
        .iter()
        .map(build_structured_log)
        .collect::<Vec<_>>();
    let right_logs = evaluate_all_cases(&fixture)
        .iter()
        .map(build_structured_log)
        .collect::<Vec<_>>();

    assert_eq!(left_logs, right_logs);

    for log in &left_logs {
        for key in &fixture.structured_log_required_keys {
            assert!(
                log.get(key.as_str()).is_some(),
                "structured log missing required key `{key}`"
            );
        }

        let replay_command = log["replay_command"]
            .as_str()
            .expect("replay command should be a string");
        assert!(
            replay_command.contains(
                "cargo test -p frankenengine-engine --test parser_diagnostics_quality_rubric"
            ),
            "unexpected replay command: {replay_command}"
        );
    }
}
