use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::e2e_harness::{
    DeterministicRunner, HarnessEvent, RunReport, TestFixture,
};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseBudgetKind, ParseErrorCode, ParserBudget, ParserOptions,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MetricDefinition {
    metric_id: String,
    description: String,
    unit: String,
    direction: String,
    weight_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct BudgetOverride {
    max_source_bytes: u64,
    max_token_count: u64,
    max_recursion_depth: u64,
}

#[derive(Debug, Deserialize)]
struct DiagnosticSample {
    sample_id: String,
    goal: String,
    source: String,
    expected_error_code: String,
    expected_diagnostic_code: String,
    expected_budget_kind: Option<String>,
    budget_override: Option<BudgetOverride>,
}

#[derive(Debug, Deserialize)]
struct IntegrationSample {
    sample_id: String,
    goal: String,
    source: String,
    expect_ok: bool,
}

#[derive(Debug, Deserialize)]
struct BaselineScenario {
    scenario_id: String,
    expected_pass: bool,
    replay_command: String,
    fixture: TestFixture,
}

#[derive(Debug, Deserialize)]
struct UserImpactBaselineFixture {
    schema_version: String,
    dashboard_version: String,
    metric_schema_version: String,
    max_allowed_regression_millionths: u32,
    metric_definitions: Vec<MetricDefinition>,
    baseline_scores_millionths: BTreeMap<String, u32>,
    required_log_keys: Vec<String>,
    diagnostic_samples: Vec<DiagnosticSample>,
    integration_samples: Vec<IntegrationSample>,
    baseline_scenarios: Vec<BaselineScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DashboardSnapshot {
    schema_version: String,
    dashboard_version: String,
    metric_schema_version: String,
    metric_scores_millionths: BTreeMap<String, u32>,
    scenario_digest_by_id: BTreeMap<String, String>,
    composite_score_millionths: u32,
}

fn load_fixture() -> UserImpactBaselineFixture {
    let path = Path::new("tests/fixtures/parser_user_impact_baseline_dashboard_v1.json");
    let bytes = fs::read(path).expect("read user-impact baseline dashboard fixture");
    serde_json::from_slice(&bytes).expect("deserialize user-impact baseline dashboard fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_USER_IMPACT_BASELINE_DASHBOARD.md");
    fs::read_to_string(path).expect("read parser user-impact baseline dashboard doc")
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

fn parser_options(sample: &DiagnosticSample) -> ParserOptions {
    let mut options = ParserOptions::default();
    if let Some(override_budget) = sample.budget_override.as_ref() {
        options.budget = ParserBudget {
            max_source_bytes: override_budget.max_source_bytes,
            max_token_count: override_budget.max_token_count,
            max_recursion_depth: override_budget.max_recursion_depth,
        };
    }
    options
}

fn assert_required_log_keys(events: &[HarnessEvent], required_keys: &[String], scenario_id: &str) {
    assert!(
        !events.is_empty(),
        "scenario `{scenario_id}` emitted empty event list"
    );

    for event in events {
        let value = serde_json::to_value(event).expect("serialize harness event");
        let object = value
            .as_object()
            .expect("harness event should serialize to object");

        for key in required_keys {
            assert!(
                object.contains_key(key),
                "scenario `{scenario_id}` event missing required key `{key}`"
            );
            if key == "error_code" {
                continue;
            }
            if let Some(field) = object.get(key).and_then(|raw| raw.as_str()) {
                assert!(
                    !field.trim().is_empty(),
                    "scenario `{scenario_id}` key `{key}` must not be empty"
                );
            }
        }
    }
}

fn evaluate_diagnostic_quality(fixture: &UserImpactBaselineFixture) -> u32 {
    assert!(
        !fixture.diagnostic_samples.is_empty(),
        "diagnostic samples must not be empty"
    );
    let parser = CanonicalEs2020Parser;
    let mut matched = 0_u64;

    for sample in &fixture.diagnostic_samples {
        let goal = parse_goal(sample.goal.as_str());
        let options = parser_options(sample);
        let expected_error_code = parse_error_code(sample.expected_error_code.as_str());

        let parse_error = parser
            .parse_with_options(sample.source.as_str(), goal, &options)
            .expect_err("diagnostic sample should produce parse error");
        assert_eq!(
            parse_error.code, expected_error_code,
            "unexpected parse error code for sample `{}`",
            sample.sample_id
        );

        let envelope = parse_error.normalized_diagnostic();
        assert_eq!(
            envelope.diagnostic_code, sample.expected_diagnostic_code,
            "unexpected diagnostic code for sample `{}`",
            sample.sample_id
        );
        assert_eq!(
            envelope.budget_kind,
            sample
                .expected_budget_kind
                .as_deref()
                .map(parse_budget_kind),
            "unexpected budget kind for sample `{}`",
            sample.sample_id
        );

        matched = matched.saturating_add(1);
    }

    let sample_count = fixture.diagnostic_samples.len() as u64;
    ((matched.saturating_mul(1_000_000)) / sample_count) as u32
}

fn evaluate_integration_friction(fixture: &UserImpactBaselineFixture) -> u32 {
    assert!(
        !fixture.integration_samples.is_empty(),
        "integration samples must not be empty"
    );
    let parser = CanonicalEs2020Parser;
    let mut matched = 0_u64;

    for sample in &fixture.integration_samples {
        let goal = parse_goal(sample.goal.as_str());
        let is_ok = parser
            .parse_with_options(sample.source.as_str(), goal, &ParserOptions::default())
            .is_ok();
        if is_ok == sample.expect_ok {
            matched = matched.saturating_add(1);
        } else {
            panic!(
                "unexpected integration outcome for sample `{}`: expected_ok={} actual_ok={}",
                sample.sample_id, sample.expect_ok, is_ok
            );
        }
    }

    let sample_count = fixture.integration_samples.len() as u64;
    ((matched.saturating_mul(1_000_000)) / sample_count) as u32
}

fn evaluate_recovery_usefulness(
    fixture: &UserImpactBaselineFixture,
) -> (u32, BTreeMap<String, String>) {
    assert!(
        !fixture.baseline_scenarios.is_empty(),
        "baseline scenarios must not be empty"
    );

    let runner = DeterministicRunner::default();
    let mut matched = 0_u64;
    let mut scenario_digest_by_id = BTreeMap::new();

    for scenario in &fixture.baseline_scenarios {
        assert!(
            !scenario.replay_command.trim().is_empty(),
            "replay command is required for scenario `{}`",
            scenario.scenario_id
        );

        let first = runner
            .run_fixture(&scenario.fixture)
            .expect("first deterministic run");
        let second = runner
            .run_fixture(&scenario.fixture)
            .expect("second deterministic run");

        if scenario.fixture.determinism_check {
            assert_eq!(
                first.output_digest, second.output_digest,
                "output digest drift for scenario `{}`",
                scenario.scenario_id
            );
            assert_eq!(
                first.events, second.events,
                "event stream drift for scenario `{}`",
                scenario.scenario_id
            );
        }

        assert_required_log_keys(
            &first.events,
            &fixture.required_log_keys,
            scenario.scenario_id.as_str(),
        );

        let pass = RunReport::from_result(&first).pass;
        if pass == scenario.expected_pass {
            matched = matched.saturating_add(1);
        }

        scenario_digest_by_id.insert(scenario.scenario_id.clone(), first.output_digest.clone());
    }

    let scenario_count = fixture.baseline_scenarios.len() as u64;
    let score = ((matched.saturating_mul(1_000_000)) / scenario_count) as u32;
    (score, scenario_digest_by_id)
}

fn weighted_composite_score(
    metric_scores: &BTreeMap<String, u32>,
    metric_definitions: &[MetricDefinition],
) -> u32 {
    let mut numerator = 0_u128;
    for metric in metric_definitions {
        let score = metric_scores
            .get(&metric.metric_id)
            .unwrap_or_else(|| panic!("missing score for metric `{}`", metric.metric_id));
        numerator =
            numerator.saturating_add(u128::from(*score) * u128::from(metric.weight_millionths));
    }
    (numerator / 1_000_000_u128) as u32
}

fn evaluate_snapshot(fixture: &UserImpactBaselineFixture) -> DashboardSnapshot {
    let diagnostic_quality = evaluate_diagnostic_quality(fixture);
    let integration_friction = evaluate_integration_friction(fixture);
    let (recovery_usefulness, scenario_digest_by_id) = evaluate_recovery_usefulness(fixture);

    let mut metric_scores_millionths = BTreeMap::new();
    metric_scores_millionths.insert("diagnostic_quality".to_string(), diagnostic_quality);
    metric_scores_millionths.insert("recovery_usefulness".to_string(), recovery_usefulness);
    metric_scores_millionths.insert("integration_friction".to_string(), integration_friction);

    let composite_score_millionths =
        weighted_composite_score(&metric_scores_millionths, &fixture.metric_definitions);

    DashboardSnapshot {
        schema_version: fixture.schema_version.clone(),
        dashboard_version: fixture.dashboard_version.clone(),
        metric_schema_version: fixture.metric_schema_version.clone(),
        metric_scores_millionths,
        scenario_digest_by_id,
        composite_score_millionths,
    }
}

#[test]
fn user_impact_baseline_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser User-Impact Baseline Dashboard (`bd-2mds.1.10.5.1`)",
        "## Required Metrics",
        "## Deterministic Baseline Workflows",
        "## Structured Log Keys",
        "## Required Artifacts",
        "./scripts/run_parser_user_impact_baseline_dashboard.sh ci",
    ] {
        assert!(
            doc.contains(section),
            "required section missing from doc: {section}"
        );
    }
}

#[test]
fn user_impact_baseline_fixture_contract_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-user-impact-baseline-dashboard.v1"
    );
    assert_eq!(fixture.dashboard_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.parser-user-impact-metrics.v1"
    );
    assert!(
        fixture.max_allowed_regression_millionths <= 200_000,
        "regression budget is unexpectedly large"
    );
    assert!(!fixture.metric_definitions.is_empty());

    let mut metric_ids = BTreeSet::new();
    let mut total_weight = 0_u64;
    for metric in &fixture.metric_definitions {
        assert!(metric_ids.insert(metric.metric_id.clone()));
        assert!(
            !metric.description.trim().is_empty(),
            "metric description is required"
        );
        assert_eq!(metric.unit, "score_millionths");
        assert_eq!(metric.direction, "higher_is_better");
        total_weight = total_weight.saturating_add(u64::from(metric.weight_millionths));
    }
    assert_eq!(total_weight, 1_000_000);

    for required in [
        "diagnostic_quality",
        "recovery_usefulness",
        "integration_friction",
        "composite",
    ] {
        assert!(
            fixture.baseline_scores_millionths.contains_key(required),
            "baseline score missing required metric `{required}`"
        );
    }

    for required_key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            fixture
                .required_log_keys
                .iter()
                .any(|key| key == required_key),
            "required log key missing: `{required_key}`"
        );
    }
}

#[test]
fn user_impact_baseline_scenarios_are_deterministic_and_replayable() {
    let fixture = load_fixture();
    let left = evaluate_snapshot(&fixture);
    let right = evaluate_snapshot(&fixture);
    assert_eq!(left, right, "dashboard snapshot must be deterministic");

    assert!(
        !left.scenario_digest_by_id.is_empty(),
        "scenario digests must be populated"
    );
    for digest in left.scenario_digest_by_id.values() {
        assert!(
            digest.len() == 16
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                && digest != "digest-error",
            "scenario digest must be deterministic FNV-1a hex"
        );
    }
}

#[test]
fn user_impact_baseline_scores_respect_regression_budget() {
    let fixture = load_fixture();
    let snapshot = evaluate_snapshot(&fixture);
    let allowed = i64::from(fixture.max_allowed_regression_millionths);

    for (metric, baseline) in &fixture.baseline_scores_millionths {
        let current = if metric == "composite" {
            snapshot.composite_score_millionths
        } else {
            *snapshot
                .metric_scores_millionths
                .get(metric)
                .unwrap_or_else(|| panic!("missing score for baseline metric `{metric}`"))
        };
        let delta = i64::from(current) - i64::from(*baseline);
        assert!(
            delta >= -allowed,
            "user-impact baseline regression for `{metric}`: baseline={} current={} delta={} allowed={}",
            baseline,
            current,
            delta,
            allowed
        );
    }
}
