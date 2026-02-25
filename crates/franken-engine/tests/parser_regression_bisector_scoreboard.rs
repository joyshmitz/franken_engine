use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MetricDirection {
    HigherIsBetter,
    LowerIsBetter,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MetricDefinition {
    metric_id: String,
    direction: MetricDirection,
    weight_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HistoryEntry {
    commit: String,
    run_id: String,
    generated_at_utc: String,
    metrics: BTreeMap<String, u64>,
    replay_command: String,
    artifact_manifest: String,
    artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedBisect {
    first_bad_commit: String,
    search_path: Vec<String>,
    classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ScoreboardExpectations {
    top_improvement_commit: String,
    worst_regression_commit: String,
    regression_alert_commits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IncidentReplayDrill {
    drill_id: String,
    replay_command: String,
    expected_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserRegressionScoreboardFixture {
    schema_version: String,
    scoreboard_version: String,
    metric_schema_version: String,
    max_allowed_regression_millionths: u32,
    metric_definitions: Vec<MetricDefinition>,
    required_log_keys: Vec<String>,
    history: Vec<HistoryEntry>,
    baseline_commit: String,
    candidate_commit: String,
    expected_bisect: ExpectedBisect,
    scoreboard_expectations: ScoreboardExpectations,
    incident_replay_drills: Vec<IncidentReplayDrill>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitScore {
    commit: String,
    run_id: String,
    generated_at_utc: String,
    composite_score_millionths: u64,
    delta_from_baseline_millionths: i64,
    regression: bool,
    replay_command: String,
    artifact_manifest: String,
    artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BisectOutcome {
    classification: String,
    first_bad_commit: Option<String>,
    search_path: Vec<String>,
}

fn load_fixture() -> ParserRegressionScoreboardFixture {
    let path = Path::new("tests/fixtures/parser_regression_bisector_scoreboard_v1.json");
    let bytes = fs::read(path).expect("read parser regression fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser regression fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_REGRESSION_BISECTOR_SCOREBOARD.md");
    fs::read_to_string(path).expect("read parser regression bisector doc")
}

fn metric_score_millionths(definition: &MetricDefinition, baseline: u64, current: u64) -> u64 {
    let baseline_nonzero = u128::from(baseline.max(1));
    let current_nonzero = u128::from(current.max(1));
    let million = 1_000_000_u128;

    let ratio = match definition.direction {
        MetricDirection::HigherIsBetter => {
            current_nonzero.saturating_mul(million) / baseline_nonzero
        }
        MetricDirection::LowerIsBetter => {
            baseline_nonzero.saturating_mul(million) / current_nonzero
        }
    };
    ratio.min(u128::from(u64::MAX)) as u64
}

fn baseline_index(fixture: &ParserRegressionScoreboardFixture) -> usize {
    fixture
        .history
        .iter()
        .position(|entry| entry.commit == fixture.baseline_commit)
        .unwrap_or_else(|| panic!("missing baseline commit `{}`", fixture.baseline_commit))
}

fn candidate_index(fixture: &ParserRegressionScoreboardFixture) -> usize {
    fixture
        .history
        .iter()
        .position(|entry| entry.commit == fixture.candidate_commit)
        .unwrap_or_else(|| panic!("missing candidate commit `{}`", fixture.candidate_commit))
}

fn composite_score_millionths(
    fixture: &ParserRegressionScoreboardFixture,
    baseline: &HistoryEntry,
    current: &HistoryEntry,
) -> u64 {
    let mut numerator = 0_u128;
    for definition in &fixture.metric_definitions {
        let baseline_metric = baseline
            .metrics
            .get(&definition.metric_id)
            .unwrap_or_else(|| panic!("baseline missing metric `{}`", definition.metric_id));
        let current_metric = current
            .metrics
            .get(&definition.metric_id)
            .unwrap_or_else(|| panic!("current missing metric `{}`", definition.metric_id));
        let score = metric_score_millionths(definition, *baseline_metric, *current_metric);
        numerator = numerator.saturating_add(
            u128::from(score).saturating_mul(u128::from(definition.weight_millionths)),
        );
    }
    (numerator / 1_000_000_u128) as u64
}

fn is_regression(delta: i64, threshold_millionths: u32) -> bool {
    delta < -(i64::from(threshold_millionths))
}

fn build_commit_scores(fixture: &ParserRegressionScoreboardFixture) -> Vec<CommitScore> {
    let base_idx = baseline_index(fixture);
    let baseline = &fixture.history[base_idx];
    let baseline_score = composite_score_millionths(fixture, baseline, baseline);

    fixture
        .history
        .iter()
        .map(|entry| {
            let composite = composite_score_millionths(fixture, baseline, entry);
            let delta = composite as i64 - baseline_score as i64;
            CommitScore {
                commit: entry.commit.clone(),
                run_id: entry.run_id.clone(),
                generated_at_utc: entry.generated_at_utc.clone(),
                composite_score_millionths: composite,
                delta_from_baseline_millionths: delta,
                regression: is_regression(delta, fixture.max_allowed_regression_millionths),
                replay_command: entry.replay_command.clone(),
                artifact_manifest: entry.artifact_manifest.clone(),
                artifact_report: entry.artifact_report.clone(),
            }
        })
        .collect()
}

fn run_bisect(fixture: &ParserRegressionScoreboardFixture) -> BisectOutcome {
    let base_idx = baseline_index(fixture);
    let candidate_idx = candidate_index(fixture);
    assert!(
        candidate_idx > base_idx,
        "candidate must be newer than baseline"
    );

    let scores = build_commit_scores(fixture);
    if !scores[candidate_idx].regression {
        return BisectOutcome {
            classification: "no_regression_detected".to_string(),
            first_bad_commit: None,
            search_path: Vec::new(),
        };
    }

    let mut low = base_idx + 1;
    let mut high = candidate_idx;
    let mut path = Vec::new();

    while low < high {
        let mid = low + ((high - low) / 2);
        path.push(scores[mid].commit.clone());
        if scores[mid].regression {
            high = mid;
        } else {
            low = mid + 1;
        }
    }

    BisectOutcome {
        classification: "regression_detected".to_string(),
        first_bad_commit: Some(scores[low].commit.clone()),
        search_path: path,
    }
}

fn top_improvement_commit(scores: &[CommitScore]) -> String {
    scores
        .iter()
        .max_by(|left, right| {
            left.delta_from_baseline_millionths
                .cmp(&right.delta_from_baseline_millionths)
                .then_with(|| right.commit.cmp(&left.commit))
        })
        .expect("non-empty scores")
        .commit
        .clone()
}

fn worst_regression_commit(scores: &[CommitScore]) -> String {
    scores
        .iter()
        .min_by(|left, right| {
            left.delta_from_baseline_millionths
                .cmp(&right.delta_from_baseline_millionths)
                .then_with(|| left.commit.cmp(&right.commit))
        })
        .expect("non-empty scores")
        .commit
        .clone()
}

fn regression_alert_commits(scores: &[CommitScore]) -> Vec<String> {
    scores
        .iter()
        .filter(|score| score.regression)
        .map(|score| score.commit.clone())
        .collect()
}

fn emit_structured_events(
    fixture: &ParserRegressionScoreboardFixture,
    scores: &[CommitScore],
    bisect: &BisectOutcome,
) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    for score in scores {
        events.push(serde_json::json!({
            "trace_id": "trace-parser-regression-bisector-v1",
            "decision_id": format!("decision-{}", score.commit),
            "policy_id": "policy-parser-regression-bisector-v1",
            "component": "parser_regression_bisector_scoreboard",
            "event": "scoreboard_row",
            "outcome": if score.regression { "regression" } else { "within_budget" },
            "error_code": if score.regression {
                serde_json::Value::String("FE-PARSER-REGRESSION-0001".to_string())
            } else {
                serde_json::Value::Null
            },
            "commit": score.commit,
            "delta_from_baseline_millionths": score.delta_from_baseline_millionths
        }));
    }

    events.push(serde_json::json!({
        "trace_id": "trace-parser-regression-bisector-v1",
        "decision_id": "decision-parser-regression-bisect",
        "policy_id": "policy-parser-regression-bisector-v1",
        "component": "parser_regression_bisector_scoreboard",
        "event": "bisect_completed",
        "outcome": bisect.classification,
        "error_code": serde_json::Value::Null,
        "first_bad_commit": bisect.first_bad_commit,
        "search_path": bisect.search_path,
        "required_key_count": fixture.required_log_keys.len()
    }));

    events
}

#[test]
fn parser_regression_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser Regression Bisector and Scoreboard Contract (`bd-2mds.1.6.4`)",
        "## Bisector Determinism Contract",
        "## Scoreboard Publication Contract",
        "## Structured Log Contract",
        "./scripts/run_parser_regression_bisector_scoreboard.sh ci",
        "./scripts/e2e/parser_regression_bisector_scoreboard_replay.sh",
    ] {
        assert!(
            doc.contains(section),
            "required doc section missing: {section}"
        );
    }
}

#[test]
fn parser_regression_fixture_contract_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-regression-bisector-scoreboard.v1"
    );
    assert_eq!(fixture.scoreboard_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.parser-telemetry.v1"
    );

    assert!(
        fixture.max_allowed_regression_millionths <= 200_000,
        "regression threshold budget unexpectedly large"
    );

    let mut metric_ids = BTreeSet::new();
    let mut total_weight = 0_u64;
    for metric in &fixture.metric_definitions {
        assert!(metric_ids.insert(metric.metric_id.clone()));
        total_weight = total_weight.saturating_add(u64::from(metric.weight_millionths));
    }
    assert_eq!(total_weight, 1_000_000);

    for required_metric in [
        "throughput_sources_per_second_millionths",
        "latency_ns_p95",
        "ns_per_token_millionths",
        "allocs_per_token_millionths",
    ] {
        assert!(
            metric_ids.contains(required_metric),
            "missing required metric definition: {required_metric}"
        );
    }

    let required_keys: BTreeSet<&str> = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            required_keys.contains(key),
            "missing required log key `{key}`"
        );
    }

    assert!(!fixture.history.is_empty(), "history must not be empty");
    for entry in &fixture.history {
        assert!(!entry.run_id.trim().is_empty());
        assert!(!entry.generated_at_utc.trim().is_empty());
        assert!(!entry.replay_command.trim().is_empty());
        assert!(!entry.artifact_manifest.trim().is_empty());
        assert!(!entry.artifact_report.trim().is_empty());
        for metric in &fixture.metric_definitions {
            assert!(
                entry.metrics.contains_key(&metric.metric_id),
                "entry `{}` missing metric `{}`",
                entry.commit,
                metric.metric_id
            );
        }
    }

    assert!(!fixture.incident_replay_drills.is_empty());
    for drill in &fixture.incident_replay_drills {
        assert!(!drill.drill_id.trim().is_empty());
        assert!(!drill.replay_command.trim().is_empty());
    }
}

#[test]
fn regression_bisector_matches_expected_path() {
    let fixture = load_fixture();
    let first = run_bisect(&fixture);
    let second = run_bisect(&fixture);
    assert_eq!(first, second, "bisect output must be deterministic");

    assert_eq!(first.classification, fixture.expected_bisect.classification);
    assert_eq!(
        first.first_bad_commit,
        Some(fixture.expected_bisect.first_bad_commit.clone())
    );
    assert_eq!(first.search_path, fixture.expected_bisect.search_path);
}

#[test]
fn scoreboard_publication_matches_expected_rankings() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);

    let top = top_improvement_commit(&scores);
    assert_eq!(
        top, fixture.scoreboard_expectations.top_improvement_commit,
        "top improvement commit mismatch"
    );

    let worst = worst_regression_commit(&scores);
    assert_eq!(
        worst, fixture.scoreboard_expectations.worst_regression_commit,
        "worst regression commit mismatch"
    );

    let alerts = regression_alert_commits(&scores);
    assert_eq!(
        alerts,
        fixture.scoreboard_expectations.regression_alert_commits
    );

    let baseline_idx = baseline_index(&fixture);
    let candidate_idx = candidate_index(&fixture);
    assert_eq!(scores[baseline_idx].delta_from_baseline_millionths, 0);
    assert!(scores[candidate_idx].regression);

    let near_threshold_commit = scores
        .iter()
        .find(|score| score.commit == "c004")
        .expect("commit c004 should exist");
    assert!(
        !near_threshold_commit.regression,
        "c004 should remain within regression budget"
    );
}

#[test]
fn structured_log_contract_and_replay_drills_are_complete() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let bisect = run_bisect(&fixture);
    let events = emit_structured_events(&fixture, &scores, &bisect);

    for drill in &fixture.incident_replay_drills {
        assert!(
            drill.expected_pass,
            "replay drill `{}` must be expected to pass in fixture",
            drill.drill_id
        );
    }

    for event in &events {
        let object = event.as_object().expect("structured event must be object");
        for required in &fixture.required_log_keys {
            assert!(
                object.contains_key(required),
                "structured event missing key `{required}`"
            );
            if required == "error_code" {
                continue;
            }
            if let Some(value) = object.get(required).and_then(|raw| raw.as_str()) {
                assert!(
                    !value.trim().is_empty(),
                    "event key `{required}` must not be empty"
                );
            }
        }
    }
}
