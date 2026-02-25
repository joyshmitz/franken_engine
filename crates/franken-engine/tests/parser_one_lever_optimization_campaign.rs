use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MetricVector {
    throughput_sources_per_second_millionths: u64,
    latency_ns_p95: u64,
    ns_per_token_millionths: u64,
    allocs_per_token_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvInputs {
    impact: u64,
    confidence: u64,
    reuse: u64,
    effort: u64,
    friction: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CampaignRun {
    lever_id: String,
    lever_category: String,
    commit: String,
    run_id: String,
    generated_at_utc: String,
    changed_paths: Vec<String>,
    attribution_note: String,
    baseline_metrics: MetricVector,
    candidate_metrics: MetricVector,
    ev_inputs: EvInputs,
    expected_ev_score_millionths: u64,
    expected_gain_millionths: i64,
    replay_command: String,
    artifact_manifest: String,
    artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_pass: bool,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Fixture {
    schema_version: String,
    campaign_version: String,
    metric_schema_version: String,
    required_log_keys: Vec<String>,
    campaign_runs: Vec<CampaignRun>,
    expected_ev_ranking: Vec<String>,
    expected_gain_ranking: Vec<String>,
    expected_selected_lever: String,
    cross_subsystem_replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CampaignResult {
    lever_id: String,
    ev_score_millionths: u64,
    gain_millionths: i64,
}

const THROUGHPUT_WEIGHT: i64 = 400_000;
const LATENCY_WEIGHT: i64 = 300_000;
const NS_PER_TOKEN_WEIGHT: i64 = 200_000;
const ALLOCS_PER_TOKEN_WEIGHT: i64 = 100_000;

fn load_fixture() -> Fixture {
    let path = Path::new("tests/fixtures/parser_one_lever_optimization_campaign_v1.json");
    let bytes = fs::read(path).expect("read parser one-lever fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser one-lever fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_ONE_LEVER_OPTIMIZATION_CAMPAIGN.md");
    fs::read_to_string(path).expect("read parser one-lever doc")
}

fn scaled_delta_higher_is_better(baseline: u64, candidate: u64) -> i64 {
    let base = i128::from(baseline.max(1));
    let cand = i128::from(candidate.max(1));
    let million = i128::from(1_000_000_i64);
    (((cand - base) * million) / base) as i64
}

fn scaled_delta_lower_is_better(baseline: u64, candidate: u64) -> i64 {
    let base = i128::from(baseline.max(1));
    let cand = i128::from(candidate.max(1));
    let million = i128::from(1_000_000_i64);
    (((base - cand) * million) / base) as i64
}

fn ev_score_millionths(inputs: &EvInputs) -> u64 {
    let numerator = inputs
        .impact
        .saturating_mul(inputs.confidence)
        .saturating_mul(inputs.reuse)
        .saturating_mul(1_000_000);
    let denominator = inputs.effort.saturating_mul(inputs.friction).max(1);
    numerator / denominator
}

fn campaign_gain_millionths(run: &CampaignRun) -> i64 {
    let throughput_delta = scaled_delta_higher_is_better(
        run.baseline_metrics
            .throughput_sources_per_second_millionths,
        run.candidate_metrics
            .throughput_sources_per_second_millionths,
    );
    let latency_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.latency_ns_p95,
        run.candidate_metrics.latency_ns_p95,
    );
    let ns_per_token_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.ns_per_token_millionths,
        run.candidate_metrics.ns_per_token_millionths,
    );
    let allocs_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.allocs_per_token_millionths,
        run.candidate_metrics.allocs_per_token_millionths,
    );

    let weighted_sum = i128::from(throughput_delta) * i128::from(THROUGHPUT_WEIGHT)
        + i128::from(latency_delta) * i128::from(LATENCY_WEIGHT)
        + i128::from(ns_per_token_delta) * i128::from(NS_PER_TOKEN_WEIGHT)
        + i128::from(allocs_delta) * i128::from(ALLOCS_PER_TOKEN_WEIGHT);
    (weighted_sum / i128::from(1_000_000_i64)) as i64
}

fn compute_campaign_results(fixture: &Fixture) -> Vec<CampaignResult> {
    fixture
        .campaign_runs
        .iter()
        .map(|run| CampaignResult {
            lever_id: run.lever_id.clone(),
            ev_score_millionths: ev_score_millionths(&run.ev_inputs),
            gain_millionths: campaign_gain_millionths(run),
        })
        .collect()
}

fn rank_by_ev(results: &[CampaignResult]) -> Vec<String> {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .ev_score_millionths
            .cmp(&left.ev_score_millionths)
            .then_with(|| left.lever_id.cmp(&right.lever_id))
    });
    ranked.into_iter().map(|entry| entry.lever_id).collect()
}

fn rank_by_gain(results: &[CampaignResult]) -> Vec<String> {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .gain_millionths
            .cmp(&left.gain_millionths)
            .then_with(|| left.lever_id.cmp(&right.lever_id))
    });
    ranked.into_iter().map(|entry| entry.lever_id).collect()
}

fn selected_lever_by_ev(results: &[CampaignResult]) -> String {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .ev_score_millionths
            .cmp(&left.ev_score_millionths)
            .then_with(|| left.lever_id.cmp(&right.lever_id))
    });
    ranked
        .first()
        .expect("campaign results must not be empty")
        .lever_id
        .clone()
}

fn emit_structured_events(fixture: &Fixture, results: &[CampaignResult]) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    for result in results {
        events.push(serde_json::json!({
            "trace_id": "trace-parser-one-lever-campaign-v1",
            "decision_id": format!("decision-{}", result.lever_id),
            "policy_id": "policy-parser-one-lever-campaign-v1",
            "component": "parser_one_lever_optimization_campaign",
            "event": "campaign_run_scored",
            "outcome": if result.gain_millionths >= 0 { "improved" } else { "regressed" },
            "error_code": serde_json::Value::Null,
            "lever_id": result.lever_id,
            "ev_score_millionths": result.ev_score_millionths,
            "gain_millionths": result.gain_millionths
        }));
    }

    events.push(serde_json::json!({
        "trace_id": "trace-parser-one-lever-campaign-v1",
        "decision_id": "decision-parser-one-lever-selection",
        "policy_id": "policy-parser-one-lever-campaign-v1",
        "component": "parser_one_lever_optimization_campaign",
        "event": "selected_lever",
        "outcome": "pass",
        "error_code": serde_json::Value::Null,
        "selected_lever": selected_lever_by_ev(results),
        "required_key_count": fixture.required_log_keys.len()
    }));

    events
}

#[test]
fn parser_one_lever_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser One-Lever Optimization Campaign Contract (`bd-2mds.1.6.3`)",
        "## EV Scoring Contract",
        "## Gain Attribution Contract",
        "## Structured Log Contract",
        "./scripts/run_parser_one_lever_optimization_campaign.sh ci",
        "./scripts/e2e/parser_one_lever_optimization_campaign_replay.sh",
    ] {
        assert!(doc.contains(section), "missing doc section: {section}");
    }
}

#[test]
fn parser_one_lever_fixture_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-one-lever-optimization-campaign.v1"
    );
    assert_eq!(fixture.campaign_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.parser-telemetry.v1"
    );

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
        assert!(required_keys.contains(key), "missing required key `{key}`");
    }

    assert!(!fixture.campaign_runs.is_empty());
    let mut lever_ids = BTreeSet::new();
    for run in &fixture.campaign_runs {
        assert!(lever_ids.insert(run.lever_id.clone()));
        assert!(!run.commit.trim().is_empty());
        assert!(!run.run_id.trim().is_empty());
        assert!(!run.generated_at_utc.trim().is_empty());
        assert!(!run.lever_category.trim().is_empty());
        assert!(!run.changed_paths.is_empty());
        assert!(!run.attribution_note.trim().is_empty());
        assert!(!run.replay_command.trim().is_empty());
        assert!(!run.artifact_manifest.trim().is_empty());
        assert!(!run.artifact_report.trim().is_empty());
        assert!(run.ev_inputs.effort > 0);
        assert!(run.ev_inputs.friction > 0);
    }

    assert!(!fixture.cross_subsystem_replay_scenarios.is_empty());
}

#[test]
fn ev_scores_match_fixture_and_are_deterministic() {
    let fixture = load_fixture();
    let first = compute_campaign_results(&fixture);
    let second = compute_campaign_results(&fixture);
    assert_eq!(first, second, "campaign scoring must be deterministic");

    for (run, result) in fixture.campaign_runs.iter().zip(first.iter()) {
        assert_eq!(result.lever_id, run.lever_id);
        assert_eq!(
            result.ev_score_millionths, run.expected_ev_score_millionths,
            "ev score mismatch for {}",
            run.lever_id
        );
    }
}

#[test]
fn gain_attribution_matches_fixture_and_rankings() {
    let fixture = load_fixture();
    let results = compute_campaign_results(&fixture);

    for (run, result) in fixture.campaign_runs.iter().zip(results.iter()) {
        assert_eq!(
            result.gain_millionths, run.expected_gain_millionths,
            "gain mismatch for {}",
            run.lever_id
        );
    }

    let ev_ranking = rank_by_ev(&results);
    assert_eq!(ev_ranking, fixture.expected_ev_ranking);

    let gain_ranking = rank_by_gain(&results);
    assert_eq!(gain_ranking, fixture.expected_gain_ranking);

    let selected = selected_lever_by_ev(&results);
    assert_eq!(selected, fixture.expected_selected_lever);
}

#[test]
fn replay_scenarios_and_structured_log_contract_are_complete() {
    let fixture = load_fixture();
    let results = compute_campaign_results(&fixture);
    let events = emit_structured_events(&fixture, &results);

    for scenario in &fixture.cross_subsystem_replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(!scenario.replay_command.trim().is_empty());
        assert!(scenario.expected_pass);
        assert_eq!(scenario.expected_outcome, "pass");
    }

    for event in &events {
        let object = event.as_object().expect("event must be object");
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
