use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HotspotEvidence {
    hotspot_id: String,
    phase: String,
    baseline_share_millionths: u64,
    baseline_profile_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MetricVector {
    analysis_graph_construction_ns: u64,
    lowering_sources_per_second_millionths: u64,
    optimization_pass_ns: u64,
    codegen_output_bytes: u64,
    compile_latency_ns: u64,
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
struct IsomorphismProofNote {
    proof_method: String,
    verification_contract_ref: String,
    drift_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CampaignRun {
    campaign_id: String,
    lever_id: String,
    lever_category: String,
    commit: String,
    run_id: String,
    generated_at_utc: String,
    changed_paths: Vec<String>,
    hotspot: HotspotEvidence,
    attribution_note: String,
    baseline_metrics: MetricVector,
    candidate_metrics: MetricVector,
    ev_inputs: EvInputs,
    expected_ev_score_millionths: u64,
    expected_gain_millionths: i64,
    isomorphism_proof: IsomorphismProofNote,
    rollback_plan_ref: String,
    replay_command: String,
    artifact_manifest: String,
    artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    scenario_kind: String,
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
    expected_selected_campaign: String,
    cross_subsystem_replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CampaignResult {
    campaign_id: String,
    ev_score_millionths: u64,
    gain_millionths: i64,
}

const ANALYSIS_WEIGHT: i64 = 200_000;
const LOWERING_WEIGHT: i64 = 200_000;
const OPTIMIZATION_WEIGHT: i64 = 200_000;
const CODEGEN_SIZE_WEIGHT: i64 = 200_000;
const LATENCY_WEIGHT: i64 = 200_000;

fn load_fixture() -> Fixture {
    let path = Path::new("tests/fixtures/compiler_hotspot_optimization_campaign_v1.json");
    let bytes = fs::read(path).expect("read compiler hotspot fixture");
    serde_json::from_slice(&bytes).expect("deserialize compiler hotspot fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/COMPILER_HOTSPOT_OPTIMIZATION_CAMPAIGN.md");
    fs::read_to_string(path).expect("read compiler hotspot contract doc")
}

fn scaled_delta_higher_is_better(baseline: u64, candidate: u64) -> i64 {
    let base = i128::from(baseline.max(1));
    let cand = i128::from(candidate.max(1));
    (((cand - base) * i128::from(1_000_000_i64)) / base) as i64
}

fn scaled_delta_lower_is_better(baseline: u64, candidate: u64) -> i64 {
    let base = i128::from(baseline.max(1));
    let cand = i128::from(candidate.max(1));
    (((base - cand) * i128::from(1_000_000_i64)) / base) as i64
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
    let analysis_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.analysis_graph_construction_ns,
        run.candidate_metrics.analysis_graph_construction_ns,
    );
    let lowering_delta = scaled_delta_higher_is_better(
        run.baseline_metrics.lowering_sources_per_second_millionths,
        run.candidate_metrics.lowering_sources_per_second_millionths,
    );
    let optimization_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.optimization_pass_ns,
        run.candidate_metrics.optimization_pass_ns,
    );
    let codegen_size_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.codegen_output_bytes,
        run.candidate_metrics.codegen_output_bytes,
    );
    let latency_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.compile_latency_ns,
        run.candidate_metrics.compile_latency_ns,
    );

    let weighted_sum = i128::from(analysis_delta) * i128::from(ANALYSIS_WEIGHT)
        + i128::from(lowering_delta) * i128::from(LOWERING_WEIGHT)
        + i128::from(optimization_delta) * i128::from(OPTIMIZATION_WEIGHT)
        + i128::from(codegen_size_delta) * i128::from(CODEGEN_SIZE_WEIGHT)
        + i128::from(latency_delta) * i128::from(LATENCY_WEIGHT);
    (weighted_sum / i128::from(1_000_000_i64)) as i64
}

fn compute_campaign_results(fixture: &Fixture) -> Vec<CampaignResult> {
    fixture
        .campaign_runs
        .iter()
        .map(|run| CampaignResult {
            campaign_id: run.campaign_id.clone(),
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
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    ranked.into_iter().map(|entry| entry.campaign_id).collect()
}

fn rank_by_gain(results: &[CampaignResult]) -> Vec<String> {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .gain_millionths
            .cmp(&left.gain_millionths)
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    ranked.into_iter().map(|entry| entry.campaign_id).collect()
}

fn selected_campaign(results: &[CampaignResult]) -> String {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .ev_score_millionths
            .cmp(&left.ev_score_millionths)
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    ranked
        .first()
        .expect("campaign results must not be empty")
        .campaign_id
        .clone()
}

fn classify_compiler_lever(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("static_analysis_graph") {
        return Some("analysis_graph");
    }
    if lower.contains("lowering_pipeline") {
        return Some("lowering_throughput");
    }
    if lower.contains("budgeted_optimization") {
        return Some("optimization_pass");
    }
    if lower.contains("frir_schema") || lower.contains("codegen") {
        return Some("codegen_latency");
    }
    None
}

fn emit_structured_events(results: &[CampaignResult]) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    for result in results {
        events.push(serde_json::json!({
            "schema_version": "franken-engine.compiler-log-event.v1",
            "trace_id": "trace-compiler-hotspot-campaign-v1",
            "decision_id": format!("decision-{}", result.campaign_id),
            "policy_id": "policy-compiler-hotspot-campaign-v1",
            "component": "compiler_hotspot_optimization_campaign",
            "event": "campaign_run_scored",
            "outcome": if result.gain_millionths >= 0 { "improved" } else { "regressed" },
            "error_code": serde_json::Value::Null
        }));
    }
    events
}

#[test]
fn compiler_hotspot_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Compiler Hotspot Optimization Campaign Contract (`bd-mjh3.6.2`)",
        "## Compiler Hotspot Targets",
        "## EV Scoring Contract",
        "## Gain Attribution Contract",
        "## Structured Log Contract",
        "./scripts/run_compiler_hotspot_optimization_campaign.sh ci",
        "./scripts/e2e/compiler_hotspot_optimization_campaign_replay.sh",
    ] {
        assert!(doc.contains(section), "missing doc section: {section}");
    }
}

#[test]
fn compiler_hotspot_fixture_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.compiler-hotspot-optimization-campaign.v1"
    );
    assert_eq!(fixture.campaign_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.compiler-hotspot-telemetry.v1"
    );
    assert!(!fixture.campaign_runs.is_empty());
    assert_eq!(fixture.campaign_runs.len(), 4);

    let required_keys: BTreeSet<&str> = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "schema_version",
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
}

#[test]
fn compiler_hotspot_campaigns_are_profile_justified_and_single_lever() {
    let fixture = load_fixture();

    for run in &fixture.campaign_runs {
        assert!(!run.campaign_id.trim().is_empty());
        assert!(!run.lever_id.trim().is_empty());
        assert!(!run.lever_category.trim().is_empty());
        assert!(!run.commit.trim().is_empty());
        assert!(!run.run_id.trim().is_empty());
        assert!(!run.generated_at_utc.trim().is_empty());
        assert!(!run.attribution_note.trim().is_empty());
        assert!(!run.rollback_plan_ref.trim().is_empty());
        assert!(!run.replay_command.trim().is_empty());
        assert!(!run.artifact_manifest.trim().is_empty());
        assert!(!run.artifact_report.trim().is_empty());
        assert!(run.hotspot.baseline_share_millionths > 0);
        assert!(run.hotspot.baseline_share_millionths <= 1_000_000);
        assert!(!run.hotspot.hotspot_id.trim().is_empty());
        assert!(!run.hotspot.phase.trim().is_empty());
        assert!(!run.hotspot.baseline_profile_ref.trim().is_empty());
        assert!(run.ev_inputs.effort > 0);
        assert!(run.ev_inputs.friction > 0);
        assert!(!run.isomorphism_proof.proof_method.trim().is_empty());
        assert!(
            !run.isomorphism_proof
                .verification_contract_ref
                .trim()
                .is_empty()
        );
        assert_eq!(run.isomorphism_proof.drift_status, "no_drift");

        let mut categories = BTreeSet::new();
        for path in &run.changed_paths {
            let category = classify_compiler_lever(path)
                .unwrap_or_else(|| panic!("unclassified compiler path `{path}`"));
            categories.insert(category);
        }
        assert_eq!(
            categories.len(),
            1,
            "campaign {} must remain single-lever",
            run.campaign_id
        );
    }
}

#[test]
fn compiler_hotspot_ev_and_gain_rankings_match_fixture() {
    let fixture = load_fixture();
    let results = compute_campaign_results(&fixture);
    assert_eq!(results.len(), fixture.campaign_runs.len());

    for run in &fixture.campaign_runs {
        let measured_ev = ev_score_millionths(&run.ev_inputs);
        assert_eq!(measured_ev, run.expected_ev_score_millionths);
        let measured_gain = campaign_gain_millionths(run);
        assert_eq!(measured_gain, run.expected_gain_millionths);
    }

    assert_eq!(rank_by_ev(&results), fixture.expected_ev_ranking);
    assert_eq!(rank_by_gain(&results), fixture.expected_gain_ranking);
    assert_eq!(
        selected_campaign(&results),
        fixture.expected_selected_campaign
    );
}

#[test]
fn compiler_hotspot_events_and_replay_contract_are_deterministic() {
    let fixture = load_fixture();
    let events = emit_structured_events(&compute_campaign_results(&fixture));
    assert_eq!(events.len(), fixture.campaign_runs.len());
    for event in events {
        for key in [
            "schema_version",
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
        ] {
            assert!(event.get(key).is_some(), "missing event key `{key}`");
        }
    }

    let scenario_kinds = fixture
        .cross_subsystem_replay_scenarios
        .iter()
        .map(|scenario| scenario.scenario_kind.as_str())
        .collect::<BTreeSet<_>>();
    assert!(scenario_kinds.contains("normal"));
    assert!(scenario_kinds.contains("adversarial"));
    assert!(scenario_kinds.contains("recovery"));
    for scenario in &fixture.cross_subsystem_replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(!scenario.replay_command.trim().is_empty());
        assert!(!scenario.expected_outcome.trim().is_empty());
        if scenario.scenario_kind == "adversarial" {
            assert!(
                !scenario.expected_pass,
                "adversarial scenario should be fail-closed"
            );
        }
    }
}
