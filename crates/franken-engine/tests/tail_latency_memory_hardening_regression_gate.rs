use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TailMemoryBudgets {
    max_p95_ns: u64,
    max_p99_ns: u64,
    max_p999_ns: u64,
    max_cvar_ns: u64,
    max_peak_heap_bytes: u64,
    max_live_allocations_tail: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DecompositionLedgerNs {
    queueing: u64,
    service: u64,
    synchronization: u64,
    retries: u64,
    gc_allocator: u64,
    abi_boundary: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MetricVector {
    mean_latency_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    cvar_ns: u64,
    peak_heap_bytes: u64,
    live_allocations_tail: u64,
    throughput_ops_per_sec_millionths: u64,
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
    campaign_id: String,
    lever_id: String,
    lever_category: String,
    commit: String,
    run_id: String,
    generated_at_utc: String,
    changed_paths: Vec<String>,
    decomposition_ledger_ns: DecompositionLedgerNs,
    baseline_metrics: MetricVector,
    candidate_metrics: MetricVector,
    compatibility_invariant_ok: bool,
    ev_inputs: EvInputs,
    expected_ev_score_millionths: u64,
    expected_outcome: String,
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
    tail_memory_budgets: TailMemoryBudgets,
    required_log_keys: Vec<String>,
    campaign_runs: Vec<CampaignRun>,
    expected_selected_campaign: String,
    expected_fail_closed_campaigns: Vec<String>,
    cross_subsystem_replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CampaignDecision {
    campaign_id: String,
    ev_score_millionths: u64,
    outcome: String,
}

fn load_fixture() -> Fixture {
    let path = Path::new("tests/fixtures/tail_latency_memory_hardening_regression_gate_v1.json");
    let bytes = fs::read(path).expect("read tail-memory fixture");
    serde_json::from_slice(&bytes).expect("deserialize tail-memory fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/TAIL_LATENCY_MEMORY_HARDENING_REGRESSION_GATE.md");
    fs::read_to_string(path).expect("read tail-memory doc")
}

fn replay_script_path(command: &str) -> Option<PathBuf> {
    let script = command.split_whitespace().next()?;
    if !script.starts_with("./scripts/e2e/") || !script.ends_with(".sh") {
        return None;
    }
    Some(Path::new("../../").join(script.trim_start_matches("./")))
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

fn classify_tail_memory_lever(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("queue") {
        return Some("queueing");
    }
    if lower.contains("service") {
        return Some("service");
    }
    if lower.contains("sync") || lower.contains("lock") {
        return Some("synchronization");
    }
    if lower.contains("retry") {
        return Some("retries");
    }
    if lower.contains("gc") || lower.contains("allocator") {
        return Some("gc_allocator");
    }
    if lower.contains("abi") || lower.contains("bridge") {
        return Some("abi_boundary");
    }
    None
}

fn leverage_classification_is_one_family(paths: &[String]) -> bool {
    let families = paths
        .iter()
        .filter_map(|path| classify_tail_memory_lever(path.as_str()))
        .collect::<BTreeSet<_>>();
    families.len() == 1
}

fn breaches_budget(run: &CampaignRun, budgets: &TailMemoryBudgets) -> bool {
    run.candidate_metrics.p95_ns > budgets.max_p95_ns
        || run.candidate_metrics.p99_ns > budgets.max_p99_ns
        || run.candidate_metrics.p999_ns > budgets.max_p999_ns
        || run.candidate_metrics.cvar_ns > budgets.max_cvar_ns
        || run.candidate_metrics.peak_heap_bytes > budgets.max_peak_heap_bytes
        || run.candidate_metrics.live_allocations_tail > budgets.max_live_allocations_tail
}

fn central_metric_improved(run: &CampaignRun) -> bool {
    run.candidate_metrics.mean_latency_ns < run.baseline_metrics.mean_latency_ns
        || run.candidate_metrics.throughput_ops_per_sec_millionths
            > run.baseline_metrics.throughput_ops_per_sec_millionths
}

fn tail_or_memory_regressed(run: &CampaignRun) -> bool {
    run.candidate_metrics.p95_ns > run.baseline_metrics.p95_ns
        || run.candidate_metrics.p99_ns > run.baseline_metrics.p99_ns
        || run.candidate_metrics.p999_ns > run.baseline_metrics.p999_ns
        || run.candidate_metrics.cvar_ns > run.baseline_metrics.cvar_ns
        || run.candidate_metrics.peak_heap_bytes > run.baseline_metrics.peak_heap_bytes
        || run.candidate_metrics.live_allocations_tail > run.baseline_metrics.live_allocations_tail
}

fn evaluate_campaign(run: &CampaignRun, budgets: &TailMemoryBudgets) -> CampaignDecision {
    let ev = ev_score_millionths(&run.ev_inputs);
    let outcome = if breaches_budget(run, budgets)
        || !run.compatibility_invariant_ok
        || (central_metric_improved(run) && tail_or_memory_regressed(run))
    {
        "hold"
    } else {
        "promote"
    };

    CampaignDecision {
        campaign_id: run.campaign_id.clone(),
        ev_score_millionths: ev,
        outcome: outcome.to_string(),
    }
}

fn selected_campaign(decisions: &[CampaignDecision]) -> Option<String> {
    let mut promotable = decisions
        .iter()
        .filter(|decision| decision.outcome == "promote")
        .cloned()
        .collect::<Vec<_>>();
    promotable.sort_by(|left, right| {
        right
            .ev_score_millionths
            .cmp(&left.ev_score_millionths)
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    promotable.first().map(|entry| entry.campaign_id.clone())
}

fn emit_structured_events(decisions: &[CampaignDecision]) -> Vec<serde_json::Value> {
    decisions
        .iter()
        .map(|decision| {
            serde_json::json!({
                "schema_version": "franken-engine.tail-latency-memory.log-event.v1",
                "trace_id": "trace-tail-latency-memory-hardening-v1",
                "decision_id": format!("decision-{}", decision.campaign_id),
                "policy_id": "policy-tail-latency-memory-hardening-v1",
                "component": "tail_latency_memory_hardening_regression_gate",
                "event": "campaign_run_scored",
                "outcome": decision.outcome,
                "error_code": serde_json::Value::Null
            })
        })
        .collect()
}

#[test]
fn tail_memory_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Tail-Latency and Memory Hardening Regression Gate (`bd-mjh3.6.4`)",
        "## Tail Decomposition Ledger Contract",
        "## Tail-Risk and Memory Objectives",
        "## Fail-Closed Decision Policy",
        "## One-Lever Attribution Discipline",
        "## Structured Log Contract",
        "./scripts/run_tail_latency_memory_hardening_regression_gate.sh ci",
        "./scripts/e2e/tail_latency_memory_hardening_regression_gate_replay.sh",
    ] {
        assert!(doc.contains(section), "missing doc section: {section}");
    }
}

#[test]
fn fixture_is_well_formed_and_contractual() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.tail-latency-memory-hardening-regression-gate.v1"
    );
    assert_eq!(fixture.campaign_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.tail-memory-telemetry.v1"
    );

    let required_keys = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
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

    assert!(!fixture.campaign_runs.is_empty());
    for run in &fixture.campaign_runs {
        assert!(!run.campaign_id.trim().is_empty());
        assert!(!run.lever_id.trim().is_empty());
        assert!(!run.lever_category.trim().is_empty());
        assert!(!run.commit.trim().is_empty());
        assert!(!run.run_id.trim().is_empty());
        assert!(!run.generated_at_utc.trim().is_empty());
        assert!(!run.changed_paths.is_empty());
        assert!(!run.replay_command.trim().is_empty());
        assert!(!run.artifact_manifest.trim().is_empty());
        assert!(!run.artifact_report.trim().is_empty());
        assert!(run.ev_inputs.effort > 0);
        assert!(run.ev_inputs.friction > 0);

        let ledger = &run.decomposition_ledger_ns;
        let terms = [
            ledger.queueing,
            ledger.service,
            ledger.synchronization,
            ledger.retries,
            ledger.gc_allocator,
            ledger.abi_boundary,
        ];
        assert!(terms.iter().all(|term| *term > 0));
        assert!(
            leverage_classification_is_one_family(&run.changed_paths),
            "run must stay one-lever attributable: {}",
            run.campaign_id
        );
    }

    assert!(!fixture.cross_subsystem_replay_scenarios.is_empty());
}

#[test]
fn ev_scoring_and_fail_closed_outcomes_match_fixture() {
    let fixture = load_fixture();
    let decisions = fixture
        .campaign_runs
        .iter()
        .map(|run| evaluate_campaign(run, &fixture.tail_memory_budgets))
        .collect::<Vec<_>>();

    for (run, decision) in fixture.campaign_runs.iter().zip(decisions.iter()) {
        assert_eq!(decision.campaign_id, run.campaign_id);
        assert_eq!(
            decision.ev_score_millionths, run.expected_ev_score_millionths,
            "ev score mismatch for {}",
            run.campaign_id
        );
        assert_eq!(
            decision.outcome, run.expected_outcome,
            "gate outcome mismatch for {}",
            run.campaign_id
        );
    }

    let selected = selected_campaign(&decisions).expect("one campaign should be promotable");
    assert_eq!(selected, fixture.expected_selected_campaign);

    let fail_closed = decisions
        .iter()
        .filter(|decision| decision.outcome == "hold")
        .map(|decision| decision.campaign_id.clone())
        .collect::<BTreeSet<_>>();
    let expected_fail_closed = fixture
        .expected_fail_closed_campaigns
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(fail_closed, expected_fail_closed);
}

#[test]
fn replay_scenarios_reference_existing_wrapper_commands() {
    let fixture = load_fixture();
    for scenario in &fixture.cross_subsystem_replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(!scenario.scenario_kind.trim().is_empty());
        assert!(scenario.expected_pass);
        assert_eq!(scenario.expected_outcome, "pass");
        let script_path = replay_script_path(scenario.replay_command.as_str())
            .expect("replay command must use scripts/e2e wrapper");
        assert!(
            script_path.is_file(),
            "replay wrapper script does not exist: {}",
            script_path.display()
        );
    }
}

#[test]
fn structured_log_events_include_required_keys() {
    let fixture = load_fixture();
    let decisions = fixture
        .campaign_runs
        .iter()
        .map(|run| evaluate_campaign(run, &fixture.tail_memory_budgets))
        .collect::<Vec<_>>();
    let events = emit_structured_events(&decisions);

    assert_eq!(events.len(), fixture.campaign_runs.len());
    for event in events {
        for key in &fixture.required_log_keys {
            assert!(event.get(key).is_some(), "missing required key `{key}`");
        }
        assert!(
            event["schema_version"]
                .as_str()
                .expect("schema version string")
                .starts_with("franken-engine.tail-latency-memory"),
            "schema version prefix mismatch"
        );
    }
}
