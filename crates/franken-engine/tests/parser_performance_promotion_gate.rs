use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct BenchmarkRow {
    workload_id: String,
    corpus_id: String,
    peer_id: String,
    quantile: String,
    franken_score_millionths: i64,
    peer_score_millionths: i64,
    sample_count: u64,
    confidence_low_delta_millionths: i64,
    confidence_high_delta_millionths: i64,
    protocol_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvidenceVector {
    lane_id: String,
    status: String,
    artifact_manifest: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TelemetryArtifact {
    artifact_id: String,
    manifest_path: String,
    protocol_hash: String,
    reproducible: bool,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_blocked_pairs: Vec<String>,
    expected_failing_workload_ids: Vec<String>,
    expected_verified_pairs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_pass: bool,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserPerformancePromotionGateFixture {
    schema_version: String,
    gate_version: String,
    protocol_version: String,
    protocol_hash: String,
    required_peers: Vec<String>,
    required_quantiles: Vec<String>,
    minimum_delta_millionths_by_quantile: BTreeMap<String, i64>,
    required_evidence_lanes: Vec<String>,
    required_structured_log_keys: Vec<String>,
    evidence_vectors: Vec<EvidenceVector>,
    telemetry_artifacts: Vec<TelemetryArtifact>,
    benchmark_rows: Vec<BenchmarkRow>,
    expected_gate: ExpectedGate,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateEvaluation {
    outcome: String,
    blocked_pairs: Vec<String>,
    failing_workload_ids: Vec<String>,
    verified_pairs: usize,
}

fn load_fixture() -> ParserPerformancePromotionGateFixture {
    let path = Path::new("tests/fixtures/parser_performance_promotion_gate_v1.json");
    let bytes = fs::read(path).expect("read parser performance promotion fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser performance promotion fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_PERFORMANCE_PROMOTION_GATE.md");
    fs::read_to_string(path).expect("read parser performance promotion gate doc")
}

fn pair_key(peer_id: &str, quantile: &str) -> (String, String) {
    (peer_id.to_string(), quantile.to_string())
}

fn pair_blocker(peer_id: &str, quantile: &str, reason: &str) -> String {
    format!("{peer_id}:{quantile}:{reason}")
}

fn evaluate_gate(fixture: &ParserPerformancePromotionGateFixture) -> GateEvaluation {
    let mut blockers = BTreeSet::new();
    let mut failing_workloads = BTreeSet::new();

    let evidence_by_lane = fixture
        .evidence_vectors
        .iter()
        .map(|lane| (lane.lane_id.as_str(), lane.status.as_str()))
        .collect::<BTreeMap<_, _>>();

    for required_lane in &fixture.required_evidence_lanes {
        match evidence_by_lane.get(required_lane.as_str()) {
            Some(status) if *status == "pass" => {}
            Some(status) => {
                blockers.insert(format!("evidence_not_green:{required_lane}:{status}"));
            }
            None => {
                blockers.insert(format!("evidence_missing:{required_lane}"));
            }
        }
    }

    for artifact in &fixture.telemetry_artifacts {
        if artifact.protocol_hash != fixture.protocol_hash {
            blockers.insert(format!("telemetry_protocol_drift:{}", artifact.artifact_id));
        }
        if !artifact.reproducible {
            blockers.insert(format!(
                "telemetry_not_reproducible:{}",
                artifact.artifact_id
            ));
        }
    }

    let mut rows_by_pair = BTreeMap::<(String, String), Vec<&BenchmarkRow>>::new();
    for row in &fixture.benchmark_rows {
        rows_by_pair
            .entry(pair_key(row.peer_id.as_str(), row.quantile.as_str()))
            .or_default()
            .push(row);

        if row.protocol_hash != fixture.protocol_hash {
            blockers.insert(pair_blocker(
                row.peer_id.as_str(),
                row.quantile.as_str(),
                "protocol_drift",
            ));
            failing_workloads.insert(row.workload_id.clone());
        }

        if row.sample_count == 0 {
            blockers.insert(pair_blocker(
                row.peer_id.as_str(),
                row.quantile.as_str(),
                "sample_count_zero",
            ));
            failing_workloads.insert(row.workload_id.clone());
        }

        if row.confidence_low_delta_millionths > row.confidence_high_delta_millionths {
            blockers.insert(pair_blocker(
                row.peer_id.as_str(),
                row.quantile.as_str(),
                "invalid_confidence_interval",
            ));
            failing_workloads.insert(row.workload_id.clone());
        }
    }

    let mut verified_pairs = 0usize;
    for peer in &fixture.required_peers {
        for quantile in &fixture.required_quantiles {
            let pair = pair_key(peer.as_str(), quantile.as_str());
            let rows = rows_by_pair.get(&pair);
            let threshold = fixture
                .minimum_delta_millionths_by_quantile
                .get(quantile)
                .copied()
                .unwrap_or(0);

            let Some(rows) = rows else {
                blockers.insert(pair_blocker(peer, quantile, "missing_pair"));
                continue;
            };

            if rows.len() != 1 {
                blockers.insert(pair_blocker(peer, quantile, "duplicate_pair_rows"));
            }

            let row = rows[0];
            let delta = row
                .franken_score_millionths
                .saturating_sub(row.peer_score_millionths);

            if delta < threshold {
                blockers.insert(pair_blocker(peer, quantile, "delta_below_threshold"));
                failing_workloads.insert(row.workload_id.clone());
            }

            if row.confidence_low_delta_millionths <= 0 {
                blockers.insert(pair_blocker(peer, quantile, "non_reproducible_win"));
                failing_workloads.insert(row.workload_id.clone());
            }

            if row.sample_count > 0
                && row.confidence_low_delta_millionths <= row.confidence_high_delta_millionths
                && row.protocol_hash == fixture.protocol_hash
                && delta >= threshold
                && row.confidence_low_delta_millionths > 0
            {
                verified_pairs = verified_pairs.saturating_add(1);
            }
        }
    }

    let blocked_pairs = blockers.into_iter().collect::<Vec<_>>();
    let failing_workload_ids = failing_workloads.into_iter().collect::<Vec<_>>();

    let outcome = if blocked_pairs.is_empty() {
        "promote"
    } else {
        "hold"
    }
    .to_string();

    GateEvaluation {
        outcome,
        blocked_pairs,
        failing_workload_ids,
        verified_pairs,
    }
}

fn emit_structured_event(
    fixture: &ParserPerformancePromotionGateFixture,
    evaluation: &GateEvaluation,
) -> serde_json::Value {
    let corpus_inventory = fixture
        .benchmark_rows
        .iter()
        .map(|row| row.corpus_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let quantile_inventory = fixture.required_quantiles.to_vec();

    let replay_pointers = fixture
        .evidence_vectors
        .iter()
        .map(|lane| lane.replay_command.clone())
        .chain(
            fixture
                .telemetry_artifacts
                .iter()
                .map(|artifact| artifact.replay_command.clone()),
        )
        .chain(
            fixture
                .replay_scenarios
                .iter()
                .map(|scenario| scenario.replay_command.clone()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-parser-performance-promotion-gate-v1",
        "decision_id": "decision-parser-performance-promotion-gate-v1",
        "policy_id": "policy-parser-performance-promotion-gate-v1",
        "component": "parser_performance_promotion_gate",
        "event": "performance_gate_evaluated",
        "outcome": evaluation.outcome,
        "error_code": if evaluation.outcome == "promote" {
            serde_json::Value::Null
        } else {
            serde_json::Value::String("FE-PARSER-PERF-GATE-0001".to_string())
        },
        "blocked_pairs": evaluation.blocked_pairs,
        "failing_workload_ids": evaluation.failing_workload_ids,
        "corpus_inventory": corpus_inventory,
        "quantile_inventory": quantile_inventory,
        "replay_pointers": replay_pointers,
        "protocol_version": fixture.protocol_version,
        "protocol_hash": fixture.protocol_hash,
        "verified_pairs": evaluation.verified_pairs,
        "telemetry_manifest_paths": fixture
            .telemetry_artifacts
            .iter()
            .map(|artifact| artifact.manifest_path.clone())
            .collect::<Vec<_>>(),
        "evidence_manifests": fixture
            .evidence_vectors
            .iter()
            .map(|lane| lane.artifact_manifest.clone())
            .collect::<Vec<_>>()
    })
}

#[test]
fn parser_performance_doc_has_required_sections() {
    let doc = load_doc();

    for section in [
        "# Parser Performance Promotion Gate (`bd-2mds.1.8.3`)",
        "## Promotion Policy",
        "## Benchmark Protocol Requirements",
        "## Reproducibility and Confidence Semantics",
        "## Evidence Requirements",
        "## Structured Log Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
    ] {
        assert!(doc.contains(section), "missing section: {section}");
    }

    for command in [
        "./scripts/run_parser_performance_promotion_gate.sh ci",
        "./scripts/e2e/parser_performance_promotion_gate_replay.sh",
    ] {
        assert!(
            doc.contains(command),
            "missing command reference: {command}"
        );
    }
}

#[test]
fn parser_performance_fixture_contract_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-performance-promotion-gate.v1"
    );
    assert_eq!(fixture.gate_version, "1.0.0");
    assert!(!fixture.protocol_version.trim().is_empty());
    assert!(fixture.protocol_hash.starts_with("sha256:"));

    assert!(!fixture.required_peers.is_empty());
    assert!(!fixture.required_quantiles.is_empty());

    for quantile in &fixture.required_quantiles {
        assert!(
            fixture
                .minimum_delta_millionths_by_quantile
                .contains_key(quantile),
            "missing threshold for quantile: {quantile}"
        );
    }

    for row in &fixture.benchmark_rows {
        assert!(
            fixture.required_peers.contains(&row.peer_id),
            "benchmark row peer is undeclared: {}",
            row.peer_id
        );
        assert!(
            fixture.required_quantiles.contains(&row.quantile),
            "benchmark row quantile is undeclared: {}",
            row.quantile
        );
        assert!(row.sample_count > 0, "sample count must be > 0");
        assert!(
            row.confidence_low_delta_millionths <= row.confidence_high_delta_millionths,
            "invalid confidence interval for {}:{}",
            row.peer_id,
            row.quantile
        );
        assert_eq!(
            row.protocol_hash, fixture.protocol_hash,
            "row protocol hash drift for {}:{}",
            row.peer_id, row.quantile
        );
    }

    let pair_count = fixture.required_peers.len() * fixture.required_quantiles.len();
    assert_eq!(
        fixture.benchmark_rows.len(),
        pair_count,
        "fixture must declare one row per required peer/quantile pair"
    );
}

#[test]
fn parser_performance_gate_evaluation_matches_expected_contract() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    assert_eq!(evaluation.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(
        evaluation.blocked_pairs,
        fixture.expected_gate.expected_blocked_pairs
    );
    assert_eq!(
        evaluation.failing_workload_ids,
        fixture.expected_gate.expected_failing_workload_ids
    );
    assert_eq!(
        evaluation.verified_pairs,
        fixture.expected_gate.expected_verified_pairs
    );
}

#[test]
fn parser_performance_structured_event_has_required_keys() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);

    let object = event
        .as_object()
        .expect("structured event should serialize to object");

    for required_key in &fixture.required_structured_log_keys {
        assert!(
            object.contains_key(required_key),
            "missing structured log key: {required_key}"
        );
    }

    assert_eq!(
        object
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .expect("outcome string"),
        fixture.expected_gate.expected_outcome
    );
}

#[test]
fn parser_performance_replay_scenarios_align_with_gate_outcome() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    for scenario in &fixture.replay_scenarios {
        assert!(
            scenario
                .replay_command
                .contains("parser_performance_promotion_gate_replay.sh"),
            "replay scenario must use one-command replay wrapper: {}",
            scenario.scenario_id
        );

        assert!(
            scenario.expected_pass,
            "scenario should expect runnable replay"
        );
        assert_eq!(scenario.expected_outcome, evaluation.outcome);
    }
}
