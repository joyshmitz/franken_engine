use std::{collections::BTreeSet, fs, path::Path};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserMode, ParserOptions};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MeasurementWindow {
    warmup_iterations: u32,
    measurement_iterations: u32,
    replicates: u32,
    max_relative_stdev_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct CorpusTier {
    tier_id: String,
    description: String,
    min_cases: u32,
    max_cases: u32,
    release_required: bool,
}

#[derive(Debug, Deserialize)]
struct BenchmarkCase {
    case_id: String,
    tier_id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_semantic_class: String,
}

#[derive(Debug, Deserialize)]
struct ParserBenchmarkProtocolFixture {
    schema_version: String,
    protocol_version: String,
    parser_mode: String,
    deterministic_environment_contract: String,
    measurement_window: MeasurementWindow,
    corpus_tiers: Vec<CorpusTier>,
    metrics: Vec<String>,
    structured_event_keys: Vec<String>,
    runner_commands: std::collections::BTreeMap<String, String>,
    benchmark_cases: Vec<BenchmarkCase>,
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown goal: {other}"),
    }
}

fn load_fixture() -> ParserBenchmarkProtocolFixture {
    let fixture_path = Path::new("tests/fixtures/parser_benchmark_protocol_v1.json");
    let bytes = fs::read(fixture_path).expect("read parser benchmark protocol fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser benchmark protocol fixture")
}

fn load_doc() -> String {
    let doc_path = Path::new("../../docs/PARSER_BENCHMARK_PROTOCOL.md");
    fs::read_to_string(doc_path).expect("read parser benchmark protocol doc")
}

#[test]
fn parser_benchmark_protocol_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "## Scope",
        "## Contract Version",
        "## Corpus Tier Model (Normative)",
        "## Workload Contract",
        "## Measurement Window Contract",
        "## Required Metric Families",
        "## Structured Event Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
        "## Operator Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "parser benchmark protocol doc missing section: {section}"
        );
    }
}

#[test]
fn fixture_declares_expected_protocol_contract_versions() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-benchmark-protocol.v1"
    );
    assert_eq!(fixture.protocol_version, "1.0.0");
    assert_eq!(fixture.parser_mode, ParserMode::ScalarReference.as_str());
    assert_eq!(
        fixture.deterministic_environment_contract,
        "franken-engine.parser-frontier.env-contract.v1"
    );
}

#[test]
fn fixture_measurement_window_is_nonzero_and_ordered() {
    let fixture = load_fixture();
    let w = fixture.measurement_window;
    assert!(w.warmup_iterations > 0);
    assert!(w.measurement_iterations > 0);
    assert!(w.replicates > 0);
    assert!(
        w.measurement_iterations >= w.warmup_iterations,
        "measurement iterations should not be below warmup iterations"
    );
    assert!(w.max_relative_stdev_millionths > 0);
}

#[test]
fn fixture_contains_all_required_corpus_tiers() {
    let fixture = load_fixture();
    assert!(
        !fixture.corpus_tiers.is_empty(),
        "corpus tier list must not be empty"
    );

    let expected: BTreeSet<&str> = ["smoke", "core", "stress", "adversarial"]
        .into_iter()
        .collect();
    let mut seen = BTreeSet::new();
    for tier in &fixture.corpus_tiers {
        assert!(!tier.description.trim().is_empty());
        assert!(tier.min_cases > 0);
        assert!(tier.max_cases >= tier.min_cases);
        assert!(tier.release_required);
        let inserted = seen.insert(tier.tier_id.as_str());
        assert!(inserted, "duplicate tier id: {}", tier.tier_id);
    }
    assert_eq!(seen, expected);
}

#[test]
fn fixture_runner_commands_are_rch_gate_entrypoints() {
    let fixture = load_fixture();
    for mode in ["check", "test", "clippy", "ci"] {
        let command = fixture
            .runner_commands
            .get(mode)
            .unwrap_or_else(|| panic!("missing runner command for mode `{mode}`"));
        assert!(
            command.starts_with("./scripts/run_parser_benchmark_protocol.sh "),
            "unexpected runner command for {mode}: {command}"
        );
    }
}

#[test]
fn fixture_declares_required_metric_and_event_keys() {
    let fixture = load_fixture();

    let required_metrics: BTreeSet<&str> = [
        "throughput_sources_per_second",
        "latency_ns_p50",
        "latency_ns_p95",
        "latency_ns_p99",
        "bytes_per_source_avg",
        "tokens_per_source_avg",
        "semantic_hash_stability_rate",
    ]
    .into_iter()
    .collect();
    let metrics: BTreeSet<&str> = fixture.metrics.iter().map(String::as_str).collect();
    assert_eq!(metrics, required_metrics);

    let required_event_keys: BTreeSet<&str> = [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let event_keys: BTreeSet<&str> = fixture
        .structured_event_keys
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(event_keys, required_event_keys);
}

#[test]
fn benchmark_cases_are_parseable_and_reference_known_tiers() {
    let fixture = load_fixture();
    let tier_ids: BTreeSet<&str> = fixture
        .corpus_tiers
        .iter()
        .map(|tier| tier.tier_id.as_str())
        .collect();
    assert!(
        !fixture.benchmark_cases.is_empty(),
        "benchmark case list must not be empty"
    );

    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let mut case_ids = BTreeSet::new();
    for case in &fixture.benchmark_cases {
        assert!(!case.family_id.trim().is_empty());
        assert!(!case.expected_semantic_class.trim().is_empty());
        assert!(
            tier_ids.contains(case.tier_id.as_str()),
            "unknown tier for case {}: {}",
            case.case_id,
            case.tier_id
        );
        let inserted = case_ids.insert(case.case_id.as_str());
        assert!(inserted, "duplicate case id: {}", case.case_id);

        parser
            .parse_with_options(
                case.source.as_str(),
                parse_goal(case.goal.as_str()),
                &options,
            )
            .unwrap_or_else(|error| panic!("case `{}` failed parse: {error}", case.case_id));
    }
}
