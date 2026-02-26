use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures_dir() -> PathBuf {
    repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/fixtures")
}

fn traces_dir() -> PathBuf {
    repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces")
}

fn list_json_files(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|err| panic!("failed to read dir entry: {err}"))
                .path()
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
        .collect();
    files.sort();
    files
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct CorpusContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    corpus: CorpusContractCorpus,
    determinism_contract: DeterminismContract,
    failure_policy: FailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CorpusContractCorpus {
    fixtures_dir: String,
    traces_dir: String,
    minimum_fixture_count: usize,
    required_focus_tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DeterminismContract {
    fixture_schema_version: String,
    trace_schema_version: String,
    require_stable_fixture_ref_and_scenario_id: bool,
    require_monotonic_event_sequence: bool,
    require_monotonic_event_timing_us: bool,
}

#[derive(Debug, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
    block_on_missing_fixture: bool,
    block_on_trace_mismatch: bool,
    block_on_schema_drift: bool,
}

#[derive(Debug, Deserialize)]
struct FixtureSpec {
    schema_version: String,
    scenario_id: String,
    fixture_ref: String,
    runtime_mode: String,
    semantic_focus: Vec<String>,
    stimulus: Vec<StimulusStep>,
    expected_observable: Vec<String>,
    component_source: String,
}

#[derive(Debug, Deserialize)]
struct StimulusStep {
    step: String,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct ObservableTrace {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    scenario_id: String,
    fixture_ref: String,
    seed: u64,
    events: Vec<TraceEvent>,
    outcome: String,
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TraceEvent {
    seq: u64,
    phase: String,
    actor: String,
    event: String,
    decision_path: String,
    timing_us: u64,
    outcome: String,
}

#[test]
fn frx_02_1_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_CANONICAL_REACT_BEHAVIOR_CORPUS_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Canonical React Behavior Corpus v1",
        "## Scope",
        "## Corpus Layout",
        "## Determinism and Replay Contract",
        "## Observable Trace Contract",
        "## CI Gate and Failure Policy",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing doc section in {}: {section}",
            path.display()
        );
    }

    let doc_lower = doc.to_ascii_lowercase();
    for phrase in [
        "hooks",
        "concurrent",
        "suspense",
        "hydration",
        "error boundary",
        "portal",
        "fail-closed",
        "deterministic",
    ] {
        assert!(
            doc_lower.contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_02_1_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&path);

    assert_eq!(
        contract.schema_version,
        "frx.canonical-react-behavior-corpus.contract.v1"
    );
    assert_eq!(contract.bead_id, "bd-mjh3.2.1");
    assert_eq!(contract.generated_by, "bd-mjh3.2.1");

    assert_eq!(
        contract.corpus.fixtures_dir,
        "crates/franken-engine/tests/conformance/frx_react_corpus/fixtures"
    );
    assert_eq!(
        contract.corpus.traces_dir,
        "crates/franken-engine/tests/conformance/frx_react_corpus/traces"
    );
    assert!(
        contract.corpus.minimum_fixture_count >= 10,
        "minimum fixture count should enforce high-risk semantic coverage"
    );

    assert_eq!(
        contract.determinism_contract.fixture_schema_version,
        "frx.react.fixture.v1"
    );
    assert_eq!(
        contract.determinism_contract.trace_schema_version,
        "frx.react.observable.trace.v1"
    );
    assert!(
        contract
            .determinism_contract
            .require_stable_fixture_ref_and_scenario_id
    );
    assert!(
        contract
            .determinism_contract
            .require_monotonic_event_sequence
    );
    assert!(
        contract
            .determinism_contract
            .require_monotonic_event_timing_us
    );

    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        "FE-FRX-02-1-CORPUS-GATE-0001"
    );
    assert!(contract.failure_policy.block_on_missing_fixture);
    assert!(contract.failure_policy.block_on_trace_mismatch);
    assert!(contract.failure_policy.block_on_schema_drift);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_frx_canonical_react_behavior_corpus_suite.sh ci")),
        "operator verification must include ci replay command"
    );
}

#[test]
fn frx_02_1_fixture_corpus_matches_contract_and_risk_coverage() {
    let contract_path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&contract_path);

    let files = list_json_files(&fixtures_dir(), ".fixture.json");
    assert!(
        files.len() >= contract.corpus.minimum_fixture_count,
        "fixture count {} below contract minimum {}",
        files.len(),
        contract.corpus.minimum_fixture_count
    );

    let mut seen_fixture_refs = BTreeSet::new();
    let mut seen_scenarios = BTreeSet::new();
    let mut aggregated_focus_tags = BTreeSet::new();

    for path in files {
        let fixture: FixtureSpec = load_json(&path);
        let name = path
            .file_name()
            .and_then(|entry| entry.to_str())
            .unwrap_or_else(|| panic!("invalid fixture filename {}", path.display()));
        let expected_ref = name
            .strip_suffix(".fixture.json")
            .unwrap_or_else(|| panic!("unexpected fixture suffix {}", path.display()));

        assert_eq!(
            fixture.schema_version,
            contract.determinism_contract.fixture_schema_version
        );
        assert_eq!(
            fixture.fixture_ref, expected_ref,
            "fixture_ref should match fixture filename stem for deterministic indexing"
        );
        assert!(!fixture.scenario_id.is_empty());
        assert!(
            seen_fixture_refs.insert(fixture.fixture_ref.clone()),
            "duplicate fixture_ref {}",
            fixture.fixture_ref
        );
        assert!(
            seen_scenarios.insert(fixture.scenario_id.clone()),
            "duplicate scenario_id {}",
            fixture.scenario_id
        );

        assert!(
            !fixture.semantic_focus.is_empty(),
            "semantic_focus cannot be empty"
        );
        for tag in fixture.semantic_focus {
            assert!(
                !tag.trim().is_empty(),
                "semantic_focus tags must be non-empty"
            );
            aggregated_focus_tags.insert(tag);
        }

        assert!(!fixture.stimulus.is_empty(), "stimulus cannot be empty");
        for stimulus in fixture.stimulus {
            assert!(
                !stimulus.step.trim().is_empty(),
                "stimulus step must be present"
            );
            assert!(
                !stimulus.payload.trim().is_empty(),
                "stimulus payload must be present"
            );
        }

        assert!(
            !fixture.expected_observable.is_empty(),
            "expected_observable cannot be empty"
        );
        assert!(
            !fixture.component_source.trim().is_empty(),
            "component_source must be populated"
        );
        assert!(
            matches!(
                fixture.runtime_mode.as_str(),
                "client" | "server" | "hydrate" | "hydration"
            ),
            "runtime_mode must be one of client/server/hydrate/hydration"
        );
    }

    for required_tag in &contract.corpus.required_focus_tags {
        assert!(
            aggregated_focus_tags.contains(required_tag),
            "required focus tag missing from fixture corpus: {required_tag}"
        );
    }
}

#[test]
fn frx_02_1_traces_are_versioned_and_replay_deterministic() {
    let contract_path = repo_root().join("docs/frx_canonical_react_behavior_corpus_v1.json");
    let contract: CorpusContract = load_json(&contract_path);

    let fixture_files = list_json_files(&fixtures_dir(), ".fixture.json");
    let trace_files = list_json_files(&traces_dir(), ".trace.json");
    assert_eq!(
        trace_files.len(),
        fixture_files.len(),
        "fixture/trace cardinality mismatch"
    );

    let mut fixture_index: BTreeMap<String, String> = BTreeMap::new();
    for path in fixture_files {
        let fixture: FixtureSpec = load_json(&path);
        fixture_index.insert(fixture.fixture_ref, fixture.scenario_id);
    }

    let mut seen_trace_ids = BTreeSet::new();
    for path in trace_files {
        let trace: ObservableTrace = load_json(&path);
        assert_eq!(
            trace.schema_version,
            contract.determinism_contract.trace_schema_version
        );
        assert_eq!(trace.component, "frx_react_corpus");
        assert!(
            trace.trace_id.starts_with("trace-frx-react-"),
            "trace_id should carry deterministic frx-react prefix"
        );
        assert!(
            trace.decision_id.starts_with("decision-frx-react-"),
            "decision_id should carry deterministic frx-react prefix"
        );
        assert!(
            trace.policy_id.starts_with("policy-frx-react-corpus-v"),
            "policy_id should carry policy version prefix"
        );
        assert!(
            trace.seed > 0,
            "seed must be non-zero for deterministic replay"
        );
        assert!(
            seen_trace_ids.insert(trace.trace_id.clone()),
            "duplicate trace_id"
        );

        let expected_scenario = fixture_index.get(&trace.fixture_ref).unwrap_or_else(|| {
            panic!(
                "trace references missing fixture_ref: {}",
                trace.fixture_ref
            )
        });
        assert_eq!(&trace.scenario_id, expected_scenario);

        assert!(!trace.events.is_empty(), "trace events cannot be empty");

        let mut prev_seq = 0_u64;
        let mut prev_timing = 0_u64;
        for event in trace.events {
            assert!(
                event.seq > prev_seq,
                "event seq must be strictly increasing"
            );
            assert!(
                event.timing_us >= prev_timing,
                "event timing_us must be monotonic"
            );
            assert!(
                !event.phase.trim().is_empty(),
                "event.phase must be populated"
            );
            assert!(
                !event.actor.trim().is_empty(),
                "event.actor must be populated"
            );
            assert!(
                !event.event.trim().is_empty(),
                "event.event must be populated"
            );
            assert!(
                !event.decision_path.trim().is_empty(),
                "event.decision_path must be populated"
            );
            assert!(
                !event.outcome.trim().is_empty(),
                "event.outcome must be populated"
            );
            prev_seq = event.seq;
            prev_timing = event.timing_us;
        }

        if trace.outcome == "pass" {
            assert!(
                trace.error_code.is_none(),
                "pass traces should not carry error_code"
            );
        }
    }
}
