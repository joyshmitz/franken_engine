use std::{collections::BTreeSet, fs, path::Path};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct HermeticWrapperFixture {
    schema_version: String,
    wrapper_id: String,
    bead_id: String,
    deterministic_env_schema_version: String,
    required_wrapper_modes: Vec<String>,
    runner_commands: std::collections::BTreeMap<String, String>,
    required_manifest_keys: Vec<String>,
    required_environment_keys: Vec<String>,
    required_event_keys: Vec<String>,
    replay_command_template: String,
}

fn load_fixture() -> HermeticWrapperFixture {
    let fixture_path = Path::new("tests/fixtures/parser_hermetic_env_manifest_v1.json");
    let bytes = fs::read(fixture_path).expect("read parser hermetic env fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser hermetic env fixture")
}

fn load_env_contract_doc() -> String {
    let doc_path = Path::new("../../docs/PARSER_FRONTIER_ENV_CONTRACT.md");
    fs::read_to_string(doc_path).expect("read parser frontier env contract doc")
}

fn load_benchmark_wrapper_script() -> String {
    let script_path = Path::new("../../scripts/run_parser_benchmark_protocol.sh");
    fs::read_to_string(script_path).expect("read parser benchmark protocol script")
}

#[test]
fn parser_frontier_env_contract_doc_has_required_sections() {
    let doc = load_env_contract_doc();
    let required_sections = [
        "# Parser Frontier Deterministic Environment Contract",
        "## Scope",
        "## Contract Version",
        "## Required Controls",
        "## Manifest Requirements",
        "## Event Logging Requirements",
        "## Operator Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "env contract doc missing required section: {section}"
        );
    }
}

#[test]
fn fixture_declares_expected_contract_versions() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-hermetic-wrapper.manifest-contract.v1"
    );
    assert_eq!(fixture.wrapper_id, "parser_benchmark_protocol_gate");
    assert_eq!(fixture.bead_id, "bd-2mds.1.7.1");
    assert_eq!(
        fixture.deterministic_env_schema_version,
        "franken-engine.parser-frontier.env-contract.v1"
    );
}

#[test]
fn fixture_requires_expected_modes_and_runner_commands() {
    let fixture = load_fixture();

    let expected_modes: BTreeSet<&str> = ["check", "test", "clippy", "ci"].into_iter().collect();
    let actual_modes: BTreeSet<&str> = fixture
        .required_wrapper_modes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_modes, expected_modes);

    for mode in expected_modes {
        let command = fixture
            .runner_commands
            .get(mode)
            .unwrap_or_else(|| panic!("missing runner command for mode `{mode}`"));
        assert!(
            command.starts_with("./scripts/run_parser_benchmark_protocol.sh "),
            "unexpected command for mode `{mode}`: {command}"
        );
    }
}

#[test]
fn fixture_declares_required_manifest_environment_and_event_keys() {
    let fixture = load_fixture();

    let required_manifest: BTreeSet<&str> = [
        "schema_version",
        "bead_id",
        "deterministic_env_schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "replay_command",
        "deterministic_environment",
        "commands",
        "artifacts",
        "operator_verification",
    ]
    .into_iter()
    .collect();
    let manifest_keys: BTreeSet<&str> = fixture
        .required_manifest_keys
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(manifest_keys, required_manifest);

    let required_environment: BTreeSet<&str> = [
        "timezone",
        "lang",
        "lc_all",
        "source_date_epoch",
        "rustc_version",
        "cargo_version",
        "rust_host",
        "cpu_fingerprint",
        "rustc_verbose_hash",
        "toolchain_fingerprint",
        "seed_transcript_checksum",
    ]
    .into_iter()
    .collect();
    let environment_keys: BTreeSet<&str> = fixture
        .required_environment_keys
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(environment_keys, required_environment);

    let required_event_keys: BTreeSet<&str> = [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "replay_command",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let event_keys: BTreeSet<&str> = fixture
        .required_event_keys
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(event_keys, required_event_keys);
}

#[test]
fn wrapper_script_embeds_hermetic_env_manifest_and_replay_fields() {
    let script = load_benchmark_wrapper_script();
    let required_markers = [
        "source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\"",
        "parser_frontier_bootstrap_env",
        "\"deterministic_env_schema_version\": \"franken-engine.parser-frontier.env-contract.v1\"",
        "parser_frontier_emit_manifest_environment_fields",
        "replay_command",
    ];
    for marker in required_markers {
        assert!(
            script.contains(marker),
            "wrapper script missing marker: {marker}"
        );
    }
}

#[test]
fn replay_template_is_one_command_entrypoint() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.replay_command_template,
        "./scripts/run_parser_benchmark_protocol.sh ci"
    );
}
