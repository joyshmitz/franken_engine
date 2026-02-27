use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseErrorCode, ParseEventKind, ParseEventMaterializationErrorCode,
    ParserOptions,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    command: String,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EquivalenceCase {
    case_id: String,
    goal: String,
    source: String,
    tamper_kind: String,
    expected_parse_error_code: Option<String>,
    expected_materialization_error_code: Option<String>,
    expect_statement_count: usize,
    expect_hash_parity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserEventAstEquivalenceFixture {
    schema_version: String,
    contract_version: String,
    required_log_keys: Vec<String>,
    replay_command: String,
    cases: Vec<EquivalenceCase>,
    replay_scenarios: Vec<ReplayScenario>,
}

fn load_fixture() -> ParserEventAstEquivalenceFixture {
    let path = Path::new("tests/fixtures/parser_event_ast_equivalence_v1.json");
    let bytes = fs::read(path).expect("read parser event ast equivalence fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser event ast equivalence fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md");
    fs::read_to_string(path).expect("read parser event ast equivalence contract doc")
}

fn parse_goal(goal: &str) -> ParseGoal {
    match goal {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unsupported fixture goal: {other}"),
    }
}

fn parse_error_code(code: &str) -> ParseErrorCode {
    match code {
        "empty_source" => ParseErrorCode::EmptySource,
        "invalid_goal" => ParseErrorCode::InvalidGoal,
        "unsupported_syntax" => ParseErrorCode::UnsupportedSyntax,
        "io_read_failed" => ParseErrorCode::IoReadFailed,
        "invalid_utf8" => ParseErrorCode::InvalidUtf8,
        "source_too_large" => ParseErrorCode::SourceTooLarge,
        "budget_exceeded" => ParseErrorCode::BudgetExceeded,
        other => panic!("unsupported parse error code in fixture: {other}"),
    }
}

fn materialization_error_code(code: &str) -> ParseEventMaterializationErrorCode {
    match code {
        "parse_failed_event_stream" => ParseEventMaterializationErrorCode::ParseFailedEventStream,
        "statement_hash_mismatch" => ParseEventMaterializationErrorCode::StatementHashMismatch,
        "statement_count_mismatch" => ParseEventMaterializationErrorCode::StatementCountMismatch,
        "statement_index_mismatch" => ParseEventMaterializationErrorCode::StatementIndexMismatch,
        "statement_kind_mismatch" => ParseEventMaterializationErrorCode::StatementKindMismatch,
        "statement_span_mismatch" => ParseEventMaterializationErrorCode::StatementSpanMismatch,
        "source_hash_mismatch" => ParseEventMaterializationErrorCode::SourceHashMismatch,
        "ast_hash_mismatch" => ParseEventMaterializationErrorCode::AstHashMismatch,
        "missing_parse_started" => ParseEventMaterializationErrorCode::MissingParseStarted,
        "missing_parse_completed" => ParseEventMaterializationErrorCode::MissingParseCompleted,
        "invalid_event_sequence" => ParseEventMaterializationErrorCode::InvalidEventSequence,
        "goal_mismatch" => ParseEventMaterializationErrorCode::GoalMismatch,
        "mode_mismatch" => ParseEventMaterializationErrorCode::ModeMismatch,
        "inconsistent_event_envelope" => {
            ParseEventMaterializationErrorCode::InconsistentEventEnvelope
        }
        "source_parse_failed" => ParseEventMaterializationErrorCode::SourceParseFailed,
        "unsupported_contract_version" => {
            ParseEventMaterializationErrorCode::UnsupportedContractVersion
        }
        "unsupported_schema_version" => {
            ParseEventMaterializationErrorCode::UnsupportedSchemaVersion
        }
        other => panic!("unsupported materialization error code in fixture: {other}"),
    }
}

fn tamper_statement_hash_if_requested(
    case: &EquivalenceCase,
    event_ir: &mut frankenengine_engine::parser::ParseEventIr,
) {
    if case.tamper_kind != "statement_hash" {
        return;
    }

    let statement_event = event_ir
        .events
        .iter_mut()
        .find(|event| event.kind == ParseEventKind::StatementParsed)
        .expect("statement_hash tamper requires a statement event");

    statement_event.payload_hash =
        Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
}

fn emit_structured_events(fixture: &ParserEventAstEquivalenceFixture) -> Vec<Value> {
    fixture
        .cases
        .iter()
        .map(|case| {
            let outcome = if case.expected_materialization_error_code.is_some() {
                "fail"
            } else {
                "pass"
            };
            let error_code = case
                .expected_materialization_error_code
                .clone()
                .or_else(|| case.expected_parse_error_code.clone());

            json!({
                "schema_version": "franken-engine.parser-event-ast-equivalence.event.v1",
                "trace_id": format!("trace-parser-event-ast-equivalence-{}", case.case_id),
                "decision_id": format!("decision-parser-event-ast-equivalence-{}", case.case_id),
                "policy_id": "policy-parser-event-ast-equivalence-v1",
                "component": "parser_event_ast_equivalence_gate",
                "event": "scenario_evaluated",
                "scenario_id": case.case_id,
                "outcome": outcome,
                "error_code": error_code,
                "replay_command": format!(
                    "PARSER_EVENT_AST_EQUIVALENCE_SCENARIO={} ./scripts/run_parser_event_ast_equivalence.sh test",
                    if case.expect_hash_parity { "parity" } else { "replay" }
                )
            })
        })
        .collect()
}

#[test]
fn parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    for case in &fixture.cases {
        if !case.expect_hash_parity || case.tamper_kind != "none" {
            continue;
        }

        let goal = parse_goal(&case.goal);
        let (parse_result, event_ir) =
            parser.parse_with_event_ir(case.source.as_str(), goal, &options);
        let syntax_tree = parse_result.expect("expected successful parse for parity case");
        let materialized = event_ir
            .materialize_from_source(case.source.as_str(), &options)
            .expect("expected successful materialization for parity case");

        assert!(event_ir.canonical_hash().starts_with("sha256:"));
        assert_eq!(
            materialized.statement_nodes.len(),
            case.expect_statement_count
        );
        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            syntax_tree.canonical_hash()
        );

        let (second_result, second_event_ir) =
            parser.parse_with_event_ir(case.source.as_str(), goal, &options);
        let second_syntax_tree = second_result.expect("expected successful second parse");
        let second_materialized = second_event_ir
            .materialize_from_source(case.source.as_str(), &options)
            .expect("expected successful second materialization");

        assert_eq!(event_ir.canonical_hash(), second_event_ir.canonical_hash());
        assert_eq!(materialized.root_node_id, second_materialized.root_node_id);
        assert_eq!(
            materialized.statement_nodes,
            second_materialized.statement_nodes
        );
        assert_eq!(
            second_materialized.syntax_tree.canonical_hash(),
            second_syntax_tree.canonical_hash()
        );
        assert_eq!(
            materialized.canonical_hash(),
            second_materialized.canonical_hash()
        );
    }
}

#[test]
fn parser_event_ast_equivalence_failure_case_has_replayable_error_codes() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let case = fixture
        .cases
        .iter()
        .find(|case| case.case_id == "empty_source_failure_contract")
        .expect("fixture must include empty_source_failure_contract case");

    let goal = parse_goal(&case.goal);
    let (first_parse, first_event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    let first_parse_err = first_parse.expect_err("empty source should fail parse");
    assert_eq!(
        first_parse_err.code,
        parse_error_code(
            case.expected_parse_error_code
                .as_deref()
                .expect("expected parse error code")
        )
    );

    let first_materialize_err = first_event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("empty-source event stream should fail materialization deterministically");
    assert_eq!(
        first_materialize_err.code,
        materialization_error_code(
            case.expected_materialization_error_code
                .as_deref()
                .expect("expected materialization error code")
        )
    );

    let (second_parse, second_event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    let second_parse_err = second_parse.expect_err("second empty source parse should fail");
    let second_materialize_err = second_event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("second empty-source materialization should fail");

    assert_eq!(first_parse_err.code, second_parse_err.code);
    assert_eq!(first_materialize_err.code, second_materialize_err.code);
    assert_eq!(
        first_event_ir.canonical_hash(),
        second_event_ir.canonical_hash()
    );
    assert_eq!(case.expect_statement_count, 0);
}

#[test]
fn parser_event_ast_equivalence_tamper_detection_is_deterministic() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let case = fixture
        .cases
        .iter()
        .find(|case| case.case_id == "tampered_statement_payload_hash")
        .expect("fixture must include tampered_statement_payload_hash case");
    let goal = parse_goal(&case.goal);

    let (parse_result, mut event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    parse_result.expect("tamper case baseline parse should succeed");
    tamper_statement_hash_if_requested(case, &mut event_ir);

    let first_err = event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("tampered statement hash must fail materialization");
    assert_eq!(
        first_err.code,
        materialization_error_code(
            case.expected_materialization_error_code
                .as_deref()
                .expect("expected materialization error code")
        )
    );

    let (second_parse_result, mut second_event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    second_parse_result.expect("second tamper baseline parse should succeed");
    tamper_statement_hash_if_requested(case, &mut second_event_ir);

    let second_err = second_event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("second tampered statement hash must fail materialization");

    assert_eq!(first_err.code, second_err.code);
    assert_eq!(first_err.sequence, second_err.sequence);
}

#[test]
fn parser_event_ast_equivalence_replay_scenarios_are_deterministic() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.replay_command,
        "./scripts/e2e/parser_event_ast_equivalence_replay.sh"
    );

    let mut scenario_ids = fixture
        .replay_scenarios
        .iter()
        .map(|scenario| scenario.scenario_id.as_str())
        .collect::<Vec<_>>();
    scenario_ids.sort_unstable();
    assert_eq!(scenario_ids, ["full", "malformed", "parity", "replay", "tamper"]);

    for scenario in &fixture.replay_scenarios {
        assert_eq!(scenario.expected_outcome, "pass");
        assert!(
            scenario
                .command
                .contains("./scripts/run_parser_event_ast_equivalence.sh test")
        );
        assert!(
            scenario
                .command
                .starts_with("PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=")
        );
        assert!(
            scenario.command.contains(&format!(
                "PARSER_EVENT_AST_EQUIVALENCE_SCENARIO={}",
                scenario.scenario_id
            )),
            "scenario command must encode its own scenario_id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_event_ast_equivalence_contract_doc_and_logs_are_well_formed() {
    let fixture = load_fixture();
    let doc = load_doc();

    assert!(doc.contains("bd-2mds.1.4.4.1"));
    assert!(doc.contains("./scripts/run_parser_event_ast_equivalence.sh ci"));
    assert!(doc.contains("./scripts/e2e/parser_event_ast_equivalence_replay.sh"));
    assert!(doc.contains("artifacts/parser_event_ast_equivalence/<timestamp>/run_manifest.json"));

    let events = emit_structured_events(&fixture);
    assert_eq!(events.len(), fixture.cases.len());

    for event in events {
        for key in &fixture.required_log_keys {
            let value = event
                .get(key)
                .unwrap_or_else(|| panic!("missing required key in event: {key}"));
            if key == "error_code" {
                assert!(value.is_null() || value.as_str().is_some());
            } else {
                assert!(value.as_str().is_some_and(|text| !text.is_empty()));
            }
        }

        let schema_version = event
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be a non-empty string");
        assert!(schema_version.starts_with("franken-engine.parser"));
    }
}
