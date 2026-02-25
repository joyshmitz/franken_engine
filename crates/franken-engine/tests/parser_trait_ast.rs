use std::fs;
use std::io::Cursor;

use frankenengine_engine::ast::{
    CANONICAL_AST_CONTRACT_VERSION, CANONICAL_AST_HASH_ALGORITHM, CANONICAL_AST_HASH_PREFIX,
    CANONICAL_AST_SCHEMA_VERSION, Expression, ParseGoal, Statement, SyntaxTree,
};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, PARSE_EVENT_IR_CONTRACT_VERSION,
    PARSE_EVENT_IR_HASH_ALGORITHM, PARSE_EVENT_IR_HASH_PREFIX, PARSE_EVENT_IR_SCHEMA_VERSION,
    PARSER_DIAGNOSTIC_HASH_ALGORITHM, PARSER_DIAGNOSTIC_HASH_PREFIX,
    PARSER_DIAGNOSTIC_SCHEMA_VERSION, PARSER_DIAGNOSTIC_TAXONOMY_VERSION, ParseBudgetKind,
    ParseDiagnosticEnvelope, ParseErrorCode, ParseEventIr, ParseEventKind, ParserBudget,
    ParserMode, ParserOptions, StreamInput,
};

#[test]
fn parser_goal_and_statement_hierarchy_are_emitted_deterministically() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("alpha;\n42;\n'hello';\nawait beta;\n", ParseGoal::Script)
        .expect("script parse should succeed");

    assert_eq!(tree.goal, ParseGoal::Script);
    assert_eq!(tree.body.len(), 4);
    assert!(matches!(
        &tree.body[0],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::Identifier(name) if name == "alpha")
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::NumericLiteral(42))
    ));
    assert!(matches!(
        &tree.body[2],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::StringLiteral(value) if value == "hello")
    ));
    assert!(matches!(
        &tree.body[3],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::Await(_))
    ));
}

#[test]
fn parser_accepts_stream_and_file_inputs_with_equal_canonical_hash() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;\n";

    let stream_tree = parser
        .parse(
            StreamInput::new(Cursor::new(source), "stdin"),
            ParseGoal::Module,
        )
        .expect("stream parse should succeed");

    let temp_path = std::env::temp_dir().join("franken_engine_parser_trait_ast_test.js");
    fs::write(&temp_path, source).expect("write temporary source file");
    let file_tree = parser
        .parse(temp_path.as_path(), ParseGoal::Module)
        .expect("file parse should succeed");

    assert_eq!(stream_tree.canonical_bytes(), file_tree.canonical_bytes());
    assert_eq!(stream_tree.canonical_hash(), file_tree.canonical_hash());
}

#[test]
fn script_goal_rejects_module_only_declarations() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("export default value;", ParseGoal::Script)
        .expect_err("script goal should reject export");
    assert_eq!(error.code, ParseErrorCode::InvalidGoal);
}

#[test]
fn canonical_ast_contract_metadata_is_versioned_and_stable() {
    assert_eq!(
        CANONICAL_AST_CONTRACT_VERSION,
        "franken-engine.parser-ast.contract.v1"
    );
    assert_eq!(
        CANONICAL_AST_SCHEMA_VERSION,
        "franken-engine.parser-ast.schema.v1"
    );
    assert_eq!(CANONICAL_AST_HASH_ALGORITHM, "sha256");
    assert_eq!(CANONICAL_AST_HASH_PREFIX, "sha256:");

    assert_eq!(
        SyntaxTree::canonical_contract_version(),
        CANONICAL_AST_CONTRACT_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_schema_version(),
        CANONICAL_AST_SCHEMA_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_hash_algorithm(),
        CANONICAL_AST_HASH_ALGORITHM
    );
    assert_eq!(
        SyntaxTree::canonical_hash_prefix(),
        CANONICAL_AST_HASH_PREFIX
    );
}

#[test]
fn canonical_ast_hash_vector_script_numeric_signed_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("-7", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(
        tree.canonical_hash(),
        "sha256:d959b7cbce9a409871d9a288d6feb3c043bdf3ce6ee54ff39051909db432adc4"
    );
}

#[test]
fn canonical_ast_hash_vector_module_import_default_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import dep from \"pkg\"", ParseGoal::Module)
        .expect("module parse should succeed");
    assert_eq!(
        tree.canonical_hash(),
        "sha256:6f9b81a8dfbaad70c345e5508dd1fae29d3d6cfdc1d18954d3486abd00d75f6c"
    );
}

#[test]
fn canonical_ast_hash_vector_module_export_default_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export default true", ParseGoal::Module)
        .expect("module parse should succeed");
    assert_eq!(
        tree.canonical_hash(),
        "sha256:ebb993de589945a2cf22f17db58200599ae3e1e6c21cd33a0fc59eab99fd8ef6"
    );
}

#[test]
fn canonical_parse_event_ir_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSE_EVENT_IR_CONTRACT_VERSION,
        "franken-engine.parser-event-ir.contract.v2"
    );
    assert_eq!(
        PARSE_EVENT_IR_SCHEMA_VERSION,
        "franken-engine.parser-event-ir.schema.v2"
    );
    assert_eq!(PARSE_EVENT_IR_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSE_EVENT_IR_HASH_PREFIX, "sha256:");

    assert_eq!(
        ParseEventIr::contract_version(),
        PARSE_EVENT_IR_CONTRACT_VERSION
    );
    assert_eq!(
        ParseEventIr::schema_version(),
        PARSE_EVENT_IR_SCHEMA_VERSION
    );
    assert_eq!(
        ParseEventIr::canonical_hash_algorithm(),
        PARSE_EVENT_IR_HASH_ALGORITHM
    );
    assert_eq!(
        ParseEventIr::canonical_hash_prefix(),
        PARSE_EVENT_IR_HASH_PREFIX
    );
}

#[test]
fn canonical_parse_event_ir_hash_vector_script_numeric_signed_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("-7", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(
        ir.canonical_hash(),
        "sha256:23c6f89b4442da0d3ca21a3415901a6b19518f02f0b51b439cbb4aae0e70ea47"
    );
}

#[test]
fn canonical_parse_event_ir_hash_vector_module_import_default_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import dep from \"pkg\"", ParseGoal::Module)
        .expect("module parse should succeed");
    let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(
        ir.canonical_hash(),
        "sha256:37b99e6645feed7454a8e063844c70657cf20db5d92741dafa256a30ae21ad60"
    );
}

#[test]
fn canonical_parse_event_ir_provenance_ids_are_stable_for_identical_inputs() {
    let parser = CanonicalEs2020Parser;
    let source = "await work";
    let left_tree = parser
        .parse(source, ParseGoal::Script)
        .expect("left parse should succeed");
    let right_tree = parser
        .parse(source, ParseGoal::Script)
        .expect("right parse should succeed");
    let left_ir =
        ParseEventIr::from_syntax_tree(&left_tree, "<inline>", ParserMode::ScalarReference);
    let right_ir =
        ParseEventIr::from_syntax_tree(&right_tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(left_ir.canonical_hash(), right_ir.canonical_hash());
    assert_eq!(left_ir.events.len(), right_ir.events.len());
    for (left, right) in left_ir.events.iter().zip(right_ir.events.iter()) {
        assert_eq!(left.trace_id, right.trace_id);
        assert_eq!(left.decision_id, right.decision_id);
        assert_eq!(left.policy_id, right.policy_id);
        assert_eq!(left.component, right.component);
    }
}

#[test]
fn canonical_parse_event_ir_failure_vector_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let (result, event_ir) =
        parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());
    let error = result.expect_err("empty source should fail");
    assert_eq!(error.code, ParseErrorCode::EmptySource);
    assert_eq!(event_ir.events.len(), 2);
    assert!(matches!(
        event_ir.events[0].kind,
        ParseEventKind::ParseStarted
    ));
    assert!(matches!(
        event_ir.events[1].kind,
        ParseEventKind::ParseFailed
    ));
    assert_eq!(
        event_ir.events[1].error_code,
        Some(ParseErrorCode::EmptySource)
    );
    assert!(
        event_ir
            .events
            .iter()
            .all(|event| event.trace_id.starts_with("trace-parser-event-"))
    );
}

#[test]
fn canonical_parse_diagnostics_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION,
        "franken-engine.parser-diagnostics.taxonomy.v1"
    );
    assert_eq!(
        PARSER_DIAGNOSTIC_SCHEMA_VERSION,
        "franken-engine.parser-diagnostics.schema.v1"
    );
    assert_eq!(PARSER_DIAGNOSTIC_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSER_DIAGNOSTIC_HASH_PREFIX, "sha256:");

    assert_eq!(
        ParseDiagnosticEnvelope::taxonomy_version(),
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    );
    assert_eq!(
        ParseDiagnosticEnvelope::schema_version(),
        PARSER_DIAGNOSTIC_SCHEMA_VERSION
    );
    assert_eq!(
        ParseDiagnosticEnvelope::canonical_hash_algorithm(),
        PARSER_DIAGNOSTIC_HASH_ALGORITHM
    );
    assert_eq!(
        ParseDiagnosticEnvelope::canonical_hash_prefix(),
        PARSER_DIAGNOSTIC_HASH_PREFIX
    );
}

#[test]
fn canonical_parse_diagnostics_hash_vector_script_empty_source_is_stable() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("", ParseGoal::Script)
        .expect_err("empty source should be rejected");
    let diagnostics = error.normalized_diagnostic();
    assert_eq!(
        diagnostics.canonical_hash(),
        "sha256:0f8535a4bba696fd0f0fc51bbe13ed8c9e4a5d1e8dd8f84acb7ce228ad17f68a"
    );
}

#[test]
fn canonical_parse_diagnostics_hash_vector_budget_exceeded_token_count_is_stable() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1,
            max_recursion_depth: 64,
        },
    };
    let error = parser
        .parse_with_options("alpha beta", ParseGoal::Script, &options)
        .expect_err("token budget should fail");
    let diagnostics = ParseDiagnosticEnvelope::from_parse_error(&error);
    assert_eq!(
        diagnostics.canonical_hash(),
        "sha256:443c9fe5a7218a6bd060824b175744a1d4cb36de120e0bbecb70f13eea5a29e5"
    );
}

#[test]
fn canonical_parse_diagnostics_utf8_boundary_budget_vector_is_stable() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1,
            max_recursion_depth: 64,
        },
    };

    let error = parser
        .parse_with_options("é β", ParseGoal::Script, &options)
        .expect_err("utf-8 boundary-safe scanner should enforce budget deterministically");
    let diagnostics = ParseDiagnosticEnvelope::from_parse_error(&error);
    let witness = diagnostics
        .witness
        .as_ref()
        .expect("budget diagnostics should include witness");
    assert_eq!(diagnostics.budget_kind, Some(ParseBudgetKind::TokenCount));
    assert_eq!(witness.token_count, 2);
    assert_eq!(witness.max_token_count, 1);
    assert!(diagnostics.canonical_hash().starts_with("sha256:"));
}
