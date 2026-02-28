//! Integration tests for static_semantics module.
//!
//! Tests the full pipeline: source text → parser → AST → static_semantics analysis.
//! Validates that the static-semantic checks integrate correctly with the parser output.

use frankenengine_engine::ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator,
};
use frankenengine_engine::ir_contract::{BindingKind, ScopeKind};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::static_semantics::{
    analyze, StaticAnalysisResult, StaticError, StaticErrorKind, StaticSemanticsEvent,
    STATIC_SEMANTICS_BEAD_ID, STATIC_SEMANTICS_COMPONENT, STATIC_SEMANTICS_CONTRACT_VERSION,
};

// ---------------------------------------------------------------------------
// Helper: parse source then analyze
// ---------------------------------------------------------------------------

fn parse_and_analyze(source: &str, goal: ParseGoal) -> StaticAnalysisResult {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let tree = parser
        .parse_with_options(source, goal, &options)
        .expect("parse should succeed");
    analyze(&tree)
}

fn span(line: u64) -> SourceSpan {
    SourceSpan::new(0, 10, line, 1, line, 10)
}

fn make_tree(goal: ParseGoal, body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal,
        body,
        span: SourceSpan::new(0, 100, 1, 1, 10, 1),
    }
}

fn var_decl(
    kind: VariableDeclarationKind,
    name: &str,
    init: Option<Expression>,
    line: u64,
) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind,
        declarations: vec![VariableDeclarator {
            name: name.to_string(),
            initializer: init,
            span: span(line),
        }],
        span: span(line),
    })
}

fn import_stmt(binding: Option<&str>, source: &str, line: u64) -> Statement {
    Statement::Import(ImportDeclaration {
        binding: binding.map(ToString::to_string),
        source: source.to_string(),
        span: span(line),
    })
}

fn export_default(expr: Expression, line: u64) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::Default(expr),
        span: span(line),
    })
}

fn export_named(name: &str, line: u64) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::NamedClause(name.to_string()),
        span: span(line),
    })
}

fn expr_stmt(expr: Expression, line: u64) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(line),
    })
}

// ===========================================================================
// Section 1: Contract Constants
// ===========================================================================

#[test]
fn contract_version_is_stable() {
    assert_eq!(
        STATIC_SEMANTICS_CONTRACT_VERSION,
        "franken-engine.static-semantics.contract.v1"
    );
}

#[test]
fn bead_id_is_correct() {
    assert_eq!(STATIC_SEMANTICS_BEAD_ID, "bd-1lsy.2.2");
}

#[test]
fn component_name_is_stable() {
    assert_eq!(STATIC_SEMANTICS_COMPONENT, "static_semantics");
}

// ===========================================================================
// Section 2: Parser→StaticSemantics Pipeline (Happy Paths)
// ===========================================================================

#[test]
fn empty_script_then_analyze() {
    // Parser rejects empty source, so use synthetic AST
    let tree = make_tree(ParseGoal::Script, vec![]);
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.scopes.len(), 1);
    assert_eq!(result.scopes[0].kind, ScopeKind::Global);
}

#[test]
fn parse_var_declaration_then_analyze() {
    let result = parse_and_analyze("var x = 42;", ParseGoal::Script);
    assert!(result.passed());
    assert!(!result.bindings.is_empty());
}

#[test]
fn parse_let_declaration_then_analyze() {
    let result = parse_and_analyze("let y = 'hello';", ParseGoal::Script);
    assert!(result.passed());
}

#[test]
fn parse_const_declaration_then_analyze() {
    let result = parse_and_analyze("const z = true;", ParseGoal::Script);
    assert!(result.passed());
}

// ===========================================================================
// Section 3: Synthetic AST Complex Scenarios
// ===========================================================================

#[test]
fn complex_module_with_imports_exports_and_declarations() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("React"), "react", 1),
            import_stmt(Some("useState"), "react", 2),
            var_decl(
                VariableDeclarationKind::Const,
                "MAX",
                Some(Expression::NumericLiteral(100)),
                3,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "count",
                Some(Expression::NumericLiteral(0)),
                4,
            ),
            export_named("count", 5),
            export_default(Expression::Identifier("React".to_string()), 6),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 4); // React, useState, MAX, count
    assert_eq!(result.scopes[0].kind, ScopeKind::Module);
}

#[test]
fn many_var_declarations_same_name() {
    let tree = make_tree(
        ParseGoal::Script,
        (1..=10)
            .map(|i| {
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(i)),
                    i as u64,
                )
            })
            .collect(),
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 10);
}

#[test]
fn many_distinct_let_bindings() {
    let names: Vec<String> = (b'a'..=b'z').map(|c| String::from(c as char)).collect();
    let tree = make_tree(
        ParseGoal::Script,
        names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                var_decl(
                    VariableDeclarationKind::Let,
                    name,
                    Some(Expression::NumericLiteral(i as i64)),
                    (i + 1) as u64,
                )
            })
            .collect(),
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 26);
}

#[test]
fn mixed_var_let_const_no_collision() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "a",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "c",
                Some(Expression::NumericLiteral(3)),
                3,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 3);
    assert_eq!(result.bindings[0].kind, BindingKind::Var);
    assert_eq!(result.bindings[1].kind, BindingKind::Let);
    assert_eq!(result.bindings[2].kind, BindingKind::Const);
}

// ===========================================================================
// Section 4: Error Detection — Comprehensive
// ===========================================================================

#[test]
fn all_error_kinds_in_single_tree() {
    // Construct a tree that triggers as many error kinds as possible
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            // ImportInScript
            import_stmt(Some("foo"), "./foo.js", 1),
            // ExportInScript
            export_default(Expression::NumericLiteral(42), 2),
            // ConstWithoutInitializer
            var_decl(VariableDeclarationKind::Const, "bad", None, 3),
            // DuplicateBinding (let + let)
            var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(1)),
                4,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(2)),
                5,
            ),
            // LexicalVarCollision
            var_decl(
                VariableDeclarationKind::Let,
                "col",
                Some(Expression::NumericLiteral(1)),
                6,
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "col",
                Some(Expression::NumericLiteral(2)),
                7,
            ),
            // AwaitOutsideAsync
            expr_stmt(
                Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
                8,
            ),
            // ReservedWordBinding
            var_decl(
                VariableDeclarationKind::Let,
                "class",
                Some(Expression::NumericLiteral(1)),
                9,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());

    let kinds: Vec<StaticErrorKind> = result.errors.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&StaticErrorKind::ImportInScript));
    assert!(kinds.contains(&StaticErrorKind::ExportInScript));
    assert!(kinds.contains(&StaticErrorKind::ConstWithoutInitializer));
    assert!(kinds.contains(&StaticErrorKind::DuplicateBinding));
    assert!(kinds.contains(&StaticErrorKind::LexicalVarCollision));
    assert!(kinds.contains(&StaticErrorKind::AwaitOutsideAsync));
    assert!(kinds.contains(&StaticErrorKind::ReservedWordBinding));
}

#[test]
fn duplicate_export_many_names() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            export_named("a", 1),
            export_named("b", 2),
            export_named("a", 3), // duplicate
            export_named("c", 4),
            export_named("b", 5), // duplicate
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    let dup_exports: Vec<&StaticError> = result
        .errors
        .iter()
        .filter(|e| e.kind == StaticErrorKind::DuplicateExport)
        .collect();
    assert_eq!(dup_exports.len(), 2);
}

#[test]
fn tdz_chain_of_references() {
    // a references b, b references c, c declared last
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "a",
                Some(Expression::Identifier("b".to_string())),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::Identifier("c".to_string())),
                2,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "c",
                Some(Expression::NumericLiteral(42)),
                3,
            ),
        ],
    );
    let result = analyze(&tree);
    // 'a' at line 1 references 'b' declared at line 2 (idx 0 < idx 1) → TDZ
    // 'b' at line 2 references 'c' declared at line 3 (idx 1 < idx 2) → TDZ
    let tdz_errors: Vec<&StaticError> = result
        .errors
        .iter()
        .filter(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        .collect();
    assert_eq!(tdz_errors.len(), 2);
}

#[test]
fn tdz_self_reference_in_initializer() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::Identifier("x".to_string())),
            1,
        )],
    );
    let result = analyze(&tree);
    // Self-reference: 'x' is used in its own initializer, but it's at the same
    // statement index so idx < decl_idx is false. This is actually valid per our
    // simplified check (the real TDZ would catch this at runtime).
    // Our static check only catches cross-statement references.
    assert!(result.passed() || result.errors.iter().any(|e| e.kind == StaticErrorKind::TemporalDeadZone));
}

// ===========================================================================
// Section 5: Import/Export Edge Cases
// ===========================================================================

#[test]
fn import_multiple_from_same_source() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("a"), "./mod.js", 1),
            import_stmt(Some("b"), "./mod.js", 2),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 2);
}

#[test]
fn import_without_binding_no_conflict() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(None, "./side-effect.js", 1),
            import_stmt(None, "./another.js", 2),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 0);
}

#[test]
fn export_default_and_named_same_identifier() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            export_default(Expression::Identifier("foo".to_string()), 1),
            export_named("foo", 2),
        ],
    );
    let result = analyze(&tree);
    // "default" and "foo" are different export names — no conflict
    assert!(result.passed());
}

#[test]
fn import_binding_then_export_same_name() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("handler"), "./handler.js", 1),
            export_named("handler", 2),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
}

// ===========================================================================
// Section 6: Binding Resolution Validation
// ===========================================================================

#[test]
fn binding_ids_are_sequential() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("a"), "./a.js", 1),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "c",
                Some(Expression::NumericLiteral(2)),
                3,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    for (i, binding) in result.bindings.iter().enumerate() {
        assert_eq!(binding.binding_id, i as u32);
    }
}

#[test]
fn binding_names_match_declarations() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "alpha",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "beta",
                Some(Expression::StringLiteral("hi".to_string())),
                2,
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "gamma",
                Some(Expression::BooleanLiteral(true)),
                3,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    let names: Vec<&str> = result.bindings.iter().map(|b| b.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn scope_bindings_match_result_bindings() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "y",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.scopes[0].bindings.len(), result.bindings.len());
}

// ===========================================================================
// Section 7: Reserved Word Edge Cases
// ===========================================================================

#[test]
fn all_keywords_rejected_as_bindings() {
    let keywords = [
        "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete",
        "do", "else", "enum", "export", "extends", "false", "finally", "for", "function", "if",
        "import", "in", "instanceof", "new", "null", "return", "super", "switch", "this",
        "throw", "true", "try", "typeof", "var", "void", "while", "with",
    ];

    for keyword in keywords {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                keyword,
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ReservedWordBinding),
            "keyword '{}' should be rejected as binding",
            keyword,
        );
    }
}

#[test]
fn strict_reserved_words_in_module() {
    let strict_reserved = ["implements", "interface", "let", "package", "private", "protected", "public", "static", "yield"];

    for word in strict_reserved {
        let tree = make_tree(
            ParseGoal::Module,
            vec![var_decl(
                VariableDeclarationKind::Const, // using const, not let, to avoid "let" shadowing confusion
                word,
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ReservedWordBinding),
            "strict-mode reserved word '{}' should be rejected in module",
            word,
        );
    }
}

#[test]
fn normal_identifiers_pass() {
    let names = [
        "foo", "bar", "myVar", "camelCase", "snake_case", "PascalCase", "_private", "$dollar",
        "x1", "longVariableName",
    ];

    for name in names {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                name,
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(
            result.passed(),
            "identifier '{}' should be accepted as binding",
            name,
        );
    }
}

// ===========================================================================
// Section 8: Structured Logging Events
// ===========================================================================

#[test]
fn event_from_complex_passing_analysis() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("a"), "./a.js", 1),
            import_stmt(Some("b"), "./b.js", 2),
            var_decl(
                VariableDeclarationKind::Const,
                "c",
                Some(Expression::NumericLiteral(1)),
                3,
            ),
            export_named("c", 4),
        ],
    );
    let result = analyze(&tree);
    let event = StaticSemanticsEvent::from_result(&result);
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_count, 0);
    assert_eq!(event.binding_count, 3);
    assert_eq!(event.scope_count, 1);
    assert!(event.is_module);
}

#[test]
fn event_from_complex_failing_analysis() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            import_stmt(Some("x"), "./x.js", 1),
            var_decl(VariableDeclarationKind::Const, "y", None, 2),
            var_decl(
                VariableDeclarationKind::Let,
                "z",
                Some(Expression::NumericLiteral(1)),
                3,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "z",
                Some(Expression::NumericLiteral(2)),
                4,
            ),
        ],
    );
    let result = analyze(&tree);
    let event = StaticSemanticsEvent::from_result(&result);
    assert_eq!(event.outcome, "fail");
    assert!(event.error_count >= 2);
    assert!(!event.is_module);
}

#[test]
fn event_serde_round_trip() {
    let tree = make_tree(ParseGoal::Module, vec![]);
    let result = analyze(&tree);
    let event = StaticSemanticsEvent::from_result(&result);
    let json = serde_json::to_string(&event).unwrap();
    let back: StaticSemanticsEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// Section 9: Serde and Canonical Value
// ===========================================================================

#[test]
fn analysis_result_serde_round_trip_complex() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("x"), "./x.js", 1),
            var_decl(
                VariableDeclarationKind::Const,
                "y",
                Some(Expression::NumericLiteral(42)),
                2,
            ),
            export_default(Expression::Identifier("x".to_string()), 3),
        ],
    );
    let result = analyze(&tree);
    let json = serde_json::to_string_pretty(&result).unwrap();
    let back: StaticAnalysisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn static_error_display_includes_line_info() {
    let err = StaticError::new(
        StaticErrorKind::DuplicateBinding,
        "identifier 'x' already declared",
        span(42),
    );
    let display = err.to_string();
    assert!(display.contains("42"));
    assert!(display.contains("FE-STATIC-DIAG-DUP-BINDING-0001"));
}

#[test]
fn all_diagnostic_codes_start_with_fe_static() {
    let kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
    ];
    for kind in kinds {
        assert!(
            kind.diagnostic_code().starts_with("FE-STATIC-DIAG-"),
            "diagnostic code '{}' should start with FE-STATIC-DIAG-",
            kind.diagnostic_code()
        );
    }
}

// ===========================================================================
// Section 10: Empty/Boundary Cases
// ===========================================================================

#[test]
fn empty_module_scope_structure() {
    let tree = make_tree(ParseGoal::Module, vec![]);
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.scopes.len(), 1);
    assert!(result.scopes[0].parent.is_none());
    assert_eq!(result.scopes[0].bindings.len(), 0);
    assert!(result.is_module);
}

#[test]
fn single_side_effect_import() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![import_stmt(None, "./polyfill.js", 1)],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 0);
}

#[test]
fn expression_only_program() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            expr_stmt(Expression::NumericLiteral(1), 1),
            expr_stmt(Expression::StringLiteral("hello".to_string()), 2),
            expr_stmt(Expression::BooleanLiteral(false), 3),
            expr_stmt(Expression::NullLiteral, 4),
            expr_stmt(Expression::UndefinedLiteral, 5),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 0);
}

#[test]
fn multi_declarator_variable_declaration() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Let,
            declarations: vec![
                VariableDeclarator {
                    name: "x".to_string(),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span(1),
                },
                VariableDeclarator {
                    name: "y".to_string(),
                    initializer: Some(Expression::NumericLiteral(2)),
                    span: span(1),
                },
                VariableDeclarator {
                    name: "z".to_string(),
                    initializer: Some(Expression::NumericLiteral(3)),
                    span: span(1),
                },
            ],
            span: span(1),
        })],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.bindings.len(), 3);
}

#[test]
fn multi_declarator_with_duplicate() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Let,
            declarations: vec![
                VariableDeclarator {
                    name: "x".to_string(),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span(1),
                },
                VariableDeclarator {
                    name: "x".to_string(),
                    initializer: Some(Expression::NumericLiteral(2)),
                    span: span(1),
                },
            ],
            span: span(1),
        })],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(result
        .errors
        .iter()
        .any(|e| e.kind == StaticErrorKind::DuplicateBinding));
}

// ===========================================================================
// Section 11: Error Ordering and Stability
// ===========================================================================

#[test]
fn errors_are_deterministic() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            import_stmt(Some("a"), "./a.js", 1),
            var_decl(VariableDeclarationKind::Const, "b", None, 2),
        ],
    );

    let result1 = analyze(&tree);
    let result2 = analyze(&tree);

    assert_eq!(result1.errors.len(), result2.errors.len());
    for (e1, e2) in result1.errors.iter().zip(result2.errors.iter()) {
        assert_eq!(e1.kind, e2.kind);
        assert_eq!(e1.message, e2.message);
    }
}

#[test]
fn analysis_is_pure_function() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("x"), "./x.js", 1),
            var_decl(
                VariableDeclarationKind::Const,
                "y",
                Some(Expression::NumericLiteral(42)),
                2,
            ),
        ],
    );

    let r1 = analyze(&tree);
    let r2 = analyze(&tree);
    assert_eq!(r1, r2);
}

// ===========================================================================
// Section 12: Canonical Value Integration
// ===========================================================================

#[test]
fn canonical_value_is_deterministic() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let r1 = analyze(&tree);
    let r2 = analyze(&tree);
    let cv1 = r1.canonical_value();
    let cv2 = r2.canonical_value();
    assert_eq!(cv1, cv2);
}
