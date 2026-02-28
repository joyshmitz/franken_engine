//! Lowering Coverage Integration Tests — bd-1lsy.2.3
//!
//! Verifies that EVERY parser-supported syntax family lowers through the
//! full IR0 → IR1 → IR2 → IR3 pipeline with:
//! - deterministic output (run twice, get identical hashes)
//! - witness generation (all passes produce witnesses)
//! - hash chain integrity (each level's source_hash references the previous level)
//! - correct scope/binding resolution
//! - canonical hash stability

#![forbid(unsafe_code)]

use frankenengine_engine::ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator,
};
use frankenengine_engine::ir_contract::{
    BindingKind, Ir0Module, Ir3Instruction, IrLevel, ScopeKind,
};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir0_to_ir3, lower_ir1_to_ir2, lower_ir2_to_ir3, LoweringContext,
    LoweringPipelineError, LoweringPipelineOutput,
};
use frankenengine_engine::static_semantics::analyze;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 1, 1, 10)
}

fn ctx() -> LoweringContext {
    LoweringContext::new("trace-cov", "decision-cov", "policy-cov")
}

fn make_ir0(goal: ParseGoal, body: Vec<Statement>) -> Ir0Module {
    Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal,
            body,
            span: span(),
        },
        "<lowering-coverage>",
    )
}

fn make_var_decl(kind: VariableDeclarationKind, name: &str, init: Option<Expression>) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind,
        declarations: vec![VariableDeclarator {
            name: name.to_string(),
            initializer: init,
            span: span(),
        }],
        span: span(),
    })
}

fn make_import(source: &str, binding: Option<&str>) -> Statement {
    Statement::Import(ImportDeclaration {
        source: source.to_string(),
        binding: binding.map(|s| s.to_string()),
        span: span(),
    })
}

fn make_default_export(expr: Expression) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::Default(expr),
        span: span(),
    })
}

fn make_named_export(clause: &str) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::NamedClause(clause.to_string()),
        span: span(),
    })
}

fn make_expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(),
    })
}

fn run_full(ir0: &Ir0Module) -> LoweringPipelineOutput {
    lower_ir0_to_ir3(ir0, &ctx()).expect("full pipeline should succeed")
}

// ===========================================================================
// Section 1: Full-Pipeline Determinism — Every Syntax Family
// ===========================================================================

#[test]
fn determinism_var_declaration() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(42)),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
    assert_eq!(a.witnesses.len(), b.witnesses.len());
    for (wa, wb) in a.witnesses.iter().zip(b.witnesses.iter()) {
        assert_eq!(wa.output_hash, wb.output_hash);
    }
}

#[test]
fn determinism_let_declaration() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "y",
            Some(Expression::StringLiteral("hello".to_string())),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_const_declaration() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Const,
            "PI",
            Some(Expression::NumericLiteral(314159)),
        )],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_import_with_binding() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("react", Some("React"))]);
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_import_no_binding() {
    let ir0 = make_ir0(ParseGoal::Module, vec![make_import("side-effect", None)]);
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_default_export() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_default_export(Expression::NumericLiteral(1))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_named_export() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_var_decl(
                VariableDeclarationKind::Const,
                "foo",
                Some(Expression::NumericLiteral(1)),
            ),
            make_named_export("foo"),
        ],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_all_literal_types() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_expr_stmt(Expression::NumericLiteral(0)),
            make_expr_stmt(Expression::StringLiteral("text".to_string())),
            make_expr_stmt(Expression::BooleanLiteral(true)),
            make_expr_stmt(Expression::BooleanLiteral(false)),
            make_expr_stmt(Expression::NullLiteral),
            make_expr_stmt(Expression::UndefinedLiteral),
        ],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_identifier_expression() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Identifier("console".to_string()))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_await_expression() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_expr_stmt(Expression::Await(Box::new(
            Expression::Identifier("promise".to_string()),
        )))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_raw_expression_no_call() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Raw("some_raw_thing".to_string()))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

#[test]
fn determinism_raw_expression_with_call() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::Raw("fn()".to_string()))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(a.ir3.content_hash(), b.ir3.content_hash());
}

// ===========================================================================
// Section 2: Hash Chain Integrity
// ===========================================================================

#[test]
fn hash_chain_ir1_links_to_ir0() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "a",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let ir0_hash = ir0.content_hash();
    let ir1_result = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1_result.module.header.source_hash, Some(ir0_hash));
    assert_eq!(ir1_result.module.header.level, IrLevel::Ir1);
}

#[test]
fn hash_chain_ir2_links_to_ir1() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "b",
            Some(Expression::NumericLiteral(2)),
        )],
    );
    let ir1_result = lower_ir0_to_ir1(&ir0).unwrap();
    let ir1_hash = ir1_result.module.content_hash();
    let ir2_result = lower_ir1_to_ir2(&ir1_result.module).unwrap();
    assert_eq!(ir2_result.module.header.source_hash, Some(ir1_hash));
    assert_eq!(ir2_result.module.header.level, IrLevel::Ir2);
}

#[test]
fn hash_chain_ir3_links_to_ir2() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "c",
            Some(Expression::NumericLiteral(3)),
        )],
    );
    let ir1_result = lower_ir0_to_ir1(&ir0).unwrap();
    let ir2_result = lower_ir1_to_ir2(&ir1_result.module).unwrap();
    let ir2_hash = ir2_result.module.content_hash();
    let ir3_result = lower_ir2_to_ir3(&ir2_result.module).unwrap();
    assert_eq!(ir3_result.module.header.source_hash, Some(ir2_hash));
    assert_eq!(ir3_result.module.header.level, IrLevel::Ir3);
}

#[test]
fn full_pipeline_three_witnesses() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "d",
            Some(Expression::NumericLiteral(4)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.witnesses[0].pass_id, "ir0_to_ir1");
    assert_eq!(output.witnesses[1].pass_id, "ir1_to_ir2");
    assert_eq!(output.witnesses[2].pass_id, "ir2_to_ir3");
}

#[test]
fn full_pipeline_isomorphism_ledger_entries() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "e",
            Some(Expression::NumericLiteral(5)),
        )],
    );
    let output = run_full(&ir0);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert_eq!(output.isomorphism_ledger[0].pass_id, "ir0_to_ir1");
    assert_eq!(output.isomorphism_ledger[1].pass_id, "ir1_to_ir2");
    assert_eq!(output.isomorphism_ledger[2].pass_id, "ir2_to_ir3");
}

#[test]
fn witness_invariant_checks_all_pass() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("pkg", Some("P")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "val",
                Some(Expression::NumericLiteral(100)),
            ),
            make_default_export(Expression::NumericLiteral(100)),
        ],
    );
    let output = run_full(&ir0);
    for witness in &output.witnesses {
        for check in &witness.invariant_checks {
            assert!(check.passed, "invariant {} failed: {}", check.name, check.detail);
        }
    }
}

// ===========================================================================
// Section 3: Scope and Binding Resolution
// ===========================================================================

#[test]
fn script_goal_creates_global_scope() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1.module.scopes.len(), 1);
    assert_eq!(ir1.module.scopes[0].kind, ScopeKind::Global);
}

#[test]
fn module_goal_creates_module_scope() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("mod", Some("m"))],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1.module.scopes.len(), 1);
    assert_eq!(ir1.module.scopes[0].kind, ScopeKind::Module);
}

#[test]
fn var_declaration_creates_var_binding() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "x");
    assert_eq!(binding.kind, BindingKind::Var);
}

#[test]
fn let_declaration_creates_let_binding() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "y",
            Some(Expression::NumericLiteral(2)),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "y");
    assert_eq!(binding.kind, BindingKind::Let);
}

#[test]
fn const_declaration_creates_const_binding() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Const,
            "Z",
            Some(Expression::NumericLiteral(3)),
        )],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "Z");
    assert_eq!(binding.kind, BindingKind::Const);
}

#[test]
fn import_creates_import_binding() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("react", Some("React"))],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    let binding = &ir1.module.scopes[0].bindings[0];
    assert_eq!(binding.name, "React");
    assert_eq!(binding.kind, BindingKind::Import);
}

#[test]
fn multiple_var_declarations_reuse_same_binding_id() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    // var + var should reuse — only one binding
    assert_eq!(ir1.module.scopes[0].bindings.len(), 1);
}

#[test]
fn multi_declarator_creates_multiple_bindings() {
    let ir0 = Ir0Module::from_syntax_tree(
        SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![
                    VariableDeclarator {
                        name: "a".to_string(),
                        initializer: Some(Expression::NumericLiteral(1)),
                        span: span(),
                    },
                    VariableDeclarator {
                        name: "b".to_string(),
                        initializer: Some(Expression::NumericLiteral(2)),
                        span: span(),
                    },
                    VariableDeclarator {
                        name: "c".to_string(),
                        initializer: Some(Expression::NumericLiteral(3)),
                        span: span(),
                    },
                ],
                span: span(),
            })],
            span: span(),
        },
        "<multi-decl>",
    );
    let ir1 = lower_ir0_to_ir1(&ir0).unwrap();
    assert_eq!(ir1.module.scopes[0].bindings.len(), 3);
    assert_eq!(ir1.module.scopes[0].bindings[0].name, "a");
    assert_eq!(ir1.module.scopes[0].bindings[1].name, "b");
    assert_eq!(ir1.module.scopes[0].bindings[2].name, "c");
}

// ===========================================================================
// Section 4: IR3 Instruction Verification
// ===========================================================================

#[test]
fn ir3_ends_with_halt() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(42))],
    );
    let output = run_full(&ir0);
    assert!(matches!(
        output.ir3.instructions.last(),
        Some(Ir3Instruction::Halt)
    ));
}

#[test]
fn ir3_has_main_function_descriptor() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let output = run_full(&ir0);
    assert_eq!(output.ir3.function_table.len(), 1);
    assert_eq!(output.ir3.function_table[0].name.as_deref(), Some("main"));
    assert_eq!(output.ir3.function_table[0].entry, 0);
}

#[test]
fn ir3_numeric_literal_produces_load_int() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(99))],
    );
    let output = run_full(&ir0);
    let has_load_int = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadInt { value: 99, .. }));
    assert!(has_load_int, "expected LoadInt(99)");
}

#[test]
fn ir3_string_literal_uses_constant_pool() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::StringLiteral(
            "hello world".to_string(),
        ))],
    );
    let output = run_full(&ir0);
    assert!(output.ir3.constant_pool.contains(&"hello world".to_string()));
    let has_load_str = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadStr { .. }));
    assert!(has_load_str, "expected LoadStr instruction");
}

#[test]
fn ir3_boolean_literal_produces_load_bool() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_expr_stmt(Expression::BooleanLiteral(true)),
            make_expr_stmt(Expression::BooleanLiteral(false)),
        ],
    );
    let output = run_full(&ir0);
    let has_true = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadBool { value: true, .. }));
    let has_false = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadBool { value: false, .. }));
    assert!(has_true, "expected LoadBool(true)");
    assert!(has_false, "expected LoadBool(false)");
}

#[test]
fn ir3_null_literal_produces_load_null() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NullLiteral)],
    );
    let output = run_full(&ir0);
    let has_load_null = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadNull { .. }));
    assert!(has_load_null, "expected LoadNull");
}

#[test]
fn ir3_undefined_literal_produces_load_undefined() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::UndefinedLiteral)],
    );
    let output = run_full(&ir0);
    let has_load_undef = output
        .ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::LoadUndefined { .. }));
    assert!(has_load_undef, "expected LoadUndefined");
}

#[test]
fn ir3_import_uses_constant_pool_for_specifier() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("lodash", Some("_"))],
    );
    let output = run_full(&ir0);
    assert!(output.ir3.constant_pool.contains(&"lodash".to_string()));
}

// ===========================================================================
// Section 5: IFC / Flow Proof Artifact
// ===========================================================================

#[test]
fn flow_proof_artifact_has_schema_version() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("pkg", Some("p"))],
    );
    let output = run_full(&ir0);
    assert!(!output.ir2_flow_proof_artifact.schema_version.is_empty());
}

#[test]
fn flow_proof_artifact_has_artifact_id() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("pkg", Some("p"))],
    );
    let output = run_full(&ir0);
    assert!(
        output.ir2_flow_proof_artifact.artifact_id.starts_with("sha256:"),
        "artifact_id should be a sha256 hash"
    );
}

#[test]
fn flow_proof_artifact_deterministic() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("pkg", Some("p"))],
    );
    let a = run_full(&ir0);
    let b = run_full(&ir0);
    assert_eq!(
        a.ir2_flow_proof_artifact.artifact_id,
        b.ir2_flow_proof_artifact.artifact_id
    );
}

#[test]
fn flow_proof_no_denied_flows_for_clean_module() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("clean", Some("c")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "val",
                Some(Expression::NumericLiteral(42)),
            ),
        ],
    );
    let output = run_full(&ir0);
    assert!(
        output.ir2_flow_proof_artifact.denied_flows.is_empty(),
        "clean module should have no denied flows"
    );
}

// ===========================================================================
// Section 6: Error Paths
// ===========================================================================

#[test]
fn empty_body_rejects_lowering() {
    let ir0 = make_ir0(ParseGoal::Script, vec![]);
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::EmptyIr0Body));
}

#[test]
fn const_without_initializer_rejects() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(VariableDeclarationKind::Const, "bad", None)],
    );
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn duplicate_let_binding_rejects() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
    );
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn full_pipeline_empty_body_reports_error() {
    let ir0 = make_ir0(ParseGoal::Script, vec![]);
    let err = lower_ir0_to_ir3(&ir0, &ctx()).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::EmptyIr0Body));
}

// ===========================================================================
// Section 7: Events / Structured Logging
// ===========================================================================

#[test]
fn full_pipeline_emits_success_events() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "z",
            Some(Expression::NumericLiteral(7)),
        )],
    );
    let output = run_full(&ir0);
    assert!(!output.events.is_empty());
    // All events should be successes for a clean module
    for event in &output.events {
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }
}

#[test]
fn events_include_all_pass_names() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("pkg", Some("p"))],
    );
    let output = run_full(&ir0);
    let event_names: Vec<&str> = output.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"ir0_to_ir1_lowered"));
    assert!(event_names.contains(&"ir1_to_ir2_lowered"));
    assert!(event_names.contains(&"ir2_to_ir3_lowered"));
}

#[test]
fn events_carry_context_fields() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let output = run_full(&ir0);
    for event in &output.events {
        assert_eq!(event.trace_id, "trace-cov");
        assert_eq!(event.decision_id, "decision-cov");
        assert_eq!(event.policy_id, "policy-cov");
    }
}

// ===========================================================================
// Section 8: Static Semantics Integration
// ===========================================================================

#[test]
fn static_semantics_passes_for_valid_var_program() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
        span: span(),
    };
    let result = analyze(&tree);
    assert!(result.passed());
    // Also verify lowering succeeds
    let ir0 = Ir0Module::from_syntax_tree(tree, "<integrated>");
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn static_semantics_detects_duplicate_let_then_lowering_also_rejects() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Let,
                "dup",
                Some(Expression::NumericLiteral(2)),
            ),
        ],
        span: span(),
    };
    // Static semantics catches it
    let analysis = analyze(&tree);
    assert!(!analysis.passed());
    // Lowering also catches it
    let ir0 = Ir0Module::from_syntax_tree(tree, "<dup>");
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn static_semantics_const_without_init_matches_lowering_rejection() {
    let tree = SyntaxTree {
        goal: ParseGoal::Script,
        body: vec![make_var_decl(VariableDeclarationKind::Const, "bad", None)],
        span: span(),
    };
    let analysis = analyze(&tree);
    assert!(!analysis.passed());
    let ir0 = Ir0Module::from_syntax_tree(tree, "<const-no-init>");
    let err = lower_ir0_to_ir1(&ir0).unwrap_err();
    assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
}

#[test]
fn static_semantics_module_with_imports_and_exports_integrates() {
    let tree = SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            make_import("react", Some("React")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "App",
                Some(Expression::StringLiteral("component".to_string())),
            ),
            make_default_export(Expression::NumericLiteral(1)),
        ],
        span: span(),
    };
    let analysis = analyze(&tree);
    assert!(analysis.passed());
    let ir0 = Ir0Module::from_syntax_tree(tree, "<module-integrated>");
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    assert!(output.ir2_flow_proof_artifact.denied_flows.is_empty());
}

// ===========================================================================
// Section 9: Canonical Hash Stability
// ===========================================================================

#[test]
fn canonical_hash_differs_for_different_inputs() {
    let ir0_a = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir0_b = make_ir0(
        ParseGoal::Script,
        vec![make_expr_stmt(Expression::NumericLiteral(2))],
    );
    let out_a = run_full(&ir0_a);
    let out_b = run_full(&ir0_b);
    assert_ne!(out_a.ir3.content_hash(), out_b.ir3.content_hash());
}

#[test]
fn canonical_hash_differs_for_script_vs_module() {
    let body = vec![make_expr_stmt(Expression::NumericLiteral(1))];
    let ir0_script = make_ir0(ParseGoal::Script, body.clone());
    let ir0_module = make_ir0(ParseGoal::Module, body);
    let out_script = run_full(&ir0_script);
    let out_module = run_full(&ir0_module);
    assert_ne!(out_script.ir3.content_hash(), out_module.ir3.content_hash());
}

#[test]
fn canonical_hash_differs_for_var_vs_let() {
    let ir0_var = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let ir0_let = make_ir0(
        ParseGoal::Script,
        vec![make_var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(1)),
        )],
    );
    let out_var = run_full(&ir0_var);
    let out_let = run_full(&ir0_let);
    // Different binding kinds should produce different IR, hence different hashes
    assert_ne!(out_var.ir1.content_hash(), out_let.ir1.content_hash());
}

// ===========================================================================
// Section 10: Complex / Composite Programs
// ===========================================================================

#[test]
fn complex_module_with_all_syntax_families() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("react", Some("React")),
            make_import("side-fx", None),
            make_var_decl(
                VariableDeclarationKind::Const,
                "VERSION",
                Some(Expression::NumericLiteral(1)),
            ),
            make_var_decl(
                VariableDeclarationKind::Let,
                "state",
                Some(Expression::BooleanLiteral(false)),
            ),
            make_expr_stmt(Expression::StringLiteral("init".to_string())),
            make_expr_stmt(Expression::NullLiteral),
            make_expr_stmt(Expression::UndefinedLiteral),
            make_default_export(Expression::NumericLiteral(42)),
            make_named_export("VERSION"),
        ],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
    assert_eq!(output.isomorphism_ledger.len(), 3);
    assert!(!output.events.is_empty());
    for witness in &output.witnesses {
        for check in &witness.invariant_checks {
            assert!(check.passed);
        }
    }
    // Determinism
    let output2 = run_full(&ir0);
    assert_eq!(output.ir3.content_hash(), output2.ir3.content_hash());
}

#[test]
fn mixed_var_and_expression_statements() {
    let ir0 = make_ir0(
        ParseGoal::Script,
        vec![
            make_var_decl(
                VariableDeclarationKind::Var,
                "a",
                Some(Expression::NumericLiteral(1)),
            ),
            make_expr_stmt(Expression::NumericLiteral(99)),
            make_var_decl(
                VariableDeclarationKind::Var,
                "b",
                Some(Expression::StringLiteral("test".to_string())),
            ),
            make_expr_stmt(Expression::Raw("fn()".to_string())),
        ],
    );
    let output = run_full(&ir0);
    assert_eq!(output.witnesses.len(), 3);
}

#[test]
fn serde_roundtrip_for_pipeline_output() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![
            make_import("pkg", Some("P")),
            make_var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(42)),
            ),
        ],
    );
    let output = run_full(&ir0);
    // Test IR1 serde
    let ir1_json = serde_json::to_string(&output.ir1).unwrap();
    let ir1_back: frankenengine_engine::ir_contract::Ir1Module =
        serde_json::from_str(&ir1_json).unwrap();
    assert_eq!(output.ir1, ir1_back);
    // Test IR2 serde
    let ir2_json = serde_json::to_string(&output.ir2).unwrap();
    let ir2_back: frankenengine_engine::ir_contract::Ir2Module =
        serde_json::from_str(&ir2_json).unwrap();
    assert_eq!(output.ir2, ir2_back);
    // Test witness serde
    let witness_json = serde_json::to_string(&output.witnesses).unwrap();
    let witness_back: Vec<frankenengine_engine::lowering_pipeline::PassWitness> =
        serde_json::from_str(&witness_json).unwrap();
    assert_eq!(output.witnesses, witness_back);
}

#[test]
fn serde_roundtrip_for_flow_proof_artifact() {
    let ir0 = make_ir0(
        ParseGoal::Module,
        vec![make_import("pkg", Some("P"))],
    );
    let output = run_full(&ir0);
    let json = serde_json::to_string(&output.ir2_flow_proof_artifact).unwrap();
    let back: frankenengine_engine::lowering_pipeline::Ir2FlowProofArtifact =
        serde_json::from_str(&json).unwrap();
    assert_eq!(output.ir2_flow_proof_artifact, back);
}
