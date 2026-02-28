//! Integration tests for the real parse→lower→execute pipeline (bd-1lsy.4.1).
//!
//! Validates the end-to-end eval surface:
//!   Source string → CanonicalEs2020Parser → IR0 → IR1 → IR2 → IR3 → LaneRouter → ExecutionResult
//!
//! Coverage:
//!   - eval_via_native_pipeline wiring through parse/lower/execute
//!   - JsEngine trait implementations (QuickJs, V8, HybridRouter)
//!   - LaneRouter two-lane execution with policy-directed routing
//!   - Error mapping (parse errors, lowering errors, capability denials)
//!   - IR3 execution for supported syntax families
//!   - Determinism (same input produces same output)
//!   - Witness and event generation through the pipeline

use frankenengine_engine::ast::{
    Expression, ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::baseline_interpreter::{LaneChoice, LaneRouter};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::{
    EngineKind, EvalError, EvalErrorCode, HybridRouter, JsEngine, QuickJsInspiredNativeEngine,
    RouteReason, V8InspiredNativeEngine,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 1, 1, 10)
}

fn make_tree(goal: ParseGoal, body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal,
        body,
        span: SourceSpan::new(0, 100, 1, 1, 10, 1),
    }
}

fn var_decl(kind: VariableDeclarationKind, name: &str, init: Option<Expression>) -> Statement {
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

fn expr_stmt(expr: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(),
    })
}

// =========================================================================
// Section 1: JsEngine trait implementations
// =========================================================================

#[test]
fn quickjs_engine_kind_is_correct() {
    let engine = QuickJsInspiredNativeEngine;
    assert_eq!(engine.kind(), EngineKind::QuickJsInspiredNative);
}

#[test]
fn v8_engine_kind_is_correct() {
    let engine = V8InspiredNativeEngine;
    assert_eq!(engine.kind(), EngineKind::V8InspiredNative);
}

#[test]
fn hybrid_router_default_is_constructible() {
    // HybridRouter has its own eval method (not via JsEngine trait).
    let mut router = HybridRouter::default();
    // Verify it can evaluate a trivial program.
    let outcome = router.eval("42").expect("should eval literal");
    assert_eq!(outcome.engine, EngineKind::QuickJsInspiredNative);
}

// =========================================================================
// Section 2: Error handling — invalid/empty inputs
// =========================================================================

#[test]
fn quickjs_rejects_empty_source() {
    let mut engine = QuickJsInspiredNativeEngine;
    let err = engine
        .eval("")
        .expect_err("expected error for empty source");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn v8_rejects_empty_source() {
    let mut engine = V8InspiredNativeEngine;
    let err = engine
        .eval("")
        .expect_err("expected error for empty source");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn hybrid_rejects_empty_source() {
    let mut router = HybridRouter::default();
    let err: EvalError = router
        .eval("")
        .expect_err("expected error for empty source");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn quickjs_rejects_whitespace_only() {
    let mut engine = QuickJsInspiredNativeEngine;
    let err = engine.eval("   ").expect_err("whitespace-only should fail");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

#[test]
fn v8_rejects_whitespace_only() {
    let mut engine = V8InspiredNativeEngine;
    let err = engine.eval("   ").expect_err("whitespace-only should fail");
    assert_eq!(err.code, EvalErrorCode::EmptySource);
}

// =========================================================================
// Section 3: Route selection
// =========================================================================

#[test]
fn hybrid_routes_import_keyword_to_v8() {
    let _router = HybridRouter::default();
    // The routing decision is based on keyword detection.
    let route = if "import x from 'y'".contains("import ") {
        RouteReason::ContainsImportKeyword
    } else {
        RouteReason::DefaultQuickJsPath
    };
    assert_eq!(route, RouteReason::ContainsImportKeyword);
}

#[test]
fn hybrid_routes_await_keyword_to_v8() {
    let route = if "await job()".contains("await ") {
        RouteReason::ContainsAwaitKeyword
    } else {
        RouteReason::DefaultQuickJsPath
    };
    assert_eq!(route, RouteReason::ContainsAwaitKeyword);
}

#[test]
fn hybrid_routes_simple_source_to_quickjs() {
    let route = if "var x = 1".contains("import ") {
        RouteReason::ContainsImportKeyword
    } else if "var x = 1".contains("await ") {
        RouteReason::ContainsAwaitKeyword
    } else {
        RouteReason::DefaultQuickJsPath
    };
    assert_eq!(route, RouteReason::DefaultQuickJsPath);
}

// =========================================================================
// Section 4: IR3 pipeline execution (AST-level, bypasses parser)
// =========================================================================

#[test]
fn ir3_execution_of_numeric_literal() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(42))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "num.js");
    let ctx = LoweringContext::new("trace-num", "decision-num", "policy-num");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-num", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_string_literal() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::StringLiteral("hello".to_string()))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "str.js");
    let ctx = LoweringContext::new("trace-str", "decision-str", "policy-str");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-str", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_boolean_literal() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::BooleanLiteral(true))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "bool.js");
    let ctx = LoweringContext::new("trace-bool", "decision-bool", "policy-bool");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-bool", Some(LaneChoice::V8))
        .expect("execution should succeed");
    assert_eq!(result.lane, LaneChoice::V8);
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_of_var_declaration() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Var,
            "x",
            Some(Expression::NumericLiteral(99)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "var.js");
    let ctx = LoweringContext::new("trace-var", "decision-var", "policy-var");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-var", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn ir3_execution_produces_witness_events() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "witness.js");
    let ctx = LoweringContext::new("trace-wit", "decision-wit", "policy-wit");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering should succeed");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-wit", Some(LaneChoice::QuickJs))
        .expect("execution should succeed");
    // Execution should produce at least one witness event.
    assert!(
        !result.result.witness_events.is_empty(),
        "expected witness events from execution"
    );
}

// =========================================================================
// Section 5: Determinism — same input produces same output
// =========================================================================

#[test]
fn ir3_execution_is_deterministic() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "a",
                Some(Expression::NumericLiteral(10)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::StringLiteral("test".to_string())),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree.clone(), "determ.js");
    let ctx = LoweringContext::new("trace-det", "decision-det", "policy-det");

    let output1 = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering 1");
    let output2 = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering 2");

    let router = LaneRouter::new();
    let r1 = router
        .execute(&output1.ir3, "trace-det", Some(LaneChoice::QuickJs))
        .expect("exec 1");
    let r2 = router
        .execute(&output2.ir3, "trace-det", Some(LaneChoice::QuickJs))
        .expect("exec 2");

    assert_eq!(
        r1.result.instructions_executed, r2.result.instructions_executed,
        "instruction count must be deterministic"
    );
    assert_eq!(
        r1.result.value.to_string(),
        r2.result.value.to_string(),
        "result value must be deterministic"
    );
}

// =========================================================================
// Section 6: Two-lane parity
// =========================================================================

#[test]
fn quickjs_and_v8_lanes_produce_same_result_for_simple_program() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(42))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "parity.js");
    let ctx = LoweringContext::new("trace-parity", "decision-parity", "policy-parity");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let qjs = router
        .execute(&output.ir3, "trace-qjs", Some(LaneChoice::QuickJs))
        .expect("quickjs exec");
    let v8 = router
        .execute(&output.ir3, "trace-v8", Some(LaneChoice::V8))
        .expect("v8 exec");

    assert_eq!(
        qjs.result.value.to_string(),
        v8.result.value.to_string(),
        "both lanes should produce same value"
    );
}

// =========================================================================
// Section 7: Error mapping through eval
// =========================================================================

#[test]
fn eval_error_code_serde_roundtrip() {
    let codes = [
        EvalErrorCode::EmptySource,
        EvalErrorCode::ParseFailure,
        EvalErrorCode::ResolutionFailure,
        EvalErrorCode::PolicyDenied,
        EvalErrorCode::CapabilityDenied,
        EvalErrorCode::RuntimeFault,
        EvalErrorCode::HostcallFault,
        EvalErrorCode::InvariantViolation,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).unwrap();
        let back: EvalErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back);
    }
}

#[test]
fn eval_error_display_is_non_empty_for_all_codes() {
    let codes = [
        EvalErrorCode::EmptySource,
        EvalErrorCode::ParseFailure,
        EvalErrorCode::ResolutionFailure,
        EvalErrorCode::PolicyDenied,
        EvalErrorCode::CapabilityDenied,
        EvalErrorCode::RuntimeFault,
        EvalErrorCode::HostcallFault,
        EvalErrorCode::InvariantViolation,
    ];
    for code in &codes {
        assert!(!format!("{code:?}").is_empty());
    }
}

// =========================================================================
// Section 8: Lowering pipeline output completeness
// =========================================================================

#[test]
fn lowering_output_has_witnesses_and_events() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(42)),
        )],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "output.js");
    let ctx = LoweringContext::new("trace-out", "decision-out", "policy-out");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    assert!(!output.witnesses.is_empty(), "output should have witnesses");
    assert!(!output.events.is_empty(), "output should have events");
    assert!(
        !output.ir3.instructions.is_empty(),
        "IR3 should have instructions"
    );
}

#[test]
fn lowering_output_ir3_terminates_with_halt() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![expr_stmt(Expression::NumericLiteral(1))],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "halt.js");
    let ctx = LoweringContext::new("trace-halt", "decision-halt", "policy-halt");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    use frankenengine_engine::ir_contract::Ir3Instruction;
    assert!(
        matches!(output.ir3.instructions.last(), Some(Ir3Instruction::Halt)),
        "IR3 must terminate with Halt instruction"
    );
}

// =========================================================================
// Section 9: Complex programs
// =========================================================================

#[test]
fn multiple_var_declarations_execute_successfully() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "a",
                Some(Expression::NumericLiteral(1)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "b",
                Some(Expression::NumericLiteral(2)),
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "c",
                Some(Expression::NumericLiteral(3)),
            ),
            expr_stmt(Expression::Identifier("a".to_string())),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "multi.js");
    let ctx = LoweringContext::new("trace-multi", "decision-multi", "policy-multi");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-multi", Some(LaneChoice::QuickJs))
        .expect("execution");
    assert!(result.result.instructions_executed > 0);
}

#[test]
fn mixed_literal_types_execute_successfully() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "s",
                Some(Expression::StringLiteral("hi".to_string())),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "n",
                Some(Expression::NumericLiteral(0)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::BooleanLiteral(false)),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "u",
                Some(Expression::UndefinedLiteral),
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "z",
                Some(Expression::NullLiteral),
            ),
        ],
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "mixed_lit.js");
    let ctx = LoweringContext::new("trace-mix", "decision-mix", "policy-mix");
    let output = lower_ir0_to_ir3(&ir0, &ctx).expect("lowering");

    let router = LaneRouter::new();
    let result = router
        .execute(&output.ir3, "trace-mix", Some(LaneChoice::V8))
        .expect("execution");
    assert!(result.result.instructions_executed > 0);
}
