mod ast {
    pub use frankenengine_engine::ast::*;
}

#[path = "../src/parser_arena.rs"]
mod parser_arena;

use ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree,
};
use parser_arena::{
    ArenaBudget, ArenaBudgetKind, ArenaError, ArenaNode, ExpressionHandle, HandleAuditEntry,
    HandleAuditKind, NodeHandle, ParserArena, SpanHandle,
};

fn span(start: u64, end: u64, line: u64, col: u64) -> SourceSpan {
    SourceSpan::new(start, end, line, col, line, col + end.saturating_sub(start))
}

fn fixture_tree() -> SyntaxTree {
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![
            Statement::Import(ImportDeclaration {
                binding: Some("alpha".to_string()),
                source: "./dep.mjs".to_string(),
                span: span(0, 24, 1, 1),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Identifier(
                    "alpha".to_string(),
                ))),
                span: span(25, 37, 2, 1),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("alpha".to_string()),
                span: span(38, 55, 3, 1),
            }),
        ],
        span: span(0, 55, 1, 1),
    }
}

#[test]
fn arena_alloc_order_is_deterministic() {
    let tree = fixture_tree();

    let a = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("first arena");
    let b = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("second arena");

    let a_handles: Vec<u32> = a.statement_handles().iter().map(|h| h.index()).collect();
    let b_handles: Vec<u32> = b.statement_handles().iter().map(|h| h.index()).collect();

    assert_eq!(a_handles, vec![0, 1, 2]);
    assert_eq!(a_handles, b_handles);
    assert_eq!(
        a.canonical_hash().expect("hash a"),
        b.canonical_hash().expect("hash b")
    );

    let expression_node = a.node(a.statement_handles()[1]).expect("expression node");
    if let ArenaNode::ExpressionStatement { expression, span } = expression_node {
        let expression_roundtrip =
            ExpressionHandle::from_parts(expression.index(), expression.generation());
        let span_roundtrip = SpanHandle::from_parts(span.index(), span.generation());

        assert_eq!(expression_roundtrip.index(), expression.index());
        assert_eq!(expression_roundtrip.generation(), expression.generation());
        assert_eq!(span_roundtrip.index(), span.index());
        assert_eq!(span_roundtrip.generation(), span.generation());

        let _ = a
            .expression(expression_roundtrip)
            .expect("expression handle should resolve");
        let _ = a.span(span_roundtrip).expect("span handle should resolve");
    } else {
        panic!("expected expression statement node at index 1");
    }

    assert!(a.bytes_used() > 0);
    assert_eq!(a.budget(), ArenaBudget::default());
}

#[test]
fn semantic_roundtrip_preserves_hash() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let round_trip = arena.to_syntax_tree().expect("round-trip");
    assert_eq!(round_trip.canonical_hash(), tree.canonical_hash());
}

#[test]
fn budget_enforcement_is_deterministic() {
    let tree = fixture_tree();
    let budget = ArenaBudget {
        max_nodes: 32,
        max_expressions: 1,
        max_spans: 64,
        max_bytes: 1024 * 1024,
    };

    let err_a = ParserArena::from_syntax_tree(&tree, budget).expect_err("should fail");
    let err_b = ParserArena::from_syntax_tree(&tree, budget).expect_err("should fail again");

    assert_eq!(err_a, err_b);
    assert!(matches!(
        err_a,
        ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Expressions,
            ..
        }
    ));
}

#[test]
fn arena_rejects_invalid_handle_generation() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");
    let first = arena.statement_handles()[0];

    let invalid = NodeHandle::from_parts(first.index(), first.generation() + 1);
    let err = arena
        .node(invalid)
        .expect_err("invalid generation must fail");

    assert!(matches!(
        err,
        ArenaError::InvalidGeneration {
            handle_kind: "node",
            ..
        }
    ));
}

#[test]
fn arena_rejects_out_of_bounds_handles() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let missing = NodeHandle::from_parts(99_999, 1);
    let err = arena.node(missing).expect_err("missing handle should fail");
    assert!(matches!(err, ArenaError::MissingNode { .. }));
}

#[test]
fn handle_audit_entries_are_deterministic() {
    let tree = fixture_tree();
    let a = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena a");
    let b = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena b");

    let entries_a = a.handle_audit_entries();
    let entries_b = b.handle_audit_entries();

    assert_eq!(entries_a, entries_b);
    assert!(!entries_a.is_empty());
    assert!(
        entries_a
            .iter()
            .any(|entry| entry.handle_kind == HandleAuditKind::Node)
    );
    assert!(
        entries_a
            .iter()
            .any(|entry| entry.handle_kind == HandleAuditKind::Expression)
    );
    assert!(
        entries_a
            .iter()
            .any(|entry| entry.handle_kind == HandleAuditKind::Span)
    );
}

#[test]
fn handle_audit_jsonl_is_parseable_and_stable() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let jsonl = arena.handle_audit_jsonl().expect("audit jsonl");
    let parsed: Vec<HandleAuditEntry> = jsonl
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid audit entry json"))
        .collect();

    assert_eq!(parsed, arena.handle_audit_entries());
}

#[test]
fn corruption_injection_guards_fail_closed_deterministically() {
    let tree = fixture_tree();
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).expect("arena");

    let node_handle = arena.statement_handles()[0];
    let node_err = arena
        .node(NodeHandle::from_parts(
            node_handle.index(),
            node_handle.generation() + 7,
        ))
        .expect_err("node generation corruption should fail");

    let expr_err = arena
        .expression(ExpressionHandle::from_parts(90_001, 1))
        .expect_err("expression OOB corruption should fail");

    let span_err = arena
        .span(SpanHandle::from_parts(70_001, 1))
        .expect_err("span OOB corruption should fail");

    assert!(matches!(
        node_err,
        ArenaError::InvalidGeneration {
            handle_kind: "node",
            ..
        }
    ));
    assert!(matches!(expr_err, ArenaError::MissingExpression { .. }));
    assert!(matches!(span_err, ArenaError::MissingSpan { .. }));
}
