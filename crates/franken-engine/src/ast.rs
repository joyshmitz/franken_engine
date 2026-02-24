//! Canonical AST surface for the parser slot (`IR0 SyntaxIR`).
//!
//! This module defines a deterministic AST hierarchy for ES2020 script/module
//! goal symbols. The parser in `parser.rs` emits this representation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::deterministic_serde::{self, CanonicalValue};

/// Parse-goal marker for ES2020 sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseGoal {
    Script,
    Module,
}

impl ParseGoal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Module => "module",
        }
    }
}

/// Source-span with byte offsets and one-based line/column markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start_offset: u64,
    pub end_offset: u64,
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
}

impl SourceSpan {
    pub fn new(
        start_offset: u64,
        end_offset: u64,
        start_line: u64,
        start_column: u64,
        end_line: u64,
        end_column: u64,
    ) -> Self {
        Self {
            start_offset,
            end_offset,
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "start_offset".to_string(),
            CanonicalValue::U64(self.start_offset),
        );
        map.insert(
            "end_offset".to_string(),
            CanonicalValue::U64(self.end_offset),
        );
        map.insert(
            "start_line".to_string(),
            CanonicalValue::U64(self.start_line),
        );
        map.insert(
            "start_column".to_string(),
            CanonicalValue::U64(self.start_column),
        );
        map.insert("end_line".to_string(), CanonicalValue::U64(self.end_line));
        map.insert(
            "end_column".to_string(),
            CanonicalValue::U64(self.end_column),
        );
        CanonicalValue::Map(map)
    }
}

/// Canonical parser output for `IR0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntaxTree {
    pub goal: ParseGoal,
    pub body: Vec<Statement>,
    pub span: SourceSpan,
}

impl SyntaxTree {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "body".to_string(),
            CanonicalValue::Array(self.body.iter().map(Statement::canonical_value).collect()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("sha256:{}", hex::encode(digest))
    }
}

/// Statement hierarchy for the canonical AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Statement {
    Import(ImportDeclaration),
    Export(ExportDeclaration),
    Expression(ExpressionStatement),
}

impl Statement {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Import(v) => &v.span,
            Self::Export(v) => &v.span,
            Self::Expression(v) => &v.span,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Import(import) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("import".to_string()),
                );
                map.insert("payload".to_string(), import.canonical_value());
            }
            Self::Export(export) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("export".to_string()),
                );
                map.insert("payload".to_string(), export.canonical_value());
            }
            Self::Expression(expr) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("expression".to_string()),
                );
                map.insert("payload".to_string(), expr.canonical_value());
            }
        }
        map.insert("span".to_string(), self.span().canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDeclaration {
    pub binding: Option<String>,
    pub source: String,
    pub span: SourceSpan,
}

impl ImportDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "binding".to_string(),
            match &self.binding {
                Some(value) => CanonicalValue::String(value.clone()),
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "source".to_string(),
            CanonicalValue::String(self.source.clone()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportKind {
    Default(Expression),
    NamedClause(String),
}

impl ExportKind {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Default(expr) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("default".to_string()),
                );
                map.insert("value".to_string(), expr.canonical_value());
            }
            Self::NamedClause(clause) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("named".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(clause.clone()));
            }
        }
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDeclaration {
    pub kind: ExportKind,
    pub span: SourceSpan,
}

impl ExportDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), self.kind.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressionStatement {
    pub expression: Expression,
    pub span: SourceSpan,
}

impl ExpressionStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("expression".to_string(), self.expression.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expression {
    Identifier(String),
    StringLiteral(String),
    NumericLiteral(i64),
    BooleanLiteral(bool),
    NullLiteral,
    UndefinedLiteral,
    Await(Box<Expression>),
    Raw(String),
}

impl Expression {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Identifier(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("identifier".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(value.clone()));
            }
            Self::StringLiteral(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("string".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(value.clone()));
            }
            Self::NumericLiteral(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("numeric".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::I64(*value));
            }
            Self::BooleanLiteral(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("boolean".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Bool(*value));
            }
            Self::NullLiteral => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("null".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Null);
            }
            Self::UndefinedLiteral => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("undefined".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Null);
            }
            Self::Await(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("await".to_string()),
                );
                map.insert("value".to_string(), value.canonical_value());
            }
            Self::Raw(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("raw".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(value.clone()));
            }
        }
        CanonicalValue::Map(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ParseGoal
    // -----------------------------------------------------------------------

    #[test]
    fn parse_goal_as_str_returns_stable_labels() {
        assert_eq!(ParseGoal::Script.as_str(), "script");
        assert_eq!(ParseGoal::Module.as_str(), "module");
    }

    #[test]
    fn parse_goal_equality_is_reflexive() {
        assert_eq!(ParseGoal::Script, ParseGoal::Script);
        assert_eq!(ParseGoal::Module, ParseGoal::Module);
        assert_ne!(ParseGoal::Script, ParseGoal::Module);
    }

    #[test]
    fn parse_goal_round_trips_through_serde() {
        for goal in [ParseGoal::Script, ParseGoal::Module] {
            let json = serde_json::to_string(&goal).expect("serialize");
            let decoded: ParseGoal = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, goal);
        }
    }

    // -----------------------------------------------------------------------
    // SourceSpan
    // -----------------------------------------------------------------------

    #[test]
    fn source_span_new_stores_all_fields() {
        let span = SourceSpan::new(10, 50, 2, 3, 5, 20);
        assert_eq!(span.start_offset, 10);
        assert_eq!(span.end_offset, 50);
        assert_eq!(span.start_line, 2);
        assert_eq!(span.start_column, 3);
        assert_eq!(span.end_line, 5);
        assert_eq!(span.end_column, 20);
    }

    #[test]
    fn source_span_canonical_value_contains_all_keys() {
        let span = SourceSpan::new(0, 100, 1, 1, 10, 5);
        let cv = span.canonical_value();
        match &cv {
            CanonicalValue::Map(map) => {
                assert!(map.contains_key("start_offset"));
                assert!(map.contains_key("end_offset"));
                assert!(map.contains_key("start_line"));
                assert!(map.contains_key("start_column"));
                assert!(map.contains_key("end_line"));
                assert!(map.contains_key("end_column"));
                assert_eq!(map.len(), 6);
            }
            _ => panic!("canonical_value must be a Map"),
        }
    }

    #[test]
    fn source_span_canonical_value_is_deterministic() {
        let span = SourceSpan::new(5, 42, 1, 6, 1, 43);
        let cv1 = span.canonical_value();
        let cv2 = span.canonical_value();
        assert_eq!(cv1, cv2);
    }

    #[test]
    fn source_span_equality_compares_all_fields() {
        let a = SourceSpan::new(0, 10, 1, 1, 1, 11);
        let b = SourceSpan::new(0, 10, 1, 1, 1, 11);
        let c = SourceSpan::new(0, 10, 1, 1, 1, 12);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn source_span_round_trips_through_serde() {
        let span = SourceSpan::new(7, 99, 3, 8, 10, 1);
        let json = serde_json::to_string(&span).expect("serialize");
        let decoded: SourceSpan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, span);
    }

    // -----------------------------------------------------------------------
    // SyntaxTree
    // -----------------------------------------------------------------------

    fn make_span() -> SourceSpan {
        SourceSpan::new(0, 10, 1, 1, 1, 11)
    }

    fn make_expr_stmt(expr: Expression) -> Statement {
        Statement::Expression(ExpressionStatement {
            expression: expr,
            span: make_span(),
        })
    }

    #[test]
    fn syntax_tree_empty_body_is_valid() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: make_span(),
        };
        assert_eq!(tree.body.len(), 0);
        assert_eq!(tree.goal, ParseGoal::Script);
    }

    #[test]
    fn syntax_tree_canonical_bytes_are_deterministic() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![make_expr_stmt(Expression::NumericLiteral(42))],
            span: make_span(),
        };
        let bytes1 = tree.canonical_bytes();
        let bytes2 = tree.canonical_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn syntax_tree_canonical_hash_has_sha256_prefix() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: make_span(),
        };
        let hash = tree.canonical_hash();
        assert!(
            hash.starts_with("sha256:"),
            "hash must start with sha256: prefix"
        );
        assert_eq!(hash.len(), 7 + 64, "sha256 hex digest is 64 chars");
    }

    #[test]
    fn syntax_tree_different_goals_produce_different_hashes() {
        let span = make_span();
        let script = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: span.clone(),
        };
        let module = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![],
            span,
        };
        assert_ne!(script.canonical_hash(), module.canonical_hash());
    }

    #[test]
    fn syntax_tree_canonical_value_contains_goal_body_span() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::Identifier("x".to_string()))],
            span: make_span(),
        };
        let cv = tree.canonical_value();
        match &cv {
            CanonicalValue::Map(map) => {
                assert!(map.contains_key("goal"));
                assert!(map.contains_key("body"));
                assert!(map.contains_key("span"));
            }
            _ => panic!("canonical_value must be a Map"),
        }
    }

    #[test]
    fn syntax_tree_round_trips_through_serde() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    binding: Some("x".to_string()),
                    source: "mod".to_string(),
                    span: make_span(),
                }),
                make_expr_stmt(Expression::NumericLiteral(1)),
            ],
            span: make_span(),
        };
        let json = serde_json::to_string(&tree).expect("serialize");
        let decoded: SyntaxTree = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, tree);
    }

    // -----------------------------------------------------------------------
    // Statement
    // -----------------------------------------------------------------------

    #[test]
    fn statement_span_returns_correct_span_for_each_variant() {
        let span = SourceSpan::new(5, 15, 2, 6, 2, 16);

        let import = Statement::Import(ImportDeclaration {
            binding: None,
            source: "x".to_string(),
            span: span.clone(),
        });
        assert_eq!(import.span(), &span);

        let export = Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("foo".to_string()),
            span: span.clone(),
        });
        assert_eq!(export.span(), &span);

        let expr = Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(0),
            span: span.clone(),
        });
        assert_eq!(expr.span(), &span);
    }

    #[test]
    fn statement_canonical_value_import_has_kind_import() {
        let stmt = Statement::Import(ImportDeclaration {
            binding: Some("dep".to_string()),
            source: "pkg".to_string(),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("import".to_string()))
                );
                assert!(map.contains_key("payload"));
                assert!(map.contains_key("span"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_canonical_value_export_has_kind_export() {
        let stmt = Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(Expression::Identifier("x".to_string())),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("export".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_canonical_value_expression_has_kind_expression() {
        let stmt = make_expr_stmt(Expression::Raw("a + b".to_string()));
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("expression".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    // -----------------------------------------------------------------------
    // ImportDeclaration
    // -----------------------------------------------------------------------

    #[test]
    fn import_declaration_with_binding_canonical_value() {
        let import = ImportDeclaration {
            binding: Some("foo".to_string()),
            source: "bar".to_string(),
            span: make_span(),
        };
        match import.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("binding"),
                    Some(&CanonicalValue::String("foo".to_string()))
                );
                assert_eq!(
                    map.get("source"),
                    Some(&CanonicalValue::String("bar".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn import_declaration_without_binding_canonical_value_has_null() {
        let import = ImportDeclaration {
            binding: None,
            source: "side-effect".to_string(),
            span: make_span(),
        };
        match import.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("binding"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    // -----------------------------------------------------------------------
    // ExportKind / ExportDeclaration
    // -----------------------------------------------------------------------

    #[test]
    fn export_kind_default_canonical_value() {
        let kind = ExportKind::Default(Expression::Identifier("main".to_string()));
        match kind.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("default".to_string()))
                );
                assert!(map.contains_key("value"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn export_kind_named_clause_canonical_value() {
        let kind = ExportKind::NamedClause("{ a, b }".to_string());
        match kind.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("named".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("{ a, b }".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    // -----------------------------------------------------------------------
    // Expression
    // -----------------------------------------------------------------------

    #[test]
    fn expression_identifier_canonical_value() {
        let expr = Expression::Identifier("myVar".to_string());
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("identifier".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("myVar".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_string_literal_canonical_value() {
        let expr = Expression::StringLiteral("hello".to_string());
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("string".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("hello".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_literal_canonical_value() {
        let expr = Expression::NumericLiteral(42);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("numeric".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(42)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_literal_handles_negative() {
        let expr = Expression::NumericLiteral(-100);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(-100)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_literal_handles_zero() {
        let expr = Expression::NumericLiteral(0);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(0)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_boolean_literal_canonical_value() {
        let expr = Expression::BooleanLiteral(true);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("boolean".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::Bool(true)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_null_literal_canonical_value() {
        let expr = Expression::NullLiteral;
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("null".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_undefined_literal_canonical_value() {
        let expr = Expression::UndefinedLiteral;
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("undefined".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_await_wraps_nested_expression() {
        let inner = Expression::Identifier("work".to_string());
        let expr = Expression::Await(Box::new(inner.clone()));
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("await".to_string()))
                );
                assert_eq!(map.get("value"), Some(&inner.canonical_value()));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_await_can_nest_deeply() {
        let inner = Expression::NumericLiteral(1);
        let mid = Expression::Await(Box::new(inner));
        let outer = Expression::Await(Box::new(mid));
        match outer.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("await".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_raw_canonical_value() {
        let expr = Expression::Raw("x + y * z".to_string());
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("raw".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("x + y * z".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_variants_round_trip_through_serde() {
        let expressions = vec![
            Expression::Identifier("x".to_string()),
            Expression::StringLiteral("hello".to_string()),
            Expression::NumericLiteral(42),
            Expression::BooleanLiteral(true),
            Expression::NullLiteral,
            Expression::UndefinedLiteral,
            Expression::Await(Box::new(Expression::Identifier("work".to_string()))),
            Expression::Raw("a + b".to_string()),
        ];
        for expr in expressions {
            let json = serde_json::to_string(&expr).expect("serialize");
            let decoded: Expression = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, expr);
        }
    }

    #[test]
    fn expression_equality_distinguishes_variants() {
        let id = Expression::Identifier("x".to_string());
        let string = Expression::StringLiteral("x".to_string());
        let raw = Expression::Raw("x".to_string());
        assert_ne!(id, string);
        assert_ne!(id, raw);
        assert_ne!(string, raw);
    }

    // -----------------------------------------------------------------------
    // Full AST determinism
    // -----------------------------------------------------------------------

    #[test]
    fn full_ast_canonical_bytes_are_stable_across_constructions() {
        let build_tree = || SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    binding: Some("dep".to_string()),
                    source: "pkg".to_string(),
                    span: SourceSpan::new(0, 18, 1, 1, 1, 19),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(Expression::Identifier("dep".to_string())),
                    span: SourceSpan::new(19, 37, 2, 1, 2, 19),
                }),
            ],
            span: SourceSpan::new(0, 37, 1, 1, 2, 19),
        };

        let tree1 = build_tree();
        let tree2 = build_tree();
        assert_eq!(tree1.canonical_bytes(), tree2.canonical_bytes());
        assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
    }
}
