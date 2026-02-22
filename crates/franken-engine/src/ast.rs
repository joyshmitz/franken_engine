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
