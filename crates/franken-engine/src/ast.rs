//! Canonical AST surface for the parser slot (`IR0 SyntaxIR`).
//!
//! This module defines a deterministic AST hierarchy for ES2020 script/module
//! goal symbols. The parser in `parser.rs` emits this representation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::deterministic_serde::{self, CanonicalValue};

/// Versioned canonical AST contract binding schema + hash semantics.
pub const CANONICAL_AST_CONTRACT_VERSION: &str = "franken-engine.parser-ast.contract.v1";
/// Versioned schema identifier for canonical AST structure and key ordering.
pub const CANONICAL_AST_SCHEMA_VERSION: &str = "franken-engine.parser-ast.schema.v1";
/// Hash algorithm used by `SyntaxTree::canonical_hash`.
pub const CANONICAL_AST_HASH_ALGORITHM: &str = "sha256";
/// Prefix used in canonical AST hash strings.
pub const CANONICAL_AST_HASH_PREFIX: &str = "sha256:";

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
    pub const fn canonical_contract_version() -> &'static str {
        CANONICAL_AST_CONTRACT_VERSION
    }

    pub const fn canonical_schema_version() -> &'static str {
        CANONICAL_AST_SCHEMA_VERSION
    }

    pub const fn canonical_hash_algorithm() -> &'static str {
        CANONICAL_AST_HASH_ALGORITHM
    }

    pub const fn canonical_hash_prefix() -> &'static str {
        CANONICAL_AST_HASH_PREFIX
    }

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
        format!("{}{}", Self::canonical_hash_prefix(), hex::encode(digest))
    }
}

/// Statement hierarchy for the canonical AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Statement {
    Import(ImportDeclaration),
    Export(ExportDeclaration),
    VariableDeclaration(VariableDeclaration),
    Expression(ExpressionStatement),
    Block(BlockStatement),
    If(IfStatement),
    For(ForStatement),
    While(WhileStatement),
    DoWhile(DoWhileStatement),
    Return(ReturnStatement),
    Throw(ThrowStatement),
    TryCatch(TryCatchStatement),
    Switch(SwitchStatement),
    Break(BreakStatement),
    Continue(ContinueStatement),
    FunctionDeclaration(FunctionDeclaration),
}

impl Statement {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Import(v) => &v.span,
            Self::Export(v) => &v.span,
            Self::VariableDeclaration(v) => &v.span,
            Self::Expression(v) => &v.span,
            Self::Block(v) => &v.span,
            Self::If(v) => &v.span,
            Self::For(v) => &v.span,
            Self::While(v) => &v.span,
            Self::DoWhile(v) => &v.span,
            Self::Return(v) => &v.span,
            Self::Throw(v) => &v.span,
            Self::TryCatch(v) => &v.span,
            Self::Switch(v) => &v.span,
            Self::Break(v) => &v.span,
            Self::Continue(v) => &v.span,
            Self::FunctionDeclaration(v) => &v.span,
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
            Self::VariableDeclaration(variable_declaration) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("variable_declaration".to_string()),
                );
                map.insert(
                    "payload".to_string(),
                    variable_declaration.canonical_value(),
                );
            }
            Self::Expression(expr) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("expression".to_string()),
                );
                map.insert("payload".to_string(), expr.canonical_value());
            }
            Self::Block(block) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("block".to_string()),
                );
                map.insert("payload".to_string(), block.canonical_value());
            }
            Self::If(if_stmt) => {
                map.insert("kind".to_string(), CanonicalValue::String("if".to_string()));
                map.insert("payload".to_string(), if_stmt.canonical_value());
            }
            Self::For(for_stmt) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("for".to_string()),
                );
                map.insert("payload".to_string(), for_stmt.canonical_value());
            }
            Self::While(while_stmt) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("while".to_string()),
                );
                map.insert("payload".to_string(), while_stmt.canonical_value());
            }
            Self::DoWhile(do_while) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("do_while".to_string()),
                );
                map.insert("payload".to_string(), do_while.canonical_value());
            }
            Self::Return(ret) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("return".to_string()),
                );
                map.insert("payload".to_string(), ret.canonical_value());
            }
            Self::Throw(throw) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("throw".to_string()),
                );
                map.insert("payload".to_string(), throw.canonical_value());
            }
            Self::TryCatch(tc) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("try_catch".to_string()),
                );
                map.insert("payload".to_string(), tc.canonical_value());
            }
            Self::Switch(sw) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("switch".to_string()),
                );
                map.insert("payload".to_string(), sw.canonical_value());
            }
            Self::Break(brk) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("break".to_string()),
                );
                map.insert("payload".to_string(), brk.canonical_value());
            }
            Self::Continue(cont) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("continue".to_string()),
                );
                map.insert("payload".to_string(), cont.canonical_value());
            }
            Self::FunctionDeclaration(func) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("function_declaration".to_string()),
                );
                map.insert("payload".to_string(), func.canonical_value());
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VariableDeclarationKind {
    Var,
    Let,
    Const,
}

impl VariableDeclarationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Var => "var",
            Self::Let => "let",
            Self::Const => "const",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableDeclarator {
    pub name: String,
    pub initializer: Option<Expression>,
    pub span: SourceSpan,
}

impl VariableDeclarator {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "name".to_string(),
            CanonicalValue::String(self.name.clone()),
        );
        map.insert(
            "initializer".to_string(),
            self.initializer
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableDeclaration {
    pub kind: VariableDeclarationKind,
    pub declarations: Vec<VariableDeclarator>,
    pub span: SourceSpan,
}

impl VariableDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "kind".to_string(),
            CanonicalValue::String(self.kind.as_str().to_string()),
        );
        map.insert(
            "declarations".to_string(),
            CanonicalValue::Array(
                self.declarations
                    .iter()
                    .map(VariableDeclarator::canonical_value)
                    .collect(),
            ),
        );
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

// ---------------------------------------------------------------------------
// Control flow statement AST nodes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockStatement {
    pub body: Vec<Statement>,
    pub span: SourceSpan,
}

impl BlockStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "body".to_string(),
            CanonicalValue::Array(self.body.iter().map(Statement::canonical_value).collect()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfStatement {
    pub condition: Expression,
    pub consequent: Box<Statement>,
    pub alternate: Option<Box<Statement>>,
    pub span: SourceSpan,
}

impl IfStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("condition".to_string(), self.condition.canonical_value());
        map.insert("consequent".to_string(), self.consequent.canonical_value());
        map.insert(
            "alternate".to_string(),
            self.alternate
                .as_ref()
                .map(|s| s.canonical_value())
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForStatement {
    pub init: Option<Box<Statement>>,
    pub condition: Option<Expression>,
    pub update: Option<Expression>,
    pub body: Box<Statement>,
    pub span: SourceSpan,
}

impl ForStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "init".to_string(),
            self.init
                .as_ref()
                .map(|s| s.canonical_value())
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "condition".to_string(),
            self.condition
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "update".to_string(),
            self.update
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhileStatement {
    pub condition: Expression,
    pub body: Box<Statement>,
    pub span: SourceSpan,
}

impl WhileStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("condition".to_string(), self.condition.canonical_value());
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoWhileStatement {
    pub body: Box<Statement>,
    pub condition: Expression,
    pub span: SourceSpan,
}

impl DoWhileStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("condition".to_string(), self.condition.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnStatement {
    pub argument: Option<Expression>,
    pub span: SourceSpan,
}

impl ReturnStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "argument".to_string(),
            self.argument
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThrowStatement {
    pub argument: Expression,
    pub span: SourceSpan,
}

impl ThrowStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("argument".to_string(), self.argument.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchClause {
    pub parameter: Option<String>,
    pub body: BlockStatement,
    pub span: SourceSpan,
}

impl CatchClause {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "parameter".to_string(),
            self.parameter
                .as_ref()
                .map(|p| CanonicalValue::String(p.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryCatchStatement {
    pub block: BlockStatement,
    pub handler: Option<CatchClause>,
    pub finalizer: Option<BlockStatement>,
    pub span: SourceSpan,
}

impl TryCatchStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("block".to_string(), self.block.canonical_value());
        map.insert(
            "handler".to_string(),
            self.handler
                .as_ref()
                .map(CatchClause::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "finalizer".to_string(),
            self.finalizer
                .as_ref()
                .map(BlockStatement::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCase {
    pub test: Option<Expression>,
    pub consequent: Vec<Statement>,
    pub span: SourceSpan,
}

impl SwitchCase {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "test".to_string(),
            self.test
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "consequent".to_string(),
            CanonicalValue::Array(
                self.consequent
                    .iter()
                    .map(Statement::canonical_value)
                    .collect(),
            ),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchStatement {
    pub discriminant: Expression,
    pub cases: Vec<SwitchCase>,
    pub span: SourceSpan,
}

impl SwitchStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "discriminant".to_string(),
            self.discriminant.canonical_value(),
        );
        map.insert(
            "cases".to_string(),
            CanonicalValue::Array(self.cases.iter().map(SwitchCase::canonical_value).collect()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakStatement {
    pub label: Option<String>,
    pub span: SourceSpan,
}

impl BreakStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "label".to_string(),
            self.label
                .as_ref()
                .map(|l| CanonicalValue::String(l.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueStatement {
    pub label: Option<String>,
    pub span: SourceSpan,
}

impl ContinueStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "label".to_string(),
            self.label
                .as_ref()
                .map(|l| CanonicalValue::String(l.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionParam {
    pub name: String,
    pub span: SourceSpan,
}

impl FunctionParam {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "name".to_string(),
            CanonicalValue::String(self.name.clone()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionDeclaration {
    pub name: Option<String>,
    pub params: Vec<FunctionParam>,
    pub body: BlockStatement,
    pub is_async: bool,
    pub is_generator: bool,
    pub span: SourceSpan,
}

impl FunctionDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "name".to_string(),
            self.name
                .as_ref()
                .map(|n| CanonicalValue::String(n.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "params".to_string(),
            CanonicalValue::Array(
                self.params
                    .iter()
                    .map(FunctionParam::canonical_value)
                    .collect(),
            ),
        );
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("is_async".to_string(), CanonicalValue::Bool(self.is_async));
        map.insert(
            "is_generator".to_string(),
            CanonicalValue::Bool(self.is_generator),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Binary operator enumeration
// ---------------------------------------------------------------------------

/// Binary operator kinds for ES2020 expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    Exponentiate,
    Equal,
    NotEqual,
    StrictEqual,
    StrictNotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LogicalAnd,
    LogicalOr,
    NullishCoalescing,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
    UnsignedRightShift,
    Instanceof,
    In,
}

impl BinaryOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Subtract => "-",
            Self::Multiply => "*",
            Self::Divide => "/",
            Self::Remainder => "%",
            Self::Exponentiate => "**",
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::StrictEqual => "===",
            Self::StrictNotEqual => "!==",
            Self::LessThan => "<",
            Self::LessThanOrEqual => "<=",
            Self::GreaterThan => ">",
            Self::GreaterThanOrEqual => ">=",
            Self::LogicalAnd => "&&",
            Self::LogicalOr => "||",
            Self::NullishCoalescing => "??",
            Self::BitwiseAnd => "&",
            Self::BitwiseOr => "|",
            Self::BitwiseXor => "^",
            Self::LeftShift => "<<",
            Self::RightShift => ">>",
            Self::UnsignedRightShift => ">>>",
            Self::Instanceof => "instanceof",
            Self::In => "in",
        }
    }

    /// Precedence level for Pratt parsing (higher binds tighter).
    pub fn precedence(self) -> u8 {
        match self {
            Self::LogicalOr => 4,
            Self::LogicalAnd => 5,
            Self::NullishCoalescing => 4,
            Self::BitwiseOr => 6,
            Self::BitwiseXor => 7,
            Self::BitwiseAnd => 8,
            Self::Equal | Self::NotEqual | Self::StrictEqual | Self::StrictNotEqual => 9,
            Self::LessThan
            | Self::LessThanOrEqual
            | Self::GreaterThan
            | Self::GreaterThanOrEqual
            | Self::Instanceof
            | Self::In => 10,
            Self::LeftShift | Self::RightShift | Self::UnsignedRightShift => 11,
            Self::Add | Self::Subtract => 12,
            Self::Multiply | Self::Divide | Self::Remainder => 13,
            Self::Exponentiate => 14,
        }
    }

    /// Whether the operator is right-associative.
    pub fn is_right_associative(self) -> bool {
        matches!(self, Self::Exponentiate)
    }
}

/// Unary operator kinds for ES2020 expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOperator {
    Negate,
    BitwiseNot,
    LogicalNot,
    Typeof,
    Void,
    Delete,
    UnaryPlus,
}

impl UnaryOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Negate => "-",
            Self::BitwiseNot => "~",
            Self::LogicalNot => "!",
            Self::Typeof => "typeof",
            Self::Void => "void",
            Self::Delete => "delete",
            Self::UnaryPlus => "+",
        }
    }
}

/// Assignment operator kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentOperator {
    Assign,
    AddAssign,
    SubtractAssign,
    MultiplyAssign,
    DivideAssign,
    RemainderAssign,
    ExponentiateAssign,
    LeftShiftAssign,
    RightShiftAssign,
    UnsignedRightShiftAssign,
    BitwiseAndAssign,
    BitwiseOrAssign,
    BitwiseXorAssign,
    LogicalAndAssign,
    LogicalOrAssign,
    NullishCoalescingAssign,
}

impl AssignmentOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assign => "=",
            Self::AddAssign => "+=",
            Self::SubtractAssign => "-=",
            Self::MultiplyAssign => "*=",
            Self::DivideAssign => "/=",
            Self::RemainderAssign => "%=",
            Self::ExponentiateAssign => "**=",
            Self::LeftShiftAssign => "<<=",
            Self::RightShiftAssign => ">>=",
            Self::UnsignedRightShiftAssign => ">>>=",
            Self::BitwiseAndAssign => "&=",
            Self::BitwiseOrAssign => "|=",
            Self::BitwiseXorAssign => "^=",
            Self::LogicalAndAssign => "&&=",
            Self::LogicalOrAssign => "||=",
            Self::NullishCoalescingAssign => "??=",
        }
    }
}

/// Property in an object literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectProperty {
    pub key: Expression,
    pub value: Expression,
    pub computed: bool,
    pub shorthand: bool,
}

impl ObjectProperty {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), self.key.canonical_value());
        map.insert("value".to_string(), self.value.canonical_value());
        map.insert("computed".to_string(), CanonicalValue::Bool(self.computed));
        map.insert(
            "shorthand".to_string(),
            CanonicalValue::Bool(self.shorthand),
        );
        CanonicalValue::Map(map)
    }
}

/// Arrow function body — either an expression or a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArrowBody {
    Expression(Box<Expression>),
    Block(BlockStatement),
}

impl ArrowBody {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Expression(expr) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("expression".to_string()),
                );
                map.insert("value".to_string(), expr.canonical_value());
            }
            Self::Block(block) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("block".to_string()),
                );
                map.insert("value".to_string(), block.canonical_value());
            }
        }
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
    Binary {
        operator: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Unary {
        operator: UnaryOperator,
        argument: Box<Expression>,
    },
    Assignment {
        operator: AssignmentOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Conditional {
        test: Box<Expression>,
        consequent: Box<Expression>,
        alternate: Box<Expression>,
    },
    Call {
        callee: Box<Expression>,
        arguments: Vec<Expression>,
    },
    Member {
        object: Box<Expression>,
        property: Box<Expression>,
        computed: bool,
    },
    This,
    ArrayLiteral(Vec<Option<Expression>>),
    ObjectLiteral(Vec<ObjectProperty>),
    ArrowFunction {
        params: Vec<FunctionParam>,
        body: ArrowBody,
        is_async: bool,
    },
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
            Self::Binary {
                operator,
                left,
                right,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("binary".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
                map.insert("left".to_string(), left.canonical_value());
                map.insert("right".to_string(), right.canonical_value());
            }
            Self::Unary { operator, argument } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("unary".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
                map.insert("argument".to_string(), argument.canonical_value());
            }
            Self::Assignment {
                operator,
                left,
                right,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("assignment".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
                map.insert("left".to_string(), left.canonical_value());
                map.insert("right".to_string(), right.canonical_value());
            }
            Self::Conditional {
                test,
                consequent,
                alternate,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("conditional".to_string()),
                );
                map.insert("test".to_string(), test.canonical_value());
                map.insert("consequent".to_string(), consequent.canonical_value());
                map.insert("alternate".to_string(), alternate.canonical_value());
            }
            Self::Call { callee, arguments } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("call".to_string()),
                );
                map.insert("callee".to_string(), callee.canonical_value());
                map.insert(
                    "arguments".to_string(),
                    CanonicalValue::Array(
                        arguments.iter().map(Expression::canonical_value).collect(),
                    ),
                );
            }
            Self::Member {
                object,
                property,
                computed,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("member".to_string()),
                );
                map.insert("object".to_string(), object.canonical_value());
                map.insert("property".to_string(), property.canonical_value());
                map.insert("computed".to_string(), CanonicalValue::Bool(*computed));
            }
            Self::This => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("this".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Null);
            }
            Self::ArrayLiteral(elements) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("array".to_string()),
                );
                map.insert(
                    "elements".to_string(),
                    CanonicalValue::Array(
                        elements
                            .iter()
                            .map(|e| {
                                e.as_ref()
                                    .map(Expression::canonical_value)
                                    .unwrap_or(CanonicalValue::Null)
                            })
                            .collect(),
                    ),
                );
            }
            Self::ObjectLiteral(properties) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("object".to_string()),
                );
                map.insert(
                    "properties".to_string(),
                    CanonicalValue::Array(
                        properties
                            .iter()
                            .map(ObjectProperty::canonical_value)
                            .collect(),
                    ),
                );
            }
            Self::ArrowFunction {
                params,
                body,
                is_async,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("arrow_function".to_string()),
                );
                map.insert(
                    "params".to_string(),
                    CanonicalValue::Array(
                        params.iter().map(FunctionParam::canonical_value).collect(),
                    ),
                );
                map.insert("body".to_string(), body.canonical_value());
                map.insert("is_async".to_string(), CanonicalValue::Bool(*is_async));
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

    fn make_var_stmt(name: &str, initializer: Option<Expression>) -> Statement {
        Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![VariableDeclarator {
                name: name.to_string(),
                initializer,
                span: make_span(),
            }],
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
            hash.starts_with(SyntaxTree::canonical_hash_prefix()),
            "hash must start with sha256: prefix"
        );
        assert_eq!(hash.len(), 7 + 64, "sha256 hex digest is 64 chars");
    }

    #[test]
    fn canonical_ast_contract_constants_are_stable() {
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
    }

    #[test]
    fn syntax_tree_contract_metadata_accessors_match_constants() {
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

        let var_decl = Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![VariableDeclarator {
                name: "value".to_string(),
                initializer: Some(Expression::NumericLiteral(1)),
                span: span.clone(),
            }],
            span: span.clone(),
        });
        assert_eq!(var_decl.span(), &span);
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
    fn variable_declaration_kind_as_str_is_stable() {
        assert_eq!(VariableDeclarationKind::Var.as_str(), "var");
        assert_eq!(VariableDeclarationKind::Let.as_str(), "let");
        assert_eq!(VariableDeclarationKind::Const.as_str(), "const");
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

    #[test]
    fn statement_canonical_value_variable_has_kind_variable_declaration() {
        let stmt = make_var_stmt("counter", Some(Expression::NumericLiteral(0)));
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("variable_declaration".to_string()))
                );
                assert!(map.contains_key("payload"));
                assert!(map.contains_key("span"));
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

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display, edge cases, hash uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn parse_goal_clone_eq() {
        let a = ParseGoal::Script;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn expression_boolean_false_canonical_value() {
        let expr = Expression::BooleanLiteral(false);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::Bool(false)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn syntax_tree_different_bodies_produce_different_hashes() {
        let span = make_span();
        let t1 = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::NumericLiteral(1))],
            span: span.clone(),
        };
        let t2 = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::NumericLiteral(2))],
            span,
        };
        assert_ne!(t1.canonical_hash(), t2.canonical_hash());
    }

    #[test]
    fn syntax_tree_empty_vs_nonempty_body_different_hashes() {
        let span = make_span();
        let empty = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: span.clone(),
        };
        let nonempty = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::NullLiteral)],
            span,
        };
        assert_ne!(empty.canonical_hash(), nonempty.canonical_hash());
    }

    #[test]
    fn import_without_binding_serde_roundtrip() {
        let stmt = Statement::Import(ImportDeclaration {
            binding: None,
            source: "side-effect-module".to_string(),
            span: make_span(),
        });
        let json = serde_json::to_string(&stmt).expect("serialize");
        let restored: Statement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stmt, restored);
    }

    #[test]
    fn export_kind_named_vs_default_different_canonical_value() {
        let default = ExportKind::Default(Expression::Identifier("x".to_string()));
        let named = ExportKind::NamedClause("x".to_string());
        assert_ne!(default.canonical_value(), named.canonical_value());
    }

    #[test]
    fn expression_numeric_i64_max() {
        let expr = Expression::NumericLiteral(i64::MAX);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(i64::MAX)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_i64_min() {
        let expr = Expression::NumericLiteral(i64::MIN);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(i64::MIN)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn source_span_zero_length_is_valid() {
        let span = SourceSpan::new(5, 5, 1, 6, 1, 6);
        assert_eq!(span.start_offset, span.end_offset);
        let cv = span.canonical_value();
        match &cv {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("start_offset"), map.get("end_offset"),);
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_await_serde_roundtrip_deep() {
        let expr = Expression::Await(Box::new(Expression::Await(Box::new(
            Expression::StringLiteral("deep".to_string()),
        ))));
        let json = serde_json::to_string(&expr).expect("serialize");
        let restored: Expression = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(expr, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON fields, roundtrip, boundary
    // -----------------------------------------------------------------------

    #[test]
    fn source_span_clone_equality() {
        let original = SourceSpan::new(10, 200, 3, 5, 12, 80);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn import_declaration_clone_equality() {
        let original = ImportDeclaration {
            binding: Some("myDep".to_string()),
            source: "some-package".to_string(),
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn export_declaration_clone_equality() {
        let original = ExportDeclaration {
            kind: ExportKind::Default(Expression::NumericLiteral(99)),
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn expression_statement_clone_equality() {
        let original = ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Identifier("f".to_string()))),
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn syntax_tree_clone_equality() {
        let original = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    binding: None,
                    source: "effects".to_string(),
                    span: make_span(),
                }),
                make_expr_stmt(Expression::BooleanLiteral(true)),
            ],
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
        assert_eq!(original.canonical_hash(), cloned.canonical_hash());
    }

    #[test]
    fn source_span_json_field_presence() {
        let span = SourceSpan::new(1, 2, 3, 4, 5, 6);
        let json = serde_json::to_string(&span).expect("serialize");
        assert!(json.contains("\"start_offset\""));
        assert!(json.contains("\"end_offset\""));
        assert!(json.contains("\"start_line\""));
        assert!(json.contains("\"start_column\""));
        assert!(json.contains("\"end_line\""));
        assert!(json.contains("\"end_column\""));
    }

    #[test]
    fn import_declaration_json_field_presence() {
        let import = ImportDeclaration {
            binding: Some("x".to_string()),
            source: "mod".to_string(),
            span: make_span(),
        };
        let json = serde_json::to_string(&import).expect("serialize");
        assert!(json.contains("\"binding\""));
        assert!(json.contains("\"source\""));
        assert!(json.contains("\"span\""));
    }

    #[test]
    fn export_declaration_json_field_presence() {
        let export = ExportDeclaration {
            kind: ExportKind::NamedClause("foo".to_string()),
            span: make_span(),
        };
        let json = serde_json::to_string(&export).expect("serialize");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"span\""));
    }

    #[test]
    fn export_declaration_serde_roundtrip() {
        let export = ExportDeclaration {
            kind: ExportKind::Default(Expression::StringLiteral("value".to_string())),
            span: SourceSpan::new(0, 25, 1, 1, 1, 26),
        };
        let json = serde_json::to_string(&export).expect("serialize");
        let restored: ExportDeclaration = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(export, restored);
    }

    #[test]
    fn all_expression_canonical_kinds_are_unique() {
        let expressions = vec![
            Expression::Identifier("a".to_string()),
            Expression::StringLiteral("a".to_string()),
            Expression::NumericLiteral(0),
            Expression::BooleanLiteral(true),
            Expression::NullLiteral,
            Expression::UndefinedLiteral,
            Expression::Await(Box::new(Expression::NullLiteral)),
            Expression::Raw("a".to_string()),
        ];
        let mut kinds = std::collections::BTreeSet::new();
        for expr in &expressions {
            match expr.canonical_value() {
                CanonicalValue::Map(map) => {
                    if let Some(CanonicalValue::String(k)) = map.get("kind") {
                        assert!(kinds.insert(k.clone()), "duplicate canonical kind: {k}");
                    } else {
                        panic!("missing kind key");
                    }
                }
                _ => panic!("expected map"),
            }
        }
        assert_eq!(kinds.len(), 8);
    }

    #[test]
    fn source_span_max_offsets_boundary() {
        let span = SourceSpan::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        let json = serde_json::to_string(&span).expect("serialize");
        let restored: SourceSpan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(span, restored);
    }

    #[test]
    fn syntax_tree_body_order_affects_hash() {
        let span = make_span();
        let stmt_a = make_expr_stmt(Expression::Identifier("a".to_string()));
        let stmt_b = make_expr_stmt(Expression::Identifier("b".to_string()));
        let tree_ab = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![stmt_a.clone(), stmt_b.clone()],
            span: span.clone(),
        };
        let tree_ba = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![stmt_b, stmt_a],
            span,
        };
        assert_ne!(tree_ab.canonical_hash(), tree_ba.canonical_hash());
    }
}
