use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree,
};

const HANDLE_GENERATION: u32 = 1;
const SPAN_ESTIMATED_BYTES: u64 = 48;
const NODE_BASE_ESTIMATED_BYTES: u64 = 24;
const EXPR_BASE_ESTIMATED_BYTES: u64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeHandle {
    index: u32,
    generation: u32,
}

impl NodeHandle {
    const fn new(index: u32) -> Self {
        Self {
            index,
            generation: HANDLE_GENERATION,
        }
    }

    pub const fn from_parts(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExpressionHandle {
    index: u32,
    generation: u32,
}

impl ExpressionHandle {
    const fn new(index: u32) -> Self {
        Self {
            index,
            generation: HANDLE_GENERATION,
        }
    }

    pub const fn from_parts(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SpanHandle {
    index: u32,
    generation: u32,
}

impl SpanHandle {
    const fn new(index: u32) -> Self {
        Self {
            index,
            generation: HANDLE_GENERATION,
        }
    }

    pub const fn from_parts(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArenaBudgetKind {
    Nodes,
    Expressions,
    Spans,
    Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaBudget {
    pub max_nodes: u32,
    pub max_expressions: u32,
    pub max_spans: u32,
    pub max_bytes: u64,
}

impl Default for ArenaBudget {
    fn default() -> Self {
        Self {
            max_nodes: 262_144,
            max_expressions: 524_288,
            max_spans: 524_288,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArenaError {
    BudgetExceeded {
        kind: ArenaBudgetKind,
        limit: u64,
        attempted: u64,
    },
    InvalidGeneration {
        handle_kind: &'static str,
        expected: u32,
        actual: u32,
        index: u32,
    },
    MissingNode {
        index: u32,
    },
    MissingExpression {
        index: u32,
    },
    MissingSpan {
        index: u32,
    },
    HandleAuditSerialization,
}

impl fmt::Display for ArenaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExceeded {
                kind,
                limit,
                attempted,
            } => write!(
                f,
                "arena budget exceeded for {:?}: limit={}, attempted={}",
                kind, limit, attempted
            ),
            Self::InvalidGeneration {
                handle_kind,
                expected,
                actual,
                index,
            } => write!(
                f,
                "invalid {} handle generation at index {}: expected {}, got {}",
                handle_kind, index, expected, actual
            ),
            Self::MissingNode { index } => {
                write!(f, "node handle points to missing index {}", index)
            }
            Self::MissingExpression { index } => {
                write!(f, "expression handle points to missing index {}", index)
            }
            Self::MissingSpan { index } => {
                write!(f, "span handle points to missing index {}", index)
            }
            Self::HandleAuditSerialization => {
                write!(f, "failed to serialize parser arena handle-audit entry")
            }
        }
    }
}

impl std::error::Error for ArenaError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArenaNode {
    Import {
        binding: Option<String>,
        source: String,
        span: SpanHandle,
    },
    ExportDefault {
        expression: ExpressionHandle,
        span: SpanHandle,
    },
    ExportNamedClause {
        clause: String,
        span: SpanHandle,
    },
    ExpressionStatement {
        expression: ExpressionHandle,
        span: SpanHandle,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArenaExpression {
    Identifier(String),
    StringLiteral(String),
    NumericLiteral(i64),
    BooleanLiteral(bool),
    NullLiteral,
    UndefinedLiteral,
    Await(ExpressionHandle),
    Raw(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleAuditKind {
    Node,
    Expression,
    Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAuditEntry {
    pub handle_kind: HandleAuditKind,
    pub index: u32,
    pub generation: u32,
    pub descriptor: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserArena {
    goal: ParseGoal,
    tree_span: SpanHandle,
    statements: Vec<NodeHandle>,
    nodes: Vec<ArenaNode>,
    expressions: Vec<ArenaExpression>,
    spans: Vec<SourceSpan>,
    budget: ArenaBudget,
    bytes_used: u64,
}

impl ParserArena {
    pub fn from_syntax_tree(tree: &SyntaxTree, budget: ArenaBudget) -> Result<Self, ArenaError> {
        let mut arena = Self {
            goal: tree.goal,
            tree_span: SpanHandle::new(0),
            statements: Vec::new(),
            nodes: Vec::new(),
            expressions: Vec::new(),
            spans: Vec::new(),
            budget,
            bytes_used: 0,
        };

        let tree_span = arena.alloc_span(&tree.span)?;
        arena.tree_span = tree_span;

        for statement in &tree.body {
            let handle = arena.alloc_statement(statement)?;
            arena.statements.push(handle);
        }

        Ok(arena)
    }

    pub const fn budget(&self) -> ArenaBudget {
        self.budget
    }

    pub const fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    pub fn statement_handles(&self) -> &[NodeHandle] {
        &self.statements
    }

    pub fn node(&self, handle: NodeHandle) -> Result<&ArenaNode, ArenaError> {
        self.validate_generation("node", handle.index, handle.generation)?;
        self.nodes
            .get(index_to_usize(handle.index))
            .ok_or(ArenaError::MissingNode {
                index: handle.index,
            })
    }

    pub fn expression(&self, handle: ExpressionHandle) -> Result<&ArenaExpression, ArenaError> {
        self.validate_generation("expression", handle.index, handle.generation)?;
        self.expressions
            .get(index_to_usize(handle.index))
            .ok_or(ArenaError::MissingExpression {
                index: handle.index,
            })
    }

    pub fn span(&self, handle: SpanHandle) -> Result<&SourceSpan, ArenaError> {
        self.validate_generation("span", handle.index, handle.generation)?;
        self.spans
            .get(index_to_usize(handle.index))
            .ok_or(ArenaError::MissingSpan {
                index: handle.index,
            })
    }

    pub fn to_syntax_tree(&self) -> Result<SyntaxTree, ArenaError> {
        let mut body = Vec::with_capacity(self.statements.len());
        for handle in &self.statements {
            body.push(self.materialize_statement(*handle)?);
        }

        Ok(SyntaxTree {
            goal: self.goal,
            body,
            span: self.span(self.tree_span)?.clone(),
        })
    }

    pub fn canonical_hash(&self) -> Result<String, ArenaError> {
        Ok(self.to_syntax_tree()?.canonical_hash())
    }

    pub fn handle_audit_entries(&self) -> Vec<HandleAuditEntry> {
        let mut entries =
            Vec::with_capacity(self.nodes.len() + self.expressions.len() + self.spans.len());

        for (index, node) in self.nodes.iter().enumerate() {
            entries.push(HandleAuditEntry {
                handle_kind: HandleAuditKind::Node,
                index: index as u32,
                generation: HANDLE_GENERATION,
                descriptor: node_audit_descriptor(node),
            });
        }

        for (index, expression) in self.expressions.iter().enumerate() {
            entries.push(HandleAuditEntry {
                handle_kind: HandleAuditKind::Expression,
                index: index as u32,
                generation: HANDLE_GENERATION,
                descriptor: expression_audit_descriptor(expression),
            });
        }

        for (index, span) in self.spans.iter().enumerate() {
            entries.push(HandleAuditEntry {
                handle_kind: HandleAuditKind::Span,
                index: index as u32,
                generation: HANDLE_GENERATION,
                descriptor: span_audit_descriptor(span),
            });
        }

        entries
    }

    pub fn handle_audit_jsonl(&self) -> Result<String, ArenaError> {
        let mut lines = Vec::new();
        for entry in self.handle_audit_entries() {
            let line =
                serde_json::to_string(&entry).map_err(|_| ArenaError::HandleAuditSerialization)?;
            lines.push(line);
        }
        Ok(lines.join("\n"))
    }

    fn alloc_statement(&mut self, statement: &Statement) -> Result<NodeHandle, ArenaError> {
        self.ensure_slot_capacity(
            ArenaBudgetKind::Nodes,
            self.nodes.len(),
            self.budget.max_nodes,
        )?;
        let index = usize_to_index(self.nodes.len(), ArenaBudgetKind::Nodes)?;

        let node = match statement {
            Statement::Import(import) => {
                let span = self.alloc_span(&import.span)?;
                self.charge_bytes(NODE_BASE_ESTIMATED_BYTES)?;
                self.charge_bytes(string_bytes(&import.source))?;
                if let Some(binding) = &import.binding {
                    self.charge_bytes(string_bytes(binding))?;
                }
                ArenaNode::Import {
                    binding: import.binding.clone(),
                    source: import.source.clone(),
                    span,
                }
            }
            Statement::Export(export) => {
                let span = self.alloc_span(&export.span)?;
                self.charge_bytes(NODE_BASE_ESTIMATED_BYTES)?;
                match &export.kind {
                    ExportKind::Default(expression) => {
                        let expression = self.alloc_expression(expression)?;
                        ArenaNode::ExportDefault { expression, span }
                    }
                    ExportKind::NamedClause(clause) => {
                        self.charge_bytes(string_bytes(clause))?;
                        ArenaNode::ExportNamedClause {
                            clause: clause.clone(),
                            span,
                        }
                    }
                }
            }
            Statement::Expression(expression_stmt) => {
                let span = self.alloc_span(&expression_stmt.span)?;
                self.charge_bytes(NODE_BASE_ESTIMATED_BYTES)?;
                let expression = self.alloc_expression(&expression_stmt.expression)?;
                ArenaNode::ExpressionStatement { expression, span }
            }
        };

        self.nodes.push(node);
        Ok(NodeHandle::new(index))
    }

    fn alloc_expression(
        &mut self,
        expression: &Expression,
    ) -> Result<ExpressionHandle, ArenaError> {
        let arena_expr = match expression {
            Expression::Identifier(value) => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                self.charge_bytes(string_bytes(value))?;
                ArenaExpression::Identifier(value.clone())
            }
            Expression::StringLiteral(value) => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                self.charge_bytes(string_bytes(value))?;
                ArenaExpression::StringLiteral(value.clone())
            }
            Expression::NumericLiteral(value) => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                ArenaExpression::NumericLiteral(*value)
            }
            Expression::BooleanLiteral(value) => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                ArenaExpression::BooleanLiteral(*value)
            }
            Expression::NullLiteral => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                ArenaExpression::NullLiteral
            }
            Expression::UndefinedLiteral => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                ArenaExpression::UndefinedLiteral
            }
            Expression::Await(inner) => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                let inner_handle = self.alloc_expression(inner)?;
                ArenaExpression::Await(inner_handle)
            }
            Expression::Raw(value) => {
                self.charge_bytes(EXPR_BASE_ESTIMATED_BYTES)?;
                self.charge_bytes(string_bytes(value))?;
                ArenaExpression::Raw(value.clone())
            }
        };

        self.ensure_slot_capacity(
            ArenaBudgetKind::Expressions,
            self.expressions.len(),
            self.budget.max_expressions,
        )?;
        let index = usize_to_index(self.expressions.len(), ArenaBudgetKind::Expressions)?;
        self.expressions.push(arena_expr);
        Ok(ExpressionHandle::new(index))
    }

    fn alloc_span(&mut self, span: &SourceSpan) -> Result<SpanHandle, ArenaError> {
        self.ensure_slot_capacity(
            ArenaBudgetKind::Spans,
            self.spans.len(),
            self.budget.max_spans,
        )?;
        let index = usize_to_index(self.spans.len(), ArenaBudgetKind::Spans)?;
        self.charge_bytes(SPAN_ESTIMATED_BYTES)?;
        self.spans.push(span.clone());
        Ok(SpanHandle::new(index))
    }

    fn ensure_slot_capacity(
        &self,
        kind: ArenaBudgetKind,
        current_len: usize,
        max: u32,
    ) -> Result<(), ArenaError> {
        let current = u64::try_from(current_len).unwrap_or(u64::MAX);
        let limit = u64::from(max);
        let attempted = current.saturating_add(1);
        if attempted > limit {
            return Err(ArenaError::BudgetExceeded {
                kind,
                limit,
                attempted,
            });
        }
        Ok(())
    }

    fn charge_bytes(&mut self, bytes: u64) -> Result<(), ArenaError> {
        let attempted = self.bytes_used.saturating_add(bytes);
        if attempted > self.budget.max_bytes {
            return Err(ArenaError::BudgetExceeded {
                kind: ArenaBudgetKind::Bytes,
                limit: self.budget.max_bytes,
                attempted,
            });
        }
        self.bytes_used = attempted;
        Ok(())
    }

    fn validate_generation(
        &self,
        handle_kind: &'static str,
        index: u32,
        generation: u32,
    ) -> Result<(), ArenaError> {
        if generation != HANDLE_GENERATION {
            return Err(ArenaError::InvalidGeneration {
                handle_kind,
                expected: HANDLE_GENERATION,
                actual: generation,
                index,
            });
        }
        Ok(())
    }

    fn materialize_statement(&self, handle: NodeHandle) -> Result<Statement, ArenaError> {
        let node = self.node(handle)?.clone();
        match node {
            ArenaNode::Import {
                binding,
                source,
                span,
            } => Ok(Statement::Import(ImportDeclaration {
                binding,
                source,
                span: self.span(span)?.clone(),
            })),
            ArenaNode::ExportDefault { expression, span } => {
                Ok(Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(self.materialize_expression(expression)?),
                    span: self.span(span)?.clone(),
                }))
            }
            ArenaNode::ExportNamedClause { clause, span } => {
                Ok(Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause(clause),
                    span: self.span(span)?.clone(),
                }))
            }
            ArenaNode::ExpressionStatement { expression, span } => {
                Ok(Statement::Expression(ExpressionStatement {
                    expression: self.materialize_expression(expression)?,
                    span: self.span(span)?.clone(),
                }))
            }
        }
    }

    fn materialize_expression(&self, handle: ExpressionHandle) -> Result<Expression, ArenaError> {
        let expression = self.expression(handle)?.clone();
        match expression {
            ArenaExpression::Identifier(value) => Ok(Expression::Identifier(value)),
            ArenaExpression::StringLiteral(value) => Ok(Expression::StringLiteral(value)),
            ArenaExpression::NumericLiteral(value) => Ok(Expression::NumericLiteral(value)),
            ArenaExpression::BooleanLiteral(value) => Ok(Expression::BooleanLiteral(value)),
            ArenaExpression::NullLiteral => Ok(Expression::NullLiteral),
            ArenaExpression::UndefinedLiteral => Ok(Expression::UndefinedLiteral),
            ArenaExpression::Await(inner) => Ok(Expression::Await(Box::new(
                self.materialize_expression(inner)?,
            ))),
            ArenaExpression::Raw(value) => Ok(Expression::Raw(value)),
        }
    }
}

fn usize_to_index(value: usize, kind: ArenaBudgetKind) -> Result<u32, ArenaError> {
    u32::try_from(value).map_err(|_| ArenaError::BudgetExceeded {
        kind,
        limit: u64::from(u32::MAX),
        attempted: u64::MAX,
    })
}

const fn index_to_usize(value: u32) -> usize {
    value as usize
}

fn string_bytes(value: &str) -> u64 {
    u64::try_from(value.len()).unwrap_or(u64::MAX)
}

fn node_audit_descriptor(node: &ArenaNode) -> String {
    match node {
        ArenaNode::Import {
            binding,
            source,
            span,
        } => format!(
            "import binding={} source={} span={}",
            binding.as_deref().unwrap_or("_"),
            source,
            span.index()
        ),
        ArenaNode::ExportDefault { expression, span } => {
            format!(
                "export_default expr={} span={}",
                expression.index(),
                span.index()
            )
        }
        ArenaNode::ExportNamedClause { clause, span } => {
            format!("export_named clause={} span={}", clause, span.index())
        }
        ArenaNode::ExpressionStatement { expression, span } => {
            format!(
                "expression_statement expr={} span={}",
                expression.index(),
                span.index()
            )
        }
    }
}

fn expression_audit_descriptor(expression: &ArenaExpression) -> String {
    match expression {
        ArenaExpression::Identifier(value) => format!("identifier {}", value),
        ArenaExpression::StringLiteral(value) => format!("string {}", value),
        ArenaExpression::NumericLiteral(value) => format!("number {}", value),
        ArenaExpression::BooleanLiteral(value) => format!("boolean {}", value),
        ArenaExpression::NullLiteral => "null".to_string(),
        ArenaExpression::UndefinedLiteral => "undefined".to_string(),
        ArenaExpression::Await(inner) => format!("await {}", inner.index()),
        ArenaExpression::Raw(value) => format!("raw {}", value),
    }
}

fn span_audit_descriptor(span: &SourceSpan) -> String {
    format!(
        "{}:{}-{}:{} offsets {}..{}",
        span.start_line,
        span.start_column,
        span.end_line,
        span.end_column,
        span.start_offset,
        span.end_offset
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_span() -> SourceSpan {
        SourceSpan::new(0, 10, 1, 1, 1, 11)
    }

    fn simple_tree() -> SyntaxTree {
        SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(42),
                span: test_span(),
            })],
            span: test_span(),
        }
    }

    fn import_tree() -> SyntaxTree {
        SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Import(ImportDeclaration {
                binding: Some("foo".to_string()),
                source: "./foo.js".to_string(),
                span: test_span(),
            })],
            span: test_span(),
        }
    }

    fn export_default_tree() -> SyntaxTree {
        SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Export(ExportDeclaration {
                kind: ExportKind::Default(Expression::Identifier("bar".to_string())),
                span: test_span(),
            })],
            span: test_span(),
        }
    }

    fn export_named_tree() -> SyntaxTree {
        SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ baz }".to_string()),
                span: test_span(),
            })],
            span: test_span(),
        }
    }

    // -----------------------------------------------------------------------
    // NodeHandle
    // -----------------------------------------------------------------------

    #[test]
    fn node_handle_parts() {
        let handle = NodeHandle::from_parts(5, 7);
        assert_eq!(handle.index(), 5);
        assert_eq!(handle.generation(), 7);
    }

    #[test]
    fn node_handle_serde_roundtrip() {
        let handle = NodeHandle::from_parts(10, 1);
        let json = serde_json::to_string(&handle).unwrap();
        let back: NodeHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, handle);
    }

    #[test]
    fn node_handle_ord() {
        let a = NodeHandle::from_parts(1, 1);
        let b = NodeHandle::from_parts(2, 1);
        assert!(a < b);
    }

    // -----------------------------------------------------------------------
    // ExpressionHandle
    // -----------------------------------------------------------------------

    #[test]
    fn expression_handle_parts() {
        let handle = ExpressionHandle::from_parts(3, 2);
        assert_eq!(handle.index(), 3);
        assert_eq!(handle.generation(), 2);
    }

    #[test]
    fn expression_handle_serde_roundtrip() {
        let handle = ExpressionHandle::from_parts(8, 1);
        let json = serde_json::to_string(&handle).unwrap();
        let back: ExpressionHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, handle);
    }

    // -----------------------------------------------------------------------
    // SpanHandle
    // -----------------------------------------------------------------------

    #[test]
    fn span_handle_parts() {
        let handle = SpanHandle::from_parts(0, 1);
        assert_eq!(handle.index(), 0);
        assert_eq!(handle.generation(), 1);
    }

    #[test]
    fn span_handle_serde_roundtrip() {
        let handle = SpanHandle::from_parts(99, 1);
        let json = serde_json::to_string(&handle).unwrap();
        let back: SpanHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, handle);
    }

    // -----------------------------------------------------------------------
    // ArenaBudget
    // -----------------------------------------------------------------------

    #[test]
    fn arena_budget_default() {
        let budget = ArenaBudget::default();
        assert_eq!(budget.max_nodes, 262_144);
        assert_eq!(budget.max_expressions, 524_288);
        assert_eq!(budget.max_spans, 524_288);
        assert_eq!(budget.max_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn arena_budget_serde_roundtrip() {
        let budget = ArenaBudget::default();
        let json = serde_json::to_string(&budget).unwrap();
        let back: ArenaBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, budget);
    }

    // -----------------------------------------------------------------------
    // ArenaBudgetKind
    // -----------------------------------------------------------------------

    #[test]
    fn arena_budget_kind_serde_roundtrip() {
        for kind in [
            ArenaBudgetKind::Nodes,
            ArenaBudgetKind::Expressions,
            ArenaBudgetKind::Spans,
            ArenaBudgetKind::Bytes,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ArenaBudgetKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    // -----------------------------------------------------------------------
    // ArenaError
    // -----------------------------------------------------------------------

    #[test]
    fn arena_error_display_budget_exceeded() {
        let err = ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Nodes,
            limit: 100,
            attempted: 101,
        };
        let msg = err.to_string();
        assert!(msg.contains("budget exceeded"));
        assert!(msg.contains("100"));
        assert!(msg.contains("101"));
    }

    #[test]
    fn arena_error_display_invalid_generation() {
        let err = ArenaError::InvalidGeneration {
            handle_kind: "node",
            expected: 1,
            actual: 2,
            index: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("node"));
        assert!(msg.contains("index 5"));
    }

    #[test]
    fn arena_error_display_missing_node() {
        let err = ArenaError::MissingNode { index: 42 };
        assert!(err.to_string().contains("42"));
    }

    #[test]
    fn arena_error_display_missing_expression() {
        let err = ArenaError::MissingExpression { index: 7 };
        assert!(err.to_string().contains("7"));
    }

    #[test]
    fn arena_error_display_missing_span() {
        let err = ArenaError::MissingSpan { index: 3 };
        assert!(err.to_string().contains("3"));
    }

    #[test]
    fn arena_error_display_handle_audit_serialization() {
        let err = ArenaError::HandleAuditSerialization;
        assert!(err.to_string().contains("serialize"));
    }

    // -----------------------------------------------------------------------
    // ParserArena — construction
    // -----------------------------------------------------------------------

    #[test]
    fn from_syntax_tree_simple_expression() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        assert_eq!(arena.statement_handles().len(), 1);
        assert!(arena.bytes_used() > 0);
    }

    #[test]
    fn from_syntax_tree_import() {
        let tree = import_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        assert_eq!(arena.statement_handles().len(), 1);
    }

    #[test]
    fn from_syntax_tree_export_default() {
        let tree = export_default_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        assert_eq!(arena.statement_handles().len(), 1);
    }

    #[test]
    fn from_syntax_tree_export_named() {
        let tree = export_named_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        assert_eq!(arena.statement_handles().len(), 1);
    }

    #[test]
    fn from_syntax_tree_empty_body() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: test_span(),
        };
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        assert_eq!(arena.statement_handles().len(), 0);
    }

    #[test]
    fn from_syntax_tree_all_expression_types() {
        let expressions = vec![
            Expression::Identifier("x".to_string()),
            Expression::StringLiteral("hello".to_string()),
            Expression::NumericLiteral(123),
            Expression::BooleanLiteral(true),
            Expression::NullLiteral,
            Expression::UndefinedLiteral,
            Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
            Expression::Raw("raw code".to_string()),
        ];
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: expressions
                .into_iter()
                .map(|e| {
                    Statement::Expression(ExpressionStatement {
                        expression: e,
                        span: test_span(),
                    })
                })
                .collect(),
            span: test_span(),
        };
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        assert_eq!(arena.statement_handles().len(), 8);
    }

    // -----------------------------------------------------------------------
    // ParserArena — roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_simple_expression() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let recovered = arena.to_syntax_tree().unwrap();
        assert_eq!(recovered, tree);
    }

    #[test]
    fn roundtrip_import() {
        let tree = import_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let recovered = arena.to_syntax_tree().unwrap();
        assert_eq!(recovered, tree);
    }

    #[test]
    fn roundtrip_export_default() {
        let tree = export_default_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let recovered = arena.to_syntax_tree().unwrap();
        assert_eq!(recovered, tree);
    }

    #[test]
    fn roundtrip_export_named() {
        let tree = export_named_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let recovered = arena.to_syntax_tree().unwrap();
        assert_eq!(recovered, tree);
    }

    #[test]
    fn roundtrip_await_expression() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Identifier(
                    "fetch".to_string(),
                ))),
                span: test_span(),
            })],
            span: test_span(),
        };
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let recovered = arena.to_syntax_tree().unwrap();
        assert_eq!(recovered, tree);
    }

    // -----------------------------------------------------------------------
    // ParserArena — canonical hash
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_hash_deterministic() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let hash1 = arena.canonical_hash().unwrap();
        let hash2 = arena.canonical_hash().unwrap();
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }

    #[test]
    fn canonical_hash_different_trees_differ() {
        let tree1 = simple_tree();
        let tree2 = import_tree();
        let arena1 = ParserArena::from_syntax_tree(&tree1, ArenaBudget::default()).unwrap();
        let arena2 = ParserArena::from_syntax_tree(&tree2, ArenaBudget::default()).unwrap();
        assert_ne!(
            arena1.canonical_hash().unwrap(),
            arena2.canonical_hash().unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // ParserArena — handle lookups
    // -----------------------------------------------------------------------

    #[test]
    fn node_lookup_valid() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let handle = arena.statement_handles()[0];
        let node = arena.node(handle).unwrap();
        matches!(node, ArenaNode::ExpressionStatement { .. });
    }

    #[test]
    fn node_lookup_invalid_generation() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let bad_handle = NodeHandle::from_parts(0, 999);
        let err = arena.node(bad_handle).unwrap_err();
        matches!(err, ArenaError::InvalidGeneration { .. });
    }

    #[test]
    fn node_lookup_missing_index() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let bad_handle = NodeHandle::from_parts(999, HANDLE_GENERATION);
        let err = arena.node(bad_handle).unwrap_err();
        matches!(err, ArenaError::MissingNode { .. });
    }

    #[test]
    fn span_lookup_invalid_generation() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let bad_handle = SpanHandle::from_parts(0, 999);
        let err = arena.span(bad_handle).unwrap_err();
        matches!(err, ArenaError::InvalidGeneration { .. });
    }

    #[test]
    fn expression_lookup_invalid_generation() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let bad_handle = ExpressionHandle::from_parts(0, 999);
        let err = arena.expression(bad_handle).unwrap_err();
        matches!(err, ArenaError::InvalidGeneration { .. });
    }

    // -----------------------------------------------------------------------
    // ParserArena — budget enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn budget_exceeded_nodes() {
        let budget = ArenaBudget {
            max_nodes: 0,
            ..ArenaBudget::default()
        };
        let tree = simple_tree();
        let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
        matches!(
            err,
            ArenaError::BudgetExceeded {
                kind: ArenaBudgetKind::Nodes,
                ..
            }
        );
    }

    #[test]
    fn budget_exceeded_bytes() {
        let budget = ArenaBudget {
            max_bytes: 1,
            ..ArenaBudget::default()
        };
        let tree = simple_tree();
        let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
        matches!(
            err,
            ArenaError::BudgetExceeded {
                kind: ArenaBudgetKind::Bytes,
                ..
            }
        );
    }

    #[test]
    fn budget_exceeded_spans() {
        let budget = ArenaBudget {
            max_spans: 0,
            ..ArenaBudget::default()
        };
        let tree = simple_tree();
        let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
        matches!(
            err,
            ArenaError::BudgetExceeded {
                kind: ArenaBudgetKind::Spans,
                ..
            }
        );
    }

    #[test]
    fn budget_exceeded_expressions() {
        let budget = ArenaBudget {
            max_expressions: 0,
            ..ArenaBudget::default()
        };
        let tree = simple_tree();
        let err = ParserArena::from_syntax_tree(&tree, budget).unwrap_err();
        matches!(
            err,
            ArenaError::BudgetExceeded {
                kind: ArenaBudgetKind::Expressions,
                ..
            }
        );
    }

    // -----------------------------------------------------------------------
    // Handle audit
    // -----------------------------------------------------------------------

    #[test]
    fn handle_audit_entries_nonempty() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let entries = arena.handle_audit_entries();
        assert!(!entries.is_empty());
        // Should have at least 1 node, 1 expression, 2 spans (tree + statement)
        let node_count = entries
            .iter()
            .filter(|e| e.handle_kind == HandleAuditKind::Node)
            .count();
        let expr_count = entries
            .iter()
            .filter(|e| e.handle_kind == HandleAuditKind::Expression)
            .count();
        let span_count = entries
            .iter()
            .filter(|e| e.handle_kind == HandleAuditKind::Span)
            .count();
        assert!(node_count >= 1);
        assert!(expr_count >= 1);
        assert!(span_count >= 1);
    }

    #[test]
    fn handle_audit_entry_serde_roundtrip() {
        let entry = HandleAuditEntry {
            handle_kind: HandleAuditKind::Node,
            index: 0,
            generation: 1,
            descriptor: "test descriptor".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: HandleAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
    }

    #[test]
    fn handle_audit_jsonl_format() {
        let tree = simple_tree();
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let jsonl = arena.handle_audit_jsonl().unwrap();
        assert!(!jsonl.is_empty());
        for line in jsonl.lines() {
            let parsed: HandleAuditEntry = serde_json::from_str(line).unwrap();
            assert!(!parsed.descriptor.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Audit descriptors
    // -----------------------------------------------------------------------

    #[test]
    fn node_audit_descriptor_import() {
        let node = ArenaNode::Import {
            binding: Some("foo".to_string()),
            source: "./bar.js".to_string(),
            span: SpanHandle::new(0),
        };
        let desc = node_audit_descriptor(&node);
        assert!(desc.contains("import"));
        assert!(desc.contains("foo"));
        assert!(desc.contains("./bar.js"));
    }

    #[test]
    fn node_audit_descriptor_import_no_binding() {
        let node = ArenaNode::Import {
            binding: None,
            source: "./side.js".to_string(),
            span: SpanHandle::new(0),
        };
        let desc = node_audit_descriptor(&node);
        assert!(desc.contains("_"));
    }

    #[test]
    fn node_audit_descriptor_export_default() {
        let node = ArenaNode::ExportDefault {
            expression: ExpressionHandle::new(3),
            span: SpanHandle::new(1),
        };
        let desc = node_audit_descriptor(&node);
        assert!(desc.contains("export_default"));
        assert!(desc.contains("3"));
    }

    #[test]
    fn node_audit_descriptor_export_named() {
        let node = ArenaNode::ExportNamedClause {
            clause: "{ x, y }".to_string(),
            span: SpanHandle::new(0),
        };
        let desc = node_audit_descriptor(&node);
        assert!(desc.contains("export_named"));
        assert!(desc.contains("{ x, y }"));
    }

    #[test]
    fn node_audit_descriptor_expression_statement() {
        let node = ArenaNode::ExpressionStatement {
            expression: ExpressionHandle::new(2),
            span: SpanHandle::new(1),
        };
        let desc = node_audit_descriptor(&node);
        assert!(desc.contains("expression_statement"));
    }

    #[test]
    fn expression_audit_descriptor_all_types() {
        assert!(
            expression_audit_descriptor(&ArenaExpression::Identifier("x".to_string()))
                .contains("identifier")
        );
        assert!(
            expression_audit_descriptor(&ArenaExpression::StringLiteral("hi".to_string()))
                .contains("string")
        );
        assert!(expression_audit_descriptor(&ArenaExpression::NumericLiteral(42)).contains("42"));
        assert!(
            expression_audit_descriptor(&ArenaExpression::BooleanLiteral(true)).contains("true")
        );
        assert_eq!(
            expression_audit_descriptor(&ArenaExpression::NullLiteral),
            "null"
        );
        assert_eq!(
            expression_audit_descriptor(&ArenaExpression::UndefinedLiteral),
            "undefined"
        );
        assert!(
            expression_audit_descriptor(&ArenaExpression::Await(ExpressionHandle::new(5)))
                .contains("await")
        );
        assert!(
            expression_audit_descriptor(&ArenaExpression::Raw("code".to_string())).contains("raw")
        );
    }

    #[test]
    fn span_audit_descriptor_format() {
        let span = SourceSpan::new(10, 20, 1, 5, 1, 15);
        let desc = span_audit_descriptor(&span);
        assert!(desc.contains("1:5-1:15"));
        assert!(desc.contains("10..20"));
    }

    // -----------------------------------------------------------------------
    // Helper functions
    // -----------------------------------------------------------------------

    #[test]
    fn string_bytes_measurement() {
        assert_eq!(string_bytes("hello"), 5);
        assert_eq!(string_bytes(""), 0);
    }

    #[test]
    fn usize_to_index_valid() {
        assert_eq!(usize_to_index(0, ArenaBudgetKind::Nodes).unwrap(), 0);
        assert_eq!(usize_to_index(100, ArenaBudgetKind::Nodes).unwrap(), 100);
    }

    #[test]
    fn index_to_usize_conversion() {
        assert_eq!(index_to_usize(0), 0);
        assert_eq!(index_to_usize(42), 42);
    }

    // -----------------------------------------------------------------------
    // HandleAuditKind
    // -----------------------------------------------------------------------

    #[test]
    fn handle_audit_kind_serde_roundtrip() {
        for kind in [
            HandleAuditKind::Node,
            HandleAuditKind::Expression,
            HandleAuditKind::Span,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: HandleAuditKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    // -----------------------------------------------------------------------
    // Multi-statement roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_mixed_statements() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    binding: Some("fs".to_string()),
                    source: "node:fs".to_string(),
                    span: test_span(),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(Expression::StringLiteral("default".to_string())),
                    span: test_span(),
                }),
                Statement::Expression(ExpressionStatement {
                    expression: Expression::BooleanLiteral(false),
                    span: test_span(),
                }),
            ],
            span: test_span(),
        };
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let recovered = arena.to_syntax_tree().unwrap();
        assert_eq!(recovered, tree);
        assert_eq!(arena.statement_handles().len(), 3);
    }

    #[test]
    fn import_without_binding_roundtrip() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Import(ImportDeclaration {
                binding: None,
                source: "./side-effects.js".to_string(),
                span: test_span(),
            })],
            span: test_span(),
        };
        let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
        let recovered = arena.to_syntax_tree().unwrap();
        assert_eq!(recovered, tree);
    }

    #[test]
    fn budget_accessor() {
        let budget = ArenaBudget {
            max_nodes: 10,
            max_expressions: 20,
            max_spans: 30,
            max_bytes: 128,
        };
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: test_span(),
        };
        let arena = ParserArena::from_syntax_tree(&tree, budget).unwrap();
        assert_eq!(arena.budget().max_nodes, 10);
        assert_eq!(arena.budget().max_expressions, 20);
    }
}
