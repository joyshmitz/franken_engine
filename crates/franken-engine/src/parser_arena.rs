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
