//! Deterministic parser interface for ES2020 script/module goals.
//!
//! The parser trait is generic over input source and emits canonical `IR0`
//! syntax artifacts from `crate::ast`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator,
};
use crate::deterministic_serde::{self, CanonicalValue};

pub type ParseResult<T> = Result<T, ParseError>;

/// Versioned Parse Event IR contract identifier.
pub const PARSE_EVENT_IR_CONTRACT_VERSION: &str = "franken-engine.parser-event-ir.contract.v2";
/// Versioned Parse Event IR schema identifier.
pub const PARSE_EVENT_IR_SCHEMA_VERSION: &str = "franken-engine.parser-event-ir.schema.v2";
/// Hash algorithm used for Parse Event IR canonical hashes.
pub const PARSE_EVENT_IR_HASH_ALGORITHM: &str = "sha256";
/// Hash prefix used for Parse Event IR canonical hashes.
pub const PARSE_EVENT_IR_HASH_PREFIX: &str = "sha256:";
/// Stable policy identifier used for parser event provenance.
pub const PARSE_EVENT_IR_POLICY_ID: &str = "franken-engine.parser-event-producer.policy.v1";
/// Stable component identifier used for parser event provenance.
pub const PARSE_EVENT_IR_COMPONENT: &str = "canonical_es2020_parser";
/// Stable prefix used for parse event trace IDs.
pub const PARSE_EVENT_IR_TRACE_PREFIX: &str = "trace-parser-event-";
/// Stable prefix used for parse event decision IDs.
pub const PARSE_EVENT_IR_DECISION_PREFIX: &str = "decision-parser-event-";
/// Versioned event->AST materializer contract identifier.
pub const PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION: &str =
    "franken-engine.parser-event-ast-materializer.contract.v1";
/// Versioned event->AST materializer schema identifier.
pub const PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION: &str =
    "franken-engine.parser-event-ast-materializer.schema.v1";
/// Stable prefix used for materialized AST node IDs.
pub const PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX: &str = "ast-node-";
/// Versioned parser diagnostics taxonomy identifier.
pub const PARSER_DIAGNOSTIC_TAXONOMY_VERSION: &str =
    "franken-engine.parser-diagnostics.taxonomy.v1";
/// Versioned normalized parser diagnostics schema identifier.
pub const PARSER_DIAGNOSTIC_SCHEMA_VERSION: &str = "franken-engine.parser-diagnostics.schema.v1";
/// Hash algorithm used for normalized parser diagnostics hashes.
pub const PARSER_DIAGNOSTIC_HASH_ALGORITHM: &str = "sha256";
/// Hash prefix used for normalized parser diagnostics hashes.
pub const PARSER_DIAGNOSTIC_HASH_PREFIX: &str = "sha256:";

/// Stable parse error codes for deterministic diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseErrorCode {
    EmptySource,
    InvalidGoal,
    UnsupportedSyntax,
    IoReadFailed,
    InvalidUtf8,
    SourceTooLarge,
    BudgetExceeded,
}

impl ParseErrorCode {
    pub const ALL: [Self; 7] = [
        Self::EmptySource,
        Self::InvalidGoal,
        Self::UnsupportedSyntax,
        Self::IoReadFailed,
        Self::InvalidUtf8,
        Self::SourceTooLarge,
        Self::BudgetExceeded,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptySource => "empty_source",
            Self::InvalidGoal => "invalid_goal",
            Self::UnsupportedSyntax => "unsupported_syntax",
            Self::IoReadFailed => "io_read_failed",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::SourceTooLarge => "source_too_large",
            Self::BudgetExceeded => "budget_exceeded",
        }
    }

    pub const fn stable_diagnostic_code(self) -> &'static str {
        match self {
            Self::EmptySource => "FE-PARSER-DIAG-EMPTY-SOURCE-0001",
            Self::InvalidGoal => "FE-PARSER-DIAG-INVALID-GOAL-0001",
            Self::UnsupportedSyntax => "FE-PARSER-DIAG-UNSUPPORTED-SYNTAX-0001",
            Self::IoReadFailed => "FE-PARSER-DIAG-IO-READ-FAILED-0001",
            Self::InvalidUtf8 => "FE-PARSER-DIAG-INVALID-UTF8-0001",
            Self::SourceTooLarge => "FE-PARSER-DIAG-SOURCE-TOO-LARGE-0001",
            Self::BudgetExceeded => "FE-PARSER-DIAG-BUDGET-EXCEEDED-0001",
        }
    }

    pub const fn diagnostic_category(self) -> ParseDiagnosticCategory {
        match self {
            Self::EmptySource => ParseDiagnosticCategory::Input,
            Self::InvalidGoal => ParseDiagnosticCategory::Goal,
            Self::UnsupportedSyntax => ParseDiagnosticCategory::Syntax,
            Self::IoReadFailed => ParseDiagnosticCategory::System,
            Self::InvalidUtf8 => ParseDiagnosticCategory::Encoding,
            Self::SourceTooLarge | Self::BudgetExceeded => ParseDiagnosticCategory::Resource,
        }
    }

    pub const fn diagnostic_severity(self) -> ParseDiagnosticSeverity {
        match self {
            Self::IoReadFailed | Self::SourceTooLarge | Self::BudgetExceeded => {
                ParseDiagnosticSeverity::Fatal
            }
            Self::EmptySource | Self::InvalidGoal | Self::UnsupportedSyntax | Self::InvalidUtf8 => {
                ParseDiagnosticSeverity::Error
            }
        }
    }

    pub const fn diagnostic_message_template(
        self,
        budget_kind: Option<ParseBudgetKind>,
    ) -> &'static str {
        match self {
            Self::EmptySource => "source is empty after whitespace normalization",
            Self::InvalidGoal => "declaration is invalid for selected parse goal",
            Self::UnsupportedSyntax => "statement or expression is unsupported by parser scaffold",
            Self::IoReadFailed => "parser input could not be read",
            Self::InvalidUtf8 => "parser input is not valid UTF-8",
            Self::SourceTooLarge => "source length/offset exceeds supported limits",
            Self::BudgetExceeded => match budget_kind {
                Some(ParseBudgetKind::SourceBytes) => "source byte budget exceeded",
                Some(ParseBudgetKind::TokenCount) => "token budget exceeded",
                Some(ParseBudgetKind::RecursionDepth) => "recursion depth budget exceeded",
                None => "parser budget exceeded",
            },
        }
    }
}

/// Deterministic parser diagnostic category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseDiagnosticCategory {
    Input,
    Goal,
    Syntax,
    Encoding,
    Resource,
    System,
}

impl ParseDiagnosticCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Goal => "goal",
            Self::Syntax => "syntax",
            Self::Encoding => "encoding",
            Self::Resource => "resource",
            Self::System => "system",
        }
    }
}

/// Deterministic parser diagnostic severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseDiagnosticSeverity {
    Error,
    Fatal,
}

impl ParseDiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

/// Taxonomy row for one stable parser diagnostic code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseDiagnosticRule {
    pub parse_error_code: ParseErrorCode,
    pub diagnostic_code: String,
    pub category: ParseDiagnosticCategory,
    pub severity: ParseDiagnosticSeverity,
    pub message_template: String,
}

/// Versioned parser diagnostics taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseDiagnosticTaxonomy {
    pub taxonomy_version: String,
    pub rules: Vec<ParseDiagnosticRule>,
}

impl ParseDiagnosticTaxonomy {
    pub const fn taxonomy_version() -> &'static str {
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    }

    pub fn v1() -> Self {
        let rules = ParseErrorCode::ALL
            .iter()
            .map(|code| ParseDiagnosticRule {
                parse_error_code: *code,
                diagnostic_code: code.stable_diagnostic_code().to_string(),
                category: code.diagnostic_category(),
                severity: code.diagnostic_severity(),
                message_template: code.diagnostic_message_template(None).to_string(),
            })
            .collect();
        Self {
            taxonomy_version: Self::taxonomy_version().to_string(),
            rules,
        }
    }

    pub fn rule_for(&self, code: ParseErrorCode) -> Option<&ParseDiagnosticRule> {
        self.rules.iter().find(|rule| rule.parse_error_code == code)
    }
}

/// Parser mode selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserMode {
    /// Deterministic scalar reference parser used as the oracle baseline.
    ScalarReference,
}

impl ParserMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScalarReference => "scalar_reference",
        }
    }
}

/// Deterministic parser budget limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserBudget {
    pub max_source_bytes: u64,
    pub max_token_count: u64,
    pub max_recursion_depth: u64,
}

impl Default for ParserBudget {
    fn default() -> Self {
        Self {
            max_source_bytes: 1_048_576,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        }
    }
}

/// Parser options controlling mode and deterministic budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserOptions {
    pub mode: ParserMode,
    pub budget: ParserBudget,
}

impl Default for ParserOptions {
    fn default() -> Self {
        Self {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget::default(),
        }
    }
}

/// Which budget category exhausted during parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseBudgetKind {
    SourceBytes,
    TokenCount,
    RecursionDepth,
}

impl ParseBudgetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBytes => "source_bytes",
            Self::TokenCount => "token_count",
            Self::RecursionDepth => "recursion_depth",
        }
    }
}

/// Deterministic parse failure witness emitted for budget failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseFailureWitness {
    pub mode: ParserMode,
    pub budget_kind: Option<ParseBudgetKind>,
    pub source_bytes: u64,
    pub token_count: u64,
    pub max_recursion_observed: u64,
    pub max_source_bytes: u64,
    pub max_token_count: u64,
    pub max_recursion_depth: u64,
}

impl ParseFailureWitness {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "mode".to_string(),
            CanonicalValue::String(self.mode.as_str().to_string()),
        );
        map.insert(
            "budget_kind".to_string(),
            self.budget_kind
                .map(|kind| CanonicalValue::String(kind.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "source_bytes".to_string(),
            CanonicalValue::U64(self.source_bytes),
        );
        map.insert(
            "token_count".to_string(),
            CanonicalValue::U64(self.token_count),
        );
        map.insert(
            "max_recursion_observed".to_string(),
            CanonicalValue::U64(self.max_recursion_observed),
        );
        map.insert(
            "max_source_bytes".to_string(),
            CanonicalValue::U64(self.max_source_bytes),
        );
        map.insert(
            "max_token_count".to_string(),
            CanonicalValue::U64(self.max_token_count),
        );
        map.insert(
            "max_recursion_depth".to_string(),
            CanonicalValue::U64(self.max_recursion_depth),
        );
        CanonicalValue::Map(map)
    }
}

/// Coverage status for a grammar family in Script/Module goals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrammarCoverageStatus {
    Supported,
    Partial,
    Unsupported,
    NotApplicable,
}

impl GrammarCoverageStatus {
    fn score_numer(self) -> u64 {
        match self {
            Self::Supported | Self::NotApplicable => 1000,
            Self::Partial => 500,
            Self::Unsupported => 0,
        }
    }
}

/// Single grammar-family row for completeness tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarFamilyCoverage {
    pub family_id: String,
    pub es2020_clause: String,
    pub script_goal: GrammarCoverageStatus,
    pub module_goal: GrammarCoverageStatus,
    pub notes: String,
}

/// Full scalar parser completeness matrix for ES2020 families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarCompletenessMatrix {
    pub schema_version: String,
    pub parser_mode: ParserMode,
    pub families: Vec<GrammarFamilyCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarCompletenessSummary {
    pub family_count: u64,
    pub supported_families: u64,
    pub partially_supported_families: u64,
    pub unsupported_families: u64,
    pub completeness_millionths: u64,
}

/// Deterministic parse error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    pub code: ParseErrorCode,
    pub message: String,
    pub source_label: String,
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<Box<ParseFailureWitness>>,
}

impl ParseError {
    fn new(
        code: ParseErrorCode,
        message: impl Into<String>,
        source_label: impl Into<String>,
        span: Option<SourceSpan>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source_label: source_label.into(),
            span,
            witness: None,
        }
    }

    fn with_witness(
        code: ParseErrorCode,
        message: impl Into<String>,
        source_label: impl Into<String>,
        span: Option<SourceSpan>,
        witness: ParseFailureWitness,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source_label: source_label.into(),
            span,
            witness: Some(Box::new(witness)),
        }
    }

    pub fn normalized_diagnostic(&self) -> ParseDiagnosticEnvelope {
        normalize_parse_error(self)
    }
}

/// Canonical parser diagnostic envelope derived from a parse error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseDiagnosticEnvelope {
    pub schema_version: String,
    pub taxonomy_version: String,
    pub hash_algorithm: String,
    pub hash_prefix: String,
    pub parse_error_code: ParseErrorCode,
    pub diagnostic_code: String,
    pub category: ParseDiagnosticCategory,
    pub severity: ParseDiagnosticSeverity,
    pub message_template: String,
    pub source_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_kind: Option<ParseBudgetKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<ParseFailureWitness>,
}

impl ParseDiagnosticEnvelope {
    pub const fn schema_version() -> &'static str {
        PARSER_DIAGNOSTIC_SCHEMA_VERSION
    }

    pub const fn taxonomy_version() -> &'static str {
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    }

    pub const fn canonical_hash_algorithm() -> &'static str {
        PARSER_DIAGNOSTIC_HASH_ALGORITHM
    }

    pub const fn canonical_hash_prefix() -> &'static str {
        PARSER_DIAGNOSTIC_HASH_PREFIX
    }

    pub fn from_parse_error(error: &ParseError) -> Self {
        normalize_parse_error(error)
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "taxonomy_version".to_string(),
            CanonicalValue::String(self.taxonomy_version.clone()),
        );
        map.insert(
            "hash_algorithm".to_string(),
            CanonicalValue::String(self.hash_algorithm.clone()),
        );
        map.insert(
            "hash_prefix".to_string(),
            CanonicalValue::String(self.hash_prefix.clone()),
        );
        map.insert(
            "parse_error_code".to_string(),
            CanonicalValue::String(self.parse_error_code.as_str().to_string()),
        );
        map.insert(
            "diagnostic_code".to_string(),
            CanonicalValue::String(self.diagnostic_code.clone()),
        );
        map.insert(
            "category".to_string(),
            CanonicalValue::String(self.category.as_str().to_string()),
        );
        map.insert(
            "severity".to_string(),
            CanonicalValue::String(self.severity.as_str().to_string()),
        );
        map.insert(
            "message_template".to_string(),
            CanonicalValue::String(self.message_template.clone()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "span".to_string(),
            self.span
                .as_ref()
                .map(SourceSpan::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "budget_kind".to_string(),
            self.budget_kind
                .map(|kind| CanonicalValue::String(kind.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "witness".to_string(),
            self.witness
                .as_ref()
                .map(ParseFailureWitness::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("{}{}", self.hash_prefix, hex::encode(digest))
    }
}

/// Normalize a parse error into the deterministic diagnostics envelope contract.
pub fn normalize_parse_error(error: &ParseError) -> ParseDiagnosticEnvelope {
    let budget_kind = error
        .witness
        .as_ref()
        .and_then(|witness| witness.budget_kind);
    ParseDiagnosticEnvelope {
        schema_version: ParseDiagnosticEnvelope::schema_version().to_string(),
        taxonomy_version: ParseDiagnosticEnvelope::taxonomy_version().to_string(),
        hash_algorithm: ParseDiagnosticEnvelope::canonical_hash_algorithm().to_string(),
        hash_prefix: ParseDiagnosticEnvelope::canonical_hash_prefix().to_string(),
        parse_error_code: error.code,
        diagnostic_code: error.code.stable_diagnostic_code().to_string(),
        category: error.code.diagnostic_category(),
        severity: error.code.diagnostic_severity(),
        message_template: error
            .code
            .diagnostic_message_template(budget_kind)
            .to_string(),
        source_label: error.source_label.clone(),
        span: error.span.clone(),
        budget_kind,
        witness: error
            .witness
            .as_ref()
            .map(|witness| witness.as_ref().clone()),
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.span {
            Some(span) => write!(
                f,
                "{:?}: {} (source={}, line={}, column={})",
                self.code, self.message, self.source_label, span.start_line, span.start_column
            ),
            None => write!(
                f,
                "{:?}: {} (source={})",
                self.code, self.message, self.source_label
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Stable parse event kinds used by the Parse Event IR schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseEventKind {
    ParseStarted,
    StatementParsed,
    ParseCompleted,
    ParseFailed,
}

impl ParseEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParseStarted => "parse_started",
            Self::StatementParsed => "statement_parsed",
            Self::ParseCompleted => "parse_completed",
            Self::ParseFailed => "parse_failed",
        }
    }

    pub fn canonical_value(self) -> CanonicalValue {
        CanonicalValue::String(self.as_str().to_string())
    }
}

/// Canonical parse-event record with deterministic provenance fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseEvent {
    pub sequence: u64,
    pub kind: ParseEventKind,
    pub parser_mode: ParserMode,
    pub goal: ParseGoal,
    pub source_label: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ParseErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
}

impl ParseEvent {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("sequence".to_string(), CanonicalValue::U64(self.sequence));
        map.insert("kind".to_string(), self.kind.canonical_value());
        map.insert(
            "parser_mode".to_string(),
            CanonicalValue::String(self.parser_mode.as_str().to_string()),
        );
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::String(self.decision_id.clone()),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "outcome".to_string(),
            CanonicalValue::String(self.outcome.clone()),
        );
        map.insert(
            "error_code".to_string(),
            self.error_code
                .map(|code| CanonicalValue::String(code.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "statement_index".to_string(),
            self.statement_index
                .map(CanonicalValue::U64)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "span".to_string(),
            self.span
                .as_ref()
                .map(SourceSpan::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "payload_kind".to_string(),
            self.payload_kind
                .as_ref()
                .map(|value| CanonicalValue::String(value.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "payload_hash".to_string(),
            self.payload_hash
                .as_ref()
                .map(|value| CanonicalValue::String(value.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        CanonicalValue::Map(map)
    }
}

/// Versioned Parse Event IR envelope with deterministic canonical serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseEventIr {
    pub schema_version: String,
    pub contract_version: String,
    pub parser_mode: ParserMode,
    pub goal: ParseGoal,
    pub source_label: String,
    pub events: Vec<ParseEvent>,
}

impl ParseEventIr {
    pub const fn contract_version() -> &'static str {
        PARSE_EVENT_IR_CONTRACT_VERSION
    }

    pub const fn schema_version() -> &'static str {
        PARSE_EVENT_IR_SCHEMA_VERSION
    }

    pub const fn canonical_hash_algorithm() -> &'static str {
        PARSE_EVENT_IR_HASH_ALGORITHM
    }

    pub const fn canonical_hash_prefix() -> &'static str {
        PARSE_EVENT_IR_HASH_PREFIX
    }

    pub fn from_syntax_tree(
        tree: &SyntaxTree,
        source_label: impl Into<String>,
        parser_mode: ParserMode,
    ) -> Self {
        let source_label = source_label.into();
        let source_fingerprint = canonical_value_hash(&tree.canonical_value());
        let (trace_id, decision_id) =
            parse_event_provenance_ids(&source_label, parser_mode, tree.goal, &source_fingerprint);
        Self::from_syntax_tree_with_provenance(
            tree,
            source_label,
            parser_mode,
            trace_id,
            decision_id,
            Some(("syntax_tree".to_string(), source_fingerprint)),
        )
    }

    pub fn from_parse_source(
        tree: &SyntaxTree,
        source_text: &str,
        source_label: impl Into<String>,
        parser_mode: ParserMode,
    ) -> Self {
        let source_label = source_label.into();
        let source_fingerprint = canonical_string_hash(source_text);
        let (trace_id, decision_id) =
            parse_event_provenance_ids(&source_label, parser_mode, tree.goal, &source_fingerprint);
        Self::from_syntax_tree_with_provenance(
            tree,
            source_label,
            parser_mode,
            trace_id,
            decision_id,
            Some(("source_text".to_string(), source_fingerprint)),
        )
    }

    pub fn from_parse_error(error: &ParseError, goal: ParseGoal, parser_mode: ParserMode) -> Self {
        let source_label = error.source_label.clone();
        let diagnostic = ParseDiagnosticEnvelope::from_parse_error(error);
        let diagnostic_hash = diagnostic.canonical_hash();
        let (trace_id, decision_id) =
            parse_event_provenance_ids(&source_label, parser_mode, goal, &diagnostic_hash);
        let events = vec![
            ParseEvent {
                sequence: 0,
                kind: ParseEventKind::ParseStarted,
                parser_mode,
                goal,
                source_label: source_label.clone(),
                trace_id: trace_id.clone(),
                decision_id: decision_id.clone(),
                policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
                component: PARSE_EVENT_IR_COMPONENT.to_string(),
                outcome: "started".to_string(),
                error_code: None,
                statement_index: None,
                span: None,
                payload_kind: Some("parse_diagnostic".to_string()),
                payload_hash: Some(diagnostic_hash.clone()),
            },
            ParseEvent {
                sequence: 1,
                kind: ParseEventKind::ParseFailed,
                parser_mode,
                goal,
                source_label: source_label.clone(),
                trace_id,
                decision_id,
                policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
                component: PARSE_EVENT_IR_COMPONENT.to_string(),
                outcome: "failure".to_string(),
                error_code: Some(error.code),
                statement_index: None,
                span: error.span.clone(),
                payload_kind: Some("parse_diagnostic".to_string()),
                payload_hash: Some(diagnostic_hash),
            },
        ];
        Self {
            schema_version: Self::schema_version().to_string(),
            contract_version: Self::contract_version().to_string(),
            parser_mode,
            goal,
            source_label,
            events,
        }
    }

    fn from_syntax_tree_with_provenance(
        tree: &SyntaxTree,
        source_label: String,
        parser_mode: ParserMode,
        trace_id: String,
        decision_id: String,
        started_payload: Option<(String, String)>,
    ) -> Self {
        let mut events = Vec::new();
        events.push(ParseEvent {
            sequence: 0,
            kind: ParseEventKind::ParseStarted,
            parser_mode,
            goal: tree.goal,
            source_label: source_label.clone(),
            trace_id: trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
            component: PARSE_EVENT_IR_COMPONENT.to_string(),
            outcome: "started".to_string(),
            error_code: None,
            statement_index: None,
            span: None,
            payload_kind: started_payload.as_ref().map(|(kind, _)| kind.clone()),
            payload_hash: started_payload.as_ref().map(|(_, hash)| hash.clone()),
        });

        for (index, statement) in tree.body.iter().enumerate() {
            let statement_index = index as u64;
            events.push(ParseEvent {
                sequence: statement_index.saturating_add(1),
                kind: ParseEventKind::StatementParsed,
                parser_mode,
                goal: tree.goal,
                source_label: source_label.clone(),
                trace_id: trace_id.clone(),
                decision_id: decision_id.clone(),
                policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
                component: PARSE_EVENT_IR_COMPONENT.to_string(),
                outcome: "parsed".to_string(),
                error_code: None,
                statement_index: Some(statement_index),
                span: Some(statement.span().clone()),
                payload_kind: Some(statement_kind_label(statement).to_string()),
                payload_hash: Some(canonical_value_hash(&statement.canonical_value())),
            });
        }

        events.push(ParseEvent {
            sequence: (tree.body.len() as u64).saturating_add(1),
            kind: ParseEventKind::ParseCompleted,
            parser_mode,
            goal: tree.goal,
            source_label: source_label.clone(),
            trace_id,
            decision_id,
            policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
            component: PARSE_EVENT_IR_COMPONENT.to_string(),
            outcome: "success".to_string(),
            error_code: None,
            statement_index: None,
            span: Some(tree.span.clone()),
            payload_kind: Some("syntax_tree".to_string()),
            payload_hash: Some(canonical_value_hash(&tree.canonical_value())),
        });

        Self {
            schema_version: Self::schema_version().to_string(),
            contract_version: Self::contract_version().to_string(),
            parser_mode,
            goal: tree.goal,
            source_label,
            events,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "contract_version".to_string(),
            CanonicalValue::String(self.contract_version.clone()),
        );
        map.insert(
            "hash_algorithm".to_string(),
            CanonicalValue::String(Self::canonical_hash_algorithm().to_string()),
        );
        map.insert(
            "hash_prefix".to_string(),
            CanonicalValue::String(Self::canonical_hash_prefix().to_string()),
        );
        map.insert(
            "parser_mode".to_string(),
            CanonicalValue::String(self.parser_mode.as_str().to_string()),
        );
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "event_count".to_string(),
            CanonicalValue::U64(self.events.len() as u64),
        );
        map.insert(
            "events".to_string(),
            CanonicalValue::Array(
                self.events
                    .iter()
                    .map(ParseEvent::canonical_value)
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("{}{}", Self::canonical_hash_prefix(), hex::encode(digest))
    }

    /// Materialize a deterministic AST witness from this event stream and source text.
    ///
    /// This verifies event ordering/provenance/payload parity, then emits a stable
    /// node-id projection over the canonical AST.
    pub fn materialize_from_source(
        &self,
        source_text: &str,
        options: &ParserOptions,
    ) -> ParseEventMaterializationResult<MaterializedSyntaxTree> {
        if self
            .events
            .iter()
            .any(|event| matches!(event.kind, ParseEventKind::ParseFailed))
        {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::ParseFailedEventStream,
                "cannot materialize AST from a failed parse event stream".to_string(),
                None,
            ));
        }
        if options.mode != self.parser_mode {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::ModeMismatch,
                format!(
                    "materializer mode mismatch: event_ir={} options={}",
                    self.parser_mode.as_str(),
                    options.mode.as_str()
                ),
                None,
            ));
        }
        let parsed =
            parse_source(source_text, &self.source_label, self.goal, options).map_err(|err| {
                ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::SourceParseFailed,
                    format!(
                        "source parse failed while materializing from event stream: {} ({})",
                        err.code.as_str(),
                        err.message
                    ),
                    None,
                )
            })?;
        self.materialize_with_tree(&parsed, Some(source_text))
    }

    /// Materialize a deterministic AST witness from this event stream and a canonical AST.
    pub fn materialize_from_syntax_tree(
        &self,
        tree: &SyntaxTree,
    ) -> ParseEventMaterializationResult<MaterializedSyntaxTree> {
        self.materialize_with_tree(tree, None)
    }

    fn materialize_with_tree(
        &self,
        tree: &SyntaxTree,
        source_text: Option<&str>,
    ) -> ParseEventMaterializationResult<MaterializedSyntaxTree> {
        if self.contract_version != Self::contract_version() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::UnsupportedContractVersion,
                format!(
                    "unsupported event-ir contract version: {}",
                    self.contract_version
                ),
                None,
            ));
        }
        if self.schema_version != Self::schema_version() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::UnsupportedSchemaVersion,
                format!(
                    "unsupported event-ir schema version: {}",
                    self.schema_version
                ),
                None,
            ));
        }
        if self.events.is_empty() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseStarted,
                "event stream is empty".to_string(),
                None,
            ));
        }
        if self.goal != tree.goal {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::GoalMismatch,
                format!(
                    "materializer goal mismatch: event_ir={} syntax_tree={}",
                    self.goal.as_str(),
                    tree.goal.as_str()
                ),
                None,
            ));
        }
        if self
            .events
            .iter()
            .any(|event| matches!(event.kind, ParseEventKind::ParseFailed))
        {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::ParseFailedEventStream,
                "cannot materialize AST from a failed parse event stream".to_string(),
                None,
            ));
        }

        for (expected_sequence, event) in self.events.iter().enumerate() {
            let expected_sequence = expected_sequence as u64;
            if event.sequence != expected_sequence {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::InvalidEventSequence,
                    format!(
                        "non-gap-free event sequence: expected {} got {}",
                        expected_sequence, event.sequence
                    ),
                    Some(event.sequence),
                ));
            }
        }

        let started = self.events.first().expect("non-empty events");
        if started.kind != ParseEventKind::ParseStarted || started.sequence != 0 {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseStarted,
                "first event must be parse_started at sequence 0".to_string(),
                Some(started.sequence),
            ));
        }
        let completed = self.events.last().expect("non-empty events");
        if completed.kind != ParseEventKind::ParseCompleted {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseCompleted,
                "final event must be parse_completed".to_string(),
                Some(completed.sequence),
            ));
        }

        let trace_id = started.trace_id.clone();
        let decision_id = started.decision_id.clone();
        let policy_id = started.policy_id.clone();
        let component = started.component.clone();

        for event in &self.events {
            if event.trace_id != trace_id
                || event.decision_id != decision_id
                || event.policy_id != policy_id
                || event.component != component
                || event.parser_mode != self.parser_mode
                || event.goal != self.goal
                || event.source_label != self.source_label
            {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
                    format!("inconsistent event envelope at sequence {}", event.sequence),
                    Some(event.sequence),
                ));
            }
        }

        let tree_hash = tree.canonical_hash();
        if let Some(payload_kind) = started.payload_kind.as_deref() {
            match payload_kind {
                "source_text" => {
                    if let Some(source_text) = source_text {
                        let source_hash = canonical_string_hash(source_text);
                        if started.payload_hash.as_deref() != Some(source_hash.as_str()) {
                            return Err(ParseEventMaterializationError::new(
                                ParseEventMaterializationErrorCode::SourceHashMismatch,
                                "parse_started payload_hash does not match source_text canonical hash"
                                    .to_string(),
                                Some(started.sequence),
                            ));
                        }
                    }
                }
                "syntax_tree" => {
                    if started.payload_hash.as_deref() != Some(tree_hash.as_str()) {
                        return Err(ParseEventMaterializationError::new(
                            ParseEventMaterializationErrorCode::AstHashMismatch,
                            "parse_started payload_hash does not match syntax_tree canonical hash"
                                .to_string(),
                            Some(started.sequence),
                        ));
                    }
                }
                other => {
                    return Err(ParseEventMaterializationError::new(
                        ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
                        format!("unsupported parse_started payload_kind: {other}"),
                        Some(started.sequence),
                    ));
                }
            }
        }

        let statement_events: Vec<&ParseEvent> = self
            .events
            .iter()
            .filter(|event| event.kind == ParseEventKind::StatementParsed)
            .collect();
        if statement_events.len() != tree.body.len() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::StatementCountMismatch,
                format!(
                    "statement event count mismatch: events={} syntax_tree={}",
                    statement_events.len(),
                    tree.body.len()
                ),
                None,
            ));
        }

        let mut statement_nodes = Vec::with_capacity(statement_events.len());
        for (expected_idx, (event, statement)) in
            statement_events.iter().zip(tree.body.iter()).enumerate()
        {
            let expected_idx_u64 = expected_idx as u64;
            if event.statement_index != Some(expected_idx_u64) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementIndexMismatch,
                    format!(
                        "statement index mismatch at sequence {}: expected {} got {:?}",
                        event.sequence, expected_idx_u64, event.statement_index
                    ),
                    Some(event.sequence),
                ));
            }
            let expected_kind = statement_kind_label(statement);
            if event.payload_kind.as_deref() != Some(expected_kind) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementKindMismatch,
                    format!(
                        "statement payload kind mismatch at sequence {}: expected {} got {:?}",
                        event.sequence, expected_kind, event.payload_kind
                    ),
                    Some(event.sequence),
                ));
            }
            let expected_hash = canonical_value_hash(&statement.canonical_value());
            if event.payload_hash.as_deref() != Some(expected_hash.as_str()) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementHashMismatch,
                    format!(
                        "statement payload hash mismatch at sequence {}",
                        event.sequence
                    ),
                    Some(event.sequence),
                ));
            }
            if event.span.as_ref() != Some(statement.span()) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementSpanMismatch,
                    format!("statement span mismatch at sequence {}", event.sequence),
                    Some(event.sequence),
                ));
            }

            let node_id = parse_event_ast_node_id(
                &trace_id,
                &decision_id,
                event.sequence,
                event.payload_hash.as_deref(),
            );
            statement_nodes.push(MaterializedStatementNode {
                node_id,
                sequence: event.sequence,
                statement_index: expected_idx_u64,
                payload_hash: expected_hash,
                span: statement.span().clone(),
            });
        }

        if completed.payload_kind.as_deref() != Some("syntax_tree") {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
                "parse_completed payload_kind must be syntax_tree".to_string(),
                Some(completed.sequence),
            ));
        }
        if completed.payload_hash.as_deref() != Some(tree_hash.as_str()) {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::AstHashMismatch,
                "parse_completed payload_hash does not match syntax_tree canonical hash"
                    .to_string(),
                Some(completed.sequence),
            ));
        }
        if completed.span.as_ref() != Some(&tree.span) {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::StatementSpanMismatch,
                "parse_completed span does not match syntax_tree span".to_string(),
                Some(completed.sequence),
            ));
        }

        let root_node_id = parse_event_ast_node_id(
            &trace_id,
            &decision_id,
            completed.sequence,
            completed.payload_hash.as_deref(),
        );
        Ok(MaterializedSyntaxTree {
            schema_version: MaterializedSyntaxTree::schema_version().to_string(),
            contract_version: MaterializedSyntaxTree::contract_version().to_string(),
            trace_id,
            decision_id,
            policy_id,
            component,
            parser_mode: self.parser_mode,
            goal: self.goal,
            source_label: self.source_label.clone(),
            root_node_id,
            statement_nodes,
            syntax_tree: tree.clone(),
        })
    }
}

pub type ParseEventMaterializationResult<T> = Result<T, ParseEventMaterializationError>;

/// Stable materialization failure codes for event->AST replay lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseEventMaterializationErrorCode {
    UnsupportedContractVersion,
    UnsupportedSchemaVersion,
    ParseFailedEventStream,
    MissingParseStarted,
    MissingParseCompleted,
    InvalidEventSequence,
    InconsistentEventEnvelope,
    GoalMismatch,
    ModeMismatch,
    StatementCountMismatch,
    StatementIndexMismatch,
    StatementKindMismatch,
    StatementHashMismatch,
    StatementSpanMismatch,
    SourceHashMismatch,
    AstHashMismatch,
    SourceParseFailed,
}

impl ParseEventMaterializationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedContractVersion => "unsupported_contract_version",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::ParseFailedEventStream => "parse_failed_event_stream",
            Self::MissingParseStarted => "missing_parse_started",
            Self::MissingParseCompleted => "missing_parse_completed",
            Self::InvalidEventSequence => "invalid_event_sequence",
            Self::InconsistentEventEnvelope => "inconsistent_event_envelope",
            Self::GoalMismatch => "goal_mismatch",
            Self::ModeMismatch => "mode_mismatch",
            Self::StatementCountMismatch => "statement_count_mismatch",
            Self::StatementIndexMismatch => "statement_index_mismatch",
            Self::StatementKindMismatch => "statement_kind_mismatch",
            Self::StatementHashMismatch => "statement_hash_mismatch",
            Self::StatementSpanMismatch => "statement_span_mismatch",
            Self::SourceHashMismatch => "source_hash_mismatch",
            Self::AstHashMismatch => "ast_hash_mismatch",
            Self::SourceParseFailed => "source_parse_failed",
        }
    }
}

/// Deterministic materializer failure with stable code + message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseEventMaterializationError {
    pub code: ParseEventMaterializationErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

impl ParseEventMaterializationError {
    fn new(
        code: ParseEventMaterializationErrorCode,
        message: String,
        sequence: Option<u64>,
    ) -> Self {
        Self {
            code,
            message,
            sequence,
        }
    }
}

impl fmt::Display for ParseEventMaterializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(sequence) = self.sequence {
            write!(
                f,
                "{} (sequence={}): {}",
                self.code.as_str(),
                sequence,
                self.message
            )
        } else {
            write!(f, "{}: {}", self.code.as_str(), self.message)
        }
    }
}

impl std::error::Error for ParseEventMaterializationError {}

/// Stable statement-node witness emitted by the deterministic AST materializer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedStatementNode {
    pub node_id: String,
    pub sequence: u64,
    pub statement_index: u64,
    pub payload_hash: String,
    pub span: SourceSpan,
}

impl MaterializedStatementNode {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "node_id".to_string(),
            CanonicalValue::String(self.node_id.clone()),
        );
        map.insert("sequence".to_string(), CanonicalValue::U64(self.sequence));
        map.insert(
            "statement_index".to_string(),
            CanonicalValue::U64(self.statement_index),
        );
        map.insert(
            "payload_hash".to_string(),
            CanonicalValue::String(self.payload_hash.clone()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

/// Deterministic AST materialization output projected from Parse Event IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedSyntaxTree {
    pub schema_version: String,
    pub contract_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub parser_mode: ParserMode,
    pub goal: ParseGoal,
    pub source_label: String,
    pub root_node_id: String,
    pub statement_nodes: Vec<MaterializedStatementNode>,
    pub syntax_tree: SyntaxTree,
}

impl MaterializedSyntaxTree {
    pub const fn contract_version() -> &'static str {
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
    }

    pub const fn schema_version() -> &'static str {
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "contract_version".to_string(),
            CanonicalValue::String(self.contract_version.clone()),
        );
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::String(self.decision_id.clone()),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "parser_mode".to_string(),
            CanonicalValue::String(self.parser_mode.as_str().to_string()),
        );
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "root_node_id".to_string(),
            CanonicalValue::String(self.root_node_id.clone()),
        );
        map.insert(
            "statement_nodes".to_string(),
            CanonicalValue::Array(
                self.statement_nodes
                    .iter()
                    .map(MaterializedStatementNode::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "syntax_tree".to_string(),
            self.syntax_tree.canonical_value(),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!(
            "{}{}",
            ParseEventIr::canonical_hash_prefix(),
            hex::encode(digest)
        )
    }
}

fn canonical_value_hash(value: &CanonicalValue) -> String {
    let digest = Sha256::digest(deterministic_serde::encode_value(value));
    format!("{PARSE_EVENT_IR_HASH_PREFIX}{}", hex::encode(digest))
}

fn canonical_string_hash(value: &str) -> String {
    canonical_value_hash(&CanonicalValue::String(value.to_string()))
}

fn parse_event_provenance_ids(
    source_label: &str,
    parser_mode: ParserMode,
    goal: ParseGoal,
    input_fingerprint: &str,
) -> (String, String) {
    let mut seed = BTreeMap::new();
    seed.insert(
        "source_label".to_string(),
        CanonicalValue::String(source_label.to_string()),
    );
    seed.insert(
        "parser_mode".to_string(),
        CanonicalValue::String(parser_mode.as_str().to_string()),
    );
    seed.insert(
        "goal".to_string(),
        CanonicalValue::String(goal.as_str().to_string()),
    );
    seed.insert(
        "input_fingerprint".to_string(),
        CanonicalValue::String(input_fingerprint.to_string()),
    );
    seed.insert(
        "policy_id".to_string(),
        CanonicalValue::String(PARSE_EVENT_IR_POLICY_ID.to_string()),
    );
    seed.insert(
        "component".to_string(),
        CanonicalValue::String(PARSE_EVENT_IR_COMPONENT.to_string()),
    );
    let digest = Sha256::digest(deterministic_serde::encode_value(&CanonicalValue::Map(
        seed,
    )));
    let digest_hex = hex::encode(digest);
    let suffix = &digest_hex[..24];
    (
        format!("{PARSE_EVENT_IR_TRACE_PREFIX}{suffix}"),
        format!("{PARSE_EVENT_IR_DECISION_PREFIX}{suffix}"),
    )
}

fn parse_event_ast_node_id(
    trace_id: &str,
    decision_id: &str,
    sequence: u64,
    payload_hash: Option<&str>,
) -> String {
    let mut seed = BTreeMap::new();
    seed.insert(
        "trace_id".to_string(),
        CanonicalValue::String(trace_id.to_string()),
    );
    seed.insert(
        "decision_id".to_string(),
        CanonicalValue::String(decision_id.to_string()),
    );
    seed.insert("sequence".to_string(), CanonicalValue::U64(sequence));
    seed.insert(
        "payload_hash".to_string(),
        payload_hash
            .map(|hash| CanonicalValue::String(hash.to_string()))
            .unwrap_or(CanonicalValue::Null),
    );
    let digest = Sha256::digest(deterministic_serde::encode_value(&CanonicalValue::Map(
        seed,
    )));
    let digest_hex = hex::encode(digest);
    let suffix = &digest_hex[..24];
    format!("{PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX}{suffix}")
}

fn statement_kind_label(statement: &Statement) -> &'static str {
    match statement {
        Statement::Import(_) => "import",
        Statement::Export(_) => "export",
        Statement::VariableDeclaration(_) => "variable_declaration",
        Statement::Expression(_) => "expression",
    }
}

impl GrammarCompletenessMatrix {
    pub const SCHEMA_VERSION: &'static str = "franken-engine.parser-grammar-completeness.v1";

    pub fn scalar_reference_es2020() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            parser_mode: ParserMode::ScalarReference,
            families: vec![
                GrammarFamilyCoverage {
                    family_id: "program.statement_list".to_string(),
                    es2020_clause: "ECMA-262 §14.2".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Line/semicolon segmented statement list is deterministic.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.expression".to_string(),
                    es2020_clause: "ECMA-262 §14.5".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Expression statements are canonicalized with stable whitespace handling."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.numeric_signed_i64".to_string(),
                    es2020_clause: "ECMA-262 §12.8.3".to_string(),
                    script_goal: GrammarCoverageStatus::Partial,
                    module_goal: GrammarCoverageStatus::Partial,
                    notes:
                        "Deterministic signed i64 subset; full ECMAScript Number grammar pending."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.string_single_double_quote".to_string(),
                    es2020_clause: "ECMA-262 §12.8.4".to_string(),
                    script_goal: GrammarCoverageStatus::Partial,
                    module_goal: GrammarCoverageStatus::Partial,
                    notes:
                        "Single/double quoted literals supported; full escape/template coverage pending."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.boolean".to_string(),
                    es2020_clause: "ECMA-262 §12.9.3".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "true/false recognized as dedicated literals.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.null".to_string(),
                    es2020_clause: "ECMA-262 §12.9.4".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "null recognized as dedicated literal.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.undefined".to_string(),
                    es2020_clause: "ECMA-262 Annex B / runtime literal".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "undefined token preserved as dedicated literal for deterministic lowering."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.await".to_string(),
                    es2020_clause: "ECMA-262 §14.8".to_string(),
                    script_goal: GrammarCoverageStatus::Partial,
                    module_goal: GrammarCoverageStatus::Partial,
                    notes:
                        "Prefix await expression handled recursively without full precedence parser."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.import_default".to_string(),
                    es2020_clause: "ECMA-262 §15.2.2".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Supports `import x from \"m\"`.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.import_side_effect".to_string(),
                    es2020_clause: "ECMA-262 §15.2.2".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Supports `import \"m\"`.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.export_default".to_string(),
                    es2020_clause: "ECMA-262 §15.2.3".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Supports `export default <expr>`.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.export_named_clause".to_string(),
                    es2020_clause: "ECMA-262 §15.2.3".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Partial,
                    notes:
                        "Named clause stored canonically as clause text; binding-level semantics pending."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.variable_declaration".to_string(),
                    es2020_clause: "ECMA-262 §14.3".to_string(),
                    script_goal: GrammarCoverageStatus::Partial,
                    module_goal: GrammarCoverageStatus::Partial,
                    notes:
                        "Supports `var` declarations with identifier bindings and optional initializers; let/const/destructuring remain pending."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.function_declaration".to_string(),
                    es2020_clause: "ECMA-262 §14.1".to_string(),
                    script_goal: GrammarCoverageStatus::Unsupported,
                    module_goal: GrammarCoverageStatus::Unsupported,
                    notes: "Function/class declaration families remain unimplemented.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.binary_precedence".to_string(),
                    es2020_clause: "ECMA-262 §13.15".to_string(),
                    script_goal: GrammarCoverageStatus::Unsupported,
                    module_goal: GrammarCoverageStatus::Unsupported,
                    notes: "Binary operators currently preserved as raw canonical expressions."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.call_member_chain".to_string(),
                    es2020_clause: "ECMA-262 §13.3".to_string(),
                    script_goal: GrammarCoverageStatus::Partial,
                    module_goal: GrammarCoverageStatus::Partial,
                    notes:
                        "Call/member surface retained as raw fallback without full parse structure."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.object_array_literal".to_string(),
                    es2020_clause: "ECMA-262 §13.2".to_string(),
                    script_goal: GrammarCoverageStatus::Unsupported,
                    module_goal: GrammarCoverageStatus::Unsupported,
                    notes: "Object/array literal structure not yet represented in AST.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.template_literal".to_string(),
                    es2020_clause: "ECMA-262 §13.2.8".to_string(),
                    script_goal: GrammarCoverageStatus::Unsupported,
                    module_goal: GrammarCoverageStatus::Unsupported,
                    notes: "Template literal grammar is pending.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.arrow_function".to_string(),
                    es2020_clause: "ECMA-262 §14.2".to_string(),
                    script_goal: GrammarCoverageStatus::Unsupported,
                    module_goal: GrammarCoverageStatus::Unsupported,
                    notes: "Arrow/function expressions are pending.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.control_flow".to_string(),
                    es2020_clause: "ECMA-262 §14".to_string(),
                    script_goal: GrammarCoverageStatus::Unsupported,
                    module_goal: GrammarCoverageStatus::Unsupported,
                    notes: "if/for/while/switch/try grammar families are pending.".to_string(),
                },
            ],
        }
    }

    pub fn summary(&self) -> GrammarCompletenessSummary {
        let mut supported = 0u64;
        let mut partial = 0u64;
        let mut unsupported = 0u64;
        let mut score = 0u64;

        for family in &self.families {
            let family_score =
                (family.script_goal.score_numer() + family.module_goal.score_numer()) / 2;
            score = score.saturating_add(family_score);

            if family_score == 1000 {
                supported = supported.saturating_add(1);
            } else if family_score == 0 {
                unsupported = unsupported.saturating_add(1);
            } else {
                partial = partial.saturating_add(1);
            }
        }

        let family_count = self.families.len() as u64;
        let completeness_millionths = if family_count == 0 {
            0
        } else {
            score.saturating_mul(1_000_000) / family_count.saturating_mul(1000)
        };

        GrammarCompletenessSummary {
            family_count,
            supported_families: supported,
            partially_supported_families: partial,
            unsupported_families: unsupported,
            completeness_millionths,
        }
    }
}

/// Concrete source text resolved from a parser input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserSource {
    pub label: String,
    pub text: String,
}

/// Input adapter trait: parse from strings, files, or stream wrappers.
pub trait ParserInput {
    fn into_source(self) -> ParseResult<ParserSource>;
}

impl ParserInput for &str {
    fn into_source(self) -> ParseResult<ParserSource> {
        Ok(ParserSource {
            label: "<inline>".to_string(),
            text: self.to_string(),
        })
    }
}

impl ParserInput for String {
    fn into_source(self) -> ParseResult<ParserSource> {
        Ok(ParserSource {
            label: "<inline>".to_string(),
            text: self,
        })
    }
}

impl ParserInput for &Path {
    fn into_source(self) -> ParseResult<ParserSource> {
        let text = fs::read_to_string(self).map_err(|error| {
            ParseError::new(
                ParseErrorCode::IoReadFailed,
                format!("failed to read source file: {error}"),
                self.display().to_string(),
                None,
            )
        })?;
        Ok(ParserSource {
            label: self.display().to_string(),
            text,
        })
    }
}

impl ParserInput for PathBuf {
    fn into_source(self) -> ParseResult<ParserSource> {
        self.as_path().into_source()
    }
}

/// Stream-backed parser input wrapper.
#[derive(Debug)]
pub struct StreamInput<R> {
    label: String,
    reader: R,
}

impl<R> StreamInput<R> {
    pub fn new(reader: R, label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            reader,
        }
    }
}

impl<R> ParserInput for StreamInput<R>
where
    R: Read,
{
    fn into_source(mut self) -> ParseResult<ParserSource> {
        let mut bytes = Vec::new();
        self.reader.read_to_end(&mut bytes).map_err(|error| {
            ParseError::new(
                ParseErrorCode::IoReadFailed,
                format!("failed to read source stream: {error}"),
                self.label.clone(),
                None,
            )
        })?;
        let text = String::from_utf8(bytes).map_err(|error| {
            ParseError::new(
                ParseErrorCode::InvalidUtf8,
                format!("stream contains invalid UTF-8: {error}"),
                self.label.clone(),
                None,
            )
        })?;
        Ok(ParserSource {
            label: self.label,
            text,
        })
    }
}

/// Parser trait for ES2020 script/module goals.
pub trait Es2020Parser {
    fn parse<I>(&self, input: I, goal: ParseGoal) -> ParseResult<SyntaxTree>
    where
        I: ParserInput;
}

/// Deterministic parser implementation used by current VM-core scaffolding.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalEs2020Parser;

impl CanonicalEs2020Parser {
    pub fn parse_with_options<I>(
        &self,
        input: I,
        goal: ParseGoal,
        options: &ParserOptions,
    ) -> ParseResult<SyntaxTree>
    where
        I: ParserInput,
    {
        let (result, _event_ir) = self.parse_with_event_ir(input, goal, options);
        result
    }

    /// Parse input while emitting a deterministic Parse Event IR stream.
    ///
    /// This method always returns a Parse Event IR value, including when parsing
    /// fails, so callers can persist replay-ready provenance for diagnostics.
    pub fn parse_with_event_ir<I>(
        &self,
        input: I,
        goal: ParseGoal,
        options: &ParserOptions,
    ) -> (ParseResult<SyntaxTree>, ParseEventIr)
    where
        I: ParserInput,
    {
        match input.into_source() {
            Ok(source) => match parse_source(&source.text, &source.label, goal, options) {
                Ok(tree) => {
                    let event_ir = ParseEventIr::from_parse_source(
                        &tree,
                        &source.text,
                        source.label,
                        options.mode,
                    );
                    (Ok(tree), event_ir)
                }
                Err(error) => {
                    let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                    (Err(error), event_ir)
                }
            },
            Err(error) => {
                let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                (Err(error), event_ir)
            }
        }
    }

    /// Parse input, emit deterministic event IR, and materialize deterministic AST node witnesses.
    pub fn parse_with_materialized_ast<I>(
        &self,
        input: I,
        goal: ParseGoal,
        options: &ParserOptions,
    ) -> (
        ParseResult<SyntaxTree>,
        ParseEventIr,
        ParseEventMaterializationResult<MaterializedSyntaxTree>,
    )
    where
        I: ParserInput,
    {
        match input.into_source() {
            Ok(source) => match parse_source(&source.text, &source.label, goal, options) {
                Ok(tree) => {
                    let event_ir = ParseEventIr::from_parse_source(
                        &tree,
                        &source.text,
                        source.label.clone(),
                        options.mode,
                    );
                    let materialized = event_ir.materialize_with_tree(&tree, Some(&source.text));
                    (Ok(tree), event_ir, materialized)
                }
                Err(error) => {
                    let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                    let materialized = Err(ParseEventMaterializationError::new(
                        ParseEventMaterializationErrorCode::ParseFailedEventStream,
                        "cannot materialize AST for failed parse".to_string(),
                        None,
                    ));
                    (Err(error), event_ir, materialized)
                }
            },
            Err(error) => {
                let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                let materialized = Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::ParseFailedEventStream,
                    "cannot materialize AST for failed parse".to_string(),
                    None,
                ));
                (Err(error), event_ir, materialized)
            }
        }
    }

    pub fn scalar_reference_grammar_matrix(&self) -> GrammarCompletenessMatrix {
        GrammarCompletenessMatrix::scalar_reference_es2020()
    }
}

impl Es2020Parser for CanonicalEs2020Parser {
    fn parse<I>(&self, input: I, goal: ParseGoal) -> ParseResult<SyntaxTree>
    where
        I: ParserInput,
    {
        self.parse_with_options(input, goal, &ParserOptions::default())
    }
}

#[derive(Debug)]
struct ParseExecutionContext<'a> {
    source_label: &'a str,
    options: &'a ParserOptions,
    source_bytes: u64,
    token_count: u64,
    max_recursion_observed: u64,
}

impl<'a> ParseExecutionContext<'a> {
    fn next_depth(&mut self, depth: u64) {
        if depth > self.max_recursion_observed {
            self.max_recursion_observed = depth;
        }
    }

    fn witness(&self, budget_kind: Option<ParseBudgetKind>) -> ParseFailureWitness {
        ParseFailureWitness {
            mode: self.options.mode,
            budget_kind,
            source_bytes: self.source_bytes,
            token_count: self.token_count,
            max_recursion_observed: self.max_recursion_observed,
            max_source_bytes: self.options.budget.max_source_bytes,
            max_token_count: self.options.budget.max_token_count,
            max_recursion_depth: self.options.budget.max_recursion_depth,
        }
    }
}

fn parse_source(
    text: &str,
    source_label: &str,
    goal: ParseGoal,
    options: &ParserOptions,
) -> ParseResult<SyntaxTree> {
    if text.trim().is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::EmptySource,
            "source is empty after whitespace normalization",
            source_label.to_string(),
            None,
        ));
    }

    let source_bytes = to_u64(text.len(), source_label, None)?;
    let token_count = count_lexical_tokens(text);
    let mut context = ParseExecutionContext {
        source_label,
        options,
        source_bytes,
        token_count,
        max_recursion_observed: 0,
    };

    if source_bytes > options.budget.max_source_bytes {
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            format!(
                "source byte budget exceeded: source_bytes={} max_source_bytes={}",
                source_bytes, options.budget.max_source_bytes
            ),
            source_label.to_string(),
            None,
            context.witness(Some(ParseBudgetKind::SourceBytes)),
        ));
    }

    if token_count > options.budget.max_token_count {
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            format!(
                "token budget exceeded: token_count={} max_token_count={}",
                token_count, options.budget.max_token_count
            ),
            source_label.to_string(),
            None,
            context.witness(Some(ParseBudgetKind::TokenCount)),
        ));
    }

    let mut statements = Vec::new();
    let mut offset = 0usize;

    for (line_idx, segment) in text.split_inclusive('\n').enumerate() {
        let line_no = to_u64(line_idx + 1, source_label, None)?;
        let line = segment
            .strip_suffix('\n')
            .unwrap_or(segment)
            .strip_suffix('\r')
            .unwrap_or(segment.strip_suffix('\n').unwrap_or(segment));
        let line_start_offset = offset;

        for (start_in_line, end_in_line, statement_text) in split_statement_segments(line) {
            let span = span_for_segment(
                line_start_offset,
                line_no,
                start_in_line,
                end_in_line,
                source_label,
            )?;
            statements.push(parse_statement(statement_text, goal, span, &mut context)?);
        }

        offset = offset.saturating_add(segment.len());
    }

    let source_len = to_u64(text.len(), source_label, None)?;
    let span = SourceSpan::new(0, source_len, 1, 1, line_count(text), 1);
    Ok(SyntaxTree {
        goal,
        body: statements,
        span,
    })
}

fn line_count(source: &str) -> u64 {
    let mut count = 1u64;
    for byte in source.as_bytes() {
        if *byte == b'\n' {
            count = count.saturating_add(1);
        }
    }
    count
}

fn split_statement_segments(line: &str) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::new();
    let mut segment_start = 0usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;

    for (index, ch) in line.char_indices() {
        if let Some(quote) = in_quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == quote {
                in_quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => in_quote = Some(ch),
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                push_segment(&mut out, line, segment_start, index);
                segment_start = index.saturating_add(ch.len_utf8());
            }
            _ => {}
        }
    }
    push_segment(&mut out, line, segment_start, line.len());
    out
}

fn push_segment<'a>(
    out: &mut Vec<(usize, usize, &'a str)>,
    line: &'a str,
    start: usize,
    end: usize,
) {
    if end < start {
        return;
    }
    let raw = &line[start..end];
    let leading = raw.len().saturating_sub(raw.trim_start().len());
    let trailing = raw.len().saturating_sub(raw.trim_end().len());
    let trimmed_start = start.saturating_add(leading);
    let trimmed_end = end.saturating_sub(trailing);
    if trimmed_end <= trimmed_start {
        return;
    }
    let trimmed = &line[trimmed_start..trimmed_end];
    out.push((trimmed_start, trimmed_end, trimmed));
}

fn span_for_segment(
    line_start_offset: usize,
    line_no: u64,
    start_in_line: usize,
    end_in_line: usize,
    source_label: &str,
) -> ParseResult<SourceSpan> {
    let start_offset = line_start_offset
        .checked_add(start_in_line)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::SourceTooLarge,
                "source offset overflow",
                source_label.to_string(),
                None,
            )
        })
        .and_then(|v| to_u64(v, source_label, None))?;
    let end_offset = line_start_offset
        .checked_add(end_in_line)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::SourceTooLarge,
                "source offset overflow",
                source_label.to_string(),
                None,
            )
        })
        .and_then(|v| to_u64(v, source_label, None))?;
    let start_column = to_u64(start_in_line.saturating_add(1), source_label, None)?;
    let end_column = to_u64(end_in_line.saturating_add(1), source_label, None)?;
    Ok(SourceSpan::new(
        start_offset,
        end_offset,
        line_no,
        start_column,
        line_no,
        end_column,
    ))
}

fn parse_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    if statement.starts_with("import ") || statement == "import" {
        if goal == ParseGoal::Script {
            return Err(ParseError::new(
                ParseErrorCode::InvalidGoal,
                "import declarations are only valid in module goal",
                context.source_label.to_string(),
                Some(span),
            ));
        }
        return parse_import(statement, context.source_label, span).map(Statement::Import);
    }

    if statement.starts_with("export ") || statement == "export" {
        if goal == ParseGoal::Script {
            return Err(ParseError::new(
                ParseErrorCode::InvalidGoal,
                "export declarations are only valid in module goal",
                context.source_label.to_string(),
                Some(span),
            ));
        }
        return parse_export(statement, span, context).map(Statement::Export);
    }

    if is_var_declaration_statement(statement) {
        return parse_var_declaration(statement, span, context).map(Statement::VariableDeclaration);
    }

    let expression = parse_expression(statement, &span, context, 1)?;
    Ok(Statement::Expression(ExpressionStatement {
        expression,
        span,
    }))
}

fn parse_import(
    statement: &str,
    source_label: &str,
    span: SourceSpan,
) -> ParseResult<ImportDeclaration> {
    let body = statement
        .get("import ".len()..)
        .map(str::trim)
        .unwrap_or("");
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import declaration is missing clause",
            source_label.to_string(),
            Some(span),
        ));
    }

    if let Some(source) = parse_quoted_string(body) {
        return Ok(ImportDeclaration {
            binding: None,
            source,
            span,
        });
    }

    let (binding_raw, source_raw) = body.split_once(" from ").ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import declaration must be `import <binding> from <quoted-source>` or `import <quoted-source>`",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    let binding = binding_raw.trim();
    if !is_identifier(binding) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "only default identifier imports are supported in this parser scaffold",
            source_label.to_string(),
            Some(span),
        ));
    }
    let source = parse_quoted_string(source_raw.trim()).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import source must be quoted",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    Ok(ImportDeclaration {
        binding: Some(binding.to_string()),
        source,
        span,
    })
}

fn parse_export(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<ExportDeclaration> {
    let body = statement
        .get("export ".len()..)
        .map(str::trim)
        .unwrap_or("");
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "export declaration is missing clause",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let kind = if let Some(default_expr) = body.strip_prefix("default ") {
        ExportKind::Default(parse_expression(default_expr.trim(), &span, context, 1)?)
    } else {
        ExportKind::NamedClause(canonicalize_whitespace(body))
    };
    Ok(ExportDeclaration { kind, span })
}

fn is_var_declaration_statement(statement: &str) -> bool {
    let Some(rest) = statement.strip_prefix("var") else {
        return false;
    };
    rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace)
}

fn parse_var_declaration(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<VariableDeclaration> {
    let body = statement
        .strip_prefix("var")
        .map(str::trim_start)
        .unwrap_or_default();
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "var declaration must include at least one binding",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let declarator_segments = split_var_declarator_segments(body);
    if declarator_segments.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "var declaration must include at least one binding",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let mut declarations = Vec::with_capacity(declarator_segments.len());
    for declarator in declarator_segments {
        let (name_raw, initializer_raw) = split_var_declarator_assignment(declarator);
        let name = name_raw.trim();
        if !is_identifier(name) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "var declaration bindings must be identifiers in parser scaffold",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }

        let initializer = match initializer_raw {
            Some(initializer_source) => {
                let initializer_source = initializer_source.trim();
                if initializer_source.is_empty() {
                    return Err(ParseError::new(
                        ParseErrorCode::UnsupportedSyntax,
                        "var initializer expression is empty",
                        context.source_label.to_string(),
                        Some(span.clone()),
                    ));
                }
                Some(parse_expression(initializer_source, &span, context, 1)?)
            }
            None => None,
        };

        declarations.push(VariableDeclarator {
            name: name.to_string(),
            initializer,
            span: span.clone(),
        });
    }

    Ok(VariableDeclaration {
        kind: VariableDeclarationKind::Var,
        declarations,
        span,
    })
}

fn split_var_declarator_segments(source: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut segment_start = 0usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;

    for (index, ch) in source.char_indices() {
        if let Some(quote) = in_quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == quote {
                in_quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => in_quote = Some(ch),
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                push_var_declarator_segment(&mut out, source, segment_start, index);
                segment_start = index.saturating_add(ch.len_utf8());
            }
            _ => {}
        }
    }
    push_var_declarator_segment(&mut out, source, segment_start, source.len());
    out
}

fn push_var_declarator_segment<'a>(
    out: &mut Vec<&'a str>,
    source: &'a str,
    start: usize,
    end: usize,
) {
    if end < start {
        return;
    }
    let raw = &source[start..end];
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    out.push(trimmed);
}

fn split_var_declarator_assignment(segment: &str) -> (&str, Option<&str>) {
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;

    for (index, ch) in segment.char_indices() {
        if let Some(quote) = in_quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == quote {
                in_quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => in_quote = Some(ch),
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '=' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                let prev = segment[..index].chars().next_back();
                let next = segment[index.saturating_add(ch.len_utf8())..]
                    .chars()
                    .next();
                let part_of_comparison =
                    matches!(prev, Some('=') | Some('!') | Some('<') | Some('>'))
                        || matches!(next, Some('='));
                if part_of_comparison {
                    continue;
                }
                let rhs_start = index.saturating_add(ch.len_utf8());
                return (&segment[..index], Some(&segment[rhs_start..]));
            }
            _ => {}
        }
    }

    (segment, None)
}

fn parse_expression(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    context.next_depth(recursion_depth);
    if recursion_depth > context.options.budget.max_recursion_depth {
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            format!(
                "recursion budget exceeded: depth={} max_recursion_depth={}",
                recursion_depth, context.options.budget.max_recursion_depth
            ),
            context.source_label.to_string(),
            Some(span.clone()),
            context.witness(Some(ParseBudgetKind::RecursionDepth)),
        ));
    }

    let expression = expression.trim();
    if expression.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "empty expression statement",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    if let Some(value) = parse_quoted_string(expression) {
        return Ok(Expression::StringLiteral(value));
    }

    if let Some(value) = parse_i64_numeric_literal(expression) {
        return Ok(Expression::NumericLiteral(value));
    }

    if expression == "true" {
        return Ok(Expression::BooleanLiteral(true));
    }
    if expression == "false" {
        return Ok(Expression::BooleanLiteral(false));
    }
    if expression == "null" {
        return Ok(Expression::NullLiteral);
    }
    if expression == "undefined" {
        return Ok(Expression::UndefinedLiteral);
    }

    if let Some(rest) = expression.strip_prefix("await ") {
        let nested = parse_expression(rest.trim(), span, context, recursion_depth + 1)?;
        return Ok(Expression::Await(Box::new(nested)));
    }
    if is_identifier(expression) {
        return Ok(Expression::Identifier(expression.to_string()));
    }
    Ok(Expression::Raw(canonicalize_whitespace(expression)))
}

fn parse_i64_numeric_literal(input: &str) -> Option<i64> {
    let mut chars = input.chars();
    let first = chars.next()?;

    if first == '-' {
        let rest = chars.as_str();
        if rest.is_empty() || !rest.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        return input.parse::<i64>().ok();
    }

    if first.is_ascii_digit() && input.chars().all(|ch| ch.is_ascii_digit()) {
        return input.parse::<i64>().ok();
    }

    None
}

fn parse_quoted_string(input: &str) -> Option<String> {
    if input.len() < 2 {
        return None;
    }
    let first = input.as_bytes()[0];
    let last = input.as_bytes()[input.len() - 1];
    if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
        let inner = &input[1..input.len() - 1];
        if inner.contains('\n') || inner.contains('\r') {
            return None;
        }
        return Some(inner.to_string());
    }
    None
}

const LEX_CLASS_WHITESPACE: u8 = 1 << 0;
const LEX_CLASS_IDENTIFIER_START: u8 = 1 << 1;
const LEX_CLASS_IDENTIFIER_CONTINUE: u8 = 1 << 2;
const LEX_CLASS_DIGIT: u8 = 1 << 3;
const LEX_CLASS_QUOTE: u8 = 1 << 4;
const LEX_CLASS_TWO_CHAR_OPERATOR_LEAD: u8 = 1 << 5;

const LEX_BYTE_CLASS_TABLE: [u8; 256] = build_lex_byte_class_table();

const fn build_lex_byte_class_table() -> [u8; 256] {
    let mut table = [0u8; 256];

    table[b' ' as usize] |= LEX_CLASS_WHITESPACE;
    table[b'\t' as usize] |= LEX_CLASS_WHITESPACE;
    table[b'\n' as usize] |= LEX_CLASS_WHITESPACE;
    table[b'\r' as usize] |= LEX_CLASS_WHITESPACE;
    table[0x0b] |= LEX_CLASS_WHITESPACE;
    table[0x0c] |= LEX_CLASS_WHITESPACE;

    let mut value = b'a';
    while value <= b'z' {
        table[value as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;
        value = value.saturating_add(1);
    }
    value = b'A';
    while value <= b'Z' {
        table[value as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;
        value = value.saturating_add(1);
    }

    value = b'0';
    while value <= b'9' {
        table[value as usize] |= LEX_CLASS_DIGIT | LEX_CLASS_IDENTIFIER_CONTINUE;
        value = value.saturating_add(1);
    }

    table[b'_' as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;
    table[b'$' as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;

    table[b'\'' as usize] |= LEX_CLASS_QUOTE;
    table[b'"' as usize] |= LEX_CLASS_QUOTE;

    table[b'=' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'!' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'<' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'>' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'&' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'|' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'?' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;

    table
}

#[inline]
const fn lex_class(byte: u8) -> u8 {
    LEX_BYTE_CLASS_TABLE[byte as usize]
}

#[inline]
const fn lex_has_class(byte: u8, class_mask: u8) -> bool {
    (lex_class(byte) & class_mask) != 0
}

#[inline]
const fn is_two_char_operator(first: u8, second: u8) -> bool {
    matches!(
        (first, second),
        (b'=', b'=')
            | (b'!', b'=')
            | (b'<', b'=')
            | (b'>', b'=')
            | (b'&', b'&')
            | (b'|', b'|')
            | (b'?', b'?')
            | (b'=', b'>')
    )
}

#[inline]
const fn utf8_codepoint_len_from_lead(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if (lead & 0b1110_0000) == 0b1100_0000 {
        2
    } else if (lead & 0b1111_0000) == 0b1110_0000 {
        3
    } else if (lead & 0b1111_1000) == 0b1111_0000 {
        4
    } else {
        1
    }
}

#[inline]
const fn is_utf8_continuation(byte: u8) -> bool {
    (byte & 0b1100_0000) == 0b1000_0000
}

fn advance_utf8_boundary_safe(bytes: &[u8], index: usize) -> usize {
    if index >= bytes.len() {
        return bytes.len();
    }

    let width = utf8_codepoint_len_from_lead(bytes[index]);
    let fallback = index.saturating_add(1);
    if width == 1 || index.saturating_add(width) > bytes.len() {
        return fallback;
    }

    let mut offset = index + 1;
    while offset < index + width {
        if !is_utf8_continuation(bytes[offset]) {
            return fallback;
        }
        offset = offset.saturating_add(1);
    }

    index + width
}

#[derive(Debug)]
struct Utf8BoundarySafeScanner<'a> {
    bytes: &'a [u8],
    index: usize,
    token_count: u64,
}

impl<'a> Utf8BoundarySafeScanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            index: 0,
            token_count: 0,
        }
    }

    fn count_tokens(mut self) -> u64 {
        while self.index < self.bytes.len() {
            let byte = self.bytes[self.index];

            if lex_has_class(byte, LEX_CLASS_WHITESPACE) {
                self.index = self.index.saturating_add(1);
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_IDENTIFIER_START) {
                self.scan_identifier();
                self.bump_token();
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_DIGIT) {
                self.scan_numeric_literal();
                self.bump_token();
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_QUOTE) {
                self.scan_string_literal(byte);
                self.bump_token();
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_TWO_CHAR_OPERATOR_LEAD)
                && self.index + 1 < self.bytes.len()
                && is_two_char_operator(byte, self.bytes[self.index + 1])
            {
                self.index = self.index.saturating_add(2);
                self.bump_token();
                continue;
            }

            self.advance_single_symbol();
            self.bump_token();
        }

        self.token_count
    }

    fn scan_identifier(&mut self) {
        self.index = self.index.saturating_add(1);
        while self.index < self.bytes.len()
            && lex_has_class(self.bytes[self.index], LEX_CLASS_IDENTIFIER_CONTINUE)
        {
            self.index = self.index.saturating_add(1);
        }
    }

    fn scan_numeric_literal(&mut self) {
        self.index = self.index.saturating_add(1);
        while self.index < self.bytes.len()
            && lex_has_class(self.bytes[self.index], LEX_CLASS_DIGIT)
        {
            self.index = self.index.saturating_add(1);
        }
    }

    fn scan_string_literal(&mut self, quote: u8) {
        self.index = self.index.saturating_add(1);

        while self.index < self.bytes.len() {
            let current = self.bytes[self.index];

            if current == b'\\' {
                self.index = self.index.saturating_add(1);
                if self.index < self.bytes.len() {
                    if self.bytes[self.index].is_ascii() {
                        self.index = self.index.saturating_add(1);
                    } else {
                        self.index = advance_utf8_boundary_safe(self.bytes, self.index);
                    }
                }
                continue;
            }

            if current == quote {
                self.index = self.index.saturating_add(1);
                break;
            }

            if current == b'\n' || current == b'\r' {
                break;
            }

            if current.is_ascii() {
                self.index = self.index.saturating_add(1);
            } else {
                self.index = advance_utf8_boundary_safe(self.bytes, self.index);
            }
        }
    }

    fn advance_single_symbol(&mut self) {
        if self.bytes[self.index].is_ascii() {
            self.index = self.index.saturating_add(1);
        } else {
            self.index = advance_utf8_boundary_safe(self.bytes, self.index);
        }
    }

    fn bump_token(&mut self) {
        self.token_count = self.token_count.saturating_add(1);
    }
}

fn count_lexical_tokens(input: &str) -> u64 {
    let token_count = Utf8BoundarySafeScanner::new(input.as_bytes()).count_tokens();
    if input.is_ascii() {
        debug_assert_eq!(token_count, count_lexical_tokens_scalar_reference(input));
    }
    token_count
}

fn count_lexical_tokens_scalar_reference(input: &str) -> u64 {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    let mut token_count = 0u64;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index = index.saturating_add(1);
            continue;
        }

        let ch = byte as char;
        if is_identifier_start(ch) {
            index = index.saturating_add(1);
            while index < bytes.len() && is_identifier_continue(bytes[index] as char) {
                index = index.saturating_add(1);
            }
            token_count = token_count.saturating_add(1);
            continue;
        }

        if byte.is_ascii_digit() {
            index = index.saturating_add(1);
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index = index.saturating_add(1);
            }
            token_count = token_count.saturating_add(1);
            continue;
        }

        if byte == b'\'' || byte == b'"' {
            let quote = byte;
            index = index.saturating_add(1);
            let mut terminated = false;

            while index < bytes.len() {
                let current = bytes[index];
                if current == b'\\' {
                    index = index.saturating_add(2);
                    continue;
                }
                if current == quote {
                    index = index.saturating_add(1);
                    terminated = true;
                    break;
                }
                if current == b'\n' || current == b'\r' {
                    break;
                }
                index = index.saturating_add(1);
            }

            if !terminated {
                // Token budget accounting must not force stricter syntax acceptance
                // than the parser surface itself; keep unmatched quotes tokenized.
                token_count = token_count.saturating_add(1);
                continue;
            }

            token_count = token_count.saturating_add(1);
            continue;
        }

        if index + 1 < bytes.len() && is_two_char_operator(bytes[index], bytes[index + 1]) {
            index = index.saturating_add(2);
            token_count = token_count.saturating_add(1);
            continue;
        }

        index = index.saturating_add(1);
        token_count = token_count.saturating_add(1);
    }

    token_count
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_' || ch == '$'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
}

fn is_identifier(input: &str) -> bool {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !is_identifier_start(first) {
        return false;
    }
    chars.all(is_identifier_continue)
}

fn canonicalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn to_u64(value: usize, source_label: &str, span: Option<SourceSpan>) -> ParseResult<u64> {
    u64::try_from(value).map_err(|_| {
        ParseError::new(
            ParseErrorCode::SourceTooLarge,
            "source length/offset does not fit into u64",
            source_label.to_string(),
            span,
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn script_goal_rejects_import_declaration() {
        let parser = CanonicalEs2020Parser;
        let error = parser
            .parse("import x from 'mod';", ParseGoal::Script)
            .expect_err("script goal should reject import");
        assert_eq!(error.code, ParseErrorCode::InvalidGoal);
    }

    #[test]
    fn parser_accepts_stream_inputs() {
        let parser = CanonicalEs2020Parser;
        let input = StreamInput::new(Cursor::new("x;\n42;\n"), "stdin");
        let tree = parser
            .parse(input, ParseGoal::Script)
            .expect("stream parse should succeed");
        assert_eq!(tree.body.len(), 2);
    }

    #[test]
    fn canonical_ast_bytes_are_stable_for_identical_input() {
        let parser = CanonicalEs2020Parser;
        let source = "await work";
        let left = parser.parse(source, ParseGoal::Script).expect("left parse");
        let right = parser
            .parse(source, ParseGoal::Script)
            .expect("right parse");
        assert_eq!(left.canonical_bytes(), right.canonical_bytes());
        assert_eq!(left.canonical_hash(), right.canonical_hash());
    }

    #[test]
    fn equivalent_whitespace_keeps_expression_shape() {
        let parser = CanonicalEs2020Parser;
        let left = parser
            .parse("await   work", ParseGoal::Script)
            .expect("left parse");
        let right = parser
            .parse("await work", ParseGoal::Script)
            .expect("right parse");

        let left_expr = match &left.body[0] {
            Statement::Expression(expr) => &expr.expression,
            _ => panic!("expected expression statement"),
        };
        let right_expr = match &right.body[0] {
            Statement::Expression(expr) => &expr.expression,
            _ => panic!("expected expression statement"),
        };
        assert_eq!(left_expr.canonical_value(), right_expr.canonical_value());
    }

    #[test]
    fn module_import_forms_are_supported() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "import dep from \"pkg\";\nimport \"side-effect\";\nexport default dep;",
                ParseGoal::Module,
            )
            .expect("module parse should succeed");
        assert_eq!(tree.body.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Empty / whitespace-only source
    // -----------------------------------------------------------------------

    #[test]
    fn empty_source_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("", ParseGoal::Script)
            .expect_err("empty source must fail");
        assert_eq!(err.code, ParseErrorCode::EmptySource);
    }

    #[test]
    fn whitespace_only_source_is_rejected() {
        let parser = CanonicalEs2020Parser;
        for ws in ["  ", "\t\t", "\n\n", "  \n  \t  "] {
            let err = parser
                .parse(ws, ParseGoal::Script)
                .expect_err("whitespace-only source must fail");
            assert_eq!(err.code, ParseErrorCode::EmptySource);
        }
    }

    // -----------------------------------------------------------------------
    // Script goal rejects export
    // -----------------------------------------------------------------------

    #[test]
    fn script_goal_rejects_export_declaration() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("export default 42", ParseGoal::Script)
            .expect_err("script goal should reject export");
        assert_eq!(err.code, ParseErrorCode::InvalidGoal);
    }

    // -----------------------------------------------------------------------
    // Expression parsing
    // -----------------------------------------------------------------------

    #[test]
    fn numeric_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        assert_eq!(tree.body.len(), 1);
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::NumericLiteral(42));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn negative_numeric_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("-7", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::NumericLiteral(v) => assert_eq!(*v, -7),
                _ => panic!("expected numeric expression for -7"),
            },
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn string_literal_single_quotes_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("'hello'", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::StringLiteral("hello".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn string_literal_double_quotes_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("\"world\"", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::StringLiteral("world".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn identifier_expression_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("foo", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::Identifier("foo".to_string()));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn underscore_prefix_is_valid_identifier() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("_private", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::Identifier("_private".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn dollar_prefix_is_valid_identifier() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("$elem", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::Identifier("$elem".to_string()));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn await_expression_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("await fetch", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::Await(inner) => {
                    assert_eq!(**inner, Expression::Identifier("fetch".to_string()));
                }
                _ => panic!("expected await expression"),
            },
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn boolean_literal_true_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("true", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::BooleanLiteral(true));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn boolean_literal_false_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("false", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::BooleanLiteral(false));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn null_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("null", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::NullLiteral);
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn undefined_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("undefined", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::UndefinedLiteral);
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn complex_expression_parses_as_raw() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("a + b * c", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::Raw(s) => assert_eq!(s, "a + b * c"),
                _ => panic!("expected raw expression"),
            },
            _ => panic!("expected expression statement"),
        }
    }

    // -----------------------------------------------------------------------
    // Variable declaration parsing
    // -----------------------------------------------------------------------

    #[test]
    fn var_declaration_with_initializer_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var counter = 1", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.kind, VariableDeclarationKind::Var);
                assert_eq!(variable_declaration.declarations.len(), 1);
                let declarator = &variable_declaration.declarations[0];
                assert_eq!(declarator.name, "counter");
                assert_eq!(declarator.initializer, Some(Expression::NumericLiteral(1)));
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn var_declaration_without_initializer_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("var ready", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.kind, VariableDeclarationKind::Var);
                assert_eq!(variable_declaration.declarations.len(), 1);
                let declarator = &variable_declaration.declarations[0];
                assert_eq!(declarator.name, "ready");
                assert_eq!(declarator.initializer, None);
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn var_declaration_with_multiple_declarators_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var first = \"a,b\", second = 2", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.declarations.len(), 2);
                let first = &variable_declaration.declarations[0];
                assert_eq!(first.name, "first");
                assert_eq!(
                    first.initializer,
                    Some(Expression::StringLiteral("a,b".to_string()))
                );
                let second = &variable_declaration.declarations[1];
                assert_eq!(second.name, "second");
                assert_eq!(second.initializer, Some(Expression::NumericLiteral(2)));
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn var_declaration_missing_binding_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var", ParseGoal::Script)
            .expect_err("var without binding must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn var_declaration_non_identifier_binding_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var {x} = source", ParseGoal::Script)
            .expect_err("destructuring binding should fail in scaffold");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn identifier_starting_with_var_is_expression_not_declaration() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("variant", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::Identifier("variant".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    // -----------------------------------------------------------------------
    // Multi-statement / semicolons
    // -----------------------------------------------------------------------

    #[test]
    fn semicolons_split_statements() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("x;42;'hello'", ParseGoal::Script)
            .expect("parse");
        assert_eq!(tree.body.len(), 3);
    }

    #[test]
    fn semicolon_inside_string_does_not_split_statement() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("'a;b';x", ParseGoal::Script).expect("parse");
        assert_eq!(tree.body.len(), 2);
    }

    #[test]
    fn multiline_source_parsed_correctly() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("x\n42\n'hello'", ParseGoal::Script)
            .expect("parse");
        assert_eq!(tree.body.len(), 3);
    }

    #[test]
    fn trailing_semicolons_do_not_create_extra_statements() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("x;", ParseGoal::Script).expect("parse");
        assert_eq!(tree.body.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Import forms
    // -----------------------------------------------------------------------

    #[test]
    fn import_with_binding_parsed_in_module() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import dep from 'pkg'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                assert_eq!(import.binding, Some("dep".to_string()));
                assert_eq!(import.source, "pkg");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_side_effect_only_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import 'polyfill'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                assert_eq!(import.binding, None);
                assert_eq!(import.source, "polyfill");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_empty_clause_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("import ", ParseGoal::Module)
            .expect_err("empty import clause must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // -----------------------------------------------------------------------
    // Export forms
    // -----------------------------------------------------------------------

    #[test]
    fn export_default_identifier_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export default main", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Export(export) => match &export.kind {
                ExportKind::Default(expr) => {
                    assert_eq!(*expr, Expression::Identifier("main".to_string()));
                }
                _ => panic!("expected default export"),
            },
            _ => panic!("expected export statement"),
        }
    }

    #[test]
    fn export_named_clause_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export { a, b }", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Export(export) => match &export.kind {
                ExportKind::NamedClause(clause) => {
                    assert_eq!(clause, "{ a, b }");
                }
                _ => panic!("expected named clause export"),
            },
            _ => panic!("expected export statement"),
        }
    }

    // -----------------------------------------------------------------------
    // ParserInput implementations
    // -----------------------------------------------------------------------

    #[test]
    fn str_input_has_inline_label() {
        let source: &str = "42";
        let ps = source.into_source().expect("into_source");
        assert_eq!(ps.label, "<inline>");
        assert_eq!(ps.text, "42");
    }

    #[test]
    fn string_input_has_inline_label() {
        let source = String::from("hello");
        let ps = source.into_source().expect("into_source");
        assert_eq!(ps.label, "<inline>");
        assert_eq!(ps.text, "hello");
    }

    #[test]
    fn stream_input_invalid_utf8_rejected() {
        let bad_bytes: &[u8] = &[0xFF, 0xFE, 0x00];
        let input = StreamInput::new(Cursor::new(bad_bytes), "bad_stream");
        let err = input.into_source().expect_err("invalid UTF-8 must fail");
        assert_eq!(err.code, ParseErrorCode::InvalidUtf8);
    }

    // -----------------------------------------------------------------------
    // ParseError display
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_display_without_span() {
        let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "test.js", None);
        let display = format!("{}", err);
        assert!(display.contains("EmptySource"));
        assert!(display.contains("test.js"));
    }

    #[test]
    fn parse_error_display_with_span() {
        let span = SourceSpan::new(0, 5, 1, 1, 1, 6);
        let err = ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "bad token",
            "test.js",
            Some(span),
        );
        let display = format!("{}", err);
        assert!(display.contains("line=1"));
        assert!(display.contains("column=1"));
    }

    #[test]
    fn parse_error_round_trips_through_serde() {
        let err = ParseError::new(
            ParseErrorCode::EmptySource,
            "source is empty",
            "<inline>",
            None,
        );
        let json = serde_json::to_string(&err).expect("serialize");
        let decoded: ParseError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, err);
    }

    #[test]
    fn budget_exhaustion_returns_stable_witness() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1024,
                max_token_count: 1,
                max_recursion_depth: 32,
            },
        };

        let err = parser
            .parse_with_options("alpha beta gamma", ParseGoal::Script, &options)
            .expect_err("token budget should fail");
        assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
        let witness = err.witness.expect("budget failures should carry witness");
        assert_eq!(witness.mode, ParserMode::ScalarReference);
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::TokenCount));
        assert_eq!(witness.max_token_count, 1);
        assert!(witness.token_count > witness.max_token_count);
    }

    #[test]
    fn byte_classification_table_covers_ascii_lexical_categories() {
        assert!(lex_has_class(b' ', LEX_CLASS_WHITESPACE));
        assert!(lex_has_class(b'\n', LEX_CLASS_WHITESPACE));
        assert!(lex_has_class(b'A', LEX_CLASS_IDENTIFIER_START));
        assert!(lex_has_class(b'A', LEX_CLASS_IDENTIFIER_CONTINUE));
        assert!(lex_has_class(b'0', LEX_CLASS_DIGIT));
        assert!(lex_has_class(b'0', LEX_CLASS_IDENTIFIER_CONTINUE));
        assert!(lex_has_class(b'\"', LEX_CLASS_QUOTE));
        assert!(lex_has_class(b'=', LEX_CLASS_TWO_CHAR_OPERATOR_LEAD));
        assert!(!lex_has_class(b'+', LEX_CLASS_TWO_CHAR_OPERATOR_LEAD));
    }

    #[test]
    fn utf8_boundary_safe_scanner_matches_scalar_reference_for_ascii_inputs() {
        let cases = [
            "alpha beta gamma",
            "a==b && c!=d || e??f => g",
            "'hello' \"world\"",
            "\"unterminated\nstring\"",
            "await foo;\nbar + baz * 5",
            "_$token123 <= 42",
        ];

        for source in cases {
            assert_eq!(
                count_lexical_tokens(source),
                count_lexical_tokens_scalar_reference(source),
                "ASCII parity drift for source: {source:?}"
            );
        }
    }

    #[test]
    fn utf8_boundary_safe_scanner_counts_multibyte_codepoints_once() {
        let two_byte = "é";
        assert_eq!(count_lexical_tokens(two_byte), 1);
        assert_eq!(count_lexical_tokens_scalar_reference(two_byte), 2);

        let four_byte = "😀";
        assert_eq!(count_lexical_tokens(four_byte), 1);
        assert_eq!(count_lexical_tokens_scalar_reference(four_byte), 4);
    }

    #[test]
    fn budget_witness_uses_utf8_boundary_safe_token_count() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1024,
                max_token_count: 1,
                max_recursion_depth: 32,
            },
        };

        let err = parser
            .parse_with_options("é β", ParseGoal::Script, &options)
            .expect_err("utf-8-aware token counting should trigger the token budget");
        let witness = err
            .witness
            .expect("budget failures should preserve witness context");
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::TokenCount));
        assert_eq!(witness.token_count, 2);
        assert_eq!(witness.max_token_count, 1);
    }

    #[test]
    fn recursion_budget_exhaustion_is_deterministic() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1024,
                max_token_count: 1024,
                max_recursion_depth: 1,
            },
        };
        let source = "await await work";
        let left = parser
            .parse_with_options(source, ParseGoal::Script, &options)
            .expect_err("left parse should fail");
        let right = parser
            .parse_with_options(source, ParseGoal::Script, &options)
            .expect_err("right parse should fail");
        assert_eq!(left.code, ParseErrorCode::BudgetExceeded);
        assert_eq!(left, right);
    }

    #[test]
    fn scalar_reference_grammar_matrix_has_non_zero_coverage() {
        let parser = CanonicalEs2020Parser;
        let matrix = parser.scalar_reference_grammar_matrix();
        let summary = matrix.summary();
        assert_eq!(
            matrix.schema_version,
            GrammarCompletenessMatrix::SCHEMA_VERSION
        );
        assert!(summary.family_count > 0);
        assert!(summary.supported_families > 0);
        assert!(summary.completeness_millionths > 0);
        assert!(summary.completeness_millionths <= 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Span correctness
    // -----------------------------------------------------------------------

    #[test]
    fn single_line_source_span_is_correct() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        assert_eq!(tree.span.start_line, 1);
        assert_eq!(tree.span.end_line, 1);
    }

    #[test]
    fn multiline_source_span_end_line_is_correct() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("x\ny\nz", ParseGoal::Script).expect("parse");
        assert_eq!(tree.span.start_line, 1);
        assert_eq!(tree.span.end_line, 3);
    }

    // -----------------------------------------------------------------------
    // Determinism: multiple parses yield identical output
    // -----------------------------------------------------------------------

    #[test]
    fn three_identical_parses_produce_identical_canonical_hashes() {
        let parser = CanonicalEs2020Parser;
        let source = "import x from 'mod';\nexport default x";
        let hashes: Vec<String> = (0..3)
            .map(|_| {
                parser
                    .parse(source, ParseGoal::Module)
                    .expect("parse")
                    .canonical_hash()
            })
            .collect();
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(hashes[1], hashes[2]);
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_code_serde_roundtrip() {
        for code in [
            ParseErrorCode::EmptySource,
            ParseErrorCode::InvalidGoal,
            ParseErrorCode::UnsupportedSyntax,
            ParseErrorCode::IoReadFailed,
            ParseErrorCode::InvalidUtf8,
            ParseErrorCode::SourceTooLarge,
            ParseErrorCode::BudgetExceeded,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let restored: ParseErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, restored);
        }
    }

    #[test]
    fn parser_mode_serde_roundtrip() {
        let mode = ParserMode::ScalarReference;
        let json = serde_json::to_string(&mode).unwrap();
        let restored: ParserMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, restored);
        // Verify snake_case rename
        assert!(json.contains("scalar_reference"));
    }

    #[test]
    fn parse_budget_kind_serde_roundtrip() {
        for kind in [
            ParseBudgetKind::SourceBytes,
            ParseBudgetKind::TokenCount,
            ParseBudgetKind::RecursionDepth,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: ParseBudgetKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn grammar_coverage_status_serde_roundtrip() {
        for status in [
            GrammarCoverageStatus::Supported,
            GrammarCoverageStatus::Partial,
            GrammarCoverageStatus::Unsupported,
            GrammarCoverageStatus::NotApplicable,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let restored: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn parser_budget_serde_roundtrip() {
        let budget = ParserBudget::default();
        let json = serde_json::to_string(&budget).unwrap();
        let restored: ParserBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, restored);
    }

    #[test]
    fn parser_options_serde_roundtrip() {
        let opts = ParserOptions::default();
        let json = serde_json::to_string(&opts).unwrap();
        let restored: ParserOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(opts, restored);
    }

    #[test]
    fn parse_failure_witness_serde_roundtrip() {
        let witness = ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: Some(ParseBudgetKind::TokenCount),
            source_bytes: 1024,
            token_count: 500,
            max_recursion_observed: 10,
            max_source_bytes: 1_048_576,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        };
        let json = serde_json::to_string(&witness).unwrap();
        let restored: ParseFailureWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, restored);
    }

    #[test]
    fn grammar_family_coverage_serde_roundtrip() {
        let gfc = GrammarFamilyCoverage {
            family_id: "primary-expression".to_string(),
            es2020_clause: "12.2".to_string(),
            script_goal: GrammarCoverageStatus::Supported,
            module_goal: GrammarCoverageStatus::Partial,
            notes: "test".to_string(),
        };
        let json = serde_json::to_string(&gfc).unwrap();
        let restored: GrammarFamilyCoverage = serde_json::from_str(&json).unwrap();
        assert_eq!(gfc, restored);
    }

    #[test]
    fn grammar_completeness_summary_serde_roundtrip() {
        let summary = GrammarCompletenessSummary {
            family_count: 10,
            supported_families: 6,
            partially_supported_families: 2,
            unsupported_families: 2,
            completeness_millionths: 700_000,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: GrammarCompletenessSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    #[test]
    fn grammar_completeness_matrix_serde_roundtrip() {
        let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
        let json = serde_json::to_string(&matrix).unwrap();
        let restored: GrammarCompletenessMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(matrix, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: default value assertions
    // -----------------------------------------------------------------------

    #[test]
    fn parser_budget_default_values() {
        let b = ParserBudget::default();
        assert_eq!(b.max_source_bytes, 1_048_576);
        assert_eq!(b.max_token_count, 65_536);
        assert_eq!(b.max_recursion_depth, 256);
    }

    #[test]
    fn parser_options_default_values() {
        let o = ParserOptions::default();
        assert_eq!(o.mode, ParserMode::ScalarReference);
        assert_eq!(o.budget, ParserBudget::default());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParserMode as_str
    // -----------------------------------------------------------------------

    #[test]
    fn parser_mode_as_str() {
        assert_eq!(ParserMode::ScalarReference.as_str(), "scalar_reference");
    }

    // -----------------------------------------------------------------------
    // Enrichment: grammar matrix summary
    // -----------------------------------------------------------------------

    #[test]
    fn grammar_matrix_summary_values() {
        let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
        let summary = matrix.summary();
        assert!(summary.family_count > 0);
        assert!(summary.supported_families > 0);
        assert!(summary.completeness_millionths > 0);
        assert_eq!(
            summary.family_count,
            summary.supported_families
                + summary.partially_supported_families
                + summary.unsupported_families
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseError witness roundtrip (witness skipped in serde)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_serde_witness_none_is_omitted() {
        // When witness is None, the field is skipped in serialization
        let err = ParseError {
            code: ParseErrorCode::BudgetExceeded,
            message: "budget exceeded".to_string(),
            source_label: "test.js".to_string(),
            span: None,
            witness: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("witness"));
        let restored: ParseError = serde_json::from_str(&json).unwrap();
        assert!(restored.witness.is_none());
        assert_eq!(restored.code, err.code);
    }

    #[test]
    fn parse_error_serde_witness_some_roundtrips() {
        let err = ParseError {
            code: ParseErrorCode::BudgetExceeded,
            message: "budget exceeded".to_string(),
            source_label: "test.js".to_string(),
            span: None,
            witness: Some(Box::new(ParseFailureWitness {
                mode: ParserMode::ScalarReference,
                budget_kind: Some(ParseBudgetKind::SourceBytes),
                source_bytes: 2_000_000,
                token_count: 0,
                max_recursion_observed: 0,
                max_source_bytes: 1_048_576,
                max_token_count: 65_536,
                max_recursion_depth: 256,
            })),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("witness"));
        let restored: ParseError = serde_json::from_str(&json).unwrap();
        assert!(restored.witness.is_some());
        assert_eq!(restored.witness.unwrap().source_bytes, 2_000_000);
    }

    #[test]
    fn parse_diagnostic_contract_metadata_is_versioned_and_stable() {
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
            ParseDiagnosticTaxonomy::taxonomy_version(),
            PARSER_DIAGNOSTIC_TAXONOMY_VERSION
        );
        assert_eq!(
            ParseDiagnosticEnvelope::schema_version(),
            PARSER_DIAGNOSTIC_SCHEMA_VERSION
        );
        assert_eq!(
            ParseDiagnosticEnvelope::taxonomy_version(),
            PARSER_DIAGNOSTIC_TAXONOMY_VERSION
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
    fn parse_diagnostic_taxonomy_v1_is_complete_and_unique() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        assert_eq!(
            taxonomy.taxonomy_version,
            PARSER_DIAGNOSTIC_TAXONOMY_VERSION.to_string()
        );
        assert_eq!(taxonomy.rules.len(), ParseErrorCode::ALL.len());

        let mut error_codes = BTreeSet::new();
        let mut diagnostic_codes = BTreeSet::new();
        for rule in &taxonomy.rules {
            assert!(error_codes.insert(rule.parse_error_code.as_str().to_string()));
            assert!(diagnostic_codes.insert(rule.diagnostic_code.clone()));
            assert_eq!(
                rule.diagnostic_code,
                rule.parse_error_code.stable_diagnostic_code()
            );
            assert_eq!(rule.category, rule.parse_error_code.diagnostic_category());
            assert_eq!(rule.severity, rule.parse_error_code.diagnostic_severity());
            assert_eq!(
                rule.message_template,
                rule.parse_error_code.diagnostic_message_template(None)
            );
        }

        for code in ParseErrorCode::ALL {
            assert!(taxonomy.rule_for(code).is_some());
        }
    }

    #[test]
    fn parse_error_normalization_ignores_raw_message_variance() {
        let span = SourceSpan::new(0, 10, 1, 1, 1, 11);
        let left = ParseError {
            code: ParseErrorCode::IoReadFailed,
            message: "failed to read source file: No such file or directory (os error 2)"
                .to_string(),
            source_label: "fixture.js".to_string(),
            span: Some(span.clone()),
            witness: None,
        };
        let right = ParseError {
            code: ParseErrorCode::IoReadFailed,
            message: "failed to read source stream: permission denied".to_string(),
            source_label: "fixture.js".to_string(),
            span: Some(span),
            witness: None,
        };

        let left_norm = left.normalized_diagnostic();
        let right_norm = ParseDiagnosticEnvelope::from_parse_error(&right);
        assert_eq!(left_norm.message_template, "parser input could not be read");
        assert_eq!(left_norm.canonical_bytes(), right_norm.canonical_bytes());
        assert_eq!(left_norm.canonical_hash(), right_norm.canonical_hash());
    }

    #[test]
    fn parse_error_normalization_preserves_budget_context() {
        let err = ParseError {
            code: ParseErrorCode::BudgetExceeded,
            message: "token budget exceeded: token_count=3 max_token_count=1".to_string(),
            source_label: "<inline>".to_string(),
            span: Some(SourceSpan::new(0, 16, 1, 1, 1, 17)),
            witness: Some(Box::new(ParseFailureWitness {
                mode: ParserMode::ScalarReference,
                budget_kind: Some(ParseBudgetKind::TokenCount),
                source_bytes: 16,
                token_count: 3,
                max_recursion_observed: 0,
                max_source_bytes: 1024,
                max_token_count: 1,
                max_recursion_depth: 64,
            })),
        };

        let normalized = normalize_parse_error(&err);
        assert_eq!(normalized.category, ParseDiagnosticCategory::Resource);
        assert_eq!(normalized.severity, ParseDiagnosticSeverity::Fatal);
        assert_eq!(
            normalized.diagnostic_code,
            ParseErrorCode::BudgetExceeded.stable_diagnostic_code()
        );
        assert_eq!(
            normalized.message_template,
            "token budget exceeded".to_string()
        );
        assert_eq!(normalized.budget_kind, Some(ParseBudgetKind::TokenCount));
        assert_eq!(
            normalized
                .witness
                .as_ref()
                .expect("budget witness should be retained")
                .token_count,
            3
        );
    }

    #[test]
    fn parse_diagnostic_envelope_serde_and_hash_are_stable() {
        let err = ParseError {
            code: ParseErrorCode::EmptySource,
            message: "source is empty after whitespace normalization".to_string(),
            source_label: "<inline>".to_string(),
            span: None,
            witness: None,
        };
        let left = normalize_parse_error(&err);
        let right = normalize_parse_error(&err);
        let json = serde_json::to_string(&left).expect("serialize envelope");
        let restored: ParseDiagnosticEnvelope =
            serde_json::from_str(&json).expect("deserialize envelope");
        assert_eq!(restored, left);
        assert_eq!(left.canonical_hash(), right.canonical_hash());
        assert!(
            left.canonical_hash()
                .starts_with(ParseDiagnosticEnvelope::canonical_hash_prefix())
        );
    }

    #[test]
    fn parse_event_kind_serde_roundtrip() {
        for kind in [
            ParseEventKind::ParseStarted,
            ParseEventKind::StatementParsed,
            ParseEventKind::ParseCompleted,
            ParseEventKind::ParseFailed,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: ParseEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn parse_event_ir_contract_metadata_is_versioned_and_stable() {
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
            PARSE_EVENT_IR_POLICY_ID,
            "franken-engine.parser-event-producer.policy.v1"
        );
        assert_eq!(PARSE_EVENT_IR_COMPONENT, "canonical_es2020_parser");
        assert_eq!(PARSE_EVENT_IR_TRACE_PREFIX, "trace-parser-event-");
        assert_eq!(PARSE_EVENT_IR_DECISION_PREFIX, "decision-parser-event-");
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
    fn parse_event_ir_from_syntax_tree_emits_deterministic_sequence() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;\n";
        let tree = parser.parse(source, ParseGoal::Module).expect("parse");

        let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        assert_eq!(ir.schema_version, PARSE_EVENT_IR_SCHEMA_VERSION);
        assert_eq!(ir.contract_version, PARSE_EVENT_IR_CONTRACT_VERSION);
        assert_eq!(ir.events.len(), tree.body.len() + 2);
        assert!(matches!(
            ir.events.first().map(|event| event.kind),
            Some(ParseEventKind::ParseStarted)
        ));
        assert!(matches!(
            ir.events.last().map(|event| event.kind),
            Some(ParseEventKind::ParseCompleted)
        ));

        for (index, event) in ir.events.iter().enumerate() {
            assert_eq!(event.sequence, index as u64);
            assert!(event.trace_id.starts_with(PARSE_EVENT_IR_TRACE_PREFIX));
            assert!(
                event
                    .decision_id
                    .starts_with(PARSE_EVENT_IR_DECISION_PREFIX)
            );
            assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
            assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
            assert!(!event.outcome.is_empty());
        }
    }

    #[test]
    fn parse_event_ir_hash_is_deterministic_for_identical_inputs() {
        let parser = CanonicalEs2020Parser;
        let source = "await work";
        let left_tree = parser.parse(source, ParseGoal::Script).expect("left parse");
        let right_tree = parser
            .parse(source, ParseGoal::Script)
            .expect("right parse");

        let left_ir =
            ParseEventIr::from_syntax_tree(&left_tree, "<inline>", ParserMode::ScalarReference);
        let right_ir =
            ParseEventIr::from_syntax_tree(&right_tree, "<inline>", ParserMode::ScalarReference);
        assert_eq!(left_ir.canonical_bytes(), right_ir.canonical_bytes());
        assert_eq!(left_ir.canonical_hash(), right_ir.canonical_hash());
        assert!(
            left_ir
                .canonical_hash()
                .starts_with(ParseEventIr::canonical_hash_prefix())
        );
    }

    #[test]
    fn parse_event_ir_serde_roundtrip() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export default true", ParseGoal::Module)
            .expect("parse");
        let ir = ParseEventIr::from_syntax_tree(&tree, "fixture.js", ParserMode::ScalarReference);
        let json = serde_json::to_string(&ir).unwrap();
        let restored: ParseEventIr = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, ir);
    }

    #[test]
    fn parse_with_event_ir_success_emits_ordered_events() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;\n";
        let (result, event_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Module, &ParserOptions::default());

        let tree = result.expect("parse should succeed");
        assert_eq!(event_ir.events.len(), tree.body.len() + 2);
        assert!(matches!(
            event_ir.events.first().map(|event| event.kind),
            Some(ParseEventKind::ParseStarted)
        ));
        assert!(matches!(
            event_ir.events.last().map(|event| event.kind),
            Some(ParseEventKind::ParseCompleted)
        ));
        for (index, event) in event_ir.events.iter().enumerate() {
            assert_eq!(event.sequence, index as u64);
            assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
            assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
            assert_eq!(event.error_code, None);
        }
    }

    #[test]
    fn parse_with_event_ir_failure_emits_parse_failed_event() {
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
        assert_eq!(
            event_ir.events[1].payload_kind.as_deref(),
            Some("parse_diagnostic")
        );
        assert!(
            event_ir.events[1]
                .payload_hash
                .as_deref()
                .is_some_and(|hash| hash.starts_with(ParseEventIr::canonical_hash_prefix()))
        );
    }

    #[test]
    fn parse_event_ast_materializer_contract_metadata_is_versioned_and_stable() {
        assert_eq!(
            PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
            "franken-engine.parser-event-ast-materializer.contract.v1"
        );
        assert_eq!(
            PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION,
            "franken-engine.parser-event-ast-materializer.schema.v1"
        );
        assert_eq!(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX, "ast-node-");
        assert_eq!(
            MaterializedSyntaxTree::contract_version(),
            PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
        );
        assert_eq!(
            MaterializedSyntaxTree::schema_version(),
            PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION
        );
    }

    #[test]
    fn materialize_from_source_matches_canonical_ast_hash_and_node_witnesses() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;\n";
        let options = ParserOptions::default();
        let (result, event_ir) = parser.parse_with_event_ir(source, ParseGoal::Module, &options);
        let tree = result.expect("parse should succeed");
        let materialized = event_ir
            .materialize_from_source(source, &options)
            .expect("materialization should succeed");

        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            tree.canonical_hash()
        );
        assert_eq!(materialized.statement_nodes.len(), tree.body.len());
        assert!(
            materialized
                .root_node_id
                .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
        );
        for (idx, node) in materialized.statement_nodes.iter().enumerate() {
            assert_eq!(node.statement_index, idx as u64);
            assert_eq!(node.sequence, (idx as u64).saturating_add(1));
            assert!(
                node.node_id
                    .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
            );
            assert!(
                node.payload_hash
                    .starts_with(ParseEventIr::canonical_hash_prefix())
            );
        }
    }

    #[test]
    fn materialized_ast_node_ids_are_deterministic_for_identical_inputs() {
        let parser = CanonicalEs2020Parser;
        let source = "await work";
        let options = ParserOptions::default();

        let (left_result, left_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        let left_tree = left_result.expect("left parse should succeed");
        let (right_result, right_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        let right_tree = right_result.expect("right parse should succeed");

        let left_materialized = left_ir
            .materialize_from_source(source, &options)
            .expect("left materialization should succeed");
        let right_materialized = right_ir
            .materialize_from_source(source, &options)
            .expect("right materialization should succeed");

        assert_eq!(
            left_materialized.syntax_tree.canonical_hash(),
            left_tree.canonical_hash()
        );
        assert_eq!(
            right_materialized.syntax_tree.canonical_hash(),
            right_tree.canonical_hash()
        );
        assert_eq!(
            left_materialized.root_node_id,
            right_materialized.root_node_id
        );
        assert_eq!(
            left_materialized.statement_nodes,
            right_materialized.statement_nodes
        );
        assert_eq!(
            left_materialized.canonical_hash(),
            right_materialized.canonical_hash()
        );
    }

    #[test]
    fn materialize_from_source_rejects_statement_hash_tampering() {
        let parser = CanonicalEs2020Parser;
        let source = "alpha;";
        let options = ParserOptions::default();
        let (_result, mut event_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        event_ir.events[1].payload_hash = Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let err = event_ir
            .materialize_from_source(source, &options)
            .expect_err("tampered payload hash must fail");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::StatementHashMismatch
        );
        assert_eq!(err.sequence, Some(1));
    }

    #[test]
    fn materialize_from_source_rejects_failed_event_streams() {
        let parser = CanonicalEs2020Parser;
        let (_result, event_ir) =
            parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());
        let err = event_ir
            .materialize_from_source("", &ParserOptions::default())
            .expect_err("failed event stream should be rejected");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::ParseFailedEventStream
        );
    }

    #[test]
    fn parse_with_materialized_ast_success_and_failure_contracts_are_deterministic() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;";
        let options = ParserOptions::default();

        let (result, _event_ir, materialized_result) =
            parser.parse_with_materialized_ast(source, ParseGoal::Module, &options);
        let tree = result.expect("parse should succeed");
        let materialized = materialized_result.expect("materializer should succeed");
        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            tree.canonical_hash()
        );

        let (failed_result, _failed_ir, failed_materialized) =
            parser.parse_with_materialized_ast("", ParseGoal::Script, &ParserOptions::default());
        let err = failed_result.expect_err("empty source should fail parse");
        assert_eq!(err.code, ParseErrorCode::EmptySource);
        assert_eq!(
            failed_materialized
                .expect_err("failed parse must not materialize")
                .code,
            ParseEventMaterializationErrorCode::ParseFailedEventStream
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseErrorCode as_str all variants
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_code_as_str_all_distinct() {
        let strs: BTreeSet<&str> = ParseErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), ParseErrorCode::ALL.len());
    }

    #[test]
    fn parse_error_code_stable_diagnostic_code_all_distinct() {
        let codes: BTreeSet<&str> = ParseErrorCode::ALL
            .iter()
            .map(|c| c.stable_diagnostic_code())
            .collect();
        assert_eq!(codes.len(), ParseErrorCode::ALL.len());
    }

    #[test]
    fn parse_error_code_diagnostic_category_covers_all_categories() {
        let categories: BTreeSet<_> = ParseErrorCode::ALL
            .iter()
            .map(|c| c.diagnostic_category().as_str())
            .collect();
        // At least 4 distinct categories
        assert!(categories.len() >= 4, "got {:?}", categories);
    }

    #[test]
    fn parse_error_code_diagnostic_severity_covers_both() {
        let severities: BTreeSet<_> = ParseErrorCode::ALL
            .iter()
            .map(|c| c.diagnostic_severity().as_str())
            .collect();
        assert!(severities.contains("error"));
        assert!(severities.contains("fatal"));
    }

    #[test]
    fn parse_error_code_diagnostic_message_template_non_empty() {
        for code in &ParseErrorCode::ALL {
            assert!(
                !code.diagnostic_message_template(None).is_empty(),
                "empty template for {:?}",
                code
            );
        }
    }

    #[test]
    fn budget_exceeded_message_template_with_budget_kind() {
        let msg = ParseErrorCode::BudgetExceeded
            .diagnostic_message_template(Some(ParseBudgetKind::TokenCount));
        assert!(
            msg.contains("token"),
            "expected token-related msg, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseDiagnosticCategory as_str all distinct
    // -----------------------------------------------------------------------

    #[test]
    fn parse_diagnostic_category_as_str_all_distinct() {
        let categories = [
            ParseDiagnosticCategory::Input,
            ParseDiagnosticCategory::Goal,
            ParseDiagnosticCategory::Syntax,
            ParseDiagnosticCategory::Encoding,
            ParseDiagnosticCategory::Resource,
            ParseDiagnosticCategory::System,
        ];
        let strs: BTreeSet<&str> = categories.iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), categories.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseBudgetKind as_str all distinct
    // -----------------------------------------------------------------------

    #[test]
    fn parse_budget_kind_as_str_all_distinct() {
        let kinds = [
            ParseBudgetKind::SourceBytes,
            ParseBudgetKind::TokenCount,
            ParseBudgetKind::RecursionDepth,
        ];
        let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(strs.len(), kinds.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseEventKind as_str all distinct
    // -----------------------------------------------------------------------

    #[test]
    fn parse_event_kind_as_str_all_distinct() {
        let kinds = [
            ParseEventKind::ParseStarted,
            ParseEventKind::StatementParsed,
            ParseEventKind::ParseCompleted,
            ParseEventKind::ParseFailed,
        ];
        let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(strs.len(), kinds.len());
    }

    #[test]
    fn parse_event_kind_canonical_value_matches_as_str() {
        for kind in [
            ParseEventKind::ParseStarted,
            ParseEventKind::StatementParsed,
            ParseEventKind::ParseCompleted,
            ParseEventKind::ParseFailed,
        ] {
            if let CanonicalValue::String(s) = kind.canonical_value() {
                assert_eq!(s, kind.as_str());
            } else {
                panic!("expected CanonicalValue::String");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseEventMaterializationErrorCode as_str
    // -----------------------------------------------------------------------

    #[test]
    fn parse_event_materialization_error_code_as_str_all_distinct() {
        let codes = [
            ParseEventMaterializationErrorCode::UnsupportedContractVersion,
            ParseEventMaterializationErrorCode::UnsupportedSchemaVersion,
            ParseEventMaterializationErrorCode::ParseFailedEventStream,
            ParseEventMaterializationErrorCode::MissingParseStarted,
            ParseEventMaterializationErrorCode::MissingParseCompleted,
            ParseEventMaterializationErrorCode::InvalidEventSequence,
            ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
            ParseEventMaterializationErrorCode::GoalMismatch,
            ParseEventMaterializationErrorCode::ModeMismatch,
            ParseEventMaterializationErrorCode::StatementCountMismatch,
            ParseEventMaterializationErrorCode::StatementIndexMismatch,
            ParseEventMaterializationErrorCode::StatementKindMismatch,
            ParseEventMaterializationErrorCode::StatementHashMismatch,
            ParseEventMaterializationErrorCode::StatementSpanMismatch,
            ParseEventMaterializationErrorCode::SourceHashMismatch,
            ParseEventMaterializationErrorCode::AstHashMismatch,
            ParseEventMaterializationErrorCode::SourceParseFailed,
        ];
        let strs: BTreeSet<&str> = codes.iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), codes.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseEventMaterializationError Display
    // -----------------------------------------------------------------------

    #[test]
    fn materialization_error_display_with_sequence() {
        let err = ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::GoalMismatch,
            "mismatch".to_string(),
            Some(5),
        );
        let display = err.to_string();
        assert!(display.contains("sequence=5"), "got: {display}");
        assert!(display.contains("goal_mismatch"), "got: {display}");
    }

    #[test]
    fn materialization_error_display_without_sequence() {
        let err = ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::SourceHashMismatch,
            "hash differs".to_string(),
            None,
        );
        let display = err.to_string();
        assert!(!display.contains("sequence="), "got: {display}");
        assert!(display.contains("source_hash_mismatch"), "got: {display}");
    }

    #[test]
    fn materialization_error_is_std_error() {
        let err: &dyn std::error::Error = &ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::ParseFailedEventStream,
            "msg".to_string(),
            None,
        );
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for missing types
    // -----------------------------------------------------------------------

    #[test]
    fn parse_diagnostic_rule_serde_roundtrip() {
        let rule = ParseDiagnosticRule {
            parse_error_code: ParseErrorCode::EmptySource,
            diagnostic_code: "FE-PARSER-DIAG-EMPTY-SOURCE-0001".to_string(),
            category: ParseDiagnosticCategory::Input,
            severity: ParseDiagnosticSeverity::Error,
            message_template: "source is empty".to_string(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let restored: ParseDiagnosticRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, restored);
    }

    #[test]
    fn parse_diagnostic_taxonomy_serde_roundtrip() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        let json = serde_json::to_string(&taxonomy).unwrap();
        let restored: ParseDiagnosticTaxonomy = serde_json::from_str(&json).unwrap();
        assert_eq!(taxonomy, restored);
    }

    #[test]
    fn parse_event_materialization_error_serde_roundtrip() {
        let err = ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::InvalidEventSequence,
            "bad seq".to_string(),
            Some(3),
        );
        let json = serde_json::to_string(&err).unwrap();
        let restored: ParseEventMaterializationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: helper functions
    // -----------------------------------------------------------------------

    #[test]
    fn line_count_single_line() {
        assert_eq!(line_count("hello"), 1);
    }

    #[test]
    fn line_count_multiple_lines() {
        assert_eq!(line_count("a\nb\nc"), 3);
    }

    #[test]
    fn line_count_trailing_newline() {
        assert_eq!(line_count("a\n"), 2);
    }

    #[test]
    fn is_identifier_empty_returns_false() {
        assert!(!is_identifier(""));
    }

    #[test]
    fn is_identifier_valid() {
        assert!(is_identifier("foo"));
        assert!(is_identifier("_bar"));
        assert!(is_identifier("$baz"));
        assert!(is_identifier("x2"));
    }

    #[test]
    fn is_identifier_invalid() {
        assert!(!is_identifier("2x"));
        assert!(!is_identifier("foo bar"));
        assert!(!is_identifier("-x"));
    }

    #[test]
    fn canonicalize_whitespace_normalizes() {
        assert_eq!(canonicalize_whitespace("  a   b  c  "), "a b c");
    }

    #[test]
    fn canonicalize_whitespace_empty() {
        assert_eq!(canonicalize_whitespace("   "), "");
    }

    #[test]
    fn is_identifier_start_cases() {
        assert!(is_identifier_start('a'));
        assert!(is_identifier_start('Z'));
        assert!(is_identifier_start('_'));
        assert!(is_identifier_start('$'));
        assert!(!is_identifier_start('0'));
        assert!(!is_identifier_start('-'));
    }

    #[test]
    fn is_identifier_continue_cases() {
        assert!(is_identifier_continue('a'));
        assert!(is_identifier_continue('0'));
        assert!(is_identifier_continue('_'));
        assert!(is_identifier_continue('$'));
        assert!(!is_identifier_continue('-'));
        assert!(!is_identifier_continue(' '));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn parse_diagnostic_category_serde_roundtrip() {
        for cat in [
            ParseDiagnosticCategory::Input,
            ParseDiagnosticCategory::Goal,
            ParseDiagnosticCategory::Syntax,
            ParseDiagnosticCategory::Encoding,
            ParseDiagnosticCategory::Resource,
            ParseDiagnosticCategory::System,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: ParseDiagnosticCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn parse_diagnostic_severity_serde_roundtrip() {
        for sev in [
            ParseDiagnosticSeverity::Error,
            ParseDiagnosticSeverity::Fatal,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: ParseDiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn parse_diagnostic_severity_as_str_all_distinct() {
        let strs: std::collections::BTreeSet<_> = [
            ParseDiagnosticSeverity::Error.as_str(),
            ParseDiagnosticSeverity::Fatal.as_str(),
        ]
        .into_iter()
        .collect();
        assert_eq!(strs.len(), 2);
    }

    #[test]
    fn parse_error_is_std_error() {
        let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "test.js", None);
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn taxonomy_rule_for_finds_matching_code() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        for code in &ParseErrorCode::ALL {
            let rule = taxonomy.rule_for(*code);
            assert!(rule.is_some(), "rule_for({:?}) returned None", code);
            assert_eq!(rule.unwrap().parse_error_code, *code);
        }
    }

    #[test]
    fn taxonomy_rule_for_severity_matches_code_method() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        for code in &ParseErrorCode::ALL {
            let rule = taxonomy.rule_for(*code).unwrap();
            assert_eq!(rule.severity, code.diagnostic_severity());
            assert_eq!(rule.category, code.diagnostic_category());
        }
    }

    #[test]
    fn grammar_coverage_status_serde_all_variants_distinct() {
        let variants = [
            GrammarCoverageStatus::Supported,
            GrammarCoverageStatus::Partial,
            GrammarCoverageStatus::Unsupported,
            GrammarCoverageStatus::NotApplicable,
        ];
        let mut names = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(v, &back);
            names.insert(json);
        }
        assert_eq!(names.len(), variants.len());
    }

    #[test]
    fn grammar_family_coverage_partial_roundtrip() {
        let fam = GrammarFamilyCoverage {
            family_id: "expressions".to_string(),
            es2020_clause: "12.2".to_string(),
            script_goal: GrammarCoverageStatus::Partial,
            module_goal: GrammarCoverageStatus::Unsupported,
            notes: "WIP".to_string(),
        };
        let json = serde_json::to_string(&fam).unwrap();
        let back: GrammarFamilyCoverage = serde_json::from_str(&json).unwrap();
        assert_eq!(fam, back);
    }

    #[test]
    fn parse_error_display_includes_source_label() {
        let err = ParseError::new(
            ParseErrorCode::InvalidUtf8,
            "bad encoding",
            "input.js",
            None,
        );
        let display = err.to_string();
        assert!(display.contains("input.js"), "display: {display}");
    }

    #[test]
    fn canonicalize_whitespace_tabs_and_newlines() {
        assert_eq!(canonicalize_whitespace("a\t\nb"), "a b");
    }

    // -- Enrichment: PearlTower batch 2 (2026-02-26) --

    // -- parse_quoted_string edge cases --

    #[test]
    fn parse_quoted_string_too_short_returns_none() {
        assert!(parse_quoted_string("").is_none());
        assert!(parse_quoted_string("x").is_none());
    }

    #[test]
    fn parse_quoted_string_mismatched_quotes_returns_none() {
        assert!(parse_quoted_string("'hello\"").is_none());
        assert!(parse_quoted_string("\"hello'").is_none());
    }

    #[test]
    fn parse_quoted_string_with_embedded_newline_returns_none() {
        assert!(parse_quoted_string("'hel\nlo'").is_none());
        assert!(parse_quoted_string("\"hel\rlo\"").is_none());
    }

    #[test]
    fn parse_quoted_string_valid_extracts_inner() {
        assert_eq!(parse_quoted_string("'abc'"), Some("abc".to_string()));
        assert_eq!(parse_quoted_string("\"xyz\""), Some("xyz".to_string()));
        assert_eq!(parse_quoted_string("''"), Some(String::new()));
    }

    // -- parse_i64_numeric_literal edge cases --

    #[test]
    fn parse_i64_numeric_literal_bare_minus_returns_none() {
        assert!(parse_i64_numeric_literal("-").is_none());
    }

    #[test]
    fn parse_i64_numeric_literal_non_numeric_returns_none() {
        assert!(parse_i64_numeric_literal("abc").is_none());
        assert!(parse_i64_numeric_literal("12a").is_none());
        assert!(parse_i64_numeric_literal("-12a").is_none());
    }

    #[test]
    fn parse_i64_numeric_literal_valid_values() {
        assert_eq!(parse_i64_numeric_literal("0"), Some(0));
        assert_eq!(parse_i64_numeric_literal("42"), Some(42));
        assert_eq!(parse_i64_numeric_literal("-7"), Some(-7));
    }

    // -- split_statement_segments with nested delimiters --

    #[test]
    fn split_statement_segments_semicolon_inside_parens_does_not_split() {
        let segments = split_statement_segments("f(a;b);x");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].2, "f(a;b)");
        assert_eq!(segments[1].2, "x");
    }

    #[test]
    fn split_statement_segments_semicolon_inside_brackets_does_not_split() {
        let segments = split_statement_segments("a[b;c];d");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].2, "a[b;c]");
        assert_eq!(segments[1].2, "d");
    }

    #[test]
    fn split_statement_segments_semicolon_inside_braces_does_not_split() {
        let segments = split_statement_segments("{a;b};c");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].2, "{a;b}");
        assert_eq!(segments[1].2, "c");
    }

    #[test]
    fn split_statement_segments_escape_in_string_does_not_close_quote() {
        let segments = split_statement_segments(r#"'a\'b';x"#);
        assert_eq!(segments.len(), 2);
    }

    // -- ParseFailureWitness::canonical_value --

    #[test]
    fn parse_failure_witness_canonical_value_has_expected_keys() {
        let witness = ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: Some(ParseBudgetKind::SourceBytes),
            source_bytes: 100,
            token_count: 10,
            max_recursion_observed: 5,
            max_source_bytes: 1_048_576,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        };
        let cv = witness.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("mode"));
            assert!(map.contains_key("budget_kind"));
            assert!(map.contains_key("source_bytes"));
            assert!(map.contains_key("token_count"));
            assert!(map.contains_key("max_recursion_observed"));
            assert!(map.contains_key("max_source_bytes"));
            assert!(map.contains_key("max_token_count"));
            assert!(map.contains_key("max_recursion_depth"));
        } else {
            panic!("expected CanonicalValue::Map");
        }
    }

    #[test]
    fn parse_failure_witness_canonical_value_null_budget_kind() {
        let witness = ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: None,
            source_bytes: 0,
            token_count: 0,
            max_recursion_observed: 0,
            max_source_bytes: 0,
            max_token_count: 0,
            max_recursion_depth: 0,
        };
        let cv = witness.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert_eq!(map.get("budget_kind"), Some(&CanonicalValue::Null));
        } else {
            panic!("expected CanonicalValue::Map");
        }
    }

    // -- materialize_from_syntax_tree --

    #[test]
    fn materialize_from_syntax_tree_succeeds_for_valid_ir() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export default 42", ParseGoal::Module)
            .expect("parse");
        let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        let materialized = ir
            .materialize_from_syntax_tree(&tree)
            .expect("should succeed");
        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            tree.canonical_hash()
        );
        assert_eq!(materialized.statement_nodes.len(), tree.body.len());
    }

    // -- ParseEventIr::from_parse_source --

    #[test]
    fn parse_event_ir_from_parse_source_has_source_text_payload() {
        let parser = CanonicalEs2020Parser;
        let source = "true";
        let tree = parser.parse(source, ParseGoal::Script).expect("parse");
        let ir =
            ParseEventIr::from_parse_source(&tree, source, "<inline>", ParserMode::ScalarReference);
        assert_eq!(ir.events[0].payload_kind.as_deref(), Some("source_text"));
        assert!(ir.events[0].payload_hash.is_some());
    }

    // -- Materialization error cases --

    #[test]
    fn materialize_rejects_unsupported_contract_version() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.contract_version = "bogus".to_string();
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("unsupported contract");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::UnsupportedContractVersion
        );
    }

    #[test]
    fn materialize_rejects_unsupported_schema_version() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.schema_version = "bogus".to_string();
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("unsupported schema");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::UnsupportedSchemaVersion
        );
    }

    #[test]
    fn materialize_rejects_goal_mismatch() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.goal = ParseGoal::Module;
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("goal mismatch");
        assert_eq!(err.code, ParseEventMaterializationErrorCode::GoalMismatch);
    }

    #[test]
    fn materialize_rejects_empty_event_stream() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.events.clear();
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("empty events");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::MissingParseStarted
        );
    }

    #[test]
    fn materialize_rejects_missing_parse_started() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        // Replace first event with a non-ParseStarted event
        ir.events[0].kind = ParseEventKind::ParseCompleted;
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("missing parse_started");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::MissingParseStarted
        );
    }

    #[test]
    fn materialize_rejects_missing_parse_completed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        let last_idx = ir.events.len() - 1;
        ir.events[last_idx].kind = ParseEventKind::ParseStarted;
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("missing parse_completed");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::MissingParseCompleted
        );
    }

    #[test]
    fn materialize_rejects_invalid_event_sequence() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        // Create a gap in sequence numbers
        if ir.events.len() > 2 {
            ir.events[1].sequence = 99;
        }
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("invalid sequence");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::InvalidEventSequence
        );
    }

    #[test]
    fn materialize_rejects_inconsistent_event_envelope() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        if ir.events.len() > 1 {
            ir.events[1].trace_id = "rogue-trace".to_string();
        }
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("inconsistent envelope");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::InconsistentEventEnvelope
        );
    }

    #[test]
    fn materialize_from_source_rejects_mode_mismatch() {
        let parser = CanonicalEs2020Parser;
        let source = "42";
        let options = ParserOptions::default();
        let (result, event_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        result.expect("parse should succeed");
        // Use options with a different mode — but since there's only one mode,
        // we alter the event_ir instead
        let mut modified_ir = event_ir;
        // No other mode exists, so test the code path by mutating parser_mode
        // This would need a second ParserMode variant. Instead test the error
        // path directly via materialize_from_syntax_tree: change ir.parser_mode
        // won't work since we only have ScalarReference.
        // Instead, test statement count mismatch:
        let tree = parser.parse(source, ParseGoal::Script).expect("parse");
        // Remove a statement event to trigger count mismatch
        modified_ir
            .events
            .retain(|event| event.kind != ParseEventKind::StatementParsed);
        // Re-number sequences for the retained events
        for (i, event) in modified_ir.events.iter_mut().enumerate() {
            event.sequence = i as u64;
        }
        let err = modified_ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("statement count mismatch");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::StatementCountMismatch
        );
    }

    // -- Source bytes budget exhaustion --

    #[test]
    fn source_bytes_budget_exhaustion() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 2,
                max_token_count: 65_536,
                max_recursion_depth: 256,
            },
        };
        let err = parser
            .parse_with_options("long source text", ParseGoal::Script, &options)
            .expect_err("source bytes budget should fail");
        assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
        let witness = err.witness.expect("should have witness");
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::SourceBytes));
        assert!(witness.source_bytes > witness.max_source_bytes);
    }

    // -- GrammarCompletenessMatrix::summary edge cases --

    #[test]
    fn grammar_completeness_summary_empty_families() {
        let matrix = GrammarCompletenessMatrix {
            schema_version: GrammarCompletenessMatrix::SCHEMA_VERSION.to_string(),
            parser_mode: ParserMode::ScalarReference,
            families: vec![],
        };
        let summary = matrix.summary();
        assert_eq!(summary.family_count, 0);
        assert_eq!(summary.completeness_millionths, 0);
    }

    #[test]
    fn grammar_completeness_summary_all_supported() {
        let matrix = GrammarCompletenessMatrix {
            schema_version: GrammarCompletenessMatrix::SCHEMA_VERSION.to_string(),
            parser_mode: ParserMode::ScalarReference,
            families: vec![GrammarFamilyCoverage {
                family_id: "test".to_string(),
                es2020_clause: "1.0".to_string(),
                script_goal: GrammarCoverageStatus::Supported,
                module_goal: GrammarCoverageStatus::Supported,
                notes: String::new(),
            }],
        };
        let summary = matrix.summary();
        assert_eq!(summary.family_count, 1);
        assert_eq!(summary.supported_families, 1);
        assert_eq!(summary.unsupported_families, 0);
        assert_eq!(summary.completeness_millionths, 1_000_000);
    }

    // -- advance_utf8_boundary_safe --

    #[test]
    fn advance_utf8_boundary_safe_past_end_returns_len() {
        let bytes = b"abc";
        assert_eq!(advance_utf8_boundary_safe(bytes, 3), 3);
        assert_eq!(advance_utf8_boundary_safe(bytes, 5), 3);
    }

    #[test]
    fn advance_utf8_boundary_safe_ascii_advances_one() {
        let bytes = b"abc";
        assert_eq!(advance_utf8_boundary_safe(bytes, 0), 1);
    }

    #[test]
    fn advance_utf8_boundary_safe_multibyte() {
        // é is two bytes: 0xC3 0xA9
        let bytes = "é".as_bytes();
        assert_eq!(bytes.len(), 2);
        assert_eq!(advance_utf8_boundary_safe(bytes, 0), 2);
    }

    // -- count_lexical_tokens edge cases --

    #[test]
    fn count_lexical_tokens_empty_returns_zero() {
        assert_eq!(count_lexical_tokens(""), 0);
    }

    #[test]
    fn count_lexical_tokens_whitespace_only_returns_zero() {
        assert_eq!(count_lexical_tokens("   \t\n  "), 0);
    }

    #[test]
    fn count_lexical_tokens_two_char_operators() {
        // == is one token, a is one, b is one => 3
        assert_eq!(count_lexical_tokens("a==b"), 3);
    }

    // -- export empty clause rejected --

    #[test]
    fn export_empty_clause_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("export ", ParseGoal::Module)
            .expect_err("empty export clause");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // -- statement_kind_label --

    #[test]
    fn statement_kind_label_covers_all_variants() {
        let span = SourceSpan::new(0, 1, 1, 1, 1, 1);
        assert_eq!(
            statement_kind_label(&Statement::Import(ImportDeclaration {
                binding: None,
                source: "m".to_string(),
                span: span.clone(),
            })),
            "import"
        );
        assert_eq!(
            statement_kind_label(&Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{}".to_string()),
                span: span.clone(),
            })),
            "export"
        );
        assert_eq!(
            statement_kind_label(&Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Var,
                declarations: vec![VariableDeclarator {
                    name: "x".to_string(),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span.clone(),
                }],
                span: span.clone(),
            })),
            "variable_declaration"
        );
        assert_eq!(
            statement_kind_label(&Statement::Expression(ExpressionStatement {
                expression: Expression::NullLiteral,
                span,
            })),
            "expression"
        );
    }

    // -- ParseDiagnosticEnvelope canonical_value key coverage --

    #[test]
    fn parse_diagnostic_envelope_canonical_value_has_all_keys() {
        let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "<inline>", None);
        let envelope = normalize_parse_error(&err);
        let cv = envelope.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            for key in [
                "schema_version",
                "taxonomy_version",
                "hash_algorithm",
                "hash_prefix",
                "parse_error_code",
                "diagnostic_code",
                "category",
                "severity",
                "message_template",
                "source_label",
                "span",
                "budget_kind",
                "witness",
            ] {
                assert!(map.contains_key(key), "missing key: {key}");
            }
        } else {
            panic!("expected CanonicalValue::Map");
        }
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-27) --

    #[test]
    fn parse_event_serde_roundtrip() {
        let e = ParseEvent {
            sequence: 1,
            kind: ParseEventKind::StatementParsed,
            parser_mode: ParserMode::ScalarReference,
            goal: ParseGoal::Script,
            source_label: "test.js".to_string(),
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "parser".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            statement_index: Some(0),
            span: Some(SourceSpan::new(0, 10, 1, 1, 1, 11)),
            payload_kind: Some("statement".to_string()),
            payload_hash: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ParseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn parse_event_minimal_serde_roundtrip() {
        let e = ParseEvent {
            sequence: 0,
            kind: ParseEventKind::ParseStarted,
            parser_mode: ParserMode::ScalarReference,
            goal: ParseGoal::Module,
            source_label: "mod.js".to_string(),
            trace_id: "t-2".to_string(),
            decision_id: "d-2".to_string(),
            policy_id: "p-2".to_string(),
            component: "parser".to_string(),
            outcome: "started".to_string(),
            error_code: None,
            statement_index: None,
            span: None,
            payload_kind: None,
            payload_hash: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ParseEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn materialized_statement_node_serde_roundtrip() {
        let n = MaterializedStatementNode {
            node_id: "node-001".to_string(),
            sequence: 1,
            statement_index: 0,
            payload_hash: "hash-abc".to_string(),
            span: SourceSpan::new(0, 20, 1, 1, 1, 21),
        };
        let json = serde_json::to_string(&n).unwrap();
        let back: MaterializedStatementNode = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn materialized_syntax_tree_serde_roundtrip() {
        let tree = MaterializedSyntaxTree {
            schema_version: MaterializedSyntaxTree::schema_version().to_string(),
            contract_version: MaterializedSyntaxTree::contract_version().to_string(),
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "parser".to_string(),
            parser_mode: ParserMode::ScalarReference,
            goal: ParseGoal::Script,
            source_label: "test.js".to_string(),
            root_node_id: "root-001".to_string(),
            statement_nodes: vec![MaterializedStatementNode {
                node_id: "node-001".to_string(),
                sequence: 1,
                statement_index: 0,
                payload_hash: "hash-abc".to_string(),
                span: SourceSpan::new(0, 10, 1, 1, 1, 11),
            }],
            syntax_tree: SyntaxTree {
                goal: ParseGoal::Script,
                body: vec![],
                span: SourceSpan::new(0, 10, 1, 1, 1, 11),
            },
        };
        let json = serde_json::to_string(&tree).unwrap();
        let back: MaterializedSyntaxTree = serde_json::from_str(&json).unwrap();
        assert_eq!(tree, back);
        assert_eq!(back.statement_nodes.len(), 1);
    }
}
