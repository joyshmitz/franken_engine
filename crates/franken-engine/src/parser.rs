//! Deterministic parser interface for ES2020 script/module goals.
//!
//! The parser trait is generic over input source and emits canonical `IR0`
//! syntax artifacts from `crate::ast`.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ast::{
    ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportDeclaration, ParseGoal,
    SourceSpan, Statement, SyntaxTree,
};

pub type ParseResult<T> = Result<T, ParseError>;

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
                    script_goal: GrammarCoverageStatus::Unsupported,
                    module_goal: GrammarCoverageStatus::Unsupported,
                    notes: "No dedicated declaration AST yet.".to_string(),
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
        let source = input.into_source()?;
        parse_source(&source.text, &source.label, goal, options)
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

fn count_lexical_tokens(input: &str) -> u64 {
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

        if index + 1 < bytes.len() {
            let two = (bytes[index], bytes[index + 1]);
            if matches!(
                two,
                (b'=', b'=')
                    | (b'!', b'=')
                    | (b'<', b'=')
                    | (b'>', b'=')
                    | (b'&', b'&')
                    | (b'|', b'|')
                    | (b'?', b'?')
                    | (b'=', b'>')
            ) {
                index = index.saturating_add(2);
                token_count = token_count.saturating_add(1);
                continue;
            }
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
}
