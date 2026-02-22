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
}

/// Deterministic parse error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    pub code: ParseErrorCode,
    pub message: String,
    pub source_label: String,
    pub span: Option<SourceSpan>,
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

impl Es2020Parser for CanonicalEs2020Parser {
    fn parse<I>(&self, input: I, goal: ParseGoal) -> ParseResult<SyntaxTree>
    where
        I: ParserInput,
    {
        let source = input.into_source()?;
        parse_source(&source.text, &source.label, goal)
    }
}

fn parse_source(text: &str, source_label: &str, goal: ParseGoal) -> ParseResult<SyntaxTree> {
    if text.trim().is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::EmptySource,
            "source is empty after whitespace normalization",
            source_label.to_string(),
            None,
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
            statements.push(parse_statement(statement_text, goal, source_label, span)?);
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

    for (index, ch) in line.char_indices() {
        if ch == ';' {
            push_segment(&mut out, line, segment_start, index);
            segment_start = index.saturating_add(ch.len_utf8());
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
    source_label: &str,
    span: SourceSpan,
) -> ParseResult<Statement> {
    if statement.starts_with("import ") {
        if goal == ParseGoal::Script {
            return Err(ParseError::new(
                ParseErrorCode::InvalidGoal,
                "import declarations are only valid in module goal",
                source_label.to_string(),
                Some(span),
            ));
        }
        return parse_import(statement, source_label, span).map(Statement::Import);
    }

    if statement.starts_with("export ") {
        if goal == ParseGoal::Script {
            return Err(ParseError::new(
                ParseErrorCode::InvalidGoal,
                "export declarations are only valid in module goal",
                source_label.to_string(),
                Some(span),
            ));
        }
        return parse_export(statement, source_label, span).map(Statement::Export);
    }

    let expression = parse_expression(statement, source_label, &span)?;
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
    let body = statement["import ".len()..].trim();
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
    source_label: &str,
    span: SourceSpan,
) -> ParseResult<ExportDeclaration> {
    let body = statement["export ".len()..].trim();
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "export declaration is missing clause",
            source_label.to_string(),
            Some(span),
        ));
    }

    let kind = if let Some(default_expr) = body.strip_prefix("default ") {
        ExportKind::Default(parse_expression(default_expr.trim(), source_label, &span)?)
    } else {
        ExportKind::NamedClause(canonicalize_whitespace(body))
    };
    Ok(ExportDeclaration { kind, span })
}

fn parse_expression(
    expression: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<Expression> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "empty expression statement",
            source_label.to_string(),
            Some(span.clone()),
        ));
    }

    if let Some(value) = parse_quoted_string(expression) {
        return Ok(Expression::StringLiteral(value));
    }
    if let Ok(value) = expression.parse::<i64>() {
        return Ok(Expression::NumericLiteral(value));
    }
    if let Some(rest) = expression.strip_prefix("await ") {
        let nested = parse_expression(rest.trim(), source_label, span)?;
        return Ok(Expression::Await(Box::new(nested)));
    }
    if is_identifier(expression) {
        return Ok(Expression::Identifier(expression.to_string()));
    }
    Ok(Expression::Raw(canonicalize_whitespace(expression)))
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

fn is_identifier(input: &str) -> bool {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
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
}
