//! SIMD/SWAR-accelerated lexical analysis for the FrankenEngine parser front-end.
//!
//! Uses SWAR (SIMD Within A Register) techniques to classify bytes in parallel
//! using ordinary 64-bit arithmetic — no `unsafe` code or platform intrinsics
//! required. Maintains strict semantic parity with the scalar reference lexer
//! (`parser::count_lexical_tokens`), with built-in differential parity checking
//! and deterministic fallback.
//!
//! ## Architecture
//!
//! The module provides three levels of lexing:
//! 1. **SWAR-accelerated** (`SwarLexer`): Processes 8 bytes at a time for whitespace
//!    skipping, identifier-boundary detection, and string delimiter scanning.
//! 2. **Scalar reference** (`ScalarLexer`): Byte-by-byte lexer that exactly mirrors
//!    `parser::count_lexical_tokens` semantics.
//! 3. **Differential harness** (`DifferentialLexer`): Runs both in parallel and
//!    asserts token-stream parity, emitting diagnostics on mismatch.
//!
//! ## Related beads
//!
//! - bd-19ba (this module)
//! - bd-drjd (arena-allocated AST / token definitions — upstream dependency)
//! - bd-1vfi (parallel parsing — downstream consumer)
//! - bd-1b70 (parser oracle — parity gate)

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ast::SourceSpan;
use crate::engine_object_id::EngineObjectId;

/// Schema version for serde stability of simd_lexer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LexerSchemaVersion {
    /// Initial version.
    V1,
}

impl fmt::Display for LexerSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => f.write_str("v1"),
        }
    }
}

// ---------------------------------------------------------------------------
// Token kinds — deterministic, exhaustive classification
// ---------------------------------------------------------------------------

/// Deterministic token classification for lexical analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TokenKind {
    /// Identifier: `[a-zA-Z_$][a-zA-Z0-9_$]*`
    Identifier,
    /// Numeric literal: `[0-9]+`
    NumericLiteral,
    /// String literal: single or double quoted, with escape support.
    StringLiteral,
    /// Unterminated string literal (hit newline or EOF before closing quote).
    UnterminatedString,
    /// Two-character operator: `==`, `!=`, `<=`, `>=`, `&&`, `||`, `??`, `=>`.
    TwoCharOperator,
    /// Single-character punctuation or operator (anything not otherwise classified).
    Punctuation,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identifier => write!(f, "Identifier"),
            Self::NumericLiteral => write!(f, "NumericLiteral"),
            Self::StringLiteral => write!(f, "StringLiteral"),
            Self::UnterminatedString => write!(f, "UnterminatedString"),
            Self::TwoCharOperator => write!(f, "TwoCharOperator"),
            Self::Punctuation => write!(f, "Punctuation"),
        }
    }
}

/// A single lexical token with kind, byte span, and source text slice reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub kind: TokenKind,
    pub start: u64,
    pub end: u64,
}

impl Token {
    pub fn span_len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn source_span(&self, line: u64, column_start: u64) -> SourceSpan {
        SourceSpan::new(
            self.start,
            self.end,
            line,
            column_start,
            line,
            column_start.saturating_add(self.span_len()),
        )
    }
}

// ---------------------------------------------------------------------------
// Lexer mode and configuration
// ---------------------------------------------------------------------------

/// Which lexer engine to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LexerMode {
    /// SWAR-accelerated path (default on all targets since it uses no intrinsics).
    Swar,
    /// Scalar reference path (guaranteed baseline).
    Scalar,
    /// Run both and assert parity; emit diagnostics on mismatch.
    Differential,
}

impl fmt::Display for LexerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Swar => write!(f, "SWAR"),
            Self::Scalar => write!(f, "Scalar"),
            Self::Differential => write!(f, "Differential"),
        }
    }
}

/// Reason the SWAR path was disabled in favor of scalar fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwarDisableReason {
    /// Operator explicitly chose scalar mode.
    OperatorOverride,
    /// Differential parity check detected a mismatch — automatic fallback.
    ParityMismatch { mismatch_index: u64 },
    /// Input too small to benefit from SWAR (below width threshold).
    InputBelowThreshold { input_len: u64, threshold: u64 },
    /// Token budget would be exceeded before SWAR scan completes.
    TokenBudgetExceeded,
}

impl fmt::Display for SwarDisableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperatorOverride => write!(f, "operator_override"),
            Self::ParityMismatch { mismatch_index } => {
                write!(f, "parity_mismatch(index={})", mismatch_index)
            }
            Self::InputBelowThreshold {
                input_len,
                threshold,
            } => write!(
                f,
                "input_below_threshold(len={}, threshold={})",
                input_len, threshold
            ),
            Self::TokenBudgetExceeded => write!(f, "token_budget_exceeded"),
        }
    }
}

/// Configuration for the lexer pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexerConfig {
    /// Which engine to use.
    pub mode: LexerMode,
    /// Maximum number of tokens before budget is exceeded.
    pub max_tokens: u64,
    /// Maximum number of source bytes to scan.
    pub max_source_bytes: u64,
    /// Minimum input size (bytes) to engage SWAR path. Below this, scalar is used.
    pub swar_min_input_bytes: u64,
    /// If true, emit full token stream. If false, only count tokens (fast path).
    pub emit_tokens: bool,
}

impl Default for LexerConfig {
    fn default() -> Self {
        Self {
            mode: LexerMode::Swar,
            max_tokens: 65_536,
            max_source_bytes: 1_048_576,
            swar_min_input_bytes: 64,
            emit_tokens: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Lexer output
// ---------------------------------------------------------------------------

/// Result of a lexing pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexerOutput {
    /// The mode that was actually used (may differ from config if fallback occurred).
    pub actual_mode: LexerMode,
    /// If SWAR was disabled, why.
    pub swar_disable_reason: Option<SwarDisableReason>,
    /// Total number of tokens found.
    pub token_count: u64,
    /// Emitted tokens (empty if `emit_tokens` was false).
    pub tokens: Vec<Token>,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Whether the token budget was exceeded.
    pub budget_exceeded: bool,
    /// Schema version for serde stability.
    pub schema_version: LexerSchemaVersion,
}

/// Mismatch detail when differential mode detects divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityMismatch {
    /// Index of the first divergent token (0-based).
    pub token_index: u64,
    /// SWAR token at the divergence point (if available).
    pub swar_token: Option<Token>,
    /// Scalar token at the divergence point (if available).
    pub scalar_token: Option<Token>,
    /// Overall SWAR token count.
    pub swar_count: u64,
    /// Overall scalar token count.
    pub scalar_count: u64,
}

impl fmt::Display for ParityMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parity mismatch at token {}: swar_count={}, scalar_count={}",
            self.token_index, self.swar_count, self.scalar_count
        )
    }
}

/// Full differential result including both outputs and any mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialResult {
    pub swar_output: LexerOutput,
    pub scalar_output: LexerOutput,
    pub parity_ok: bool,
    pub mismatch: Option<ParityMismatch>,
}

// ---------------------------------------------------------------------------
// Lexer error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LexerError {
    /// Source exceeds maximum allowed byte count.
    SourceTooLarge { size: u64, max: u64 },
    /// Token budget was exceeded during scanning.
    TokenBudgetExceeded { count: u64, max: u64 },
    /// Internal consistency error.
    InternalError(String),
}

impl fmt::Display for LexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLarge { size, max } => {
                write!(f, "source too large: {} bytes (max {})", size, max)
            }
            Self::TokenBudgetExceeded { count, max } => {
                write!(f, "token budget exceeded: {} tokens (max {})", count, max)
            }
            Self::InternalError(msg) => write!(f, "internal lexer error: {}", msg),
        }
    }
}

// ---------------------------------------------------------------------------
// SWAR bit-parallel primitives (safe Rust, no intrinsics)
// ---------------------------------------------------------------------------

/// SWAR word size: we process 8 bytes at a time using u64 arithmetic.
const SWAR_WIDTH: usize = 8;

/// Broadcast a single byte to all 8 positions of a u64.
#[inline]
const fn broadcast(byte: u8) -> u64 {
    0x0101_0101_0101_0101_u64.wrapping_mul(byte as u64)
}

/// Produce a mask where each byte position that equals `target` has its high bit set.
/// Other bytes have their high bit clear.
///
/// Uses a carry-safe SWAR formulation: isolates the lower 7 bits of each XOR'd byte,
/// adds 0x7F per lane (which never overflows a byte boundary since max input is 0x7F),
/// and checks whether both the lower-7-bit and high-bit portions are zero. This avoids
/// the borrow-propagation false positive in the classic `(v - 0x01…) & ~v & 0x80…`
/// pattern (which misdetects byte value target+1 after a match).
#[inline]
const fn byte_eq_mask(word: u64, target: u8) -> u64 {
    let broadcast_target = broadcast(target);
    let xor = word ^ broadcast_target;
    let high_bits = 0x8080_8080_8080_8080_u64;
    let low_mask = !high_bits; // 0x7F7F_7F7F_7F7F_7F7F
    // Check lower 7 bits of each byte are zero (carry-free: max 0x7F + 0x7F = 0xFE < 0x100)
    let lower7 = xor & low_mask;
    let lower_nonzero = lower7.wrapping_add(low_mask) & high_bits;
    let lower_zero = !lower_nonzero & high_bits;
    // Check high bit of each byte is also zero
    let high_zero = !xor & high_bits;
    lower_zero & high_zero
}

// The following SWAR mask functions are available for testing and future use
// when borrow-propagation-safe formulations are validated. The production SWAR
// path currently uses explicit byte-by-byte word checks (is_all_whitespace_word,
// is_all_ident_continue_word, is_all_digit_word) which avoid SWAR false positives.

#[cfg(test)]
fn whitespace_mask(word: u64) -> u64 {
    byte_eq_mask(word, b' ')
        | byte_eq_mask(word, b'\t')
        | byte_eq_mask(word, b'\n')
        | byte_eq_mask(word, b'\r')
}

#[cfg(test)]
fn digit_mask(word: u64) -> u64 {
    let high_bits = 0x8080_8080_8080_8080_u64;
    let low_bound = 0x3030_3030_3030_3030_u64;
    let high_bound = 0x3939_3939_3939_3939_u64;
    let ge_low = !word.wrapping_sub(low_bound) & high_bits;
    let le_high = !high_bound.wrapping_sub(word) & high_bits;
    ge_low & le_high
}

#[cfg(test)]
fn identifier_continue_mask(word: u64) -> u64 {
    alpha_mask(word) | digit_mask(word) | byte_eq_mask(word, b'_') | byte_eq_mask(word, b'$')
}

#[cfg(test)]
fn alpha_mask(word: u64) -> u64 {
    let upper = word & !broadcast(0x20);
    let high_bits = 0x8080_8080_8080_8080_u64;
    let a_broadcast = broadcast(b'A');
    let z_broadcast = broadcast(b'Z');
    let ge_a = !upper.wrapping_sub(a_broadcast) & high_bits;
    let le_z = !z_broadcast.wrapping_sub(upper) & high_bits;
    ge_a & le_z
}

#[cfg(test)]
const fn mask_popcount(mask: u64) -> u32 {
    (mask >> 7).count_ones()
}

#[cfg(test)]
const fn mask_first_set(mask: u64) -> u32 {
    if mask == 0 {
        8
    } else {
        mask.trailing_zeros() / 8
    }
}

// ---------------------------------------------------------------------------
// Scalar reference lexer
// ---------------------------------------------------------------------------

/// Scalar reference lexer — byte-by-byte, mirrors `parser::count_lexical_tokens` exactly.
pub struct ScalarLexer;

impl ScalarLexer {
    pub fn lex(input: &[u8], config: &LexerConfig) -> Result<LexerOutput, LexerError> {
        let input_len = input.len() as u64;
        if input_len > config.max_source_bytes {
            return Err(LexerError::SourceTooLarge {
                size: input_len,
                max: config.max_source_bytes,
            });
        }

        let mut index = 0usize;
        let mut tokens = Vec::new();
        let mut token_count = 0u64;
        let emit = config.emit_tokens;

        while index < input.len() {
            if token_count >= config.max_tokens {
                return Ok(LexerOutput {
                    actual_mode: LexerMode::Scalar,
                    swar_disable_reason: None,
                    token_count,
                    tokens,
                    bytes_scanned: index as u64,
                    budget_exceeded: true,
                    schema_version: LexerSchemaVersion::V1,
                });
            }

            let byte = input[index];

            // Whitespace
            if byte.is_ascii_whitespace() {
                index = index.saturating_add(1);
                continue;
            }

            // Identifier
            if is_ident_start(byte) {
                let start = index as u64;
                index = index.saturating_add(1);
                while index < input.len() && is_ident_continue(input[index]) {
                    index = index.saturating_add(1);
                }
                token_count = token_count.saturating_add(1);
                if emit {
                    tokens.push(Token {
                        kind: TokenKind::Identifier,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // Numeric literal
            if byte.is_ascii_digit() {
                let start = index as u64;
                index = index.saturating_add(1);
                while index < input.len() && input[index].is_ascii_digit() {
                    index = index.saturating_add(1);
                }
                token_count = token_count.saturating_add(1);
                if emit {
                    tokens.push(Token {
                        kind: TokenKind::NumericLiteral,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // String literal
            if byte == b'\'' || byte == b'"' {
                let quote = byte;
                let start = index as u64;
                index = index.saturating_add(1);
                let mut terminated = false;

                while index < input.len() {
                    let current = input[index];
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

                token_count = token_count.saturating_add(1);
                if emit {
                    let kind = if terminated {
                        TokenKind::StringLiteral
                    } else {
                        TokenKind::UnterminatedString
                    };
                    tokens.push(Token {
                        kind,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // Two-character operators
            if index + 1 < input.len() && is_two_char_operator(input[index], input[index + 1]) {
                let start = index as u64;
                index = index.saturating_add(2);
                token_count = token_count.saturating_add(1);
                if emit {
                    tokens.push(Token {
                        kind: TokenKind::TwoCharOperator,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // Single punctuation / operator
            let start = index as u64;
            index = index.saturating_add(1);
            token_count = token_count.saturating_add(1);
            if emit {
                tokens.push(Token {
                    kind: TokenKind::Punctuation,
                    start,
                    end: index as u64,
                });
            }
        }

        Ok(LexerOutput {
            actual_mode: LexerMode::Scalar,
            swar_disable_reason: None,
            token_count,
            tokens,
            bytes_scanned: input.len() as u64,
            budget_exceeded: false,
            schema_version: LexerSchemaVersion::V1,
        })
    }
}

// ---------------------------------------------------------------------------
// SWAR-accelerated lexer
// ---------------------------------------------------------------------------

/// SWAR-accelerated lexer — processes 8 bytes at a time for fast whitespace
/// skipping and identifier/digit boundary detection.
pub struct SwarLexer;

impl SwarLexer {
    pub fn lex(input: &[u8], config: &LexerConfig) -> Result<LexerOutput, LexerError> {
        let input_len = input.len() as u64;
        if input_len > config.max_source_bytes {
            return Err(LexerError::SourceTooLarge {
                size: input_len,
                max: config.max_source_bytes,
            });
        }

        // Fall back to scalar for very small inputs
        if input_len < config.swar_min_input_bytes {
            let mut result = ScalarLexer::lex(input, config)?;
            result.swar_disable_reason = Some(SwarDisableReason::InputBelowThreshold {
                input_len,
                threshold: config.swar_min_input_bytes,
            });
            return Ok(result);
        }

        let mut index = 0usize;
        let mut tokens = Vec::new();
        let mut token_count = 0u64;
        let emit = config.emit_tokens;
        let len = input.len();

        while index < len {
            if token_count >= config.max_tokens {
                return Ok(LexerOutput {
                    actual_mode: LexerMode::Swar,
                    swar_disable_reason: Some(SwarDisableReason::TokenBudgetExceeded),
                    token_count,
                    tokens,
                    bytes_scanned: index as u64,
                    budget_exceeded: true,
                    schema_version: LexerSchemaVersion::V1,
                });
            }

            // SWAR fast-path: skip whitespace in 8-byte chunks.
            // Only use SWAR for the all-whitespace case to avoid borrow-propagation
            // false positives in the byte_eq_mask SWAR trick.
            while index + SWAR_WIDTH <= len {
                let word = read_u64_le(input, index);
                if is_all_whitespace_word(word) {
                    index = index.saturating_add(SWAR_WIDTH);
                } else {
                    break;
                }
            }

            // Scalar whitespace skip for remainder
            while index < len && input[index].is_ascii_whitespace() {
                index = index.saturating_add(1);
            }

            if index >= len {
                break;
            }

            let byte = input[index];

            // Identifier with SWAR continuation scanning
            if is_ident_start(byte) {
                let start = index as u64;
                index = index.saturating_add(1);

                // SWAR scan for identifier continuation bytes — only all-match fast path
                while index + SWAR_WIDTH <= len {
                    let word = read_u64_le(input, index);
                    if is_all_ident_continue_word(word) {
                        index = index.saturating_add(SWAR_WIDTH);
                    } else {
                        break;
                    }
                }

                // Scalar remainder
                while index < len && is_ident_continue(input[index]) {
                    index = index.saturating_add(1);
                }

                token_count = token_count.saturating_add(1);
                if emit {
                    tokens.push(Token {
                        kind: TokenKind::Identifier,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // Numeric literal with SWAR digit scanning
            if byte.is_ascii_digit() {
                let start = index as u64;
                index = index.saturating_add(1);

                // SWAR scan for digit bytes — only all-match fast path
                while index + SWAR_WIDTH <= len {
                    let word = read_u64_le(input, index);
                    if is_all_digit_word(word) {
                        index = index.saturating_add(SWAR_WIDTH);
                    } else {
                        break;
                    }
                }

                while index < len && input[index].is_ascii_digit() {
                    index = index.saturating_add(1);
                }

                token_count = token_count.saturating_add(1);
                if emit {
                    tokens.push(Token {
                        kind: TokenKind::NumericLiteral,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // String literal with SWAR quote/escape scanning
            if byte == b'\'' || byte == b'"' {
                let quote = byte;
                let start = index as u64;
                index = index.saturating_add(1);
                let mut terminated = false;

                // SWAR scan for string termination
                while index + SWAR_WIDTH <= len {
                    let word = read_u64_le(input, index);
                    let quote_mask = byte_eq_mask(word, quote);
                    let escape_mask = byte_eq_mask(word, b'\\');
                    let nl_mask = byte_eq_mask(word, b'\n') | byte_eq_mask(word, b'\r');

                    let interesting = quote_mask | escape_mask | nl_mask;
                    if interesting == 0 {
                        // No interesting bytes in this chunk — skip all 8
                        index = index.saturating_add(SWAR_WIDTH);
                        continue;
                    }

                    // Found something interesting — fall back to scalar for correctness
                    break;
                }

                // Scalar string scanning for remainder / complex cases
                while index < len {
                    let current = input[index];
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

                token_count = token_count.saturating_add(1);
                if emit {
                    let kind = if terminated {
                        TokenKind::StringLiteral
                    } else {
                        TokenKind::UnterminatedString
                    };
                    tokens.push(Token {
                        kind,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // Two-character operators
            if index + 1 < len && is_two_char_operator(input[index], input[index + 1]) {
                let start = index as u64;
                index = index.saturating_add(2);
                token_count = token_count.saturating_add(1);
                if emit {
                    tokens.push(Token {
                        kind: TokenKind::TwoCharOperator,
                        start,
                        end: index as u64,
                    });
                }
                continue;
            }

            // Single punctuation
            let start = index as u64;
            index = index.saturating_add(1);
            token_count = token_count.saturating_add(1);
            if emit {
                tokens.push(Token {
                    kind: TokenKind::Punctuation,
                    start,
                    end: index as u64,
                });
            }
        }

        Ok(LexerOutput {
            actual_mode: LexerMode::Swar,
            swar_disable_reason: None,
            token_count,
            tokens,
            bytes_scanned: input.len() as u64,
            budget_exceeded: false,
            schema_version: LexerSchemaVersion::V1,
        })
    }
}

// ---------------------------------------------------------------------------
// Differential lexer
// ---------------------------------------------------------------------------

/// Runs both SWAR and scalar lexers and compares results for parity.
pub struct DifferentialLexer;

impl DifferentialLexer {
    pub fn lex(input: &[u8], config: &LexerConfig) -> Result<DifferentialResult, LexerError> {
        // Force emit_tokens for comparison
        let mut emit_config = config.clone();
        emit_config.emit_tokens = true;

        let mut swar_config = emit_config.clone();
        swar_config.mode = LexerMode::Swar;
        let swar_output = SwarLexer::lex(input, &swar_config)?;

        let mut scalar_config = emit_config;
        scalar_config.mode = LexerMode::Scalar;
        let scalar_output = ScalarLexer::lex(input, &scalar_config)?;

        let mismatch = find_mismatch(&swar_output, &scalar_output);
        let parity_ok = mismatch.is_none();

        Ok(DifferentialResult {
            swar_output,
            scalar_output,
            parity_ok,
            mismatch,
        })
    }
}

fn find_mismatch(swar: &LexerOutput, scalar: &LexerOutput) -> Option<ParityMismatch> {
    // First check token counts
    if swar.token_count != scalar.token_count {
        let min_len = swar.tokens.len().min(scalar.tokens.len());
        // Find first divergence point
        for i in 0..min_len {
            if swar.tokens[i] != scalar.tokens[i] {
                return Some(ParityMismatch {
                    token_index: i as u64,
                    swar_token: Some(swar.tokens[i].clone()),
                    scalar_token: Some(scalar.tokens[i].clone()),
                    swar_count: swar.token_count,
                    scalar_count: scalar.token_count,
                });
            }
        }
        // Counts differ but tokens agree up to min_len — divergence at min_len
        return Some(ParityMismatch {
            token_index: min_len as u64,
            swar_token: swar.tokens.get(min_len).cloned(),
            scalar_token: scalar.tokens.get(min_len).cloned(),
            swar_count: swar.token_count,
            scalar_count: scalar.token_count,
        });
    }

    // Check individual tokens
    for (i, (s, r)) in swar.tokens.iter().zip(scalar.tokens.iter()).enumerate() {
        if s != r {
            return Some(ParityMismatch {
                token_index: i as u64,
                swar_token: Some(s.clone()),
                scalar_token: Some(r.clone()),
                swar_count: swar.token_count,
                scalar_count: scalar.token_count,
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Lex the input using the configured mode. Returns the lexer output or an error.
pub fn lex(input: &str, config: &LexerConfig) -> Result<LexerOutput, LexerError> {
    let bytes = input.as_bytes();
    match config.mode {
        LexerMode::Scalar => ScalarLexer::lex(bytes, config),
        LexerMode::Swar => SwarLexer::lex(bytes, config),
        LexerMode::Differential => {
            let diff = DifferentialLexer::lex(bytes, config)?;
            if diff.parity_ok {
                // Return SWAR result (it's the fast one)
                Ok(diff.swar_output)
            } else {
                // Parity failure — return scalar result with diagnostic
                let mismatch_index = diff.mismatch.as_ref().map(|m| m.token_index).unwrap_or(0);
                let mut output = diff.scalar_output;
                output.swar_disable_reason =
                    Some(SwarDisableReason::ParityMismatch { mismatch_index });
                Ok(output)
            }
        }
    }
}

/// Quick token count — does not emit individual tokens.
pub fn count_tokens(input: &str, config: &LexerConfig) -> Result<u64, LexerError> {
    let mut count_config = config.clone();
    count_config.emit_tokens = false;
    let output = lex(input, &count_config)?;
    Ok(output.token_count)
}

// ---------------------------------------------------------------------------
// Lexer artifact for reproducibility
// ---------------------------------------------------------------------------

/// Artifact bundle produced by the lexer for reproducibility and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexerArtifact {
    /// Unique identifier for this artifact.
    pub artifact_id: EngineObjectId,
    /// Configuration used for the run.
    pub config: LexerConfig,
    /// Output from the lexer.
    pub output: LexerOutput,
    /// SHA-256 of the input source (for reproducibility without storing the source).
    pub input_hash: String,
    /// Input length in bytes.
    pub input_len: u64,
    /// Schema version.
    pub schema_version: LexerSchemaVersion,
}

/// Architecture capability profile for SWAR support decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchCapabilityProfile {
    /// SWAR width in bytes (always 8 for u64-based SWAR).
    pub swar_width: u32,
    /// Target pointer width in bits (32 or 64).
    pub pointer_width: u32,
    /// Whether the target is little-endian (required for our SWAR read).
    pub little_endian: bool,
    /// Whether SWAR path is available (true on all targets with 64-bit u64).
    pub swar_available: bool,
}

impl ArchCapabilityProfile {
    /// Detect the current architecture's SWAR capability.
    pub fn detect() -> Self {
        Self {
            swar_width: 8,
            pointer_width: if cfg!(target_pointer_width = "64") {
                64
            } else {
                32
            },
            little_endian: cfg!(target_endian = "little"),
            swar_available: true, // u64 SWAR works on all targets
        }
    }

    /// Whether the architecture supports the SWAR fast path.
    pub fn supports_swar(&self) -> bool {
        self.swar_available && self.little_endian
    }
}

// ---------------------------------------------------------------------------
// Throughput measurement
// ---------------------------------------------------------------------------

/// Throughput measurement for a lexer run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputSample {
    /// Lexer mode used.
    pub mode: LexerMode,
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Tokens produced.
    pub token_count: u64,
    /// Wall time in nanoseconds.
    pub wall_time_ns: u64,
    /// Bytes per second (millionths for fixed-point).
    pub bytes_per_second_millionths: u64,
    /// Tokens per second (millionths for fixed-point).
    pub tokens_per_second_millionths: u64,
}

impl ThroughputSample {
    /// Compute throughput from raw measurements.
    pub fn compute(mode: LexerMode, input_bytes: u64, token_count: u64, wall_time_ns: u64) -> Self {
        let bytes_per_sec = if wall_time_ns > 0 {
            input_bytes
                .saturating_mul(1_000_000_000)
                .saturating_mul(1_000_000)
                .checked_div(wall_time_ns)
                .unwrap_or(0)
        } else {
            0
        };
        let tokens_per_sec = if wall_time_ns > 0 {
            token_count
                .saturating_mul(1_000_000_000)
                .saturating_mul(1_000_000)
                .checked_div(wall_time_ns)
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            mode,
            input_bytes,
            token_count,
            wall_time_ns,
            bytes_per_second_millionths: bytes_per_sec,
            tokens_per_second_millionths: tokens_per_sec,
        }
    }
}

/// Comparison between SWAR and scalar throughput.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputComparison {
    pub swar: ThroughputSample,
    pub scalar: ThroughputSample,
    /// Speedup ratio in millionths (e.g. 3_000_000 = 3x faster).
    /// Values > 1_000_000 mean SWAR is faster.
    pub speedup_millionths: u64,
}

impl ThroughputComparison {
    pub fn compute(swar: ThroughputSample, scalar: ThroughputSample) -> Self {
        let speedup = if scalar.bytes_per_second_millionths > 0 {
            swar.bytes_per_second_millionths
                .saturating_mul(1_000_000)
                .checked_div(scalar.bytes_per_second_millionths)
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            swar,
            scalar,
            speedup_millionths: speedup,
        }
    }
}

// ---------------------------------------------------------------------------
// Rollback gate
// ---------------------------------------------------------------------------

/// Configuration for the SWAR rollback gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackGateConfig {
    /// Maximum allowed parity mismatches before SWAR is disabled.
    pub max_parity_mismatches: u64,
    /// Minimum speedup (millionths) required to keep SWAR enabled.
    pub min_speedup_millionths: u64,
    /// Maximum p99 tail latency regression (millionths) allowed.
    pub max_p99_regression_millionths: u64,
}

impl Default for RollbackGateConfig {
    fn default() -> Self {
        Self {
            max_parity_mismatches: 0,
            min_speedup_millionths: 1_000_000, // At least 1x (no regression)
            max_p99_regression_millionths: 500_000, // 50% max regression on p99
        }
    }
}

/// Result of the rollback gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackGateResult {
    /// Whether SWAR should remain enabled.
    pub swar_approved: bool,
    /// Parity mismatches observed.
    pub parity_mismatches: u64,
    /// Speedup ratio observed (millionths).
    pub observed_speedup_millionths: u64,
    /// Reasons for disabling SWAR (empty if approved).
    pub disable_reasons: Vec<String>,
}

/// Evaluate whether SWAR should remain enabled based on observed behavior.
pub fn evaluate_rollback_gate(
    parity_mismatches: u64,
    speedup_millionths: u64,
    p99_regression_millionths: u64,
    config: &RollbackGateConfig,
) -> RollbackGateResult {
    let mut reasons = Vec::new();

    if parity_mismatches > config.max_parity_mismatches {
        reasons.push(format!(
            "parity mismatches {} > max {}",
            parity_mismatches, config.max_parity_mismatches
        ));
    }

    if speedup_millionths < config.min_speedup_millionths {
        reasons.push(format!(
            "speedup {} < min {}",
            speedup_millionths, config.min_speedup_millionths
        ));
    }

    if p99_regression_millionths > config.max_p99_regression_millionths {
        reasons.push(format!(
            "p99 regression {} > max {}",
            p99_regression_millionths, config.max_p99_regression_millionths
        ));
    }

    RollbackGateResult {
        swar_approved: reasons.is_empty(),
        parity_mismatches,
        observed_speedup_millionths: speedup_millionths,
        disable_reasons: reasons,
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

#[inline]
fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

#[inline]
fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

#[inline]
fn is_two_char_operator(a: u8, b: u8) -> bool {
    matches!(
        (a, b),
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

/// Check if all 8 bytes in a word are ASCII whitespace.
/// Uses explicit byte extraction — avoids SWAR borrow-propagation false positives.
#[inline]
fn is_all_whitespace_word(word: u64) -> bool {
    let bytes = word.to_le_bytes();
    bytes[0].is_ascii_whitespace()
        && bytes[1].is_ascii_whitespace()
        && bytes[2].is_ascii_whitespace()
        && bytes[3].is_ascii_whitespace()
        && bytes[4].is_ascii_whitespace()
        && bytes[5].is_ascii_whitespace()
        && bytes[6].is_ascii_whitespace()
        && bytes[7].is_ascii_whitespace()
}

/// Check if all 8 bytes in a word are identifier continuation characters.
#[inline]
fn is_all_ident_continue_word(word: u64) -> bool {
    let bytes = word.to_le_bytes();
    is_ident_continue(bytes[0])
        && is_ident_continue(bytes[1])
        && is_ident_continue(bytes[2])
        && is_ident_continue(bytes[3])
        && is_ident_continue(bytes[4])
        && is_ident_continue(bytes[5])
        && is_ident_continue(bytes[6])
        && is_ident_continue(bytes[7])
}

/// Check if all 8 bytes in a word are ASCII digits.
#[inline]
fn is_all_digit_word(word: u64) -> bool {
    let bytes = word.to_le_bytes();
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7].is_ascii_digit()
}

/// Read 8 bytes from `input[offset..]` as a little-endian u64.
/// If fewer than 8 bytes remain, pad with zeros.
#[inline]
fn read_u64_le(input: &[u8], offset: usize) -> u64 {
    let remaining = input.len().saturating_sub(offset);
    if remaining >= 8 {
        let slice = &input[offset..offset + 8];
        u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    } else {
        let mut buf = [0u8; 8];
        let copy_len = remaining.min(8);
        buf[..copy_len].copy_from_slice(&input[offset..offset + copy_len]);
        u64::from_le_bytes(buf)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> LexerConfig {
        LexerConfig::default()
    }

    fn scalar_config() -> LexerConfig {
        LexerConfig {
            mode: LexerMode::Scalar,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    fn diff_config() -> LexerConfig {
        LexerConfig {
            mode: LexerMode::Differential,
            ..Default::default()
        }
    }

    // --- SWAR primitives ---

    #[test]
    fn broadcast_fills_all_bytes() {
        let val = broadcast(0x42);
        assert_eq!(val, 0x4242_4242_4242_4242);
    }

    #[test]
    fn byte_eq_mask_matches_target() {
        let word = u64::from_le_bytes([b'a', b'b', b'a', b'c', b'a', b'd', b'a', b'e']);
        let mask = byte_eq_mask(word, b'a');
        // Bytes 0, 2, 4, 6 should match (high bit set)
        assert_eq!(mask_popcount(mask), 4);
        assert_eq!(mask_first_set(mask), 0);
    }

    #[test]
    fn byte_eq_mask_no_match() {
        let word = u64::from_le_bytes([b'x', b'y', b'z', b'w', b'v', b'u', b't', b's']);
        let mask = byte_eq_mask(word, b'a');
        assert_eq!(mask_popcount(mask), 0);
        assert_eq!(mask_first_set(mask), 8);
    }

    #[test]
    fn whitespace_mask_detects_all_ws_types() {
        let word = u64::from_le_bytes([b' ', b'\t', b'\n', b'\r', b' ', b'\t', b'\n', b'\r']);
        let mask = whitespace_mask(word);
        assert_eq!(mask_popcount(mask), 8);
    }

    #[test]
    fn whitespace_mask_rejects_non_ws() {
        let word = u64::from_le_bytes([b'a', b'b', b'c', b'd', b'1', b'2', b'3', b'4']);
        let mask = whitespace_mask(word);
        assert_eq!(mask_popcount(mask), 0);
    }

    #[test]
    fn digit_mask_detects_digits() {
        let word = u64::from_le_bytes([b'0', b'5', b'9', b'a', b'z', b' ', b'1', b'8']);
        let mask = digit_mask(word);
        // Positions 0,1,2,6,7 are digits
        assert_eq!(mask_popcount(mask), 5);
    }

    #[test]
    fn alpha_mask_detects_letters() {
        let word = u64::from_le_bytes([b'a', b'Z', b'0', b'_', b'M', b'q', b' ', b'\n']);
        let mask = alpha_mask(word);
        // a, Z, M, q are alpha
        assert_eq!(mask_popcount(mask), 4);
    }

    #[test]
    fn identifier_continue_mask_includes_dollar_underscore() {
        let word = u64::from_le_bytes([b'$', b'_', b'a', b'Z', b'0', b' ', b'!', b'@']);
        let mask = identifier_continue_mask(word);
        // $, _, a, Z, 0 are ident continues; ' ', '!', '@' are not
        assert_eq!(mask_popcount(mask), 5);
    }

    #[test]
    fn identifier_continue_mask_includes_digits() {
        let word = u64::from_le_bytes([b'$', b'_', b'a', b'Z', b'0', b'9', b' ', b'!']);
        let mask = identifier_continue_mask(word);
        // $, _, a, Z, 0, 9 are ident continues
        assert_eq!(mask_popcount(mask), 6);
    }

    #[test]
    fn mask_first_set_finds_correct_byte() {
        // High bit set in byte 2 (0-indexed)
        let mask = 0x0000_0000_0080_0000_u64;
        assert_eq!(mask_first_set(mask), 2);
    }

    // --- Scalar lexer ---

    #[test]
    fn scalar_empty_input() {
        let result = ScalarLexer::lex(b"", &default_config()).unwrap();
        assert_eq!(result.token_count, 0);
        assert!(result.tokens.is_empty());
    }

    #[test]
    fn scalar_whitespace_only() {
        let result = ScalarLexer::lex(b"   \t\n\r  ", &default_config()).unwrap();
        assert_eq!(result.token_count, 0);
    }

    #[test]
    fn scalar_single_identifier() {
        let result = ScalarLexer::lex(b"hello", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[0].start, 0);
        assert_eq!(result.tokens[0].end, 5);
    }

    #[test]
    fn scalar_dollar_identifier() {
        let result = ScalarLexer::lex(b"$foo_bar123", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
    }

    #[test]
    fn scalar_numeric_literal() {
        let result = ScalarLexer::lex(b"42", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::NumericLiteral);
    }

    #[test]
    fn scalar_string_literal_double_quote() {
        let result = ScalarLexer::lex(b"\"hello world\"", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn scalar_string_literal_single_quote() {
        let result = ScalarLexer::lex(b"'hello'", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn scalar_string_with_escape() {
        let result = ScalarLexer::lex(b"\"he\\\"llo\"", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn scalar_unterminated_string() {
        let result = ScalarLexer::lex(b"\"hello\nworld\"", &default_config()).unwrap();
        // The first string is unterminated at newline, then 'world' is ident, then '"' is punct
        assert_eq!(result.tokens[0].kind, TokenKind::UnterminatedString);
    }

    #[test]
    fn scalar_two_char_operators() {
        let input = b"== != <= >= && || ?? =>";
        let result = ScalarLexer::lex(input, &default_config()).unwrap();
        assert_eq!(result.token_count, 8);
        for tok in &result.tokens {
            assert_eq!(tok.kind, TokenKind::TwoCharOperator);
        }
    }

    #[test]
    fn scalar_punctuation() {
        let result = ScalarLexer::lex(b"+ - * / ( )", &default_config()).unwrap();
        assert_eq!(result.token_count, 6);
        for tok in &result.tokens {
            assert_eq!(tok.kind, TokenKind::Punctuation);
        }
    }

    #[test]
    fn scalar_mixed_expression() {
        let input = b"foo + bar * 123";
        let result = ScalarLexer::lex(input, &default_config()).unwrap();
        assert_eq!(result.token_count, 5);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[1].kind, TokenKind::Punctuation); // +
        assert_eq!(result.tokens[2].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[3].kind, TokenKind::Punctuation); // *
        assert_eq!(result.tokens[4].kind, TokenKind::NumericLiteral);
    }

    #[test]
    fn scalar_token_budget_exceeded() {
        let config = LexerConfig {
            max_tokens: 3,
            ..default_config()
        };
        let result = ScalarLexer::lex(b"a b c d e", &config).unwrap();
        assert!(result.budget_exceeded);
        assert_eq!(result.token_count, 3);
    }

    #[test]
    fn scalar_source_too_large() {
        let config = LexerConfig {
            max_source_bytes: 5,
            ..default_config()
        };
        let err = ScalarLexer::lex(b"hello world", &config).unwrap_err();
        assert!(matches!(err, LexerError::SourceTooLarge { .. }));
    }

    // --- SWAR lexer ---

    #[test]
    fn swar_falls_back_on_small_input() {
        let config = LexerConfig {
            swar_min_input_bytes: 64,
            ..default_config()
        };
        let result = SwarLexer::lex(b"hello", &config).unwrap();
        assert!(result.swar_disable_reason.is_some());
        assert!(matches!(
            result.swar_disable_reason,
            Some(SwarDisableReason::InputBelowThreshold { .. })
        ));
    }

    #[test]
    fn swar_processes_large_whitespace_block() {
        let input = " ".repeat(256) + "hello";
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.actual_mode, LexerMode::Swar);
    }

    #[test]
    fn swar_long_identifier() {
        let input = "a".repeat(200);
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[0].start, 0);
        assert_eq!(result.tokens[0].end, 200);
    }

    #[test]
    fn swar_long_number() {
        let input = "1".repeat(200);
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::NumericLiteral);
    }

    #[test]
    fn swar_long_string() {
        let input = format!("\"{}\"", "x".repeat(200));
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn swar_mixed_tokens_large_input() {
        // Build an input > 64 bytes with mixed token types
        let input = "function foo(x, y) { return x + y * 123; } var bar = \"hello world\"; if (a == b && c != d) { console.log(42); }";
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let swar_result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        let scalar_result = ScalarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(swar_result.token_count, scalar_result.token_count);
    }

    // --- Differential lexer ---

    #[test]
    fn differential_parity_on_simple_input() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = "var x = 42; function foo() { return x + 1; }";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert!(result.mismatch.is_none());
    }

    #[test]
    fn differential_parity_on_operators() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = "a == b && c != d || e <= f >= g ?? h => i";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(
            result.swar_output.token_count,
            result.scalar_output.token_count
        );
    }

    #[test]
    fn differential_parity_on_strings_with_escapes() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = r#"var s = "hello \"world\""; var t = 'it\'s';"#;
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    #[test]
    fn differential_parity_on_large_whitespace() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = format!(
            "{}a{}b{}c",
            " ".repeat(100),
            "\t".repeat(50),
            "\n".repeat(30)
        );
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(result.swar_output.token_count, 3);
    }

    #[test]
    fn differential_parity_on_unterminated_strings() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = "\"hello\nworld\"";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    #[test]
    fn differential_parity_on_empty() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let result = DifferentialLexer::lex(b"", &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(result.swar_output.token_count, 0);
    }

    #[test]
    fn differential_parity_on_long_identifiers() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = format!(
            "{} + {} + {}",
            "a".repeat(100),
            "b".repeat(100),
            "c".repeat(100)
        );
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(result.swar_output.token_count, 5); // 3 idents + 2 punctuation
    }

    #[test]
    fn differential_parity_on_adversarial_unicode() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        // Multi-byte UTF-8 treated as individual non-ASCII bytes
        let input = "var x = \u{00e9}\u{00f1}\u{00fc};";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    // --- Public API ---

    #[test]
    fn lex_with_scalar_mode() {
        let output = lex("hello world", &scalar_config()).unwrap();
        assert_eq!(output.token_count, 2);
        assert_eq!(output.actual_mode, LexerMode::Scalar);
    }

    #[test]
    fn lex_with_swar_mode() {
        let config = LexerConfig {
            mode: LexerMode::Swar,
            swar_min_input_bytes: 0,
            ..Default::default()
        };
        let output = lex("hello world", &config).unwrap();
        assert_eq!(output.token_count, 2);
        assert_eq!(output.actual_mode, LexerMode::Swar);
    }

    #[test]
    fn lex_differential_returns_swar_on_parity() {
        let output = lex(
            "var x = 42;",
            &LexerConfig {
                mode: LexerMode::Differential,
                swar_min_input_bytes: 0,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(output.actual_mode, LexerMode::Swar);
    }

    #[test]
    fn count_tokens_matches_scalar() {
        let input = "var x = foo(1, 2, 3); if (a == b) { return; }";
        let count = count_tokens(input, &scalar_config()).unwrap();
        let output = lex(input, &scalar_config()).unwrap();
        assert_eq!(count, output.token_count);
    }

    // --- Architecture ---

    #[test]
    fn arch_profile_detects_swar_support() {
        let profile = ArchCapabilityProfile::detect();
        assert_eq!(profile.swar_width, 8);
        assert!(profile.swar_available);
    }

    // --- Throughput ---

    #[test]
    fn throughput_sample_computes_correctly() {
        let sample = ThroughputSample::compute(LexerMode::Swar, 1000, 50, 1_000_000);
        // 1000 bytes in 1ms = 1_000_000_000 bytes/sec → * 1_000_000 for fixed-point
        assert!(sample.bytes_per_second_millionths > 0);
        assert!(sample.tokens_per_second_millionths > 0);
    }

    #[test]
    fn throughput_sample_zero_time() {
        let sample = ThroughputSample::compute(LexerMode::Scalar, 1000, 50, 0);
        assert_eq!(sample.bytes_per_second_millionths, 0);
        assert_eq!(sample.tokens_per_second_millionths, 0);
    }

    #[test]
    fn throughput_comparison_speedup() {
        let swar = ThroughputSample {
            mode: LexerMode::Swar,
            input_bytes: 1000,
            token_count: 50,
            wall_time_ns: 100_000,
            bytes_per_second_millionths: 10_000_000_000,
            tokens_per_second_millionths: 500_000_000,
        };
        let scalar = ThroughputSample {
            mode: LexerMode::Scalar,
            input_bytes: 1000,
            token_count: 50,
            wall_time_ns: 300_000,
            bytes_per_second_millionths: 3_333_333_333,
            tokens_per_second_millionths: 166_666_666,
        };
        let comparison = ThroughputComparison::compute(swar, scalar);
        // 10B / 3.33B ≈ 3x
        assert!(comparison.speedup_millionths > 2_000_000);
    }

    // --- Rollback gate ---

    #[test]
    fn rollback_gate_approves_clean_run() {
        let result = evaluate_rollback_gate(0, 2_000_000, 0, &RollbackGateConfig::default());
        assert!(result.swar_approved);
        assert!(result.disable_reasons.is_empty());
    }

    #[test]
    fn rollback_gate_rejects_parity_mismatch() {
        let result = evaluate_rollback_gate(1, 2_000_000, 0, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
        assert_eq!(result.disable_reasons.len(), 1);
    }

    #[test]
    fn rollback_gate_rejects_low_speedup() {
        let result = evaluate_rollback_gate(0, 500_000, 0, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
    }

    #[test]
    fn rollback_gate_rejects_p99_regression() {
        let result = evaluate_rollback_gate(0, 2_000_000, 600_000, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
    }

    #[test]
    fn rollback_gate_multiple_failures() {
        let result = evaluate_rollback_gate(5, 100_000, 900_000, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
        assert_eq!(result.disable_reasons.len(), 3);
    }

    // --- Serde ---

    #[test]
    fn token_kind_serde_round_trip() {
        let kinds = vec![
            TokenKind::Identifier,
            TokenKind::NumericLiteral,
            TokenKind::StringLiteral,
            TokenKind::UnterminatedString,
            TokenKind::TwoCharOperator,
            TokenKind::Punctuation,
        ];
        let json = serde_json::to_string(&kinds).unwrap();
        let back: Vec<TokenKind> = serde_json::from_str(&json).unwrap();
        assert_eq!(kinds, back);
    }

    #[test]
    fn lexer_output_serde_round_trip() {
        let output = lex("var x = 42;", &scalar_config()).unwrap();
        let json = serde_json::to_string(&output).unwrap();
        let back: LexerOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    #[test]
    fn lexer_config_serde_round_trip() {
        let config = LexerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: LexerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn differential_result_serde_round_trip() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let result = DifferentialLexer::lex(b"a + b", &config).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: DifferentialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // --- Display ---

    #[test]
    fn token_kind_display() {
        assert_eq!(TokenKind::Identifier.to_string(), "Identifier");
        assert_eq!(TokenKind::NumericLiteral.to_string(), "NumericLiteral");
        assert_eq!(TokenKind::StringLiteral.to_string(), "StringLiteral");
        assert_eq!(
            TokenKind::UnterminatedString.to_string(),
            "UnterminatedString"
        );
        assert_eq!(TokenKind::TwoCharOperator.to_string(), "TwoCharOperator");
        assert_eq!(TokenKind::Punctuation.to_string(), "Punctuation");
    }

    #[test]
    fn lexer_mode_display() {
        assert_eq!(LexerMode::Swar.to_string(), "SWAR");
        assert_eq!(LexerMode::Scalar.to_string(), "Scalar");
        assert_eq!(LexerMode::Differential.to_string(), "Differential");
    }

    #[test]
    fn swar_disable_reason_display() {
        assert_eq!(
            SwarDisableReason::OperatorOverride.to_string(),
            "operator_override"
        );
        assert_eq!(
            SwarDisableReason::ParityMismatch { mismatch_index: 42 }.to_string(),
            "parity_mismatch(index=42)"
        );
        assert_eq!(
            SwarDisableReason::InputBelowThreshold {
                input_len: 10,
                threshold: 64
            }
            .to_string(),
            "input_below_threshold(len=10, threshold=64)"
        );
        assert_eq!(
            SwarDisableReason::TokenBudgetExceeded.to_string(),
            "token_budget_exceeded"
        );
    }

    #[test]
    fn lexer_error_display() {
        assert_eq!(
            LexerError::SourceTooLarge {
                size: 200,
                max: 100
            }
            .to_string(),
            "source too large: 200 bytes (max 100)"
        );
        assert_eq!(
            LexerError::TokenBudgetExceeded {
                count: 500,
                max: 100
            }
            .to_string(),
            "token budget exceeded: 500 tokens (max 100)"
        );
    }

    // --- Determinism ---

    #[test]
    fn scalar_output_is_deterministic() {
        let input = "var x = foo(1, 2, 3); if (a == b) { return 'hello'; }";
        let out1 = lex(input, &scalar_config()).unwrap();
        let out2 = lex(input, &scalar_config()).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn swar_output_is_deterministic() {
        let config = LexerConfig {
            mode: LexerMode::Swar,
            swar_min_input_bytes: 0,
            ..Default::default()
        };
        let input = "var x = foo(1, 2, 3); if (a == b) { return 'hello'; }";
        let out1 = lex(input, &config).unwrap();
        let out2 = lex(input, &config).unwrap();
        assert_eq!(out1, out2);
    }

    // --- Token span properties ---

    #[test]
    fn token_span_len() {
        let token = Token {
            kind: TokenKind::Identifier,
            start: 5,
            end: 10,
        };
        assert_eq!(token.span_len(), 5);
    }

    #[test]
    fn token_source_span() {
        let token = Token {
            kind: TokenKind::Identifier,
            start: 5,
            end: 10,
        };
        let span = token.source_span(1, 5);
        assert_eq!(span.start_offset, 5);
        assert_eq!(span.end_offset, 10);
        assert_eq!(span.start_line, 1);
        assert_eq!(span.end_line, 1);
    }

    // --- Parity mismatch display ---

    #[test]
    fn parity_mismatch_display() {
        let m = ParityMismatch {
            token_index: 3,
            swar_token: None,
            scalar_token: None,
            swar_count: 10,
            scalar_count: 11,
        };
        assert_eq!(
            m.to_string(),
            "parity mismatch at token 3: swar_count=10, scalar_count=11"
        );
    }

    // --- Stress: long mixed input ---

    #[test]
    fn differential_parity_stress_long_mixed() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            max_tokens: 100_000,
            ..default_config()
        };
        // Build a long input with diverse tokens
        let mut input = String::new();
        for i in 0u64..200 {
            input.push_str(&format!("var x{} = {}; ", i, i));
            if i.is_multiple_of(5) {
                input.push_str(&format!("\"string{}\" ", i));
            }
            if i.is_multiple_of(7) {
                input.push_str("== != && || ");
            }
        }
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok, "parity mismatch: {:?}", result.mismatch);
    }

    // --- Stress: only whitespace ---

    #[test]
    fn swar_all_whitespace_large() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = " ".repeat(1024);
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 0);
        assert_eq!(result.bytes_scanned, 1024);
    }

    // --- Stress: dense punctuation ---

    #[test]
    fn differential_parity_dense_punctuation() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            max_tokens: 100_000,
            ..default_config()
        };
        let input = "+-*/(){}[];,.:<>!@#%^~".repeat(20);
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    // --- Artifact ---

    #[test]
    fn lexer_artifact_serde_round_trip() {
        let output = lex("x + y", &scalar_config()).unwrap();
        let artifact = LexerArtifact {
            artifact_id: crate::engine_object_id::derive_id(
                crate::engine_object_id::ObjectDomain::EvidenceRecord,
                "simd-lexer-test",
                &crate::engine_object_id::SchemaId::from_definition(b"test-artifact"),
                b"test-artifact",
            )
            .unwrap(),
            config: scalar_config(),
            output,
            input_hash: "abc123".to_string(),
            input_len: 5,
            schema_version: LexerSchemaVersion::V1,
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: LexerArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn token_kind_ord() {
        assert!(TokenKind::Identifier < TokenKind::NumericLiteral);
        assert!(TokenKind::NumericLiteral < TokenKind::StringLiteral);
        assert!(TokenKind::StringLiteral < TokenKind::UnterminatedString);
        assert!(TokenKind::TwoCharOperator < TokenKind::Punctuation);
    }

    #[test]
    fn lexer_mode_ord() {
        assert!(LexerMode::Swar < LexerMode::Scalar);
        assert!(LexerMode::Scalar < LexerMode::Differential);
    }
}
