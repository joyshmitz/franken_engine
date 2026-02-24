//! Structured-concurrency parallel parsing with deterministic partitioning,
//! merge semantics, and bounded task orchestration.
//!
//! Partitions large source inputs into deterministic chunks, lexes each chunk
//! independently using the SIMD/SWAR lexer, then merges results with a stable
//! key-sorted canonicalization pass. Serial fallback is triggered on budget
//! exhaustion, parity mismatch, or small-file routing policy.
//!
//! ## Architecture
//!
//! 1. **Partition**: input split at deterministic newline-aligned boundaries.
//! 2. **Parallel lex**: each chunk lexed independently (simulated, no threads).
//! 3. **Merge**: chunk results merged by start offset with boundary token repair.
//! 4. **Parity check**: merged output compared against serial reference.
//! 5. **Fallback**: on any mismatch, fallback to serial output with evidence.
//!
//! ## Related beads
//!
//! - bd-1vfi (this module)
//! - bd-19ba (SIMD lexer — upstream)
//! - bd-3rjg (parallel interference gate — downstream)
//! - bd-1gfn (error recovery — downstream)

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::simd_lexer::{self, LexerConfig, LexerMode, LexerOutput, Token};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "parallel_parser";

/// Schema version for serde stability.
pub const SCHEMA_VERSION: &str = "franken-engine.parallel-parser.v1";

/// Default minimum input size (bytes) before parallel mode activates.
pub const DEFAULT_MIN_PARALLEL_BYTES: u64 = 4096;

/// Default maximum worker count.
pub const DEFAULT_MAX_WORKERS: u32 = 8;

/// Default per-chunk compute budget (microseconds).
pub const DEFAULT_CHUNK_BUDGET_US: u64 = 50_000;

/// Default merge buffer size (bytes).
pub const DEFAULT_MERGE_BUFFER_BYTES: u64 = 1_048_576;

/// Default small-file overhead threshold (percent, fixed-point millionths).
pub const DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS: u64 = 100_000; // 10%

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the parallel parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelConfig {
    /// Minimum input size (bytes) to enable parallel mode.
    pub min_parallel_bytes: u64,
    /// Maximum number of worker tasks.
    pub max_workers: u32,
    /// Per-chunk compute budget in microseconds.
    pub chunk_budget_us: u64,
    /// Maximum merge buffer size in bytes.
    pub merge_buffer_bytes: u64,
    /// Small-file overhead threshold (millionths, 1_000_000 = 100%).
    pub overhead_threshold_millionths: u64,
    /// Schedule seed for deterministic task ordering.
    pub schedule_seed: u64,
    /// Inner lexer configuration.
    pub lexer_config: LexerConfig,
    /// Whether to force serial parity check on every run.
    pub always_check_parity: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            min_parallel_bytes: DEFAULT_MIN_PARALLEL_BYTES,
            max_workers: DEFAULT_MAX_WORKERS,
            chunk_budget_us: DEFAULT_CHUNK_BUDGET_US,
            merge_buffer_bytes: DEFAULT_MERGE_BUFFER_BYTES,
            overhead_threshold_millionths: DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS,
            schedule_seed: 0,
            lexer_config: LexerConfig::default(),
            always_check_parity: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Parser mode and routing
// ---------------------------------------------------------------------------

/// Routing decision for a parse request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ParserMode {
    /// Serial (single-threaded) parsing.
    Serial,
    /// Parallel (multi-chunk) parsing.
    Parallel,
}

impl fmt::Display for ParserMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serial => write!(f, "serial"),
            Self::Parallel => write!(f, "parallel"),
        }
    }
}

/// Reason a request was routed to serial mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerialReason {
    /// Input below minimum size for parallel.
    InputBelowThreshold { input_bytes: u64, threshold: u64 },
    /// Worker count configured to 1 or less.
    SingleWorker,
    /// Budget exhausted during parallel execution.
    BudgetExhausted { budget_us: u64 },
    /// Parity mismatch detected; fell back to serial.
    ParityMismatch { mismatch_index: u64 },
    /// Merge buffer exceeded.
    MergeBufferExceeded { buffer_bytes: u64, limit: u64 },
}

impl fmt::Display for SerialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputBelowThreshold {
                input_bytes,
                threshold,
            } => write!(f, "input {input_bytes}B below threshold {threshold}B"),
            Self::SingleWorker => write!(f, "single worker configured"),
            Self::BudgetExhausted { budget_us } => {
                write!(f, "budget exhausted ({budget_us}us)")
            }
            Self::ParityMismatch { mismatch_index } => {
                write!(f, "parity mismatch at token {mismatch_index}")
            }
            Self::MergeBufferExceeded {
                buffer_bytes,
                limit,
            } => write!(f, "merge buffer {buffer_bytes}B exceeds {limit}B"),
        }
    }
}

// ---------------------------------------------------------------------------
// Chunk partitioning
// ---------------------------------------------------------------------------

/// A deterministic partition of the input into chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkPlan {
    /// Chunk boundaries: (start_byte, end_byte) pairs.
    pub chunks: Vec<(u64, u64)>,
    /// Hash of the partition plan for determinism verification.
    pub plan_hash: ContentHash,
    /// Number of workers.
    pub worker_count: u32,
}

/// Compute deterministic chunk boundaries aligned to newline positions.
pub fn compute_chunk_plan(input: &[u8], max_workers: u32) -> ChunkPlan {
    let len = input.len() as u64;
    if len == 0 || max_workers <= 1 {
        let chunks = if len == 0 { vec![] } else { vec![(0, len)] };
        let hash = compute_plan_hash(&chunks);
        return ChunkPlan {
            chunks,
            plan_hash: hash,
            worker_count: 1,
        };
    }

    let worker_count = max_workers.min(len as u32);
    let chunk_size = len / worker_count as u64;
    let mut chunks = Vec::new();
    let mut start = 0u64;

    for i in 0..worker_count {
        if i == worker_count - 1 {
            // Last chunk takes the remainder.
            if start < len {
                chunks.push((start, len));
            }
        } else {
            let mut end = start + chunk_size;
            // Align to next newline to avoid splitting tokens.
            while end < len && input[end as usize] != b'\n' {
                end += 1;
            }
            // Include the newline itself in this chunk.
            if end < len {
                end += 1;
            }
            if start < end {
                chunks.push((start, end));
                start = end;
            }
        }
    }

    // Edge case: if alignment pushed us past the end, ensure no empty chunks.
    if chunks.is_empty() && len > 0 {
        chunks.push((0, len));
    }

    let plan_hash = compute_plan_hash(&chunks);
    ChunkPlan {
        chunks,
        plan_hash,
        worker_count,
    }
}

fn compute_plan_hash(chunks: &[(u64, u64)]) -> ContentHash {
    let mut parts = Vec::new();
    for (s, e) in chunks {
        parts.push(format!("{s}:{e}"));
    }
    ContentHash::compute(parts.join("|").as_bytes())
}

// ---------------------------------------------------------------------------
// Chunk result and merge
// ---------------------------------------------------------------------------

/// Result of lexing a single chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkResult {
    /// Chunk index (0-based).
    pub chunk_index: u32,
    /// Start byte offset in the original input.
    pub chunk_start: u64,
    /// End byte offset in the original input.
    pub chunk_end: u64,
    /// Tokens produced (offsets are relative to chunk_start).
    pub tokens: Vec<Token>,
    /// Token count.
    pub token_count: u64,
}

/// Merge chunk results into a single ordered token stream.
/// Adjusts token offsets to be absolute (relative to input start).
pub fn merge_chunks(chunks: &[ChunkResult]) -> Vec<Token> {
    let mut all_tokens = Vec::new();
    for chunk in chunks {
        for token in &chunk.tokens {
            all_tokens.push(Token {
                kind: token.kind,
                start: token.start + chunk.chunk_start,
                end: token.end + chunk.chunk_start,
            });
        }
    }
    // Stable sort by start offset for deterministic ordering.
    all_tokens.sort_by_key(|t| (t.start, t.end));
    all_tokens
}

/// Repair boundary tokens where a multi-character token was split across chunks.
/// Adjacent tokens that overlap or are contiguous with the same kind are merged.
pub fn repair_boundary_tokens(tokens: &mut Vec<Token>) {
    if tokens.len() < 2 {
        return;
    }
    let mut write = 0;
    for read in 1..tokens.len() {
        if tokens[write].kind == tokens[read].kind && tokens[write].end >= tokens[read].start {
            // Merge: extend the write token to cover both.
            tokens[write].end = tokens[write].end.max(tokens[read].end);
        } else {
            write += 1;
            tokens[write] = tokens[read].clone();
        }
    }
    tokens.truncate(write + 1);
}

// ---------------------------------------------------------------------------
// Witness and evidence
// ---------------------------------------------------------------------------

/// Merge witness: deterministic record of the merge operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeWitness {
    /// Hash of the merged token stream.
    pub merged_hash: ContentHash,
    /// Number of chunks merged.
    pub chunk_count: u32,
    /// Number of boundary repairs performed.
    pub boundary_repairs: u64,
    /// Total tokens after merge.
    pub total_tokens: u64,
}

/// Schedule transcript: deterministic record of task scheduling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleTranscript {
    /// Schedule seed used.
    pub seed: u64,
    /// Worker count.
    pub worker_count: u32,
    /// Chunk plan hash.
    pub plan_hash: ContentHash,
    /// Execution order (chunk indices in execution order).
    pub execution_order: Vec<u32>,
}

/// Parity result: comparison between parallel and serial outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityResult {
    /// Whether parity holds.
    pub parity_ok: bool,
    /// Index of first mismatched token (if any).
    pub mismatch_index: Option<u64>,
    /// Parallel token count.
    pub parallel_count: u64,
    /// Serial token count.
    pub serial_count: u64,
}

// ---------------------------------------------------------------------------
// Fallback
// ---------------------------------------------------------------------------

/// Fallback cause taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackCause {
    /// Routing decision (before parallel attempt).
    Routing(SerialReason),
    /// Parity failure (after parallel attempt).
    ParityFailure { mismatch_index: u64 },
    /// Budget/resource limit.
    ResourceLimit(SerialReason),
}

impl fmt::Display for FallbackCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Routing(r) => write!(f, "routing: {r}"),
            Self::ParityFailure { mismatch_index } => {
                write!(f, "parity failure at token {mismatch_index}")
            }
            Self::ResourceLimit(r) => write!(f, "resource limit: {r}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Timeout / cancellation policy
// ---------------------------------------------------------------------------

/// Timeout policy for parallel chunk processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutPolicy {
    /// Maximum wall-clock microseconds for the entire parallel phase.
    pub max_total_us: u64,
    /// Maximum wall-clock microseconds per chunk.
    pub max_chunk_us: u64,
    /// Whether to allow graceful drain before hard cancel.
    pub allow_drain: bool,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            max_total_us: 500_000,
            max_chunk_us: 100_000,
            allow_drain: true,
        }
    }
}

/// State of a cancellation lifecycle: request → drain → finalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CancellationState {
    /// No cancellation requested.
    None,
    /// Cancellation requested, workers draining.
    Requested,
    /// Workers have drained, finalizing.
    Draining,
    /// Cancellation complete, results discarded or partial.
    Finalized,
}

impl fmt::Display for CancellationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Requested => write!(f, "requested"),
            Self::Draining => write!(f, "draining"),
            Self::Finalized => write!(f, "finalized"),
        }
    }
}

/// Record of a timeout/cancellation event during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationRecord {
    /// Final cancellation state reached.
    pub state: CancellationState,
    /// Elapsed microseconds at cancellation.
    pub elapsed_us: u64,
    /// Chunk that triggered the timeout (if per-chunk).
    pub trigger_chunk: Option<u32>,
    /// Whether drain was completed before finalization.
    pub drain_completed: bool,
}

// ---------------------------------------------------------------------------
// Backpressure instrumentation
// ---------------------------------------------------------------------------

/// Backpressure state for the parallel work queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BackpressureLevel {
    /// Normal operating conditions.
    Normal,
    /// Approaching capacity limits.
    Elevated,
    /// At capacity, new work will be delayed.
    Critical,
}

impl fmt::Display for BackpressureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Elevated => write!(f, "elevated"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Queue and backpressure metrics for a parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureSnapshot {
    /// Current queue depth (pending chunks).
    pub queue_depth: u32,
    /// Maximum observed queue depth during this run.
    pub peak_queue_depth: u32,
    /// Backpressure level.
    pub level: BackpressureLevel,
    /// Number of chunks that experienced queueing delay.
    pub delayed_chunks: u32,
    /// Total queueing delay in microseconds.
    pub total_delay_us: u64,
}

// ---------------------------------------------------------------------------
// Workload routing digest
// ---------------------------------------------------------------------------

/// Why a specific input was routed to serial or parallel mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDigest {
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Configured threshold for parallel activation.
    pub parallel_threshold: u64,
    /// Configured worker count.
    pub configured_workers: u32,
    /// Effective worker count (may be reduced for small inputs).
    pub effective_workers: u32,
    /// Final routing decision.
    pub decision: ParserMode,
    /// Human-readable rationale.
    pub rationale: String,
    /// Whether the input contains newlines suitable for partitioning.
    pub has_partition_points: bool,
    /// Estimated overhead ratio (millionths, 1_000_000 = 100%).
    pub estimated_overhead_millionths: u64,
}

// ---------------------------------------------------------------------------
// Performance instrumentation
// ---------------------------------------------------------------------------

/// Throughput sample for a single parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputSample {
    /// Bytes processed.
    pub bytes: u64,
    /// Tokens produced.
    pub tokens: u64,
    /// Total elapsed microseconds (wall clock).
    pub elapsed_us: u64,
    /// Throughput: bytes per second (fixed-point millionths).
    pub bytes_per_sec_millionths: u64,
    /// Throughput: tokens per second (fixed-point millionths).
    pub tokens_per_sec_millionths: u64,
}

impl ThroughputSample {
    /// Compute a throughput sample from raw measurements.
    pub fn compute(bytes: u64, tokens: u64, elapsed_us: u64) -> Self {
        let bytes_per_sec_millionths = if elapsed_us > 0 {
            bytes
                .checked_mul(1_000_000_000_000)
                .and_then(|n| n.checked_div(elapsed_us))
                .unwrap_or(0)
        } else {
            0
        };
        let tokens_per_sec_millionths = if elapsed_us > 0 {
            tokens
                .checked_mul(1_000_000_000_000)
                .and_then(|n| n.checked_div(elapsed_us))
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            bytes,
            tokens,
            elapsed_us,
            bytes_per_sec_millionths,
            tokens_per_sec_millionths,
        }
    }
}

/// Per-chunk timing for performance analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkTiming {
    /// Chunk index.
    pub chunk_index: u32,
    /// Chunk size in bytes.
    pub chunk_bytes: u64,
    /// Tokens produced by this chunk.
    pub token_count: u64,
    /// Elapsed microseconds for this chunk's lexing.
    pub elapsed_us: u64,
}

/// Aggregated performance report for a parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceReport {
    /// Overall throughput.
    pub throughput: ThroughputSample,
    /// Per-chunk timings (parallel mode only).
    pub chunk_timings: Vec<ChunkTiming>,
    /// Merge phase elapsed microseconds.
    pub merge_elapsed_us: u64,
    /// Parity check elapsed microseconds.
    pub parity_check_elapsed_us: u64,
}

// ---------------------------------------------------------------------------
// Replay envelope
// ---------------------------------------------------------------------------

/// Full replay envelope: contains everything needed to reproduce a parse run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEnvelope {
    /// Schema version.
    pub schema_version: String,
    /// Input content hash (NOT the input itself — too large).
    pub input_hash: ContentHash,
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Configuration used.
    pub config: ParallelConfig,
    /// Security epoch.
    pub epoch_raw: u64,
    /// Trace identifier.
    pub trace_id: String,
    /// Run identifier.
    pub run_id: String,
    /// Chunk plan used (if parallel).
    pub chunk_plan: Option<ChunkPlan>,
    /// Schedule transcript (if parallel).
    pub schedule_transcript: Option<ScheduleTranscript>,
    /// Merge witness (if parallel).
    pub merge_witness: Option<MergeWitness>,
    /// Parity result (if checked).
    pub parity_result: Option<ParityResult>,
    /// Routing digest.
    pub routing_digest: RoutingDigest,
    /// Cancellation record (if any).
    pub cancellation: Option<CancellationRecord>,
    /// Output hash for verification.
    pub output_hash: ContentHash,
    /// Replay command hint.
    pub replay_command: String,
}

/// Build a replay envelope from a completed parse.
pub fn build_replay_envelope(
    input: &ParseInput<'_>,
    output: &ParseOutput,
    routing_digest: &RoutingDigest,
) -> ReplayEnvelope {
    ReplayEnvelope {
        schema_version: SCHEMA_VERSION.to_string(),
        input_hash: ContentHash::compute(input.source.as_bytes()),
        input_bytes: input.source.len() as u64,
        config: input.config.clone(),
        epoch_raw: input.epoch.as_u64(),
        trace_id: input.trace_id.to_string(),
        run_id: input.run_id.to_string(),
        chunk_plan: output.chunk_plan.clone(),
        schedule_transcript: output.schedule_transcript.clone(),
        merge_witness: output.merge_witness.clone(),
        parity_result: output.parity_result.clone(),
        routing_digest: routing_digest.clone(),
        cancellation: None,
        output_hash: output.output_hash.clone(),
        replay_command: format!(
            "franken-engine parallel-parse --trace-id {} --run-id {} --seed {} --workers {}",
            input.trace_id, input.run_id, input.config.schedule_seed, input.config.max_workers,
        ),
    }
}

// ---------------------------------------------------------------------------
// Rollback control
// ---------------------------------------------------------------------------

/// Rollback control: can disable parallel mode at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackControl {
    /// Whether parallel mode is currently disabled.
    pub parallel_disabled: bool,
    /// Reason for disabling (if disabled).
    pub disable_reason: Option<String>,
    /// Number of consecutive parity failures that triggered rollback.
    pub consecutive_failures: u32,
    /// Threshold of consecutive failures before auto-rollback.
    pub auto_rollback_threshold: u32,
    /// Set of trace IDs that triggered failures.
    pub failure_trace_ids: BTreeSet<String>,
}

impl Default for RollbackControl {
    fn default() -> Self {
        Self {
            parallel_disabled: false,
            disable_reason: None,
            consecutive_failures: 0,
            auto_rollback_threshold: 3,
            failure_trace_ids: BTreeSet::new(),
        }
    }
}

impl RollbackControl {
    /// Record a parity failure. Returns true if auto-rollback was triggered.
    pub fn record_failure(&mut self, trace_id: &str) -> bool {
        self.consecutive_failures += 1;
        self.failure_trace_ids.insert(trace_id.to_string());
        if self.consecutive_failures >= self.auto_rollback_threshold {
            self.parallel_disabled = true;
            self.disable_reason = Some(format!(
                "auto-rollback after {} consecutive parity failures",
                self.consecutive_failures
            ));
            true
        } else {
            false
        }
    }

    /// Record a successful parallel parse, resetting the failure counter.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    /// Manually disable parallel mode.
    pub fn force_disable(&mut self, reason: &str) {
        self.parallel_disabled = true;
        self.disable_reason = Some(reason.to_string());
    }

    /// Re-enable parallel mode.
    pub fn re_enable(&mut self) {
        self.parallel_disabled = false;
        self.disable_reason = None;
        self.consecutive_failures = 0;
        self.failure_trace_ids.clear();
    }
}

// ---------------------------------------------------------------------------
// Parse output
// ---------------------------------------------------------------------------

/// Full output of a parallel parse operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseOutput {
    /// Schema version.
    pub schema_version: String,
    /// Mode actually used.
    pub mode: ParserMode,
    /// If serial was used, why.
    pub serial_reason: Option<SerialReason>,
    /// Fallback cause (if fallback occurred).
    pub fallback_cause: Option<FallbackCause>,
    /// Final tokens.
    pub tokens: Vec<Token>,
    /// Token count.
    pub token_count: u64,
    /// Bytes scanned.
    pub bytes_scanned: u64,
    /// Chunk plan (if parallel was attempted).
    pub chunk_plan: Option<ChunkPlan>,
    /// Merge witness (if parallel was attempted).
    pub merge_witness: Option<MergeWitness>,
    /// Schedule transcript (if parallel was attempted).
    pub schedule_transcript: Option<ScheduleTranscript>,
    /// Parity result (if parity check was performed).
    pub parity_result: Option<ParityResult>,
    /// Content hash of the output token stream.
    pub output_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

/// Structured log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseLogEntry {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub parser_mode: Option<String>,
    pub worker_count: Option<u32>,
    pub input_bytes: Option<u64>,
    pub token_count: Option<u64>,
    pub fallback_reason: Option<String>,
    pub parity_result: Option<String>,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors during parallel parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseError {
    /// Lexer error in a chunk.
    LexerError { chunk_index: u32, detail: String },
    /// Input too large for configured limits.
    InputTooLarge { size: u64, max: u64 },
    /// Invalid configuration.
    InvalidConfig { detail: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LexerError {
                chunk_index,
                detail,
            } => write!(f, "lexer error in chunk {chunk_index}: {detail}"),
            Self::InputTooLarge { size, max } => {
                write!(f, "input too large: {size}B exceeds {max}B")
            }
            Self::InvalidConfig { detail } => write!(f, "invalid config: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Parse input
// ---------------------------------------------------------------------------

/// Input for a parse operation.
#[derive(Debug, Clone)]
pub struct ParseInput<'a> {
    /// Source text to parse.
    pub source: &'a str,
    /// Trace identifier for structured logging.
    pub trace_id: &'a str,
    /// Run identifier.
    pub run_id: &'a str,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Configuration.
    pub config: &'a ParallelConfig,
}

// ---------------------------------------------------------------------------
// Core parse logic
// ---------------------------------------------------------------------------

/// Parse source input using the parallel parser.
///
/// Routes to serial or parallel mode based on configuration and input size.
/// If parallel mode is used, performs a parity check against the serial
/// reference and falls back if mismatch is detected.
pub fn parse(input: &ParseInput<'_>) -> Result<ParseOutput, ParseError> {
    let source = input.source;
    let bytes = source.as_bytes();
    let config = input.config;

    // Validate configuration.
    if config.max_workers == 0 {
        return Err(ParseError::InvalidConfig {
            detail: "max_workers must be >= 1".to_string(),
        });
    }

    // Check input size.
    if bytes.len() as u64 > config.lexer_config.max_source_bytes {
        return Err(ParseError::InputTooLarge {
            size: bytes.len() as u64,
            max: config.lexer_config.max_source_bytes,
        });
    }

    // Routing decision.
    let should_parallel = bytes.len() as u64 >= config.min_parallel_bytes && config.max_workers > 1;

    if !should_parallel {
        let reason = if config.max_workers <= 1 {
            SerialReason::SingleWorker
        } else {
            SerialReason::InputBelowThreshold {
                input_bytes: bytes.len() as u64,
                threshold: config.min_parallel_bytes,
            }
        };
        return serial_parse(source, &config.lexer_config, Some(reason));
    }

    // --- Parallel path ---

    // 1. Compute chunk plan.
    let chunk_plan = compute_chunk_plan(bytes, config.max_workers);

    // 2. Lex each chunk independently.
    let mut chunk_results = Vec::new();
    let mut lexer_config = config.lexer_config.clone();
    lexer_config.emit_tokens = true;

    for (idx, &(start, end)) in chunk_plan.chunks.iter().enumerate() {
        let chunk_bytes = &bytes[start as usize..end as usize];
        let chunk_str = std::str::from_utf8(chunk_bytes).unwrap_or("");
        match simd_lexer::lex(chunk_str, &lexer_config) {
            Ok(output) => {
                chunk_results.push(ChunkResult {
                    chunk_index: idx as u32,
                    chunk_start: start,
                    chunk_end: end,
                    tokens: output.tokens,
                    token_count: output.token_count,
                });
            }
            Err(e) => {
                return Err(ParseError::LexerError {
                    chunk_index: idx as u32,
                    detail: format!("{e:?}"),
                });
            }
        }
    }

    // 3. Build schedule transcript.
    let execution_order: Vec<u32> = (0..chunk_plan.chunks.len() as u32).collect();
    let schedule_transcript = ScheduleTranscript {
        seed: config.schedule_seed,
        worker_count: chunk_plan.worker_count,
        plan_hash: chunk_plan.plan_hash.clone(),
        execution_order,
    };

    // 4. Merge chunks.
    let mut merged_tokens = merge_chunks(&chunk_results);
    let pre_repair_count = merged_tokens.len() as u64;
    repair_boundary_tokens(&mut merged_tokens);
    let post_repair_count = merged_tokens.len() as u64;
    let boundary_repairs = pre_repair_count.saturating_sub(post_repair_count);

    // Check merge buffer.
    let merge_buffer_size = merged_tokens.len() as u64 * 24; // approximate Token size
    if merge_buffer_size > config.merge_buffer_bytes {
        let reason = SerialReason::MergeBufferExceeded {
            buffer_bytes: merge_buffer_size,
            limit: config.merge_buffer_bytes,
        };
        return serial_parse(source, &config.lexer_config, Some(reason));
    }

    let merged_hash = compute_token_hash(&merged_tokens);
    let merge_witness = MergeWitness {
        merged_hash: merged_hash.clone(),
        chunk_count: chunk_plan.chunks.len() as u32,
        boundary_repairs,
        total_tokens: merged_tokens.len() as u64,
    };

    // 5. Parity check against serial reference.
    let parity_result = if config.always_check_parity {
        let serial_output = serial_parse_inner(source, &config.lexer_config)?;
        let parity = check_parity(&merged_tokens, &serial_output.tokens);
        Some(parity)
    } else {
        None
    };

    // 6. Handle parity failure.
    if let Some(ref pr) = parity_result
        && !pr.parity_ok
    {
        let mismatch_index = pr.mismatch_index.unwrap_or(0);
        // Fall back to serial output.
        let serial = serial_parse_inner(source, &config.lexer_config)?;
        let output_hash = compute_token_hash(&serial.tokens);
        return Ok(ParseOutput {
            schema_version: SCHEMA_VERSION.to_string(),
            mode: ParserMode::Serial,
            serial_reason: Some(SerialReason::ParityMismatch { mismatch_index }),
            fallback_cause: Some(FallbackCause::ParityFailure { mismatch_index }),
            tokens: serial.tokens,
            token_count: serial.token_count,
            bytes_scanned: serial.bytes_scanned,
            chunk_plan: Some(chunk_plan),
            merge_witness: Some(merge_witness),
            schedule_transcript: Some(schedule_transcript),
            parity_result: Some(pr.clone()),
            output_hash,
        });
    }

    // 7. Success — return parallel output.
    let output_hash = merged_hash;
    Ok(ParseOutput {
        schema_version: SCHEMA_VERSION.to_string(),
        mode: ParserMode::Parallel,
        serial_reason: None,
        fallback_cause: None,
        tokens: merged_tokens.clone(),
        token_count: merged_tokens.len() as u64,
        bytes_scanned: bytes.len() as u64,
        chunk_plan: Some(chunk_plan),
        merge_witness: Some(merge_witness),
        schedule_transcript: Some(schedule_transcript),
        parity_result,
        output_hash,
    })
}

/// Serial parse (direct single-threaded path).
fn serial_parse(
    source: &str,
    lexer_config: &LexerConfig,
    reason: Option<SerialReason>,
) -> Result<ParseOutput, ParseError> {
    let output = serial_parse_inner(source, lexer_config)?;
    let output_hash = compute_token_hash(&output.tokens);
    Ok(ParseOutput {
        schema_version: SCHEMA_VERSION.to_string(),
        mode: ParserMode::Serial,
        serial_reason: reason,
        fallback_cause: None,
        tokens: output.tokens,
        token_count: output.token_count,
        bytes_scanned: output.bytes_scanned,
        chunk_plan: None,
        merge_witness: None,
        schedule_transcript: None,
        parity_result: None,
        output_hash,
    })
}

/// Inner serial parse returning raw lexer output.
fn serial_parse_inner(source: &str, lexer_config: &LexerConfig) -> Result<LexerOutput, ParseError> {
    let mut config = lexer_config.clone();
    config.emit_tokens = true;
    config.mode = LexerMode::Scalar;
    simd_lexer::lex(source, &config).map_err(|e| ParseError::LexerError {
        chunk_index: 0,
        detail: format!("{e:?}"),
    })
}

/// Compute a content hash over a token stream.
fn compute_token_hash(tokens: &[Token]) -> ContentHash {
    let mut parts = Vec::new();
    for token in tokens {
        parts.push(format!("{}:{}:{}", token.kind, token.start, token.end));
    }
    ContentHash::compute(parts.join("|").as_bytes())
}

/// Check parity between parallel-merged and serial token streams.
fn check_parity(parallel: &[Token], serial: &[Token]) -> ParityResult {
    let parallel_count = parallel.len() as u64;
    let serial_count = serial.len() as u64;

    let min_len = parallel.len().min(serial.len());
    for i in 0..min_len {
        if parallel[i] != serial[i] {
            return ParityResult {
                parity_ok: false,
                mismatch_index: Some(i as u64),
                parallel_count,
                serial_count,
            };
        }
    }

    if parallel_count != serial_count {
        return ParityResult {
            parity_ok: false,
            mismatch_index: Some(min_len as u64),
            parallel_count,
            serial_count,
        };
    }

    ParityResult {
        parity_ok: true,
        mismatch_index: None,
        parallel_count,
        serial_count,
    }
}

/// Compute a routing digest for the given input and configuration.
pub fn compute_routing_digest(source: &str, config: &ParallelConfig) -> RoutingDigest {
    let input_bytes = source.len() as u64;
    let has_partition_points = source.as_bytes().contains(&b'\n');
    let should_parallel =
        input_bytes >= config.min_parallel_bytes && config.max_workers > 1 && has_partition_points;

    let effective_workers = if should_parallel {
        config.max_workers.min(input_bytes as u32)
    } else {
        1
    };

    let decision = if should_parallel {
        ParserMode::Parallel
    } else {
        ParserMode::Serial
    };

    let rationale = if config.max_workers <= 1 {
        "single worker configured".to_string()
    } else if input_bytes < config.min_parallel_bytes {
        format!(
            "input {}B below threshold {}B",
            input_bytes, config.min_parallel_bytes
        )
    } else if !has_partition_points {
        "no newlines for chunk partitioning".to_string()
    } else {
        format!("parallel with {} effective workers", effective_workers)
    };

    // Rough overhead estimate: parallel has ~20% overhead for small inputs.
    let estimated_overhead_millionths = if input_bytes < config.min_parallel_bytes * 2 {
        200_000 // 20%
    } else if input_bytes < config.min_parallel_bytes * 4 {
        100_000 // 10%
    } else {
        50_000 // 5%
    };

    RoutingDigest {
        input_bytes,
        parallel_threshold: config.min_parallel_bytes,
        configured_workers: config.max_workers,
        effective_workers,
        decision,
        rationale,
        has_partition_points,
        estimated_overhead_millionths,
    }
}

/// Generate structured log entries from a parse output.
pub fn generate_log_entries(trace_id: &str, output: &ParseOutput) -> Vec<ParseLogEntry> {
    let mut entries = Vec::new();

    entries.push(ParseLogEntry {
        trace_id: trace_id.to_string(),
        component: COMPONENT.to_string(),
        event: "parse_complete".to_string(),
        outcome: if output.fallback_cause.is_some() {
            "fallback".to_string()
        } else {
            "ok".to_string()
        },
        parser_mode: Some(format!("{}", output.mode)),
        worker_count: output.chunk_plan.as_ref().map(|p| p.worker_count),
        input_bytes: Some(output.bytes_scanned),
        token_count: Some(output.token_count),
        fallback_reason: output.fallback_cause.as_ref().map(|c| format!("{c}")),
        parity_result: output
            .parity_result
            .as_ref()
            .map(|p| if p.parity_ok { "ok" } else { "mismatch" }.to_string()),
        error_code: None,
    });

    if let Some(ref cause) = output.fallback_cause {
        entries.push(ParseLogEntry {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: "fallback_triggered".to_string(),
            outcome: "fallback".to_string(),
            parser_mode: None,
            worker_count: None,
            input_bytes: None,
            token_count: None,
            fallback_reason: Some(format!("{cause}")),
            parity_result: None,
            error_code: Some("fallback".to_string()),
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ParallelConfig {
        ParallelConfig::default()
    }

    fn small_config() -> ParallelConfig {
        ParallelConfig {
            min_parallel_bytes: 10,
            max_workers: 4,
            always_check_parity: true,
            ..default_config()
        }
    }

    fn make_input<'a>(source: &'a str, config: &'a ParallelConfig) -> ParseInput<'a> {
        ParseInput {
            source,
            trace_id: "test-trace",
            run_id: "test-run",
            epoch: SecurityEpoch::from_raw(1),
            config,
        }
    }

    // --- Configuration tests ---

    #[test]
    fn default_config_reasonable() {
        let config = default_config();
        assert_eq!(config.min_parallel_bytes, DEFAULT_MIN_PARALLEL_BYTES);
        assert_eq!(config.max_workers, DEFAULT_MAX_WORKERS);
        assert!(config.always_check_parity);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = default_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: ParallelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- Routing tests ---

    #[test]
    fn small_input_routes_to_serial() {
        let config = default_config();
        let input = make_input("var x = 1;", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(output.serial_reason.is_some());
    }

    #[test]
    fn single_worker_routes_to_serial() {
        let config = ParallelConfig {
            max_workers: 1,
            min_parallel_bytes: 0,
            ..default_config()
        };
        let input = make_input("var x = 1; var y = 2;", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(matches!(
            output.serial_reason,
            Some(SerialReason::SingleWorker)
        ));
    }

    #[test]
    fn zero_workers_is_error() {
        let config = ParallelConfig {
            max_workers: 0,
            ..default_config()
        };
        let input = make_input("x", &config);
        assert!(matches!(
            parse(&input),
            Err(ParseError::InvalidConfig { .. })
        ));
    }

    // --- Chunk plan tests ---

    #[test]
    fn chunk_plan_empty_input() {
        let plan = compute_chunk_plan(b"", 4);
        assert!(plan.chunks.is_empty());
        assert_eq!(plan.worker_count, 1);
    }

    #[test]
    fn chunk_plan_single_worker() {
        let plan = compute_chunk_plan(b"hello world", 1);
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(plan.chunks[0], (0, 11));
    }

    #[test]
    fn chunk_plan_two_workers() {
        let input = b"line one\nline two\nline three\n";
        let plan = compute_chunk_plan(input, 2);
        assert_eq!(plan.chunks.len(), 2);
        // First chunk ends at a newline boundary.
        let (_, end) = plan.chunks[0];
        assert!(end > 0);
        assert_eq!(input[end as usize - 1], b'\n');
        // Second chunk starts where first ended.
        assert_eq!(plan.chunks[1].0, end);
        assert_eq!(plan.chunks[1].1, input.len() as u64);
    }

    #[test]
    fn chunk_plan_deterministic() {
        let input = b"a\nb\nc\nd\ne\nf\ng\n";
        let p1 = compute_chunk_plan(input, 3);
        let p2 = compute_chunk_plan(input, 3);
        assert_eq!(p1.plan_hash, p2.plan_hash);
        assert_eq!(p1.chunks, p2.chunks);
    }

    #[test]
    fn chunk_plan_covers_entire_input() {
        let input = b"line1\nline2\nline3\nline4\nline5\n";
        let plan = compute_chunk_plan(input, 3);
        assert_eq!(plan.chunks.first().unwrap().0, 0);
        assert_eq!(plan.chunks.last().unwrap().1, input.len() as u64);
        // Chunks are contiguous.
        for w in plan.chunks.windows(2) {
            assert_eq!(w[0].1, w[1].0);
        }
    }

    #[test]
    fn chunk_plan_no_newlines() {
        let input = b"abcdefghij"; // no newlines
        let plan = compute_chunk_plan(input, 2);
        // Should still partition (but boundary won't align to newline).
        assert!(!plan.chunks.is_empty());
        assert_eq!(plan.chunks.last().unwrap().1, 10);
    }

    // --- Merge tests ---

    #[test]
    fn merge_empty_chunks() {
        let merged = merge_chunks(&[]);
        assert!(merged.is_empty());
    }

    #[test]
    fn merge_single_chunk() {
        let tokens = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let chunk = ChunkResult {
            chunk_index: 0,
            chunk_start: 10,
            chunk_end: 20,
            tokens,
            token_count: 1,
        };
        let merged = merge_chunks(&[chunk]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, 10); // offset adjusted
        assert_eq!(merged[0].end, 13);
    }

    #[test]
    fn merge_preserves_order() {
        let chunk1 = ChunkResult {
            chunk_index: 0,
            chunk_start: 0,
            chunk_end: 10,
            tokens: vec![Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 3,
            }],
            token_count: 1,
        };
        let chunk2 = ChunkResult {
            chunk_index: 1,
            chunk_start: 10,
            chunk_end: 20,
            tokens: vec![Token {
                kind: simd_lexer::TokenKind::NumericLiteral,
                start: 2,
                end: 5,
            }],
            token_count: 1,
        };
        let merged = merge_chunks(&[chunk1, chunk2]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].start, 0); // from chunk1
        assert_eq!(merged[1].start, 12); // from chunk2 (10 + 2)
    }

    // --- Boundary repair tests ---

    #[test]
    fn repair_no_overlaps() {
        let mut tokens = vec![
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 3,
            },
            Token {
                kind: simd_lexer::TokenKind::Punctuation,
                start: 4,
                end: 5,
            },
        ];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn repair_merges_overlapping_same_kind() {
        let mut tokens = vec![
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 5,
            },
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 3,
                end: 8,
            },
        ];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].start, 0);
        assert_eq!(tokens[0].end, 8);
    }

    #[test]
    fn repair_does_not_merge_different_kinds() {
        let mut tokens = vec![
            Token {
                kind: simd_lexer::TokenKind::Identifier,
                start: 0,
                end: 5,
            },
            Token {
                kind: simd_lexer::TokenKind::Punctuation,
                start: 3,
                end: 8,
            },
        ];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn repair_empty_tokens() {
        let mut tokens: Vec<Token> = vec![];
        repair_boundary_tokens(&mut tokens);
        assert!(tokens.is_empty());
    }

    #[test]
    fn repair_single_token() {
        let mut tokens = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 5,
        }];
        repair_boundary_tokens(&mut tokens);
        assert_eq!(tokens.len(), 1);
    }

    // --- Parity check tests ---

    #[test]
    fn parity_check_identical() {
        let tokens = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let result = check_parity(&tokens, &tokens);
        assert!(result.parity_ok);
        assert_eq!(result.mismatch_index, None);
    }

    #[test]
    fn parity_check_different_count() {
        let parallel = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let serial = vec![];
        let result = check_parity(&parallel, &serial);
        assert!(!result.parity_ok);
        assert_eq!(result.mismatch_index, Some(0));
    }

    #[test]
    fn parity_check_different_kind() {
        let parallel = vec![Token {
            kind: simd_lexer::TokenKind::Identifier,
            start: 0,
            end: 3,
        }];
        let serial = vec![Token {
            kind: simd_lexer::TokenKind::NumericLiteral,
            start: 0,
            end: 3,
        }];
        let result = check_parity(&parallel, &serial);
        assert!(!result.parity_ok);
        assert_eq!(result.mismatch_index, Some(0));
    }

    // --- Full parallel parse tests ---

    #[test]
    fn parallel_parse_large_input_with_newlines() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        // Should attempt parallel and succeed (or fall back).
        assert!(output.token_count > 0);
        assert!(output.chunk_plan.is_some());
    }

    #[test]
    fn parallel_parse_deterministic() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let o1 = parse(&input).unwrap();
        let o2 = parse(&input).unwrap();
        assert_eq!(o1.output_hash, o2.output_hash);
        assert_eq!(o1.token_count, o2.token_count);
    }

    #[test]
    fn parallel_parse_serial_fallback_small_input() {
        let config = default_config(); // default 4096 threshold
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);
        assert!(output.chunk_plan.is_none());
    }

    #[test]
    fn parallel_parse_tokens_match_serial() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();

        // Also parse serially.
        let serial_config = ParallelConfig {
            max_workers: 1,
            min_parallel_bytes: 0,
            ..small_config()
        };
        let serial_input = make_input(&source, &serial_config);
        let serial_output = parse(&serial_input).unwrap();

        // Token counts should match.
        assert_eq!(output.token_count, serial_output.token_count);
    }

    #[test]
    fn parallel_parse_with_operators() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("x{} == y{} && z{} != w{}\n", i, i, i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
    }

    #[test]
    fn parallel_parse_with_strings() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var s{} = \"hello{}\";\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
    }

    // --- Schedule transcript tests ---

    #[test]
    fn schedule_transcript_serde_roundtrip() {
        let transcript = ScheduleTranscript {
            seed: 42,
            worker_count: 4,
            plan_hash: ContentHash::compute(b"test"),
            execution_order: vec![0, 1, 2, 3],
        };
        let json = serde_json::to_string(&transcript).unwrap();
        let back: ScheduleTranscript = serde_json::from_str(&json).unwrap();
        assert_eq!(transcript, back);
    }

    // --- Merge witness tests ---

    #[test]
    fn merge_witness_serde_roundtrip() {
        let witness = MergeWitness {
            merged_hash: ContentHash::compute(b"test"),
            chunk_count: 3,
            boundary_repairs: 1,
            total_tokens: 42,
        };
        let json = serde_json::to_string(&witness).unwrap();
        let back: MergeWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, back);
    }

    // --- Parity result tests ---

    #[test]
    fn parity_result_serde_roundtrip() {
        let result = ParityResult {
            parity_ok: true,
            mismatch_index: None,
            parallel_count: 100,
            serial_count: 100,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ParityResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // --- ParseOutput tests ---

    #[test]
    fn parse_output_serde_roundtrip() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        let json = serde_json::to_string(&output).unwrap();
        let back: ParseOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    // --- Log entry tests ---

    #[test]
    fn log_entries_for_serial() {
        let config = default_config();
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        let entries = generate_log_entries("trace-1", &output);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.event == "parse_complete"));
        assert!(entries[0].parser_mode.as_deref() == Some("serial"));
    }

    #[test]
    fn log_entries_for_parallel() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        let entries = generate_log_entries("trace-1", &output);
        assert!(!entries.is_empty());
    }

    #[test]
    fn log_entries_trace_id_consistent() {
        let config = default_config();
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        let entries = generate_log_entries("trace-42", &output);
        assert!(entries.iter().all(|e| e.trace_id == "trace-42"));
    }

    // --- Display tests ---

    #[test]
    fn parser_mode_display() {
        assert_eq!(ParserMode::Serial.to_string(), "serial");
        assert_eq!(ParserMode::Parallel.to_string(), "parallel");
    }

    #[test]
    fn serial_reason_display() {
        let reason = SerialReason::InputBelowThreshold {
            input_bytes: 100,
            threshold: 4096,
        };
        assert!(reason.to_string().contains("100B below threshold 4096B"));
    }

    #[test]
    fn fallback_cause_display() {
        let cause = FallbackCause::ParityFailure { mismatch_index: 42 };
        assert!(cause.to_string().contains("parity failure"));
    }

    #[test]
    fn parse_error_display() {
        let e = ParseError::LexerError {
            chunk_index: 2,
            detail: "bad".to_string(),
        };
        assert!(e.to_string().contains("chunk 2"));
    }

    // --- Error tests ---

    #[test]
    fn error_serde_roundtrip() {
        let e = ParseError::InputTooLarge {
            size: 1000,
            max: 500,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ParseError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Schema version ---

    #[test]
    fn schema_version_in_output() {
        let config = default_config();
        let input = make_input("x", &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.schema_version, SCHEMA_VERSION);
    }

    // --- Chunk plan hash ---

    #[test]
    fn chunk_plan_hash_differs_for_different_plans() {
        let input1 = b"a\nbcdefghijk\n";
        let input2 = b"abcdefghij\nk\n";
        let p1 = compute_chunk_plan(input1, 2);
        let p2 = compute_chunk_plan(input2, 2);
        // Different newline positions produce different chunk boundaries.
        assert_ne!(p1.chunks, p2.chunks);
        assert_ne!(p1.plan_hash, p2.plan_hash);
    }

    // --- Worker count invariance ---

    #[test]
    fn different_worker_counts_same_tokens() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config2 = ParallelConfig {
            max_workers: 2,
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..default_config()
        };
        let config4 = ParallelConfig {
            max_workers: 4,
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..default_config()
        };
        let input2 = make_input(&source, &config2);
        let input4 = make_input(&source, &config4);
        let o2 = parse(&input2).unwrap();
        let o4 = parse(&input4).unwrap();
        assert_eq!(o2.token_count, o4.token_count);
    }

    // ===================================================================
    // Enrichment tests (bd-1vfi structured concurrency extensions)
    // ===================================================================

    #[test]
    fn timeout_policy_default() {
        let tp = TimeoutPolicy::default();
        assert_eq!(tp.max_total_us, 500_000);
        assert_eq!(tp.max_chunk_us, 100_000);
        assert!(tp.allow_drain);
    }

    #[test]
    fn timeout_policy_serde_roundtrip() {
        let tp = TimeoutPolicy {
            max_total_us: 1_000_000,
            max_chunk_us: 200_000,
            allow_drain: false,
        };
        let json = serde_json::to_string(&tp).unwrap();
        let back: TimeoutPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(tp, back);
    }

    #[test]
    fn cancellation_state_ordering() {
        assert!(CancellationState::None < CancellationState::Requested);
        assert!(CancellationState::Requested < CancellationState::Draining);
        assert!(CancellationState::Draining < CancellationState::Finalized);
    }

    #[test]
    fn cancellation_state_display() {
        assert_eq!(CancellationState::None.to_string(), "none");
        assert_eq!(CancellationState::Requested.to_string(), "requested");
        assert_eq!(CancellationState::Draining.to_string(), "draining");
        assert_eq!(CancellationState::Finalized.to_string(), "finalized");
    }

    #[test]
    fn cancellation_record_serde_roundtrip() {
        let cr = CancellationRecord {
            state: CancellationState::Finalized,
            elapsed_us: 42_000,
            trigger_chunk: Some(2),
            drain_completed: true,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let back: CancellationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(cr, back);
    }

    #[test]
    fn cancellation_record_no_trigger_chunk() {
        let cr = CancellationRecord {
            state: CancellationState::Requested,
            elapsed_us: 500_000,
            trigger_chunk: None,
            drain_completed: false,
        };
        let json = serde_json::to_string(&cr).unwrap();
        assert!(json.contains("\"trigger_chunk\":null"));
        let back: CancellationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(cr, back);
    }

    #[test]
    fn backpressure_level_ordering() {
        assert!(BackpressureLevel::Normal < BackpressureLevel::Elevated);
        assert!(BackpressureLevel::Elevated < BackpressureLevel::Critical);
    }

    #[test]
    fn backpressure_level_display() {
        assert_eq!(BackpressureLevel::Normal.to_string(), "normal");
        assert_eq!(BackpressureLevel::Elevated.to_string(), "elevated");
        assert_eq!(BackpressureLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn backpressure_snapshot_serde_roundtrip() {
        let bp = BackpressureSnapshot {
            queue_depth: 3,
            peak_queue_depth: 5,
            level: BackpressureLevel::Elevated,
            delayed_chunks: 2,
            total_delay_us: 15_000,
        };
        let json = serde_json::to_string(&bp).unwrap();
        let back: BackpressureSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(bp, back);
    }

    #[test]
    fn backpressure_snapshot_zero_delay() {
        let bp = BackpressureSnapshot {
            queue_depth: 0,
            peak_queue_depth: 0,
            level: BackpressureLevel::Normal,
            delayed_chunks: 0,
            total_delay_us: 0,
        };
        assert_eq!(bp.total_delay_us, 0);
        assert_eq!(bp.level, BackpressureLevel::Normal);
    }

    #[test]
    fn routing_digest_serial_small_input() {
        let config = default_config();
        let digest = compute_routing_digest("x = 1", &config);
        assert_eq!(digest.decision, ParserMode::Serial);
        assert_eq!(digest.effective_workers, 1);
        assert!(digest.rationale.contains("below threshold"));
    }

    #[test]
    fn routing_digest_serial_single_worker() {
        let config = ParallelConfig {
            max_workers: 1,
            ..default_config()
        };
        let digest = compute_routing_digest("x = 1\ny = 2\n", &config);
        assert_eq!(digest.decision, ParserMode::Serial);
        assert!(digest.rationale.contains("single worker"));
    }

    #[test]
    fn routing_digest_parallel_large_input() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let digest = compute_routing_digest(&source, &config);
        assert_eq!(digest.decision, ParserMode::Parallel);
        assert!(digest.effective_workers > 1);
        assert!(digest.has_partition_points);
    }

    #[test]
    fn routing_digest_serial_no_newlines() {
        let config = ParallelConfig {
            min_parallel_bytes: 5,
            max_workers: 4,
            ..default_config()
        };
        let digest = compute_routing_digest("abcdefghijklmnop", &config);
        assert_eq!(digest.decision, ParserMode::Serial);
        assert!(!digest.has_partition_points);
        assert!(digest.rationale.contains("no newlines"));
    }

    #[test]
    fn routing_digest_serde_roundtrip() {
        let config = small_config();
        let digest = compute_routing_digest("x\ny\nz\n", &config);
        let json = serde_json::to_string(&digest).unwrap();
        let back: RoutingDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(digest, back);
    }

    #[test]
    fn routing_digest_overhead_decreases_with_size() {
        let config = ParallelConfig {
            min_parallel_bytes: 10,
            max_workers: 4,
            ..default_config()
        };
        let small_src = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\n";
        let d_small = compute_routing_digest(small_src, &config);

        let mut large_src = String::new();
        for i in 0..200 {
            large_src.push_str(&format!("var longVariableName{} = {};\n", i, i));
        }
        let d_large = compute_routing_digest(&large_src, &config);

        assert!(d_small.estimated_overhead_millionths >= d_large.estimated_overhead_millionths);
    }

    #[test]
    fn throughput_sample_zero_elapsed() {
        let sample = ThroughputSample::compute(1000, 50, 0);
        assert_eq!(sample.bytes_per_sec_millionths, 0);
        assert_eq!(sample.tokens_per_sec_millionths, 0);
    }

    #[test]
    fn throughput_sample_normal() {
        let sample = ThroughputSample::compute(1000, 50, 1000);
        assert!(sample.bytes_per_sec_millionths > 0);
        assert!(sample.tokens_per_sec_millionths > 0);
    }

    #[test]
    fn throughput_sample_serde_roundtrip() {
        let sample = ThroughputSample::compute(500, 25, 2000);
        let json = serde_json::to_string(&sample).unwrap();
        let back: ThroughputSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn throughput_sample_proportional() {
        let s1 = ThroughputSample::compute(1000, 50, 1000);
        let s2 = ThroughputSample::compute(2000, 100, 1000);
        assert!(s2.bytes_per_sec_millionths > s1.bytes_per_sec_millionths);
    }

    #[test]
    fn chunk_timing_serde_roundtrip() {
        let ct = ChunkTiming {
            chunk_index: 2,
            chunk_bytes: 1024,
            token_count: 50,
            elapsed_us: 3500,
        };
        let json = serde_json::to_string(&ct).unwrap();
        let back: ChunkTiming = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, back);
    }

    #[test]
    fn performance_report_serde_roundtrip() {
        let report = PerformanceReport {
            throughput: ThroughputSample::compute(1000, 50, 2000),
            chunk_timings: vec![
                ChunkTiming {
                    chunk_index: 0,
                    chunk_bytes: 500,
                    token_count: 25,
                    elapsed_us: 1000,
                },
                ChunkTiming {
                    chunk_index: 1,
                    chunk_bytes: 500,
                    token_count: 25,
                    elapsed_us: 1000,
                },
            ],
            merge_elapsed_us: 200,
            parity_check_elapsed_us: 300,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: PerformanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn replay_envelope_from_serial_parse() {
        let config = default_config();
        let input = make_input("x + y", &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let envelope = build_replay_envelope(&input, &output, &digest);
        assert_eq!(envelope.schema_version, SCHEMA_VERSION);
        assert_eq!(envelope.input_bytes, 5);
        assert!(envelope.replay_command.contains("--trace-id"));
        assert!(envelope.replay_command.contains("--workers"));
    }

    #[test]
    fn replay_envelope_from_parallel_parse() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let envelope = build_replay_envelope(&input, &output, &digest);
        assert!(envelope.input_bytes > 100);
        assert_eq!(envelope.output_hash, output.output_hash);
    }

    #[test]
    fn replay_envelope_serde_roundtrip() {
        let config = default_config();
        let input = make_input("x", &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let envelope = build_replay_envelope(&input, &output, &digest);
        let json = serde_json::to_string(&envelope).unwrap();
        let back: ReplayEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, back);
    }

    #[test]
    fn replay_envelope_deterministic() {
        let config = default_config();
        let input = make_input("var a = 1;", &config);
        let output = parse(&input).unwrap();
        let digest = compute_routing_digest(input.source, &config);
        let e1 = build_replay_envelope(&input, &output, &digest);
        let e2 = build_replay_envelope(&input, &output, &digest);
        assert_eq!(e1.input_hash, e2.input_hash);
        assert_eq!(e1.output_hash, e2.output_hash);
    }

    #[test]
    fn rollback_default_not_disabled() {
        let rc = RollbackControl::default();
        assert!(!rc.parallel_disabled);
        assert_eq!(rc.consecutive_failures, 0);
        assert_eq!(rc.auto_rollback_threshold, 3);
    }

    #[test]
    fn rollback_record_failure_below_threshold() {
        let mut rc = RollbackControl::default();
        let triggered = rc.record_failure("trace-1");
        assert!(!triggered);
        assert_eq!(rc.consecutive_failures, 1);
        assert!(!rc.parallel_disabled);
    }

    #[test]
    fn rollback_auto_trigger_at_threshold() {
        let mut rc = RollbackControl::default();
        rc.record_failure("trace-1");
        rc.record_failure("trace-2");
        let triggered = rc.record_failure("trace-3");
        assert!(triggered);
        assert!(rc.parallel_disabled);
        assert!(
            rc.disable_reason
                .as_ref()
                .unwrap()
                .contains("3 consecutive")
        );
        assert_eq!(rc.failure_trace_ids.len(), 3);
    }

    #[test]
    fn rollback_success_resets_counter() {
        let mut rc = RollbackControl::default();
        rc.record_failure("trace-1");
        rc.record_failure("trace-2");
        rc.record_success();
        assert_eq!(rc.consecutive_failures, 0);
        assert!(!rc.parallel_disabled);
    }

    #[test]
    fn rollback_force_disable() {
        let mut rc = RollbackControl::default();
        rc.force_disable("manual intervention");
        assert!(rc.parallel_disabled);
        assert_eq!(rc.disable_reason.as_deref(), Some("manual intervention"));
    }

    #[test]
    fn rollback_re_enable_clears_state() {
        let mut rc = RollbackControl::default();
        rc.record_failure("t1");
        rc.record_failure("t2");
        rc.record_failure("t3");
        assert!(rc.parallel_disabled);
        rc.re_enable();
        assert!(!rc.parallel_disabled);
        assert!(rc.disable_reason.is_none());
        assert_eq!(rc.consecutive_failures, 0);
        assert!(rc.failure_trace_ids.is_empty());
    }

    #[test]
    fn rollback_serde_roundtrip() {
        let mut rc = RollbackControl::default();
        rc.record_failure("trace-1");
        let json = serde_json::to_string(&rc).unwrap();
        let back: RollbackControl = serde_json::from_str(&json).unwrap();
        assert_eq!(rc, back);
    }

    #[test]
    fn rollback_custom_threshold() {
        let mut rc = RollbackControl {
            auto_rollback_threshold: 5,
            ..Default::default()
        };
        for i in 0..4 {
            let triggered = rc.record_failure(&format!("t{}", i));
            assert!(!triggered);
        }
        let triggered = rc.record_failure("t4");
        assert!(triggered);
        assert!(rc.parallel_disabled);
    }

    #[test]
    fn full_pipeline_serial_small() {
        let config = default_config();
        let source = "x = 1;";
        let digest = compute_routing_digest(source, &config);
        assert_eq!(digest.decision, ParserMode::Serial);

        let input = make_input(source, &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.mode, ParserMode::Serial);

        let envelope = build_replay_envelope(&input, &output, &digest);
        assert_eq!(envelope.input_bytes, source.len() as u64);
    }

    #[test]
    fn full_pipeline_parallel_large() {
        let config = small_config();
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let digest = compute_routing_digest(&source, &config);
        assert_eq!(digest.decision, ParserMode::Parallel);

        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);

        let envelope = build_replay_envelope(&input, &output, &digest);
        assert_eq!(envelope.output_hash, output.output_hash);
        assert!(envelope.replay_command.contains("--workers 4"));
    }

    #[test]
    fn rollback_integration_with_parse() {
        let mut rc = RollbackControl::default();
        let config = small_config();
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }

        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
        rc.record_success();
        assert!(!rc.parallel_disabled);

        for i in 0..3 {
            rc.record_failure(&format!("fail-{i}"));
        }
        assert!(rc.parallel_disabled);
    }

    #[test]
    fn parallel_determinism_across_seeds() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("var x{} = {};\n", i, i));
        }
        let config1 = ParallelConfig {
            schedule_seed: 42,
            ..small_config()
        };
        let config2 = ParallelConfig {
            schedule_seed: 99,
            ..small_config()
        };
        let i1 = make_input(&source, &config1);
        let i2 = make_input(&source, &config2);
        let o1 = parse(&i1).unwrap();
        let o2 = parse(&i2).unwrap();
        assert_eq!(o1.token_count, o2.token_count);
    }

    #[test]
    fn parallel_parse_eight_workers() {
        let mut source = String::new();
        for i in 0..200 {
            source.push_str(&format!("let value{} = compute({});\n", i, i));
        }
        let config = ParallelConfig {
            max_workers: 8,
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..default_config()
        };
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
        if let Some(ref plan) = output.chunk_plan {
            assert!(plan.worker_count <= 8);
        }
    }

    #[test]
    fn chunk_plan_large_worker_count_capped_by_input() {
        let input = b"a\nb\nc\n";
        let plan = compute_chunk_plan(input, 100);
        assert!(plan.worker_count <= 6);
    }

    #[test]
    fn parallel_parse_only_newlines() {
        let source = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
        let config = ParallelConfig {
            min_parallel_bytes: 5,
            max_workers: 4,
            always_check_parity: true,
            ..default_config()
        };
        let input = make_input(source, &config);
        let output = parse(&input).unwrap();
        assert_eq!(output.token_count, 0);
    }

    #[test]
    fn parallel_parse_mixed_content_types() {
        let mut source = String::new();
        for i in 0..50 {
            source.push_str(&format!(
                "var s{} = \"hello\"; x{} == {} && y{} != z{};\n",
                i, i, i, i, i
            ));
        }
        let config = small_config();
        let input = make_input(&source, &config);
        let output = parse(&input).unwrap();
        assert!(output.token_count > 0);
    }
}
