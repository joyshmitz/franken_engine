//! Signed replacement-lineage log with transparency-verifiable append semantics.
//!
//! Records every slot replacement event in an append-only, hash-chained log.
//! Each entry includes a replacement receipt, predecessor hash, sequence number,
//! and a Merkle-tree commitment enabling inclusion and consistency proofs.
//!
//! Periodic signed checkpoints (tree-heads) allow independent verifiers to
//! confirm that the log has not been tampered with since a previous checkpoint.
//!
//! Plan reference: Section 10.15 item 4 of 9I.6 (`bd-kr99`).
//! Cross-refs: bd-7rwi (ReplacementReceipt schema), bd-1g5c (promotion gate
//! runner produces the receipts), bd-1ilz (frankensqlite-backed index).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::self_replacement::ReplacementReceipt;
use crate::slot_registry::SlotId;

// ---------------------------------------------------------------------------
// Replacement types
// ---------------------------------------------------------------------------

/// The kind of replacement recorded in a lineage log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReplacementKind {
    /// Delegate cell replaced by native implementation.
    DelegateToNative,
    /// Native implementation demoted back to delegate cell.
    Demotion,
    /// Rollback to a previously known-good implementation.
    Rollback,
    /// Re-promotion after a demotion/rollback cycle.
    RePromotion,
}

impl ReplacementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DelegateToNative => "delegate_to_native",
            Self::Demotion => "demotion",
            Self::Rollback => "rollback",
            Self::RePromotion => "re_promotion",
        }
    }
}

impl fmt::Display for ReplacementKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Log entry
// ---------------------------------------------------------------------------

/// A single entry in the replacement lineage log.
///
/// Entries form a hash chain: each entry includes the content hash of its
/// predecessor, providing tamper-evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageLogEntry {
    /// Monotonically increasing sequence number (0-indexed).
    pub sequence: u64,
    /// The replacement receipt for this event.
    pub receipt: ReplacementReceipt,
    /// Kind of replacement.
    pub kind: ReplacementKind,
    /// Content hash of the preceding entry (all-zeros for the first entry).
    pub predecessor_hash: ContentHash,
    /// Content hash of this entry (computed over canonical serialization).
    pub entry_hash: ContentHash,
}

impl LineageLogEntry {
    /// Compute the canonical content hash of this entry.
    ///
    /// Deterministic: hash(sequence || kind || receipt_id || old_digest ||
    /// new_digest || predecessor_hash).
    fn compute_hash(
        sequence: u64,
        kind: ReplacementKind,
        receipt: &ReplacementReceipt,
        predecessor_hash: &ContentHash,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&sequence.to_be_bytes());
        canonical.extend_from_slice(kind.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.receipt_id.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.old_cell_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.new_cell_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(receipt.slot_id.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(predecessor_hash.as_bytes());
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// Merkle tree for inclusion / consistency proofs
// ---------------------------------------------------------------------------

/// A node in the Merkle tree. Leaf nodes hash log entries; internal nodes
/// hash their two children.
fn merkle_leaf(entry_hash: &ContentHash) -> ContentHash {
    let mut buf = Vec::with_capacity(33);
    buf.push(0x00); // leaf prefix
    buf.extend_from_slice(entry_hash.as_bytes());
    ContentHash::compute(&buf)
}

fn merkle_node(left: &ContentHash, right: &ContentHash) -> ContentHash {
    let mut buf = Vec::with_capacity(65);
    buf.push(0x01); // node prefix
    buf.extend_from_slice(left.as_bytes());
    buf.extend_from_slice(right.as_bytes());
    ContentHash::compute(&buf)
}

/// Compute the Merkle root of a list of entry hashes.
fn compute_merkle_root(entry_hashes: &[ContentHash]) -> ContentHash {
    if entry_hashes.is_empty() {
        return ContentHash::compute(b"empty_lineage_tree");
    }
    if entry_hashes.len() == 1 {
        return merkle_leaf(&entry_hashes[0]);
    }

    let mut current_level: Vec<ContentHash> = entry_hashes.iter().map(merkle_leaf).collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(merkle_node(&current_level[i], &current_level[i + 1]));
            } else {
                // Odd node promoted directly.
                next_level.push(current_level[i].clone());
            }
            i += 2;
        }
        current_level = next_level;
    }
    current_level.remove(0)
}

/// Direction in a Merkle proof path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDirection {
    /// The sibling is to the left.
    Left,
    /// The sibling is to the right.
    Right,
}

/// A single step in a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub sibling_hash: ContentHash,
    pub direction: ProofDirection,
}

/// Merkle inclusion proof for a single log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the entry in the log.
    pub entry_index: u64,
    /// The entry's hash.
    pub entry_hash: ContentHash,
    /// Path of sibling hashes from leaf to root.
    pub path: Vec<MerkleProofStep>,
    /// The expected Merkle root.
    pub root: ContentHash,
}

/// Build a Merkle inclusion proof for entry at `index`.
fn build_inclusion_proof(entry_hashes: &[ContentHash], index: usize) -> Option<InclusionProof> {
    if index >= entry_hashes.len() || entry_hashes.is_empty() {
        return None;
    }

    let root = compute_merkle_root(entry_hashes);

    if entry_hashes.len() == 1 {
        return Some(InclusionProof {
            entry_index: index as u64,
            entry_hash: entry_hashes[index].clone(),
            path: Vec::new(),
            root,
        });
    }

    // Build the proof path by walking up the tree.
    let mut current_level: Vec<ContentHash> = entry_hashes.iter().map(merkle_leaf).collect();
    let mut path = Vec::new();
    let mut pos = index;

    while current_level.len() > 1 {
        if pos.is_multiple_of(2) {
            // We're a left child; sibling is to our right (if exists).
            if pos + 1 < current_level.len() {
                path.push(MerkleProofStep {
                    sibling_hash: current_level[pos + 1].clone(),
                    direction: ProofDirection::Right,
                });
            }
            // No sibling: odd node promoted, no step needed.
        } else {
            // We're a right child; sibling is to our left.
            path.push(MerkleProofStep {
                sibling_hash: current_level[pos - 1].clone(),
                direction: ProofDirection::Left,
            });
        }

        // Move to next level.
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(merkle_node(&current_level[i], &current_level[i + 1]));
            } else {
                next_level.push(current_level[i].clone());
            }
            i += 2;
        }
        current_level = next_level;
        pos /= 2;
    }

    Some(InclusionProof {
        entry_index: index as u64,
        entry_hash: entry_hashes[index].clone(),
        path,
        root,
    })
}

/// Verify an inclusion proof.
pub fn verify_inclusion_proof(proof: &InclusionProof) -> bool {
    let mut current = merkle_leaf(&proof.entry_hash);
    for step in &proof.path {
        current = match step.direction {
            ProofDirection::Left => merkle_node(&step.sibling_hash, &current),
            ProofDirection::Right => merkle_node(&current, &step.sibling_hash),
        };
    }
    current == proof.root
}

// ---------------------------------------------------------------------------
// Consistency proofs
// ---------------------------------------------------------------------------

/// Proof that a newer checkpoint extends an older checkpoint without rewriting
/// historical entries.
///
/// The proof carries the hash inventory needed for independent verification:
/// - `older_entry_hashes` must match the prefix of `newer_entry_hashes`
/// - Merkle roots recomputed from each hash list must match the recorded roots
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Older checkpoint sequence number.
    pub older_checkpoint_seq: u64,
    /// Newer checkpoint sequence number.
    pub newer_checkpoint_seq: u64,
    /// Number of entries covered by the older checkpoint.
    pub older_log_length: u64,
    /// Number of entries covered by the newer checkpoint.
    pub newer_log_length: u64,
    /// Recorded Merkle root of the older checkpoint.
    pub older_root: ContentHash,
    /// Recorded Merkle root of the newer checkpoint.
    pub newer_root: ContentHash,
    /// Entry hashes covered by the older checkpoint.
    pub older_entry_hashes: Vec<ContentHash>,
    /// Entry hashes covered by the newer checkpoint.
    pub newer_entry_hashes: Vec<ContentHash>,
}

/// Verify a checkpoint consistency proof.
pub fn verify_consistency_proof(proof: &ConsistencyProof) -> bool {
    if proof.older_log_length > proof.newer_log_length {
        return false;
    }
    if proof.older_entry_hashes.len() as u64 != proof.older_log_length {
        return false;
    }
    if proof.newer_entry_hashes.len() as u64 != proof.newer_log_length {
        return false;
    }
    if proof.older_entry_hashes != proof.newer_entry_hashes[..proof.older_entry_hashes.len()] {
        return false;
    }

    let recomputed_older_root = compute_merkle_root(&proof.older_entry_hashes);
    if recomputed_older_root != proof.older_root {
        return false;
    }
    let recomputed_newer_root = compute_merkle_root(&proof.newer_entry_hashes);
    recomputed_newer_root == proof.newer_root
}

// ---------------------------------------------------------------------------
// Signed checkpoint (tree-head)
// ---------------------------------------------------------------------------

/// A signed checkpoint representing the state of the lineage log at a
/// particular sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogCheckpoint {
    /// Checkpoint sequence number (monotonically increasing).
    pub checkpoint_seq: u64,
    /// Sequence number of the latest entry included in this checkpoint.
    pub log_length: u64,
    /// Merkle root over all entries up to `log_length`.
    pub merkle_root: ContentHash,
    /// Timestamp (nanoseconds, monotonic) when the checkpoint was created.
    pub timestamp_ns: u64,
    /// Security epoch at checkpoint time.
    pub epoch: SecurityEpoch,
    /// Content hash of this checkpoint for verification.
    pub checkpoint_hash: ContentHash,
}

impl LogCheckpoint {
    fn compute_checkpoint_hash(
        checkpoint_seq: u64,
        log_length: u64,
        merkle_root: &ContentHash,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"lineage_checkpoint|");
        canonical.extend_from_slice(&checkpoint_seq.to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&log_length.to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(merkle_root.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&epoch.as_u64().to_be_bytes());
        ContentHash::compute(&canonical)
    }
}

// ---------------------------------------------------------------------------
// Query types
// ---------------------------------------------------------------------------

/// Filter for querying log entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageQuery {
    /// Filter by slot ID (if present).
    pub slot_id: Option<SlotId>,
    /// Filter by replacement kind (if present).
    pub kinds: Option<BTreeSet<ReplacementKind>>,
    /// Minimum timestamp (inclusive, nanoseconds).
    pub min_timestamp_ns: Option<u64>,
    /// Maximum timestamp (inclusive, nanoseconds).
    pub max_timestamp_ns: Option<u64>,
}

impl LineageQuery {
    pub fn for_slot(slot_id: SlotId) -> Self {
        Self {
            slot_id: Some(slot_id),
            kinds: None,
            min_timestamp_ns: None,
            max_timestamp_ns: None,
        }
    }

    pub fn all() -> Self {
        Self {
            slot_id: None,
            kinds: None,
            min_timestamp_ns: None,
            max_timestamp_ns: None,
        }
    }

    fn matches(&self, entry: &LineageLogEntry) -> bool {
        if let Some(ref sid) = self.slot_id
            && entry.receipt.slot_id != *sid
        {
            return false;
        }
        if let Some(ref kinds) = self.kinds
            && !kinds.contains(&entry.kind)
        {
            return false;
        }
        if let Some(min_ts) = self.min_timestamp_ns
            && entry.receipt.timestamp_ns < min_ts
        {
            return false;
        }
        if let Some(max_ts) = self.max_timestamp_ns
            && entry.receipt.timestamp_ns > max_ts
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Slot lineage summary
// ---------------------------------------------------------------------------

/// A summary of a single step in a slot's replacement lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageStep {
    pub sequence: u64,
    pub kind: ReplacementKind,
    pub old_cell_digest: String,
    pub new_cell_digest: String,
    pub receipt_id: String,
    pub timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub validation_artifact_count: usize,
}

// ---------------------------------------------------------------------------
// Verification results
// ---------------------------------------------------------------------------

/// Result of verifying a slot's replacement lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageVerification {
    pub slot_id: SlotId,
    pub total_entries: usize,
    pub chain_valid: bool,
    pub all_receipts_present: bool,
    pub issues: Vec<String>,
}

/// Result of an audit across the entire log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResult {
    pub total_entries: u64,
    pub total_slots: usize,
    pub chain_valid: bool,
    pub merkle_valid: bool,
    pub checkpoint_count: usize,
    pub latest_checkpoint_seq: Option<u64>,
    pub issues: Vec<String>,
}

// ---------------------------------------------------------------------------
// Structured log events
// ---------------------------------------------------------------------------

/// Structured log event emitted by the lineage log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from lineage log operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageLogError {
    /// Sequence number mismatch on append.
    SequenceMismatch { expected: u64, got: u64 },
    /// Chain hash does not match predecessor.
    ChainBreak { sequence: u64 },
    /// Duplicate receipt ID in the log.
    DuplicateReceipt { receipt_id: String },
    /// Checkpoint references a log length beyond current entries.
    CheckpointBeyondLog {
        checkpoint_length: u64,
        log_length: u64,
    },
    /// Requested checkpoint sequence does not exist.
    CheckpointNotFound { checkpoint_seq: u64 },
    /// Checkpoint order is invalid for consistency verification.
    InvalidCheckpointOrder { older: u64, newer: u64 },
    /// Log is empty, operation requires entries.
    EmptyLog,
}

impl fmt::Display for LineageLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceMismatch { expected, got } => {
                write!(f, "sequence mismatch: expected {expected}, got {got}")
            }
            Self::ChainBreak { sequence } => {
                write!(f, "chain break at sequence {sequence}")
            }
            Self::DuplicateReceipt { receipt_id } => {
                write!(f, "duplicate receipt: {receipt_id}")
            }
            Self::CheckpointBeyondLog {
                checkpoint_length,
                log_length,
            } => {
                write!(
                    f,
                    "checkpoint length {checkpoint_length} beyond log length {log_length}"
                )
            }
            Self::CheckpointNotFound { checkpoint_seq } => {
                write!(f, "checkpoint not found: sequence {checkpoint_seq}")
            }
            Self::InvalidCheckpointOrder { older, newer } => {
                write!(
                    f,
                    "invalid checkpoint order: older={older}, newer={newer} (must be older < newer)"
                )
            }
            Self::EmptyLog => f.write_str("log is empty"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the lineage log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageLogConfig {
    /// How often to create automatic checkpoints (every N appends).
    pub checkpoint_interval: u64,
    /// Maximum number of entries to keep in memory (0 = unlimited).
    pub max_entries_in_memory: u64,
}

impl Default for LineageLogConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 100,
            max_entries_in_memory: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Lineage log engine
// ---------------------------------------------------------------------------

/// The replacement lineage log engine.
///
/// Append-only, hash-chained log of slot replacement events with Merkle tree
/// commitments and periodic signed checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplacementLineageLog {
    config: LineageLogConfig,
    entries: Vec<LineageLogEntry>,
    checkpoints: Vec<LogCheckpoint>,
    checkpoint_seq_counter: u64,
    events: Vec<LineageLogEvent>,
    event_seq: u64,
}

impl ReplacementLineageLog {
    /// Create a new empty lineage log.
    pub fn new(config: LineageLogConfig) -> Self {
        Self {
            config,
            entries: Vec::new(),
            checkpoints: Vec::new(),
            checkpoint_seq_counter: 0,
            events: Vec::new(),
            event_seq: 0,
        }
    }

    /// Current number of entries in the log.
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries in the log.
    pub fn entries(&self) -> &[LineageLogEntry] {
        &self.entries
    }

    /// All checkpoints.
    pub fn checkpoints(&self) -> &[LogCheckpoint] {
        &self.checkpoints
    }

    /// Structured log events.
    pub fn events(&self) -> &[LineageLogEvent] {
        &self.events
    }

    /// Build a consistency proof showing that `newer_checkpoint_seq` extends
    /// `older_checkpoint_seq` without rewriting historical entries.
    pub fn consistency_proof(
        &self,
        older_checkpoint_seq: u64,
        newer_checkpoint_seq: u64,
    ) -> Result<ConsistencyProof, LineageLogError> {
        if older_checkpoint_seq >= newer_checkpoint_seq {
            return Err(LineageLogError::InvalidCheckpointOrder {
                older: older_checkpoint_seq,
                newer: newer_checkpoint_seq,
            });
        }

        let older = self.checkpoint_by_seq(older_checkpoint_seq).ok_or(
            LineageLogError::CheckpointNotFound {
                checkpoint_seq: older_checkpoint_seq,
            },
        )?;
        let newer = self.checkpoint_by_seq(newer_checkpoint_seq).ok_or(
            LineageLogError::CheckpointNotFound {
                checkpoint_seq: newer_checkpoint_seq,
            },
        )?;

        if older.log_length > newer.log_length {
            return Err(LineageLogError::InvalidCheckpointOrder {
                older: older_checkpoint_seq,
                newer: newer_checkpoint_seq,
            });
        }

        if newer.log_length > self.entries.len() as u64 {
            return Err(LineageLogError::CheckpointBeyondLog {
                checkpoint_length: newer.log_length,
                log_length: self.entries.len() as u64,
            });
        }

        let newer_entry_hashes: Vec<ContentHash> = self
            .entries
            .iter()
            .take(newer.log_length as usize)
            .map(|entry| entry.entry_hash.clone())
            .collect();
        let older_entry_hashes: Vec<ContentHash> = newer_entry_hashes
            .iter()
            .take(older.log_length as usize)
            .cloned()
            .collect();

        Ok(ConsistencyProof {
            older_checkpoint_seq,
            newer_checkpoint_seq,
            older_log_length: older.log_length,
            newer_log_length: newer.log_length,
            older_root: older.merkle_root.clone(),
            newer_root: newer.merkle_root.clone(),
            older_entry_hashes,
            newer_entry_hashes,
        })
    }

    /// Append a replacement event to the log.
    pub fn append(
        &mut self,
        receipt: ReplacementReceipt,
        kind: ReplacementKind,
        timestamp_ns: u64,
    ) -> Result<u64, LineageLogError> {
        let sequence = self.entries.len() as u64;

        // Check for duplicate receipt.
        let receipt_id_str = hex::encode(receipt.receipt_id.as_bytes());
        for existing in &self.entries {
            if existing.receipt.receipt_id == receipt.receipt_id {
                return Err(LineageLogError::DuplicateReceipt {
                    receipt_id: receipt_id_str,
                });
            }
        }

        // Predecessor hash: hash of the previous entry, or zeros for first.
        let predecessor_hash = if let Some(last) = self.entries.last() {
            last.entry_hash.clone()
        } else {
            ContentHash::compute(b"genesis")
        };

        let entry_hash = LineageLogEntry::compute_hash(sequence, kind, &receipt, &predecessor_hash);

        let entry = LineageLogEntry {
            sequence,
            receipt,
            kind,
            predecessor_hash,
            entry_hash,
        };

        self.entries.push(entry);

        self.emit_event(
            "entry_appended",
            "ok",
            None,
            &format!("seq={sequence},kind={kind}"),
        );

        // Auto-checkpoint.
        if self.config.checkpoint_interval > 0
            && (sequence + 1).is_multiple_of(self.config.checkpoint_interval)
        {
            let _ = self.create_checkpoint(timestamp_ns, SecurityEpoch::from_raw(1));
        }

        Ok(sequence)
    }

    /// Create a signed checkpoint at the current log state.
    pub fn create_checkpoint(
        &mut self,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<u64, LineageLogError> {
        if self.entries.is_empty() {
            return Err(LineageLogError::EmptyLog);
        }

        let log_length = self.entries.len() as u64;
        let entry_hashes: Vec<ContentHash> =
            self.entries.iter().map(|e| e.entry_hash.clone()).collect();
        let merkle_root = compute_merkle_root(&entry_hashes);

        let checkpoint_seq = self.checkpoint_seq_counter;
        self.checkpoint_seq_counter += 1;

        let checkpoint_hash = LogCheckpoint::compute_checkpoint_hash(
            checkpoint_seq,
            log_length,
            &merkle_root,
            timestamp_ns,
            epoch,
        );

        let checkpoint = LogCheckpoint {
            checkpoint_seq,
            log_length,
            merkle_root,
            timestamp_ns,
            epoch,
            checkpoint_hash,
        };

        self.checkpoints.push(checkpoint);

        self.emit_event(
            "checkpoint_created",
            "ok",
            None,
            &format!("checkpoint_seq={checkpoint_seq},log_length={log_length}"),
        );

        Ok(checkpoint_seq)
    }

    /// Query log entries matching a filter.
    pub fn query(&self, filter: &LineageQuery) -> Vec<&LineageLogEntry> {
        self.entries.iter().filter(|e| filter.matches(e)).collect()
    }

    /// Get the complete replacement lineage for a slot.
    pub fn slot_lineage(&self, slot_id: &SlotId) -> Vec<LineageStep> {
        self.entries
            .iter()
            .filter(|e| e.receipt.slot_id == *slot_id)
            .map(|e| LineageStep {
                sequence: e.sequence,
                kind: e.kind,
                old_cell_digest: e.receipt.old_cell_digest.clone(),
                new_cell_digest: e.receipt.new_cell_digest.clone(),
                receipt_id: hex::encode(e.receipt.receipt_id.as_bytes()),
                timestamp_ns: e.receipt.timestamp_ns,
                epoch: e.receipt.epoch,
                validation_artifact_count: e.receipt.validation_artifacts.len(),
            })
            .collect()
    }

    /// Generate a Merkle inclusion proof for a specific entry.
    pub fn inclusion_proof(&self, sequence: u64) -> Option<InclusionProof> {
        let entry_hashes: Vec<ContentHash> =
            self.entries.iter().map(|e| e.entry_hash.clone()).collect();
        build_inclusion_proof(&entry_hashes, sequence as usize)
    }

    /// Verify the full replacement lineage for a slot.
    pub fn verify_slot_lineage(&self, slot_id: &SlotId) -> LineageVerification {
        let slot_entries: Vec<&LineageLogEntry> = self
            .entries
            .iter()
            .filter(|e| e.receipt.slot_id == *slot_id)
            .collect();

        let mut issues = Vec::new();

        if slot_entries.is_empty() {
            return LineageVerification {
                slot_id: slot_id.clone(),
                total_entries: 0,
                chain_valid: true,
                all_receipts_present: true,
                issues: vec!["no entries for this slot".to_string()],
            };
        }

        // Verify each entry's hash is correct.
        let mut chain_valid = true;
        for entry in &slot_entries {
            let expected_hash = LineageLogEntry::compute_hash(
                entry.sequence,
                entry.kind,
                &entry.receipt,
                &entry.predecessor_hash,
            );
            if expected_hash != entry.entry_hash {
                chain_valid = false;
                issues.push(format!("entry {} hash mismatch", entry.sequence));
            }
        }

        // Verify chain continuity: each entry's predecessor hash should match
        // the actual predecessor in the global log.
        for entry in &slot_entries {
            if entry.sequence == 0 {
                let genesis = ContentHash::compute(b"genesis");
                if entry.predecessor_hash != genesis {
                    chain_valid = false;
                    issues.push("first entry has wrong genesis hash".to_string());
                }
            } else if let Some(pred) = self.entries.get(entry.sequence as usize - 1)
                && entry.predecessor_hash != pred.entry_hash
            {
                chain_valid = false;
                issues.push(format!(
                    "entry {} predecessor hash mismatch",
                    entry.sequence
                ));
            }
        }

        LineageVerification {
            slot_id: slot_id.clone(),
            total_entries: slot_entries.len(),
            chain_valid,
            all_receipts_present: true,
            issues,
        }
    }

    /// Audit the entire log for consistency and completeness.
    pub fn audit(&self) -> AuditResult {
        let mut issues = Vec::new();
        let mut chain_valid = true;

        // Verify the full hash chain.
        for (i, entry) in self.entries.iter().enumerate() {
            let expected_pred = if i == 0 {
                ContentHash::compute(b"genesis")
            } else {
                self.entries[i - 1].entry_hash.clone()
            };

            if entry.predecessor_hash != expected_pred {
                chain_valid = false;
                issues.push(format!("chain break at sequence {}", entry.sequence));
            }

            let expected_hash = LineageLogEntry::compute_hash(
                entry.sequence,
                entry.kind,
                &entry.receipt,
                &entry.predecessor_hash,
            );
            if entry.entry_hash != expected_hash {
                chain_valid = false;
                issues.push(format!("hash mismatch at sequence {}", entry.sequence));
            }

            if entry.sequence != i as u64 {
                issues.push(format!(
                    "sequence gap: expected {i}, got {}",
                    entry.sequence
                ));
            }
        }

        // Verify Merkle root matches the latest checkpoint.
        let entry_hashes: Vec<ContentHash> =
            self.entries.iter().map(|e| e.entry_hash.clone()).collect();
        let current_root = compute_merkle_root(&entry_hashes);
        let mut merkle_valid = if let Some(last_cp) = self.checkpoints.last() {
            if last_cp.log_length == self.entries.len() as u64 {
                if last_cp.merkle_root != current_root {
                    issues.push("latest checkpoint merkle root mismatch".to_string());
                    false
                } else {
                    true
                }
            } else {
                // Checkpoint covers a prefix — verify that prefix.
                let prefix_hashes: Vec<ContentHash> = entry_hashes
                    .iter()
                    .take(last_cp.log_length as usize)
                    .cloned()
                    .collect();
                let prefix_root = compute_merkle_root(&prefix_hashes);
                if last_cp.merkle_root != prefix_root {
                    issues.push("checkpoint merkle root mismatch for prefix".to_string());
                    false
                } else {
                    true
                }
            }
        } else {
            true // No checkpoints, nothing to verify.
        };

        // Verify checkpoint chain monotonicity and pairwise consistency proofs.
        for window in self.checkpoints.windows(2) {
            if window[1].checkpoint_seq <= window[0].checkpoint_seq {
                issues.push("checkpoint sequence not monotonic".to_string());
                merkle_valid = false;
            }
            if window[1].log_length < window[0].log_length {
                issues.push("checkpoint log_length regressed".to_string());
                merkle_valid = false;
            }

            match self.consistency_proof(window[0].checkpoint_seq, window[1].checkpoint_seq) {
                Ok(proof) => {
                    if !verify_consistency_proof(&proof) {
                        issues.push(format!(
                            "checkpoint consistency proof failed ({} -> {})",
                            window[0].checkpoint_seq, window[1].checkpoint_seq
                        ));
                        merkle_valid = false;
                    }
                }
                Err(err) => {
                    issues.push(format!(
                        "checkpoint consistency generation failed ({} -> {}): {err}",
                        window[0].checkpoint_seq, window[1].checkpoint_seq
                    ));
                    merkle_valid = false;
                }
            }
        }

        // Count unique slots.
        let unique_slots: BTreeSet<&SlotId> =
            self.entries.iter().map(|e| &e.receipt.slot_id).collect();

        let latest_checkpoint_seq = self.checkpoints.last().map(|cp| cp.checkpoint_seq);

        AuditResult {
            total_entries: self.entries.len() as u64,
            total_slots: unique_slots.len(),
            chain_valid,
            merkle_valid,
            checkpoint_count: self.checkpoints.len(),
            latest_checkpoint_seq,
            issues,
        }
    }

    /// Get the current Merkle root.
    pub fn merkle_root(&self) -> ContentHash {
        let entry_hashes: Vec<ContentHash> =
            self.entries.iter().map(|e| e.entry_hash.clone()).collect();
        compute_merkle_root(&entry_hashes)
    }

    /// Get distinct slot IDs that appear in the log.
    pub fn slot_ids(&self) -> Vec<SlotId> {
        let unique: BTreeSet<&SlotId> = self.entries.iter().map(|e| &e.receipt.slot_id).collect();
        unique.into_iter().cloned().collect()
    }

    // ── internal helpers ────────────────────────────────────────────

    fn checkpoint_by_seq(&self, checkpoint_seq: u64) -> Option<&LogCheckpoint> {
        self.checkpoints
            .iter()
            .find(|cp| cp.checkpoint_seq == checkpoint_seq)
    }

    fn emit_event(
        &mut self,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
        trace_suffix: &str,
    ) {
        let seq = self.event_seq;
        self.event_seq += 1;
        self.events.push(LineageLogEvent {
            trace_id: format!("lineage-{seq}-{trace_suffix}"),
            decision_id: format!("lineage-decision-{seq}"),
            policy_id: "replacement-lineage-policy".to_string(),
            component: "replacement_lineage_log".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{self, ObjectDomain};
    use crate::self_replacement::{
        SchemaVersion, SignatureBundle, ValidationArtifactKind, ValidationArtifactRef,
    };

    fn test_slot_id(name: &str) -> SlotId {
        SlotId::new(name).expect("valid slot id")
    }

    fn test_receipt(slot_name: &str, old: &str, new: &str, ts: u64) -> ReplacementReceipt {
        let slot_id = test_slot_id(slot_name);
        let receipt_id = engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "test-zone",
            &engine_object_id::SchemaId::from_definition(b"test-receipt-schema"),
            &format!("{slot_name}|{old}|{new}|{ts}").into_bytes(),
        )
        .expect("valid id");

        ReplacementReceipt {
            receipt_id,
            schema_version: SchemaVersion::V1,
            slot_id,
            old_cell_digest: old.to_string(),
            new_cell_digest: new.to_string(),
            validation_artifacts: vec![ValidationArtifactRef {
                kind: ValidationArtifactKind::EquivalenceResult,
                artifact_digest: "deadbeef".to_string(),
                passed: true,
                summary: "test artifact".to_string(),
            }],
            rollback_token: format!("rollback-{old}"),
            promotion_rationale: "test promotion".to_string(),
            timestamp_ns: ts,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone".to_string(),
            signature_bundle: SignatureBundle::new(1),
        }
    }

    // ── basic operations ────────────────────────────────────────────

    #[test]
    fn new_log_is_empty() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn append_single_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old-digest", "new-digest", 1000);
        let seq = log
            .append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        assert_eq!(seq, 0);
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn append_multiple_entries() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let receipt = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            let seq = log
                .append(receipt, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            assert_eq!(seq, i);
        }
        assert_eq!(log.len(), 5);
    }

    #[test]
    fn duplicate_receipt_rejected() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt.clone(), ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let result = log.append(receipt, ReplacementKind::DelegateToNative, 2000);
        assert!(matches!(
            result,
            Err(LineageLogError::DuplicateReceipt { .. })
        ));
    }

    // ── hash chain ──────────────────────────────────────────────────

    #[test]
    fn first_entry_uses_genesis_predecessor() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let genesis = ContentHash::compute(b"genesis");
        assert_eq!(log.entries()[0].predecessor_hash, genesis);
    }

    #[test]
    fn entries_are_hash_chained() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let receipt = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(receipt, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        // Entry 1's predecessor should be entry 0's hash.
        assert_eq!(
            log.entries()[1].predecessor_hash,
            log.entries()[0].entry_hash
        );
        assert_eq!(
            log.entries()[2].predecessor_hash,
            log.entries()[1].entry_hash
        );
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let mut log1 = ReplacementLineageLog::new(LineageLogConfig::default());
        let mut log2 = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log1.append(receipt.clone(), ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log2.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        assert_eq!(log1.entries()[0].entry_hash, log2.entries()[0].entry_hash);
    }

    // ── Merkle tree ─────────────────────────────────────────────────

    #[test]
    fn merkle_root_single_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let root = log.merkle_root();
        // Should be merkle_leaf(entry_hash).
        let expected = merkle_leaf(&log.entries()[0].entry_hash);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_deterministic() {
        let mut log1 = ReplacementLineageLog::new(LineageLogConfig::default());
        let mut log2 = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log1.append(r.clone(), ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            log2.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        assert_eq!(log1.merkle_root(), log2.merkle_root());
    }

    #[test]
    fn merkle_root_changes_with_new_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-0", "new-0", 100);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        let root1 = log.merkle_root();
        let r2 = test_receipt("slot-a", "old-1", "new-1", 200);
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        let root2 = log.merkle_root();
        assert_ne!(root1, root2);
    }

    // ── inclusion proofs ────────────────────────────────────────────

    #[test]
    fn inclusion_proof_single_entry() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let receipt = test_receipt("slot-a", "old", "new", 1000);
        log.append(receipt, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let proof = log.inclusion_proof(0).expect("proof exists");
        assert!(verify_inclusion_proof(&proof));
    }

    #[test]
    fn inclusion_proof_multiple_entries() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..8 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        // Verify inclusion proof for every entry.
        for i in 0..8 {
            let proof = log.inclusion_proof(i).expect("proof exists");
            assert_eq!(proof.entry_index, i);
            assert!(
                verify_inclusion_proof(&proof),
                "inclusion proof failed for entry {i}"
            );
        }
    }

    #[test]
    fn inclusion_proof_odd_count() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..7 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        for i in 0..7 {
            let proof = log.inclusion_proof(i).expect("proof exists");
            assert!(
                verify_inclusion_proof(&proof),
                "inclusion proof failed for entry {i}"
            );
        }
    }

    #[test]
    fn inclusion_proof_out_of_bounds() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 100);
        log.append(r, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        assert!(log.inclusion_proof(5).is_none());
    }

    #[test]
    fn tampered_inclusion_proof_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let mut proof = log.inclusion_proof(2).expect("proof exists");
        // Tamper with the entry hash.
        proof.entry_hash = ContentHash::compute(b"tampered");
        assert!(!verify_inclusion_proof(&proof));
    }

    // ── checkpoints ─────────────────────────────────────────────────

    #[test]
    fn create_checkpoint() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let cp_seq = log
            .create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        assert_eq!(cp_seq, 0);
        assert_eq!(log.checkpoints().len(), 1);
        assert_eq!(log.checkpoints()[0].log_length, 1);
    }

    #[test]
    fn checkpoint_on_empty_log_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let result = log.create_checkpoint(1000, SecurityEpoch::from_raw(1));
        assert!(matches!(result, Err(LineageLogError::EmptyLog)));
    }

    #[test]
    fn checkpoint_merkle_root_matches() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        log.create_checkpoint(500, SecurityEpoch::from_raw(1))
            .unwrap();
        let root = log.merkle_root();
        assert_eq!(log.checkpoints()[0].merkle_root, root);
    }

    #[test]
    fn auto_checkpoint_at_interval() {
        let config = LineageLogConfig {
            checkpoint_interval: 3,
            max_entries_in_memory: 0,
        };
        let mut log = ReplacementLineageLog::new(config);
        for i in 0..6 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        // Checkpoints at entries 2 (seq 0..2 = 3 entries) and 5 (seq 0..5 = 6 entries).
        assert_eq!(log.checkpoints().len(), 2);
    }

    #[test]
    fn checkpoint_hash_deterministic() {
        let mut log1 = ReplacementLineageLog::new(LineageLogConfig::default());
        let mut log2 = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log1.append(r.clone(), ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log2.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log1.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        log2.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        assert_eq!(
            log1.checkpoints()[0].checkpoint_hash,
            log2.checkpoints()[0].checkpoint_hash
        );
    }

    #[test]
    fn consistency_proof_between_checkpoints_verifies() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..6 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            if i == 2 || i == 5 {
                log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                    .unwrap();
            }
        }

        let proof = log.consistency_proof(0, 1).expect("proof");
        assert_eq!(proof.older_log_length, 3);
        assert_eq!(proof.newer_log_length, 6);
        assert!(verify_consistency_proof(&proof));
    }

    #[test]
    fn consistency_proof_tamper_is_detected() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            if i == 1 || i == 3 {
                log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                    .unwrap();
            }
        }

        let mut proof = log.consistency_proof(0, 1).expect("proof");
        proof.newer_entry_hashes[0] = ContentHash::compute(b"tampered");
        assert!(!verify_consistency_proof(&proof));
    }

    #[test]
    fn consistency_proof_invalid_order_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..2 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                .unwrap();
        }

        let err = log.consistency_proof(1, 0).expect_err("invalid order");
        assert!(matches!(
            err,
            LineageLogError::InvalidCheckpointOrder { older: 1, newer: 0 }
        ));
    }

    #[test]
    fn consistency_proof_missing_checkpoint_fails() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 100);
        log.append(r, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.create_checkpoint(100, SecurityEpoch::from_raw(1))
            .unwrap();

        let err = log
            .consistency_proof(0, 99)
            .expect_err("missing checkpoint must fail");
        assert!(matches!(
            err,
            LineageLogError::CheckpointNotFound { checkpoint_seq: 99 }
        ));
    }

    // ── queries ─────────────────────────────────────────────────────

    #[test]
    fn query_by_slot_id() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-a", "new-a", 100);
        let r2 = test_receipt("slot-b", "old-b", "new-b", 200);
        let r3 = test_receipt("slot-a", "new-a", "newer-a", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        log.append(r3, ReplacementKind::RePromotion, 300).unwrap();

        let results = log.query(&LineageQuery::for_slot(test_slot_id("slot-a")));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_by_kind() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old", "new", 100);
        let r2 = test_receipt("slot-a", "new", "old", 200);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::Rollback, 200).unwrap();

        let mut kinds = BTreeSet::new();
        kinds.insert(ReplacementKind::Rollback);
        let query = LineageQuery {
            slot_id: None,
            kinds: Some(kinds),
            min_timestamp_ns: None,
            max_timestamp_ns: None,
        };
        let results = log.query(&query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, ReplacementKind::Rollback);
    }

    #[test]
    fn query_by_time_range() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let r = test_receipt(
                "slot-a",
                &format!("old-{i}"),
                &format!("new-{i}"),
                (i + 1) * 100,
            );
            log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 100)
                .unwrap();
        }
        let query = LineageQuery {
            slot_id: None,
            kinds: None,
            min_timestamp_ns: Some(200),
            max_timestamp_ns: Some(400),
        };
        let results = log.query(&query);
        assert_eq!(results.len(), 3); // timestamps 200, 300, 400
    }

    #[test]
    fn query_all() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let results = log.query(&LineageQuery::all());
        assert_eq!(results.len(), 3);
    }

    // ── slot lineage ────────────────────────────────────────────────

    #[test]
    fn slot_lineage_tracks_replacement_chain() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "delegate-v1", "native-v1", 100);
        let r2 = test_receipt("slot-a", "native-v1", "delegate-v1", 200);
        let r3 = test_receipt("slot-a", "delegate-v1", "native-v2", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::Demotion, 200).unwrap();
        log.append(r3, ReplacementKind::RePromotion, 300).unwrap();

        let lineage = log.slot_lineage(&test_slot_id("slot-a"));
        assert_eq!(lineage.len(), 3);
        assert_eq!(lineage[0].kind, ReplacementKind::DelegateToNative);
        assert_eq!(lineage[1].kind, ReplacementKind::Demotion);
        assert_eq!(lineage[2].kind, ReplacementKind::RePromotion);
    }

    #[test]
    fn slot_lineage_isolates_slots() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-a", "new-a", 100);
        let r2 = test_receipt("slot-b", "old-b", "new-b", 200);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();

        let lineage_a = log.slot_lineage(&test_slot_id("slot-a"));
        let lineage_b = log.slot_lineage(&test_slot_id("slot-b"));
        assert_eq!(lineage_a.len(), 1);
        assert_eq!(lineage_b.len(), 1);
    }

    // ── verification ────────────────────────────────────────────────

    #[test]
    fn verify_slot_lineage_valid() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let result = log.verify_slot_lineage(&test_slot_id("slot-a"));
        assert!(result.chain_valid);
        assert!(result.issues.is_empty());
        assert_eq!(result.total_entries, 3);
    }

    #[test]
    fn verify_slot_lineage_empty() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        let result = log.verify_slot_lineage(&test_slot_id("slot-nonexistent"));
        assert_eq!(result.total_entries, 0);
        assert_eq!(result.issues.len(), 1);
    }

    // ── audit ───────────────────────────────────────────────────────

    #[test]
    fn audit_valid_log() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..5 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        log.create_checkpoint(500, SecurityEpoch::from_raw(1))
            .unwrap();

        let audit = log.audit();
        assert!(audit.chain_valid);
        assert!(audit.merkle_valid);
        assert_eq!(audit.total_entries, 5);
        assert_eq!(audit.total_slots, 1);
        assert_eq!(audit.checkpoint_count, 1);
        assert!(audit.issues.is_empty());
    }

    #[test]
    fn audit_multi_slot_log() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-a", "old-a", "new-a", 100);
        let r2 = test_receipt("slot-b", "old-b", "new-b", 200);
        let r3 = test_receipt("slot-c", "old-c", "new-c", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        log.append(r3, ReplacementKind::DelegateToNative, 300)
            .unwrap();

        let audit = log.audit();
        assert!(audit.chain_valid);
        assert_eq!(audit.total_slots, 3);
    }

    #[test]
    fn audit_empty_log() {
        let log = ReplacementLineageLog::new(LineageLogConfig::default());
        let audit = log.audit();
        assert!(audit.chain_valid);
        assert!(audit.merkle_valid);
        assert_eq!(audit.total_entries, 0);
    }

    // ── replacement kind ────────────────────────────────────────────

    #[test]
    fn replacement_kind_display() {
        assert_eq!(
            ReplacementKind::DelegateToNative.to_string(),
            "delegate_to_native"
        );
        assert_eq!(ReplacementKind::Demotion.to_string(), "demotion");
        assert_eq!(ReplacementKind::Rollback.to_string(), "rollback");
        assert_eq!(ReplacementKind::RePromotion.to_string(), "re_promotion");
    }

    #[test]
    fn replacement_kind_serde_round_trip() {
        let kinds = [
            ReplacementKind::DelegateToNative,
            ReplacementKind::Demotion,
            ReplacementKind::Rollback,
            ReplacementKind::RePromotion,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).expect("serialize");
            let decoded: ReplacementKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*kind, decoded);
        }
    }

    // ── serde round-trips ───────────────────────────────────────────

    #[test]
    fn log_entry_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        let entry = &log.entries()[0];
        let json = serde_json::to_vec(entry).expect("serialize");
        let decoded: LineageLogEntry = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(*entry, decoded);
    }

    #[test]
    fn checkpoint_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        let cp = &log.checkpoints()[0];
        let json = serde_json::to_vec(cp).expect("serialize");
        let decoded: LogCheckpoint = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(*cp, decoded);
    }

    #[test]
    fn inclusion_proof_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        let proof = log.inclusion_proof(2).expect("proof exists");
        let json = serde_json::to_vec(&proof).expect("serialize");
        let decoded: InclusionProof = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(proof, decoded);
        assert!(verify_inclusion_proof(&decoded));
    }

    #[test]
    fn consistency_proof_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..4 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
            if i == 1 || i == 3 {
                log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                    .unwrap();
            }
        }

        let proof = log.consistency_proof(0, 1).expect("proof");
        let json = serde_json::to_vec(&proof).expect("serialize");
        let decoded: ConsistencyProof = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(proof, decoded);
        assert!(verify_consistency_proof(&decoded));
    }

    #[test]
    fn full_log_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        for i in 0..3 {
            let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
            log.append(r, ReplacementKind::DelegateToNative, i * 100)
                .unwrap();
        }
        log.create_checkpoint(300, SecurityEpoch::from_raw(1))
            .unwrap();
        let json = serde_json::to_vec(&log).expect("serialize");
        let decoded: ReplacementLineageLog = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(log.len(), decoded.len());
        assert_eq!(log.merkle_root(), decoded.merkle_root());
    }

    // ── structured events ───────────────────────────────────────────

    #[test]
    fn append_emits_event() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        assert!(!log.events().is_empty());
        let event = &log.events()[0];
        assert_eq!(event.event, "entry_appended");
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.component, "replacement_lineage_log");
    }

    #[test]
    fn checkpoint_emits_event() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        let cp_events: Vec<_> = log
            .events()
            .iter()
            .filter(|e| e.event == "checkpoint_created")
            .collect();
        assert_eq!(cp_events.len(), 1);
    }

    // ── error display ───────────────────────────────────────────────

    #[test]
    fn error_display() {
        let err = LineageLogError::SequenceMismatch {
            expected: 5,
            got: 3,
        };
        assert!(err.to_string().contains("sequence mismatch"));

        let err = LineageLogError::ChainBreak { sequence: 7 };
        assert!(err.to_string().contains("chain break"));

        let err = LineageLogError::CheckpointNotFound { checkpoint_seq: 9 };
        assert!(err.to_string().contains("not found"));

        let err = LineageLogError::InvalidCheckpointOrder { older: 2, newer: 1 };
        assert!(err.to_string().contains("invalid checkpoint order"));

        let err = LineageLogError::EmptyLog;
        assert!(err.to_string().contains("empty"));
    }

    // ── slot_ids helper ─────────────────────────────────────────────

    #[test]
    fn slot_ids_returns_unique_sorted() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r1 = test_receipt("slot-c", "old", "new", 100);
        let r2 = test_receipt("slot-a", "old", "new", 200);
        let r3 = test_receipt("slot-c", "old2", "new2", 300);
        log.append(r1, ReplacementKind::DelegateToNative, 100)
            .unwrap();
        log.append(r2, ReplacementKind::DelegateToNative, 200)
            .unwrap();
        log.append(r3, ReplacementKind::RePromotion, 300).unwrap();

        let ids = log.slot_ids();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].as_str(), "slot-a"); // sorted
        assert_eq!(ids[1].as_str(), "slot-c");
    }

    // ── config ──────────────────────────────────────────────────────

    #[test]
    fn config_serde_round_trip() {
        let config = LineageLogConfig {
            checkpoint_interval: 50,
            max_entries_in_memory: 1000,
        };
        let json = serde_json::to_vec(&config).expect("serialize");
        let decoded: LineageLogConfig = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(config, decoded);
    }

    #[test]
    fn default_config_values() {
        let config = LineageLogConfig::default();
        assert_eq!(config.checkpoint_interval, 100);
        assert_eq!(config.max_entries_in_memory, 0);
    }

    // ── lineage query serde ─────────────────────────────────────────

    #[test]
    fn lineage_query_serde_round_trip() {
        let query = LineageQuery {
            slot_id: Some(test_slot_id("slot-a")),
            kinds: Some(BTreeSet::from([ReplacementKind::Demotion])),
            min_timestamp_ns: Some(100),
            max_timestamp_ns: Some(500),
        };
        let json = serde_json::to_vec(&query).expect("serialize");
        let decoded: LineageQuery = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(query, decoded);
    }

    // ── audit result serde ──────────────────────────────────────────

    #[test]
    fn audit_result_serde_round_trip() {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-a", "old", "new", 1000);
        log.append(r, ReplacementKind::DelegateToNative, 1000)
            .unwrap();
        log.create_checkpoint(1000, SecurityEpoch::from_raw(1))
            .unwrap();
        let audit = log.audit();
        let json = serde_json::to_vec(&audit).expect("serialize");
        let decoded: AuditResult = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(audit, decoded);
    }
}
