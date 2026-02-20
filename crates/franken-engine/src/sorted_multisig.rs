//! Deterministic ordering for multi-signature arrays.
//!
//! Enforces that signature arrays are sorted by canonical public key
//! ordering before any verification. The `SortedSignatureArray` newtype
//! can only be constructed in sorted order, eliminating signature-array
//! permutation as a source of non-determinism.
//!
//! Canonical ordering: lexicographic byte ordering of the serialized
//! public key (for same-algorithm keys).
//!
//! Plan references: Section 10.10 item 5, 9E.2 ("Multi-signature vectors
//! must be sorted by stable signer key ordering before verification").

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::signature_preimage::{Signature, SignatureError, VerificationKey};

// ---------------------------------------------------------------------------
// SignerSignature — a (key, signature) pair
// ---------------------------------------------------------------------------

/// A single signer's contribution: verification key + signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSignature {
    /// The signer's verification key.
    pub signer: VerificationKey,
    /// The signature produced by this signer.
    pub signature: Signature,
}

impl SignerSignature {
    /// Create a new signer-signature pair.
    pub fn new(signer: VerificationKey, signature: Signature) -> Self {
        Self { signer, signature }
    }
}

// Ordering by verification key bytes (lexicographic).
impl PartialOrd for SignerSignature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignerSignature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.signer.0.cmp(&other.signer.0)
    }
}

// ---------------------------------------------------------------------------
// MultiSigError
// ---------------------------------------------------------------------------

/// Errors from multi-signature operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiSigError {
    /// Signature array is not sorted.
    UnsortedSignatureArray {
        position: usize,
        prev_key_hex: String,
        current_key_hex: String,
    },
    /// Duplicate signer key in array.
    DuplicateSignerKey {
        key_hex: String,
        positions: (usize, usize),
    },
    /// Quorum not met.
    QuorumNotMet {
        required: usize,
        valid: usize,
        total: usize,
    },
    /// Empty signature array.
    EmptyArray,
    /// Quorum threshold is zero.
    ZeroQuorumThreshold,
    /// Quorum threshold exceeds signer count.
    ThresholdExceedsSignerCount {
        threshold: usize,
        signer_count: usize,
    },
    /// Underlying signature verification error.
    SignatureError { detail: String },
}

impl fmt::Display for MultiSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsortedSignatureArray {
                position,
                prev_key_hex,
                current_key_hex,
            } => write!(
                f,
                "unsorted at position {position}: {prev_key_hex} >= {current_key_hex}"
            ),
            Self::DuplicateSignerKey { key_hex, positions } => write!(
                f,
                "duplicate signer key {key_hex} at positions {} and {}",
                positions.0, positions.1
            ),
            Self::QuorumNotMet {
                required,
                valid,
                total,
            } => write!(
                f,
                "quorum not met: {valid}/{total} valid, {required} required"
            ),
            Self::EmptyArray => write!(f, "empty signature array"),
            Self::ZeroQuorumThreshold => write!(f, "quorum threshold is zero"),
            Self::ThresholdExceedsSignerCount {
                threshold,
                signer_count,
            } => write!(
                f,
                "threshold {threshold} exceeds signer count {signer_count}"
            ),
            Self::SignatureError { detail } => write!(f, "signature error: {detail}"),
        }
    }
}

impl std::error::Error for MultiSigError {}

// ---------------------------------------------------------------------------
// SortedSignatureArray — the core invariant-enforcing type
// ---------------------------------------------------------------------------

/// A signature array that is guaranteed to be sorted by signer key
/// in lexicographic byte order with no duplicates.
///
/// This type can only be constructed via `new()` or `from_unsorted()`,
/// both of which enforce the invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortedSignatureArray {
    /// The sorted array of signer-signature pairs.
    entries: Vec<SignerSignature>,
}

impl SortedSignatureArray {
    /// Create from an already-sorted array, verifying the invariant.
    ///
    /// Returns `Err` if the array is not sorted or contains duplicates.
    pub fn new(entries: Vec<SignerSignature>) -> Result<Self, MultiSigError> {
        if entries.is_empty() {
            return Err(MultiSigError::EmptyArray);
        }
        verify_sorted_no_duplicates(&entries)?;
        Ok(Self { entries })
    }

    /// Create from an unsorted array by sorting it.
    ///
    /// Returns `Err` if there are duplicate signer keys.
    pub fn from_unsorted(mut entries: Vec<SignerSignature>) -> Result<Self, MultiSigError> {
        if entries.is_empty() {
            return Err(MultiSigError::EmptyArray);
        }
        entries.sort();
        // Check for duplicates after sorting.
        for i in 1..entries.len() {
            if entries[i].signer == entries[i - 1].signer {
                return Err(MultiSigError::DuplicateSignerKey {
                    key_hex: entries[i].signer.to_hex(),
                    positions: (i - 1, i),
                });
            }
        }
        Ok(Self { entries })
    }

    /// Add a signature in sorted position.
    ///
    /// Returns `Err` if the signer key already exists.
    pub fn insert(&mut self, entry: SignerSignature) -> Result<(), MultiSigError> {
        // Check for duplicate.
        if let Some(pos) = self.entries.iter().position(|e| e.signer == entry.signer) {
            return Err(MultiSigError::DuplicateSignerKey {
                key_hex: entry.signer.to_hex(),
                positions: (pos, self.entries.len()),
            });
        }
        // Find insertion point.
        let pos = self
            .entries
            .binary_search_by(|e| e.signer.0.cmp(&entry.signer.0))
            .unwrap_or_else(|p| p);
        self.entries.insert(pos, entry);
        Ok(())
    }

    /// Number of signatures in the array.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the array is empty (should never be true after construction).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Access the sorted entries.
    pub fn entries(&self) -> &[SignerSignature] {
        &self.entries
    }

    /// Get the signer keys in sorted order.
    pub fn signer_keys(&self) -> Vec<&VerificationKey> {
        self.entries.iter().map(|e| &e.signer).collect()
    }

    /// Check if a specific signer key is present.
    pub fn contains_signer(&self, key: &VerificationKey) -> bool {
        self.entries
            .binary_search_by(|e| e.signer.0.cmp(&key.0))
            .is_ok()
    }

    /// Verify quorum: at least `threshold` signatures must be valid.
    ///
    /// `verify_fn` is called for each (signer, signature) pair to
    /// check validity. The function should verify the signature against
    /// the preimage using the given verification key.
    pub fn verify_quorum<F>(
        &self,
        threshold: usize,
        authorized_signers: &[VerificationKey],
        mut verify_fn: F,
    ) -> Result<QuorumResult, MultiSigError>
    where
        F: FnMut(&VerificationKey, &Signature) -> Result<(), SignatureError>,
    {
        if threshold == 0 {
            return Err(MultiSigError::ZeroQuorumThreshold);
        }

        let mut valid_count = 0usize;
        let mut invalid = Vec::new();
        let mut unauthorized = Vec::new();

        for entry in &self.entries {
            // Check if signer is in the authorized set.
            if !authorized_signers.iter().any(|k| k == &entry.signer) {
                unauthorized.push(entry.signer.clone());
                continue;
            }

            match verify_fn(&entry.signer, &entry.signature) {
                Ok(()) => valid_count += 1,
                Err(e) => invalid.push((entry.signer.clone(), e.to_string())),
            }
        }

        let quorum_met = valid_count >= threshold;
        let result = QuorumResult {
            quorum_met,
            valid_count,
            invalid_count: invalid.len(),
            unauthorized_count: unauthorized.len(),
            total: self.entries.len(),
            threshold,
            invalid_signers: invalid,
            unauthorized_signers: unauthorized,
        };

        if quorum_met {
            Ok(result)
        } else {
            Err(MultiSigError::QuorumNotMet {
                required: threshold,
                valid: valid_count,
                total: self.entries.len(),
            })
        }
    }
}

/// Result of a quorum verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumResult {
    /// Whether the quorum threshold was met.
    pub quorum_met: bool,
    /// Number of valid signatures from authorized signers.
    pub valid_count: usize,
    /// Number of invalid signatures.
    pub invalid_count: usize,
    /// Number of signatures from unauthorized signers.
    pub unauthorized_count: usize,
    /// Total number of signatures in the array.
    pub total: usize,
    /// The quorum threshold.
    pub threshold: usize,
    /// Details of invalid signatures.
    pub invalid_signers: Vec<(VerificationKey, String)>,
    /// Keys of unauthorized signers.
    pub unauthorized_signers: Vec<VerificationKey>,
}

impl fmt::Display for QuorumResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "quorum: {}/{} valid (threshold {}), {} invalid, {} unauthorized",
            self.valid_count,
            self.total,
            self.threshold,
            self.invalid_count,
            self.unauthorized_count
        )
    }
}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

/// Verify that a signature array is sorted and has no duplicates.
///
/// Uses a single linear scan (O(n)) rather than re-sorting.
fn verify_sorted_no_duplicates(entries: &[SignerSignature]) -> Result<(), MultiSigError> {
    for i in 1..entries.len() {
        let prev = &entries[i - 1].signer.0;
        let curr = &entries[i].signer.0;
        match prev.cmp(curr) {
            std::cmp::Ordering::Less => {} // correct order
            std::cmp::Ordering::Equal => {
                return Err(MultiSigError::DuplicateSignerKey {
                    key_hex: entries[i].signer.to_hex(),
                    positions: (i - 1, i),
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(MultiSigError::UnsortedSignatureArray {
                    position: i,
                    prev_key_hex: entries[i - 1].signer.to_hex(),
                    current_key_hex: entries[i].signer.to_hex(),
                });
            }
        }
    }
    Ok(())
}

/// Verify that a raw array of signer-signature pairs is sorted.
///
/// Standalone check function for pre-validation at trust boundaries.
pub fn is_sorted(entries: &[SignerSignature]) -> Result<(), MultiSigError> {
    if entries.is_empty() {
        return Err(MultiSigError::EmptyArray);
    }
    verify_sorted_no_duplicates(entries)
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Events emitted during multi-sig operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSigEvent {
    pub event_type: MultiSigEventType,
    pub trace_id: String,
}

/// Types of multi-sig events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiSigEventType {
    /// Array created with sorted entries.
    ArrayCreated { signer_count: usize },
    /// Signature inserted in sorted position.
    SignatureInserted { signer_hex: String },
    /// Quorum verification succeeded.
    QuorumVerified {
        valid: usize,
        threshold: usize,
        total: usize,
    },
    /// Quorum verification failed.
    QuorumFailed {
        valid: usize,
        threshold: usize,
        total: usize,
    },
    /// Sorting invariant violation detected.
    SortingViolation { detail: String },
    /// Duplicate signer detected.
    DuplicateSigner { key_hex: String },
}

impl fmt::Display for MultiSigEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayCreated { signer_count } => {
                write!(f, "array created with {signer_count} signers")
            }
            Self::SignatureInserted { signer_hex } => {
                write!(f, "signature inserted for {signer_hex}")
            }
            Self::QuorumVerified {
                valid,
                threshold,
                total,
            } => write!(
                f,
                "quorum verified: {valid}/{total} (threshold {threshold})"
            ),
            Self::QuorumFailed {
                valid,
                threshold,
                total,
            } => write!(f, "quorum failed: {valid}/{total} (threshold {threshold})"),
            Self::SortingViolation { detail } => {
                write!(f, "sorting violation: {detail}")
            }
            Self::DuplicateSigner { key_hex } => {
                write!(f, "duplicate signer: {key_hex}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MultiSigContext — convenience wrapper with event tracking
// ---------------------------------------------------------------------------

/// Context for multi-signature operations with audit event tracking.
#[derive(Debug)]
pub struct MultiSigContext {
    events: Vec<MultiSigEvent>,
}

impl MultiSigContext {
    /// Create a new context.
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Create a sorted array from unsorted entries, tracking events.
    pub fn create_sorted(
        &mut self,
        entries: Vec<SignerSignature>,
        trace_id: &str,
    ) -> Result<SortedSignatureArray, MultiSigError> {
        match SortedSignatureArray::from_unsorted(entries) {
            Ok(arr) => {
                self.events.push(MultiSigEvent {
                    event_type: MultiSigEventType::ArrayCreated {
                        signer_count: arr.len(),
                    },
                    trace_id: trace_id.to_string(),
                });
                Ok(arr)
            }
            Err(e) => {
                let event_type = match &e {
                    MultiSigError::DuplicateSignerKey { key_hex, .. } => {
                        MultiSigEventType::DuplicateSigner {
                            key_hex: key_hex.clone(),
                        }
                    }
                    other => MultiSigEventType::SortingViolation {
                        detail: other.to_string(),
                    },
                };
                self.events.push(MultiSigEvent {
                    event_type,
                    trace_id: trace_id.to_string(),
                });
                Err(e)
            }
        }
    }

    /// Verify quorum with event tracking.
    pub fn verify_quorum<F>(
        &mut self,
        array: &SortedSignatureArray,
        threshold: usize,
        authorized_signers: &[VerificationKey],
        verify_fn: F,
        trace_id: &str,
    ) -> Result<QuorumResult, MultiSigError>
    where
        F: FnMut(&VerificationKey, &Signature) -> Result<(), SignatureError>,
    {
        match array.verify_quorum(threshold, authorized_signers, verify_fn) {
            Ok(result) => {
                self.events.push(MultiSigEvent {
                    event_type: MultiSigEventType::QuorumVerified {
                        valid: result.valid_count,
                        threshold: result.threshold,
                        total: result.total,
                    },
                    trace_id: trace_id.to_string(),
                });
                Ok(result)
            }
            Err(e) => {
                if let MultiSigError::QuorumNotMet {
                    valid,
                    required,
                    total,
                } = &e
                {
                    self.events.push(MultiSigEvent {
                        event_type: MultiSigEventType::QuorumFailed {
                            valid: *valid,
                            threshold: *required,
                            total: *total,
                        },
                        trace_id: trace_id.to_string(),
                    });
                }
                Err(e)
            }
        }
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<MultiSigEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counts by type.
    pub fn event_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            let key = match &event.event_type {
                MultiSigEventType::ArrayCreated { .. } => "array_created",
                MultiSigEventType::SignatureInserted { .. } => "signature_inserted",
                MultiSigEventType::QuorumVerified { .. } => "quorum_verified",
                MultiSigEventType::QuorumFailed { .. } => "quorum_failed",
                MultiSigEventType::SortingViolation { .. } => "sorting_violation",
                MultiSigEventType::DuplicateSigner { .. } => "duplicate_signer",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }
}

impl Default for MultiSigContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_serde::{CanonicalValue, SchemaHash};
    use crate::engine_object_id::ObjectDomain;
    use crate::signature_preimage::{
        SIGNATURE_LEN, SIGNATURE_SENTINEL, SIGNING_KEY_LEN, SignatureContext, SignaturePreimage,
        SigningKey,
    };

    fn make_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; SIGNING_KEY_LEN])
    }

    fn make_sig_pair(seed: u8) -> (SigningKey, VerificationKey) {
        let sk = make_signing_key(seed);
        let vk = sk.verification_key();
        (sk, vk)
    }

    /// Test object for signing.
    struct TestObj {
        schema: SchemaHash,
        data: u64,
    }

    impl SignaturePreimage for TestObj {
        fn signature_domain(&self) -> ObjectDomain {
            ObjectDomain::PolicyObject
        }
        fn signature_schema(&self) -> &SchemaHash {
            &self.schema
        }
        fn unsigned_view(&self) -> CanonicalValue {
            let mut map = std::collections::BTreeMap::new();
            map.insert("data".to_string(), CanonicalValue::U64(self.data));
            map.insert(
                "signature".to_string(),
                CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
            );
            CanonicalValue::Map(map)
        }
    }

    fn test_obj() -> TestObj {
        TestObj {
            schema: SchemaHash::from_definition(b"test-multisig-v1"),
            data: 42,
        }
    }

    fn sign_with(sk: &SigningKey, obj: &TestObj) -> Signature {
        let mut ctx = SignatureContext::new();
        ctx.sign(obj, sk, "test").unwrap()
    }

    // -- Construction --

    #[test]
    fn sorted_array_from_sorted_entries() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let obj = test_obj();

        let mut entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        ];
        entries.sort();

        let arr = SortedSignatureArray::new(entries).unwrap();
        assert_eq!(arr.len(), 2);
        // Verify sorted order.
        assert!(arr.entries()[0].signer.0 < arr.entries()[1].signer.0);
    }

    #[test]
    fn from_unsorted_sorts_correctly() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let (sk3, vk3) = make_sig_pair(3);
        let obj = test_obj();

        // Insert in reverse order.
        let entries = vec![
            SignerSignature::new(vk3, sign_with(&sk3, &obj)),
            SignerSignature::new(vk1, sign_with(&sk1, &obj)),
            SignerSignature::new(vk2, sign_with(&sk2, &obj)),
        ];

        let arr = SortedSignatureArray::from_unsorted(entries).unwrap();
        assert_eq!(arr.len(), 3);

        // Verify sorted.
        for i in 1..arr.len() {
            assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
        }
    }

    #[test]
    fn empty_array_rejected() {
        let err = SortedSignatureArray::new(vec![]).unwrap_err();
        assert!(matches!(err, MultiSigError::EmptyArray));
    }

    #[test]
    fn from_unsorted_empty_rejected() {
        let err = SortedSignatureArray::from_unsorted(vec![]).unwrap_err();
        assert!(matches!(err, MultiSigError::EmptyArray));
    }

    // -- Duplicate detection --

    #[test]
    fn duplicate_signer_rejected_on_construction() {
        let (sk1, vk1) = make_sig_pair(1);
        let obj = test_obj();

        let entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        ];

        let err = SortedSignatureArray::from_unsorted(entries).unwrap_err();
        assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));
    }

    #[test]
    fn duplicate_signer_rejected_on_insert() {
        let (sk1, vk1) = make_sig_pair(1);
        let obj = test_obj();

        let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
        let mut arr = SortedSignatureArray::new(entries).unwrap();

        let err = arr
            .insert(SignerSignature::new(vk1, sign_with(&sk1, &obj)))
            .unwrap_err();
        assert!(matches!(err, MultiSigError::DuplicateSignerKey { .. }));
    }

    // -- Unsorted rejection --

    #[test]
    fn unsorted_array_rejected() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let obj = test_obj();

        let mut entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
        ];

        // Force reverse order if needed.
        if entries[0].signer.0 < entries[1].signer.0 {
            entries.swap(0, 1);
        }

        let err = SortedSignatureArray::new(entries).unwrap_err();
        assert!(matches!(err, MultiSigError::UnsortedSignatureArray { .. }));
    }

    // -- Insert maintains sorted order --

    #[test]
    fn insert_maintains_order() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let (sk3, vk3) = make_sig_pair(3);
        let obj = test_obj();

        // Start with two entries.
        let entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
        ];
        let mut arr = SortedSignatureArray::from_unsorted(entries).unwrap();

        // Insert middle entry.
        arr.insert(SignerSignature::new(vk2, sign_with(&sk2, &obj)))
            .unwrap();

        assert_eq!(arr.len(), 3);
        for i in 1..arr.len() {
            assert!(arr.entries()[i - 1].signer.0 < arr.entries()[i].signer.0);
        }
    }

    // -- Contains signer --

    #[test]
    fn contains_signer_works() {
        let (sk1, vk1) = make_sig_pair(1);
        let (_, vk2) = make_sig_pair(2);
        let obj = test_obj();

        let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
        let arr = SortedSignatureArray::new(entries).unwrap();

        assert!(arr.contains_signer(&vk1));
        assert!(!arr.contains_signer(&vk2));
    }

    // -- Quorum verification --

    #[test]
    fn quorum_verification_succeeds() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let (sk3, vk3) = make_sig_pair(3);
        let obj = test_obj();

        let entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
            SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
        ];
        let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

        let authorized = vec![vk1.clone(), vk2.clone(), vk3.clone()];
        let preimage = obj.preimage_bytes();

        let result = arr
            .verify_quorum(2, &authorized, |vk, sig| {
                crate::signature_preimage::verify_signature(vk, &preimage, sig)
            })
            .unwrap();

        assert!(result.quorum_met);
        assert_eq!(result.valid_count, 3);
        assert_eq!(result.threshold, 2);
    }

    #[test]
    fn quorum_fails_insufficient_valid() {
        let (sk1, vk1) = make_sig_pair(1);
        let (_sk2, vk2) = make_sig_pair(2);
        let obj = test_obj();

        // Put a garbage sig under sk2's key (invalid sig).
        let entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk2.clone(), Signature::from_bytes([0xAA; SIGNATURE_LEN])),
        ];
        let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

        let authorized = vec![vk1, vk2];
        let preimage = obj.preimage_bytes();

        let err = arr
            .verify_quorum(2, &authorized, |vk, sig| {
                crate::signature_preimage::verify_signature(vk, &preimage, sig)
            })
            .unwrap_err();

        assert!(matches!(err, MultiSigError::QuorumNotMet { .. }));
    }

    #[test]
    fn quorum_skips_unauthorized_signers() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let (sk3, vk3) = make_sig_pair(3);
        let obj = test_obj();

        let entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
            SignerSignature::new(vk3.clone(), sign_with(&sk3, &obj)),
        ];
        let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

        // Only vk1 and vk2 are authorized; vk3 is not.
        let authorized = vec![vk1, vk2];
        let preimage = obj.preimage_bytes();

        let result = arr
            .verify_quorum(2, &authorized, |vk, sig| {
                crate::signature_preimage::verify_signature(vk, &preimage, sig)
            })
            .unwrap();

        assert!(result.quorum_met);
        assert_eq!(result.valid_count, 2);
        assert_eq!(result.unauthorized_count, 1);
    }

    #[test]
    fn zero_quorum_threshold_rejected() {
        let (sk1, vk1) = make_sig_pair(1);
        let obj = test_obj();

        let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
        let arr = SortedSignatureArray::new(entries).unwrap();

        let err = arr.verify_quorum(0, &[vk1], |_, _| Ok(())).unwrap_err();
        assert!(matches!(err, MultiSigError::ZeroQuorumThreshold));
    }

    // -- is_sorted standalone check --

    #[test]
    fn is_sorted_accepts_sorted() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let obj = test_obj();

        let mut entries = vec![
            SignerSignature::new(vk1, sign_with(&sk1, &obj)),
            SignerSignature::new(vk2, sign_with(&sk2, &obj)),
        ];
        entries.sort();
        assert!(is_sorted(&entries).is_ok());
    }

    #[test]
    fn is_sorted_rejects_empty() {
        assert!(matches!(is_sorted(&[]), Err(MultiSigError::EmptyArray)));
    }

    // -- Serialization round-trip preserves sorting --

    #[test]
    fn serialization_preserves_sorted_order() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let obj = test_obj();

        let entries = vec![
            SignerSignature::new(vk1, sign_with(&sk1, &obj)),
            SignerSignature::new(vk2, sign_with(&sk2, &obj)),
        ];
        let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

        let json = serde_json::to_string(&arr).expect("serialize");
        let restored: SortedSignatureArray = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(arr, restored);
        // Verify still sorted.
        for i in 1..restored.entries().len() {
            assert!(restored.entries()[i - 1].signer.0 < restored.entries()[i].signer.0);
        }
    }

    // -- Event tracking --

    #[test]
    fn context_tracks_creation() {
        let (sk1, vk1) = make_sig_pair(1);
        let obj = test_obj();

        let mut ctx = MultiSigContext::new();
        let entries = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
        ctx.create_sorted(entries, "t-create").unwrap();

        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            MultiSigEventType::ArrayCreated { signer_count: 1 }
        ));
    }

    #[test]
    fn context_tracks_duplicate_on_create() {
        let (sk1, vk1) = make_sig_pair(1);
        let obj = test_obj();

        let mut ctx = MultiSigContext::new();
        let entries = vec![
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
            SignerSignature::new(vk1, sign_with(&sk1, &obj)),
        ];
        ctx.create_sorted(entries, "t-dup").unwrap_err();

        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            MultiSigEventType::DuplicateSigner { .. }
        ));
    }

    #[test]
    fn context_tracks_quorum_verified() {
        let (sk1, vk1) = make_sig_pair(1);
        let obj = test_obj();
        let preimage = obj.preimage_bytes();

        let mut ctx = MultiSigContext::new();
        let entries = vec![SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj))];
        let arr = ctx.create_sorted(entries, "t-q1").unwrap();

        ctx.verify_quorum(
            &arr,
            1,
            &[vk1],
            |vk, sig| crate::signature_preimage::verify_signature(vk, &preimage, sig),
            "t-q2",
        )
        .unwrap();

        let counts = ctx.event_counts();
        assert_eq!(counts.get("array_created"), Some(&1));
        assert_eq!(counts.get("quorum_verified"), Some(&1));
    }

    #[test]
    fn drain_events_clears() {
        let mut ctx = MultiSigContext::new();
        let (sk1, vk1) = make_sig_pair(1);
        let obj = test_obj();
        let entries = vec![SignerSignature::new(vk1, sign_with(&sk1, &obj))];
        ctx.create_sorted(entries, "t-drain").unwrap();
        assert_eq!(ctx.drain_events().len(), 1);
        assert_eq!(ctx.drain_events().len(), 0);
    }

    // -- Display --

    #[test]
    fn multisig_error_display() {
        let err = MultiSigError::QuorumNotMet {
            required: 3,
            valid: 1,
            total: 5,
        };
        assert!(err.to_string().contains("3"));
        assert!(err.to_string().contains("1"));

        assert_eq!(
            MultiSigError::EmptyArray.to_string(),
            "empty signature array"
        );
    }

    #[test]
    fn quorum_result_display() {
        let result = QuorumResult {
            quorum_met: true,
            valid_count: 2,
            invalid_count: 0,
            unauthorized_count: 1,
            total: 3,
            threshold: 2,
            invalid_signers: vec![],
            unauthorized_signers: vec![],
        };
        assert!(result.to_string().contains("2/3"));
    }

    #[test]
    fn event_type_display() {
        let evt = MultiSigEventType::ArrayCreated { signer_count: 3 };
        assert!(evt.to_string().contains("3"));
    }

    // -- Serialization --

    #[test]
    fn multisig_error_serialization_round_trip() {
        let errors = vec![
            MultiSigError::EmptyArray,
            MultiSigError::ZeroQuorumThreshold,
            MultiSigError::UnsortedSignatureArray {
                position: 1,
                prev_key_hex: "aa".to_string(),
                current_key_hex: "bb".to_string(),
            },
            MultiSigError::DuplicateSignerKey {
                key_hex: "cc".to_string(),
                positions: (0, 1),
            },
            MultiSigError::QuorumNotMet {
                required: 3,
                valid: 1,
                total: 5,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: MultiSigError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn quorum_result_serialization_round_trip() {
        let result = QuorumResult {
            quorum_met: true,
            valid_count: 2,
            invalid_count: 0,
            unauthorized_count: 0,
            total: 2,
            threshold: 2,
            invalid_signers: vec![],
            unauthorized_signers: vec![],
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: QuorumResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn multisig_event_serialization_round_trip() {
        let event = MultiSigEvent {
            event_type: MultiSigEventType::QuorumVerified {
                valid: 2,
                threshold: 2,
                total: 3,
            },
            trace_id: "t-ser".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: MultiSigEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Default --

    #[test]
    fn context_default() {
        let ctx = MultiSigContext::default();
        assert!(ctx.events.is_empty());
    }

    // -- Signer keys accessor --

    #[test]
    fn signer_keys_returns_sorted_keys() {
        let (sk1, vk1) = make_sig_pair(1);
        let (sk2, vk2) = make_sig_pair(2);
        let obj = test_obj();

        let entries = vec![
            SignerSignature::new(vk2.clone(), sign_with(&sk2, &obj)),
            SignerSignature::new(vk1.clone(), sign_with(&sk1, &obj)),
        ];
        let arr = SortedSignatureArray::from_unsorted(entries).unwrap();

        let keys = arr.signer_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].0 < keys[1].0);
    }
}
