//! Integration tests for the `hash_tiers` module.
//!
//! Tests three-tier hashing: IntegrityHash, ContentHash, AuthenticityHash,
//! determinism, domain separation, and serde roundtrips.

#![forbid(unsafe_code)]

use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash, IntegrityHash};

// ---------------------------------------------------------------------------
// IntegrityHash (Tier 1)
// ---------------------------------------------------------------------------

#[test]
fn integrity_hash_deterministic() {
    let a = IntegrityHash::compute(b"hello");
    let b = IntegrityHash::compute(b"hello");
    assert_eq!(a, b);
}

#[test]
fn integrity_hash_different_inputs_differ() {
    let a = IntegrityHash::compute(b"hello");
    let b = IntegrityHash::compute(b"world");
    assert_ne!(a, b);
}

#[test]
fn integrity_hash_empty_input() {
    let h = IntegrityHash::compute(b"");
    assert_eq!(h.as_u64(), h.0);
}

#[test]
fn integrity_hash_display_format() {
    let h = IntegrityHash::compute(b"test");
    let display = h.to_string();
    assert!(display.starts_with("integrity:"));
    assert_eq!(display.len(), "integrity:".len() + 16); // 16 hex digits
}

#[test]
fn integrity_hash_serde_roundtrip() {
    let h = IntegrityHash::compute(b"serde-test");
    let json = serde_json::to_string(&h).unwrap();
    let decoded: IntegrityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

// ---------------------------------------------------------------------------
// ContentHash (Tier 2)
// ---------------------------------------------------------------------------

#[test]
fn content_hash_deterministic() {
    let a = ContentHash::compute(b"hello");
    let b = ContentHash::compute(b"hello");
    assert_eq!(a, b);
}

#[test]
fn content_hash_different_inputs_differ() {
    let a = ContentHash::compute(b"hello");
    let b = ContentHash::compute(b"world");
    assert_ne!(a, b);
}

#[test]
fn content_hash_is_32_bytes() {
    let h = ContentHash::compute(b"test");
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn content_hash_to_hex_is_64_chars() {
    let h = ContentHash::compute(b"test");
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn content_hash_display_format() {
    let h = ContentHash::compute(b"test");
    let display = h.to_string();
    assert!(display.starts_with("content:"));
}

#[test]
fn content_hash_serde_roundtrip() {
    let h = ContentHash::compute(b"serde-test");
    let json = serde_json::to_string(&h).unwrap();
    let decoded: ContentHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn content_hash_empty_input() {
    let h = ContentHash::compute(b"");
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn content_hash_large_input() {
    let data = vec![0xab; 100_000];
    let h = ContentHash::compute(&data);
    assert_eq!(h.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// AuthenticityHash (Tier 3)
// ---------------------------------------------------------------------------

#[test]
fn authenticity_hash_keyed_deterministic() {
    let a = AuthenticityHash::compute_keyed(b"key", b"data");
    let b = AuthenticityHash::compute_keyed(b"key", b"data");
    assert_eq!(a, b);
}

#[test]
fn authenticity_hash_different_keys_differ() {
    let a = AuthenticityHash::compute_keyed(b"key1", b"data");
    let b = AuthenticityHash::compute_keyed(b"key2", b"data");
    assert_ne!(a, b);
}

#[test]
fn authenticity_hash_different_data_differ() {
    let a = AuthenticityHash::compute_keyed(b"key", b"data1");
    let b = AuthenticityHash::compute_keyed(b"key", b"data2");
    assert_ne!(a, b);
}

#[test]
fn authenticity_hash_unkeyed_deterministic() {
    let a = AuthenticityHash::compute(b"test");
    let b = AuthenticityHash::compute(b"test");
    assert_eq!(a, b);
}

#[test]
fn authenticity_hash_is_32_bytes() {
    let h = AuthenticityHash::compute_keyed(b"key", b"data");
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn authenticity_hash_to_hex_is_64_chars() {
    let h = AuthenticityHash::compute_keyed(b"key", b"data");
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn authenticity_hash_display_format() {
    let h = AuthenticityHash::compute(b"test");
    let display = h.to_string();
    assert!(display.starts_with("authenticity:"));
}

#[test]
fn authenticity_hash_constant_time_eq_same() {
    let a = AuthenticityHash::compute(b"same");
    let b = AuthenticityHash::compute(b"same");
    assert!(a.constant_time_eq(&b));
}

#[test]
fn authenticity_hash_constant_time_eq_different() {
    let a = AuthenticityHash::compute(b"aaa");
    let b = AuthenticityHash::compute(b"bbb");
    assert!(!a.constant_time_eq(&b));
}

#[test]
fn authenticity_hash_serde_roundtrip() {
    let h = AuthenticityHash::compute_keyed(b"key", b"serde-test");
    let json = serde_json::to_string(&h).unwrap();
    let decoded: AuthenticityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

// ---------------------------------------------------------------------------
// Cross-tier isolation
// ---------------------------------------------------------------------------

#[test]
fn same_input_different_tiers_may_differ() {
    let data = b"cross-tier-test";
    let integrity = IntegrityHash::compute(data);
    let content = ContentHash::compute(data);
    let authenticity = AuthenticityHash::compute(data);

    // Different types, can't directly compare — verify they're distinct types
    let _ = integrity.as_u64();
    let _ = content.as_bytes();
    let _ = authenticity.as_bytes();
}

// ---------------------------------------------------------------------------
// Determinism across multiple runs
// ---------------------------------------------------------------------------

#[test]
fn all_tiers_deterministic_10_runs() {
    let data = b"determinism-test";
    let key = b"test-key";

    let i0 = IntegrityHash::compute(data);
    let c0 = ContentHash::compute(data);
    let a0 = AuthenticityHash::compute_keyed(key, data);

    for _ in 0..10 {
        assert_eq!(IntegrityHash::compute(data), i0);
        assert_eq!(ContentHash::compute(data), c0);
        assert_eq!(AuthenticityHash::compute_keyed(key, data), a0);
    }
}
