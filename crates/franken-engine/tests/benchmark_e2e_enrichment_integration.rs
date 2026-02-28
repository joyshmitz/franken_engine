#![forbid(unsafe_code)]
//! Enrichment integration tests for `benchmark_e2e`.
//!
//! Adds as_str exactness, Debug distinctness, default values, PRNG
//! determinism, regression detection, and benchmark runner coverage
//! beyond the existing 29 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::benchmark_e2e::{
    BENCHMARK_E2E_COMPONENT, BENCHMARK_E2E_SCHEMA_VERSION, BenchmarkFamily, BenchmarkSuiteConfig,
    LatencyDistribution, MIN_START_BUDGET_MILLIONTHS, RegressionThresholds, ScaleProfile,
    Xorshift64, detect_regression, run_benchmark, run_benchmark_suite,
};

// ===========================================================================
// 1) ScaleProfile — exact as_str
// ===========================================================================

#[test]
fn scale_profile_as_str_exact() {
    assert_eq!(ScaleProfile::Small.as_str(), "S");
    assert_eq!(ScaleProfile::Medium.as_str(), "M");
    assert_eq!(ScaleProfile::Large.as_str(), "L");
}

#[test]
fn scale_profile_extension_count() {
    assert_eq!(ScaleProfile::Small.extension_count(), 10);
    assert_eq!(ScaleProfile::Medium.extension_count(), 50);
    assert_eq!(ScaleProfile::Large.extension_count(), 200);
}

#[test]
fn scale_profile_iterations() {
    assert_eq!(ScaleProfile::Small.iterations(), 100);
    assert_eq!(ScaleProfile::Medium.iterations(), 500);
    assert_eq!(ScaleProfile::Large.iterations(), 2_000);
}

// ===========================================================================
// 2) BenchmarkFamily — exact as_str / all()
// ===========================================================================

#[test]
fn benchmark_family_as_str_all_distinct() {
    let all = BenchmarkFamily::all();
    let strs: Vec<&str> = all.iter().map(|f| f.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), all.len());
}

#[test]
fn benchmark_family_all_count() {
    assert_eq!(BenchmarkFamily::all().len(), 5);
}

#[test]
fn benchmark_family_default_weights_sum_to_one() {
    let total: f64 = BenchmarkFamily::all()
        .iter()
        .map(|f| f.default_weight())
        .sum();
    assert!(
        (total - 1.0).abs() < 0.001,
        "weights should sum to ~1.0, got {total}"
    );
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_scale_profile() {
    let variants = [
        format!("{:?}", ScaleProfile::Small),
        format!("{:?}", ScaleProfile::Medium),
        format!("{:?}", ScaleProfile::Large),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_benchmark_family() {
    let variants: Vec<String> = BenchmarkFamily::all()
        .iter()
        .map(|f| format!("{f:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 4) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(BENCHMARK_E2E_COMPONENT, "benchmark_e2e");
    assert_eq!(
        BENCHMARK_E2E_SCHEMA_VERSION,
        "franken-engine.benchmark-e2e.v1"
    );
    assert_eq!(MIN_START_BUDGET_MILLIONTHS, 1_000);
}

// ===========================================================================
// 5) RegressionThresholds — default
// ===========================================================================

#[test]
fn regression_thresholds_default() {
    let t = RegressionThresholds::default();
    assert!((t.throughput_regression_pct - 5.0).abs() < 0.001);
    assert!((t.p95_latency_regression_pct - 10.0).abs() < 0.001);
    assert!((t.p99_latency_regression_pct - 15.0).abs() < 0.001);
}

// ===========================================================================
// 6) BenchmarkSuiteConfig — default
// ===========================================================================

#[test]
fn suite_config_default() {
    let config = BenchmarkSuiteConfig::default();
    assert_eq!(config.seed, 42);
    assert_eq!(config.profiles.len(), 3);
    assert_eq!(config.families.len(), 5);
}

// ===========================================================================
// 7) Xorshift64 — determinism
// ===========================================================================

#[test]
fn xorshift64_same_seed_same_sequence() {
    let mut rng1 = Xorshift64::new(42);
    let mut rng2 = Xorshift64::new(42);
    for _ in 0..20 {
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}

#[test]
fn xorshift64_zero_seed_works() {
    let mut rng = Xorshift64::new(0);
    let v = rng.next_u64();
    assert_ne!(v, 0);
}

#[test]
fn xorshift64_different_seeds_differ() {
    let mut rng1 = Xorshift64::new(1);
    let mut rng2 = Xorshift64::new(2);
    let v1 = rng1.next_u64();
    let v2 = rng2.next_u64();
    assert_ne!(v1, v2);
}

#[test]
fn xorshift64_next_usize_in_bound() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        let v = rng.next_usize(10);
        assert!(v < 10);
    }
}

// ===========================================================================
// 8) LatencyDistribution — from_samples
// ===========================================================================

#[test]
fn latency_distribution_from_samples() {
    let mut samples = vec![100, 200, 300, 400, 500];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 100);
    assert_eq!(dist.max_us, 500);
    assert_eq!(dist.sample_count, 5);
}

#[test]
fn latency_distribution_single_sample() {
    let mut samples = vec![42];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 42);
    assert_eq!(dist.max_us, 42);
    assert_eq!(dist.p50_us, 42);
}

// ===========================================================================
// 9) run_benchmark — produces measurements
// ===========================================================================

#[test]
fn run_benchmark_produces_measurement() {
    let m = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.duration_us > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
}

#[test]
fn run_benchmark_deterministic() {
    let m1 = run_benchmark(BenchmarkFamily::CapabilityChurn, ScaleProfile::Small, 42);
    let m2 = run_benchmark(BenchmarkFamily::CapabilityChurn, ScaleProfile::Small, 42);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.total_operations, m2.total_operations);
}

// ===========================================================================
// 10) detect_regression
// ===========================================================================

#[test]
fn detect_regression_no_regression() {
    let m1 = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    let m2 = m1.clone();
    let thresholds = RegressionThresholds::default();
    let result = detect_regression(&m2, &m1, &thresholds);
    assert!(!result.blocked);
    assert!(result.blockers.is_empty());
}

// ===========================================================================
// 11) run_benchmark_suite
// ===========================================================================

#[test]
fn run_suite_default_config() {
    let config = BenchmarkSuiteConfig {
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        ..BenchmarkSuiteConfig::default()
    };
    let result = run_benchmark_suite(&config);
    assert!(!result.measurements.is_empty());
    assert!(result.total_operations > 0);
    assert!(!result.events.is_empty());
}
