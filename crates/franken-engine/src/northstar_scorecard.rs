//! North-Star Scorecard — objective metric stack and success scorecard
//! for FrankenEngine runtime.
//!
//! Tracks the key performance, correctness, and reliability metrics that
//! determine alpha/beta/GA readiness.  Every metric uses fixed-point
//! millionths (1_000_000 = 1.0) for deterministic cross-platform arithmetic.
//!
//! Scorecard dimensions:
//! - **Compatibility**: pass rate against the canonical React behavior corpus
//! - **Responsiveness**: input-to-paint latency (p50/p95/p99)
//! - **Render latency**: per-update latency distribution
//! - **Footprint**: bundle size + runtime memory usage
//! - **Fallback frequency**: how often safe-mode fallback fires
//! - **Rollback latency**: time from incident detection to safe-mode restore
//! - **Evidence completeness**: fraction of high-impact decisions with signed receipts
//!
//! Plan reference: FRX-01.2 (North-Star Scorecard).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Milestone — alpha / beta / GA
// ---------------------------------------------------------------------------

/// Release milestone for threshold evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Milestone {
    /// Internal prototype; relaxed thresholds.
    Alpha,
    /// External beta; tighter thresholds.
    Beta,
    /// General availability; full thresholds.
    Ga,
}

impl fmt::Display for Milestone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alpha => write!(f, "alpha"),
            Self::Beta => write!(f, "beta"),
            Self::Ga => write!(f, "ga"),
        }
    }
}

// ---------------------------------------------------------------------------
// MetricKind — the seven scorecard dimensions
// ---------------------------------------------------------------------------

/// Scorecard metric dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MetricKind {
    /// Compatibility pass rate (millionths; MILLION = 100%).
    CompatibilityPassRate,
    /// Input-to-paint responsiveness p99 (microseconds).
    ResponsivenessP99Us,
    /// Render/update latency p50 (microseconds).
    RenderLatencyP50Us,
    /// Render/update latency p95 (microseconds).
    RenderLatencyP95Us,
    /// Render/update latency p99 (microseconds).
    RenderLatencyP99Us,
    /// Bundle size (bytes).
    BundleSizeBytes,
    /// Runtime memory footprint (bytes).
    RuntimeMemoryBytes,
    /// Fallback frequency (millionths; MILLION = 100%).
    FallbackFrequency,
    /// Rollback latency p99 (microseconds).
    RollbackLatencyP99Us,
    /// Evidence completeness (millionths; MILLION = 100%).
    EvidenceCompleteness,
}

impl MetricKind {
    pub const ALL: [MetricKind; 10] = [
        MetricKind::CompatibilityPassRate,
        MetricKind::ResponsivenessP99Us,
        MetricKind::RenderLatencyP50Us,
        MetricKind::RenderLatencyP95Us,
        MetricKind::RenderLatencyP99Us,
        MetricKind::BundleSizeBytes,
        MetricKind::RuntimeMemoryBytes,
        MetricKind::FallbackFrequency,
        MetricKind::RollbackLatencyP99Us,
        MetricKind::EvidenceCompleteness,
    ];

    /// Whether higher values are better for this metric.
    pub fn higher_is_better(&self) -> bool {
        matches!(
            self,
            MetricKind::CompatibilityPassRate | MetricKind::EvidenceCompleteness
        )
    }
}

impl fmt::Display for MetricKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CompatibilityPassRate => "compatibility_pass_rate",
            Self::ResponsivenessP99Us => "responsiveness_p99_us",
            Self::RenderLatencyP50Us => "render_latency_p50_us",
            Self::RenderLatencyP95Us => "render_latency_p95_us",
            Self::RenderLatencyP99Us => "render_latency_p99_us",
            Self::BundleSizeBytes => "bundle_size_bytes",
            Self::RuntimeMemoryBytes => "runtime_memory_bytes",
            Self::FallbackFrequency => "fallback_frequency",
            Self::RollbackLatencyP99Us => "rollback_latency_p99_us",
            Self::EvidenceCompleteness => "evidence_completeness",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Threshold — per-milestone pass/fail boundary
// ---------------------------------------------------------------------------

/// Threshold definition for a single metric at a given milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Threshold {
    pub metric: MetricKind,
    pub milestone: Milestone,
    /// For "higher is better" metrics: value must be >= this.
    /// For "lower is better" metrics: value must be <= this.
    pub boundary: i64,
}

/// Default threshold set for alpha/beta/GA.
pub fn default_thresholds() -> Vec<Threshold> {
    vec![
        // -- Compatibility pass rate --
        Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000, // 80%
        },
        Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Beta,
            boundary: 950_000, // 95%
        },
        Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Ga,
            boundary: 990_000, // 99%
        },
        // -- Responsiveness p99 --
        Threshold {
            metric: MetricKind::ResponsivenessP99Us,
            milestone: Milestone::Alpha,
            boundary: 100_000, // 100ms
        },
        Threshold {
            metric: MetricKind::ResponsivenessP99Us,
            milestone: Milestone::Beta,
            boundary: 50_000, // 50ms
        },
        Threshold {
            metric: MetricKind::ResponsivenessP99Us,
            milestone: Milestone::Ga,
            boundary: 16_000, // 16ms (single frame)
        },
        // -- Render latency p50 --
        Threshold {
            metric: MetricKind::RenderLatencyP50Us,
            milestone: Milestone::Alpha,
            boundary: 10_000, // 10ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP50Us,
            milestone: Milestone::Beta,
            boundary: 5_000, // 5ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP50Us,
            milestone: Milestone::Ga,
            boundary: 2_000, // 2ms
        },
        // -- Render latency p95 --
        Threshold {
            metric: MetricKind::RenderLatencyP95Us,
            milestone: Milestone::Alpha,
            boundary: 50_000, // 50ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP95Us,
            milestone: Milestone::Beta,
            boundary: 16_000, // 16ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP95Us,
            milestone: Milestone::Ga,
            boundary: 8_000, // 8ms
        },
        // -- Render latency p99 --
        Threshold {
            metric: MetricKind::RenderLatencyP99Us,
            milestone: Milestone::Alpha,
            boundary: 100_000, // 100ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP99Us,
            milestone: Milestone::Beta,
            boundary: 50_000, // 50ms
        },
        Threshold {
            metric: MetricKind::RenderLatencyP99Us,
            milestone: Milestone::Ga,
            boundary: 16_000, // 16ms
        },
        // -- Bundle size --
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 10_000_000, // 10MB
        },
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Beta,
            boundary: 5_000_000, // 5MB
        },
        Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Ga,
            boundary: 2_000_000, // 2MB
        },
        // -- Runtime memory --
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Alpha,
            boundary: 256_000_000, // 256MB
        },
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Beta,
            boundary: 128_000_000, // 128MB
        },
        Threshold {
            metric: MetricKind::RuntimeMemoryBytes,
            milestone: Milestone::Ga,
            boundary: 64_000_000, // 64MB
        },
        // -- Fallback frequency --
        Threshold {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Alpha,
            boundary: 200_000, // 20%
        },
        Threshold {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Beta,
            boundary: 50_000, // 5%
        },
        Threshold {
            metric: MetricKind::FallbackFrequency,
            milestone: Milestone::Ga,
            boundary: 10_000, // 1%
        },
        // -- Rollback latency p99 --
        Threshold {
            metric: MetricKind::RollbackLatencyP99Us,
            milestone: Milestone::Alpha,
            boundary: 500_000, // 500ms
        },
        Threshold {
            metric: MetricKind::RollbackLatencyP99Us,
            milestone: Milestone::Beta,
            boundary: 250_000, // 250ms
        },
        Threshold {
            metric: MetricKind::RollbackLatencyP99Us,
            milestone: Milestone::Ga,
            boundary: 100_000, // 100ms
        },
        // -- Evidence completeness --
        Threshold {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Alpha,
            boundary: 500_000, // 50%
        },
        Threshold {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Beta,
            boundary: 900_000, // 90%
        },
        Threshold {
            metric: MetricKind::EvidenceCompleteness,
            milestone: Milestone::Ga,
            boundary: 990_000, // 99%
        },
    ]
}

// ---------------------------------------------------------------------------
// MetricSample — a single metric observation
// ---------------------------------------------------------------------------

/// A single metric observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSample {
    pub kind: MetricKind,
    pub value: i64,
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// MetricSummary — aggregated statistics for a single metric
// ---------------------------------------------------------------------------

/// Aggregated summary for a single metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSummary {
    pub kind: MetricKind,
    /// Number of observations.
    pub count: u64,
    /// Minimum observed value.
    pub min: i64,
    /// Maximum observed value.
    pub max: i64,
    /// Mean (millionths for rate-type metrics; raw for absolute-value metrics).
    pub mean: i64,
    /// p50 quantile.
    pub p50: i64,
    /// p95 quantile.
    pub p95: i64,
    /// p99 quantile.
    pub p99: i64,
}

// ---------------------------------------------------------------------------
// ScorecardEvaluation — pass/fail per metric per milestone
// ---------------------------------------------------------------------------

/// Result of evaluating a metric against a milestone threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdResult {
    /// Metric meets the threshold.
    Pass {
        metric: MetricKind,
        milestone: Milestone,
        value: i64,
        threshold: i64,
        headroom: i64,
    },
    /// Metric fails the threshold.
    Fail {
        metric: MetricKind,
        milestone: Milestone,
        value: i64,
        threshold: i64,
        shortfall: i64,
    },
    /// Insufficient data to evaluate.
    InsufficientData {
        metric: MetricKind,
        milestone: Milestone,
    },
}

impl ThresholdResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, ThresholdResult::Pass { .. })
    }
}

/// Full scorecard evaluation for a milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardEvaluation {
    pub milestone: Milestone,
    pub epoch: SecurityEpoch,
    pub results: Vec<ThresholdResult>,
    /// Overall pass: all metrics meet threshold.
    pub overall_pass: bool,
    /// Number of passing metrics.
    pub pass_count: u64,
    /// Number of failing metrics.
    pub fail_count: u64,
    /// Pass rate (millionths).
    pub pass_rate_millionths: i64,
}

// ---------------------------------------------------------------------------
// Scorecard — the tracker
// ---------------------------------------------------------------------------

/// Tracks all scorecard metrics and evaluates against milestone thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scorecard {
    /// Threshold definitions.
    thresholds: Vec<Threshold>,
    /// Observations per metric kind (sorted for quantile computation).
    observations: BTreeMap<MetricKind, Vec<i64>>,
    /// Maximum observations to keep per metric (ring-buffer semantics).
    max_observations: usize,
    /// Current epoch.
    epoch: SecurityEpoch,
}

impl Scorecard {
    /// Create with default thresholds.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            thresholds: default_thresholds(),
            observations: BTreeMap::new(),
            max_observations: 10_000,
            epoch,
        }
    }

    /// Create with custom thresholds.
    pub fn with_thresholds(thresholds: Vec<Threshold>, epoch: SecurityEpoch) -> Self {
        Self {
            thresholds,
            observations: BTreeMap::new(),
            max_observations: 10_000,
            epoch,
        }
    }

    /// Record a metric observation.
    pub fn record(&mut self, sample: MetricSample) {
        let values = self.observations.entry(sample.kind).or_default();
        // Insert in sorted order.
        let pos = values.partition_point(|&x| x < sample.value);
        values.insert(pos, sample.value);
        // Trim if over limit.
        if values.len() > self.max_observations {
            values.remove(0);
        }
        self.epoch = sample.epoch;
    }

    /// Get summary statistics for a metric.
    pub fn summary(&self, kind: MetricKind) -> Option<MetricSummary> {
        let values = self.observations.get(&kind)?;
        if values.is_empty() {
            return None;
        }
        let n = values.len();
        let min = values[0];
        let max = values[n - 1];
        let sum: i64 = values.iter().sum();
        let mean = sum / n as i64;
        let p50 = values[n / 2];
        let p95 = values[(n * 95) / 100];
        let p99 = values[(n * 99) / 100];

        Some(MetricSummary {
            kind,
            count: n as u64,
            min,
            max,
            mean,
            p50,
            p95,
            p99,
        })
    }

    /// Get the current value for a metric (latest observation's representative).
    ///
    /// For rate-type metrics (CompatibilityPassRate, FallbackFrequency,
    /// EvidenceCompleteness), returns the mean.
    /// For latency/size metrics, returns the appropriate quantile.
    pub fn current_value(&self, kind: MetricKind) -> Option<i64> {
        let summary = self.summary(kind)?;
        match kind {
            MetricKind::CompatibilityPassRate
            | MetricKind::FallbackFrequency
            | MetricKind::EvidenceCompleteness => Some(summary.mean),
            MetricKind::ResponsivenessP99Us
            | MetricKind::RenderLatencyP99Us
            | MetricKind::RollbackLatencyP99Us => Some(summary.p99),
            MetricKind::RenderLatencyP50Us => Some(summary.p50),
            MetricKind::RenderLatencyP95Us => Some(summary.p95),
            MetricKind::BundleSizeBytes | MetricKind::RuntimeMemoryBytes => Some(summary.max),
        }
    }

    /// Evaluate the scorecard against a specific milestone.
    pub fn evaluate(&self, milestone: Milestone) -> ScorecardEvaluation {
        let relevant: Vec<&Threshold> = self
            .thresholds
            .iter()
            .filter(|t| t.milestone == milestone)
            .collect();

        let mut results = Vec::new();
        let mut pass_count = 0u64;
        let mut fail_count = 0u64;

        for threshold in &relevant {
            let value = self.current_value(threshold.metric);
            match value {
                None => {
                    results.push(ThresholdResult::InsufficientData {
                        metric: threshold.metric,
                        milestone,
                    });
                    fail_count += 1;
                }
                Some(v) => {
                    let passes = if threshold.metric.higher_is_better() {
                        v >= threshold.boundary
                    } else {
                        v <= threshold.boundary
                    };
                    if passes {
                        let headroom = if threshold.metric.higher_is_better() {
                            v - threshold.boundary
                        } else {
                            threshold.boundary - v
                        };
                        results.push(ThresholdResult::Pass {
                            metric: threshold.metric,
                            milestone,
                            value: v,
                            threshold: threshold.boundary,
                            headroom,
                        });
                        pass_count += 1;
                    } else {
                        let shortfall = if threshold.metric.higher_is_better() {
                            threshold.boundary - v
                        } else {
                            v - threshold.boundary
                        };
                        results.push(ThresholdResult::Fail {
                            metric: threshold.metric,
                            milestone,
                            value: v,
                            threshold: threshold.boundary,
                            shortfall,
                        });
                        fail_count += 1;
                    }
                }
            }
        }

        let total = pass_count + fail_count;
        let pass_rate = if total == 0 {
            0
        } else {
            (pass_count as i64).saturating_mul(MILLION) / (total as i64)
        };

        ScorecardEvaluation {
            milestone,
            epoch: self.epoch,
            results,
            overall_pass: fail_count == 0 && pass_count > 0,
            pass_count,
            fail_count,
            pass_rate_millionths: pass_rate,
        }
    }

    /// Evaluate all milestones and return the highest passing one.
    pub fn highest_passing_milestone(&self) -> Option<Milestone> {
        for ms in [Milestone::Ga, Milestone::Beta, Milestone::Alpha] {
            let eval = self.evaluate(ms);
            if eval.overall_pass {
                return Some(ms);
            }
        }
        None
    }

    /// Get observation count for a metric.
    pub fn observation_count(&self, kind: MetricKind) -> u64 {
        self.observations
            .get(&kind)
            .map(|v| v.len() as u64)
            .unwrap_or(0)
    }

    /// Total observations across all metrics.
    pub fn total_observations(&self) -> u64 {
        self.observations.values().map(|v| v.len() as u64).sum()
    }

    /// Get the threshold definitions.
    pub fn thresholds(&self) -> &[Threshold] {
        &self.thresholds
    }

    /// Set the epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }

    /// Generate a human-readable report string.
    pub fn report(&self, milestone: Milestone) -> String {
        let eval = self.evaluate(milestone);
        let mut lines = Vec::new();
        lines.push(format!(
            "=== North-Star Scorecard: {milestone} (epoch {}) ===",
            eval.epoch.as_u64()
        ));
        lines.push(format!(
            "Overall: {} ({}/{} pass, {:.1}%)",
            if eval.overall_pass { "PASS" } else { "FAIL" },
            eval.pass_count,
            eval.pass_count + eval.fail_count,
            eval.pass_rate_millionths as f64 / 10_000.0,
        ));
        lines.push(String::new());
        for result in &eval.results {
            match result {
                ThresholdResult::Pass {
                    metric,
                    value,
                    threshold,
                    headroom,
                    ..
                } => {
                    lines.push(format!(
                        "  [PASS] {metric}: {value} (threshold: {threshold}, headroom: {headroom})"
                    ));
                }
                ThresholdResult::Fail {
                    metric,
                    value,
                    threshold,
                    shortfall,
                    ..
                } => {
                    lines.push(format!(
                        "  [FAIL] {metric}: {value} (threshold: {threshold}, shortfall: {shortfall})"
                    ));
                }
                ThresholdResult::InsufficientData { metric, .. } => {
                    lines.push(format!("  [----] {metric}: insufficient data"));
                }
            }
        }
        lines.join("\n")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn sample(kind: MetricKind, value: i64, ep: u64) -> MetricSample {
        MetricSample {
            kind,
            value,
            epoch: epoch(ep),
        }
    }

    // -----------------------------------------------------------------------
    // Milestone tests
    // -----------------------------------------------------------------------

    #[test]
    fn milestone_display() {
        assert_eq!(format!("{}", Milestone::Alpha), "alpha");
        assert_eq!(format!("{}", Milestone::Beta), "beta");
        assert_eq!(format!("{}", Milestone::Ga), "ga");
    }

    #[test]
    fn milestone_serde_roundtrip() {
        for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
            let json = serde_json::to_string(&ms).unwrap();
            let back: Milestone = serde_json::from_str(&json).unwrap();
            assert_eq!(ms, back);
        }
    }

    #[test]
    fn milestone_ordering() {
        assert!(Milestone::Alpha < Milestone::Beta);
        assert!(Milestone::Beta < Milestone::Ga);
    }

    // -----------------------------------------------------------------------
    // MetricKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn metric_kind_all_ten() {
        assert_eq!(MetricKind::ALL.len(), 10);
    }

    #[test]
    fn metric_kind_display() {
        assert_eq!(
            format!("{}", MetricKind::CompatibilityPassRate),
            "compatibility_pass_rate"
        );
        assert_eq!(
            format!("{}", MetricKind::RollbackLatencyP99Us),
            "rollback_latency_p99_us"
        );
    }

    #[test]
    fn metric_kind_higher_is_better() {
        assert!(MetricKind::CompatibilityPassRate.higher_is_better());
        assert!(MetricKind::EvidenceCompleteness.higher_is_better());
        assert!(!MetricKind::ResponsivenessP99Us.higher_is_better());
        assert!(!MetricKind::FallbackFrequency.higher_is_better());
        assert!(!MetricKind::BundleSizeBytes.higher_is_better());
    }

    #[test]
    fn metric_kind_serde_roundtrip() {
        for kind in &MetricKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: MetricKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // -----------------------------------------------------------------------
    // Threshold tests
    // -----------------------------------------------------------------------

    #[test]
    fn default_thresholds_cover_all_milestones() {
        let thresholds = default_thresholds();
        for ms in [Milestone::Alpha, Milestone::Beta, Milestone::Ga] {
            let count = thresholds.iter().filter(|t| t.milestone == ms).count();
            assert_eq!(count, 10, "milestone {ms} should have 10 thresholds");
        }
    }

    #[test]
    fn default_thresholds_serde_roundtrip() {
        let thresholds = default_thresholds();
        let json = serde_json::to_string(&thresholds).unwrap();
        let back: Vec<Threshold> = serde_json::from_str(&json).unwrap();
        assert_eq!(thresholds.len(), back.len());
    }

    #[test]
    fn thresholds_get_stricter_from_alpha_to_ga() {
        let thresholds = default_thresholds();
        // For CompatibilityPassRate (higher is better): alpha < beta < ga.
        let cpr: Vec<&Threshold> = thresholds
            .iter()
            .filter(|t| t.metric == MetricKind::CompatibilityPassRate)
            .collect();
        assert!(cpr[0].boundary < cpr[1].boundary);
        assert!(cpr[1].boundary < cpr[2].boundary);

        // For ResponsivenessP99Us (lower is better): alpha > beta > ga.
        let resp: Vec<&Threshold> = thresholds
            .iter()
            .filter(|t| t.metric == MetricKind::ResponsivenessP99Us)
            .collect();
        assert!(resp[0].boundary > resp[1].boundary);
        assert!(resp[1].boundary > resp[2].boundary);
    }

    // -----------------------------------------------------------------------
    // Scorecard basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_new_empty() {
        let sc = Scorecard::new(epoch(1));
        assert_eq!(sc.total_observations(), 0);
        assert_eq!(sc.thresholds().len(), 30); // 10 metrics × 3 milestones
    }

    #[test]
    fn scorecard_record_and_summary() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..100 {
            sc.record(sample(MetricKind::RenderLatencyP50Us, i * 100, 1));
        }
        let summary = sc.summary(MetricKind::RenderLatencyP50Us).unwrap();
        assert_eq!(summary.count, 100);
        assert_eq!(summary.min, 0);
        assert_eq!(summary.max, 9900);
        assert_eq!(summary.p50, 5000);
    }

    #[test]
    fn scorecard_no_data_returns_none() {
        let sc = Scorecard::new(epoch(1));
        assert!(sc.summary(MetricKind::BundleSizeBytes).is_none());
        assert!(sc.current_value(MetricKind::BundleSizeBytes).is_none());
    }

    #[test]
    fn scorecard_observation_count() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1000, 1));
        sc.record(sample(MetricKind::BundleSizeBytes, 2000, 1));
        assert_eq!(sc.observation_count(MetricKind::BundleSizeBytes), 2);
        assert_eq!(sc.observation_count(MetricKind::RuntimeMemoryBytes), 0);
    }

    // -----------------------------------------------------------------------
    // Evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_all_insufficient_data() {
        let sc = Scorecard::new(epoch(1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(!eval.overall_pass);
        assert_eq!(eval.fail_count, 10);
        assert_eq!(eval.pass_count, 0);
    }

    #[test]
    fn evaluate_passes_alpha_with_good_data() {
        let mut sc = Scorecard::new(epoch(1));
        // Set all metrics to values that pass alpha.
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1)); // 90% > 80%
            sc.record(sample(MetricKind::ResponsivenessP99Us, 50_000, 1)); // 50ms < 100ms
            sc.record(sample(MetricKind::RenderLatencyP50Us, 5_000, 1)); // 5ms < 10ms
            sc.record(sample(MetricKind::RenderLatencyP95Us, 20_000, 1)); // 20ms < 50ms
            sc.record(sample(MetricKind::RenderLatencyP99Us, 50_000, 1)); // 50ms < 100ms
            sc.record(sample(MetricKind::BundleSizeBytes, 5_000_000, 1)); // 5MB < 10MB
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000_000, 1)); // 100MB < 256MB
            sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1)); // 10% < 20%
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1)); // 200ms < 500ms
            sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1)); // 60% > 50%
        }
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(eval.overall_pass, "alpha should pass: {eval:?}");
        assert_eq!(eval.pass_count, 10);
        assert_eq!(eval.fail_count, 0);
    }

    #[test]
    fn evaluate_fails_ga_with_alpha_data() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 850_000, 1)); // 85% < 99%
            sc.record(sample(MetricKind::ResponsivenessP99Us, 80_000, 1)); // 80ms > 16ms
            sc.record(sample(MetricKind::RenderLatencyP50Us, 8_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 40_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 80_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 8_000_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 200_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 150_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 400_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 550_000, 1));
        }
        let eval = sc.evaluate(Milestone::Ga);
        assert!(!eval.overall_pass, "GA should fail with alpha-level data");
        assert!(eval.fail_count > 0);
    }

    #[test]
    fn highest_passing_milestone_none_initially() {
        let sc = Scorecard::new(epoch(1));
        assert_eq!(sc.highest_passing_milestone(), None);
    }

    #[test]
    fn highest_passing_milestone_alpha() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 50_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 5_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 20_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 50_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 5_000_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 100_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 100_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 200_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 600_000, 1));
        }
        assert_eq!(sc.highest_passing_milestone(), Some(Milestone::Alpha));
    }

    // -----------------------------------------------------------------------
    // ThresholdResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_result_is_pass() {
        let pass = ThresholdResult::Pass {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            value: 900_000,
            threshold: 800_000,
            headroom: 100_000,
        };
        assert!(pass.is_pass());

        let fail = ThresholdResult::Fail {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Ga,
            value: 800_000,
            threshold: 990_000,
            shortfall: 190_000,
        };
        assert!(!fail.is_pass());

        let insuf = ThresholdResult::InsufficientData {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
        };
        assert!(!insuf.is_pass());
    }

    #[test]
    fn threshold_result_serde_roundtrip() {
        let results = vec![
            ThresholdResult::Pass {
                metric: MetricKind::CompatibilityPassRate,
                milestone: Milestone::Alpha,
                value: 900_000,
                threshold: 800_000,
                headroom: 100_000,
            },
            ThresholdResult::Fail {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Ga,
                value: 5_000_000,
                threshold: 2_000_000,
                shortfall: 3_000_000,
            },
        ];
        for result in &results {
            let json = serde_json::to_string(result).unwrap();
            let back: ThresholdResult = serde_json::from_str(&json).unwrap();
            assert_eq!(*result, back);
        }
    }

    // -----------------------------------------------------------------------
    // ScorecardEvaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_evaluation_serde_roundtrip() {
        let eval = ScorecardEvaluation {
            milestone: Milestone::Beta,
            epoch: epoch(42),
            results: vec![],
            overall_pass: false,
            pass_count: 0,
            fail_count: 0,
            pass_rate_millionths: 0,
        };
        let json = serde_json::to_string(&eval).unwrap();
        let back: ScorecardEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(eval, back);
    }

    // -----------------------------------------------------------------------
    // Report tests
    // -----------------------------------------------------------------------

    #[test]
    fn report_contains_milestone_name() {
        let sc = Scorecard::new(epoch(1));
        let report = sc.report(Milestone::Alpha);
        assert!(report.contains("alpha"));
        assert!(report.contains("FAIL"));
    }

    #[test]
    fn report_pass_with_data() {
        let mut sc = Scorecard::new(epoch(1));
        for _ in 0..10 {
            sc.record(sample(MetricKind::CompatibilityPassRate, 999_000, 1));
            sc.record(sample(MetricKind::ResponsivenessP99Us, 1_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP50Us, 500, 1));
            sc.record(sample(MetricKind::RenderLatencyP95Us, 2_000, 1));
            sc.record(sample(MetricKind::RenderLatencyP99Us, 5_000, 1));
            sc.record(sample(MetricKind::BundleSizeBytes, 500_000, 1));
            sc.record(sample(MetricKind::RuntimeMemoryBytes, 10_000_000, 1));
            sc.record(sample(MetricKind::FallbackFrequency, 1_000, 1));
            sc.record(sample(MetricKind::RollbackLatencyP99Us, 10_000, 1));
            sc.record(sample(MetricKind::EvidenceCompleteness, 999_000, 1));
        }
        let report = sc.report(Milestone::Ga);
        assert!(report.contains("PASS"), "report: {report}");
    }

    // -----------------------------------------------------------------------
    // Scorecard serde tests
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_serde_roundtrip() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 1000, 1));
        let json = serde_json::to_string(&sc).unwrap();
        let back: Scorecard = serde_json::from_str(&json).unwrap();
        assert_eq!(sc.total_observations(), back.total_observations());
    }

    // -----------------------------------------------------------------------
    // MetricSample tests
    // -----------------------------------------------------------------------

    #[test]
    fn metric_sample_serde_roundtrip() {
        let s = sample(MetricKind::CompatibilityPassRate, 950_000, 42);
        let json = serde_json::to_string(&s).unwrap();
        let back: MetricSample = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // MetricSummary tests
    // -----------------------------------------------------------------------

    #[test]
    fn metric_summary_serde_roundtrip() {
        let summary = MetricSummary {
            kind: MetricKind::BundleSizeBytes,
            count: 100,
            min: 1000,
            max: 5000,
            mean: 3000,
            p50: 3000,
            p95: 4500,
            p99: 4900,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: MetricSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -----------------------------------------------------------------------
    // Custom threshold tests
    // -----------------------------------------------------------------------

    #[test]
    fn custom_thresholds_used() {
        let thresholds = vec![Threshold {
            metric: MetricKind::BundleSizeBytes,
            milestone: Milestone::Alpha,
            boundary: 1_000, // very strict
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 500, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        assert!(eval.overall_pass);

        let mut sc2 = Scorecard::with_thresholds(
            vec![Threshold {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Alpha,
                boundary: 100,
            }],
            epoch(1),
        );
        sc2.record(sample(MetricKind::BundleSizeBytes, 500, 1));
        let eval2 = sc2.evaluate(Milestone::Alpha);
        assert!(!eval2.overall_pass);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_observation_summary() {
        let mut sc = Scorecard::new(epoch(1));
        sc.record(sample(MetricKind::RenderLatencyP50Us, 42, 1));
        let summary = sc.summary(MetricKind::RenderLatencyP50Us).unwrap();
        assert_eq!(summary.count, 1);
        assert_eq!(summary.min, 42);
        assert_eq!(summary.max, 42);
        assert_eq!(summary.mean, 42);
        assert_eq!(summary.p50, 42);
    }

    #[test]
    fn current_value_uses_correct_quantile() {
        let mut sc = Scorecard::new(epoch(1));
        for i in 0..100 {
            sc.record(sample(MetricKind::RenderLatencyP50Us, i, 1));
        }
        // p50 for RenderLatencyP50Us.
        let val = sc.current_value(MetricKind::RenderLatencyP50Us).unwrap();
        assert_eq!(val, 50); // p50 of 0..99

        for i in 0..100 {
            sc.record(sample(MetricKind::RenderLatencyP99Us, i, 1));
        }
        // p99 for RenderLatencyP99Us.
        let val99 = sc.current_value(MetricKind::RenderLatencyP99Us).unwrap();
        assert_eq!(val99, 99); // p99 of 0..99
    }

    #[test]
    fn set_epoch_updates() {
        let mut sc = Scorecard::new(epoch(1));
        sc.set_epoch(epoch(42));
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.epoch, epoch(42));
    }

    #[test]
    fn pass_rate_computation() {
        let thresholds = vec![
            Threshold {
                metric: MetricKind::BundleSizeBytes,
                milestone: Milestone::Alpha,
                boundary: 10_000,
            },
            Threshold {
                metric: MetricKind::RuntimeMemoryBytes,
                milestone: Milestone::Alpha,
                boundary: 10_000,
            },
        ];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::BundleSizeBytes, 5_000, 1)); // pass
        sc.record(sample(MetricKind::RuntimeMemoryBytes, 20_000, 1)); // fail
        let eval = sc.evaluate(Milestone::Alpha);
        assert_eq!(eval.pass_count, 1);
        assert_eq!(eval.fail_count, 1);
        assert_eq!(eval.pass_rate_millionths, 500_000); // 50%
    }

    #[test]
    fn headroom_and_shortfall_correct() {
        let thresholds = vec![Threshold {
            metric: MetricKind::CompatibilityPassRate,
            milestone: Milestone::Alpha,
            boundary: 800_000,
        }];
        let mut sc = Scorecard::with_thresholds(thresholds, epoch(1));
        sc.record(sample(MetricKind::CompatibilityPassRate, 900_000, 1));
        let eval = sc.evaluate(Milestone::Alpha);
        if let ThresholdResult::Pass { headroom, .. } = &eval.results[0] {
            assert_eq!(*headroom, 100_000);
        } else {
            panic!("expected pass");
        }
    }
}
