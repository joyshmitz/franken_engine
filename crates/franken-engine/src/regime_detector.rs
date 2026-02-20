//! BOCPD-based regime detector for workload/health stream shift detection.
//!
//! Implements Bayesian Online Change Point Detection (Adams & MacKay, 2007)
//! to identify when the system's operating regime has changed (e.g., normal
//! operation -> attack spike -> recovery).  The PolicyController uses the
//! regime estimate to select the appropriate loss matrix.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic computation.
//!
//! Plan references: Section 10.11 item 15, 9G.5 (policy controller with
//! expected-loss actions under guardrails), Top-10 #2 (guardplane),
//! #8 (per-extension resource budget).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Regime — categorical operating state
// ---------------------------------------------------------------------------

/// Categorical operating regime estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Regime {
    /// System operating normally.
    Normal,
    /// Elevated activity; not yet confirmed threat.
    Elevated,
    /// Active attack or severe anomaly detected.
    Attack,
    /// System in degraded state (partial failure, resource exhaustion).
    Degraded,
    /// Recovering from incident; transitioning back to normal.
    Recovery,
}

impl fmt::Display for Regime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Elevated => write!(f, "elevated"),
            Self::Attack => write!(f, "attack"),
            Self::Degraded => write!(f, "degraded"),
            Self::Recovery => write!(f, "recovery"),
        }
    }
}

// ---------------------------------------------------------------------------
// HazardFunction — prior on run-length
// ---------------------------------------------------------------------------

/// Hazard function that provides the prior probability of a change point
/// at each time step.
pub trait HazardFunction: fmt::Debug {
    /// Probability of change point at run length `run_length` (millionths).
    fn hazard(&self, run_length: u64) -> i64;
}

/// Constant hazard: change point probability is 1/lambda at every step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantHazard {
    /// Expected run length (lambda).  Hazard = 1/lambda.
    pub lambda: u64,
}

impl HazardFunction for ConstantHazard {
    fn hazard(&self, _run_length: u64) -> i64 {
        if self.lambda == 0 {
            return 1_000_000; // degenerate: always change
        }
        (1_000_000i64) / (self.lambda as i64)
    }
}

// ---------------------------------------------------------------------------
// ObservationModel — sufficient statistics for conjugate updates
// ---------------------------------------------------------------------------

/// Sufficient statistics for a Normal-InverseGamma conjugate model.
///
/// Tracks running mean and variance for each run-length hypothesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalStats {
    /// Prior mean (millionths).
    pub mu0: i64,
    /// Prior precision scale (kappa_0, millionths).
    pub kappa0: i64,
    /// Prior shape (alpha_0, millionths).
    pub alpha0: i64,
    /// Prior scale (beta_0, millionths).
    pub beta0: i64,
}

impl NormalStats {
    /// Default weakly-informative prior centered at zero.
    pub fn default_prior() -> Self {
        Self {
            mu0: 0,
            kappa0: 100_000,   // 0.1
            alpha0: 1_000_000, // 1.0
            beta0: 1_000_000,  // 1.0
        }
    }
}

/// Per-run-length sufficient statistics for Normal model.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunLengthStats {
    /// Number of observations in this run.
    n: u64,
    /// Sum of observations (millionths).
    sum: i64,
    /// Sum of squared observations (millionths^2 / 1M for scale).
    sum_sq: i64,
}

impl RunLengthStats {
    fn new() -> Self {
        Self {
            n: 0,
            sum: 0,
            sum_sq: 0,
        }
    }

    fn add_observation(&mut self, x_millionths: i64) {
        self.n += 1;
        self.sum += x_millionths;
        // Store sum_sq scaled down to prevent overflow: x^2 / 1M
        self.sum_sq += (x_millionths as i128 * x_millionths as i128 / 1_000_000) as i64;
    }

    /// Predictive log-likelihood (proportional) for a new observation
    /// under the Normal-InverseGamma posterior.
    ///
    /// Returns a score in millionths (higher = more likely).
    /// Uses the Student-t predictive distribution approximation.
    fn predictive_score(&self, x_millionths: i64, prior: &NormalStats) -> i64 {
        let kappa_n = prior.kappa0 + (self.n as i64) * 1_000_000;
        let alpha_n = prior.alpha0 + (self.n as i64) * 500_000; // alpha + n/2

        if kappa_n == 0 || alpha_n == 0 {
            return 500_000; // uniform fallback
        }

        // Posterior mean
        let mu_n = if self.n == 0 {
            prior.mu0
        } else {
            let num = prior.kappa0 as i128 * prior.mu0 as i128 + self.sum as i128 * 1_000_000i128;
            (num / kappa_n as i128) as i64
        };

        // Deviation from posterior mean
        let dev = x_millionths - mu_n;
        let dev_sq = (dev as i128 * dev as i128 / 1_000_000) as i64;

        // Score: penalize large deviations.
        // Higher alpha_n and kappa_n make the distribution tighter.
        // Simple approximation: score = 1M - (dev^2 * kappa_n) / (beta_n * 2)
        let beta_n = prior.beta0.max(1);
        let penalty = (dev_sq as i128 * kappa_n as i128 / (beta_n as i128 * 2)).min(2_000_000);
        (1_000_000 - penalty as i64).max(1)
    }
}

// ---------------------------------------------------------------------------
// RegimeChangeEvent — structured output
// ---------------------------------------------------------------------------

/// Event emitted when a regime change is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeChangeEvent {
    /// Detector identifier.
    pub detector_id: String,
    /// Metric stream that triggered the change.
    pub metric_stream: String,
    /// Previous regime estimate.
    pub old_regime: Regime,
    /// New regime estimate.
    pub new_regime: Regime,
    /// Confidence in the change point (millionths, 0..1_000_000).
    pub confidence_millionths: i64,
    /// Index in the observation sequence where the change was detected.
    pub change_point_index: u64,
    /// Current epoch.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// DetectorError
// ---------------------------------------------------------------------------

/// Errors from regime detector operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorError {
    /// Observation value out of valid range.
    InvalidObservation { reason: String },
    /// Detector is not configured for this metric stream.
    UnknownMetricStream { stream: String },
}

impl fmt::Display for DetectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObservation { reason } => {
                write!(f, "invalid observation: {reason}")
            }
            Self::UnknownMetricStream { stream } => {
                write!(f, "unknown metric stream: {stream}")
            }
        }
    }
}

impl std::error::Error for DetectorError {}

// ---------------------------------------------------------------------------
// RegimeClassifier — maps statistics to regime labels
// ---------------------------------------------------------------------------

/// Maps observation statistics to regime categories.
///
/// Uses configurable thresholds on the recent mean observation level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeClassifier {
    /// Threshold between Normal and Elevated (millionths).
    pub elevated_threshold: i64,
    /// Threshold between Elevated and Attack (millionths).
    pub attack_threshold: i64,
    /// Below this threshold: Degraded (millionths).
    pub degraded_threshold: i64,
}

impl RegimeClassifier {
    /// Classify a mean observation level into a regime.
    pub fn classify(&self, mean_millionths: i64) -> Regime {
        if mean_millionths <= self.degraded_threshold {
            Regime::Degraded
        } else if mean_millionths >= self.attack_threshold {
            Regime::Attack
        } else if mean_millionths >= self.elevated_threshold {
            Regime::Elevated
        } else {
            Regime::Normal
        }
    }
}

impl Default for RegimeClassifier {
    fn default() -> Self {
        Self {
            elevated_threshold: 700_000,  // 0.7
            attack_threshold: 900_000,    // 0.9
            degraded_threshold: -500_000, // -0.5
        }
    }
}

// ---------------------------------------------------------------------------
// DetectorConfig
// ---------------------------------------------------------------------------

/// Configuration for a single-stream regime detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Detector identifier.
    pub detector_id: String,
    /// Metric stream name.
    pub metric_stream: String,
    /// Maximum run-length to track (truncation for memory efficiency).
    pub max_run_length: usize,
    /// Regime classifier thresholds.
    pub classifier: RegimeClassifier,
    /// Normal-InverseGamma prior.
    pub prior: NormalStats,
    /// Hazard function lambda (for ConstantHazard).
    pub hazard_lambda: u64,
}

// ---------------------------------------------------------------------------
// RegimeDetector — BOCPD for a single metric stream
// ---------------------------------------------------------------------------

/// BOCPD-based regime detector for a single metric stream.
///
/// Maintains a run-length distribution and detects change points
/// using Bayesian posterior updates with a conjugate Normal-InverseGamma
/// observation model.
#[derive(Debug)]
pub struct RegimeDetector {
    config: DetectorConfig,
    /// Run-length probabilities (millionths).  Index = run length.
    run_length_probs: Vec<i64>,
    /// Sufficient statistics per run-length hypothesis.
    run_length_stats: Vec<RunLengthStats>,
    /// Current regime estimate.
    current_regime: Regime,
    /// Total observations processed.
    observation_count: u64,
    /// Recent observation window for regime classification.
    recent_window: Vec<i64>,
    /// Window size for regime classification.
    window_size: usize,
    /// Event log.
    events: Vec<RegimeChangeEvent>,
    /// Current epoch.
    epoch: SecurityEpoch,
    /// Hazard function.
    hazard: Box<dyn HazardFunction>,
}

impl RegimeDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: DetectorConfig, epoch: SecurityEpoch) -> Self {
        let hazard_lambda = config.hazard_lambda;
        let max_rl = config.max_run_length;

        // Initialize with uniform prior on run-length 0.
        let mut run_length_probs = vec![0i64; max_rl + 1];
        run_length_probs[0] = 1_000_000; // all mass at run-length 0

        let mut run_length_stats = Vec::with_capacity(max_rl + 1);
        for _ in 0..=max_rl {
            run_length_stats.push(RunLengthStats::new());
        }

        Self {
            config,
            run_length_probs,
            run_length_stats,
            current_regime: Regime::Normal,
            observation_count: 0,
            recent_window: Vec::new(),
            window_size: 10,
            events: Vec::new(),
            epoch,
            hazard: Box::new(ConstantHazard {
                lambda: hazard_lambda,
            }),
        }
    }

    /// Current regime estimate.
    pub fn regime(&self) -> Regime {
        self.current_regime
    }

    /// Total observations processed.
    pub fn observation_count(&self) -> u64 {
        self.observation_count
    }

    /// Detector configuration.
    pub fn config(&self) -> &DetectorConfig {
        &self.config
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<RegimeChangeEvent> {
        std::mem::take(&mut self.events)
    }

    /// Most probable run length.
    pub fn most_probable_run_length(&self) -> usize {
        self.run_length_probs
            .iter()
            .enumerate()
            .max_by_key(|&(_, &p)| p)
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    /// Change-point probability: probability that run-length is 0.
    pub fn change_point_probability(&self) -> i64 {
        self.run_length_probs.first().copied().unwrap_or(0)
    }

    /// Process a new observation and update the run-length distribution.
    ///
    /// Returns the new regime estimate.
    pub fn observe(&mut self, x_millionths: i64) -> Result<Regime, DetectorError> {
        self.observation_count += 1;
        let max_rl = self.config.max_run_length;

        // Step 1: Compute predictive probabilities for each run length.
        let pred_probs: Vec<i64> = self.run_length_stats[..=max_rl]
            .iter()
            .map(|s| s.predictive_score(x_millionths, &self.config.prior))
            .collect();

        // Step 2: Compute growth probabilities.
        // growth_prob[r+1] = run_length_prob[r] * pred_prob[r] * (1 - H(r))
        let mut new_probs = vec![0i64; max_rl + 1];
        let mut changepoint_mass: i64 = 0;

        for r in 0..max_rl {
            let h = self.hazard.hazard(r as u64);
            let survival = 1_000_000 - h; // 1 - H(r)

            // growth: prob[r] * pred[r] * survival / 1M^2
            let growth =
                self.run_length_probs[r] as i128 * pred_probs[r] as i128 * survival as i128
                    / (1_000_000i128 * 1_000_000);
            new_probs[r + 1] = growth as i64;

            // changepoint mass: prob[r] * pred[r] * H(r) / 1M^2
            let cp = self.run_length_probs[r] as i128 * pred_probs[r] as i128 * h as i128
                / (1_000_000i128 * 1_000_000);
            changepoint_mass += cp as i64;
        }

        // Step 3: Change-point probability goes to run-length 0.
        new_probs[0] = changepoint_mass;

        // Step 4: Normalize.
        let total: i64 = new_probs.iter().sum();
        if total > 0 {
            for p in &mut new_probs {
                *p = (*p as i128 * 1_000_000 / total as i128) as i64;
            }
        } else {
            // Degenerate: reset to uniform at 0.
            new_probs[0] = 1_000_000;
        }

        self.run_length_probs = new_probs;

        // Step 5: Update sufficient statistics.
        // Shift stats: each run-length r gets the observation added.
        // New run-length 0 gets fresh stats.
        let mut new_stats = Vec::with_capacity(max_rl + 1);
        new_stats.push(RunLengthStats::new()); // r=0: fresh

        for r in 0..max_rl {
            let mut s = self.run_length_stats[r].clone();
            s.add_observation(x_millionths);
            new_stats.push(s);
        }

        self.run_length_stats = new_stats;

        // Step 6: Update recent window for regime classification.
        self.recent_window.push(x_millionths);
        if self.recent_window.len() > self.window_size {
            self.recent_window.remove(0);
        }

        // Step 7: Classify regime based on recent window mean.
        let old_regime = self.current_regime;
        if !self.recent_window.is_empty() {
            let mean = self.recent_window.iter().sum::<i64>() / self.recent_window.len() as i64;
            self.current_regime = self.config.classifier.classify(mean);
        }

        // Step 8: Emit event if regime changed.
        if self.current_regime != old_regime {
            self.events.push(RegimeChangeEvent {
                detector_id: self.config.detector_id.clone(),
                metric_stream: self.config.metric_stream.clone(),
                old_regime,
                new_regime: self.current_regime,
                confidence_millionths: self.change_point_probability(),
                change_point_index: self.observation_count,
                epoch: self.epoch,
            });
        }

        Ok(self.current_regime)
    }

    /// Update the epoch (e.g., on epoch transition).
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }
}

// ---------------------------------------------------------------------------
// MultiStreamDetector — manages detectors across metric streams
// ---------------------------------------------------------------------------

/// Manages multiple regime detectors, one per metric stream.
#[derive(Debug, Default)]
pub struct MultiStreamDetector {
    detectors: BTreeMap<String, RegimeDetector>,
}

impl MultiStreamDetector {
    /// Create an empty multi-stream detector.
    pub fn new() -> Self {
        Self {
            detectors: BTreeMap::new(),
        }
    }

    /// Register a detector for a metric stream.
    pub fn register(&mut self, detector: RegimeDetector) {
        let stream = detector.config.metric_stream.clone();
        self.detectors.insert(stream, detector);
    }

    /// Number of registered streams.
    pub fn stream_count(&self) -> usize {
        self.detectors.len()
    }

    /// Get the current regime for a stream.
    pub fn regime(&self, stream: &str) -> Option<Regime> {
        self.detectors.get(stream).map(|d| d.regime())
    }

    /// Process an observation for a metric stream.
    pub fn observe(&mut self, stream: &str, x_millionths: i64) -> Result<Regime, DetectorError> {
        let detector =
            self.detectors
                .get_mut(stream)
                .ok_or_else(|| DetectorError::UnknownMetricStream {
                    stream: stream.to_string(),
                })?;
        detector.observe(x_millionths)
    }

    /// Drain all events from all detectors.
    pub fn drain_all_events(&mut self) -> Vec<RegimeChangeEvent> {
        let mut all = Vec::new();
        for detector in self.detectors.values_mut() {
            all.extend(detector.drain_events());
        }
        all
    }

    /// Get overall regime (worst-case across all streams).
    pub fn overall_regime(&self) -> Regime {
        self.detectors
            .values()
            .map(|d| d.regime())
            .max()
            .unwrap_or(Regime::Normal)
    }

    /// Update epoch on all detectors.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        for detector in self.detectors.values_mut() {
            detector.set_epoch(epoch);
        }
    }

    /// Get a reference to a detector by stream name.
    pub fn get(&self, stream: &str) -> Option<&RegimeDetector> {
        self.detectors.get(stream)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(stream: &str) -> DetectorConfig {
        DetectorConfig {
            detector_id: "det-1".to_string(),
            metric_stream: stream.to_string(),
            max_run_length: 50,
            classifier: RegimeClassifier::default(),
            prior: NormalStats::default_prior(),
            hazard_lambda: 100,
        }
    }

    fn test_detector(stream: &str) -> RegimeDetector {
        RegimeDetector::new(test_config(stream), SecurityEpoch::GENESIS)
    }

    // -- Regime enum --

    #[test]
    fn regime_display() {
        assert_eq!(Regime::Normal.to_string(), "normal");
        assert_eq!(Regime::Elevated.to_string(), "elevated");
        assert_eq!(Regime::Attack.to_string(), "attack");
        assert_eq!(Regime::Degraded.to_string(), "degraded");
        assert_eq!(Regime::Recovery.to_string(), "recovery");
    }

    #[test]
    fn regime_ordering() {
        assert!(Regime::Normal < Regime::Elevated);
        assert!(Regime::Elevated < Regime::Attack);
        assert!(Regime::Attack < Regime::Degraded);
        assert!(Regime::Degraded < Regime::Recovery);
    }

    // -- Constant hazard --

    #[test]
    fn constant_hazard_computes_correct_rate() {
        let h = ConstantHazard { lambda: 100 };
        // 1/100 = 0.01 = 10_000 millionths
        assert_eq!(h.hazard(0), 10_000);
        assert_eq!(h.hazard(50), 10_000);
    }

    #[test]
    fn constant_hazard_zero_lambda() {
        let h = ConstantHazard { lambda: 0 };
        assert_eq!(h.hazard(0), 1_000_000); // always change
    }

    // -- Regime classifier --

    #[test]
    fn classifier_normal_range() {
        let c = RegimeClassifier::default();
        assert_eq!(c.classify(0), Regime::Normal);
        assert_eq!(c.classify(500_000), Regime::Normal);
        assert_eq!(c.classify(699_999), Regime::Normal);
    }

    #[test]
    fn classifier_elevated_range() {
        let c = RegimeClassifier::default();
        assert_eq!(c.classify(700_000), Regime::Elevated);
        assert_eq!(c.classify(800_000), Regime::Elevated);
        assert_eq!(c.classify(899_999), Regime::Elevated);
    }

    #[test]
    fn classifier_attack_range() {
        let c = RegimeClassifier::default();
        assert_eq!(c.classify(900_000), Regime::Attack);
        assert_eq!(c.classify(1_000_000), Regime::Attack);
        assert_eq!(c.classify(5_000_000), Regime::Attack);
    }

    #[test]
    fn classifier_degraded_range() {
        let c = RegimeClassifier::default();
        assert_eq!(c.classify(-500_000), Regime::Degraded);
        assert_eq!(c.classify(-1_000_000), Regime::Degraded);
    }

    // -- Detector basics --

    #[test]
    fn new_detector_starts_normal() {
        let det = test_detector("hostcall_rate");
        assert_eq!(det.regime(), Regime::Normal);
        assert_eq!(det.observation_count(), 0);
    }

    #[test]
    fn single_observation_updates_count() {
        let mut det = test_detector("hostcall_rate");
        det.observe(100_000).unwrap();
        assert_eq!(det.observation_count(), 1);
    }

    #[test]
    fn normal_observations_maintain_normal_regime() {
        let mut det = test_detector("hostcall_rate");
        for _ in 0..20 {
            det.observe(300_000).unwrap(); // 0.3, well within normal
        }
        assert_eq!(det.regime(), Regime::Normal);
        let events = det.drain_events();
        // No regime change events
        assert!(events.is_empty());
    }

    #[test]
    fn high_observations_trigger_elevated_then_attack() {
        let mut det = test_detector("hostcall_rate");

        // Feed 10+ normal observations first to fill window
        for _ in 0..10 {
            det.observe(300_000).unwrap();
        }
        assert_eq!(det.regime(), Regime::Normal);

        // Now feed high observations to push mean above elevated threshold
        for _ in 0..15 {
            det.observe(950_000).unwrap();
        }

        // With window_size=10, after 10+ high obs the mean should be high
        assert!(det.regime() >= Regime::Elevated);
    }

    #[test]
    fn regime_change_emits_event() {
        let mut det = test_detector("hostcall_rate");

        // Fill with normal
        for _ in 0..10 {
            det.observe(300_000).unwrap();
        }

        // Push to attack
        for _ in 0..15 {
            det.observe(950_000).unwrap();
        }

        let events = det.drain_events();
        assert!(!events.is_empty());

        let last = events.last().unwrap();
        assert_eq!(last.detector_id, "det-1");
        assert_eq!(last.metric_stream, "hostcall_rate");
    }

    // -- Run-length distribution --

    #[test]
    fn most_probable_run_length_starts_at_zero() {
        let det = test_detector("m");
        assert_eq!(det.most_probable_run_length(), 0);
    }

    #[test]
    fn run_length_increases_with_stable_observations() {
        let mut det = test_detector("m");
        for _ in 0..20 {
            det.observe(500_000).unwrap();
        }
        // After stable observations, most probable run length should be > 0
        assert!(det.most_probable_run_length() > 0);
    }

    // -- Determinism --

    #[test]
    fn deterministic_replay() {
        let observations = vec![
            300_000i64, 300_000, 310_000, 290_000, 300_000, 950_000, 960_000, 940_000, 950_000,
            950_000, 300_000, 300_000,
        ];

        let run = |obs: &[i64]| -> (Vec<Regime>, Vec<RegimeChangeEvent>) {
            let mut det = test_detector("m");
            let regimes: Vec<Regime> = obs.iter().map(|&x| det.observe(x).unwrap()).collect();
            let events = det.drain_events();
            (regimes, events)
        };

        let (regimes1, events1) = run(&observations);
        let (regimes2, events2) = run(&observations);

        assert_eq!(regimes1, regimes2);
        assert_eq!(events1, events2);
    }

    // -- MultiStreamDetector --

    #[test]
    fn multi_stream_registers_and_observes() {
        let mut multi = MultiStreamDetector::new();
        multi.register(test_detector("hostcall_rate"));
        multi.register(test_detector("error_rate"));

        assert_eq!(multi.stream_count(), 2);
        assert_eq!(multi.regime("hostcall_rate"), Some(Regime::Normal));
        assert_eq!(multi.regime("error_rate"), Some(Regime::Normal));

        multi.observe("hostcall_rate", 300_000).unwrap();
        assert_eq!(multi.get("hostcall_rate").unwrap().observation_count(), 1);
    }

    #[test]
    fn multi_stream_unknown_stream_error() {
        let mut multi = MultiStreamDetector::new();
        let err = multi.observe("nonexistent", 100_000).unwrap_err();
        assert_eq!(
            err,
            DetectorError::UnknownMetricStream {
                stream: "nonexistent".to_string()
            }
        );
    }

    #[test]
    fn multi_stream_overall_regime_worst_case() {
        let mut multi = MultiStreamDetector::new();
        multi.register(test_detector("a"));
        multi.register(test_detector("b"));

        // Feed "a" with attack-level data
        for _ in 0..15 {
            multi.observe("a", 950_000).unwrap();
        }

        // "b" stays normal
        for _ in 0..15 {
            multi.observe("b", 300_000).unwrap();
        }

        // Overall should be at least elevated (worst case across streams)
        assert!(multi.overall_regime() >= Regime::Elevated);
    }

    #[test]
    fn multi_stream_epoch_update() {
        let mut multi = MultiStreamDetector::new();
        multi.register(test_detector("a"));

        let new_epoch = SecurityEpoch::from_raw(5);
        multi.set_epoch(new_epoch);

        // Feed observation that triggers a regime change
        for _ in 0..15 {
            multi.observe("a", 950_000).unwrap();
        }

        let events = multi.drain_all_events();
        if let Some(event) = events.last() {
            assert_eq!(event.epoch, new_epoch);
        }
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            DetectorError::InvalidObservation {
                reason: "nan".to_string()
            }
            .to_string(),
            "invalid observation: nan"
        );
        assert_eq!(
            DetectorError::UnknownMetricStream {
                stream: "x".to_string()
            }
            .to_string(),
            "unknown metric stream: x"
        );
    }

    // -- Serialization --

    #[test]
    fn regime_serialization_round_trip() {
        let regimes = vec![
            Regime::Normal,
            Regime::Elevated,
            Regime::Attack,
            Regime::Degraded,
            Regime::Recovery,
        ];
        for regime in &regimes {
            let json = serde_json::to_string(regime).expect("serialize");
            let restored: Regime = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*regime, restored);
        }
    }

    #[test]
    fn regime_change_event_serialization_round_trip() {
        let event = RegimeChangeEvent {
            detector_id: "det-1".to_string(),
            metric_stream: "hostcall_rate".to_string(),
            old_regime: Regime::Normal,
            new_regime: Regime::Attack,
            confidence_millionths: 750_000,
            change_point_index: 42,
            epoch: SecurityEpoch::from_raw(3),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: RegimeChangeEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn detector_error_serialization_round_trip() {
        let errors = vec![
            DetectorError::InvalidObservation {
                reason: "oob".to_string(),
            },
            DetectorError::UnknownMetricStream {
                stream: "x".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: DetectorError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn normal_stats_serialization_round_trip() {
        let stats = NormalStats::default_prior();
        let json = serde_json::to_string(&stats).expect("serialize");
        let restored: NormalStats = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stats, restored);
    }

    #[test]
    fn classifier_serialization_round_trip() {
        let c = RegimeClassifier::default();
        let json = serde_json::to_string(&c).expect("serialize");
        let restored: RegimeClassifier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, restored);
    }
}
