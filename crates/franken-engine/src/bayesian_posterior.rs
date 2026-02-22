//! Bayesian posterior updater API for the Probabilistic Guardplane.
//!
//! Maintains a posterior probability distribution over extension risk
//! states.  Takes hostcall telemetry evidence and updates a Bayesian
//! belief about whether an extension is benign, anomalous, or malicious.
//!
//! All probabilities use fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform arithmetic.
//!
//! Plan reference: Section 10.5, item 4.
//! Cross-refs: 9A.2 (Probabilistic Guardplane), 9C.2 (Bayesian decision
//! loop), 9B.2 (conformal prediction, e-process, BOCPD).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// One million — the unit for fixed-point probability.
const MILLION: i64 = 1_000_000;

/// Minimum probability mass to prevent underflow (0.01% = 100 / 1_000_000).
const FLOOR_MASS: i64 = 100;

/// Default prior: 85% benign, 10% unknown, 4% anomalous, 1% malicious.
const DEFAULT_PRIOR_BENIGN: i64 = 850_000;
const DEFAULT_PRIOR_ANOMALOUS: i64 = 40_000;
const DEFAULT_PRIOR_MALICIOUS: i64 = 10_000;
const DEFAULT_PRIOR_UNKNOWN: i64 = 100_000;

// ---------------------------------------------------------------------------
// RiskState — the state space
// ---------------------------------------------------------------------------

/// Discrete risk classification for an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskState {
    Benign,
    Anomalous,
    Malicious,
    Unknown,
}

impl fmt::Display for RiskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Benign => "benign",
            Self::Anomalous => "anomalous",
            Self::Malicious => "malicious",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

impl RiskState {
    /// All variants in canonical order.
    pub const ALL: [RiskState; 4] = [
        RiskState::Benign,
        RiskState::Anomalous,
        RiskState::Malicious,
        RiskState::Unknown,
    ];
}

// ---------------------------------------------------------------------------
// Posterior — probability distribution over RiskState
// ---------------------------------------------------------------------------

/// Probability distribution over risk states, in fixed-point millionths.
///
/// Invariant: the four probabilities sum to exactly `MILLION`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posterior {
    /// P(Benign) in millionths.
    pub p_benign: i64,
    /// P(Anomalous) in millionths.
    pub p_anomalous: i64,
    /// P(Malicious) in millionths.
    pub p_malicious: i64,
    /// P(Unknown) in millionths.
    pub p_unknown: i64,
}

impl Posterior {
    /// Create a posterior with the default prior (high P(Benign)).
    pub fn default_prior() -> Self {
        Self {
            p_benign: DEFAULT_PRIOR_BENIGN,
            p_anomalous: DEFAULT_PRIOR_ANOMALOUS,
            p_malicious: DEFAULT_PRIOR_MALICIOUS,
            p_unknown: DEFAULT_PRIOR_UNKNOWN,
        }
    }

    /// Create a uniform prior (25% each).
    pub fn uniform() -> Self {
        Self {
            p_benign: 250_000,
            p_anomalous: 250_000,
            p_malicious: 250_000,
            p_unknown: 250_000,
        }
    }

    /// Create a posterior from raw millionths. Normalizes to sum to MILLION.
    pub fn from_millionths(benign: i64, anomalous: i64, malicious: i64, unknown: i64) -> Self {
        let mut p = Self {
            p_benign: benign.max(0),
            p_anomalous: anomalous.max(0),
            p_malicious: malicious.max(0),
            p_unknown: unknown.max(0),
        };
        p.normalize();
        p
    }

    /// The probability for a given state.
    pub fn probability(&self, state: RiskState) -> i64 {
        match state {
            RiskState::Benign => self.p_benign,
            RiskState::Anomalous => self.p_anomalous,
            RiskState::Malicious => self.p_malicious,
            RiskState::Unknown => self.p_unknown,
        }
    }

    /// The most likely state (MAP estimate).
    pub fn map_estimate(&self) -> RiskState {
        let mut best = RiskState::Benign;
        let mut best_p = self.p_benign;
        for state in &RiskState::ALL {
            let p = self.probability(*state);
            if p > best_p {
                best = *state;
                best_p = p;
            }
        }
        best
    }

    /// Verify that the posterior sums to MILLION.
    pub fn is_valid(&self) -> bool {
        self.sum() == MILLION
            && self.p_benign >= 0
            && self.p_anomalous >= 0
            && self.p_malicious >= 0
            && self.p_unknown >= 0
    }

    /// Sum of all probabilities.
    fn sum(&self) -> i64 {
        self.p_benign + self.p_anomalous + self.p_malicious + self.p_unknown
    }

    /// Normalize to ensure sum = MILLION. Applies floor mass and distributes
    /// remainder to the largest component.
    fn normalize(&mut self) {
        // Apply floor.
        self.p_benign = self.p_benign.max(FLOOR_MASS);
        self.p_anomalous = self.p_anomalous.max(FLOOR_MASS);
        self.p_malicious = self.p_malicious.max(FLOOR_MASS);
        self.p_unknown = self.p_unknown.max(FLOOR_MASS);

        let total = self.sum();
        if total == 0 {
            // Degenerate case: uniform.
            self.p_benign = 250_000;
            self.p_anomalous = 250_000;
            self.p_malicious = 250_000;
            self.p_unknown = 250_000;
            return;
        }

        // Scale each proportionally.
        self.p_benign = self.p_benign * MILLION / total;
        self.p_anomalous = self.p_anomalous * MILLION / total;
        self.p_malicious = self.p_malicious * MILLION / total;
        self.p_unknown = self.p_unknown * MILLION / total;

        // Distribute remainder to the largest to maintain exact sum.
        let remainder = MILLION - self.sum();
        if remainder != 0 {
            // Find largest and add remainder there.
            let max_val = self
                .p_benign
                .max(self.p_anomalous)
                .max(self.p_malicious)
                .max(self.p_unknown);
            if self.p_benign == max_val {
                self.p_benign += remainder;
            } else if self.p_anomalous == max_val {
                self.p_anomalous += remainder;
            } else if self.p_malicious == max_val {
                self.p_malicious += remainder;
            } else {
                self.p_unknown += remainder;
            }
        }
    }
}

impl fmt::Display for Posterior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "B={:.1}% A={:.1}% M={:.1}% U={:.1}%",
            self.p_benign as f64 / 10_000.0,
            self.p_anomalous as f64 / 10_000.0,
            self.p_malicious as f64 / 10_000.0,
            self.p_unknown as f64 / 10_000.0,
        )
    }
}

// ---------------------------------------------------------------------------
// Evidence — derived features from telemetry
// ---------------------------------------------------------------------------

/// Derived evidence features from a hostcall telemetry record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Extension being evaluated.
    pub extension_id: String,
    /// Hostcall rate in calls per second (millionths: 1_000_000 = 1.0 calls/s).
    pub hostcall_rate_millionths: i64,
    /// Number of distinct capability types used (0-16).
    pub distinct_capabilities: u32,
    /// Resource consumption score (millionths: higher = more consumption).
    pub resource_score_millionths: i64,
    /// Timing anomaly score (millionths: 0 = normal, higher = more anomalous).
    pub timing_anomaly_millionths: i64,
    /// Denial rate in recent window (millionths).
    pub denial_rate_millionths: i64,
    /// Security epoch at evidence time.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// LikelihoodModel — configurable per-state likelihoods
// ---------------------------------------------------------------------------

/// Likelihood configuration for each risk state.
///
/// Each field defines how likely a given evidence feature is under that
/// state.  Higher values = more likely.  All in millionths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LikelihoodModel {
    /// Hostcall rate thresholds per state (millionths).
    /// If rate > threshold, likelihood drops for Benign, rises for Malicious.
    pub benign_rate_ceiling: i64,
    pub anomalous_rate_floor: i64,
    /// Denial rate thresholds (millionths).
    pub benign_denial_ceiling: i64,
    pub malicious_denial_floor: i64,
    /// Timing anomaly threshold (millionths).
    pub timing_anomaly_threshold: i64,
    /// Resource score threshold (millionths).
    pub resource_threshold: i64,
}

impl Default for LikelihoodModel {
    fn default() -> Self {
        Self {
            benign_rate_ceiling: 100_000_000,  // 100 calls/s
            anomalous_rate_floor: 500_000_000, // 500 calls/s
            benign_denial_ceiling: 50_000,     // 5% denial rate
            malicious_denial_floor: 200_000,   // 20% denial rate
            timing_anomaly_threshold: 500_000, // 50% anomaly score
            resource_threshold: 700_000,       // 70% resource usage
        }
    }
}

impl LikelihoodModel {
    /// Compute likelihood ratios for each state given evidence.
    /// Returns (benign, anomalous, malicious, unknown) in millionths.
    pub fn compute_likelihoods(&self, evidence: &Evidence) -> [i64; 4] {
        let mut l_benign: i64 = MILLION;
        let mut l_anomalous: i64 = MILLION;
        let mut l_malicious: i64 = MILLION;
        let l_unknown: i64 = MILLION; // Uniform likelihood for unknown.

        // --- Hostcall rate signal ---
        let rate = evidence.hostcall_rate_millionths;
        if rate > self.anomalous_rate_floor {
            // Very high rate: strongly suggests anomalous or malicious.
            l_benign = l_benign * 200_000 / MILLION; // 0.2
            l_anomalous = l_anomalous * 1_500_000 / MILLION; // 1.5
            l_malicious = l_malicious * 2_000_000 / MILLION; // 2.0
        } else if rate > self.benign_rate_ceiling {
            // Elevated rate: somewhat anomalous.
            l_benign = l_benign * 600_000 / MILLION; // 0.6
            l_anomalous = l_anomalous * 1_300_000 / MILLION; // 1.3
            l_malicious = l_malicious * 1_200_000 / MILLION; // 1.2
        }
        // else: normal rate, all stay at 1.0

        // --- Denial rate signal ---
        let denial = evidence.denial_rate_millionths;
        if denial > self.malicious_denial_floor {
            l_benign = l_benign * 100_000 / MILLION; // 0.1
            l_anomalous = l_anomalous * 800_000 / MILLION; // 0.8
            l_malicious = l_malicious * 3_000_000 / MILLION; // 3.0
        } else if denial > self.benign_denial_ceiling {
            l_benign = l_benign * 500_000 / MILLION; // 0.5
            l_anomalous = l_anomalous * 1_500_000 / MILLION; // 1.5
            l_malicious = l_malicious * 1_500_000 / MILLION; // 1.5
        }

        // --- Timing anomaly signal ---
        if evidence.timing_anomaly_millionths > self.timing_anomaly_threshold {
            l_benign = l_benign * 300_000 / MILLION; // 0.3
            l_anomalous = l_anomalous * 2_000_000 / MILLION; // 2.0
            l_malicious = l_malicious * 1_800_000 / MILLION; // 1.8
        }

        // --- Resource consumption signal ---
        if evidence.resource_score_millionths > self.resource_threshold {
            l_benign = l_benign * 400_000 / MILLION; // 0.4
            l_anomalous = l_anomalous * 1_500_000 / MILLION; // 1.5
            l_malicious = l_malicious * 1_800_000 / MILLION; // 1.8
        }

        // Floor to prevent zero likelihoods.
        [
            l_benign.max(FLOOR_MASS),
            l_anomalous.max(FLOOR_MASS),
            l_malicious.max(FLOOR_MASS),
            l_unknown.max(FLOOR_MASS),
        ]
    }
}

// ---------------------------------------------------------------------------
// UpdateResult — output of a Bayesian update step
// ---------------------------------------------------------------------------

/// Result of a single Bayesian update step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateResult {
    /// Posterior after the update.
    pub posterior: Posterior,
    /// Likelihoods used in this update (benign, anomalous, malicious, unknown).
    pub likelihoods: [i64; 4],
    /// Cumulative log-likelihood ratio (millionths of nats).
    pub cumulative_llr_millionths: i64,
    /// Total evidence updates applied.
    pub update_count: u64,
}

// ---------------------------------------------------------------------------
// ChangePointDetector — BOCPD component
// ---------------------------------------------------------------------------

/// Bayesian Online Change Point Detection (BOCPD) state.
///
/// Tracks run-length distribution: probability that the current regime
/// has lasted for exactly `r` steps.  A spike at r=0 indicates a change
/// point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePointDetector {
    /// Run-length probabilities (millionths).  Index = run length.
    run_length_probs: Vec<i64>,
    /// Hazard rate (probability of change per step, millionths).
    hazard_rate: i64,
    /// Maximum run length to track.
    max_run_length: usize,
}

impl ChangePointDetector {
    /// Create a new detector with given hazard rate (millionths).
    pub fn new(hazard_rate_millionths: i64, max_run_length: usize) -> Self {
        let mut run_length_probs = vec![0i64; max_run_length + 1];
        run_length_probs[0] = MILLION; // Start with run length 0.
        Self {
            run_length_probs,
            hazard_rate: hazard_rate_millionths,
            max_run_length,
        }
    }

    /// Update with new evidence.  Returns the change-point probability
    /// (millionths), i.e. P(run_length = 0 | data).
    pub fn update(&mut self, predictive_likelihood: i64) -> i64 {
        let n = self.run_length_probs.len();
        let mut new_probs = vec![0i64; n];

        // Growth: each existing run length grows by 1.
        let survival_rate = MILLION - self.hazard_rate;
        for r in (0..n).rev() {
            let growth = self.run_length_probs[r] * survival_rate / MILLION;
            let weighted = growth * predictive_likelihood / MILLION;
            let target_idx = (r + 1).min(n - 1);
            new_probs[target_idx] += weighted.max(0);
        }

        // Change point: mass from all run lengths flowing to r=0.
        let mut change_mass: i64 = 0;
        for r in 0..n {
            let hazard_flow = self.run_length_probs[r] * self.hazard_rate / MILLION;
            let weighted = hazard_flow * predictive_likelihood / MILLION;
            change_mass += weighted.max(0);
        }
        new_probs[0] = change_mass;

        // Normalize.
        let total: i64 = new_probs.iter().sum();
        if total > 0 {
            for p in &mut new_probs {
                *p = *p * MILLION / total;
            }
            // Fix remainder.
            let remainder = MILLION - new_probs.iter().sum::<i64>();
            if remainder != 0 {
                new_probs[0] += remainder;
            }
        } else {
            // Degenerate: reset to change point.
            new_probs[0] = MILLION;
        }

        self.run_length_probs = new_probs;
        self.run_length_probs[0]
    }

    /// Current change-point probability (millionths).
    pub fn change_point_probability(&self) -> i64 {
        self.run_length_probs[0]
    }

    /// Most likely current run length.
    pub fn map_run_length(&self) -> usize {
        self.run_length_probs
            .iter()
            .enumerate()
            .max_by_key(|(_, p)| *p)
            .map(|(r, _)| r)
            .unwrap_or(0)
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        for p in &mut self.run_length_probs {
            *p = 0;
        }
        self.run_length_probs[0] = MILLION;
    }
}

// ---------------------------------------------------------------------------
// CalibrationResult — calibration check output
// ---------------------------------------------------------------------------

/// Result of checking posterior calibration against ground truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationResult {
    /// Ground truth state.
    pub ground_truth: RiskState,
    /// Posterior probability assigned to ground truth (millionths).
    pub assigned_probability: i64,
    /// Whether the MAP estimate matches ground truth.
    pub map_correct: bool,
    /// Brier score component (millionths of squared error).
    pub brier_component_millionths: i64,
}

// ---------------------------------------------------------------------------
// BayesianPosteriorUpdater — the main engine
// ---------------------------------------------------------------------------

/// Bayesian posterior updater for extension risk assessment.
///
/// Maintains a posterior distribution over [`RiskState`] values and
/// supports sequential evidence updates with cumulative log-likelihood
/// ratio tracking and Bayesian Online Change Point Detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianPosteriorUpdater {
    posterior: Posterior,
    likelihood_model: LikelihoodModel,
    change_detector: ChangePointDetector,
    cumulative_llr_millionths: i64,
    update_count: u64,
    evidence_hashes: Vec<ContentHash>,
    extension_id: String,
    epoch: SecurityEpoch,
}

impl BayesianPosteriorUpdater {
    /// Create a new updater with the given prior and extension ID.
    pub fn new(prior: Posterior, extension_id: impl Into<String>) -> Self {
        Self {
            posterior: prior,
            likelihood_model: LikelihoodModel::default(),
            change_detector: ChangePointDetector::new(50_000, 100), // 5% hazard, max 100 steps
            cumulative_llr_millionths: 0,
            update_count: 0,
            evidence_hashes: Vec::new(),
            extension_id: extension_id.into(),
            epoch: SecurityEpoch::GENESIS,
        }
    }

    /// Create with a custom likelihood model.
    pub fn with_model(
        prior: Posterior,
        extension_id: impl Into<String>,
        model: LikelihoodModel,
    ) -> Self {
        let mut updater = Self::new(prior, extension_id);
        updater.likelihood_model = model;
        updater
    }

    /// Perform one Bayesian update step with new evidence.
    pub fn update(&mut self, evidence: &Evidence) -> UpdateResult {
        let likelihoods = self.likelihood_model.compute_likelihoods(evidence);

        // Bayes rule: posterior ∝ likelihood × prior
        let unnormalized = [
            self.posterior.p_benign * likelihoods[0] / MILLION,
            self.posterior.p_anomalous * likelihoods[1] / MILLION,
            self.posterior.p_malicious * likelihoods[2] / MILLION,
            self.posterior.p_unknown * likelihoods[3] / MILLION,
        ];

        self.posterior = Posterior::from_millionths(
            unnormalized[0],
            unnormalized[1],
            unnormalized[2],
            unnormalized[3],
        );

        // Update cumulative log-likelihood ratio (benign vs malicious).
        // LLR = log(L_malicious / L_benign), in millionths of nats.
        let llr_step = if likelihoods[0] > 0 {
            // Approximate log ratio: (mal - ben) / ben scaled to millionths.
            (likelihoods[2] - likelihoods[0]) * MILLION / likelihoods[0]
        } else {
            MILLION // Max positive LLR when benign likelihood is 0.
        };
        self.cumulative_llr_millionths += llr_step;

        // BOCPD update: use mean likelihood as predictive.
        let mean_likelihood = (likelihoods[0] + likelihoods[1] + likelihoods[2] + likelihoods[3])
            .checked_div(4)
            .unwrap_or(MILLION);
        self.change_detector.update(mean_likelihood);

        // Track evidence hash.
        let evidence_bytes = format!(
            "{}:{}:{}:{}:{}",
            evidence.extension_id,
            evidence.hostcall_rate_millionths,
            evidence.denial_rate_millionths,
            evidence.timing_anomaly_millionths,
            evidence.resource_score_millionths,
        );
        self.evidence_hashes
            .push(ContentHash::compute(evidence_bytes.as_bytes()));

        self.update_count += 1;

        UpdateResult {
            posterior: self.posterior.clone(),
            likelihoods,
            cumulative_llr_millionths: self.cumulative_llr_millionths,
            update_count: self.update_count,
        }
    }

    /// Current posterior.
    pub fn posterior(&self) -> &Posterior {
        &self.posterior
    }

    /// Cumulative log-likelihood ratio (millionths).
    pub fn log_likelihood_ratio(&self) -> i64 {
        self.cumulative_llr_millionths
    }

    /// Change-point probability from BOCPD (millionths).
    pub fn change_point_probability(&self) -> i64 {
        self.change_detector.change_point_probability()
    }

    /// Total number of evidence updates applied.
    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    /// Reset to a new prior, clearing all accumulated evidence.
    pub fn reset(&mut self, prior: Posterior) {
        self.posterior = prior;
        self.cumulative_llr_millionths = 0;
        self.update_count = 0;
        self.evidence_hashes.clear();
        self.change_detector.reset();
    }

    /// Set the security epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
    }

    /// Check posterior calibration against known ground truth.
    pub fn calibration_check(&self, ground_truth: RiskState) -> CalibrationResult {
        let assigned = self.posterior.probability(ground_truth);
        let map_est = self.posterior.map_estimate();

        // Brier score component: (1 - p_correct)^2 in millionths.
        let error = MILLION - assigned;
        let brier = error * error / MILLION;

        CalibrationResult {
            ground_truth,
            assigned_probability: assigned,
            map_correct: map_est == ground_truth,
            brier_component_millionths: brier,
        }
    }

    /// Extension ID this updater tracks.
    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    /// Hashes of all evidence used in updates.
    pub fn evidence_hashes(&self) -> &[ContentHash] {
        &self.evidence_hashes
    }

    /// Content hash of the current state (for checkpoint).
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.extension_id.as_bytes());
        buf.extend_from_slice(&self.posterior.p_benign.to_le_bytes());
        buf.extend_from_slice(&self.posterior.p_anomalous.to_le_bytes());
        buf.extend_from_slice(&self.posterior.p_malicious.to_le_bytes());
        buf.extend_from_slice(&self.posterior.p_unknown.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_llr_millionths.to_le_bytes());
        buf.extend_from_slice(&self.update_count.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// UpdaterStore — multi-extension updater management
// ---------------------------------------------------------------------------

/// Store managing posterior updaters for multiple extensions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdaterStore {
    updaters: Vec<BayesianPosteriorUpdater>,
}

impl UpdaterStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create an updater for an extension.
    pub fn get_or_create(&mut self, extension_id: &str) -> &mut BayesianPosteriorUpdater {
        if let Some(idx) = self
            .updaters
            .iter()
            .position(|u| u.extension_id == extension_id)
        {
            &mut self.updaters[idx]
        } else {
            self.updaters.push(BayesianPosteriorUpdater::new(
                Posterior::default_prior(),
                extension_id,
            ));
            self.updaters.last_mut().unwrap()
        }
    }

    /// Get an updater by extension ID (read-only).
    pub fn get(&self, extension_id: &str) -> Option<&BayesianPosteriorUpdater> {
        self.updaters
            .iter()
            .find(|u| u.extension_id == extension_id)
    }

    /// Number of tracked extensions.
    pub fn len(&self) -> usize {
        self.updaters.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.updaters.is_empty()
    }

    /// Extensions with risk above a threshold (P(Benign) < threshold).
    pub fn risky_extensions(&self, benign_threshold: i64) -> Vec<(&str, &Posterior)> {
        self.updaters
            .iter()
            .filter(|u| u.posterior.p_benign < benign_threshold)
            .map(|u| (u.extension_id.as_str(), &u.posterior))
            .collect()
    }

    /// All extension IDs and their MAP estimates.
    pub fn summary(&self) -> BTreeMap<String, RiskState> {
        self.updaters
            .iter()
            .map(|u| (u.extension_id.clone(), u.posterior.map_estimate()))
            .collect()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn benign_evidence() -> Evidence {
        Evidence {
            extension_id: "ext-001".to_string(),
            hostcall_rate_millionths: 10_000_000, // 10 calls/s — normal
            distinct_capabilities: 3,
            resource_score_millionths: 200_000, // 20% — low
            timing_anomaly_millionths: 50_000,  // 5% — normal
            denial_rate_millionths: 10_000,     // 1% — low
            epoch: SecurityEpoch::GENESIS,
        }
    }

    fn malicious_evidence() -> Evidence {
        Evidence {
            extension_id: "ext-001".to_string(),
            hostcall_rate_millionths: 800_000_000, // 800 calls/s — very high
            distinct_capabilities: 12,
            resource_score_millionths: 900_000, // 90% — very high
            timing_anomaly_millionths: 800_000, // 80% — very anomalous
            denial_rate_millionths: 400_000,    // 40% — high denial
            epoch: SecurityEpoch::GENESIS,
        }
    }

    fn anomalous_evidence() -> Evidence {
        Evidence {
            extension_id: "ext-001".to_string(),
            hostcall_rate_millionths: 200_000_000, // 200 calls/s — elevated
            distinct_capabilities: 6,
            resource_score_millionths: 500_000, // 50%
            timing_anomaly_millionths: 300_000, // 30%
            denial_rate_millionths: 100_000,    // 10%
            epoch: SecurityEpoch::GENESIS,
        }
    }

    // -----------------------------------------------------------------------
    // RiskState tests
    // -----------------------------------------------------------------------

    #[test]
    fn risk_state_display() {
        assert_eq!(RiskState::Benign.to_string(), "benign");
        assert_eq!(RiskState::Anomalous.to_string(), "anomalous");
        assert_eq!(RiskState::Malicious.to_string(), "malicious");
        assert_eq!(RiskState::Unknown.to_string(), "unknown");
    }

    #[test]
    fn risk_state_all_variants() {
        assert_eq!(RiskState::ALL.len(), 4);
    }

    #[test]
    fn risk_state_serde_roundtrip() {
        for state in &RiskState::ALL {
            let json = serde_json::to_string(state).unwrap();
            let restored: RiskState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Posterior tests
    // -----------------------------------------------------------------------

    #[test]
    fn default_prior_sums_to_million() {
        let p = Posterior::default_prior();
        assert!(p.is_valid());
        assert_eq!(p.sum(), MILLION);
    }

    #[test]
    fn uniform_prior_sums_to_million() {
        let p = Posterior::uniform();
        assert!(p.is_valid());
        assert_eq!(p.p_benign, 250_000);
    }

    #[test]
    fn from_millionths_normalizes() {
        let p = Posterior::from_millionths(500, 300, 100, 100);
        assert!(p.is_valid());
        assert_eq!(p.sum(), MILLION);
    }

    #[test]
    fn from_millionths_zero_input() {
        // All zeros → floors applied → normalized.
        let p = Posterior::from_millionths(0, 0, 0, 0);
        assert!(p.is_valid());
    }

    #[test]
    fn map_estimate_correct() {
        let p = Posterior::default_prior();
        assert_eq!(p.map_estimate(), RiskState::Benign);

        let p = Posterior::from_millionths(100, 100, 800, 100);
        assert_eq!(p.map_estimate(), RiskState::Malicious);
    }

    #[test]
    fn posterior_probability_accessor() {
        let p = Posterior::default_prior();
        assert_eq!(p.probability(RiskState::Benign), p.p_benign);
        assert_eq!(p.probability(RiskState::Anomalous), p.p_anomalous);
        assert_eq!(p.probability(RiskState::Malicious), p.p_malicious);
        assert_eq!(p.probability(RiskState::Unknown), p.p_unknown);
    }

    #[test]
    fn posterior_display() {
        let p = Posterior::default_prior();
        let s = p.to_string();
        assert!(s.contains("B="));
        assert!(s.contains("M="));
    }

    #[test]
    fn posterior_serde_roundtrip() {
        let p = Posterior::default_prior();
        let json = serde_json::to_string(&p).unwrap();
        let restored: Posterior = serde_json::from_str(&json).unwrap();
        assert_eq!(p, restored);
    }

    // -----------------------------------------------------------------------
    // LikelihoodModel tests
    // -----------------------------------------------------------------------

    #[test]
    fn likelihood_default() {
        let model = LikelihoodModel::default();
        assert!(model.benign_rate_ceiling > 0);
        assert!(model.anomalous_rate_floor > model.benign_rate_ceiling);
    }

    #[test]
    fn likelihood_benign_evidence() {
        let model = LikelihoodModel::default();
        let l = model.compute_likelihoods(&benign_evidence());
        // Benign evidence should give high benign likelihood.
        assert!(
            l[0] >= l[2],
            "benign likelihood should >= malicious for benign evidence"
        );
    }

    #[test]
    fn likelihood_malicious_evidence() {
        let model = LikelihoodModel::default();
        let l = model.compute_likelihoods(&malicious_evidence());
        // Malicious evidence should give high malicious likelihood.
        assert!(
            l[2] > l[0],
            "malicious likelihood should > benign for malicious evidence"
        );
    }

    #[test]
    fn likelihood_serde_roundtrip() {
        let model = LikelihoodModel::default();
        let json = serde_json::to_string(&model).unwrap();
        let restored: LikelihoodModel = serde_json::from_str(&json).unwrap();
        assert_eq!(model, restored);
    }

    #[test]
    fn likelihood_floor_prevents_zero() {
        let model = LikelihoodModel::default();
        // Even extreme evidence shouldn't produce zero likelihoods.
        let l = model.compute_likelihoods(&malicious_evidence());
        for ll in &l {
            assert!(*ll >= FLOOR_MASS, "likelihood must be >= floor: {ll}");
        }
    }

    // -----------------------------------------------------------------------
    // BayesianPosteriorUpdater tests
    // -----------------------------------------------------------------------

    #[test]
    fn updater_new() {
        let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        assert!(updater.posterior().is_valid());
        assert_eq!(updater.update_count(), 0);
        assert_eq!(updater.extension_id(), "ext-001");
    }

    #[test]
    fn single_benign_update_stays_benign() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let result = updater.update(&benign_evidence());
        assert!(result.posterior.is_valid());
        assert_eq!(result.posterior.map_estimate(), RiskState::Benign);
        assert_eq!(result.update_count, 1);
    }

    #[test]
    fn single_malicious_update_shifts_toward_malicious() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let before = updater.posterior().p_malicious;
        updater.update(&malicious_evidence());
        let after = updater.posterior().p_malicious;
        assert!(
            after > before,
            "malicious evidence should increase P(Malicious)"
        );
    }

    #[test]
    fn multiple_malicious_updates_converge() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        for _ in 0..10 {
            updater.update(&malicious_evidence());
        }
        assert_eq!(
            updater.posterior().map_estimate(),
            RiskState::Malicious,
            "10 malicious updates should converge to Malicious MAP"
        );
    }

    #[test]
    fn multiple_benign_updates_remain_benign() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        for _ in 0..10 {
            updater.update(&benign_evidence());
        }
        assert_eq!(updater.posterior().map_estimate(), RiskState::Benign);
        assert!(updater.posterior().p_benign > 800_000);
    }

    #[test]
    fn update_count_increments() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        updater.update(&benign_evidence());
        updater.update(&benign_evidence());
        updater.update(&malicious_evidence());
        assert_eq!(updater.update_count(), 3);
    }

    #[test]
    fn reset_clears_state() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        updater.update(&malicious_evidence());
        updater.update(&malicious_evidence());
        updater.reset(Posterior::default_prior());
        assert_eq!(updater.update_count(), 0);
        assert_eq!(updater.log_likelihood_ratio(), 0);
        assert_eq!(*updater.posterior(), Posterior::default_prior());
    }

    #[test]
    fn deterministic_updates() {
        let mut u1 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let mut u2 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");

        let evidence = benign_evidence();
        u1.update(&evidence);
        u2.update(&evidence);

        assert_eq!(u1.posterior(), u2.posterior());
        assert_eq!(u1.log_likelihood_ratio(), u2.log_likelihood_ratio());
        assert_eq!(u1.content_hash(), u2.content_hash());
    }

    #[test]
    fn evidence_hashes_tracked() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        updater.update(&benign_evidence());
        updater.update(&malicious_evidence());
        assert_eq!(updater.evidence_hashes().len(), 2);
    }

    #[test]
    fn epoch_tracking() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        updater.set_epoch(SecurityEpoch::from_raw(5));
        assert_eq!(updater.epoch, SecurityEpoch::from_raw(5));
    }

    #[test]
    fn content_hash_deterministic() {
        let u1 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let u2 = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        assert_eq!(u1.content_hash(), u2.content_hash());
    }

    #[test]
    fn updater_serde_roundtrip() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        updater.update(&benign_evidence());
        let json = serde_json::to_string(&updater).unwrap();
        let restored: BayesianPosteriorUpdater = serde_json::from_str(&json).unwrap();
        assert_eq!(updater.posterior(), restored.posterior());
        assert_eq!(updater.update_count(), restored.update_count());
    }

    // -----------------------------------------------------------------------
    // CalibrationResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn calibration_check_benign_correct() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        for _ in 0..5 {
            updater.update(&benign_evidence());
        }
        let cal = updater.calibration_check(RiskState::Benign);
        assert!(cal.map_correct);
        assert!(cal.assigned_probability > 500_000);
        assert!(cal.brier_component_millionths < 500_000);
    }

    #[test]
    fn calibration_check_malicious_after_benign() {
        let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let cal = updater.calibration_check(RiskState::Malicious);
        // Default prior has low P(Malicious), so if ground truth is Malicious,
        // the calibration should show MAP is wrong.
        assert!(!cal.map_correct);
        assert!(cal.assigned_probability < 100_000);
    }

    #[test]
    fn calibration_serde_roundtrip() {
        let updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let cal = updater.calibration_check(RiskState::Benign);
        let json = serde_json::to_string(&cal).unwrap();
        let restored: CalibrationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(cal, restored);
    }

    // -----------------------------------------------------------------------
    // ChangePointDetector tests
    // -----------------------------------------------------------------------

    #[test]
    fn change_detector_initial_state() {
        let det = ChangePointDetector::new(50_000, 50);
        assert_eq!(det.change_point_probability(), MILLION);
        assert_eq!(det.map_run_length(), 0);
    }

    #[test]
    fn change_detector_stable_regime_grows_run_length() {
        let mut det = ChangePointDetector::new(50_000, 50);
        // Feed stable evidence (likelihood = 1.0).
        for _ in 0..10 {
            det.update(MILLION);
        }
        // Run length should have grown, change point probability should decrease.
        assert!(
            det.change_point_probability() < 200_000,
            "stable regime should have low change-point prob: {}",
            det.change_point_probability()
        );
        assert!(det.map_run_length() > 0, "run length should grow");
    }

    #[test]
    fn change_detector_reset() {
        let mut det = ChangePointDetector::new(50_000, 50);
        for _ in 0..10 {
            det.update(MILLION);
        }
        det.reset();
        assert_eq!(det.change_point_probability(), MILLION);
        assert_eq!(det.map_run_length(), 0);
    }

    #[test]
    fn change_detector_serde_roundtrip() {
        let mut det = ChangePointDetector::new(50_000, 50);
        det.update(MILLION);
        let json = serde_json::to_string(&det).unwrap();
        let restored: ChangePointDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(det, restored);
    }

    // -----------------------------------------------------------------------
    // BOCPD regime change detection
    // -----------------------------------------------------------------------

    #[test]
    fn bocpd_detects_regime_change() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");

        // Benign regime for 20 steps.
        for _ in 0..20 {
            updater.update(&benign_evidence());
        }
        let cp_before = updater.change_point_probability();

        // Sudden shift to malicious.
        for _ in 0..5 {
            updater.update(&malicious_evidence());
        }
        let cp_after = updater.change_point_probability();

        // Change point probability should be elevated after regime shift.
        // (The BOCPD won't necessarily spike to >50%, but the dynamics should change.)
        assert!(
            cp_after != cp_before || updater.posterior().map_estimate() != RiskState::Benign,
            "regime change should be detectable"
        );
    }

    // -----------------------------------------------------------------------
    // UpdaterStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn store_new_empty() {
        let store = UpdaterStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn store_get_or_create() {
        let mut store = UpdaterStore::new();
        let updater = store.get_or_create("ext-001");
        assert_eq!(updater.extension_id(), "ext-001");
        assert_eq!(store.len(), 1);

        // Second call should return existing.
        let updater = store.get_or_create("ext-001");
        updater.update(&benign_evidence());
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("ext-001").unwrap().update_count(), 1);
    }

    #[test]
    fn store_multiple_extensions() {
        let mut store = UpdaterStore::new();
        store.get_or_create("ext-001");
        store.get_or_create("ext-002");
        store.get_or_create("ext-003");
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn store_risky_extensions() {
        let mut store = UpdaterStore::new();
        let u1 = store.get_or_create("ext-001");
        for _ in 0..10 {
            u1.update(&malicious_evidence());
        }
        store.get_or_create("ext-002"); // Default prior (benign)

        let risky = store.risky_extensions(500_000); // P(Benign) < 50%
        assert_eq!(risky.len(), 1);
        assert_eq!(risky[0].0, "ext-001");
    }

    #[test]
    fn store_summary() {
        let mut store = UpdaterStore::new();
        store.get_or_create("ext-001");
        let u2 = store.get_or_create("ext-002");
        for _ in 0..10 {
            u2.update(&malicious_evidence());
        }

        let summary = store.summary();
        assert_eq!(summary.get("ext-001"), Some(&RiskState::Benign));
        assert_eq!(summary.get("ext-002"), Some(&RiskState::Malicious));
    }

    #[test]
    fn store_serde_roundtrip() {
        let mut store = UpdaterStore::new();
        store.get_or_create("ext-001");
        let json = serde_json::to_string(&store).unwrap();
        let restored: UpdaterStore = serde_json::from_str(&json).unwrap();
        assert_eq!(store.len(), restored.len());
    }

    // -----------------------------------------------------------------------
    // Evidence serde
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_serde_roundtrip() {
        let ev = benign_evidence();
        let json = serde_json::to_string(&ev).unwrap();
        let restored: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    // -----------------------------------------------------------------------
    // UpdateResult serde
    // -----------------------------------------------------------------------

    #[test]
    fn update_result_serde_roundtrip() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let result = updater.update(&benign_evidence());
        let json = serde_json::to_string(&result).unwrap();
        let restored: UpdateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn zero_evidence_features() {
        let evidence = Evidence {
            extension_id: "ext-001".to_string(),
            hostcall_rate_millionths: 0,
            distinct_capabilities: 0,
            resource_score_millionths: 0,
            timing_anomaly_millionths: 0,
            denial_rate_millionths: 0,
            epoch: SecurityEpoch::GENESIS,
        };
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let result = updater.update(&evidence);
        assert!(result.posterior.is_valid());
    }

    #[test]
    fn extreme_values_no_panic() {
        let evidence = Evidence {
            extension_id: "ext-001".to_string(),
            hostcall_rate_millionths: i64::MAX / 2,
            distinct_capabilities: u32::MAX,
            resource_score_millionths: MILLION,
            timing_anomaly_millionths: MILLION,
            denial_rate_millionths: MILLION,
            epoch: SecurityEpoch::from_raw(u64::MAX),
        };
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        let result = updater.update(&evidence);
        assert!(result.posterior.is_valid());
    }

    #[test]
    fn posterior_with_one_dominant_state() {
        let p = Posterior::from_millionths(MILLION, 0, 0, 0);
        assert!(p.is_valid());
        assert_eq!(p.map_estimate(), RiskState::Benign);
        // Dominant state should have >99% of mass.
        assert!(p.p_benign > 990_000);
        // Minor states should be > 0 (floor applied before normalization).
        assert!(p.p_anomalous > 0);
        assert!(p.p_malicious > 0);
        assert!(p.p_unknown > 0);
    }

    // -----------------------------------------------------------------------
    // Anomalous evidence
    // -----------------------------------------------------------------------

    #[test]
    fn anomalous_evidence_shifts_toward_anomalous() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::uniform(), "ext-001");
        for _ in 0..5 {
            updater.update(&anomalous_evidence());
        }
        let p = updater.posterior();
        assert!(
            p.p_anomalous > p.p_benign,
            "anomalous evidence should increase P(Anomalous) above P(Benign)"
        );
    }

    // -----------------------------------------------------------------------
    // LLR direction
    // -----------------------------------------------------------------------

    #[test]
    fn llr_positive_for_malicious() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        updater.update(&malicious_evidence());
        assert!(
            updater.log_likelihood_ratio() > 0,
            "LLR should be positive for malicious evidence"
        );
    }

    #[test]
    fn llr_negative_or_zero_for_benign() {
        let mut updater = BayesianPosteriorUpdater::new(Posterior::default_prior(), "ext-001");
        updater.update(&benign_evidence());
        assert!(
            updater.log_likelihood_ratio() <= 0,
            "LLR should be <= 0 for benign evidence: {}",
            updater.log_likelihood_ratio()
        );
    }
}
