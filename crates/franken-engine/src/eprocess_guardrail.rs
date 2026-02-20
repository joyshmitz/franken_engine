//! E-process guardrail integration for hard-blocking unsafe automatic retunes.
//!
//! E-process (anytime-valid sequential testing) guardrails provide
//! mathematically rigorous boundaries that the PolicyController must never
//! violate, regardless of expected-loss calculations.  Each guardrail
//! accumulates an e-value (product of likelihood ratios); when the e-value
//! exceeds the rejection threshold the guardrail triggers and blocks
//! specified actions until an authorized reset.
//!
//! Plan references: Section 10.11 item 14, 9G.5 (policy controller
//! with expected-loss actions under guardrails), Top-10 #2 (guardplane),
//! #8 (per-extension resource budget).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// GuardrailState — Active / Triggered / Suspended
// ---------------------------------------------------------------------------

/// State of an e-process guardrail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardrailState {
    /// Actively accumulating evidence; not yet triggered.
    Active,
    /// E-value exceeded threshold; actions are blocked.
    Triggered,
    /// Temporarily suspended by operator (not accumulating).
    Suspended,
}

impl fmt::Display for GuardrailState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Triggered => write!(f, "triggered"),
            Self::Suspended => write!(f, "suspended"),
        }
    }
}

// ---------------------------------------------------------------------------
// LikelihoodRatioFn — pluggable evidence update
// ---------------------------------------------------------------------------

/// A likelihood-ratio function that maps an observation to a ratio.
///
/// Given an observation value (fixed-point millionths), returns the
/// likelihood ratio L(observation | H1) / L(observation | H0) as
/// fixed-point millionths (1_000_000 = 1.0).
///
/// Returns `None` if the observation is outside the valid domain.
pub trait LikelihoodRatioFn: fmt::Debug {
    /// Compute the likelihood ratio for a single observation.
    fn ratio(&self, observation_millionths: i64) -> Option<i64>;

    /// Human-readable family name (e.g., "normal", "binomial").
    fn family(&self) -> &str;
}

/// Simple threshold-based likelihood ratio: returns `high_ratio` when the
/// observation exceeds the threshold, `low_ratio` otherwise.
///
/// Useful for binary alarm signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdLikelihoodRatio {
    /// Observation threshold (millionths).
    pub threshold_millionths: i64,
    /// Ratio when observation >= threshold.
    pub high_ratio_millionths: i64,
    /// Ratio when observation < threshold.
    pub low_ratio_millionths: i64,
}

impl LikelihoodRatioFn for ThresholdLikelihoodRatio {
    fn ratio(&self, observation_millionths: i64) -> Option<i64> {
        if observation_millionths >= self.threshold_millionths {
            Some(self.high_ratio_millionths)
        } else {
            Some(self.low_ratio_millionths)
        }
    }

    fn family(&self) -> &str {
        "threshold"
    }
}

/// Universal inference e-value: ratio = observation / null_mean.
///
/// Model-free construction: e_t = X_t / mu_0 where mu_0 is the null
/// hypothesis mean.  Returns millionths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalLikelihoodRatio {
    /// Null hypothesis mean (millionths).
    pub null_mean_millionths: i64,
}

impl LikelihoodRatioFn for UniversalLikelihoodRatio {
    fn ratio(&self, observation_millionths: i64) -> Option<i64> {
        if self.null_mean_millionths == 0 {
            return None;
        }
        // ratio = observation / null_mean, in millionths
        let r = (observation_millionths as i128 * 1_000_000) / self.null_mean_millionths as i128;
        Some(r as i64)
    }

    fn family(&self) -> &str {
        "universal"
    }
}

// ---------------------------------------------------------------------------
// GuardrailError
// ---------------------------------------------------------------------------

/// Errors from e-process guardrail operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardrailError {
    /// Guardrail is suspended; cannot update.
    Suspended { guardrail_id: String },
    /// Guardrail is already triggered; update is a no-op.
    AlreadyTriggered { guardrail_id: String },
    /// Likelihood ratio function returned None (invalid observation).
    InvalidObservation { guardrail_id: String },
    /// Reset requires authorization (no valid reset receipt).
    ResetUnauthorized { guardrail_id: String },
    /// Guardrail is not in triggered state; cannot reset.
    NotTriggered { guardrail_id: String },
    /// E-value overflow (would exceed i64 range).
    EValueOverflow { guardrail_id: String },
}

impl fmt::Display for GuardrailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suspended { guardrail_id } => {
                write!(f, "guardrail '{guardrail_id}' is suspended")
            }
            Self::AlreadyTriggered { guardrail_id } => {
                write!(f, "guardrail '{guardrail_id}' already triggered")
            }
            Self::InvalidObservation { guardrail_id } => {
                write!(f, "invalid observation for guardrail '{guardrail_id}'")
            }
            Self::ResetUnauthorized { guardrail_id } => {
                write!(f, "unauthorized reset for guardrail '{guardrail_id}'")
            }
            Self::NotTriggered { guardrail_id } => {
                write!(f, "guardrail '{guardrail_id}' is not triggered")
            }
            Self::EValueOverflow { guardrail_id } => {
                write!(f, "e-value overflow for guardrail '{guardrail_id}'")
            }
        }
    }
}

impl std::error::Error for GuardrailError {}

// ---------------------------------------------------------------------------
// ResetReceipt — authorization for resetting a triggered guardrail
// ---------------------------------------------------------------------------

/// Authorization receipt for resetting a triggered guardrail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetReceipt {
    /// Who authorized the reset (operator id or epoch transition).
    pub authorized_by: String,
    /// Rationale for the reset.
    pub rationale: String,
    /// Epoch at which the reset occurs.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// GuardrailEvent — structured event for evidence emission
// ---------------------------------------------------------------------------

/// Structured event emitted by guardrail state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardrailEvent {
    /// E-value was updated.
    EValueUpdated {
        guardrail_id: String,
        previous_e_value: i64,
        new_e_value: i64,
        observation: i64,
        likelihood_ratio: i64,
    },
    /// Guardrail triggered (e-value exceeded threshold).
    Triggered {
        guardrail_id: String,
        e_value: i64,
        threshold: i64,
        blocked_actions: Vec<String>,
    },
    /// Guardrail was reset.
    Reset {
        guardrail_id: String,
        authorized_by: String,
        rationale: String,
        epoch: SecurityEpoch,
    },
    /// Guardrail was suspended.
    SuspendedEvent {
        guardrail_id: String,
        reason: String,
    },
    /// Guardrail was resumed from suspension.
    Resumed { guardrail_id: String },
}

// ---------------------------------------------------------------------------
// EProcessGuardrail — single anytime-valid sequential constraint
// ---------------------------------------------------------------------------

/// A single e-process guardrail representing an anytime-valid sequential
/// constraint.
///
/// Accumulates an e-value (product of likelihood ratios) from a metric
/// stream.  When the e-value exceeds the rejection threshold, the guardrail
/// triggers and blocks specified actions.
#[derive(Debug)]
pub struct EProcessGuardrail {
    /// Unique guardrail identifier.
    pub guardrail_id: String,
    /// Metric/evidence stream being monitored.
    pub metric_stream: String,
    /// Current accumulated e-value (fixed-point millionths; 1_000_000 = 1.0).
    e_value_millionths: i64,
    /// Rejection threshold (default: 1/alpha for significance level alpha).
    threshold_millionths: i64,
    /// Description of the safety condition being guarded.
    pub null_hypothesis: String,
    /// Current state.
    state: GuardrailState,
    /// Actions blocked when triggered.
    blocked_actions: BTreeSet<String>,
    /// Epoch at which this guardrail was configured.
    config_epoch: SecurityEpoch,
    /// Number of observations processed.
    observation_count: u64,
    /// Event log for evidence emission.
    events: Vec<GuardrailEvent>,
    /// Pluggable likelihood ratio function.
    lr_fn: Box<dyn LikelihoodRatioFn>,
}

impl EProcessGuardrail {
    /// Create a new active guardrail.
    ///
    /// - `threshold_millionths`: rejection threshold (e.g., 20_000_000 for alpha=0.05).
    /// - `blocked_actions`: actions to block when triggered.
    /// - `lr_fn`: likelihood ratio function for evidence updates.
    pub fn new(
        guardrail_id: impl Into<String>,
        metric_stream: impl Into<String>,
        null_hypothesis: impl Into<String>,
        threshold_millionths: i64,
        blocked_actions: BTreeSet<String>,
        config_epoch: SecurityEpoch,
        lr_fn: Box<dyn LikelihoodRatioFn>,
    ) -> Self {
        Self {
            guardrail_id: guardrail_id.into(),
            metric_stream: metric_stream.into(),
            e_value_millionths: 1_000_000, // start at 1.0
            threshold_millionths,
            null_hypothesis: null_hypothesis.into(),
            state: GuardrailState::Active,
            blocked_actions,
            config_epoch,
            observation_count: 0,
            events: Vec::new(),
            lr_fn,
        }
    }

    /// Current e-value (millionths).
    pub fn e_value(&self) -> i64 {
        self.e_value_millionths
    }

    /// Rejection threshold (millionths).
    pub fn threshold(&self) -> i64 {
        self.threshold_millionths
    }

    /// Current state.
    pub fn state(&self) -> GuardrailState {
        self.state
    }

    /// Actions blocked by this guardrail (only meaningful when triggered).
    pub fn blocked_actions(&self) -> &BTreeSet<String> {
        &self.blocked_actions
    }

    /// Configuration epoch.
    pub fn config_epoch(&self) -> SecurityEpoch {
        self.config_epoch
    }

    /// Number of observations processed.
    pub fn observation_count(&self) -> u64 {
        self.observation_count
    }

    /// Drain and return accumulated events.
    pub fn drain_events(&mut self) -> Vec<GuardrailEvent> {
        std::mem::take(&mut self.events)
    }

    /// Check if a specific action is blocked by this guardrail.
    pub fn blocks(&self, action: &str) -> bool {
        self.state == GuardrailState::Triggered && self.blocked_actions.contains(action)
    }

    /// Update the e-value with a new observation.
    ///
    /// The e-value is updated as: `e_new = e_old * lr(observation) / 1_000_000`
    /// (dividing by 1M to maintain fixed-point scale).
    ///
    /// If the updated e-value >= threshold, the guardrail transitions to
    /// `Triggered` and emits a `GuardrailEvent::Triggered`.
    pub fn update(&mut self, observation_millionths: i64) -> Result<(), GuardrailError> {
        match self.state {
            GuardrailState::Suspended => {
                return Err(GuardrailError::Suspended {
                    guardrail_id: self.guardrail_id.clone(),
                });
            }
            GuardrailState::Triggered => {
                return Err(GuardrailError::AlreadyTriggered {
                    guardrail_id: self.guardrail_id.clone(),
                });
            }
            GuardrailState::Active => {}
        }

        let lr = self.lr_fn.ratio(observation_millionths).ok_or_else(|| {
            GuardrailError::InvalidObservation {
                guardrail_id: self.guardrail_id.clone(),
            }
        })?;

        let previous = self.e_value_millionths;

        // e_new = e_old * lr / 1_000_000 (fixed-point multiply)
        let product = self.e_value_millionths as i128 * lr as i128;
        let new_val = product / 1_000_000;

        if new_val > i64::MAX as i128 {
            return Err(GuardrailError::EValueOverflow {
                guardrail_id: self.guardrail_id.clone(),
            });
        }

        self.e_value_millionths = new_val as i64;
        self.observation_count += 1;

        self.events.push(GuardrailEvent::EValueUpdated {
            guardrail_id: self.guardrail_id.clone(),
            previous_e_value: previous,
            new_e_value: self.e_value_millionths,
            observation: observation_millionths,
            likelihood_ratio: lr,
        });

        // Check threshold.
        if self.e_value_millionths >= self.threshold_millionths {
            self.state = GuardrailState::Triggered;
            self.events.push(GuardrailEvent::Triggered {
                guardrail_id: self.guardrail_id.clone(),
                e_value: self.e_value_millionths,
                threshold: self.threshold_millionths,
                blocked_actions: self.blocked_actions.iter().cloned().collect(),
            });
        }

        Ok(())
    }

    /// Reset a triggered guardrail with an authorization receipt.
    ///
    /// Resets e-value to 1.0 and transitions back to Active.
    pub fn reset(&mut self, receipt: &ResetReceipt) -> Result<(), GuardrailError> {
        if self.state != GuardrailState::Triggered {
            return Err(GuardrailError::NotTriggered {
                guardrail_id: self.guardrail_id.clone(),
            });
        }

        if receipt.authorized_by.is_empty() {
            return Err(GuardrailError::ResetUnauthorized {
                guardrail_id: self.guardrail_id.clone(),
            });
        }

        self.e_value_millionths = 1_000_000; // reset to 1.0
        self.state = GuardrailState::Active;
        self.observation_count = 0;

        self.events.push(GuardrailEvent::Reset {
            guardrail_id: self.guardrail_id.clone(),
            authorized_by: receipt.authorized_by.clone(),
            rationale: receipt.rationale.clone(),
            epoch: receipt.epoch,
        });

        Ok(())
    }

    /// Suspend the guardrail (stops accumulating evidence).
    pub fn suspend(&mut self, reason: impl Into<String>) {
        self.state = GuardrailState::Suspended;
        self.events.push(GuardrailEvent::SuspendedEvent {
            guardrail_id: self.guardrail_id.clone(),
            reason: reason.into(),
        });
    }

    /// Resume a suspended guardrail.
    pub fn resume(&mut self) {
        if self.state == GuardrailState::Suspended {
            self.state = GuardrailState::Active;
            self.events.push(GuardrailEvent::Resumed {
                guardrail_id: self.guardrail_id.clone(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// GuardrailRegistry — manages multiple concurrent guardrails
// ---------------------------------------------------------------------------

/// Registry of active guardrails that the PolicyController consults.
///
/// Multiple guardrails can be active simultaneously.  An action is blocked
/// if ANY active guardrail in triggered state blocks it.
#[derive(Debug, Default)]
pub struct GuardrailRegistry {
    guardrails: Vec<EProcessGuardrail>,
}

impl GuardrailRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            guardrails: Vec::new(),
        }
    }

    /// Add a guardrail to the registry.
    pub fn add(&mut self, guardrail: EProcessGuardrail) {
        self.guardrails.push(guardrail);
    }

    /// Number of guardrails.
    pub fn len(&self) -> usize {
        self.guardrails.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.guardrails.is_empty()
    }

    /// Get the set of all currently blocked actions (union across all
    /// triggered guardrails).
    pub fn blocked_actions(&self) -> BTreeSet<String> {
        let mut blocked = BTreeSet::new();
        for gr in &self.guardrails {
            if gr.state() == GuardrailState::Triggered {
                blocked.extend(gr.blocked_actions().iter().cloned());
            }
        }
        blocked
    }

    /// Check if a specific action is blocked by any triggered guardrail.
    pub fn is_blocked(&self, action: &str) -> bool {
        self.guardrails.iter().any(|gr| gr.blocks(action))
    }

    /// Get all blocking guardrail IDs for a given action.
    pub fn blocking_guardrails(&self, action: &str) -> Vec<String> {
        self.guardrails
            .iter()
            .filter(|gr| gr.blocks(action))
            .map(|gr| gr.guardrail_id.clone())
            .collect()
    }

    /// Compute the permitted action set: actions from `all_actions` that are
    /// not blocked by any triggered guardrail.
    pub fn permitted_actions<'a>(&self, all_actions: &'a [String]) -> Vec<&'a String> {
        all_actions.iter().filter(|a| !self.is_blocked(a)).collect()
    }

    /// Update all active guardrails with a new observation from the
    /// given metric stream.  Only guardrails matching the metric stream
    /// are updated.
    pub fn update_stream(
        &mut self,
        metric_stream: &str,
        observation_millionths: i64,
    ) -> Vec<GuardrailError> {
        let mut errors = Vec::new();
        for gr in &mut self.guardrails {
            if gr.metric_stream == metric_stream
                && gr.state() == GuardrailState::Active
                && let Err(e) = gr.update(observation_millionths)
            {
                errors.push(e);
            }
        }
        errors
    }

    /// Drain all events from all guardrails.
    pub fn drain_all_events(&mut self) -> Vec<GuardrailEvent> {
        let mut all_events = Vec::new();
        for gr in &mut self.guardrails {
            all_events.extend(gr.drain_events());
        }
        all_events
    }

    /// Get a mutable reference to a guardrail by ID.
    pub fn get_mut(&mut self, guardrail_id: &str) -> Option<&mut EProcessGuardrail> {
        self.guardrails
            .iter_mut()
            .find(|gr| gr.guardrail_id == guardrail_id)
    }

    /// Get a reference to a guardrail by ID.
    pub fn get(&self, guardrail_id: &str) -> Option<&EProcessGuardrail> {
        self.guardrails
            .iter()
            .find(|gr| gr.guardrail_id == guardrail_id)
    }

    /// Reset all guardrails for a new epoch (operator-driven bulk reset).
    pub fn reset_all(&mut self, receipt: &ResetReceipt) -> Vec<GuardrailError> {
        let mut errors = Vec::new();
        for gr in &mut self.guardrails {
            if gr.state() == GuardrailState::Triggered
                && let Err(e) = gr.reset(receipt)
            {
                errors.push(e);
            }
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guardrail() -> EProcessGuardrail {
        let mut blocked = BTreeSet::new();
        blocked.insert("low".to_string());
        blocked.insert("medium".to_string());

        EProcessGuardrail::new(
            "fnr-guard",
            "false_negative_rate",
            "false-negative rate <= 0.01",
            20_000_000, // threshold = 20.0 (alpha = 0.05)
            blocked,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 10_000,     // 0.01
                high_ratio_millionths: 5_000_000, // 5.0
                low_ratio_millionths: 500_000,    // 0.5
            }),
        )
    }

    // -- State lifecycle --

    #[test]
    fn new_guardrail_starts_active() {
        let gr = test_guardrail();
        assert_eq!(gr.state(), GuardrailState::Active);
        assert_eq!(gr.e_value(), 1_000_000); // 1.0
        assert_eq!(gr.observation_count(), 0);
    }

    #[test]
    fn state_display() {
        assert_eq!(GuardrailState::Active.to_string(), "active");
        assert_eq!(GuardrailState::Triggered.to_string(), "triggered");
        assert_eq!(GuardrailState::Suspended.to_string(), "suspended");
    }

    // -- E-value accumulation --

    #[test]
    fn below_threshold_observation_decreases_e_value() {
        let mut gr = test_guardrail();
        // observation = 5_000 (0.005), below threshold 10_000
        // lr = 500_000 (0.5)
        // e_new = 1_000_000 * 500_000 / 1_000_000 = 500_000 (0.5)
        gr.update(5_000).unwrap();
        assert_eq!(gr.e_value(), 500_000);
        assert_eq!(gr.state(), GuardrailState::Active);
        assert_eq!(gr.observation_count(), 1);
    }

    #[test]
    fn above_threshold_observation_increases_e_value() {
        let mut gr = test_guardrail();
        // observation = 15_000 (0.015), above threshold 10_000
        // lr = 5_000_000 (5.0)
        // e_new = 1_000_000 * 5_000_000 / 1_000_000 = 5_000_000 (5.0)
        gr.update(15_000).unwrap();
        assert_eq!(gr.e_value(), 5_000_000);
        assert_eq!(gr.state(), GuardrailState::Active);
    }

    #[test]
    fn repeated_high_observations_trigger_guardrail() {
        let mut gr = test_guardrail();
        // Each high observation multiplies e by 5.0
        // After 1: 5.0, after 2: 25.0 >= threshold 20.0 -> triggered
        gr.update(15_000).unwrap(); // e = 5.0
        assert_eq!(gr.state(), GuardrailState::Active);

        gr.update(15_000).unwrap(); // e = 25.0 >= 20.0
        assert_eq!(gr.state(), GuardrailState::Triggered);
        assert_eq!(gr.e_value(), 25_000_000);
    }

    #[test]
    fn triggered_guardrail_rejects_updates() {
        let mut gr = test_guardrail();
        gr.update(15_000).unwrap();
        gr.update(15_000).unwrap(); // triggers
        assert_eq!(gr.state(), GuardrailState::Triggered);

        let err = gr.update(15_000).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::AlreadyTriggered {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    // -- Blocking semantics --

    #[test]
    fn active_guardrail_does_not_block() {
        let gr = test_guardrail();
        assert!(!gr.blocks("low"));
        assert!(!gr.blocks("medium"));
    }

    #[test]
    fn triggered_guardrail_blocks_specified_actions() {
        let mut gr = test_guardrail();
        gr.update(15_000).unwrap();
        gr.update(15_000).unwrap(); // triggers

        assert!(gr.blocks("low"));
        assert!(gr.blocks("medium"));
        assert!(!gr.blocks("high")); // not in blocked set
    }

    // -- Reset --

    #[test]
    fn reset_triggered_guardrail() {
        let mut gr = test_guardrail();
        gr.update(15_000).unwrap();
        gr.update(15_000).unwrap(); // triggers

        let receipt = ResetReceipt {
            authorized_by: "operator-1".to_string(),
            rationale: "FNR condition addressed".to_string(),
            epoch: SecurityEpoch::from_raw(1),
        };
        gr.reset(&receipt).unwrap();

        assert_eq!(gr.state(), GuardrailState::Active);
        assert_eq!(gr.e_value(), 1_000_000); // reset to 1.0
        assert_eq!(gr.observation_count(), 0);
    }

    #[test]
    fn reset_non_triggered_fails() {
        let mut gr = test_guardrail();
        let receipt = ResetReceipt {
            authorized_by: "operator-1".to_string(),
            rationale: "test".to_string(),
            epoch: SecurityEpoch::GENESIS,
        };
        let err = gr.reset(&receipt).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::NotTriggered {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    #[test]
    fn reset_with_empty_authorized_by_fails() {
        let mut gr = test_guardrail();
        gr.update(15_000).unwrap();
        gr.update(15_000).unwrap(); // triggers

        let receipt = ResetReceipt {
            authorized_by: "".to_string(),
            rationale: "test".to_string(),
            epoch: SecurityEpoch::GENESIS,
        };
        let err = gr.reset(&receipt).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::ResetUnauthorized {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    // -- Suspend / Resume --

    #[test]
    fn suspend_stops_accumulation() {
        let mut gr = test_guardrail();
        gr.suspend("maintenance window");
        assert_eq!(gr.state(), GuardrailState::Suspended);

        let err = gr.update(15_000).unwrap_err();
        assert_eq!(
            err,
            GuardrailError::Suspended {
                guardrail_id: "fnr-guard".to_string()
            }
        );
    }

    #[test]
    fn resume_after_suspend() {
        let mut gr = test_guardrail();
        gr.suspend("maintenance");
        gr.resume();
        assert_eq!(gr.state(), GuardrailState::Active);
        gr.update(15_000).unwrap(); // works again
    }

    // -- Events --

    #[test]
    fn update_emits_e_value_updated_event() {
        let mut gr = test_guardrail();
        gr.update(5_000).unwrap();

        let events = gr.drain_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            GuardrailEvent::EValueUpdated {
                previous_e_value,
                new_e_value,
                ..
            } => {
                assert_eq!(*previous_e_value, 1_000_000);
                assert_eq!(*new_e_value, 500_000);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn trigger_emits_triggered_event() {
        let mut gr = test_guardrail();
        gr.update(15_000).unwrap();
        gr.update(15_000).unwrap(); // triggers

        let events = gr.drain_events();
        // Should have 2 update events + 1 triggered event
        assert_eq!(events.len(), 3);
        match &events[2] {
            GuardrailEvent::Triggered {
                blocked_actions,
                e_value,
                threshold,
                ..
            } => {
                assert_eq!(*e_value, 25_000_000);
                assert_eq!(*threshold, 20_000_000);
                assert_eq!(blocked_actions.len(), 2);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn reset_emits_reset_event() {
        let mut gr = test_guardrail();
        gr.update(15_000).unwrap();
        gr.update(15_000).unwrap();
        gr.drain_events(); // clear

        let receipt = ResetReceipt {
            authorized_by: "operator".to_string(),
            rationale: "addressed".to_string(),
            epoch: SecurityEpoch::from_raw(1),
        };
        gr.reset(&receipt).unwrap();

        let events = gr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], GuardrailEvent::Reset { .. }));
    }

    // -- Universal likelihood ratio --

    #[test]
    fn universal_lr_computes_ratio() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 500_000, // 0.5
        };
        // observation = 1_000_000 (1.0), ratio = 1.0/0.5 = 2.0
        assert_eq!(lr.ratio(1_000_000), Some(2_000_000));
        // observation = 250_000 (0.25), ratio = 0.25/0.5 = 0.5
        assert_eq!(lr.ratio(250_000), Some(500_000));
    }

    #[test]
    fn universal_lr_rejects_zero_mean() {
        let lr = UniversalLikelihoodRatio {
            null_mean_millionths: 0,
        };
        assert_eq!(lr.ratio(1_000_000), None);
    }

    // -- GuardrailRegistry --

    #[test]
    fn registry_blocked_actions_union() {
        let mut registry = GuardrailRegistry::new();

        let mut blocked1 = BTreeSet::new();
        blocked1.insert("low".to_string());
        let mut gr1 = EProcessGuardrail::new(
            "gr1",
            "metric-a",
            "test",
            5_000_000,
            blocked1,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        // Trigger gr1 immediately (ratio=10.0, e=10.0 >= threshold 5.0)
        gr1.update(1_000_000).unwrap();

        let mut blocked2 = BTreeSet::new();
        blocked2.insert("medium".to_string());
        let gr2 = EProcessGuardrail::new(
            "gr2",
            "metric-b",
            "test",
            100_000_000,
            blocked2,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );

        registry.add(gr1);
        registry.add(gr2);

        // gr1 is triggered (blocks "low"), gr2 is active (blocks nothing)
        let blocked = registry.blocked_actions();
        assert!(blocked.contains("low"));
        assert!(!blocked.contains("medium"));
    }

    #[test]
    fn registry_update_stream_targets_matching_guardrails() {
        let mut registry = GuardrailRegistry::new();

        let blocked = BTreeSet::new();
        let gr = EProcessGuardrail::new(
            "gr1",
            "fnr",
            "test",
            100_000_000,
            blocked,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 2_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        registry.add(gr);

        // Update matching stream
        let errors = registry.update_stream("fnr", 1_000_000);
        assert!(errors.is_empty());
        assert_eq!(registry.get("gr1").unwrap().observation_count(), 1);

        // Update non-matching stream — no effect
        let errors = registry.update_stream("other", 1_000_000);
        assert!(errors.is_empty());
        assert_eq!(registry.get("gr1").unwrap().observation_count(), 1);
    }

    #[test]
    fn registry_permitted_actions() {
        let mut registry = GuardrailRegistry::new();

        let mut blocked = BTreeSet::new();
        blocked.insert("low".to_string());
        let mut gr = EProcessGuardrail::new(
            "gr1",
            "m",
            "test",
            5_000_000,
            blocked,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        gr.update(1_000_000).unwrap(); // triggers
        registry.add(gr);

        let all = vec!["low".to_string(), "medium".to_string(), "high".to_string()];
        let permitted = registry.permitted_actions(&all);
        assert_eq!(permitted.len(), 2);
        assert!(!permitted.contains(&&"low".to_string()));
    }

    #[test]
    fn registry_reset_all() {
        let mut registry = GuardrailRegistry::new();

        let mut blocked = BTreeSet::new();
        blocked.insert("low".to_string());
        let mut gr = EProcessGuardrail::new(
            "gr1",
            "m",
            "test",
            5_000_000,
            blocked,
            SecurityEpoch::GENESIS,
            Box::new(ThresholdLikelihoodRatio {
                threshold_millionths: 0,
                high_ratio_millionths: 10_000_000,
                low_ratio_millionths: 500_000,
            }),
        );
        gr.update(1_000_000).unwrap(); // triggers
        registry.add(gr);

        let receipt = ResetReceipt {
            authorized_by: "operator".to_string(),
            rationale: "epoch transition".to_string(),
            epoch: SecurityEpoch::from_raw(1),
        };
        let errors = registry.reset_all(&receipt);
        assert!(errors.is_empty());
        assert_eq!(registry.get("gr1").unwrap().state(), GuardrailState::Active);
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_replay_produces_identical_trigger_point() {
        let observations = vec![5_000i64, 15_000, 5_000, 15_000, 15_000];

        let run = |obs: &[i64]| -> (u64, i64) {
            let mut gr = test_guardrail();
            for &o in obs {
                if gr.state() == GuardrailState::Triggered {
                    break;
                }
                let _ = gr.update(o);
            }
            (gr.observation_count(), gr.e_value())
        };

        let (count1, ev1) = run(&observations);
        let (count2, ev2) = run(&observations);
        assert_eq!(count1, count2);
        assert_eq!(ev1, ev2);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            GuardrailError::Suspended {
                guardrail_id: "g1".to_string()
            }
            .to_string(),
            "guardrail 'g1' is suspended"
        );
        assert_eq!(
            GuardrailError::AlreadyTriggered {
                guardrail_id: "g1".to_string()
            }
            .to_string(),
            "guardrail 'g1' already triggered"
        );
    }

    // -- Serialization --

    #[test]
    fn guardrail_state_serialization_round_trip() {
        let states = vec![
            GuardrailState::Active,
            GuardrailState::Triggered,
            GuardrailState::Suspended,
        ];
        for state in &states {
            let json = serde_json::to_string(state).expect("serialize");
            let restored: GuardrailState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, restored);
        }
    }

    #[test]
    fn guardrail_error_serialization_round_trip() {
        let errors = vec![
            GuardrailError::Suspended {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::AlreadyTriggered {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::InvalidObservation {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::ResetUnauthorized {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::NotTriggered {
                guardrail_id: "g".to_string(),
            },
            GuardrailError::EValueOverflow {
                guardrail_id: "g".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: GuardrailError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn reset_receipt_serialization_round_trip() {
        let receipt = ResetReceipt {
            authorized_by: "operator-1".to_string(),
            rationale: "addressed".to_string(),
            epoch: SecurityEpoch::from_raw(5),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let restored: ResetReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, restored);
    }

    #[test]
    fn guardrail_event_serialization_round_trip() {
        let events = vec![
            GuardrailEvent::EValueUpdated {
                guardrail_id: "g".to_string(),
                previous_e_value: 1_000_000,
                new_e_value: 5_000_000,
                observation: 15_000,
                likelihood_ratio: 5_000_000,
            },
            GuardrailEvent::Triggered {
                guardrail_id: "g".to_string(),
                e_value: 25_000_000,
                threshold: 20_000_000,
                blocked_actions: vec!["low".to_string()],
            },
            GuardrailEvent::Reset {
                guardrail_id: "g".to_string(),
                authorized_by: "op".to_string(),
                rationale: "ok".to_string(),
                epoch: SecurityEpoch::GENESIS,
            },
            GuardrailEvent::SuspendedEvent {
                guardrail_id: "g".to_string(),
                reason: "maint".to_string(),
            },
            GuardrailEvent::Resumed {
                guardrail_id: "g".to_string(),
            },
        ];
        for event in &events {
            let json = serde_json::to_string(event).expect("serialize");
            let restored: GuardrailEvent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*event, restored);
        }
    }

    #[test]
    fn threshold_lr_serialization_round_trip() {
        let lr = ThresholdLikelihoodRatio {
            threshold_millionths: 10_000,
            high_ratio_millionths: 5_000_000,
            low_ratio_millionths: 500_000,
        };
        let json = serde_json::to_string(&lr).expect("serialize");
        let restored: ThresholdLikelihoodRatio = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(lr.threshold_millionths, restored.threshold_millionths);
        assert_eq!(lr.high_ratio_millionths, restored.high_ratio_millionths);
    }
}
