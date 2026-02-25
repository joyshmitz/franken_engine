//! Observability Channel Model and Rate-Distortion Constitution.
//!
//! Defines a formal channel model for evidence generation and transport
//! across compiler, runtime, and control-plane paths.  Every evidence
//! payload family has explicit utility functions, distortion metrics,
//! rate-distortion envelopes, and failure budgets.
//!
//! The constitutional policy forbids:
//! - uncapped telemetry (every channel has a rate budget),
//! - unverifiable lossy compression (distortion must be measurable),
//! - evidence emission without backpressure bounds.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Plan reference: FRX-17.1 (Observability Channel Model).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for channel model artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.observability-channel.v1";

// ---------------------------------------------------------------------------
// PayloadFamily — evidence payload taxonomy
// ---------------------------------------------------------------------------

/// Evidence payload family classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFamily {
    /// Decision evidence: lane routing, containment, fallback decisions.
    Decision,
    /// Replay evidence: deterministic replay transcripts and traces.
    Replay,
    /// Optimization evidence: compilation pass witnesses, e-graph logs.
    Optimization,
    /// Security evidence: capability grants, revocations, incident records.
    Security,
    /// Legal provenance: audit chains, compliance artifacts, retention records.
    LegalProvenance,
}

impl PayloadFamily {
    pub const ALL: [PayloadFamily; 5] = [
        PayloadFamily::Decision,
        PayloadFamily::Replay,
        PayloadFamily::Optimization,
        PayloadFamily::Security,
        PayloadFamily::LegalProvenance,
    ];
}

impl fmt::Display for PayloadFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decision => write!(f, "decision"),
            Self::Replay => write!(f, "replay"),
            Self::Optimization => write!(f, "optimization"),
            Self::Security => write!(f, "security"),
            Self::LegalProvenance => write!(f, "legal_provenance"),
        }
    }
}

// ---------------------------------------------------------------------------
// DistortionMetric — how we measure information loss
// ---------------------------------------------------------------------------

/// Metric used to quantify distortion when compressing or sampling evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistortionMetric {
    /// Hamming distortion: fraction of symbols that differ.
    Hamming,
    /// Squared error distortion (for quantile-valued payloads).
    SquaredError,
    /// Log-loss distortion (for probability-valued payloads).
    LogLoss,
    /// Edit distance distortion (for structured trace payloads).
    EditDistance,
    /// Binary: either lossless or total loss (for legal provenance).
    BinaryFidelity,
}

impl fmt::Display for DistortionMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hamming => write!(f, "hamming"),
            Self::SquaredError => write!(f, "squared_error"),
            Self::LogLoss => write!(f, "log_loss"),
            Self::EditDistance => write!(f, "edit_distance"),
            Self::BinaryFidelity => write!(f, "binary_fidelity"),
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelPath — where evidence flows
// ---------------------------------------------------------------------------

/// The pipeline path through which evidence travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPath {
    /// Compiler output → evidence ledger.
    CompilerToLedger,
    /// Runtime controller → evidence ledger.
    RuntimeToLedger,
    /// Control plane → governance audit.
    ControlPlaneToAudit,
    /// Cross-lane replay → deterministic verifier.
    ReplayToVerifier,
    /// Any path → external compliance archive.
    ToComplianceArchive,
}

impl ChannelPath {
    pub const ALL: [ChannelPath; 5] = [
        ChannelPath::CompilerToLedger,
        ChannelPath::RuntimeToLedger,
        ChannelPath::ControlPlaneToAudit,
        ChannelPath::ReplayToVerifier,
        ChannelPath::ToComplianceArchive,
    ];
}

impl fmt::Display for ChannelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompilerToLedger => write!(f, "compiler_to_ledger"),
            Self::RuntimeToLedger => write!(f, "runtime_to_ledger"),
            Self::ControlPlaneToAudit => write!(f, "control_plane_to_audit"),
            Self::ReplayToVerifier => write!(f, "replay_to_verifier"),
            Self::ToComplianceArchive => write!(f, "to_compliance_archive"),
        }
    }
}

// ---------------------------------------------------------------------------
// RateDistortionPoint — a single operating point on the R(D) curve
// ---------------------------------------------------------------------------

/// A single point on the rate-distortion frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateDistortionPoint {
    /// Distortion level (millionths of the distortion metric's unit).
    pub distortion_millionths: i64,
    /// Rate in millibits per symbol (millionths of bits).
    pub rate_millibits: i64,
}

// ---------------------------------------------------------------------------
// RateDistortionEnvelope — the achievable frontier for a family
// ---------------------------------------------------------------------------

/// Rate-distortion envelope for one payload family.
///
/// Defines the minimum rate (bits) needed to represent the payload at
/// each distortion level, plus operational constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateDistortionEnvelope {
    /// Which payload family this envelope covers.
    pub family: PayloadFamily,
    /// The distortion metric used.
    pub metric: DistortionMetric,
    /// Frontier points (sorted by increasing distortion).
    pub frontier: Vec<RateDistortionPoint>,
    /// Maximum tolerable distortion (millionths).  Above this, the
    /// evidence is considered unverifiable and must be rejected.
    pub max_distortion_millionths: i64,
    /// Minimum required rate (millibits per symbol).  Below this,
    /// the compression is considered insufficient quality.
    pub min_rate_millibits: i64,
}

impl RateDistortionEnvelope {
    /// Interpolate the frontier to find the rate for a given distortion.
    ///
    /// Returns `None` if distortion exceeds `max_distortion_millionths`
    /// or if the frontier is empty.
    pub fn rate_at_distortion(&self, distortion_millionths: i64) -> Option<i64> {
        if distortion_millionths > self.max_distortion_millionths {
            return None;
        }
        if self.frontier.is_empty() {
            return None;
        }
        // Find surrounding points and linearly interpolate.
        let mut prev: Option<&RateDistortionPoint> = None;
        for pt in &self.frontier {
            if pt.distortion_millionths >= distortion_millionths {
                if let Some(p) = prev {
                    // Linear interpolation.
                    let dd = pt.distortion_millionths - p.distortion_millionths;
                    if dd == 0 {
                        return Some(pt.rate_millibits);
                    }
                    let frac = distortion_millionths - p.distortion_millionths;
                    let dr = pt.rate_millibits - p.rate_millibits;
                    return Some(p.rate_millibits + (dr * frac) / dd);
                }
                return Some(pt.rate_millibits);
            }
            prev = Some(pt);
        }
        // Past last point — use last point's rate.
        self.frontier.last().map(|pt| pt.rate_millibits)
    }

    /// Check if a given (rate, distortion) operating point is within the
    /// achievable region.
    pub fn is_achievable(&self, rate_millibits: i64, distortion_millionths: i64) -> bool {
        if distortion_millionths > self.max_distortion_millionths {
            return false;
        }
        match self.rate_at_distortion(distortion_millionths) {
            Some(min_rate) => rate_millibits >= min_rate,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// FailureBudget — how many evidence losses per epoch we tolerate
// ---------------------------------------------------------------------------

/// Failure budget for a channel: how many evidence items can be lost
/// or degraded per epoch before triggering a policy violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureBudget {
    /// Maximum dropped evidence items per epoch.
    pub max_drops_per_epoch: u64,
    /// Maximum degraded (high-distortion) items per epoch.
    pub max_degraded_per_epoch: u64,
    /// Distortion threshold (millionths) above which an item is "degraded".
    pub degradation_threshold_millionths: i64,
    /// Whether exceeding the budget triggers immediate demotion.
    pub fail_closed: bool,
}

impl Default for FailureBudget {
    fn default() -> Self {
        Self {
            max_drops_per_epoch: 0,
            max_degraded_per_epoch: 10,
            degradation_threshold_millionths: 100_000, // 10%
            fail_closed: true,
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelSpec — full specification for one observability channel
// ---------------------------------------------------------------------------

/// Complete specification for one observability channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSpec {
    /// Channel identifier.
    pub channel_id: String,
    /// Payload family this channel transports.
    pub family: PayloadFamily,
    /// The pipeline path.
    pub path: ChannelPath,
    /// Rate-distortion envelope.
    pub envelope: RateDistortionEnvelope,
    /// Failure budget.
    pub failure_budget: FailureBudget,
    /// Maximum emission rate: items per epoch.
    pub max_items_per_epoch: u64,
    /// Backpressure buffer limit.
    pub buffer_capacity: u64,
    /// Whether lossy compression is permitted (constitutional constraint).
    pub lossy_permitted: bool,
    /// Tags for filtering.
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// DistortionRiskEntry — distortion-to-risk conversion
// ---------------------------------------------------------------------------

/// Maps a distortion level to a risk score for governance consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistortionRiskEntry {
    /// Distortion level (millionths).
    pub distortion_millionths: i64,
    /// Risk score (millionths, 0 = no risk, MILLION = maximum risk).
    pub risk_millionths: i64,
    /// Human-readable consequence description.
    pub consequence: String,
}

// ---------------------------------------------------------------------------
// DistortionRiskLedger — distortion-to-risk conversion table
// ---------------------------------------------------------------------------

/// Conversion table from distortion to risk for a payload family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistortionRiskLedger {
    pub family: PayloadFamily,
    pub entries: Vec<DistortionRiskEntry>,
}

impl DistortionRiskLedger {
    /// Interpolate risk for a given distortion level.
    pub fn risk_at_distortion(&self, distortion_millionths: i64) -> i64 {
        if self.entries.is_empty() {
            return 0;
        }
        let mut prev: Option<&DistortionRiskEntry> = None;
        for entry in &self.entries {
            if entry.distortion_millionths >= distortion_millionths {
                if let Some(p) = prev {
                    let dd = entry.distortion_millionths - p.distortion_millionths;
                    if dd == 0 {
                        return entry.risk_millionths;
                    }
                    let frac = distortion_millionths - p.distortion_millionths;
                    let dr = entry.risk_millionths - p.risk_millionths;
                    return p.risk_millionths + (dr * frac) / dd;
                }
                return entry.risk_millionths;
            }
            prev = Some(entry);
        }
        self.entries.last().map(|e| e.risk_millionths).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// PolicyViolation — when constitutional constraints are breached
// ---------------------------------------------------------------------------

/// A violation of the observability constitution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub channel_id: String,
    pub epoch: SecurityEpoch,
    pub violation_kind: ViolationKind,
    pub detail: String,
}

/// Kind of constitutional violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Telemetry rate exceeded without budget.
    UncappedTelemetry,
    /// Lossy compression applied without verifiable distortion bound.
    UnverifiableLoss,
    /// Evidence dropped beyond failure budget.
    DropBudgetExceeded,
    /// Degradation budget exceeded.
    DegradationBudgetExceeded,
    /// Backpressure buffer overflow.
    BackpressureOverflow,
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UncappedTelemetry => write!(f, "uncapped_telemetry"),
            Self::UnverifiableLoss => write!(f, "unverifiable_loss"),
            Self::DropBudgetExceeded => write!(f, "drop_budget_exceeded"),
            Self::DegradationBudgetExceeded => write!(f, "degradation_budget_exceeded"),
            Self::BackpressureOverflow => write!(f, "backpressure_overflow"),
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelState — runtime state for a channel
// ---------------------------------------------------------------------------

/// Runtime state for an observability channel within an epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelState {
    pub channel_id: String,
    pub epoch: SecurityEpoch,
    pub items_emitted: u64,
    pub items_dropped: u64,
    pub items_degraded: u64,
    pub buffer_used: u64,
    pub violations: Vec<PolicyViolation>,
}

impl ChannelState {
    pub fn new(channel_id: String, epoch: SecurityEpoch) -> Self {
        Self {
            channel_id,
            epoch,
            items_emitted: 0,
            items_dropped: 0,
            items_degraded: 0,
            buffer_used: 0,
            violations: Vec::new(),
        }
    }

    /// Record an emission.  Returns `Err` with a violation if the emission
    /// would breach the channel spec's constitutional constraints.
    pub fn emit(
        &mut self,
        spec: &ChannelSpec,
        distortion_millionths: i64,
    ) -> Result<(), PolicyViolation> {
        // Check rate cap.
        if self.items_emitted >= spec.max_items_per_epoch {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::UncappedTelemetry,
                detail: format!(
                    "rate cap {} exceeded at {}",
                    spec.max_items_per_epoch, self.items_emitted,
                ),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Check backpressure.
        if self.buffer_used >= spec.buffer_capacity {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::BackpressureOverflow,
                detail: format!("buffer full: {}/{}", self.buffer_used, spec.buffer_capacity,),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Check lossy compression constitutional constraint.
        if distortion_millionths > 0 && !spec.lossy_permitted {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::UnverifiableLoss,
                detail: format!(
                    "lossy emission (distortion={distortion_millionths}) on lossless-only channel",
                ),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Track degradation.
        if distortion_millionths > spec.failure_budget.degradation_threshold_millionths {
            self.items_degraded += 1;
            if self.items_degraded > spec.failure_budget.max_degraded_per_epoch {
                let violation = PolicyViolation {
                    channel_id: self.channel_id.clone(),
                    epoch: self.epoch,
                    violation_kind: ViolationKind::DegradationBudgetExceeded,
                    detail: format!(
                        "degraded items {} exceed budget {}",
                        self.items_degraded, spec.failure_budget.max_degraded_per_epoch,
                    ),
                };
                self.violations.push(violation.clone());
                if spec.failure_budget.fail_closed {
                    return Err(violation);
                }
            }
        }

        self.items_emitted += 1;
        self.buffer_used += 1;
        Ok(())
    }

    /// Record a dropped evidence item.
    pub fn record_drop(&mut self, spec: &ChannelSpec) -> Result<(), PolicyViolation> {
        self.items_dropped += 1;
        if self.items_dropped > spec.failure_budget.max_drops_per_epoch {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::DropBudgetExceeded,
                detail: format!(
                    "drops {} exceed budget {}",
                    self.items_dropped, spec.failure_budget.max_drops_per_epoch,
                ),
            };
            self.violations.push(violation.clone());
            if spec.failure_budget.fail_closed {
                return Err(violation);
            }
        }
        Ok(())
    }

    /// Drain one item from the buffer.
    pub fn drain_one(&mut self) {
        self.buffer_used = self.buffer_used.saturating_sub(1);
    }

    /// Check if the channel is in a healthy state.
    pub fn is_healthy(&self, spec: &ChannelSpec) -> bool {
        self.items_dropped <= spec.failure_budget.max_drops_per_epoch
            && self.items_degraded <= spec.failure_budget.max_degraded_per_epoch
            && self.violations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ChannelReport — CI-readable report for all channels
// ---------------------------------------------------------------------------

/// Health report for the observability channel model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelReport {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub channels: Vec<ChannelHealthEntry>,
    pub total_violations: u64,
    pub gate_pass: bool,
    pub content_hash: String,
    pub summary: String,
}

/// Health entry for one channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelHealthEntry {
    pub channel_id: String,
    pub family: PayloadFamily,
    pub path: ChannelPath,
    pub items_emitted: u64,
    pub items_dropped: u64,
    pub items_degraded: u64,
    pub utilization_millionths: i64,
    pub healthy: bool,
    pub violation_count: u64,
}

/// Generate a channel report from specs and states.
pub fn generate_report(
    specs: &[ChannelSpec],
    states: &BTreeMap<String, ChannelState>,
    epoch: SecurityEpoch,
) -> ChannelReport {
    let mut entries = Vec::new();
    let mut total_violations = 0u64;
    let mut any_unhealthy = false;

    for spec in specs {
        let state = states.get(&spec.channel_id);
        let (emitted, dropped, degraded, violations, healthy) = match state {
            Some(s) => {
                let h = s.is_healthy(spec);
                (
                    s.items_emitted,
                    s.items_dropped,
                    s.items_degraded,
                    s.violations.len() as u64,
                    h,
                )
            }
            None => (0, 0, 0, 0, true),
        };

        let utilization = if spec.max_items_per_epoch > 0 {
            (emitted as i128 * MILLION as i128 / spec.max_items_per_epoch as i128) as i64
        } else {
            0
        };

        if !healthy {
            any_unhealthy = true;
        }
        total_violations += violations;

        entries.push(ChannelHealthEntry {
            channel_id: spec.channel_id.clone(),
            family: spec.family,
            path: spec.path,
            items_emitted: emitted,
            items_dropped: dropped,
            items_degraded: degraded,
            utilization_millionths: utilization,
            healthy,
            violation_count: violations,
        });
    }

    let canonical = serde_json::to_string(&entries).unwrap_or_default();
    let hash = Sha256::digest(canonical.as_bytes());
    let content_hash = hex::encode(hash);

    let healthy_count = entries.iter().filter(|e| e.healthy).count();
    let summary = format!(
        "{}/{} channels healthy, {} violations — gate {}",
        healthy_count,
        entries.len(),
        total_violations,
        if !any_unhealthy { "PASS" } else { "FAIL" },
    );

    ChannelReport {
        schema_version: SCHEMA_VERSION.to_string(),
        epoch,
        channels: entries,
        total_violations,
        gate_pass: !any_unhealthy,
        content_hash,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Default channel specs — canonical channel configuration
// ---------------------------------------------------------------------------

/// Build the canonical set of observability channel specifications.
pub fn canonical_channel_specs() -> Vec<ChannelSpec> {
    vec![
        ChannelSpec {
            channel_id: "ch-decision-ledger".to_string(),
            family: PayloadFamily::Decision,
            path: ChannelPath::RuntimeToLedger,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Decision,
                metric: DistortionMetric::LogLoss,
                frontier: vec![
                    RateDistortionPoint {
                        distortion_millionths: 0,
                        rate_millibits: 2_000_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 50_000,
                        rate_millibits: 1_200_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 100_000,
                        rate_millibits: 800_000,
                    },
                ],
                max_distortion_millionths: 100_000, // 10%
                min_rate_millibits: 500_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 5,
                degradation_threshold_millionths: 50_000,
                fail_closed: true,
            },
            max_items_per_epoch: 100_000,
            buffer_capacity: 4096,
            lossy_permitted: true,
            tags: vec!["decision".to_string(), "runtime".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-replay-verifier".to_string(),
            family: PayloadFamily::Replay,
            path: ChannelPath::ReplayToVerifier,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Replay,
                metric: DistortionMetric::Hamming,
                frontier: vec![RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 8_000_000,
                }],
                max_distortion_millionths: 0, // lossless only
                min_rate_millibits: 8_000_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 0,
                degradation_threshold_millionths: 0,
                fail_closed: true,
            },
            max_items_per_epoch: 50_000,
            buffer_capacity: 2048,
            lossy_permitted: false,
            tags: vec!["replay".to_string(), "lossless".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-optimization-ledger".to_string(),
            family: PayloadFamily::Optimization,
            path: ChannelPath::CompilerToLedger,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Optimization,
                metric: DistortionMetric::SquaredError,
                frontier: vec![
                    RateDistortionPoint {
                        distortion_millionths: 0,
                        rate_millibits: 4_000_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 100_000,
                        rate_millibits: 2_000_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 200_000,
                        rate_millibits: 1_000_000,
                    },
                ],
                max_distortion_millionths: 200_000, // 20%
                min_rate_millibits: 500_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 10,
                max_degraded_per_epoch: 50,
                degradation_threshold_millionths: 100_000,
                fail_closed: false,
            },
            max_items_per_epoch: 200_000,
            buffer_capacity: 8192,
            lossy_permitted: true,
            tags: vec!["optimization".to_string(), "compiler".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-security-audit".to_string(),
            family: PayloadFamily::Security,
            path: ChannelPath::ControlPlaneToAudit,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Security,
                metric: DistortionMetric::BinaryFidelity,
                frontier: vec![RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 1_000_000,
                }],
                max_distortion_millionths: 0, // lossless only
                min_rate_millibits: 1_000_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 0,
                degradation_threshold_millionths: 0,
                fail_closed: true,
            },
            max_items_per_epoch: 10_000,
            buffer_capacity: 1024,
            lossy_permitted: false,
            tags: vec!["security".to_string(), "audit".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-legal-archive".to_string(),
            family: PayloadFamily::LegalProvenance,
            path: ChannelPath::ToComplianceArchive,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::LegalProvenance,
                metric: DistortionMetric::BinaryFidelity,
                frontier: vec![RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 500_000,
                }],
                max_distortion_millionths: 0, // lossless only
                min_rate_millibits: 500_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 0,
                degradation_threshold_millionths: 0,
                fail_closed: true,
            },
            max_items_per_epoch: 5_000,
            buffer_capacity: 512,
            lossy_permitted: false,
            tags: vec!["legal".to_string(), "compliance".to_string()],
        },
    ]
}

/// Build the canonical distortion-to-risk conversion ledger.
pub fn canonical_risk_ledgers() -> Vec<DistortionRiskLedger> {
    vec![
        DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "lossless decision evidence".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 50_000,
                    risk_millionths: 200_000,
                    consequence: "minor precision loss in loss estimates".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 100_000,
                    risk_millionths: 600_000,
                    consequence: "significant decision audit degradation".to_string(),
                },
            ],
        },
        DistortionRiskLedger {
            family: PayloadFamily::Security,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "lossless security evidence".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 1,
                    risk_millionths: MILLION,
                    consequence: "any loss in security evidence is maximum risk".to_string(),
                },
            ],
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    // -- PayloadFamily --

    #[test]
    fn payload_family_all_five() {
        assert_eq!(PayloadFamily::ALL.len(), 5);
    }

    #[test]
    fn payload_family_display() {
        assert_eq!(PayloadFamily::Decision.to_string(), "decision");
        assert_eq!(PayloadFamily::Replay.to_string(), "replay");
        assert_eq!(PayloadFamily::Optimization.to_string(), "optimization");
        assert_eq!(PayloadFamily::Security.to_string(), "security");
        assert_eq!(
            PayloadFamily::LegalProvenance.to_string(),
            "legal_provenance"
        );
    }

    #[test]
    fn payload_family_serde_roundtrip() {
        for fam in PayloadFamily::ALL {
            let json = serde_json::to_string(&fam).unwrap();
            let back: PayloadFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(back, fam);
        }
    }

    // -- DistortionMetric --

    #[test]
    fn distortion_metric_display() {
        assert_eq!(DistortionMetric::Hamming.to_string(), "hamming");
        assert_eq!(DistortionMetric::SquaredError.to_string(), "squared_error");
        assert_eq!(DistortionMetric::LogLoss.to_string(), "log_loss");
        assert_eq!(DistortionMetric::EditDistance.to_string(), "edit_distance");
        assert_eq!(
            DistortionMetric::BinaryFidelity.to_string(),
            "binary_fidelity"
        );
    }

    // -- ChannelPath --

    #[test]
    fn channel_path_all_five() {
        assert_eq!(ChannelPath::ALL.len(), 5);
    }

    #[test]
    fn channel_path_display() {
        assert_eq!(
            ChannelPath::CompilerToLedger.to_string(),
            "compiler_to_ledger"
        );
        assert_eq!(
            ChannelPath::RuntimeToLedger.to_string(),
            "runtime_to_ledger"
        );
    }

    // -- RateDistortionEnvelope --

    #[test]
    fn envelope_rate_at_zero_distortion() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        assert_eq!(env.rate_at_distortion(0), Some(2_000_000));
    }

    #[test]
    fn envelope_rate_interpolation() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        // Midpoint: distortion 50_000 → rate ~1_500_000
        assert_eq!(env.rate_at_distortion(50_000), Some(1_500_000));
    }

    #[test]
    fn envelope_rate_exceeds_max_distortion() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            }],
            max_distortion_millionths: 50_000,
            min_rate_millibits: 500_000,
        };
        assert_eq!(env.rate_at_distortion(100_000), None);
    }

    #[test]
    fn envelope_empty_frontier() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        assert_eq!(env.rate_at_distortion(0), None);
    }

    #[test]
    fn envelope_is_achievable() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        // Above the R(D) curve: achievable.
        assert!(env.is_achievable(2_000_000, 0));
        assert!(env.is_achievable(1_500_000, 50_000));
        // Below the R(D) curve: not achievable.
        assert!(!env.is_achievable(500_000, 0));
        // Beyond max distortion: not achievable.
        assert!(!env.is_achievable(2_000_000, 200_000));
    }

    // -- DistortionRiskLedger --

    #[test]
    fn risk_ledger_interpolation() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "none".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 100_000,
                    risk_millionths: MILLION,
                    consequence: "max".to_string(),
                },
            ],
        };
        assert_eq!(ledger.risk_at_distortion(0), 0);
        assert_eq!(ledger.risk_at_distortion(50_000), 500_000);
        assert_eq!(ledger.risk_at_distortion(100_000), MILLION);
    }

    #[test]
    fn risk_ledger_empty() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![],
        };
        assert_eq!(ledger.risk_at_distortion(50_000), 0);
    }

    #[test]
    fn risk_ledger_security_binary() {
        let ledgers = canonical_risk_ledgers();
        let sec = ledgers
            .iter()
            .find(|l| l.family == PayloadFamily::Security)
            .unwrap();
        assert_eq!(sec.risk_at_distortion(0), 0);
        assert_eq!(sec.risk_at_distortion(1), MILLION);
    }

    // -- ChannelState --

    #[test]
    fn channel_state_emit_within_budget() {
        let spec = &canonical_channel_specs()[0]; // decision channel
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(spec, 0).is_ok());
        assert_eq!(state.items_emitted, 1);
        assert_eq!(state.buffer_used, 1);
    }

    #[test]
    fn channel_state_emit_rate_exceeded() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.max_items_per_epoch = 2;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(&spec, 0).is_ok());
        assert!(state.emit(&spec, 0).is_ok());
        let result = state.emit(&spec, 0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::UncappedTelemetry
        );
    }

    #[test]
    fn channel_state_backpressure() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.buffer_capacity = 1;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(&spec, 0).is_ok());
        let result = state.emit(&spec, 0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::BackpressureOverflow
        );
    }

    #[test]
    fn channel_state_drain_releases_buffer() {
        let spec = &canonical_channel_specs()[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        state.emit(spec, 0).unwrap();
        assert_eq!(state.buffer_used, 1);
        state.drain_one();
        assert_eq!(state.buffer_used, 0);
    }

    #[test]
    fn channel_state_lossy_on_lossless_channel() {
        let spec = &canonical_channel_specs()[1]; // replay channel (lossless)
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let result = state.emit(spec, 10_000); // nonzero distortion
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::UnverifiableLoss
        );
    }

    #[test]
    fn channel_state_lossy_on_lossy_channel() {
        let spec = &canonical_channel_specs()[0]; // decision channel (lossy ok)
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(spec, 10_000).is_ok());
    }

    #[test]
    fn channel_state_degradation_tracked() {
        let spec = &canonical_channel_specs()[0]; // degradation threshold 50_000
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // Below threshold.
        state.emit(spec, 40_000).unwrap();
        assert_eq!(state.items_degraded, 0);
        // Above threshold.
        state.emit(spec, 60_000).unwrap();
        assert_eq!(state.items_degraded, 1);
    }

    #[test]
    fn channel_state_drop_budget() {
        let spec = &canonical_channel_specs()[0]; // max_drops = 0
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let result = state.record_drop(spec);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::DropBudgetExceeded
        );
    }

    #[test]
    fn channel_state_drop_budget_with_tolerance() {
        let spec = &canonical_channel_specs()[2]; // optimization: max_drops = 10
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        for _ in 0..10 {
            assert!(state.record_drop(spec).is_ok());
        }
        // 11th drop exceeds budget but fail_closed=false so no error.
        assert!(state.record_drop(spec).is_ok());
    }

    #[test]
    fn channel_state_healthy() {
        let spec = &canonical_channel_specs()[0];
        let state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.is_healthy(spec));
    }

    #[test]
    fn channel_state_unhealthy_after_violation() {
        let spec = &canonical_channel_specs()[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let _ = state.record_drop(spec); // violates drop budget
        assert!(!state.is_healthy(spec));
    }

    // -- Report --

    #[test]
    fn report_all_healthy() {
        let specs = canonical_channel_specs();
        let states = BTreeMap::new();
        let report = generate_report(&specs, &states, epoch(1));
        assert!(report.gate_pass);
        assert_eq!(report.total_violations, 0);
        assert_eq!(report.channels.len(), specs.len());
    }

    #[test]
    fn report_with_violation() {
        let specs = canonical_channel_specs();
        let mut states = BTreeMap::new();
        let mut state = ChannelState::new("ch-decision-ledger".to_string(), epoch(1));
        let _ = state.record_drop(&specs[0]);
        states.insert("ch-decision-ledger".to_string(), state);

        let report = generate_report(&specs, &states, epoch(1));
        assert!(!report.gate_pass);
        assert!(report.total_violations > 0);
    }

    #[test]
    fn report_content_hash_deterministic() {
        let specs = canonical_channel_specs();
        let states = BTreeMap::new();
        let r1 = generate_report(&specs, &states, epoch(1));
        let r2 = generate_report(&specs, &states, epoch(1));
        assert_eq!(r1.content_hash, r2.content_hash);
        assert!(!r1.content_hash.is_empty());
    }

    #[test]
    fn report_schema_version() {
        let specs = canonical_channel_specs();
        let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_summary_format() {
        let specs = canonical_channel_specs();
        let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
        assert!(report.summary.contains("healthy"));
        assert!(report.summary.contains("PASS"));
    }

    #[test]
    fn report_utilization_computed() {
        let specs = canonical_channel_specs();
        let mut states = BTreeMap::new();
        let spec = &specs[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // Emit 1000 items out of 100_000 capacity.
        for _ in 0..1000 {
            state.emit(spec, 0).unwrap();
            state.drain_one();
        }
        states.insert(spec.channel_id.clone(), state);

        let report = generate_report(&specs, &states, epoch(1));
        let entry = report
            .channels
            .iter()
            .find(|e| e.channel_id == "ch-decision-ledger")
            .unwrap();
        assert_eq!(entry.items_emitted, 1000);
        // 1000/100_000 = 10_000 millionths = 1%
        assert_eq!(entry.utilization_millionths, 10_000);
    }

    // -- Canonical specs --

    #[test]
    fn canonical_specs_cover_all_families() {
        let specs = canonical_channel_specs();
        let families: std::collections::BTreeSet<_> = specs.iter().map(|s| s.family).collect();
        for fam in PayloadFamily::ALL {
            assert!(families.contains(&fam), "missing family: {fam}");
        }
    }

    #[test]
    fn canonical_specs_unique_ids() {
        let specs = canonical_channel_specs();
        let ids: std::collections::BTreeSet<_> = specs.iter().map(|s| &s.channel_id).collect();
        assert_eq!(ids.len(), specs.len());
    }

    #[test]
    fn canonical_specs_security_and_legal_are_lossless() {
        let specs = canonical_channel_specs();
        for spec in &specs {
            if spec.family == PayloadFamily::Security
                || spec.family == PayloadFamily::LegalProvenance
            {
                assert!(
                    !spec.lossy_permitted,
                    "{} should be lossless",
                    spec.channel_id
                );
                assert_eq!(
                    spec.envelope.max_distortion_millionths, 0,
                    "{} should have zero max distortion",
                    spec.channel_id,
                );
            }
        }
    }

    #[test]
    fn canonical_specs_replay_is_lossless() {
        let specs = canonical_channel_specs();
        let replay = specs
            .iter()
            .find(|s| s.family == PayloadFamily::Replay)
            .unwrap();
        assert!(!replay.lossy_permitted);
    }

    // -- Serde roundtrips --

    #[test]
    fn channel_spec_serde_roundtrip() {
        let specs = canonical_channel_specs();
        let json = serde_json::to_string(&specs).unwrap();
        let back: Vec<ChannelSpec> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), specs.len());
    }

    #[test]
    fn channel_state_serde_roundtrip() {
        let mut state = ChannelState::new("test".to_string(), epoch(1));
        state.items_emitted = 42;
        let json = serde_json::to_string(&state).unwrap();
        let back: ChannelState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.items_emitted, 42);
    }

    #[test]
    fn channel_report_serde_roundtrip() {
        let specs = canonical_channel_specs();
        let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
        let json = serde_json::to_string(&report).unwrap();
        let back: ChannelReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.gate_pass, report.gate_pass);
        assert_eq!(back.content_hash, report.content_hash);
    }

    #[test]
    fn violation_kind_display() {
        assert_eq!(
            ViolationKind::UncappedTelemetry.to_string(),
            "uncapped_telemetry"
        );
        assert_eq!(
            ViolationKind::UnverifiableLoss.to_string(),
            "unverifiable_loss"
        );
        assert_eq!(
            ViolationKind::DropBudgetExceeded.to_string(),
            "drop_budget_exceeded"
        );
        assert_eq!(
            ViolationKind::DegradationBudgetExceeded.to_string(),
            "degradation_budget_exceeded"
        );
        assert_eq!(
            ViolationKind::BackpressureOverflow.to_string(),
            "backpressure_overflow"
        );
    }

    #[test]
    fn failure_budget_default() {
        let budget = FailureBudget::default();
        assert_eq!(budget.max_drops_per_epoch, 0);
        assert_eq!(budget.max_degraded_per_epoch, 10);
        assert!(budget.fail_closed);
    }
}
