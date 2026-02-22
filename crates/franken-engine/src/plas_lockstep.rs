//! Deterministic lockstep checks for PLAS minimal-policy synthesis.
//!
//! Evaluates whether a synthesized minimal capability policy preserves
//! behavior relative to full-manifest execution, while classifying
//! Node/Bun baseline divergences separately from PLAS regressions.
//!
//! Plan reference: Section 10.15 item 11 (`bd-32d3`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

const PLAS_LOCKSTEP_COMPONENT: &str = "plas_lockstep";

/// Runtime lane participating in lockstep evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockstepRuntime {
    FrankenEngineFull,
    FrankenEngineMinimal,
    Node,
    Bun,
}

impl LockstepRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrankenEngineFull => "franken_engine_full",
            Self::FrankenEngineMinimal => "franken_engine_minimal",
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

impl fmt::Display for LockstepRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Observable behavior from one runtime lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeObservation {
    pub runtime: LockstepRuntime,
    pub output_digest: String,
    pub side_effect_digest: String,
    pub state_digest: String,
    pub error_code: Option<String>,
    #[serde(default)]
    pub capability_denials: Vec<String>,
    pub elapsed_ns: u64,
}

impl RuntimeObservation {
    fn normalize(&mut self) {
        self.output_digest = self.output_digest.trim().to_string();
        self.side_effect_digest = self.side_effect_digest.trim().to_string();
        self.state_digest = self.state_digest.trim().to_string();
        self.error_code = self
            .error_code
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.capability_denials = self
            .capability_denials
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        self.capability_denials.sort();
        self.capability_denials.dedup();
    }

    fn validate(&self, field_name: &str) -> Result<(), PlasLockstepError> {
        if self.output_digest.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: format!("{field_name}.output_digest must not be empty"),
            });
        }
        if self.side_effect_digest.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: format!("{field_name}.side_effect_digest must not be empty"),
            });
        }
        if self.state_digest.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: format!("{field_name}.state_digest must not be empty"),
            });
        }
        Ok(())
    }
}

/// Runtime-specific tolerance for known baseline differences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeTolerance {
    #[serde(default)]
    pub allow_output_digest_mismatch: bool,
    #[serde(default)]
    pub allow_side_effect_digest_mismatch: bool,
    #[serde(default)]
    pub allow_state_digest_mismatch: bool,
    #[serde(default)]
    pub allowed_error_codes: BTreeSet<String>,
}

impl RuntimeTolerance {
    fn normalize(&mut self) {
        self.allowed_error_codes = self
            .allowed_error_codes
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
}

/// One lockstep scenario covering full/minimal FE and Node/Bun references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasLockstepCase {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub scenario_id: String,
    pub full_manifest: RuntimeObservation,
    pub minimal_policy: RuntimeObservation,
    pub node_reference: Option<RuntimeObservation>,
    pub bun_reference: Option<RuntimeObservation>,
    #[serde(default)]
    pub reference_tolerances: BTreeMap<LockstepRuntime, RuntimeTolerance>,
    /// Maximum allowed slowdown for minimal policy vs full-manifest run.
    ///
    /// Units: millionths. Example: 150_000 = 15% slower allowed.
    pub max_performance_degradation_millionths: u64,
}

impl PlasLockstepCase {
    fn normalize(&mut self) {
        self.trace_id = self.trace_id.trim().to_string();
        self.decision_id = self.decision_id.trim().to_string();
        self.policy_id = self.policy_id.trim().to_string();
        self.extension_id = self.extension_id.trim().to_string();
        self.scenario_id = self.scenario_id.trim().to_string();

        self.full_manifest.normalize();
        self.minimal_policy.normalize();
        if let Some(reference) = &mut self.node_reference {
            reference.normalize();
        }
        if let Some(reference) = &mut self.bun_reference {
            reference.normalize();
        }
        for tolerance in self.reference_tolerances.values_mut() {
            tolerance.normalize();
        }
    }

    fn validate(&self) -> Result<(), PlasLockstepError> {
        if self.trace_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.extension_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "extension_id must not be empty".to_string(),
            });
        }
        if self.scenario_id.is_empty() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "scenario_id must not be empty".to_string(),
            });
        }

        self.full_manifest.validate("full_manifest")?;
        self.minimal_policy.validate("minimal_policy")?;

        if self.full_manifest.runtime != LockstepRuntime::FrankenEngineFull {
            return Err(PlasLockstepError::InvalidCase {
                detail: "full_manifest.runtime must be franken_engine_full".to_string(),
            });
        }
        if self.minimal_policy.runtime != LockstepRuntime::FrankenEngineMinimal {
            return Err(PlasLockstepError::InvalidCase {
                detail: "minimal_policy.runtime must be franken_engine_minimal".to_string(),
            });
        }

        if let Some(reference) = &self.node_reference {
            reference.validate("node_reference")?;
            if reference.runtime != LockstepRuntime::Node {
                return Err(PlasLockstepError::InvalidCase {
                    detail: "node_reference.runtime must be node".to_string(),
                });
            }
        }
        if let Some(reference) = &self.bun_reference {
            reference.validate("bun_reference")?;
            if reference.runtime != LockstepRuntime::Bun {
                return Err(PlasLockstepError::InvalidCase {
                    detail: "bun_reference.runtime must be bun".to_string(),
                });
            }
        }
        if self.node_reference.is_none() && self.bun_reference.is_none() {
            return Err(PlasLockstepError::InvalidCase {
                detail: "at least one Node/Bun reference observation is required".to_string(),
            });
        }
        Ok(())
    }
}

/// Required failure taxonomy for PLAS lockstep checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockstepFailureClass {
    CorrectnessRegression,
    CapabilityGap,
    PlatformDivergence,
}

impl LockstepFailureClass {
    pub fn error_code(self) -> &'static str {
        match self {
            Self::CorrectnessRegression => "correctness_regression",
            Self::CapabilityGap => "capability_gap",
            Self::PlatformDivergence => "platform_divergence",
        }
    }
}

impl fmt::Display for LockstepFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error_code())
    }
}

/// Semantic comparison result between the FE full-manifest baseline and another runtime lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeComparison {
    pub runtime: LockstepRuntime,
    pub semantic_match: bool,
    pub mismatch_fields: Vec<String>,
}

/// Structured lockstep log row with stable keys for replay and scorecards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasLockstepLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Complete lockstep verdict for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasLockstepEvaluation {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub scenario_id: String,
    pub pass: bool,
    pub failure_class: Option<LockstepFailureClass>,
    pub failure_detail: Option<String>,
    pub performance_degradation_millionths: u64,
    pub comparisons: Vec<RuntimeComparison>,
    pub log: PlasLockstepLogEvent,
}

/// Errors from PLAS lockstep evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlasLockstepError {
    InvalidCase { detail: String },
}

impl fmt::Display for PlasLockstepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCase { detail } => write!(f, "invalid lockstep case: {detail}"),
        }
    }
}

impl std::error::Error for PlasLockstepError {}

/// Evaluate one deterministic PLAS lockstep scenario.
pub fn evaluate_plas_lockstep_case(
    mut scenario: PlasLockstepCase,
) -> Result<PlasLockstepEvaluation, PlasLockstepError> {
    scenario.normalize();
    scenario.validate()?;

    let mut comparisons = Vec::new();
    let baseline_tolerance = RuntimeTolerance::default();

    let minimal_vs_full = compare_against_baseline(
        &scenario.full_manifest,
        &scenario.minimal_policy,
        &baseline_tolerance,
    );
    comparisons.push(minimal_vs_full.clone());

    let performance_degradation_millionths = performance_degradation_millionths(
        scenario.full_manifest.elapsed_ns,
        scenario.minimal_policy.elapsed_ns,
    );

    let mut failure_class = None;
    let mut failure_detail = None;

    if !minimal_vs_full.semantic_match {
        if is_capability_gap(&scenario) {
            failure_class = Some(LockstepFailureClass::CapabilityGap);
            failure_detail = Some(format!(
                "minimal policy denied capabilities: {}",
                scenario.minimal_policy.capability_denials.join(",")
            ));
        } else {
            failure_class = Some(LockstepFailureClass::CorrectnessRegression);
            failure_detail = Some(format!(
                "minimal policy diverged from full manifest on {}",
                minimal_vs_full.mismatch_fields.join(",")
            ));
        }
    } else if performance_degradation_millionths > scenario.max_performance_degradation_millionths {
        failure_class = Some(LockstepFailureClass::CorrectnessRegression);
        failure_detail = Some(format!(
            "performance degradation {} exceeded threshold {}",
            performance_degradation_millionths, scenario.max_performance_degradation_millionths
        ));
    }

    let mut reference_divergences = Vec::new();
    if let Some(reference) = &scenario.node_reference {
        let tolerance = scenario
            .reference_tolerances
            .get(&LockstepRuntime::Node)
            .cloned()
            .unwrap_or_default();
        let comparison = compare_against_baseline(&scenario.full_manifest, reference, &tolerance);
        if !comparison.semantic_match {
            reference_divergences.push(reference.runtime.to_string());
        }
        comparisons.push(comparison);
    }
    if let Some(reference) = &scenario.bun_reference {
        let tolerance = scenario
            .reference_tolerances
            .get(&LockstepRuntime::Bun)
            .cloned()
            .unwrap_or_default();
        let comparison = compare_against_baseline(&scenario.full_manifest, reference, &tolerance);
        if !comparison.semantic_match {
            reference_divergences.push(reference.runtime.to_string());
        }
        comparisons.push(comparison);
    }

    if failure_class.is_none() && !reference_divergences.is_empty() {
        failure_class = Some(LockstepFailureClass::PlatformDivergence);
        failure_detail = Some(format!(
            "full-manifest behavior diverges from {} baseline(s)",
            reference_divergences.join(",")
        ));
    }

    let pass = failure_class.is_none();
    let log = PlasLockstepLogEvent {
        trace_id: scenario.trace_id.clone(),
        decision_id: scenario.decision_id.clone(),
        policy_id: scenario.policy_id.clone(),
        component: PLAS_LOCKSTEP_COMPONENT.to_string(),
        event: "plas_lockstep_case_evaluated".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: failure_class.map(|class| class.error_code().to_string()),
    };

    Ok(PlasLockstepEvaluation {
        trace_id: scenario.trace_id,
        decision_id: scenario.decision_id,
        policy_id: scenario.policy_id,
        extension_id: scenario.extension_id,
        scenario_id: scenario.scenario_id,
        pass,
        failure_class,
        failure_detail,
        performance_degradation_millionths,
        comparisons,
        log,
    })
}

fn is_capability_gap(scenario: &PlasLockstepCase) -> bool {
    !scenario.minimal_policy.capability_denials.is_empty()
        && scenario.full_manifest.capability_denials.is_empty()
        && scenario.full_manifest.error_code.is_none()
}

fn compare_against_baseline(
    baseline: &RuntimeObservation,
    observed: &RuntimeObservation,
    tolerance: &RuntimeTolerance,
) -> RuntimeComparison {
    let mut mismatch_fields = Vec::new();

    if baseline.output_digest != observed.output_digest && !tolerance.allow_output_digest_mismatch {
        mismatch_fields.push("output_digest".to_string());
    }
    if baseline.side_effect_digest != observed.side_effect_digest
        && !tolerance.allow_side_effect_digest_mismatch
    {
        mismatch_fields.push("side_effect_digest".to_string());
    }
    if baseline.state_digest != observed.state_digest && !tolerance.allow_state_digest_mismatch {
        mismatch_fields.push("state_digest".to_string());
    }

    if baseline.error_code != observed.error_code {
        let baseline_allowed = baseline
            .error_code
            .as_ref()
            .is_some_and(|error| tolerance.allowed_error_codes.contains(error));
        let observed_allowed = observed
            .error_code
            .as_ref()
            .is_some_and(|error| tolerance.allowed_error_codes.contains(error));
        if !(baseline_allowed || observed_allowed) {
            mismatch_fields.push("error_code".to_string());
        }
    }

    RuntimeComparison {
        runtime: observed.runtime,
        semantic_match: mismatch_fields.is_empty(),
        mismatch_fields,
    }
}

fn performance_degradation_millionths(full_elapsed_ns: u64, minimal_elapsed_ns: u64) -> u64 {
    if full_elapsed_ns == 0 || minimal_elapsed_ns <= full_elapsed_ns {
        return 0;
    }

    let slowdown = minimal_elapsed_ns - full_elapsed_ns;
    let scaled = (u128::from(slowdown) * 1_000_000u128) / u128::from(full_elapsed_ns);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}
