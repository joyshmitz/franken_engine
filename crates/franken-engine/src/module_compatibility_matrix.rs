//! Explicit compatibility matrix for Node/Bun module edge cases.
//!
//! This module keeps compatibility behavior explicit and machine-readable.
//! Divergences from Node/Bun must include waiver metadata and migration
//! guidance; mode-specific behavior changes must declare explicit, removable
//! shims so compatibility is never hidden in resolver internals.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::feature_parity_tracker::FeatureParityTracker;
use crate::hash_tiers::ContentHash;

const COMPONENT_NAME: &str = "module_compatibility_matrix";
pub const DEFAULT_MATRIX_JSON: &str =
    include_str!("../../../docs/module_compatibility_matrix_v1.json");

pub type CompatibilityResult<T> = Result<T, Box<CompatibilityMatrixError>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleFeature {
    Esm,
    Cjs,
    DualMode,
    ConditionalExports,
    PackageJsonFields,
}

impl ModuleFeature {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Esm => "esm",
            Self::Cjs => "cjs",
            Self::DualMode => "dual_mode",
            Self::ConditionalExports => "conditional_exports",
            Self::PackageJsonFields => "package_json_fields",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityRuntime {
    FrankenEngine,
    Node,
    Bun,
}

impl CompatibilityRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrankenEngine => "franken_engine",
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityMode {
    Native,
    NodeCompat,
    BunCompat,
}

impl CompatibilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::NodeCompat => "node_compat",
            Self::BunCompat => "bun_compat",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceRuntime {
    Node,
    Bun,
}

impl ReferenceRuntime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplicitShim {
    pub shim_id: String,
    pub mode: CompatibilityMode,
    pub description: String,
    pub removable: bool,
    pub test_case_ref: String,
}

impl ExplicitShim {
    fn normalize(&mut self) {
        self.shim_id = self.shim_id.trim().to_string();
        self.description = self.description.trim().to_string();
        self.test_case_ref = self.test_case_ref.trim().to_string();
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "shim_id".to_string(),
            CanonicalValue::String(self.shim_id.clone()),
        );
        map.insert(
            "mode".to_string(),
            CanonicalValue::String(self.mode.as_str().to_string()),
        );
        map.insert(
            "description".to_string(),
            CanonicalValue::String(self.description.clone()),
        );
        map.insert(
            "removable".to_string(),
            CanonicalValue::Bool(self.removable),
        );
        map.insert(
            "test_case_ref".to_string(),
            CanonicalValue::String(self.test_case_ref.clone()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergencePolicy {
    pub diverges_from: Vec<ReferenceRuntime>,
    pub reason: String,
    pub impact: String,
    pub waiver_id: String,
    pub migration_guidance: String,
}

impl DivergencePolicy {
    fn normalize(&mut self) {
        self.diverges_from.sort();
        self.diverges_from.dedup();
        self.reason = self.reason.trim().to_string();
        self.impact = self.impact.trim().to_string();
        self.waiver_id = self.waiver_id.trim().to_string();
        self.migration_guidance = self.migration_guidance.trim().to_string();
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "diverges_from".to_string(),
            CanonicalValue::Array(
                self.diverges_from
                    .iter()
                    .map(|runtime| CanonicalValue::String(runtime.as_str().to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "reason".to_string(),
            CanonicalValue::String(self.reason.clone()),
        );
        map.insert(
            "impact".to_string(),
            CanonicalValue::String(self.impact.clone()),
        );
        map.insert(
            "waiver_id".to_string(),
            CanonicalValue::String(self.waiver_id.clone()),
        );
        map.insert(
            "migration_guidance".to_string(),
            CanonicalValue::String(self.migration_guidance.clone()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrixEntry {
    pub case_id: String,
    pub feature: ModuleFeature,
    pub scenario: String,
    pub node_behavior: String,
    pub bun_behavior: String,
    pub franken_native_behavior: String,
    pub franken_node_compat_behavior: String,
    pub franken_bun_compat_behavior: String,
    pub explicit_shims: Vec<ExplicitShim>,
    pub lockstep_case_refs: Vec<String>,
    pub test262_refs: Vec<String>,
    pub divergence: Option<DivergencePolicy>,
}

impl CompatibilityMatrixEntry {
    fn normalize(&mut self) {
        self.case_id = self.case_id.trim().to_string();
        self.scenario = self.scenario.trim().to_string();
        self.node_behavior = self.node_behavior.trim().to_string();
        self.bun_behavior = self.bun_behavior.trim().to_string();
        self.franken_native_behavior = self.franken_native_behavior.trim().to_string();
        self.franken_node_compat_behavior = self.franken_node_compat_behavior.trim().to_string();
        self.franken_bun_compat_behavior = self.franken_bun_compat_behavior.trim().to_string();

        for shim in &mut self.explicit_shims {
            shim.normalize();
        }
        self.explicit_shims
            .sort_by(|lhs, rhs| (lhs.mode, &lhs.shim_id).cmp(&(rhs.mode, &rhs.shim_id)));
        self.explicit_shims
            .dedup_by(|lhs, rhs| lhs.mode == rhs.mode && lhs.shim_id == rhs.shim_id);

        normalize_string_vec(&mut self.lockstep_case_refs);
        normalize_string_vec(&mut self.test262_refs);

        if let Some(divergence) = &mut self.divergence {
            divergence.normalize();
        }
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "case_id".to_string(),
            CanonicalValue::String(self.case_id.clone()),
        );
        map.insert(
            "feature".to_string(),
            CanonicalValue::String(self.feature.as_str().to_string()),
        );
        map.insert(
            "scenario".to_string(),
            CanonicalValue::String(self.scenario.clone()),
        );
        map.insert(
            "node_behavior".to_string(),
            CanonicalValue::String(self.node_behavior.clone()),
        );
        map.insert(
            "bun_behavior".to_string(),
            CanonicalValue::String(self.bun_behavior.clone()),
        );
        map.insert(
            "franken_native_behavior".to_string(),
            CanonicalValue::String(self.franken_native_behavior.clone()),
        );
        map.insert(
            "franken_node_compat_behavior".to_string(),
            CanonicalValue::String(self.franken_node_compat_behavior.clone()),
        );
        map.insert(
            "franken_bun_compat_behavior".to_string(),
            CanonicalValue::String(self.franken_bun_compat_behavior.clone()),
        );
        map.insert(
            "explicit_shims".to_string(),
            CanonicalValue::Array(
                self.explicit_shims
                    .iter()
                    .map(ExplicitShim::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "lockstep_case_refs".to_string(),
            CanonicalValue::Array(
                self.lockstep_case_refs
                    .iter()
                    .map(|reference| CanonicalValue::String(reference.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "test262_refs".to_string(),
            CanonicalValue::Array(
                self.test262_refs
                    .iter()
                    .map(|reference| CanonicalValue::String(reference.clone()))
                    .collect(),
            ),
        );

        let divergence = match &self.divergence {
            Some(divergence) => divergence.canonical_value(),
            None => CanonicalValue::Null,
        };
        map.insert("divergence".to_string(), divergence);

        CanonicalValue::Map(map)
    }

    fn expected_behavior(&self, runtime: CompatibilityRuntime, mode: CompatibilityMode) -> &str {
        match runtime {
            CompatibilityRuntime::Node => &self.node_behavior,
            CompatibilityRuntime::Bun => &self.bun_behavior,
            CompatibilityRuntime::FrankenEngine => match mode {
                CompatibilityMode::Native => &self.franken_native_behavior,
                CompatibilityMode::NodeCompat => &self.franken_node_compat_behavior,
                CompatibilityMode::BunCompat => &self.franken_bun_compat_behavior,
            },
        }
    }

    fn mismatched_runtimes(&self) -> BTreeSet<ReferenceRuntime> {
        let mut mismatches = BTreeSet::new();
        if self.franken_native_behavior != self.node_behavior {
            mismatches.insert(ReferenceRuntime::Node);
        }
        if self.franken_native_behavior != self.bun_behavior {
            mismatches.insert(ReferenceRuntime::Bun);
        }
        mismatches
    }

    fn has_shim_for_mode(&self, mode: CompatibilityMode) -> bool {
        self.explicit_shims.iter().any(|shim| shim.mode == mode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompatibilityMatrixDocument {
    schema_version: String,
    entries: Vec<CompatibilityMatrixEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl CompatibilityContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityEvent {
    pub seq: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub case_id: String,
    pub runtime: String,
    pub mode: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityMatrixErrorCode {
    MatrixParseError,
    DuplicateCaseId,
    CaseNotFound,
    HiddenShim,
    MissingWaiver,
    MissingMigrationGuidance,
    InvalidMatrix,
    ObservationMismatch,
}

impl CompatibilityMatrixErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::MatrixParseError => "FE-MODCOMP-0001",
            Self::DuplicateCaseId => "FE-MODCOMP-0002",
            Self::CaseNotFound => "FE-MODCOMP-0003",
            Self::HiddenShim => "FE-MODCOMP-0004",
            Self::MissingWaiver => "FE-MODCOMP-0005",
            Self::MissingMigrationGuidance => "FE-MODCOMP-0006",
            Self::InvalidMatrix => "FE-MODCOMP-0007",
            Self::ObservationMismatch => "FE-MODCOMP-0008",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrixError {
    pub code: CompatibilityMatrixErrorCode,
    pub message: String,
    pub event: Option<CompatibilityEvent>,
}

impl fmt::Display for CompatibilityMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.event {
            Some(event) => write!(
                f,
                "{}: {} (trace_id={}, decision_id={}, policy_id={})",
                self.code.stable_code(),
                self.message,
                event.trace_id,
                event.decision_id,
                event.policy_id,
            ),
            None => write!(f, "{}: {}", self.code.stable_code(), self.message),
        }
    }
}

impl std::error::Error for CompatibilityMatrixError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityObservation {
    pub case_id: String,
    pub runtime: CompatibilityRuntime,
    pub mode: CompatibilityMode,
    pub observed_behavior: String,
}

impl CompatibilityObservation {
    pub fn new(
        case_id: impl Into<String>,
        runtime: CompatibilityRuntime,
        mode: CompatibilityMode,
        observed_behavior: impl Into<String>,
    ) -> Self {
        Self {
            case_id: case_id.into(),
            runtime,
            mode,
            observed_behavior: observed_behavior.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityObservationOutcome {
    pub case_id: String,
    pub runtime: CompatibilityRuntime,
    pub mode: CompatibilityMode,
    pub observed_behavior: String,
    pub expected_behavior: String,
    pub matched: bool,
    pub divergence: Option<DivergencePolicy>,
    pub event: CompatibilityEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCompatibilityMatrix {
    pub schema_version: String,
    entries: BTreeMap<String, CompatibilityMatrixEntry>,
    events: Vec<CompatibilityEvent>,
    next_event_seq: u64,
}

#[derive(Debug, Clone)]
struct EventDraft {
    event: String,
    outcome: String,
    error_code: String,
    case_id: String,
    runtime: CompatibilityRuntime,
    mode: CompatibilityMode,
    detail: String,
}

impl EventDraft {
    fn allow(
        event: impl Into<String>,
        case_id: impl Into<String>,
        runtime: CompatibilityRuntime,
        mode: CompatibilityMode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event: event.into(),
            outcome: "allow".to_string(),
            error_code: "none".to_string(),
            case_id: case_id.into(),
            runtime,
            mode,
            detail: detail.into(),
        }
    }

    fn deny(
        event: impl Into<String>,
        case_id: impl Into<String>,
        runtime: CompatibilityRuntime,
        mode: CompatibilityMode,
        code: CompatibilityMatrixErrorCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event: event.into(),
            outcome: "deny".to_string(),
            error_code: code.stable_code().to_string(),
            case_id: case_id.into(),
            runtime,
            mode,
            detail: detail.into(),
        }
    }
}

impl ModuleCompatibilityMatrix {
    pub fn from_default_json() -> CompatibilityResult<Self> {
        Self::from_json_str(DEFAULT_MATRIX_JSON)
    }

    pub fn from_json_str(raw: &str) -> CompatibilityResult<Self> {
        let document: CompatibilityMatrixDocument =
            serde_json::from_str(raw).map_err(|error| parse_error(error.to_string()))?;
        Self::from_entries(document.schema_version, document.entries)
    }

    pub fn from_entries(
        schema_version: impl Into<String>,
        mut entries: Vec<CompatibilityMatrixEntry>,
    ) -> CompatibilityResult<Self> {
        let schema_version = schema_version.into().trim().to_string();
        if schema_version.is_empty() {
            return Err(simple_error(
                CompatibilityMatrixErrorCode::InvalidMatrix,
                "schema_version must not be empty",
            ));
        }

        let mut catalog = BTreeMap::new();
        for entry in &mut entries {
            entry.normalize();
            if entry.case_id.is_empty() {
                return Err(simple_error(
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "case_id must not be empty",
                ));
            }
            if catalog
                .insert(entry.case_id.clone(), entry.clone())
                .is_some()
            {
                return Err(simple_error(
                    CompatibilityMatrixErrorCode::DuplicateCaseId,
                    format!("duplicate case_id '{}' in matrix", entry.case_id),
                ));
            }
        }

        Ok(Self {
            schema_version,
            entries: catalog,
            events: Vec::new(),
            next_event_seq: 0,
        })
    }

    pub fn entries(&self) -> Vec<&CompatibilityMatrixEntry> {
        self.entries.values().collect()
    }

    pub fn entry(&self, case_id: &str) -> Option<&CompatibilityMatrixEntry> {
        self.entries.get(case_id)
    }

    pub fn required_waiver_ids(&self) -> BTreeSet<String> {
        self.entries
            .values()
            .filter_map(|entry| entry.divergence.as_ref())
            .map(|divergence| divergence.waiver_id.clone())
            .collect()
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        let document = CompatibilityMatrixDocument {
            schema_version: self.schema_version.clone(),
            entries: self.entries.values().cloned().collect(),
        };
        serde_json::to_string_pretty(&document)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }

    pub fn validate_against_tracker(
        &mut self,
        tracker: &FeatureParityTracker,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<()> {
        let approved = tracker.waivers().keys().cloned().collect::<BTreeSet<_>>();
        self.validate_with_waivers(&approved, context)
    }

    pub fn validate_with_waivers(
        &mut self,
        approved_waivers: &BTreeSet<String>,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<()> {
        let case_ids = self.entries.keys().cloned().collect::<Vec<_>>();
        for case_id in case_ids {
            let entry = self.entries.get(&case_id).cloned().ok_or_else(|| {
                simple_error(CompatibilityMatrixErrorCode::CaseNotFound, case_id.clone())
            })?;

            self.validate_entry(&entry, approved_waivers, context)?;
            self.push_event(
                context,
                EventDraft::allow(
                    "compatibility_entry_validated",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    "compatibility entry passed deterministic validation",
                ),
            );
        }
        Ok(())
    }

    pub fn evaluate_observation(
        &mut self,
        observation: &CompatibilityObservation,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<CompatibilityObservationOutcome> {
        let case_id = observation.case_id.trim().to_string();
        let entry = self.entries.get(&case_id).cloned().ok_or_else(|| {
            self.error(
                context,
                CompatibilityMatrixErrorCode::CaseNotFound,
                EventDraft::deny(
                    "compatibility_observation",
                    case_id.clone(),
                    observation.runtime,
                    observation.mode,
                    CompatibilityMatrixErrorCode::CaseNotFound,
                    format!("unknown case_id '{}'", observation.case_id),
                ),
            )
        })?;

        let expected_behavior = entry
            .expected_behavior(observation.runtime, observation.mode)
            .to_string();
        let observed_behavior = observation.observed_behavior.trim().to_string();

        if expected_behavior != observed_behavior {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::ObservationMismatch,
                EventDraft::deny(
                    "compatibility_observation",
                    entry.case_id.clone(),
                    observation.runtime,
                    observation.mode,
                    CompatibilityMatrixErrorCode::ObservationMismatch,
                    format!(
                        "behavior mismatch for case '{}' (expected='{}', observed='{}')",
                        entry.case_id, expected_behavior, observed_behavior
                    ),
                ),
            ));
        }

        let event = self.push_event(
            context,
            EventDraft::allow(
                "compatibility_observation",
                entry.case_id.clone(),
                observation.runtime,
                observation.mode,
                "observed behavior matches documented matrix",
            ),
        );

        Ok(CompatibilityObservationOutcome {
            case_id: entry.case_id,
            runtime: observation.runtime,
            mode: observation.mode,
            observed_behavior,
            expected_behavior,
            matched: true,
            divergence: entry.divergence,
            event,
        })
    }

    pub fn events(&self) -> &[CompatibilityEvent] {
        &self.events
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "entries".to_string(),
            CanonicalValue::Array(
                self.entries
                    .values()
                    .map(CompatibilityMatrixEntry::canonical_value)
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }

    fn validate_entry(
        &mut self,
        entry: &CompatibilityMatrixEntry,
        approved_waivers: &BTreeSet<String>,
        context: &CompatibilityContext,
    ) -> CompatibilityResult<()> {
        if entry.scenario.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "scenario must not be empty",
                ),
            ));
        }

        if entry.lockstep_case_refs.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "lockstep_case_refs must include at least one reference",
                ),
            ));
        }

        if entry.test262_refs.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    "test262_refs must include at least one reference",
                ),
            ));
        }

        for shim in &entry.explicit_shims {
            if shim.shim_id.is_empty() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must include non-empty shim_id",
                    ),
                ));
            }
            if shim.description.is_empty() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must include non-empty description",
                    ),
                ));
            }
            if shim.test_case_ref.is_empty() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must include non-empty test_case_ref",
                    ),
                ));
            }
            if !shim.removable {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        shim.mode,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "explicit shim must be removable",
                    ),
                ));
            }
        }

        if entry.franken_node_compat_behavior != entry.franken_native_behavior
            && !entry.has_shim_for_mode(CompatibilityMode::NodeCompat)
        {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::HiddenShim,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::NodeCompat,
                    CompatibilityMatrixErrorCode::HiddenShim,
                    "node_compat behavior diverges from native without explicit shim",
                ),
            ));
        }

        if entry.franken_bun_compat_behavior != entry.franken_native_behavior
            && !entry.has_shim_for_mode(CompatibilityMode::BunCompat)
        {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::HiddenShim,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::BunCompat,
                    CompatibilityMatrixErrorCode::HiddenShim,
                    "bun_compat behavior diverges from native without explicit shim",
                ),
            ));
        }

        let mismatches = entry.mismatched_runtimes();
        if mismatches.is_empty() {
            if entry.divergence.is_some() {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        CompatibilityMode::Native,
                        CompatibilityMatrixErrorCode::InvalidMatrix,
                        "divergence metadata present but native behavior matches Node and Bun",
                    ),
                ));
            }
            return Ok(());
        }

        let divergence = match &entry.divergence {
            Some(divergence) => divergence,
            None => {
                return Err(self.error(
                    context,
                    CompatibilityMatrixErrorCode::MissingWaiver,
                    EventDraft::deny(
                        "compatibility_entry_validation",
                        entry.case_id.clone(),
                        CompatibilityRuntime::FrankenEngine,
                        CompatibilityMode::Native,
                        CompatibilityMatrixErrorCode::MissingWaiver,
                        "native behavior diverges from reference runtimes but no divergence policy is declared",
                    ),
                ));
            }
        };

        let declared = divergence
            .diverges_from
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if declared != mismatches {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::InvalidMatrix,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::InvalidMatrix,
                    format!(
                        "divergence runtime set mismatch (declared={:?}, actual={:?})",
                        declared, mismatches
                    ),
                ),
            ));
        }

        if divergence.waiver_id.is_empty() || !approved_waivers.contains(&divergence.waiver_id) {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::MissingWaiver,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::MissingWaiver,
                    format!(
                        "missing approved waiver '{}' for documented divergence",
                        divergence.waiver_id
                    ),
                ),
            ));
        }

        if divergence.migration_guidance.is_empty() {
            return Err(self.error(
                context,
                CompatibilityMatrixErrorCode::MissingMigrationGuidance,
                EventDraft::deny(
                    "compatibility_entry_validation",
                    entry.case_id.clone(),
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    CompatibilityMatrixErrorCode::MissingMigrationGuidance,
                    "divergence requires migration guidance",
                ),
            ));
        }

        Ok(())
    }

    fn push_event(
        &mut self,
        context: &CompatibilityContext,
        draft: EventDraft,
    ) -> CompatibilityEvent {
        let event = CompatibilityEvent {
            seq: self.next_event_seq,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT_NAME.to_string(),
            event: draft.event,
            outcome: draft.outcome,
            error_code: draft.error_code,
            case_id: draft.case_id,
            runtime: draft.runtime.as_str().to_string(),
            mode: draft.mode.as_str().to_string(),
            detail: draft.detail,
        };
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        self.events.push(event.clone());
        event
    }

    fn error(
        &mut self,
        context: &CompatibilityContext,
        code: CompatibilityMatrixErrorCode,
        draft: EventDraft,
    ) -> Box<CompatibilityMatrixError> {
        let detail = draft.detail.clone();
        let event = self.push_event(context, draft);
        Box::new(CompatibilityMatrixError {
            code,
            message: detail,
            event: Some(event),
        })
    }
}

impl Default for ModuleCompatibilityMatrix {
    fn default() -> Self {
        Self::from_default_json().expect("default module compatibility matrix must parse")
    }
}

fn normalize_string_vec(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        *value = value.trim().to_string();
    }
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
}

fn parse_error(message: String) -> Box<CompatibilityMatrixError> {
    Box::new(CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::MatrixParseError,
        message,
        event: None,
    })
}

fn simple_error(
    code: CompatibilityMatrixErrorCode,
    message: impl Into<String>,
) -> Box<CompatibilityMatrixError> {
    Box::new(CompatibilityMatrixError {
        code,
        message: message.into(),
        event: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CompatibilityContext {
        CompatibilityContext::new("trace-modcompat", "decision-modcompat", "policy-modcompat")
    }

    #[test]
    fn default_matrix_round_trips_and_hashes_deterministically() {
        let matrix_a = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let matrix_b = ModuleCompatibilityMatrix::from_default_json().unwrap();

        assert_eq!(matrix_a.canonical_hash(), matrix_b.canonical_hash());
        assert_eq!(
            matrix_a.to_json_pretty().unwrap(),
            matrix_b.to_json_pretty().unwrap()
        );
    }

    #[test]
    fn validation_requires_explicit_shim_for_mode_specific_divergence() {
        let entry = CompatibilityMatrixEntry {
            case_id: "case-hidden-shim".to_string(),
            feature: ModuleFeature::Cjs,
            scenario: "hidden shim check".to_string(),
            node_behavior: "throw".to_string(),
            bun_behavior: "bridge".to_string(),
            franken_native_behavior: "throw".to_string(),
            franken_node_compat_behavior: "throw".to_string(),
            franken_bun_compat_behavior: "bridge".to_string(),
            explicit_shims: vec![],
            lockstep_case_refs: vec!["lockstep/module/hidden-shim".to_string()],
            test262_refs: vec!["language/module-code/sample.js".to_string()],
            divergence: Some(DivergencePolicy {
                diverges_from: vec![ReferenceRuntime::Bun],
                reason: "strict native mode".to_string(),
                impact: "requires compat mode".to_string(),
                waiver_id: "w-hidden".to_string(),
                migration_guidance: "use import".to_string(),
            }),
        };

        let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
        let mut waivers = BTreeSet::new();
        waivers.insert("w-hidden".to_string());

        let error = matrix
            .validate_with_waivers(&waivers, &context())
            .expect_err("expected hidden shim validation error");
        assert_eq!(error.code, CompatibilityMatrixErrorCode::HiddenShim);
        assert_eq!(
            error
                .event
                .as_ref()
                .expect("event should be attached")
                .error_code,
            CompatibilityMatrixErrorCode::HiddenShim.stable_code(),
        );
    }

    #[test]
    fn validation_requires_approved_waiver_for_native_divergence() {
        let mut matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
        let waivers = BTreeSet::new();

        let error = matrix
            .validate_with_waivers(&waivers, &context())
            .expect_err("expected missing waiver error");
        assert_eq!(error.code, CompatibilityMatrixErrorCode::MissingWaiver);
    }
}
