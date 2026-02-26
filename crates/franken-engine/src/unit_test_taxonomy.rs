//! FRX-20.1 unit-test taxonomy and fixture registry contract.
//!
//! This module defines a deterministic, versioned taxonomy for unit-test
//! classes and binds fixture registries to lane ownership and replay controls.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const UNIT_TEST_TAXONOMY_SCHEMA_VERSION: &str = "frx.unit-test-taxonomy.v1";
pub const FIXTURE_REGISTRY_SCHEMA_VERSION: &str = "frx.fixture-registry.v1";
pub const DETERMINISM_CONTRACT_SCHEMA_VERSION: &str = "frx.test-determinism-contract.v1";

pub const REQUIRED_STRUCTURED_LOG_FIELDS: &[&str] = &[
    "schema_version",
    "scenario_id",
    "trace_id",
    "decision_id",
    "policy_id",
    "component",
    "event",
    "decision_path",
    "seed",
    "timing_us",
    "outcome",
    "error_code",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitTestClass {
    Core,
    Edge,
    Adversarial,
    Regression,
    FaultInjection,
}

impl UnitTestClass {
    pub const ALL: [Self; 5] = [
        Self::Core,
        Self::Edge,
        Self::Adversarial,
        Self::Regression,
        Self::FaultInjection,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Edge => "edge",
            Self::Adversarial => "adversarial",
            Self::Regression => "regression",
            Self::FaultInjection => "fault_injection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneId {
    Compiler,
    JsRuntime,
    WasmRuntime,
    HybridRouter,
    Verification,
    Toolchain,
    GovernanceEvidence,
    AdoptionRelease,
}

impl LaneId {
    pub const ALL: [Self; 8] = [
        Self::Compiler,
        Self::JsRuntime,
        Self::WasmRuntime,
        Self::HybridRouter,
        Self::Verification,
        Self::Toolchain,
        Self::GovernanceEvidence,
        Self::AdoptionRelease,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compiler => "compiler",
            Self::JsRuntime => "js_runtime",
            Self::WasmRuntime => "wasm_runtime",
            Self::HybridRouter => "hybrid_router",
            Self::Verification => "verification",
            Self::Toolchain => "toolchain",
            Self::GovernanceEvidence => "governance_evidence",
            Self::AdoptionRelease => "adoption_release",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismContract {
    pub schema_version: String,
    pub require_seed: bool,
    pub require_seed_transcript_checksum: bool,
    pub require_fixed_timezone: bool,
    pub timezone: String,
    pub require_fixed_locale: bool,
    pub lang: String,
    pub lc_all: String,
    pub require_toolchain_fingerprint: bool,
    pub require_replay_command: bool,
}

impl DeterminismContract {
    pub fn default_frx20() -> Self {
        Self {
            schema_version: DETERMINISM_CONTRACT_SCHEMA_VERSION.to_string(),
            require_seed: true,
            require_seed_transcript_checksum: true,
            require_fixed_timezone: true,
            timezone: "UTC".to_string(),
            require_fixed_locale: true,
            lang: "C.UTF-8".to_string(),
            lc_all: "C.UTF-8".to_string(),
            require_toolchain_fingerprint: true,
            require_replay_command: true,
        }
    }

    fn validate(&self) -> Result<(), TaxonomyValidationError> {
        if self.schema_version != DETERMINISM_CONTRACT_SCHEMA_VERSION {
            return Err(TaxonomyValidationError::InvalidSchemaVersion {
                field: "determinism_contract.schema_version".to_string(),
                expected: DETERMINISM_CONTRACT_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.require_fixed_timezone && self.timezone.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "determinism_contract.timezone".to_string(),
            });
        }
        if self.require_fixed_locale
            && (self.lang.trim().is_empty() || self.lc_all.trim().is_empty())
        {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "determinism_contract.locale".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRegistryEntry {
    pub fixture_id: String,
    pub fixture_path: String,
    pub trace_path: Option<String>,
    pub provenance: String,
    pub owner_lane: LaneId,
    pub required_classes: Vec<UnitTestClass>,
    pub e2e_family: String,
    pub seed_strategy: String,
    pub structured_log_fields: Vec<String>,
    pub artifact_retention: String,
}

impl FixtureRegistryEntry {
    fn validate(&self, seen_ids: &mut BTreeSet<String>) -> Result<(), TaxonomyValidationError> {
        if self.fixture_id.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "fixture_registry.fixture_id".to_string(),
            });
        }
        if !seen_ids.insert(self.fixture_id.clone()) {
            return Err(TaxonomyValidationError::DuplicateFixtureId {
                fixture_id: self.fixture_id.clone(),
            });
        }
        if self.fixture_path.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.fixture_path", self.fixture_id),
            });
        }
        if self.provenance.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.provenance", self.fixture_id),
            });
        }
        if self.required_classes.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.required_classes", self.fixture_id),
            });
        }
        if self.e2e_family.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.e2e_family", self.fixture_id),
            });
        }
        if self.seed_strategy.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.seed_strategy", self.fixture_id),
            });
        }
        if self.artifact_retention.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.artifact_retention", self.fixture_id),
            });
        }

        let field_set: BTreeSet<&str> = self
            .structured_log_fields
            .iter()
            .map(String::as_str)
            .collect();
        for required in REQUIRED_STRUCTURED_LOG_FIELDS {
            if !field_set.contains(required) {
                return Err(TaxonomyValidationError::MissingStructuredLogField {
                    fixture_id: self.fixture_id.clone(),
                    field: (*required).to_string(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCoverageContract {
    pub lane: LaneId,
    pub owner: String,
    pub required_unit_classes: Vec<UnitTestClass>,
    pub mapped_e2e_families: Vec<String>,
    pub coverage_rationale: String,
}

impl LaneCoverageContract {
    fn validate(&self) -> Result<(), TaxonomyValidationError> {
        if self.owner.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.owner", self.lane.as_str()),
            });
        }
        if self.required_unit_classes.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.required_unit_classes", self.lane.as_str()),
            });
        }
        if self.mapped_e2e_families.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.mapped_e2e_families", self.lane.as_str()),
            });
        }
        if self.coverage_rationale.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.coverage_rationale", self.lane.as_str()),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitTestTaxonomyBundle {
    pub schema_version: String,
    pub fixture_registry_schema_version: String,
    pub determinism_contract: DeterminismContract,
    pub lane_coverage: Vec<LaneCoverageContract>,
    pub fixture_registry: Vec<FixtureRegistryEntry>,
}

impl UnitTestTaxonomyBundle {
    pub fn validate_for_gate(&self) -> Result<(), TaxonomyValidationError> {
        if self.schema_version != UNIT_TEST_TAXONOMY_SCHEMA_VERSION {
            return Err(TaxonomyValidationError::InvalidSchemaVersion {
                field: "schema_version".to_string(),
                expected: UNIT_TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.fixture_registry_schema_version != FIXTURE_REGISTRY_SCHEMA_VERSION {
            return Err(TaxonomyValidationError::InvalidSchemaVersion {
                field: "fixture_registry_schema_version".to_string(),
                expected: FIXTURE_REGISTRY_SCHEMA_VERSION.to_string(),
                actual: self.fixture_registry_schema_version.clone(),
            });
        }

        self.determinism_contract.validate()?;

        if self.lane_coverage.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "lane_coverage".to_string(),
            });
        }

        let mut seen_lanes = BTreeSet::new();
        for coverage in &self.lane_coverage {
            coverage.validate()?;
            if !seen_lanes.insert(coverage.lane) {
                return Err(TaxonomyValidationError::DuplicateLaneCoverage {
                    lane: coverage.lane.as_str().to_string(),
                });
            }
        }

        for lane in LaneId::ALL {
            if !seen_lanes.contains(&lane) {
                return Err(TaxonomyValidationError::MissingLaneCoverage {
                    lane: lane.as_str().to_string(),
                });
            }
        }

        if self.fixture_registry.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "fixture_registry".to_string(),
            });
        }

        let mut seen_fixture_ids = BTreeSet::new();
        for fixture in &self.fixture_registry {
            fixture.validate(&mut seen_fixture_ids)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaxonomyValidationError {
    MissingRequiredField {
        field: String,
    },
    InvalidSchemaVersion {
        field: String,
        expected: String,
        actual: String,
    },
    MissingStructuredLogField {
        fixture_id: String,
        field: String,
    },
    DuplicateFixtureId {
        fixture_id: String,
    },
    DuplicateLaneCoverage {
        lane: String,
    },
    MissingLaneCoverage {
        lane: String,
    },
}

impl TaxonomyValidationError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MissingRequiredField { .. } => "FE-FRX-20-1-REGISTRY-0001",
            Self::InvalidSchemaVersion { .. } => "FE-FRX-20-1-SCHEMA-0001",
            Self::MissingStructuredLogField { .. } => "FE-FRX-20-1-LOGGING-0001",
            Self::DuplicateFixtureId { .. } => "FE-FRX-20-1-REGISTRY-0002",
            Self::DuplicateLaneCoverage { .. } => "FE-FRX-20-1-COVERAGE-0001",
            Self::MissingLaneCoverage { .. } => "FE-FRX-20-1-COVERAGE-0002",
        }
    }
}

pub fn default_frx20_bundle() -> UnitTestTaxonomyBundle {
    UnitTestTaxonomyBundle {
        schema_version: UNIT_TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
        fixture_registry_schema_version: FIXTURE_REGISTRY_SCHEMA_VERSION.to_string(),
        determinism_contract: DeterminismContract::default_frx20(),
        lane_coverage: vec![
            LaneCoverageContract {
                lane: LaneId::Compiler,
                owner: "frx-compiler-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::Edge,
                ],
                mapped_e2e_families: vec!["frx_track_b_compiler".to_string()],
                coverage_rationale:
                    "Compiler lane requires deterministic semantic and lowering parity.".to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::JsRuntime,
                owner: "frx-js-runtime-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Edge,
                    UnitTestClass::Adversarial,
                ],
                mapped_e2e_families: vec!["frx_track_c_js_runtime".to_string()],
                coverage_rationale:
                    "JS runtime lane validates hook/effect ordering and replay stability.".to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::WasmRuntime,
                owner: "frx-wasm-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Edge,
                    UnitTestClass::FaultInjection,
                ],
                mapped_e2e_families: vec!["frx_track_d_wasm_lane".to_string()],
                coverage_rationale:
                    "WASM lane enforces fallback and scheduler integrity under degraded conditions."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::HybridRouter,
                owner: "frx-hybrid-router".to_string(),
                required_unit_classes: vec![UnitTestClass::Core, UnitTestClass::Regression],
                mapped_e2e_families: vec!["frx_track_d_hybrid_router".to_string()],
                coverage_rationale:
                    "Router lane must preserve deterministic routing decisions across seeds."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::Verification,
                owner: "frx-verification-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Adversarial,
                    UnitTestClass::FaultInjection,
                ],
                mapped_e2e_families: vec!["frx_track_e_verification".to_string()],
                coverage_rationale:
                    "Verification lane requires adversarial and fault-driven evidence closure.".to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::Toolchain,
                owner: "frx-toolchain-lane".to_string(),
                required_unit_classes: vec![UnitTestClass::Core, UnitTestClass::Regression],
                mapped_e2e_families: vec!["frx_track_f_toolchain".to_string()],
                coverage_rationale:
                    "Toolchain lane validates compatibility and reproducible integration hooks."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::GovernanceEvidence,
                owner: "frx-governance-evidence-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::FaultInjection,
                ],
                mapped_e2e_families: vec!["frx_governance_evidence".to_string()],
                coverage_rationale:
                    "Governance lane enforces evidence integrity and replay linkage contracts."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::AdoptionRelease,
                owner: "frx-adoption-release-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::Adversarial,
                ],
                mapped_e2e_families: vec!["frx_adoption_release".to_string()],
                coverage_rationale:
                    "Adoption/release lane validates fail-closed readiness with deterministic replay."
                        .to_string(),
            },
        ],
        fixture_registry: vec![
            FixtureRegistryEntry {
                fixture_id: "frx.react.corpus.v1".to_string(),
                fixture_path:
                    "crates/franken-engine/tests/conformance/frx_react_corpus/fixtures".to_string(),
                trace_path: Some(
                    "crates/franken-engine/tests/conformance/frx_react_corpus/traces".to_string(),
                ),
                provenance: "docs/frx_canonical_react_behavior_corpus_v1.json".to_string(),
                owner_lane: LaneId::JsRuntime,
                required_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Edge,
                    UnitTestClass::Regression,
                ],
                e2e_family: "frx_react_behavior_replay".to_string(),
                seed_strategy: "fixture_seed_stable_by_scenario".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+events+commands".to_string(),
            },
            FixtureRegistryEntry {
                fixture_id: "ifc.corpus.v1".to_string(),
                fixture_path: "crates/franken-engine/tests/conformance/ifc_corpus/fixtures"
                    .to_string(),
                trace_path: Some(
                    "crates/franken-engine/tests/conformance/ifc_corpus/expected".to_string(),
                ),
                provenance: "crates/franken-engine/tests/conformance/ifc_corpus/ifc_conformance_assets.json"
                    .to_string(),
                owner_lane: LaneId::Verification,
                required_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Adversarial,
                    UnitTestClass::FaultInjection,
                ],
                e2e_family: "ifc_conformance_gate".to_string(),
                seed_strategy: "seed_fixed_by_asset_id".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+evidence+ifc_summary".to_string(),
            },
            FixtureRegistryEntry {
                fixture_id: "transplanted.conformance.v1".to_string(),
                fixture_path:
                    "crates/franken-engine/tests/conformance/transplanted/fixtures".to_string(),
                trace_path: Some(
                    "crates/franken-engine/tests/conformance/transplanted/expected".to_string(),
                ),
                provenance:
                    "crates/franken-engine/tests/conformance/transplanted/conformance_assets.json"
                        .to_string(),
                owner_lane: LaneId::Compiler,
                required_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::Edge,
                ],
                e2e_family: "parser_conformance_replay".to_string(),
                seed_strategy: "seed_fixed_by_fixture_ref".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+evidence+counterexample".to_string(),
            },
            FixtureRegistryEntry {
                fixture_id: "parser.phase0.semantic.fixtures.v1".to_string(),
                fixture_path:
                    "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json"
                        .to_string(),
                trace_path: None,
                provenance: "docs/PARSER_GRAMMAR_CLOSURE_BACKLOG.md".to_string(),
                owner_lane: LaneId::Compiler,
                required_classes: vec![UnitTestClass::Core, UnitTestClass::Regression],
                e2e_family: "parser_phase0_gate".to_string(),
                seed_strategy: "seed_derived_from_fixture_hash".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+events+commands".to_string(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundle_validates() {
        let bundle = default_frx20_bundle();
        assert_eq!(bundle.validate_for_gate(), Ok(()));
    }

    #[test]
    fn fails_on_missing_structured_log_field() {
        let mut bundle = default_frx20_bundle();
        bundle.fixture_registry[0]
            .structured_log_fields
            .retain(|field| field != "trace_id");

        let error = bundle
            .validate_for_gate()
            .expect_err("expected missing log field");
        assert_eq!(error.error_code(), "FE-FRX-20-1-LOGGING-0001");
    }

    #[test]
    fn fails_on_duplicate_fixture_ids() {
        let mut bundle = default_frx20_bundle();
        let duplicate = bundle.fixture_registry[0].clone();
        bundle.fixture_registry.push(duplicate);

        let error = bundle
            .validate_for_gate()
            .expect_err("expected duplicate fixture id");
        assert_eq!(error.error_code(), "FE-FRX-20-1-REGISTRY-0002");
    }

    #[test]
    fn fails_when_lane_coverage_missing() {
        let mut bundle = default_frx20_bundle();
        bundle
            .lane_coverage
            .retain(|coverage| coverage.lane != LaneId::HybridRouter);

        let error = bundle
            .validate_for_gate()
            .expect_err("expected missing lane coverage");
        assert_eq!(error.error_code(), "FE-FRX-20-1-COVERAGE-0002");
    }

    #[test]
    fn fails_when_schema_version_mismatches() {
        let mut bundle = default_frx20_bundle();
        bundle.schema_version = "frx.unit-test-taxonomy.v0".to_string();

        let error = bundle
            .validate_for_gate()
            .expect_err("expected schema mismatch");
        assert_eq!(error.error_code(), "FE-FRX-20-1-SCHEMA-0001");
    }

    #[test]
    fn serde_roundtrip_preserves_bundle() {
        let bundle = default_frx20_bundle();
        let encoded = serde_json::to_string(&bundle).expect("serialize bundle");
        let decoded: UnitTestTaxonomyBundle =
            serde_json::from_str(&encoded).expect("deserialize bundle");
        assert_eq!(decoded, bundle);
    }
}
