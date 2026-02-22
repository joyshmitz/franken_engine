#![allow(dead_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn seeded(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceAssetManifest {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub assets: Vec<ConformanceAssetRecord>,
}

impl ConformanceAssetManifest {
    pub const CURRENT_SCHEMA: &'static str = "franken-engine.conformance-assets.v1";

    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let bytes = fs::read(path.as_ref())?;
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(manifest)
    }

    fn validate_and_resolve(
        &self,
        manifest_path: &Path,
    ) -> Result<Vec<ResolvedConformanceAsset>, ConformanceManifestError> {
        if self.schema_version.trim() != Self::CURRENT_SCHEMA {
            return Err(ConformanceManifestError::UnsupportedSchema {
                expected: Self::CURRENT_SCHEMA.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.assets.is_empty() {
            return Err(ConformanceManifestError::EmptyAssetSet);
        }

        let manifest_root = manifest_path
            .parent()
            .ok_or(ConformanceManifestError::ManifestHasNoParent)?;
        let mut resolved = Vec::with_capacity(self.assets.len());

        for asset in &self.assets {
            asset.validate()?;

            let fixture_abs = manifest_root.join(&asset.fixture_path);
            let expected_abs = manifest_root.join(&asset.expected_output_path);
            let fixture_bytes =
                fs::read(&fixture_abs).map_err(|err| ConformanceManifestError::AssetIo {
                    asset_id: asset.asset_id.clone(),
                    path: fixture_abs.clone(),
                    source: err,
                })?;
            let expected_bytes =
                fs::read(&expected_abs).map_err(|err| ConformanceManifestError::AssetIo {
                    asset_id: asset.asset_id.clone(),
                    path: expected_abs.clone(),
                    source: err,
                })?;

            let fixture_hash = sha256_hex(&fixture_bytes);
            if fixture_hash != asset.fixture_hash {
                return Err(ConformanceManifestError::FixtureHashMismatch {
                    asset_id: asset.asset_id.clone(),
                    expected: asset.fixture_hash.clone(),
                    actual: fixture_hash,
                });
            }

            let expected_hash = sha256_hex(&expected_bytes);
            if expected_hash != asset.expected_output_hash {
                return Err(ConformanceManifestError::ExpectedOutputHashMismatch {
                    asset_id: asset.asset_id.clone(),
                    expected: asset.expected_output_hash.clone(),
                    actual: expected_hash,
                });
            }

            resolved.push(ResolvedConformanceAsset {
                record: asset.clone(),
                fixture_path: fixture_abs,
                expected_output_path: expected_abs,
            });
        }

        Ok(resolved)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceAssetRecord {
    pub asset_id: String,
    pub source_donor: String,
    pub semantic_domain: String,
    pub normative_reference: String,
    pub fixture_path: String,
    pub fixture_hash: String,
    pub expected_output_path: String,
    pub expected_output_hash: String,
    pub import_date: String,
}

impl ConformanceAssetRecord {
    fn validate(&self) -> Result<(), ConformanceManifestError> {
        if self.asset_id.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("asset_id"));
        }
        if self.source_donor.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("source_donor"));
        }
        if self.semantic_domain.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("semantic_domain"));
        }
        if self.normative_reference.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField(
                "normative_reference",
            ));
        }
        if self.fixture_path.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("fixture_path"));
        }
        if self.fixture_hash.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("fixture_hash"));
        }
        if self.expected_output_path.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField(
                "expected_output_path",
            ));
        }
        if self.expected_output_hash.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField(
                "expected_output_hash",
            ));
        }
        if self.import_date.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("import_date"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ResolvedConformanceAsset {
    record: ConformanceAssetRecord,
    fixture_path: PathBuf,
    expected_output_path: PathBuf,
}

#[derive(Debug)]
pub enum ConformanceManifestError {
    UnsupportedSchema {
        expected: String,
        actual: String,
    },
    EmptyAssetSet,
    ManifestHasNoParent,
    MissingField(&'static str),
    AssetIo {
        asset_id: String,
        path: PathBuf,
        source: io::Error,
    },
    FixtureHashMismatch {
        asset_id: String,
        expected: String,
        actual: String,
    },
    ExpectedOutputHashMismatch {
        asset_id: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ConformanceManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { expected, actual } => {
                write!(
                    f,
                    "unsupported conformance manifest schema: expected `{expected}`, got `{actual}`"
                )
            }
            Self::EmptyAssetSet => write!(f, "conformance manifest contains no assets"),
            Self::ManifestHasNoParent => write!(f, "manifest path has no parent directory"),
            Self::MissingField(field) => {
                write!(f, "manifest entry is missing required field `{field}`")
            }
            Self::AssetIo {
                asset_id,
                path,
                source,
            } => write!(
                f,
                "failed to read conformance asset `{asset_id}` at {}: {source}",
                path.display()
            ),
            Self::FixtureHashMismatch {
                asset_id,
                expected,
                actual,
            } => write!(
                f,
                "fixture hash mismatch for `{asset_id}`: expected `{expected}`, got `{actual}`"
            ),
            Self::ExpectedOutputHashMismatch {
                asset_id,
                expected,
                actual,
            } => write!(
                f,
                "expected output hash mismatch for `{asset_id}`: expected `{expected}`, got `{actual}`"
            ),
        }
    }
}

impl Error for ConformanceManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AssetIo { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DonorFixture {
    pub donor_harness: String,
    pub source: String,
    pub observed_output: String,
}

pub trait DonorHarnessApi {
    fn adapt_source(&self, source: &str) -> String;
}

#[derive(Debug, Clone, Default)]
pub struct DonorHarnessAdapter;

impl DonorHarnessApi for DonorHarnessAdapter {
    fn adapt_source(&self, source: &str) -> String {
        source
            .replace("$262.createRealm()", "__franken_create_realm()")
            .replace("$DONE", "__franken_done")
            .replace("print(", "franken_print(")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaiverReasonCode {
    HarnessGap,
    HostHookMissing,
    IntentionalDivergence,
    NotYetImplemented,
}

impl WaiverReasonCode {
    fn parse(input: &str) -> Option<Self> {
        match input.trim() {
            "harness_gap" => Some(Self::HarnessGap),
            "host_hook_missing" => Some(Self::HostHookMissing),
            "intentional_divergence" => Some(Self::IntentionalDivergence),
            "not_yet_implemented" => Some(Self::NotYetImplemented),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceWaiver {
    pub asset_id: String,
    pub reason_code: WaiverReasonCode,
    pub tracking_bead: String,
    pub expiry_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConformanceWaiverSet {
    pub waivers: Vec<ConformanceWaiver>,
}

impl ConformanceWaiverSet {
    pub fn load_toml(path: impl AsRef<Path>) -> io::Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path.as_ref())?;
        parse_waiver_toml(&content)
    }

    fn find_active(&self, asset_id: &str, run_date: &str) -> Option<&ConformanceWaiver> {
        self.waivers
            .iter()
            .find(|waiver| waiver.asset_id == asset_id && waiver.expiry_date.as_str() >= run_date)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReproMetadata {
    pub version_combination: BTreeMap<String, String>,
    pub first_seen_commit: String,
    pub regression_commit: Option<String>,
    pub ci_run_id: Option<String>,
    pub issue_tracker_project: String,
    pub issue_tracking_bead: Option<String>,
}

impl Default for ConformanceReproMetadata {
    fn default() -> Self {
        let mut version_combination = BTreeMap::new();
        version_combination.insert(
            "franken_engine".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        Self {
            version_combination,
            first_seen_commit: "unknown".to_string(),
            regression_commit: None,
            ci_run_id: None,
            issue_tracker_project: "beads".to_string(),
            issue_tracking_bead: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceFailureClass {
    Breaking,
    Behavioral,
    Observability,
    Performance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceFailureSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceDeltaKind {
    SchemaFieldAdded,
    SchemaFieldRemoved,
    SchemaFieldModified,
    BehavioralSemanticShift,
    TimingChange,
    ErrorFormatChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceDeltaClassification {
    pub kind: ConformanceDeltaKind,
    pub field: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceMinimizationSummary {
    pub strategy: String,
    pub original_source_lines: usize,
    pub minimized_source_lines: usize,
    pub original_expected_lines: usize,
    pub minimized_expected_lines: usize,
    pub original_actual_lines: usize,
    pub minimized_actual_lines: usize,
    pub preserved_failure_class: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReproEnvironment {
    pub locale: String,
    pub timezone: String,
    pub gc_schedule: String,
    pub rust_toolchain: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReplayContract {
    pub deterministic_seed: u64,
    pub replay_command: String,
    pub verification_command: String,
    pub verification_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceIssueLink {
    pub tracker: String,
    pub issue_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunLinkage {
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub ci_run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceMinimizedFailingVector {
    pub asset_id: String,
    pub source_donor: String,
    pub semantic_domain: String,
    pub normative_reference: String,
    pub fixture: DonorFixture,
    pub expected_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceMinimizedReproArtifact {
    pub schema_version: String,
    pub artifact_id: String,
    pub failure_id: String,
    pub boundary_surface: String,
    pub failure_class: ConformanceFailureClass,
    pub severity: ConformanceFailureSeverity,
    pub version_combination: BTreeMap<String, String>,
    pub first_seen_commit: String,
    pub regression_commit: Option<String>,
    pub environment: ConformanceReproEnvironment,
    pub replay: ConformanceReplayContract,
    pub expected_output: String,
    pub actual_output: String,
    pub delta_classification: Vec<ConformanceDeltaClassification>,
    pub minimization: ConformanceMinimizationSummary,
    pub failing_vector: ConformanceMinimizedFailingVector,
    pub evidence_ledger_id: String,
    pub linked_run: ConformanceRunLinkage,
    pub issue_tracker: ConformanceIssueLink,
}

impl ConformanceMinimizedReproArtifact {
    pub const CURRENT_SCHEMA: &'static str = "franken-engine.conformance-min-repro.v1";

    pub fn verify_replay(&self) -> Result<(), ConformanceReplayVerificationError> {
        let expected = canonicalize_conformance_output(&self.failing_vector.expected_output);
        let actual = canonicalize_conformance_output(&self.failing_vector.fixture.observed_output);
        if expected == actual {
            return Err(ConformanceReplayVerificationError::FailureNotReproduced);
        }

        let observed_delta = classify_conformance_delta(&expected, &actual);
        let observed_class = classify_failure_class(&observed_delta);
        if observed_class != self.failure_class {
            return Err(ConformanceReplayVerificationError::FailureClassMismatch {
                expected: self.failure_class,
                actual: observed_class,
            });
        }
        if observed_delta != self.delta_classification {
            return Err(ConformanceReplayVerificationError::DeltaClassificationDrift);
        }

        let digest = repro_verification_digest(self.replay.deterministic_seed, &expected, &actual);
        if digest != self.replay.verification_digest {
            return Err(ConformanceReplayVerificationError::DigestMismatch {
                expected: self.replay.verification_digest.clone(),
                actual: digest,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceReplayVerificationError {
    FailureNotReproduced,
    FailureClassMismatch {
        expected: ConformanceFailureClass,
        actual: ConformanceFailureClass,
    },
    DeltaClassificationDrift,
    DigestMismatch {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ConformanceReplayVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailureNotReproduced => write!(
                f,
                "replay verification failed: expected mismatch but outputs are equal"
            ),
            Self::FailureClassMismatch { expected, actual } => write!(
                f,
                "replay verification failure class mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::DeltaClassificationDrift => write!(
                f,
                "replay verification delta classification drifted from recorded artifact"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "replay verification digest mismatch: expected `{expected}`, got `{actual}`"
            ),
        }
    }
}

impl Error for ConformanceReplayVerificationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunnerConfig {
    pub trace_prefix: String,
    pub policy_id: String,
    pub seed: u64,
    pub locale: String,
    pub timezone: String,
    pub gc_schedule: String,
    pub run_date: String,
    pub repro_metadata: ConformanceReproMetadata,
}

impl Default for ConformanceRunnerConfig {
    fn default() -> Self {
        Self {
            trace_prefix: "trace-conformance".to_string(),
            policy_id: "policy-conformance-v1".to_string(),
            seed: 7,
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            run_date: "1970-01-01".to_string(),
            repro_metadata: ConformanceReproMetadata::default(),
        }
    }
}

impl ConformanceRunnerConfig {
    fn validate(&self) -> Result<(), ConformanceRunError> {
        if self.trace_prefix.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "trace_prefix is required".to_string(),
            ));
        }
        if self.policy_id.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "policy_id is required".to_string(),
            ));
        }
        if self.locale.as_str() != "C" {
            return Err(ConformanceRunError::InvalidConfig(
                "locale must be fixed to `C`".to_string(),
            ));
        }
        if self.timezone.as_str() != "UTC" {
            return Err(ConformanceRunError::InvalidConfig(
                "timezone must be fixed to `UTC`".to_string(),
            ));
        }
        if self.gc_schedule.as_str() != "deterministic" {
            return Err(ConformanceRunError::InvalidConfig(
                "gc_schedule must be `deterministic`".to_string(),
            ));
        }
        if self.run_date.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "run_date is required".to_string(),
            ));
        }
        if self.repro_metadata.first_seen_commit.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "repro_metadata.first_seen_commit is required".to_string(),
            ));
        }
        if self.repro_metadata.issue_tracker_project.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "repro_metadata.issue_tracker_project is required".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub asset_id: String,
    pub semantic_domain: String,
    pub duration_us: u64,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunSummary {
    pub run_id: String,
    pub asset_manifest_hash: String,
    pub total_assets: usize,
    pub passed: usize,
    pub failed: usize,
    pub waived: usize,
    pub errored: usize,
    pub env_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunResult {
    pub run_id: String,
    pub asset_manifest_hash: String,
    pub logs: Vec<ConformanceLogEvent>,
    pub summary: ConformanceRunSummary,
    pub minimized_repros: Vec<ConformanceMinimizedReproArtifact>,
}

impl ConformanceRunResult {
    pub fn enforce_ci_gate(&self) -> Result<(), ConformanceCiGateError> {
        if self.summary.failed > 0 || self.summary.errored > 0 {
            Err(ConformanceCiGateError {
                failed: self.summary.failed,
                errored: self.summary.errored,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCiGateError {
    pub failed: usize,
    pub errored: usize,
}

impl fmt::Display for ConformanceCiGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conformance CI gate failed: failed={}, errored={}",
            self.failed, self.errored
        )
    }
}

impl Error for ConformanceCiGateError {}

#[derive(Debug)]
pub enum ConformanceRunError {
    InvalidConfig(String),
    Manifest(ConformanceManifestError),
    FixtureIo {
        asset_id: String,
        path: PathBuf,
        source: io::Error,
    },
    InvalidFixture {
        asset_id: String,
        source: io::Error,
    },
    ExpectedOutputIo {
        asset_id: String,
        path: PathBuf,
        source: io::Error,
    },
    ReproInvariant {
        asset_id: String,
        detail: String,
    },
    Io(io::Error),
}

impl fmt::Display for ConformanceRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid conformance config: {reason}"),
            Self::Manifest(err) => write!(f, "{err}"),
            Self::FixtureIo {
                asset_id,
                path,
                source,
            } => write!(
                f,
                "failed to read fixture for `{asset_id}` at {}: {source}",
                path.display()
            ),
            Self::InvalidFixture { asset_id, source } => {
                write!(f, "invalid donor fixture for `{asset_id}`: {source}")
            }
            Self::ExpectedOutputIo {
                asset_id,
                path,
                source,
            } => write!(
                f,
                "failed to read expected output for `{asset_id}` at {}: {source}",
                path.display()
            ),
            Self::ReproInvariant { asset_id, detail } => {
                write!(f, "repro invariant violated for `{asset_id}`: {detail}")
            }
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl Error for ConformanceRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(err) => Some(err),
            Self::FixtureIo { source, .. } => Some(source),
            Self::InvalidFixture { source, .. } => Some(source),
            Self::ExpectedOutputIo { source, .. } => Some(source),
            Self::Io(err) => Some(err),
            Self::InvalidConfig(_) | Self::ReproInvariant { .. } => None,
        }
    }
}

impl From<ConformanceManifestError> for ConformanceRunError {
    fn from(value: ConformanceManifestError) -> Self {
        Self::Manifest(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConformanceRunner {
    pub config: ConformanceRunnerConfig,
    pub adapter: DonorHarnessAdapter,
}

impl ConformanceRunner {
    pub fn run(
        &self,
        manifest_path: impl AsRef<Path>,
        waivers: &ConformanceWaiverSet,
    ) -> Result<ConformanceRunResult, ConformanceRunError> {
        self.config.validate()?;
        let manifest_path = manifest_path.as_ref();
        let manifest =
            ConformanceAssetManifest::load(manifest_path).map_err(ConformanceRunError::Io)?;
        let resolved = manifest.validate_and_resolve(manifest_path)?;
        let asset_manifest_hash =
            sha256_hex(&canonical_json_bytes(&manifest).map_err(ConformanceRunError::Io)?);
        let run_id = format!(
            "conformance-{}",
            &digest_hex(asset_manifest_hash.as_bytes())[..12]
        );

        let mut rng = DeterministicRng::seeded(self.config.seed);
        let mut logs = Vec::with_capacity(resolved.len());
        let mut minimized_repros = Vec::new();
        let mut passed = 0usize;
        let mut failed = 0usize;
        let mut waived = 0usize;
        let errored = 0usize;

        for (idx, asset) in resolved.iter().enumerate() {
            let duration_us = 50 + (rng.next_u64() % 950);
            let trace_id = format!("{}-{}-{idx:04}", self.config.trace_prefix, run_id);
            let decision_id = format!("decision-conformance-{idx:04}");
            let expected_output =
                fs::read_to_string(&asset.expected_output_path).map_err(|source| {
                    ConformanceRunError::ExpectedOutputIo {
                        asset_id: asset.record.asset_id.clone(),
                        path: asset.expected_output_path.clone(),
                        source,
                    }
                })?;
            let fixture_bytes =
                fs::read(&asset.fixture_path).map_err(|source| ConformanceRunError::FixtureIo {
                    asset_id: asset.record.asset_id.clone(),
                    path: asset.fixture_path.clone(),
                    source,
                })?;
            let fixture: DonorFixture = serde_json::from_slice(&fixture_bytes).map_err(|err| {
                ConformanceRunError::InvalidFixture {
                    asset_id: asset.record.asset_id.clone(),
                    source: io::Error::new(io::ErrorKind::InvalidData, err),
                }
            })?;

            let _adapted_source = self.adapter.adapt_source(&fixture.source);
            let actual = canonicalize_conformance_output(&fixture.observed_output);
            let expected = canonicalize_conformance_output(&expected_output);

            let (outcome, error_code, error_detail) = if actual == expected {
                passed += 1;
                ("pass".to_string(), None, None)
            } else if let Some(waiver) = waivers.find_active(
                asset.record.asset_id.as_str(),
                self.config.run_date.as_str(),
            ) {
                waived += 1;
                (
                    "waived".to_string(),
                    Some("FE-CONFORMANCE-WAIVED".to_string()),
                    Some(format!(
                        "waived via {} (tracking {})",
                        waiver.expiry_date, waiver.tracking_bead
                    )),
                )
            } else {
                failed += 1;
                let repro = self.build_minimized_repro_artifact(
                    &run_id,
                    &trace_id,
                    &decision_id,
                    asset,
                    &fixture,
                    &expected,
                );
                repro
                    .verify_replay()
                    .map_err(|err| ConformanceRunError::ReproInvariant {
                        asset_id: asset.record.asset_id.clone(),
                        detail: err.to_string(),
                    })?;
                let failure_id = repro.failure_id.clone();
                minimized_repros.push(repro);
                (
                    "fail".to_string(),
                    Some("FE-CONFORMANCE-MISMATCH".to_string()),
                    Some(format!(
                        "canonicalized output mismatch; minimized repro `{failure_id}` generated"
                    )),
                )
            };

            logs.push(ConformanceLogEvent {
                trace_id,
                decision_id,
                policy_id: self.config.policy_id.clone(),
                component: "conformance_runner".to_string(),
                event: "asset_execution".to_string(),
                outcome,
                error_code,
                asset_id: asset.record.asset_id.clone(),
                semantic_domain: asset.record.semantic_domain.clone(),
                duration_us,
                error_detail,
            });
        }

        let summary = ConformanceRunSummary {
            run_id: run_id.clone(),
            asset_manifest_hash: asset_manifest_hash.clone(),
            total_assets: logs.len(),
            passed,
            failed,
            waived,
            errored,
            env_fingerprint: self.env_fingerprint(),
        };

        Ok(ConformanceRunResult {
            run_id,
            asset_manifest_hash,
            logs,
            summary,
            minimized_repros,
        })
    }

    fn build_minimized_repro_artifact(
        &self,
        run_id: &str,
        trace_id: &str,
        decision_id: &str,
        asset: &ResolvedConformanceAsset,
        fixture: &DonorFixture,
        expected: &str,
    ) -> ConformanceMinimizedReproArtifact {
        let actual = canonicalize_conformance_output(&fixture.observed_output);
        let original_delta = classify_conformance_delta(expected, &actual);
        let original_failure_class = classify_failure_class(&original_delta);

        let minimized =
            minimize_conformance_case(&fixture.source, expected, &actual, original_failure_class);
        let minimized_delta = classify_conformance_delta(
            &minimized.minimized_expected_output,
            &minimized.minimized_actual_output,
        );
        let minimized_failure_class = classify_failure_class(&minimized_delta);
        let severity = severity_for_failure_class(minimized_failure_class);
        let failure_id = build_failure_id(
            asset.record.asset_id.as_str(),
            self.config.seed,
            &minimized.minimized_expected_output,
            &minimized.minimized_actual_output,
        );

        let replay_relative_path = format!("minimized_repros/{failure_id}.json");
        let replay_command = format!("franken-conformance replay {replay_relative_path}");
        let verification_command = format!("{replay_command} --verify");
        let verification_digest = repro_verification_digest(
            self.config.seed,
            &minimized.minimized_expected_output,
            &minimized.minimized_actual_output,
        );

        let mut version_combination = self.config.repro_metadata.version_combination.clone();
        version_combination
            .entry("source_donor".to_string())
            .or_insert_with(|| asset.record.source_donor.clone());
        version_combination
            .entry("manifest_schema".to_string())
            .or_insert_with(|| ConformanceAssetManifest::CURRENT_SCHEMA.to_string());
        version_combination
            .entry("policy_id".to_string())
            .or_insert_with(|| self.config.policy_id.clone());

        let issue_id = self
            .config
            .repro_metadata
            .issue_tracking_bead
            .clone()
            .unwrap_or_else(|| format!("auto/{}/{}", asset.record.asset_id, failure_id));

        ConformanceMinimizedReproArtifact {
            schema_version: ConformanceMinimizedReproArtifact::CURRENT_SCHEMA.to_string(),
            artifact_id: format!("repro-{failure_id}"),
            failure_id: failure_id.clone(),
            boundary_surface: format!(
                "{}/{}",
                asset.record.source_donor, asset.record.semantic_domain
            ),
            failure_class: minimized_failure_class,
            severity,
            version_combination,
            first_seen_commit: self.config.repro_metadata.first_seen_commit.clone(),
            regression_commit: self.config.repro_metadata.regression_commit.clone(),
            environment: ConformanceReproEnvironment {
                locale: self.config.locale.clone(),
                timezone: self.config.timezone.clone(),
                gc_schedule: self.config.gc_schedule.clone(),
                rust_toolchain: std::env::var("RUSTUP_TOOLCHAIN")
                    .unwrap_or_else(|_| "unknown".to_string()),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
            },
            replay: ConformanceReplayContract {
                deterministic_seed: self.config.seed,
                replay_command,
                verification_command,
                verification_digest,
            },
            expected_output: minimized.minimized_expected_output.clone(),
            actual_output: minimized.minimized_actual_output.clone(),
            delta_classification: minimized_delta,
            minimization: ConformanceMinimizationSummary {
                preserved_failure_class: minimized_failure_class == original_failure_class,
                ..minimized.summary
            },
            failing_vector: ConformanceMinimizedFailingVector {
                asset_id: asset.record.asset_id.clone(),
                source_donor: asset.record.source_donor.clone(),
                semantic_domain: asset.record.semantic_domain.clone(),
                normative_reference: asset.record.normative_reference.clone(),
                fixture: DonorFixture {
                    donor_harness: fixture.donor_harness.clone(),
                    source: minimized.minimized_source,
                    observed_output: minimized.minimized_actual_output,
                },
                expected_output: minimized.minimized_expected_output,
            },
            evidence_ledger_id: format!("conformance-ledger/{failure_id}"),
            linked_run: ConformanceRunLinkage {
                run_id: run_id.to_string(),
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                ci_run_id: self.config.repro_metadata.ci_run_id.clone(),
            },
            issue_tracker: ConformanceIssueLink {
                tracker: self.config.repro_metadata.issue_tracker_project.clone(),
                issue_id,
            },
        }
    }

    fn env_fingerprint(&self) -> String {
        let envelope = format!(
            "locale={};timezone={};gc={};seed={}",
            self.config.locale, self.config.timezone, self.config.gc_schedule, self.config.seed
        );
        sha256_hex(envelope.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCollectedArtifacts {
    pub run_manifest_path: PathBuf,
    pub conformance_evidence_path: PathBuf,
    pub minimized_repro_index_path: Option<PathBuf>,
    pub minimized_repro_events_path: Option<PathBuf>,
    pub minimized_repro_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ConformanceEvidenceCollector {
    root: PathBuf,
}

impl ConformanceEvidenceCollector {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn collect(&self, run: &ConformanceRunResult) -> io::Result<ConformanceCollectedArtifacts> {
        let run_root = self.root.join(&run.run_id);
        fs::create_dir_all(&run_root)?;

        let run_manifest_path = run_root.join("run_manifest.json");
        write_atomic(&run_manifest_path, &canonical_json_bytes(&run.summary)?)?;

        let mut evidence_lines = String::new();
        let summary_line = serde_json::to_string(&ConformanceEvidenceSummaryLine {
            run_manifest: "run_manifest.json".to_string(),
            run_id: run.run_id.clone(),
            asset_manifest_hash: run.asset_manifest_hash.clone(),
            pass_count: run.summary.passed,
            fail_count: run.summary.failed,
            waived_count: run.summary.waived,
            error_count: run.summary.errored,
            env_fingerprint: run.summary.env_fingerprint.clone(),
            minimized_repro_count: run.minimized_repros.len(),
        })
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        evidence_lines.push_str(&summary_line);
        evidence_lines.push('\n');

        for event in &run.logs {
            let line = serde_json::to_string(event)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            evidence_lines.push_str(&line);
            evidence_lines.push('\n');
        }

        let conformance_evidence_path = run_root.join("conformance_evidence.jsonl");
        write_atomic(&conformance_evidence_path, evidence_lines.as_bytes())?;

        let mut minimized_repro_paths = Vec::new();
        let mut minimized_repro_index_path = None;
        let mut minimized_repro_events_path = None;

        if !run.minimized_repros.is_empty() {
            let minimized_repro_root = run_root.join("minimized_repros");
            fs::create_dir_all(&minimized_repro_root)?;

            let mut repro_index = ConformanceMinimizedReproIndex {
                schema_version: "franken-engine.conformance-min-repro-index.v1".to_string(),
                run_id: run.run_id.clone(),
                entries: Vec::with_capacity(run.minimized_repros.len()),
            };
            let mut repro_events = String::new();

            for repro in &run.minimized_repros {
                repro
                    .verify_replay()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

                let relative_path = format!("minimized_repros/{}.json", repro.failure_id);
                let path = run_root.join(&relative_path);
                write_atomic(&path, &canonical_json_bytes(repro)?)?;
                minimized_repro_paths.push(path.clone());

                repro_index
                    .entries
                    .push(ConformanceMinimizedReproIndexEntry {
                        failure_id: repro.failure_id.clone(),
                        artifact_id: repro.artifact_id.clone(),
                        artifact_path: relative_path.clone(),
                        evidence_ledger_id: repro.evidence_ledger_id.clone(),
                        replay_command: repro.replay.replay_command.clone(),
                        verification_command: repro.replay.verification_command.clone(),
                        issue_tracker_id: repro.issue_tracker.issue_id.clone(),
                    });

                let policy_id = run
                    .logs
                    .iter()
                    .find(|event| {
                        event.trace_id == repro.linked_run.trace_id
                            && event.decision_id == repro.linked_run.decision_id
                    })
                    .map(|event| event.policy_id.clone())
                    .unwrap_or_else(|| "policy-conformance-v1".to_string());
                let event_line = serde_json::to_string(&ConformanceMinimizedReproEventLine {
                    trace_id: repro.linked_run.trace_id.clone(),
                    decision_id: repro.linked_run.decision_id.clone(),
                    policy_id,
                    component: "conformance_repro_collector".to_string(),
                    event: "minimized_repro_persisted".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                    failure_id: repro.failure_id.clone(),
                    artifact_path: relative_path,
                    issue_tracker_id: repro.issue_tracker.issue_id.clone(),
                })
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                repro_events.push_str(&event_line);
                repro_events.push('\n');
            }

            let index_path = minimized_repro_root.join("index.json");
            write_atomic(&index_path, &canonical_json_bytes(&repro_index)?)?;
            minimized_repro_index_path = Some(index_path);

            let events_path = minimized_repro_root.join("events.jsonl");
            write_atomic(&events_path, repro_events.as_bytes())?;
            minimized_repro_events_path = Some(events_path);
        }

        Ok(ConformanceCollectedArtifacts {
            run_manifest_path,
            conformance_evidence_path,
            minimized_repro_index_path,
            minimized_repro_events_path,
            minimized_repro_paths,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceEvidenceSummaryLine {
    run_manifest: String,
    run_id: String,
    asset_manifest_hash: String,
    pass_count: usize,
    fail_count: usize,
    waived_count: usize,
    error_count: usize,
    env_fingerprint: String,
    minimized_repro_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceMinimizedReproIndex {
    schema_version: String,
    run_id: String,
    entries: Vec<ConformanceMinimizedReproIndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceMinimizedReproIndexEntry {
    failure_id: String,
    artifact_id: String,
    artifact_path: String,
    evidence_ledger_id: String,
    replay_command: String,
    verification_command: String,
    issue_tracker_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceMinimizedReproEventLine {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    failure_id: String,
    artifact_path: String,
    issue_tracker_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConformanceMinimizationOutcome {
    minimized_source: String,
    minimized_expected_output: String,
    minimized_actual_output: String,
    summary: ConformanceMinimizationSummary,
}

fn build_failure_id(asset_id: &str, seed: u64, expected: &str, actual: &str) -> String {
    let material = format!("asset={asset_id};seed={seed};expected={expected};actual={actual}");
    format!("cf-{}", &digest_hex(material.as_bytes())[..16])
}

fn repro_verification_digest(seed: u64, expected: &str, actual: &str) -> String {
    let material = format!("seed={seed};expected={expected};actual={actual}");
    digest_hex(material.as_bytes())
}

pub fn classify_conformance_delta(
    expected: &str,
    actual: &str,
) -> Vec<ConformanceDeltaClassification> {
    let expected = canonicalize_conformance_output(expected);
    let actual = canonicalize_conformance_output(actual);
    if expected == actual {
        return Vec::new();
    }

    let mut deltas = Vec::new();

    if let (Some(expected_props), Some(actual_props)) =
        (parse_props_fields(&expected), parse_props_fields(&actual))
    {
        for removed in expected_props
            .iter()
            .filter(|field| !actual_props.contains(*field))
        {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::SchemaFieldRemoved,
                field: Some(removed.clone()),
                expected: Some("present".to_string()),
                actual: Some("missing".to_string()),
                detail: format!("schema field `{removed}` removed from canonical props output"),
            });
        }
        for added in actual_props
            .iter()
            .filter(|field| !expected_props.contains(*field))
        {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::SchemaFieldAdded,
                field: Some(added.clone()),
                expected: Some("missing".to_string()),
                actual: Some("present".to_string()),
                detail: format!("schema field `{added}` added to canonical props output"),
            });
        }
        if deltas.is_empty() {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::SchemaFieldModified,
                field: None,
                expected: Some(expected.clone()),
                actual: Some(actual.clone()),
                detail: "props schema changed without pure add/remove diff".to_string(),
            });
        }
    }

    if deltas.is_empty() {
        let expected_error = extract_error_signature(&expected);
        let actual_error = extract_error_signature(&actual);
        if expected_error != actual_error {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::ErrorFormatChange,
                field: None,
                expected: expected_error,
                actual: actual_error,
                detail: "error surface format changed".to_string(),
            });
        }
    }

    if deltas.is_empty() && numeric_delta_only(&expected, &actual) {
        deltas.push(ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::TimingChange,
            field: None,
            expected: Some(expected.clone()),
            actual: Some(actual.clone()),
            detail: "numeric-only delta indicates timing/performance shift".to_string(),
        });
    }

    if deltas.is_empty() {
        deltas.push(ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::BehavioralSemanticShift,
            field: None,
            expected: Some(expected),
            actual: Some(actual),
            detail: "canonical output changed in behavioral semantics".to_string(),
        });
    }

    deltas
}

pub fn classify_failure_class(
    deltas: &[ConformanceDeltaClassification],
) -> ConformanceFailureClass {
    if deltas.is_empty() {
        return ConformanceFailureClass::Behavioral;
    }
    let mut resolved = delta_kind_to_failure_class(deltas[0].kind);
    for delta in deltas.iter().skip(1) {
        let candidate = delta_kind_to_failure_class(delta.kind);
        if failure_class_priority(candidate) > failure_class_priority(resolved) {
            resolved = candidate;
        }
    }
    resolved
}

pub fn severity_for_failure_class(class: ConformanceFailureClass) -> ConformanceFailureSeverity {
    match class {
        ConformanceFailureClass::Breaking => ConformanceFailureSeverity::Critical,
        ConformanceFailureClass::Behavioral => ConformanceFailureSeverity::Error,
        ConformanceFailureClass::Observability => ConformanceFailureSeverity::Warning,
        ConformanceFailureClass::Performance => ConformanceFailureSeverity::Warning,
    }
}

fn failure_class_priority(class: ConformanceFailureClass) -> u8 {
    match class {
        ConformanceFailureClass::Breaking => 4,
        ConformanceFailureClass::Behavioral => 3,
        ConformanceFailureClass::Observability => 2,
        ConformanceFailureClass::Performance => 1,
    }
}

fn delta_kind_to_failure_class(kind: ConformanceDeltaKind) -> ConformanceFailureClass {
    match kind {
        ConformanceDeltaKind::SchemaFieldAdded
        | ConformanceDeltaKind::SchemaFieldRemoved
        | ConformanceDeltaKind::SchemaFieldModified => ConformanceFailureClass::Breaking,
        ConformanceDeltaKind::BehavioralSemanticShift => ConformanceFailureClass::Behavioral,
        ConformanceDeltaKind::TimingChange => ConformanceFailureClass::Performance,
        ConformanceDeltaKind::ErrorFormatChange => ConformanceFailureClass::Observability,
    }
}

fn parse_props_fields(payload: &str) -> Option<Vec<String>> {
    for line in payload.lines() {
        if let Some(rest) = line.strip_prefix("props:") {
            let mut values: Vec<String> = rest
                .split(',')
                .map(str::trim)
                .filter(|field| !field.is_empty())
                .map(ToString::to_string)
                .collect();
            values.sort();
            values.dedup();
            return Some(values);
        }
    }
    None
}

fn extract_error_signature(payload: &str) -> Option<String> {
    payload
        .lines()
        .map(str::trim)
        .find(|line| line.contains("Error|"))
        .map(ToString::to_string)
}

fn numeric_delta_only(expected: &str, actual: &str) -> bool {
    let expected_tokens: Vec<&str> = expected.split_whitespace().collect();
    let actual_tokens: Vec<&str> = actual.split_whitespace().collect();
    if expected_tokens.len() != actual_tokens.len() {
        return false;
    }
    let mut saw_numeric_delta = false;
    for (lhs, rhs) in expected_tokens.iter().zip(actual_tokens.iter()) {
        match (lhs.parse::<f64>(), rhs.parse::<f64>()) {
            (Ok(lhs_num), Ok(rhs_num)) => {
                if (lhs_num - rhs_num).abs() > f64::EPSILON {
                    saw_numeric_delta = true;
                }
            }
            (Err(_), Err(_)) => {
                if lhs != rhs {
                    return false;
                }
            }
            _ => return false,
        }
    }
    saw_numeric_delta
}

fn minimize_conformance_case(
    source: &str,
    expected: &str,
    actual: &str,
    failure_class: ConformanceFailureClass,
) -> ConformanceMinimizationOutcome {
    let source_segments = split_source_segments(source);
    let expected_lines = split_output_lines(expected);
    let actual_lines = split_output_lines(actual);

    let minimized_source_segments =
        minimize_source_segments(&source_segments, failure_class, expected, actual);
    let (mut minimized_expected_lines, mut minimized_actual_lines) =
        reduce_output_lines(&expected_lines, &actual_lines, failure_class);
    minimize_lines_greedy(
        &mut minimized_expected_lines,
        &minimized_actual_lines,
        failure_class,
        true,
    );
    minimize_lines_greedy(
        &mut minimized_actual_lines,
        &minimized_expected_lines,
        failure_class,
        false,
    );

    let minimized_source = join_source_segments(&minimized_source_segments);
    let minimized_expected_output =
        canonicalize_conformance_output(&join_output_lines(&minimized_expected_lines));
    let minimized_actual_output =
        canonicalize_conformance_output(&join_output_lines(&minimized_actual_lines));

    let preserved_failure_class = preserves_failure_class(
        &minimized_expected_output,
        &minimized_actual_output,
        failure_class,
    );
    let (minimized_expected_output, minimized_actual_output) = if preserved_failure_class {
        (minimized_expected_output, minimized_actual_output)
    } else {
        (
            canonicalize_conformance_output(expected),
            canonicalize_conformance_output(actual),
        )
    };
    let minimized_source_line_count = split_source_segments(&minimized_source).len();

    ConformanceMinimizationOutcome {
        minimized_source,
        minimized_expected_output: minimized_expected_output.clone(),
        minimized_actual_output: minimized_actual_output.clone(),
        summary: ConformanceMinimizationSummary {
            strategy: "greedy-delta-debugging".to_string(),
            original_source_lines: source_segments.len(),
            minimized_source_lines: minimized_source_line_count,
            original_expected_lines: expected_lines.len(),
            minimized_expected_lines: split_output_lines(&minimized_expected_output).len(),
            original_actual_lines: actual_lines.len(),
            minimized_actual_lines: split_output_lines(&minimized_actual_output).len(),
            preserved_failure_class,
        },
    }
}

fn split_source_segments(source: &str) -> Vec<String> {
    let normalized = source.replace("\r\n", "\n").replace('\r', "\n");
    let mut segments = Vec::new();
    for line in normalized.lines() {
        for segment in line.split(';') {
            let trimmed = segment.trim();
            if !trimmed.is_empty() {
                segments.push(trimmed.to_string());
            }
        }
    }
    if segments.is_empty() {
        vec!["void 0".to_string()]
    } else {
        segments
    }
}

fn join_source_segments(segments: &[String]) -> String {
    segments.join(";\n")
}

fn split_output_lines(payload: &str) -> Vec<String> {
    let canonical = canonicalize_conformance_output(payload);
    let lines: Vec<String> = canonical
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect();
    if lines.is_empty() {
        vec!["<empty>".to_string()]
    } else {
        lines
    }
}

fn join_output_lines(lines: &[String]) -> String {
    lines.join("\n")
}

fn minimize_source_segments(
    original: &[String],
    failure_class: ConformanceFailureClass,
    expected: &str,
    actual: &str,
) -> Vec<String> {
    let mut best = if original.is_empty() {
        vec!["void 0".to_string()]
    } else {
        original.to_vec()
    };
    let mut improved = true;
    while improved && best.len() > 1 {
        improved = false;
        for idx in 0..best.len() {
            if best.len() <= 1 {
                break;
            }
            let candidate: Vec<String> = best
                .iter()
                .enumerate()
                .filter(|(pos, _)| *pos != idx)
                .map(|(_, item)| item.clone())
                .collect();
            if candidate.is_empty() {
                continue;
            }
            if preserves_failure_class(expected, actual, failure_class) {
                best = candidate;
                improved = true;
                break;
            }
        }
    }
    best
}

fn reduce_output_lines(
    expected: &[String],
    actual: &[String],
    failure_class: ConformanceFailureClass,
) -> (Vec<String>, Vec<String>) {
    let mut start = 0usize;
    while start < expected.len() && start < actual.len() && expected[start] == actual[start] {
        start += 1;
    }

    let mut end_expected = expected.len();
    let mut end_actual = actual.len();
    while end_expected > start
        && end_actual > start
        && expected[end_expected - 1] == actual[end_actual - 1]
    {
        end_expected -= 1;
        end_actual -= 1;
    }

    let mut expected_reduced = expected[start..end_expected].to_vec();
    let mut actual_reduced = actual[start..end_actual].to_vec();

    if expected_reduced.is_empty() {
        expected_reduced.push(
            expected
                .first()
                .cloned()
                .unwrap_or_else(|| "<empty>".to_string()),
        );
    }
    if actual_reduced.is_empty() {
        actual_reduced.push(
            actual
                .first()
                .cloned()
                .unwrap_or_else(|| "<empty>".to_string()),
        );
    }

    let expected_payload = join_output_lines(&expected_reduced);
    let actual_payload = join_output_lines(&actual_reduced);
    if !preserves_failure_class(&expected_payload, &actual_payload, failure_class) {
        return (expected.to_vec(), actual.to_vec());
    }

    (expected_reduced, actual_reduced)
}

fn minimize_lines_greedy(
    lines: &mut Vec<String>,
    other: &[String],
    failure_class: ConformanceFailureClass,
    is_expected_side: bool,
) {
    let mut improved = true;
    while improved && lines.len() > 1 {
        improved = false;
        for idx in 0..lines.len() {
            if lines.len() <= 1 {
                break;
            }
            let candidate: Vec<String> = lines
                .iter()
                .enumerate()
                .filter(|(pos, _)| *pos != idx)
                .map(|(_, line)| line.clone())
                .collect();
            if candidate.is_empty() {
                continue;
            }
            let candidate_payload = join_output_lines(&candidate);
            let other_payload = join_output_lines(other);
            let preserved = if is_expected_side {
                preserves_failure_class(&candidate_payload, &other_payload, failure_class)
            } else {
                preserves_failure_class(&other_payload, &candidate_payload, failure_class)
            };
            if preserved {
                *lines = candidate;
                improved = true;
                break;
            }
        }
    }
}

fn preserves_failure_class(
    expected: &str,
    actual: &str,
    failure_class: ConformanceFailureClass,
) -> bool {
    let expected = canonicalize_conformance_output(expected);
    let actual = canonicalize_conformance_output(actual);
    if expected == actual {
        return false;
    }
    classify_failure_class(&classify_conformance_delta(&expected, &actual)) == failure_class
}

pub fn canonicalize_conformance_output(raw: &str) -> String {
    let mut out_lines = Vec::new();

    for line in raw.replace("\r\n", "\n").replace('\r', "\n").lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let normalized = if let Some(rest) = trimmed.strip_prefix("props:") {
            let mut values: Vec<_> = rest
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            values.sort();
            format!("props:{}", values.join(","))
        } else {
            normalize_value_line(trimmed)
        };

        out_lines.push(normalized);
    }

    out_lines.join("\n")
}

fn normalize_value_line(line: &str) -> String {
    let normalized_error = line
        .replace("TypeError: ", "TypeError|")
        .replace("ReferenceError: ", "ReferenceError|")
        .replace("SyntaxError: ", "SyntaxError|");
    let mut out = Vec::new();
    for token in normalized_error.split_whitespace() {
        if let Ok(value) = token.parse::<f64>() {
            out.push(format!("{value:.6}"));
        } else {
            out.push(token.to_string());
        }
    }
    out.join(" ")
}

fn parse_waiver_toml(content: &str) -> io::Result<ConformanceWaiverSet> {
    #[derive(Default)]
    struct RawWaiver {
        asset_id: Option<String>,
        reason_code: Option<String>,
        tracking_bead: Option<String>,
        expiry_date: Option<String>,
    }

    fn parse_quoted(line_no: usize, value: &str) -> io::Result<String> {
        let trimmed = value.trim();
        if trimmed.len() < 2 || !trimmed.starts_with('"') || !trimmed.ends_with('"') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TOML string at line {line_no}"),
            ));
        }
        Ok(trimmed[1..trimmed.len() - 1].to_string())
    }

    fn finalize(raw: RawWaiver, line_no: usize) -> io::Result<ConformanceWaiver> {
        let asset_id = raw.asset_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver is missing asset_id before line {line_no}"),
            )
        })?;
        let reason_code_raw = raw.reason_code.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` is missing reason_code"),
            )
        })?;
        let reason_code = WaiverReasonCode::parse(reason_code_raw.as_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` has unknown reason_code `{reason_code_raw}`"),
            )
        })?;
        let tracking_bead = raw.tracking_bead.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` is missing tracking_bead"),
            )
        })?;
        let expiry_date = raw.expiry_date.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` is missing expiry_date"),
            )
        })?;

        Ok(ConformanceWaiver {
            asset_id,
            reason_code,
            tracking_bead,
            expiry_date,
        })
    }

    let mut waivers = Vec::new();
    let mut current: Option<RawWaiver> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = raw_line.split('#').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }

        if stripped == "[[waiver]]" {
            if let Some(previous) = current.take() {
                waivers.push(finalize(previous, line_no)?);
            }
            current = Some(RawWaiver::default());
            continue;
        }

        let current_mut = current.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("key-value pair before [[waiver]] at line {line_no}"),
            )
        })?;

        let (key, value) = stripped.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid waiver entry at line {line_no}"),
            )
        })?;

        let value = parse_quoted(line_no, value)?;
        match key.trim() {
            "asset_id" => current_mut.asset_id = Some(value),
            "reason_code" => current_mut.reason_code = Some(value),
            "tracking_bead" => current_mut.tracking_bead = Some(value),
            "expiry_date" => current_mut.expiry_date = Some(value),
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown waiver field `{unknown}` at line {line_no}"),
                ));
            }
        }
    }

    if let Some(last) = current.take() {
        waivers.push(finalize(last, content.lines().count() + 1)?);
    }

    Ok(ConformanceWaiverSet { waivers })
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a64(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;

    let mut tmp_name = path.file_name().unwrap_or_default().to_owned();
    tmp_name.push(".tmp");
    let tmp = parent.join(tmp_name);
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
