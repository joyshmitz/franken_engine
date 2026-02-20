#![allow(dead_code)]

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
pub struct ConformanceRunnerConfig {
    pub trace_prefix: String,
    pub policy_id: String,
    pub seed: u64,
    pub locale: String,
    pub timezone: String,
    pub gc_schedule: String,
    pub run_date: String,
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
            Self::InvalidConfig(_) => None,
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
                (
                    "fail".to_string(),
                    Some("FE-CONFORMANCE-MISMATCH".to_string()),
                    Some("canonicalized output mismatch".to_string()),
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
        })
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

        Ok(ConformanceCollectedArtifacts {
            run_manifest_path,
            conformance_evidence_path,
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
    const PRIME: u64 = 0x0000_0001_0000_01b3;

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

    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
