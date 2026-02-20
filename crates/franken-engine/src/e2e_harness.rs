// Allow dead code: this is test infrastructure; not all items are used yet.
#![allow(dead_code)]
//! Deterministic E2E harness substrate for FrankenEngine.
//!
//! This module provides:
//! - deterministic runner (seeded randomness + virtual time)
//! - fixture store (content-addressed JSON fixtures)
//! - structured log assertions
//! - artifact collection (manifest + JSONL events + JSON/Markdown reports)
//! - replay verification (digest + event equality)

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Minimal virtual clock for deterministic tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClock {
    now_micros: u64,
}

impl VirtualClock {
    /// Creates a clock pinned to a deterministic start instant.
    pub fn new(now_micros: u64) -> Self {
        Self { now_micros }
    }

    /// Returns the current virtual timestamp in microseconds.
    pub fn now_micros(self) -> u64 {
        self.now_micros
    }

    /// Advances the clock by a deterministic delta.
    pub fn advance(&mut self, delta_micros: u64) {
        self.now_micros = self.now_micros.saturating_add(delta_micros);
    }
}

/// XorShift-based deterministic RNG suitable for reproducible tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn seeded(seed: u64) -> Self {
        // Avoid all-zero xorshift state.
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

/// One deterministic step in an E2E fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioStep {
    pub component: String,
    pub event: String,
    #[serde(default)]
    pub advance_micros: u64,
    /// Optional knobs used to force deterministic error/outcome classes.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Expected event shape for log assertions and replay baselines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedEvent {
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default)]
    pub error_code: Option<String>,
}

/// Versioned fixture contract for deterministic E2E runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestFixture {
    pub fixture_id: String,
    pub fixture_version: u32,
    pub seed: u64,
    pub virtual_time_start_micros: u64,
    pub policy_id: String,
    pub steps: Vec<ScenarioStep>,
    #[serde(default)]
    pub expected_events: Vec<ExpectedEvent>,
    #[serde(default)]
    pub determinism_check: bool,
}

impl TestFixture {
    pub const CURRENT_VERSION: u32 = 1;

    pub fn validate(&self) -> Result<(), FixtureValidationError> {
        if self.fixture_id.trim().is_empty() {
            return Err(FixtureValidationError::MissingFixtureId);
        }
        if self.fixture_version != Self::CURRENT_VERSION {
            return Err(FixtureValidationError::UnsupportedVersion {
                expected: Self::CURRENT_VERSION,
                actual: self.fixture_version,
            });
        }
        if self.policy_id.trim().is_empty() {
            return Err(FixtureValidationError::MissingPolicyId);
        }
        if self.steps.is_empty() {
            return Err(FixtureValidationError::MissingSteps);
        }
        for (idx, step) in self.steps.iter().enumerate() {
            if step.component.trim().is_empty() {
                return Err(FixtureValidationError::InvalidStep {
                    index: idx,
                    reason: "component is empty".to_string(),
                });
            }
            if step.event.trim().is_empty() {
                return Err(FixtureValidationError::InvalidStep {
                    index: idx,
                    reason: "event is empty".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Structured event emitted by deterministic harness execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub sequence: u64,
    pub virtual_time_micros: u64,
}

/// Replayable run output for a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResult {
    pub fixture_id: String,
    pub run_id: String,
    pub seed: u64,
    pub start_virtual_time_micros: u64,
    pub end_virtual_time_micros: u64,
    pub random_transcript: Vec<u64>,
    pub events: Vec<HarnessEvent>,
    pub output_digest: String,
}

/// Deterministic runner configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRunnerConfig {
    pub trace_prefix: String,
}

impl Default for DeterministicRunnerConfig {
    fn default() -> Self {
        Self {
            trace_prefix: "trace".to_string(),
        }
    }
}

/// Deterministic test runner.
#[derive(Debug, Clone, Default)]
pub struct DeterministicRunner {
    pub config: DeterministicRunnerConfig,
}

impl DeterministicRunner {
    pub fn run_fixture(&self, fixture: &TestFixture) -> Result<RunResult, FixtureValidationError> {
        fixture.validate()?;

        let mut clock = VirtualClock::new(fixture.virtual_time_start_micros);
        let mut rng = DeterministicRng::seeded(fixture.seed);
        let trace_id = format!("{}-{}", self.config.trace_prefix, fixture.fixture_id);

        let mut random_transcript = Vec::with_capacity(fixture.steps.len());
        let mut events = Vec::with_capacity(fixture.steps.len());

        for (idx, step) in fixture.steps.iter().enumerate() {
            clock.advance(step.advance_micros);
            let sample = rng.next_u64();
            random_transcript.push(sample);

            let error_code = step.metadata.get("error_code").cloned();
            let outcome = if error_code.is_some() {
                "error".to_string()
            } else {
                step.metadata
                    .get("outcome")
                    .cloned()
                    .unwrap_or_else(|| "ok".to_string())
            };

            events.push(HarnessEvent {
                trace_id: trace_id.clone(),
                decision_id: format!("decision-{:04}", idx),
                policy_id: fixture.policy_id.clone(),
                component: step.component.clone(),
                event: step.event.clone(),
                outcome,
                error_code,
                sequence: idx as u64,
                virtual_time_micros: clock.now_micros(),
            });
        }

        let digest = digest_run(
            &fixture.fixture_id,
            fixture.seed,
            &random_transcript,
            &events,
        );
        let run_id = format!(
            "run-{}-{}",
            sanitize_label(&fixture.fixture_id),
            &digest[..12.min(digest.len())]
        );

        Ok(RunResult {
            fixture_id: fixture.fixture_id.clone(),
            run_id,
            seed: fixture.seed,
            start_virtual_time_micros: fixture.virtual_time_start_micros,
            end_virtual_time_micros: clock.now_micros(),
            random_transcript,
            events,
            output_digest: digest,
        })
    }
}

/// Fixture-validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureValidationError {
    MissingFixtureId,
    MissingPolicyId,
    MissingSteps,
    UnsupportedVersion { expected: u32, actual: u32 },
    InvalidStep { index: usize, reason: String },
}

impl fmt::Display for FixtureValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFixtureId => write!(f, "fixture_id is required"),
            Self::MissingPolicyId => write!(f, "policy_id is required"),
            Self::MissingSteps => write!(f, "fixture must contain at least one step"),
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported fixture version: expected {expected}, got {actual}"
                )
            }
            Self::InvalidStep { index, reason } => {
                write!(f, "invalid step at index {index}: {reason}")
            }
        }
    }
}

impl Error for FixtureValidationError {}

/// Content-addressed fixture store.
#[derive(Debug, Clone)]
pub struct FixtureStore {
    root: PathBuf,
}

impl FixtureStore {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn save_fixture(&self, fixture: &TestFixture) -> io::Result<PathBuf> {
        fixture
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let payload = canonical_json_bytes(fixture)?;
        let digest = digest_hex(&payload);
        let filename = format!(
            "{}-{}.json",
            sanitize_label(&fixture.fixture_id),
            &digest[..16]
        );
        let path = self.root.join(filename);
        write_atomic(&path, &payload)?;
        Ok(path)
    }

    pub fn load_fixture(&self, path: impl AsRef<Path>) -> io::Result<TestFixture> {
        let bytes = fs::read(path.as_ref())?;
        let fixture: TestFixture = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fixture
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(fixture)
    }
}

/// Structured log expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogExpectation {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Log-assertion mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogAssertionError {
    pub missing: Vec<LogExpectation>,
}

impl fmt::Display for LogAssertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing {} expected log events", self.missing.len())
    }
}

impl Error for LogAssertionError {}

/// Validates that each expected structured log event has a matching emission.
pub fn assert_structured_logs(
    events: &[HarnessEvent],
    expectations: &[LogExpectation],
) -> Result<(), LogAssertionError> {
    let mut missing = Vec::new();
    for expected in expectations {
        let found = events.iter().any(|actual| {
            actual.component == expected.component
                && actual.event == expected.event
                && actual.outcome == expected.outcome
                && actual.error_code == expected.error_code
        });
        if !found {
            missing.push(expected.clone());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LogAssertionError { missing })
    }
}

/// Replay-verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayVerification {
    pub matches: bool,
    pub expected_digest: String,
    pub actual_digest: String,
    pub reason: Option<String>,
}

/// Verifies deterministic replay equivalence between two run outputs.
pub fn verify_replay(expected: &RunResult, actual: &RunResult) -> ReplayVerification {
    let digest_matches = expected.output_digest == actual.output_digest;
    let events_match = expected.events == actual.events;
    let transcript_matches = expected.random_transcript == actual.random_transcript;
    let matches = digest_matches && events_match && transcript_matches;

    let reason = if matches {
        None
    } else if !digest_matches {
        Some("digest mismatch".to_string())
    } else if !events_match {
        Some("event stream mismatch".to_string())
    } else {
        Some("random transcript mismatch".to_string())
    };

    ReplayVerification {
        matches,
        expected_digest: expected.output_digest.clone(),
        actual_digest: actual.output_digest.clone(),
        reason,
    }
}

/// Counterfactual replay delta summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualDelta {
    pub baseline_run_id: String,
    pub counterfactual_run_id: String,
    pub digest_changed: bool,
    pub diverged_at_sequence: Option<u64>,
    pub changed_events: usize,
    pub changed_outcomes: usize,
}

/// Compares baseline and counterfactual runs and summarizes divergences.
pub fn compare_counterfactual(
    baseline: &RunResult,
    counterfactual: &RunResult,
) -> CounterfactualDelta {
    let mut diverged_at_sequence = None;
    let mut changed_events = 0usize;
    let mut changed_outcomes = 0usize;

    let max_len = baseline.events.len().max(counterfactual.events.len());
    for idx in 0..max_len {
        let base = baseline.events.get(idx);
        let alt = counterfactual.events.get(idx);
        if base != alt {
            changed_events += 1;
            if diverged_at_sequence.is_none() {
                diverged_at_sequence = Some(idx as u64);
            }
        }

        if let (Some(base_event), Some(alt_event)) = (base, alt)
            && (base_event.outcome != alt_event.outcome
                || base_event.error_code != alt_event.error_code)
        {
            changed_outcomes += 1;
        }
    }

    CounterfactualDelta {
        baseline_run_id: baseline.run_id.clone(),
        counterfactual_run_id: counterfactual.run_id.clone(),
        digest_changed: baseline.output_digest != counterfactual.output_digest,
        diverged_at_sequence,
        changed_events,
        changed_outcomes,
    }
}

/// Persisted golden digest for a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenBaseline {
    pub fixture_id: String,
    pub output_digest: String,
    pub source_run_id: String,
}

/// Signed artifact documenting an intentional golden update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGoldenUpdate {
    pub update_id: String,
    pub fixture_id: String,
    pub previous_digest: String,
    pub next_digest: String,
    pub source_run_id: String,
    pub signer: String,
    pub signature: String,
    pub rationale: String,
}

/// Golden verification failures.
#[derive(Debug)]
pub enum GoldenVerificationError {
    MissingBaseline { fixture_id: String },
    InvalidBaseline(io::Error),
    DigestMismatch { expected: String, actual: String },
}

impl fmt::Display for GoldenVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBaseline { fixture_id } => {
                write!(f, "missing golden baseline for fixture `{fixture_id}`")
            }
            Self::InvalidBaseline(err) => write!(f, "invalid golden baseline: {err}"),
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "golden digest mismatch: expected `{expected}`, got `{actual}`"
                )
            }
        }
    }
}

impl Error for GoldenVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBaseline(err) => Some(err),
            _ => None,
        }
    }
}

/// Content-addressed golden output store with signed update artifacts.
#[derive(Debug, Clone)]
pub struct GoldenStore {
    root: PathBuf,
}

impl GoldenStore {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("baselines"))?;
        fs::create_dir_all(root.join("updates"))?;
        Ok(Self { root })
    }

    pub fn write_baseline(&self, result: &RunResult) -> io::Result<PathBuf> {
        let baseline = GoldenBaseline {
            fixture_id: result.fixture_id.clone(),
            output_digest: result.output_digest.clone(),
            source_run_id: result.run_id.clone(),
        };
        let path = self.baseline_path(&result.fixture_id);
        write_atomic(&path, &canonical_json_bytes(&baseline)?)?;
        Ok(path)
    }

    pub fn verify_run(&self, result: &RunResult) -> Result<(), GoldenVerificationError> {
        let path = self.baseline_path(&result.fixture_id);
        if !path.exists() {
            return Err(GoldenVerificationError::MissingBaseline {
                fixture_id: result.fixture_id.clone(),
            });
        }

        let bytes = fs::read(path).map_err(GoldenVerificationError::InvalidBaseline)?;
        let baseline: GoldenBaseline = serde_json::from_slice(&bytes).map_err(|err| {
            GoldenVerificationError::InvalidBaseline(io::Error::new(
                io::ErrorKind::InvalidData,
                err,
            ))
        })?;

        if baseline.output_digest != result.output_digest {
            return Err(GoldenVerificationError::DigestMismatch {
                expected: baseline.output_digest,
                actual: result.output_digest.clone(),
            });
        }
        Ok(())
    }

    pub fn write_signed_update(
        &self,
        result: &RunResult,
        signer: &str,
        signature: &str,
        rationale: &str,
    ) -> io::Result<PathBuf> {
        if signer.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "signer is required",
            ));
        }
        if signature.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "signature is required",
            ));
        }
        if rationale.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rationale is required",
            ));
        }

        let baseline = self.load_baseline(&result.fixture_id)?;
        let update_id = digest_hex(
            format!(
                "{}:{}:{}:{}:{}:{}",
                result.fixture_id,
                baseline.output_digest,
                result.output_digest,
                signer.trim(),
                signature.trim(),
                rationale.trim()
            )
            .as_bytes(),
        );

        let update = SignedGoldenUpdate {
            update_id: update_id.clone(),
            fixture_id: result.fixture_id.clone(),
            previous_digest: baseline.output_digest,
            next_digest: result.output_digest.clone(),
            source_run_id: result.run_id.clone(),
            signer: signer.trim().to_string(),
            signature: signature.trim().to_string(),
            rationale: rationale.trim().to_string(),
        };

        let path = self.root.join("updates").join(format!(
            "{}-{update_id}.json",
            sanitize_label(&result.fixture_id)
        ));
        write_atomic(&path, &canonical_json_bytes(&update)?)?;
        Ok(path)
    }

    fn load_baseline(&self, fixture_id: &str) -> io::Result<GoldenBaseline> {
        let path = self.baseline_path(fixture_id);
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    fn baseline_path(&self, fixture_id: &str) -> PathBuf {
        self.root
            .join("baselines")
            .join(format!("{}.json", sanitize_label(fixture_id)))
    }
}

/// Machine-readable run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    pub fixture_id: String,
    pub run_id: String,
    pub seed: u64,
    pub event_count: usize,
    pub output_digest: String,
    pub replay_pointer: String,
}

/// Human/machine report summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    pub fixture_id: String,
    pub run_id: String,
    pub pass: bool,
    pub event_count: usize,
    pub output_digest: String,
    pub first_error_code: Option<String>,
}

impl RunReport {
    pub fn from_result(result: &RunResult) -> Self {
        let first_error_code = result
            .events
            .iter()
            .find_map(|event| event.error_code.clone());
        Self {
            fixture_id: result.fixture_id.clone(),
            run_id: result.run_id.clone(),
            pass: first_error_code.is_none(),
            event_count: result.events.len(),
            output_digest: result.output_digest.clone(),
            first_error_code,
        }
    }

    pub fn to_markdown(&self) -> String {
        let status = if self.pass { "pass" } else { "fail" };
        let first_error = self.first_error_code.as_deref().unwrap_or("none");
        format!(
            "# E2E Run Report\n\n- fixture_id: `{}`\n- run_id: `{}`\n- status: `{}`\n- event_count: `{}`\n- output_digest: `{}`\n- first_error_code: `{}`\n",
            self.fixture_id, self.run_id, status, self.event_count, self.output_digest, first_error
        )
    }
}

/// Paths to collected run artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedArtifacts {
    pub manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub report_json_path: PathBuf,
    pub report_markdown_path: PathBuf,
}

/// Collects deterministic artifacts for a test run.
#[derive(Debug, Clone)]
pub struct ArtifactCollector {
    root: PathBuf,
}

impl ArtifactCollector {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn collect(&self, result: &RunResult) -> io::Result<CollectedArtifacts> {
        let run_root = self.root.join(&result.run_id);
        fs::create_dir_all(&run_root)?;

        let manifest = RunManifest {
            fixture_id: result.fixture_id.clone(),
            run_id: result.run_id.clone(),
            seed: result.seed,
            event_count: result.events.len(),
            output_digest: result.output_digest.clone(),
            replay_pointer: format!("replay://{}", result.run_id),
        };
        let report = RunReport::from_result(result);

        let manifest_path = run_root.join("manifest.json");
        let events_path = run_root.join("events.jsonl");
        let report_json_path = run_root.join("report.json");
        let report_markdown_path = run_root.join("report.md");

        write_atomic(&manifest_path, &canonical_json_bytes(&manifest)?)?;

        let mut jsonl = String::new();
        for event in &result.events {
            let line = serde_json::to_string(event)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            jsonl.push_str(&line);
            jsonl.push('\n');
        }
        write_atomic(&events_path, jsonl.as_bytes())?;

        write_atomic(&report_json_path, &canonical_json_bytes(&report)?)?;
        write_atomic(&report_markdown_path, report.to_markdown().as_bytes())?;

        Ok(CollectedArtifacts {
            manifest_path,
            events_path,
            report_json_path,
            report_markdown_path,
        })
    }
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn digest_run(
    fixture_id: &str,
    seed: u64,
    random_transcript: &[u64],
    events: &[HarnessEvent],
) -> String {
    #[derive(Serialize)]
    struct DigestEnvelope<'a> {
        fixture_id: &'a str,
        seed: u64,
        random_transcript: &'a [u64],
        events: &'a [HarnessEvent],
    }

    match serde_json::to_vec(&DigestEnvelope {
        fixture_id,
        seed,
        random_transcript,
        events,
    }) {
        Ok(bytes) => digest_hex(&bytes),
        Err(_) => "digest-error".to_string(),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a64(bytes))
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

fn sanitize_label(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    out
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
