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
    const PRIME: u64 = 0x0100_0000_01b3;

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

    let mut tmp_name = path.file_name().unwrap_or_default().to_owned();
    tmp_name.push(".tmp");
    let tmp = parent.join(tmp_name);
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── VirtualClock ──────────────────────────────────────────────

    #[test]
    fn virtual_clock_new_and_now() {
        let clock = VirtualClock::new(1000);
        assert_eq!(clock.now_micros(), 1000);
    }

    #[test]
    fn virtual_clock_advance() {
        let mut clock = VirtualClock::new(100);
        clock.advance(50);
        assert_eq!(clock.now_micros(), 150);
    }

    #[test]
    fn virtual_clock_advance_saturating() {
        let mut clock = VirtualClock::new(u64::MAX - 5);
        clock.advance(100);
        assert_eq!(clock.now_micros(), u64::MAX);
    }

    #[test]
    fn virtual_clock_serde_round_trip() {
        let clock = VirtualClock::new(42);
        let json = serde_json::to_string(&clock).unwrap();
        let back: VirtualClock = serde_json::from_str(&json).unwrap();
        assert_eq!(clock, back);
    }

    // ── DeterministicRng ──────────────────────────────────────────

    #[test]
    fn rng_seeded_deterministic() {
        let mut a = DeterministicRng::seeded(123);
        let mut b = DeterministicRng::seeded(123);
        let seq_a: Vec<u64> = (0..10).map(|_| a.next_u64()).collect();
        let seq_b: Vec<u64> = (0..10).map(|_| b.next_u64()).collect();
        assert_eq!(seq_a, seq_b);
    }

    #[test]
    fn rng_different_seeds_differ() {
        let mut a = DeterministicRng::seeded(1);
        let mut b = DeterministicRng::seeded(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn rng_zero_seed_not_stuck() {
        let mut rng = DeterministicRng::seeded(0);
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        assert_ne!(v1, 0);
        assert_ne!(v1, v2);
    }

    #[test]
    fn rng_serde_round_trip() {
        let rng = DeterministicRng::seeded(999);
        let json = serde_json::to_string(&rng).unwrap();
        let back: DeterministicRng = serde_json::from_str(&json).unwrap();
        assert_eq!(rng, back);
    }

    // ── ScenarioStep / ExpectedEvent serde ────────────────────────

    #[test]
    fn scenario_step_defaults() {
        let json = r#"{"component":"c","event":"e"}"#;
        let step: ScenarioStep = serde_json::from_str(json).unwrap();
        assert_eq!(step.advance_micros, 0);
        assert!(step.metadata.is_empty());
    }

    #[test]
    fn expected_event_round_trip() {
        let ev = ExpectedEvent {
            component: "comp".into(),
            event: "evt".into(),
            outcome: "ok".into(),
            error_code: Some("E001".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: ExpectedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // ── TestFixture ───────────────────────────────────────────────

    fn valid_fixture() -> TestFixture {
        TestFixture {
            fixture_id: "fix-001".into(),
            fixture_version: TestFixture::CURRENT_VERSION,
            seed: 42,
            virtual_time_start_micros: 1000,
            policy_id: "policy-A".into(),
            steps: vec![ScenarioStep {
                component: "auth".into(),
                event: "login".into(),
                advance_micros: 100,
                metadata: BTreeMap::new(),
            }],
            expected_events: vec![],
            determinism_check: false,
        }
    }

    #[test]
    fn fixture_validate_valid() {
        assert!(valid_fixture().validate().is_ok());
    }

    #[test]
    fn fixture_validate_missing_fixture_id() {
        let mut f = valid_fixture();
        f.fixture_id = "  ".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingFixtureId)
        ));
    }

    #[test]
    fn fixture_validate_wrong_version() {
        let mut f = valid_fixture();
        f.fixture_version = 99;
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn fixture_validate_missing_policy_id() {
        let mut f = valid_fixture();
        f.policy_id = "".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingPolicyId)
        ));
    }

    #[test]
    fn fixture_validate_missing_steps() {
        let mut f = valid_fixture();
        f.steps.clear();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingSteps)
        ));
    }

    #[test]
    fn fixture_validate_empty_component() {
        let mut f = valid_fixture();
        f.steps[0].component = "".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::InvalidStep { index: 0, .. })
        ));
    }

    #[test]
    fn fixture_validate_empty_event() {
        let mut f = valid_fixture();
        f.steps[0].event = " ".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::InvalidStep { index: 0, .. })
        ));
    }

    #[test]
    fn fixture_serde_round_trip() {
        let f = valid_fixture();
        let json = serde_json::to_string(&f).unwrap();
        let back: TestFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // ── FixtureValidationError Display ────────────────────────────

    #[test]
    fn fixture_error_display_missing_fixture_id() {
        let e = FixtureValidationError::MissingFixtureId;
        assert_eq!(e.to_string(), "fixture_id is required");
    }

    #[test]
    fn fixture_error_display_missing_policy_id() {
        let e = FixtureValidationError::MissingPolicyId;
        assert_eq!(e.to_string(), "policy_id is required");
    }

    #[test]
    fn fixture_error_display_missing_steps() {
        let e = FixtureValidationError::MissingSteps;
        assert_eq!(e.to_string(), "fixture must contain at least one step");
    }

    #[test]
    fn fixture_error_display_unsupported_version() {
        let e = FixtureValidationError::UnsupportedVersion {
            expected: 1,
            actual: 5,
        };
        assert!(e.to_string().contains("expected 1"));
        assert!(e.to_string().contains("got 5"));
    }

    #[test]
    fn fixture_error_display_invalid_step() {
        let e = FixtureValidationError::InvalidStep {
            index: 3,
            reason: "oops".into(),
        };
        assert!(e.to_string().contains("index 3"));
        assert!(e.to_string().contains("oops"));
    }

    // ── DeterministicRunner ───────────────────────────────────────

    #[test]
    fn runner_default_config() {
        let cfg = DeterministicRunnerConfig::default();
        assert_eq!(cfg.trace_prefix, "trace");
    }

    #[test]
    fn runner_run_fixture_basic() {
        let runner = DeterministicRunner::default();
        let fixture = valid_fixture();
        let result = runner.run_fixture(&fixture).unwrap();
        assert_eq!(result.fixture_id, "fix-001");
        assert_eq!(result.seed, 42);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.random_transcript.len(), 1);
        assert_eq!(result.start_virtual_time_micros, 1000);
        assert_eq!(result.end_virtual_time_micros, 1100);
    }

    #[test]
    fn runner_run_fixture_deterministic() {
        let runner = DeterministicRunner::default();
        let fixture = valid_fixture();
        let r1 = runner.run_fixture(&fixture).unwrap();
        let r2 = runner.run_fixture(&fixture).unwrap();
        assert_eq!(r1.output_digest, r2.output_digest);
        assert_eq!(r1.events, r2.events);
        assert_eq!(r1.random_transcript, r2.random_transcript);
    }

    #[test]
    fn runner_run_fixture_rejects_invalid() {
        let runner = DeterministicRunner::default();
        let mut f = valid_fixture();
        f.steps.clear();
        assert!(runner.run_fixture(&f).is_err());
    }

    #[test]
    fn runner_event_has_trace_prefix() {
        let runner = DeterministicRunner {
            config: DeterministicRunnerConfig {
                trace_prefix: "custom".into(),
            },
        };
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        assert!(result.events[0].trace_id.starts_with("custom-"));
    }

    #[test]
    fn runner_error_code_propagation() {
        let mut f = valid_fixture();
        let mut meta = BTreeMap::new();
        meta.insert("error_code".into(), "E_TEST".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        assert_eq!(result.events[0].outcome, "error");
        assert_eq!(result.events[0].error_code.as_deref(), Some("E_TEST"));
    }

    #[test]
    fn runner_custom_outcome() {
        let mut f = valid_fixture();
        let mut meta = BTreeMap::new();
        meta.insert("outcome".into(), "warn".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        assert_eq!(result.events[0].outcome, "warn");
    }

    #[test]
    fn runner_multiple_steps_time_advances() {
        let mut f = valid_fixture();
        f.steps.push(ScenarioStep {
            component: "db".into(),
            event: "query".into(),
            advance_micros: 200,
            metadata: BTreeMap::new(),
        });
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].virtual_time_micros, 1100);
        assert_eq!(result.events[1].virtual_time_micros, 1300);
        assert_eq!(result.events[0].sequence, 0);
        assert_eq!(result.events[1].sequence, 1);
    }

    // ── assert_structured_logs ────────────────────────────────────

    #[test]
    fn assert_logs_all_match() {
        let events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        let expectations = vec![LogExpectation {
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
        }];
        assert!(assert_structured_logs(&events, &expectations).is_ok());
    }

    #[test]
    fn assert_logs_missing() {
        let events = vec![];
        let expectations = vec![LogExpectation {
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
        }];
        let err = assert_structured_logs(&events, &expectations).unwrap_err();
        assert_eq!(err.missing.len(), 1);
        assert!(err.to_string().contains("1"));
    }

    #[test]
    fn assert_logs_empty_expectations_pass() {
        let events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        assert!(assert_structured_logs(&events, &[]).is_ok());
    }

    #[test]
    fn assert_logs_error_code_mismatch() {
        let events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        let expectations = vec![LogExpectation {
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: Some("E001".into()),
        }];
        assert!(assert_structured_logs(&events, &expectations).is_err());
    }

    // ── verify_replay ─────────────────────────────────────────────

    fn make_run_result(digest: &str, seed: u64) -> RunResult {
        RunResult {
            fixture_id: "fix-1".into(),
            run_id: "run-1".into(),
            seed,
            start_virtual_time_micros: 0,
            end_virtual_time_micros: 100,
            random_transcript: vec![seed],
            events: vec![],
            output_digest: digest.into(),
        }
    }

    #[test]
    fn replay_matches() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("abc", 1);
        let v = verify_replay(&a, &b);
        assert!(v.matches);
        assert!(v.reason.is_none());
    }

    #[test]
    fn replay_digest_mismatch() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("xyz", 1);
        let v = verify_replay(&a, &b);
        assert!(!v.matches);
        assert_eq!(v.reason.as_deref(), Some("digest mismatch"));
    }

    #[test]
    fn replay_transcript_mismatch() {
        let a = make_run_result("abc", 1);
        let mut b = make_run_result("abc", 1);
        b.random_transcript = vec![999];
        let v = verify_replay(&a, &b);
        assert!(!v.matches);
        assert_eq!(v.reason.as_deref(), Some("random transcript mismatch"));
    }

    // ── compare_counterfactual ────────────────────────────────────

    #[test]
    fn counterfactual_identical_runs() {
        let runner = DeterministicRunner::default();
        let fixture = valid_fixture();
        let a = runner.run_fixture(&fixture).unwrap();
        let b = runner.run_fixture(&fixture).unwrap();
        let delta = compare_counterfactual(&a, &b);
        assert!(!delta.digest_changed);
        assert_eq!(delta.changed_events, 0);
        assert_eq!(delta.changed_outcomes, 0);
        assert!(delta.diverged_at_sequence.is_none());
    }

    #[test]
    fn counterfactual_different_seeds() {
        let runner = DeterministicRunner::default();
        let f1 = valid_fixture();
        let mut f2 = valid_fixture();
        f2.seed = 999;
        f2.fixture_id = "fix-002".into();
        let a = runner.run_fixture(&f1).unwrap();
        let b = runner.run_fixture(&f2).unwrap();
        let delta = compare_counterfactual(&a, &b);
        assert!(delta.digest_changed);
    }

    #[test]
    fn counterfactual_different_event_lengths() {
        let mut a = make_run_result("a", 1);
        a.events.push(HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        });
        let b = make_run_result("b", 1);
        let delta = compare_counterfactual(&a, &b);
        assert_eq!(delta.changed_events, 1);
        assert_eq!(delta.diverged_at_sequence, Some(0));
    }

    #[test]
    fn counterfactual_outcome_diff() {
        let mut a = make_run_result("a", 1);
        let mut b = make_run_result("b", 1);
        let evt = HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        };
        a.events.push(evt.clone());
        let mut evt2 = evt;
        evt2.outcome = "fail".into();
        b.events.push(evt2);
        let delta = compare_counterfactual(&a, &b);
        assert_eq!(delta.changed_outcomes, 1);
    }

    // ── RunReport ─────────────────────────────────────────────────

    #[test]
    fn run_report_from_result_pass() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let report = RunReport::from_result(&result);
        assert!(report.pass);
        assert_eq!(report.event_count, 1);
        assert!(report.first_error_code.is_none());
    }

    #[test]
    fn run_report_from_result_with_error() {
        let mut f = valid_fixture();
        let mut meta = BTreeMap::new();
        meta.insert("error_code".into(), "E_BOOM".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        let report = RunReport::from_result(&result);
        assert!(!report.pass);
        assert_eq!(report.first_error_code.as_deref(), Some("E_BOOM"));
    }

    #[test]
    fn run_report_to_markdown_contains_status() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let report = RunReport::from_result(&result);
        let md = report.to_markdown();
        assert!(md.contains("status: `pass`"));
        assert!(md.contains("# E2E Run Report"));
    }

    #[test]
    fn run_report_serde_round_trip() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let report = RunReport::from_result(&result);
        let json = serde_json::to_string(&report).unwrap();
        let back: RunReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // ── RunManifest / GoldenBaseline / SignedGoldenUpdate serde ───

    #[test]
    fn run_manifest_serde_round_trip() {
        let m = RunManifest {
            fixture_id: "f".into(),
            run_id: "r".into(),
            seed: 10,
            event_count: 5,
            output_digest: "abc".into(),
            replay_pointer: "replay://r".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: RunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn golden_baseline_serde_round_trip() {
        let g = GoldenBaseline {
            fixture_id: "f".into(),
            output_digest: "d".into(),
            source_run_id: "r".into(),
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: GoldenBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn signed_golden_update_serde_round_trip() {
        let u = SignedGoldenUpdate {
            update_id: "u".into(),
            fixture_id: "f".into(),
            previous_digest: "p".into(),
            next_digest: "n".into(),
            source_run_id: "r".into(),
            signer: "bob".into(),
            signature: "sig".into(),
            rationale: "reason".into(),
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: SignedGoldenUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }

    // ── ReplayVerification serde ──────────────────────────────────

    #[test]
    fn replay_verification_serde_round_trip() {
        let v = ReplayVerification {
            matches: true,
            expected_digest: "e".into(),
            actual_digest: "a".into(),
            reason: None,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ReplayVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // ── CounterfactualDelta serde ─────────────────────────────────

    #[test]
    fn counterfactual_delta_serde_round_trip() {
        let d = CounterfactualDelta {
            baseline_run_id: "b".into(),
            counterfactual_run_id: "c".into(),
            digest_changed: true,
            diverged_at_sequence: Some(3),
            changed_events: 5,
            changed_outcomes: 2,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: CounterfactualDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // ── GoldenVerificationError Display ───────────────────────────

    #[test]
    fn golden_error_display_missing() {
        let e = GoldenVerificationError::MissingBaseline {
            fixture_id: "fix-1".into(),
        };
        assert!(e.to_string().contains("fix-1"));
    }

    #[test]
    fn golden_error_display_invalid() {
        let inner = io::Error::other("bad");
        let e = GoldenVerificationError::InvalidBaseline(inner);
        assert!(e.to_string().contains("invalid golden baseline"));
        assert!(e.source().is_some());
    }

    #[test]
    fn golden_error_display_mismatch() {
        let e = GoldenVerificationError::DigestMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        assert!(e.to_string().contains("aaa"));
        assert!(e.to_string().contains("bbb"));
    }

    // ── fnv1a64 ───────────────────────────────────────────────────

    #[test]
    fn fnv1a64_deterministic() {
        let a = fnv1a64(b"hello");
        let b = fnv1a64(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn fnv1a64_different_inputs() {
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
    }

    #[test]
    fn fnv1a64_empty() {
        let h = fnv1a64(b"");
        // FNV-1a offset basis
        assert_eq!(h, 0xcbf2_9ce4_8422_2325);
    }

    // ── digest_hex ────────────────────────────────────────────────

    #[test]
    fn digest_hex_deterministic() {
        let a = digest_hex(b"test");
        let b = digest_hex(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn digest_hex_length() {
        let h = digest_hex(b"test");
        assert_eq!(h.len(), 16); // 16 hex chars for u64
    }

    // ── sanitize_label ────────────────────────────────────────────

    #[test]
    fn sanitize_label_alphanumeric_passthrough() {
        assert_eq!(sanitize_label("hello-world_123"), "hello-world_123");
    }

    #[test]
    fn sanitize_label_replaces_special() {
        assert_eq!(sanitize_label("a/b:c d"), "a-b-c-d");
    }

    #[test]
    fn sanitize_label_empty() {
        assert_eq!(sanitize_label(""), "");
    }

    // ── HarnessEvent serde ────────────────────────────────────────

    #[test]
    fn harness_event_serde_round_trip() {
        let ev = HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: Some("E001".into()),
            sequence: 7,
            virtual_time_micros: 42,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: HarnessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // ── RunResult serde ───────────────────────────────────────────

    #[test]
    fn run_result_serde_round_trip() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: RunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // ── digest_run ────────────────────────────────────────────────

    #[test]
    fn digest_run_deterministic() {
        let a = digest_run("fix", 1, &[10, 20], &[]);
        let b = digest_run("fix", 1, &[10, 20], &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_run_changes_with_seed() {
        let a = digest_run("fix", 1, &[10], &[]);
        let b = digest_run("fix", 2, &[10], &[]);
        assert_ne!(a, b);
    }

    // ── LogAssertionError Display ─────────────────────────────────

    #[test]
    fn log_assertion_error_display() {
        let e = LogAssertionError {
            missing: vec![
                LogExpectation {
                    component: "a".into(),
                    event: "b".into(),
                    outcome: "c".into(),
                    error_code: None,
                },
                LogExpectation {
                    component: "d".into(),
                    event: "e".into(),
                    outcome: "f".into(),
                    error_code: None,
                },
            ],
        };
        assert!(e.to_string().contains("2"));
    }

    // ── FixtureStore / GoldenStore / ArtifactCollector with tmpdir

    #[test]
    fn fixture_store_save_and_load() {
        let dir = std::env::temp_dir().join(format!("e2e_test_fixture_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = FixtureStore::new(&dir).unwrap();
        let fixture = valid_fixture();
        let path = store.save_fixture(&fixture).unwrap();
        assert!(path.exists());
        let loaded = store.load_fixture(&path).unwrap();
        assert_eq!(fixture, loaded);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fixture_store_rejects_invalid_fixture() {
        let dir = std::env::temp_dir().join(format!("e2e_test_invalid_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = FixtureStore::new(&dir).unwrap();
        let mut f = valid_fixture();
        f.steps.clear();
        assert!(store.save_fixture(&f).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_write_and_verify() {
        let dir = std::env::temp_dir().join(format!("e2e_test_golden_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        assert!(store.verify_run(&result).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_verify_missing_baseline() {
        let dir = std::env::temp_dir().join(format!("e2e_test_no_bl_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let result = make_run_result("abc", 1);
        let err = store.verify_run(&result).unwrap_err();
        assert!(matches!(
            err,
            GoldenVerificationError::MissingBaseline { .. }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_verify_digest_mismatch() {
        let dir = std::env::temp_dir().join(format!("e2e_test_mismatch_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        let mut altered = result.clone();
        altered.output_digest = "tampered".into();
        let err = store.verify_run(&altered).unwrap_err();
        assert!(matches!(
            err,
            GoldenVerificationError::DigestMismatch { .. }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_signed_update() {
        let dir = std::env::temp_dir().join(format!("e2e_test_signed_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        let path = store
            .write_signed_update(&result, "alice", "sig123", "intentional update")
            .unwrap();
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_signed_update_empty_signer() {
        let dir = std::env::temp_dir().join(format!("e2e_test_nosig_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        assert!(
            store
                .write_signed_update(&result, " ", "sig", "reason")
                .is_err()
        );
        assert!(
            store
                .write_signed_update(&result, "alice", "", "reason")
                .is_err()
        );
        assert!(
            store
                .write_signed_update(&result, "alice", "sig", "  ")
                .is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn artifact_collector_collect() {
        let dir = std::env::temp_dir().join(format!("e2e_test_artifacts_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let collector = ArtifactCollector::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let artifacts = collector.collect(&result).unwrap();
        assert!(artifacts.manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.report_json_path.exists());
        assert!(artifacts.report_markdown_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
