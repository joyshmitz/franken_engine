//! Deterministic RGC test harness utilities shared across unit and integration lanes.
//!
//! This module provides:
//! - deterministic run context identifiers (trace/decision/policy IDs),
//! - fixture loading with path-traversal protection,
//! - structured test log event envelopes with stable keys,
//! - artifact triad writers (`run_manifest.json`, `events.jsonl`, `commands.txt`).

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RGC_TEST_HARNESS_SCHEMA_VERSION: &str = "franken-engine.rgc-test-harness.v1";
pub const RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION: &str = "franken-engine.rgc-test-event.v1";
pub const RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.rgc-test-harness.run-manifest.v1";
pub const RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION: &str =
    "franken-engine.rgc-baseline-e2e-scenario.v1";
pub const RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION: &str = "franken-engine.rgc-artifact-validator.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessLane {
    Parser,
    Runtime,
    Security,
    Governance,
    E2e,
}

impl HarnessLane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Runtime => "runtime",
            Self::Security => "security",
            Self::Governance => "governance",
            Self::E2e => "e2e",
        }
    }
}

impl fmt::Display for HarnessLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Input parameters for [`DeterministicTestContext::event`].
#[derive(Debug, Clone)]
pub struct EventInput<'a> {
    pub sequence: u64,
    pub component: &'a str,
    pub event: &'a str,
    pub outcome: &'a str,
    pub error_code: Option<&'a str>,
    pub timing_us: u64,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicTestContext {
    pub scenario_id: String,
    pub fixture_id: String,
    pub lane: HarnessLane,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl DeterministicTestContext {
    pub fn new(
        scenario_id: impl Into<String>,
        fixture_id: impl Into<String>,
        lane: HarnessLane,
        seed: u64,
    ) -> Self {
        let scenario_id = scenario_id.into();
        let fixture_id = fixture_id.into();
        let seed_material = format!("{}|{}|{}|{}", scenario_id, fixture_id, lane, seed);
        let digest = hex::encode(Sha256::digest(seed_material.as_bytes()));
        let short = &digest[..16];

        Self {
            scenario_id,
            fixture_id,
            lane,
            seed,
            trace_id: format!("trace-rgc-{short}"),
            decision_id: format!("decision-rgc-{short}"),
            policy_id: format!("policy-rgc-{}-v1", lane.as_str()),
        }
    }

    pub fn default_run_id(&self) -> String {
        format!(
            "run-{}-{}",
            sanitize_label(&self.scenario_id),
            &self.trace_id["trace-rgc-".len()..]
        )
    }

    pub fn event(&self, input: EventInput<'_>) -> HarnessLogEvent {
        HarnessLogEvent {
            schema_version: RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: self.scenario_id.clone(),
            fixture_id: self.fixture_id.clone(),
            trace_id: self.trace_id.clone(),
            decision_id: self.decision_id.clone(),
            policy_id: self.policy_id.clone(),
            lane: self.lane,
            component: input.component.to_string(),
            event: input.event.to_string(),
            outcome: input.outcome.to_string(),
            error_code: input.error_code.map(std::string::ToString::to_string),
            seed: self.seed,
            sequence: input.sequence,
            timing_us: input.timing_us,
            timestamp_unix_ms: input.timestamp_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessLogEvent {
    pub schema_version: String,
    pub scenario_id: String,
    pub fixture_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub lane: HarnessLane,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub seed: u64,
    pub sequence: u64,
    pub timing_us: u64,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessRunManifest {
    pub schema_version: String,
    pub harness_schema_version: String,
    pub run_id: String,
    pub scenario_id: String,
    pub fixture_id: String,
    pub lane: HarnessLane,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub event_count: usize,
    pub command_count: usize,
    pub env_fingerprint: String,
    pub replay_command: String,
    pub generated_at_unix_ms: u64,
}

impl HarnessRunManifest {
    pub fn from_context(
        context: &DeterministicTestContext,
        run_id: impl Into<String>,
        event_count: usize,
        command_count: usize,
        replay_command: impl Into<String>,
        generated_at_unix_ms: u64,
    ) -> Self {
        let replay_command = replay_command.into();
        let env_material = format!(
            "{}|{}|{}|{}|{}|{}",
            RGC_TEST_HARNESS_SCHEMA_VERSION,
            context.lane.as_str(),
            context.seed,
            context.scenario_id,
            context.fixture_id,
            replay_command
        );
        let env_fingerprint = hex::encode(Sha256::digest(env_material.as_bytes()));

        Self {
            schema_version: RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION.to_string(),
            harness_schema_version: RGC_TEST_HARNESS_SCHEMA_VERSION.to_string(),
            run_id: run_id.into(),
            scenario_id: context.scenario_id.clone(),
            fixture_id: context.fixture_id.clone(),
            lane: context.lane,
            seed: context.seed,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            event_count,
            command_count,
            env_fingerprint,
            replay_command,
            generated_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessArtifactTriad {
    pub run_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineScenarioDomain {
    Runtime,
    Module,
    Security,
}

impl BaselineScenarioDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Module => "module",
            Self::Security => "security",
        }
    }
}

impl fmt::Display for BaselineScenarioDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineScenarioOutcome {
    HappyPath,
    CanonicalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineE2eScenario {
    pub schema_version: String,
    pub scenario_id: String,
    pub fixture_id: String,
    pub lane: HarnessLane,
    pub domain: BaselineScenarioDomain,
    pub outcome: BaselineScenarioOutcome,
    pub component: String,
    pub event: String,
    pub error_code: Option<String>,
}

impl BaselineE2eScenario {
    fn new(
        scenario_id: &str,
        fixture_id: &str,
        domain: BaselineScenarioDomain,
        outcome: BaselineScenarioOutcome,
        component: &str,
        event: &str,
        error_code: Option<&str>,
    ) -> Self {
        Self {
            schema_version: RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_id: scenario_id.to_string(),
            fixture_id: fixture_id.to_string(),
            lane: HarnessLane::E2e,
            domain,
            outcome,
            component: component.to_string(),
            event: event.to_string(),
            error_code: error_code.map(std::string::ToString::to_string),
        }
    }
}

pub fn baseline_e2e_scenario_registry() -> Vec<BaselineE2eScenario> {
    let mut scenarios = vec![
        BaselineE2eScenario::new(
            "rgc-053a-runtime-happy",
            "runtime-smoke-happy",
            BaselineScenarioDomain::Runtime,
            BaselineScenarioOutcome::HappyPath,
            "runtime_lane",
            "execute_runtime_smoke",
            None,
        ),
        BaselineE2eScenario::new(
            "rgc-053a-runtime-failure",
            "runtime-smoke-failure",
            BaselineScenarioDomain::Runtime,
            BaselineScenarioOutcome::CanonicalFailure,
            "runtime_lane",
            "runtime_guard_abort",
            Some("FE-RGC-053A-RUNTIME-0001"),
        ),
        BaselineE2eScenario::new(
            "rgc-053a-module-happy",
            "module-smoke-happy",
            BaselineScenarioDomain::Module,
            BaselineScenarioOutcome::HappyPath,
            "module_loader",
            "resolve_graph",
            None,
        ),
        BaselineE2eScenario::new(
            "rgc-053a-module-failure",
            "module-smoke-failure",
            BaselineScenarioDomain::Module,
            BaselineScenarioOutcome::CanonicalFailure,
            "module_loader",
            "resolution_rejected",
            Some("FE-RGC-053A-MODULE-0001"),
        ),
        BaselineE2eScenario::new(
            "rgc-053a-security-happy",
            "security-smoke-happy",
            BaselineScenarioDomain::Security,
            BaselineScenarioOutcome::HappyPath,
            "security_guardplane",
            "capability_allowed",
            None,
        ),
        BaselineE2eScenario::new(
            "rgc-053a-security-failure",
            "security-smoke-failure",
            BaselineScenarioDomain::Security,
            BaselineScenarioOutcome::CanonicalFailure,
            "security_guardplane",
            "containment_triggered",
            Some("FE-RGC-053A-SECURITY-0001"),
        ),
    ];
    scenarios.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    scenarios
}

pub fn select_baseline_e2e_scenarios(
    domains: &[BaselineScenarioDomain],
    include_failures: bool,
) -> Vec<BaselineE2eScenario> {
    let allowed_domains: BTreeSet<BaselineScenarioDomain> = if domains.is_empty() {
        [
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Module,
            BaselineScenarioDomain::Security,
        ]
        .into_iter()
        .collect()
    } else {
        domains.iter().copied().collect()
    };

    let mut selected: Vec<_> = baseline_e2e_scenario_registry()
        .into_iter()
        .filter(|scenario| allowed_domains.contains(&scenario.domain))
        .filter(|scenario| {
            include_failures || scenario.outcome == BaselineScenarioOutcome::HappyPath
        })
        .collect();
    selected.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    selected
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactValidationErrorCode {
    MissingArtifact,
    InvalidManifestJson,
    InvalidEventJson,
    MissingRequiredField,
    CorrelationMismatch,
    CountMismatch,
    EmptyCommands,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactValidationFinding {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: ArtifactValidationErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactValidationReport {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub valid: bool,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub findings: Vec<ArtifactValidationFinding>,
}

impl ArtifactValidationFinding {
    fn new(error_code: ArtifactValidationErrorCode, message: impl Into<String>) -> Self {
        Self {
            component: "rgc_artifact_validator".to_string(),
            event: "validate_artifact_triad".to_string(),
            outcome: "fail".to_string(),
            error_code,
            message: message.into(),
        }
    }
}

fn manifest_required_field(
    manifest: &serde_json::Value,
    field: &str,
    findings: &mut Vec<ArtifactValidationFinding>,
) -> Option<String> {
    let value = manifest.get(field).and_then(serde_json::Value::as_str);
    match value {
        Some(raw) if !raw.trim().is_empty() => Some(raw.to_string()),
        _ => {
            findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::MissingRequiredField,
                format!("manifest missing required non-empty field `{field}`"),
            ));
            None
        }
    }
}

pub fn validate_artifact_triad(run_dir: impl AsRef<Path>) -> ArtifactValidationReport {
    let run_dir = run_dir.as_ref();
    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    let mut findings = Vec::new();
    for (name, path) in [
        ("run_manifest.json", &manifest_path),
        ("events.jsonl", &events_path),
        ("commands.txt", &commands_path),
    ] {
        if !path.exists() {
            findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::MissingArtifact,
                format!("missing required artifact `{name}` at `{}`", path.display()),
            ));
        }
    }

    let mut run_id = None;
    let mut trace_id = None;
    let mut decision_id = None;
    let mut policy_id = None;
    let mut seed = None;
    let mut expected_event_count = None;
    let mut expected_command_count = None;

    if manifest_path.exists() {
        match fs::read_to_string(&manifest_path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(manifest) => {
                    let schema =
                        manifest_required_field(&manifest, "schema_version", &mut findings);
                    if let Some(schema) = schema
                        && schema != RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION
                    {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            format!(
                                "manifest schema_version mismatch: expected `{}` found `{schema}`",
                                RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION
                            ),
                        ));
                    }
                    run_id = manifest_required_field(&manifest, "run_id", &mut findings);
                    trace_id = manifest_required_field(&manifest, "trace_id", &mut findings);
                    decision_id = manifest_required_field(&manifest, "decision_id", &mut findings);
                    policy_id = manifest_required_field(&manifest, "policy_id", &mut findings);
                    let _scenario_id =
                        manifest_required_field(&manifest, "scenario_id", &mut findings);
                    let _fixture_id =
                        manifest_required_field(&manifest, "fixture_id", &mut findings);
                    let _replay_command =
                        manifest_required_field(&manifest, "replay_command", &mut findings);
                    let _env_fingerprint =
                        manifest_required_field(&manifest, "env_fingerprint", &mut findings);

                    seed = manifest.get("seed").and_then(serde_json::Value::as_u64);
                    if seed.is_none() {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            "manifest missing numeric `seed` field",
                        ));
                    }

                    expected_event_count = manifest
                        .get("event_count")
                        .and_then(serde_json::Value::as_u64);
                    if expected_event_count.is_none() {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            "manifest missing numeric `event_count` field",
                        ));
                    }

                    expected_command_count = manifest
                        .get("command_count")
                        .and_then(serde_json::Value::as_u64);
                    if expected_command_count.is_none() {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            "manifest missing numeric `command_count` field",
                        ));
                    }
                }
                Err(err) => findings.push(ArtifactValidationFinding::new(
                    ArtifactValidationErrorCode::InvalidManifestJson,
                    format!("invalid manifest JSON: {err}"),
                )),
            },
            Err(err) => findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::InvalidManifestJson,
                format!("failed to read manifest file: {err}"),
            )),
        }
    }

    if events_path.exists() {
        match fs::read_to_string(&events_path) {
            Ok(raw) => {
                let mut parsed_count = 0_u64;
                for (line_number, line) in raw.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    parsed_count = parsed_count.saturating_add(1);
                    match serde_json::from_str::<HarnessLogEvent>(line) {
                        Ok(event) => {
                            if let Some(expected) = trace_id.as_deref()
                                && event.trace_id != expected
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} trace_id mismatch: expected `{expected}` found `{}`",
                                            line_number + 1,
                                            event.trace_id
                                        ),
                                    ));
                            }
                            if let Some(expected) = decision_id.as_deref()
                                && event.decision_id != expected
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} decision_id mismatch: expected `{expected}` found `{}`",
                                            line_number + 1,
                                            event.decision_id
                                        ),
                                    ));
                            }
                            if let Some(expected) = policy_id.as_deref()
                                && event.policy_id != expected
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} policy_id mismatch: expected `{expected}` found `{}`",
                                            line_number + 1,
                                            event.policy_id
                                        ),
                                    ));
                            }
                            if let Some(expected_seed) = seed
                                && event.seed != expected_seed
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} seed mismatch: expected `{expected_seed}` found `{}`",
                                            line_number + 1,
                                            event.seed
                                        ),
                                    ));
                            }
                        }
                        Err(err) => findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::InvalidEventJson,
                            format!("invalid event JSON at line {}: {err}", line_number + 1),
                        )),
                    }
                }
                if let Some(expected) = expected_event_count
                    && parsed_count != expected
                {
                    findings.push(ArtifactValidationFinding::new(
                        ArtifactValidationErrorCode::CountMismatch,
                        format!("event count mismatch: manifest={expected} parsed={parsed_count}"),
                    ));
                }
            }
            Err(err) => findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::InvalidEventJson,
                format!("failed to read events file: {err}"),
            )),
        }
    }

    if commands_path.exists() {
        match fs::read_to_string(&commands_path) {
            Ok(raw) => {
                let command_count =
                    raw.lines().filter(|line| !line.trim().is_empty()).count() as u64;
                if command_count == 0 {
                    findings.push(ArtifactValidationFinding::new(
                        ArtifactValidationErrorCode::EmptyCommands,
                        "commands.txt contains no commands",
                    ));
                }
                if let Some(expected) = expected_command_count
                    && command_count != expected
                {
                    findings.push(ArtifactValidationFinding::new(
                        ArtifactValidationErrorCode::CountMismatch,
                        format!(
                            "command count mismatch: manifest={expected} parsed={command_count}"
                        ),
                    ));
                }
            }
            Err(err) => findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::EmptyCommands,
                format!("failed to read commands.txt: {err}"),
            )),
        }
    }

    let valid = findings.is_empty();
    ArtifactValidationReport {
        schema_version: RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "rgc_artifact_validator".to_string(),
        event: "validate_artifact_triad".to_string(),
        outcome: if valid { "pass" } else { "fail" }.to_string(),
        valid,
        run_id,
        trace_id,
        decision_id,
        policy_id,
        findings,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureLoadError {
    InvalidRelativePath { relative_path: String },
    IoRead { path: String, message: String },
    JsonParse { path: String, message: String },
}

impl fmt::Display for FixtureLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelativePath { relative_path } => write!(
                f,
                "invalid fixture relative path (must not escape root): {relative_path}"
            ),
            Self::IoRead { path, message } => {
                write!(f, "failed to read fixture `{path}`: {message}")
            }
            Self::JsonParse { path, message } => {
                write!(f, "failed to parse fixture JSON `{path}`: {message}")
            }
        }
    }
}

impl Error for FixtureLoadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactWriteError {
    Io { path: String, message: String },
    Json { path: String, message: String },
}

impl fmt::Display for ArtifactWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "I/O error writing `{path}`: {message}"),
            Self::Json { path, message } => {
                write!(f, "serialization error for `{path}`: {message}")
            }
        }
    }
}

impl Error for ArtifactWriteError {}

pub fn load_json_fixture<T>(
    fixtures_root: impl AsRef<Path>,
    relative_path: &str,
) -> Result<T, FixtureLoadError>
where
    T: DeserializeOwned,
{
    let rel = Path::new(relative_path);
    if relative_path.trim().is_empty()
        || rel.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(FixtureLoadError::InvalidRelativePath {
            relative_path: relative_path.to_string(),
        });
    }

    let path = fixtures_root.as_ref().join(rel);
    let raw = fs::read_to_string(&path).map_err(|err| FixtureLoadError::IoRead {
        path: path.display().to_string(),
        message: err.to_string(),
    })?;
    serde_json::from_str(&raw).map_err(|err| FixtureLoadError::JsonParse {
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

pub fn write_artifact_triad(
    artifact_root: impl AsRef<Path>,
    manifest: &HarnessRunManifest,
    events: &[HarnessLogEvent],
    commands: &[String],
) -> Result<HarnessArtifactTriad, ArtifactWriteError> {
    let run_dir = artifact_root.as_ref().join(&manifest.run_id);
    fs::create_dir_all(&run_dir).map_err(|err| ArtifactWriteError::Io {
        path: run_dir.display().to_string(),
        message: err.to_string(),
    })?;

    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    let manifest_json =
        serde_json::to_vec_pretty(manifest).map_err(|err| ArtifactWriteError::Json {
            path: manifest_path.display().to_string(),
            message: err.to_string(),
        })?;
    write_atomic(&manifest_path, &manifest_json)?;

    let mut events_jsonl = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(|err| ArtifactWriteError::Json {
            path: events_path.display().to_string(),
            message: err.to_string(),
        })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }
    write_atomic(&events_path, events_jsonl.as_bytes())?;

    let mut commands_buf = String::new();
    for command in commands {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }
    write_atomic(&commands_path, commands_buf.as_bytes())?;

    Ok(HarnessArtifactTriad {
        run_dir,
        manifest_path,
        events_path,
        commands_path,
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ArtifactWriteError> {
    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp_path, bytes).map_err(|err| ArtifactWriteError::Io {
        path: tmp_path.display().to_string(),
        message: err.to_string(),
    })?;
    fs::rename(&tmp_path, path).map_err(|err| ArtifactWriteError::Io {
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

fn sanitize_label(label: &str) -> String {
    let sanitized: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    sanitized.trim_matches('-').to_lowercase()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct DemoFixture {
        scenario: String,
        value: u64,
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "franken_engine_{label}_{nanos}_{}",
            std::process::id()
        ))
    }

    #[test]
    fn deterministic_context_ids_are_stable_for_same_inputs() {
        let a = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 42);
        let b = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 42);
        assert_eq!(a.trace_id, b.trace_id);
        assert_eq!(a.decision_id, b.decision_id);
        assert_eq!(a.policy_id, b.policy_id);
    }

    #[test]
    fn deterministic_context_ids_change_when_seed_changes() {
        let a = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 1);
        let b = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 2);
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn fixture_loader_rejects_parent_traversal() {
        let root = PathBuf::from("/tmp");
        let error = load_json_fixture::<DemoFixture>(&root, "../escape.json")
            .expect_err("path traversal must fail");
        assert!(matches!(
            error,
            FixtureLoadError::InvalidRelativePath { .. }
        ));
    }

    #[test]
    fn fixture_loader_reads_valid_json_fixture() {
        let root = temp_dir("fixture_loader");
        fs::create_dir_all(&root).expect("create temp fixture root");
        let fixture_path = root.join("fixture.json");
        fs::write(
            &fixture_path,
            "{\"scenario\":\"runtime-happy\",\"value\":7}\n",
        )
        .expect("write fixture");

        let loaded: DemoFixture =
            load_json_fixture(&root, "fixture.json").expect("fixture should load");
        assert_eq!(
            loaded,
            DemoFixture {
                scenario: "runtime-happy".to_string(),
                value: 7
            }
        );
    }

    #[test]
    fn artifact_writer_emits_manifest_events_and_commands() {
        let root = temp_dir("artifact_writer");
        let context = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Parser, 9);
        let run_id = context.default_run_id();
        let events = vec![
            context.event(EventInput {
                sequence: 0,
                component: "rgc_test_harness",
                event: "fixture_loaded",
                outcome: "pass",
                error_code: None,
                timing_us: 11,
                timestamp_unix_ms: 1_700_000_000_000,
            }),
            context.event(EventInput {
                sequence: 1,
                component: "rgc_test_harness",
                event: "assertions_complete",
                outcome: "pass",
                error_code: None,
                timing_us: 23,
                timestamp_unix_ms: 1_700_000_000_001,
            }),
        ];
        let commands = vec![
            "cargo check -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_test_harness_replay.sh ci",
            1_700_000_000_111,
        );

        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("artifact triad should write");
        assert!(triad.manifest_path.exists());
        assert!(triad.events_path.exists());
        assert!(triad.commands_path.exists());

        let saved_manifest: HarnessRunManifest =
            serde_json::from_str(&fs::read_to_string(&triad.manifest_path).expect("read manifest"))
                .expect("manifest JSON should parse");
        assert_eq!(saved_manifest.event_count, 2);
        assert_eq!(saved_manifest.command_count, 2);
        assert!(!saved_manifest.env_fingerprint.trim().is_empty());

        let saved_events = fs::read_to_string(&triad.events_path).expect("read events");
        assert_eq!(saved_events.lines().count(), 2);
    }

    #[test]
    fn baseline_registry_covers_runtime_module_security_happy_and_failure() {
        let registry = baseline_e2e_scenario_registry();
        assert_eq!(registry.len(), 6, "expected 3 domains x 2 outcomes");

        for domain in [
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Module,
            BaselineScenarioDomain::Security,
        ] {
            let happy = registry
                .iter()
                .filter(|scenario| {
                    scenario.domain == domain
                        && scenario.outcome == BaselineScenarioOutcome::HappyPath
                })
                .count();
            let canonical_failure = registry
                .iter()
                .filter(|scenario| {
                    scenario.domain == domain
                        && scenario.outcome == BaselineScenarioOutcome::CanonicalFailure
                })
                .count();
            assert_eq!(happy, 1, "missing happy-path scenario for {domain}");
            assert_eq!(
                canonical_failure, 1,
                "missing canonical-failure scenario for {domain}"
            );
        }
    }

    #[test]
    fn baseline_selection_is_deterministic_and_filterable() {
        let first = select_baseline_e2e_scenarios(
            &[
                BaselineScenarioDomain::Runtime,
                BaselineScenarioDomain::Security,
            ],
            true,
        );
        let second = select_baseline_e2e_scenarios(
            &[
                BaselineScenarioDomain::Runtime,
                BaselineScenarioDomain::Security,
            ],
            true,
        );
        assert_eq!(first, second, "selection must be deterministic");
        assert_eq!(
            first.len(),
            4,
            "runtime+security should return four scenarios"
        );

        let happy_only = select_baseline_e2e_scenarios(&[], false);
        assert_eq!(
            happy_only.len(),
            3,
            "happy-only should include one per domain"
        );
        assert!(
            happy_only
                .iter()
                .all(|scenario| scenario.outcome == BaselineScenarioOutcome::HappyPath)
        );
    }

    #[test]
    fn artifact_validator_accepts_valid_harness_triad() {
        let root = temp_dir("artifact_validator_valid");
        let context = DeterministicTestContext::new(
            "rgc-053a-runtime-happy",
            "runtime-smoke-happy",
            HarnessLane::E2e,
            53,
        );
        let run_id = context.default_run_id();
        let events = vec![context.event(EventInput {
            sequence: 0,
            component: "runtime_lane",
            event: "execute_runtime_smoke",
            outcome: "pass",
            error_code: None,
            timing_us: 31,
            timestamp_unix_ms: 1_700_100_000_000,
        })];
        let commands = vec![
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_test_harness_replay.sh ci",
            1_700_100_000_100,
        );

        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("artifact triad should write");
        let report = validate_artifact_triad(&triad.run_dir);
        assert!(
            report.valid,
            "expected valid report, got: {:?}",
            report.findings
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.run_id.as_deref(), Some(manifest.run_id.as_str()));
        assert_eq!(report.trace_id.as_deref(), Some(manifest.trace_id.as_str()));
    }

    #[test]
    fn artifact_validator_reports_missing_and_malformed_artifacts() {
        let root = temp_dir("artifact_validator_invalid");
        let run_dir = root.join("broken-run");
        fs::create_dir_all(&run_dir).expect("create run dir");

        fs::write(
            run_dir.join("run_manifest.json"),
            r#"{"schema_version":"wrong.schema","run_id":"","trace_id":"","decision_id":"","policy_id":"","seed":"not-a-number"}"#,
        )
        .expect("write malformed manifest");
        fs::write(run_dir.join("events.jsonl"), "{not-json}\n").expect("write malformed events");
        fs::write(run_dir.join("commands.txt"), "\n").expect("write empty commands");

        let report = validate_artifact_triad(&run_dir);
        assert!(!report.valid);
        assert!(!report.findings.is_empty());
        assert!(report.findings.iter().any(|finding| {
            finding.error_code == ArtifactValidationErrorCode::MissingRequiredField
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.error_code == ArtifactValidationErrorCode::InvalidEventJson
        }));
        assert!(
            report.findings.iter().any(|finding| {
                finding.error_code == ArtifactValidationErrorCode::EmptyCommands
            })
        );
    }
}
