use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::ParseGoal;
use crate::parser::{CanonicalEs2020Parser, Es2020Parser};

pub const DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH: &str =
    "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json";

const EXPECTED_FIXTURE_SCHEMA_VERSION: &str = "franken-engine.parser-phase0.semantic-fixtures.v1";
const EXPECTED_FIXTURE_PARSER_MODE: &str = "scalar_reference";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessEngineKind {
    FrankenCanonical,
    FixtureExpectedHash,
    ExternalCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEngineSpec {
    pub engine_id: String,
    pub display_name: String,
    pub kind: HarnessEngineKind,
    pub version_pin: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

impl HarnessEngineSpec {
    pub fn franken_canonical(version_pin: impl Into<String>) -> Self {
        Self {
            engine_id: "franken_canonical".to_string(),
            display_name: "FrankenEngine Canonical Parser".to_string(),
            kind: HarnessEngineKind::FrankenCanonical,
            version_pin: version_pin.into(),
            command: None,
            args: Vec::new(),
        }
    }

    pub fn fixture_expected_hash(version_pin: impl Into<String>) -> Self {
        Self {
            engine_id: "fixture_expected_hash".to_string(),
            display_name: "Fixture Expected Hash Baseline".to_string(),
            kind: HarnessEngineKind::FixtureExpectedHash,
            version_pin: version_pin.into(),
            command: None,
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiEngineHarnessConfig {
    pub fixture_catalog_path: PathBuf,
    pub fixture_limit: Option<usize>,
    pub fixture_id_filter: Option<String>,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub locale: String,
    pub timezone: String,
    pub engines: Vec<HarnessEngineSpec>,
}

impl MultiEngineHarnessConfig {
    pub fn with_defaults(seed: u64) -> Self {
        let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        Self {
            fixture_catalog_path: PathBuf::from(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH),
            fixture_limit: Some(8),
            fixture_id_filter: None,
            seed,
            trace_id: format!("trace-parser-multi-engine-{now}"),
            decision_id: format!("decision-parser-multi-engine-{now}"),
            policy_id: "policy-parser-multi-engine-v1".to_string(),
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            engines: vec![
                HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
                HarnessEngineSpec::fixture_expected_hash("fixture-catalog@phase0-v1"),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HarnessFixtureCatalog {
    pub schema_version: String,
    pub parser_mode: String,
    pub fixtures: Vec<HarnessFixtureSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HarnessFixtureSpec {
    pub id: String,
    pub family_id: String,
    pub goal: String,
    pub source: String,
    pub expected_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineOutcomeKind {
    Hash,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineRunOutcome {
    pub kind: EngineOutcomeKind,
    pub value: String,
    pub deterministic: bool,
    pub duration_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineFixtureResult {
    pub engine_id: String,
    pub display_name: String,
    pub version_pin: String,
    pub derived_seed: u64,
    pub first_run: EngineRunOutcome,
    pub second_run: EngineRunOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureComparisonResult {
    pub fixture_id: String,
    pub family_id: String,
    pub goal: String,
    pub source_hash: String,
    pub equivalent_across_engines: bool,
    pub nondeterministic_engine_count: u64,
    pub divergence_reason: Option<String>,
    pub replay_command: String,
    pub engine_results: Vec<EngineFixtureResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiEngineHarnessSummary {
    pub total_fixtures: u64,
    pub equivalent_fixtures: u64,
    pub divergent_fixtures: u64,
    pub fixtures_with_nondeterminism: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiEngineHarnessReport {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub fixture_catalog_path: String,
    pub fixture_catalog_hash: String,
    pub parser_mode: String,
    pub seed: u64,
    pub locale: String,
    pub timezone: String,
    pub fixture_count: u64,
    pub engine_specs: Vec<HarnessEngineSpec>,
    pub summary: MultiEngineHarnessSummary,
    pub fixture_results: Vec<FixtureComparisonResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EngineObservation {
    Hash(String),
    Error(String),
}

impl EngineObservation {
    fn kind(&self) -> EngineOutcomeKind {
        match self {
            Self::Hash(_) => EngineOutcomeKind::Hash,
            Self::Error(_) => EngineOutcomeKind::Error,
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::Hash(value) | Self::Error(value) => value,
        }
    }

    fn signature(&self) -> String {
        match self {
            Self::Hash(value) => format!("hash:{value}"),
            Self::Error(value) => format!("error:{value}"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ExternalCommandRequest {
    goal: String,
    source: String,
    seed: u64,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    engine_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalCommandResponse {
    hash: Option<String>,
    error_code: Option<String>,
}

#[derive(Debug)]
pub enum MultiEngineHarnessError {
    Io {
        path: String,
        source: std::io::Error,
    },
    DecodeCatalog(String),
    InvalidCatalogSchema {
        expected: String,
        actual: String,
    },
    InvalidCatalogParserMode {
        expected: String,
        actual: String,
    },
    EmptyFixtureCatalog,
    DuplicateFixtureId {
        fixture_id: String,
    },
    UnknownGoal {
        fixture_id: String,
        goal: String,
    },
    FixtureFilterNotFound {
        fixture_id: String,
    },
    InvalidConfig(String),
    ExternalEngine {
        engine_id: String,
        detail: String,
    },
}

impl fmt::Display for MultiEngineHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "failed to read `{path}`: {source}"),
            Self::DecodeCatalog(message) => {
                write!(f, "failed to decode multi-engine fixture catalog: {message}")
            }
            Self::InvalidCatalogSchema { expected, actual } => write!(
                f,
                "invalid multi-engine catalog schema `{actual}` (expected `{expected}`)"
            ),
            Self::InvalidCatalogParserMode { expected, actual } => write!(
                f,
                "invalid multi-engine catalog parser_mode `{actual}` (expected `{expected}`)"
            ),
            Self::EmptyFixtureCatalog => write!(f, "multi-engine fixture catalog must not be empty"),
            Self::DuplicateFixtureId { fixture_id } => {
                write!(f, "multi-engine fixture id `{fixture_id}` appears more than once")
            }
            Self::UnknownGoal { fixture_id, goal } => {
                write!(f, "fixture `{fixture_id}` has unknown parse goal `{goal}`")
            }
            Self::FixtureFilterNotFound { fixture_id } => {
                write!(f, "fixture filter `{fixture_id}` did not match any fixture")
            }
            Self::InvalidConfig(message) => write!(f, "invalid multi-engine harness config: {message}"),
            Self::ExternalEngine { engine_id, detail } => {
                write!(f, "external engine `{engine_id}` failed: {detail}")
            }
        }
    }
}

impl std::error::Error for MultiEngineHarnessError {}

pub fn run_multi_engine_harness(
    config: &MultiEngineHarnessConfig,
) -> Result<MultiEngineHarnessReport, MultiEngineHarnessError> {
    validate_config(config)?;

    let catalog = load_fixture_catalog(config.fixture_catalog_path.as_path())?;
    let catalog_hash = hash_bytes(
        &fs::read(config.fixture_catalog_path.as_path()).map_err(|source| MultiEngineHarnessError::Io {
            path: config.fixture_catalog_path.display().to_string(),
            source,
        })?,
    );

    let mut selected = catalog.fixtures;
    if let Some(fixture_id) = config.fixture_id_filter.as_ref() {
        selected.retain(|fixture| fixture.id == *fixture_id);
        if selected.is_empty() {
            return Err(MultiEngineHarnessError::FixtureFilterNotFound {
                fixture_id: fixture_id.clone(),
            });
        }
    }

    if let Some(limit) = config.fixture_limit
        && selected.len() > limit
    {
        selected.truncate(limit);
    }

    let run_id = derive_run_id(config, catalog_hash.as_str(), &selected);

    let mut fixture_results = Vec::with_capacity(selected.len());
    let mut equivalent_count = 0_u64;
    let mut divergent_count = 0_u64;
    let mut fixtures_with_nondeterminism = 0_u64;

    for fixture in &selected {
        let goal = parse_goal(fixture.id.as_str(), fixture.goal.as_str())?;
        let source_hash = hash_bytes(fixture.source.as_bytes());
        let replay_command = format!(
            "cargo run -p frankenengine-engine --bin franken_parser_multi_engine_harness -- --fixture-catalog {} --seed {} --fixture-id {} --trace-id {} --decision-id {} --policy-id {}",
            config.fixture_catalog_path.display(),
            config.seed,
            fixture.id,
            config.trace_id,
            config.decision_id,
            config.policy_id,
        );

        let mut engine_results = Vec::with_capacity(config.engines.len());
        let mut outcome_signatures = BTreeMap::<String, Vec<String>>::new();
        let mut nondeterministic_engine_count = 0_u64;

        for engine in &config.engines {
            let derived_seed = derive_engine_seed(config.seed, fixture.id.as_str(), engine.engine_id.as_str());
            let first = execute_engine(engine, fixture, goal, derived_seed, config)?;
            let second = execute_engine(engine, fixture, goal, derived_seed, config)?;
            let deterministic = first.observation == second.observation;
            if !deterministic {
                nondeterministic_engine_count += 1;
            }

            let first_run = EngineRunOutcome {
                kind: first.observation.kind(),
                value: first.observation.value().to_string(),
                deterministic,
                duration_us: first.duration_us,
            };
            let second_run = EngineRunOutcome {
                kind: second.observation.kind(),
                value: second.observation.value().to_string(),
                deterministic,
                duration_us: second.duration_us,
            };

            outcome_signatures
                .entry(first.observation.signature())
                .or_default()
                .push(engine.engine_id.clone());

            engine_results.push(EngineFixtureResult {
                engine_id: engine.engine_id.clone(),
                display_name: engine.display_name.clone(),
                version_pin: engine.version_pin.clone(),
                derived_seed,
                first_run,
                second_run,
            });
        }

        let equivalent_across_engines = outcome_signatures.len() == 1 && nondeterministic_engine_count == 0;
        let divergence_reason = if equivalent_across_engines {
            None
        } else {
            Some(format_divergence_reason(
                &outcome_signatures,
                nondeterministic_engine_count,
            ))
        };

        if equivalent_across_engines {
            equivalent_count += 1;
        } else {
            divergent_count += 1;
        }
        if nondeterministic_engine_count > 0 {
            fixtures_with_nondeterminism += 1;
        }

        fixture_results.push(FixtureComparisonResult {
            fixture_id: fixture.id.clone(),
            family_id: fixture.family_id.clone(),
            goal: fixture.goal.clone(),
            source_hash,
            equivalent_across_engines,
            nondeterministic_engine_count,
            divergence_reason,
            replay_command,
            engine_results,
        });
    }

    Ok(MultiEngineHarnessReport {
        schema_version: "franken-engine.parser-multi-engine.report.v1".to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        run_id,
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        fixture_catalog_path: config.fixture_catalog_path.display().to_string(),
        fixture_catalog_hash: catalog_hash,
        parser_mode: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
        seed: config.seed,
        locale: config.locale.clone(),
        timezone: config.timezone.clone(),
        fixture_count: fixture_results.len() as u64,
        engine_specs: config.engines.clone(),
        summary: MultiEngineHarnessSummary {
            total_fixtures: fixture_results.len() as u64,
            equivalent_fixtures: equivalent_count,
            divergent_fixtures: divergent_count,
            fixtures_with_nondeterminism,
        },
        fixture_results,
    })
}

fn derive_run_id(
    config: &MultiEngineHarnessConfig,
    catalog_hash: &str,
    fixtures: &[HarnessFixtureSpec],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(catalog_hash.as_bytes());
    hasher.update(config.seed.to_le_bytes());
    hasher.update(config.locale.as_bytes());
    hasher.update(config.timezone.as_bytes());

    for engine in &config.engines {
        hasher.update(engine.engine_id.as_bytes());
        hasher.update(engine.version_pin.as_bytes());
        hasher.update(format!("{:?}", engine.kind).as_bytes());
        if let Some(command) = engine.command.as_ref() {
            hasher.update(command.as_bytes());
        }
        for arg in &engine.args {
            hasher.update(arg.as_bytes());
        }
    }

    for fixture in fixtures {
        hasher.update(fixture.id.as_bytes());
        hasher.update(fixture.expected_hash.as_bytes());
    }

    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn format_divergence_reason(
    outcome_signatures: &BTreeMap<String, Vec<String>>,
    nondeterministic_engine_count: u64,
) -> String {
    let mut parts = Vec::new();
    for (signature, engines) in outcome_signatures {
        parts.push(format!("{signature} <- [{}]", engines.join(",")));
    }
    if nondeterministic_engine_count > 0 {
        parts.push(format!("nondeterministic_engines={nondeterministic_engine_count}"));
    }
    parts.join("; ")
}

fn validate_config(config: &MultiEngineHarnessConfig) -> Result<(), MultiEngineHarnessError> {
    if config.trace_id.trim().is_empty() {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "trace_id must not be empty".to_string(),
        ));
    }
    if config.decision_id.trim().is_empty() {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "decision_id must not be empty".to_string(),
        ));
    }
    if config.policy_id.trim().is_empty() {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "policy_id must not be empty".to_string(),
        ));
    }
    if config.engines.len() < 2 {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "at least two engine specs are required".to_string(),
        ));
    }

    let mut engine_ids = BTreeSet::new();
    for engine in &config.engines {
        if engine.engine_id.trim().is_empty() {
            return Err(MultiEngineHarnessError::InvalidConfig(
                "engine_id must not be empty".to_string(),
            ));
        }
        if !engine_ids.insert(engine.engine_id.clone()) {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "engine_id `{}` appears more than once",
                engine.engine_id
            )));
        }
        if engine.version_pin.trim().is_empty() {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "engine `{}` has empty version_pin",
                engine.engine_id
            )));
        }
        if matches!(engine.kind, HarnessEngineKind::ExternalCommand)
            && engine
                .command
                .as_ref()
                .is_none_or(|command| command.trim().is_empty())
        {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "external engine `{}` requires command",
                engine.engine_id
            )));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct TimedObservation {
    observation: EngineObservation,
    duration_us: u64,
}

fn execute_engine(
    engine: &HarnessEngineSpec,
    fixture: &HarnessFixtureSpec,
    goal: ParseGoal,
    seed: u64,
    config: &MultiEngineHarnessConfig,
) -> Result<TimedObservation, MultiEngineHarnessError> {
    let started = Instant::now();
    let observation = match engine.kind {
        HarnessEngineKind::FrankenCanonical => {
            let parser = CanonicalEs2020Parser;
            match parser.parse(fixture.source.as_str(), goal) {
                Ok(tree) => EngineObservation::Hash(tree.canonical_hash()),
                Err(error) => EngineObservation::Error(format!("{:?}", error.code)),
            }
        }
        HarnessEngineKind::FixtureExpectedHash => {
            EngineObservation::Hash(fixture.expected_hash.clone())
        }
        HarnessEngineKind::ExternalCommand => {
            run_external_engine(engine, fixture, goal, seed, config)?
        }
    };

    Ok(TimedObservation {
        observation,
        duration_us: started.elapsed().as_micros() as u64,
    })
}

fn run_external_engine(
    engine: &HarnessEngineSpec,
    fixture: &HarnessFixtureSpec,
    goal: ParseGoal,
    seed: u64,
    config: &MultiEngineHarnessConfig,
) -> Result<EngineObservation, MultiEngineHarnessError> {
    let command = engine
        .command
        .as_ref()
        .ok_or_else(|| MultiEngineHarnessError::ExternalEngine {
            engine_id: engine.engine_id.clone(),
            detail: "missing command".to_string(),
        })?;

    let request = ExternalCommandRequest {
        goal: goal.as_str().to_string(),
        source: fixture.source.clone(),
        seed,
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        engine_id: engine.engine_id.clone(),
    };

    let payload = serde_json::to_vec(&request).map_err(|error| MultiEngineHarnessError::ExternalEngine {
        engine_id: engine.engine_id.clone(),
        detail: format!("failed to serialize request payload: {error}"),
    })?;

    let mut process = Command::new(command);
    process
        .args(&engine.args)
        .env("LC_ALL", config.locale.as_str())
        .env("LANG", config.locale.as_str())
        .env("TZ", config.timezone.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = process.spawn().map_err(|error| MultiEngineHarnessError::ExternalEngine {
        engine_id: engine.engine_id.clone(),
        detail: format!("failed to spawn command `{command}`: {error}"),
    })?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(&payload)
            .map_err(|error| MultiEngineHarnessError::ExternalEngine {
                engine_id: engine.engine_id.clone(),
                detail: format!("failed to write stdin payload: {error}"),
            })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| MultiEngineHarnessError::ExternalEngine {
            engine_id: engine.engine_id.clone(),
            detail: format!("failed waiting for process exit: {error}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(MultiEngineHarnessError::ExternalEngine {
            engine_id: engine.engine_id.clone(),
            detail: format!(
                "command exited with status {}{}",
                output
                    .status
                    .code()
                    .map_or_else(|| "signal".to_string(), |code| code.to_string()),
                if stderr.is_empty() {
                    "".to_string()
                } else {
                    format!("; stderr={stderr}")
                }
            ),
        });
    }

    let response: ExternalCommandResponse = serde_json::from_slice(&output.stdout).map_err(|error| {
        MultiEngineHarnessError::ExternalEngine {
            engine_id: engine.engine_id.clone(),
            detail: format!("invalid JSON response: {error}"),
        }
    })?;

    if let Some(hash) = response.hash {
        return Ok(EngineObservation::Hash(hash));
    }
    if let Some(error_code) = response.error_code {
        return Ok(EngineObservation::Error(error_code));
    }

    Err(MultiEngineHarnessError::ExternalEngine {
        engine_id: engine.engine_id.clone(),
        detail: "response must include either `hash` or `error_code`".to_string(),
    })
}

pub fn derive_engine_seed(master_seed: u64, fixture_id: &str, engine_id: &str) -> u64 {
    let payload = format!("{master_seed}:{fixture_id}:{engine_id}");
    let digest = Sha256::digest(payload.as_bytes());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

pub fn load_fixture_catalog(path: &Path) -> Result<HarnessFixtureCatalog, MultiEngineHarnessError> {
    let bytes = fs::read(path).map_err(|source| MultiEngineHarnessError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let catalog = serde_json::from_slice::<HarnessFixtureCatalog>(&bytes)
        .map_err(|error| MultiEngineHarnessError::DecodeCatalog(error.to_string()))?;
    validate_fixture_catalog(&catalog)?;
    Ok(catalog)
}

fn validate_fixture_catalog(catalog: &HarnessFixtureCatalog) -> Result<(), MultiEngineHarnessError> {
    if catalog.schema_version != EXPECTED_FIXTURE_SCHEMA_VERSION {
        return Err(MultiEngineHarnessError::InvalidCatalogSchema {
            expected: EXPECTED_FIXTURE_SCHEMA_VERSION.to_string(),
            actual: catalog.schema_version.clone(),
        });
    }

    if catalog.parser_mode != EXPECTED_FIXTURE_PARSER_MODE {
        return Err(MultiEngineHarnessError::InvalidCatalogParserMode {
            expected: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
            actual: catalog.parser_mode.clone(),
        });
    }

    if catalog.fixtures.is_empty() {
        return Err(MultiEngineHarnessError::EmptyFixtureCatalog);
    }

    let mut seen = BTreeSet::new();
    for fixture in &catalog.fixtures {
        if !seen.insert(fixture.id.clone()) {
            return Err(MultiEngineHarnessError::DuplicateFixtureId {
                fixture_id: fixture.id.clone(),
            });
        }
        if fixture.expected_hash.trim().is_empty() {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "fixture `{}` has empty expected_hash",
                fixture.id
            )));
        }
    }

    Ok(())
}

fn parse_goal(fixture_id: &str, goal: &str) -> Result<ParseGoal, MultiEngineHarnessError> {
    match goal {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(MultiEngineHarnessError::UnknownGoal {
            fixture_id: fixture_id.to_string(),
            goal: other.to_string(),
        }),
    }
}

fn hash_bytes(input: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(input)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_engine_seed_is_stable() {
        let a = derive_engine_seed(7, "fixture", "engine");
        let b = derive_engine_seed(7, "fixture", "engine");
        assert_eq!(a, b);
    }

    #[test]
    fn default_config_contains_two_engines() {
        let config = MultiEngineHarnessConfig::with_defaults(9);
        assert_eq!(config.engines.len(), 2);
        assert_eq!(config.engines[0].engine_id, "franken_canonical");
        assert_eq!(config.engines[1].engine_id, "fixture_expected_hash");
    }

    #[test]
    fn validate_config_rejects_single_engine() {
        let mut config = MultiEngineHarnessConfig::with_defaults(1);
        config.engines.pop();
        let err = validate_config(&config).expect_err("single engine should fail");
        assert!(
            err.to_string().contains("at least two engine specs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_fixture_catalog_rejects_duplicate_ids() {
        let catalog = HarnessFixtureCatalog {
            schema_version: EXPECTED_FIXTURE_SCHEMA_VERSION.to_string(),
            parser_mode: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
            fixtures: vec![
                HarnessFixtureSpec {
                    id: "dup".to_string(),
                    family_id: "f".to_string(),
                    goal: "script".to_string(),
                    source: "x".to_string(),
                    expected_hash: "sha256:a".to_string(),
                },
                HarnessFixtureSpec {
                    id: "dup".to_string(),
                    family_id: "f".to_string(),
                    goal: "script".to_string(),
                    source: "y".to_string(),
                    expected_hash: "sha256:b".to_string(),
                },
            ],
        };

        let err = validate_fixture_catalog(&catalog).expect_err("duplicate ids should fail");
        assert!(err.to_string().contains("appears more than once"));
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn harness_engine_kind_serde_roundtrip() {
        for kind in [
            HarnessEngineKind::FrankenCanonical,
            HarnessEngineKind::FixtureExpectedHash,
            HarnessEngineKind::ExternalCommand,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: HarnessEngineKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn harness_engine_kind_snake_case_format() {
        let json = serde_json::to_string(&HarnessEngineKind::FrankenCanonical).unwrap();
        assert_eq!(json, "\"franken_canonical\"");
        let json = serde_json::to_string(&HarnessEngineKind::FixtureExpectedHash).unwrap();
        assert_eq!(json, "\"fixture_expected_hash\"");
        let json = serde_json::to_string(&HarnessEngineKind::ExternalCommand).unwrap();
        assert_eq!(json, "\"external_command\"");
    }

    #[test]
    fn harness_engine_spec_serde_roundtrip() {
        let spec = HarnessEngineSpec::franken_canonical("v1.0");
        let json = serde_json::to_string(&spec).expect("serialize");
        let restored: HarnessEngineSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, restored);
    }

    #[test]
    fn harness_engine_spec_external_command_serde() {
        let spec = HarnessEngineSpec {
            engine_id: "ext-1".to_string(),
            display_name: "External Engine".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "v2".to_string(),
            command: Some("/usr/bin/engine".to_string()),
            args: vec!["--mode".to_string(), "strict".to_string()],
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let restored: HarnessEngineSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, restored);
    }

    #[test]
    fn engine_outcome_kind_serialize() {
        let hash_json = serde_json::to_string(&EngineOutcomeKind::Hash).unwrap();
        assert_eq!(hash_json, "\"hash\"");
        let error_json = serde_json::to_string(&EngineOutcomeKind::Error).unwrap();
        assert_eq!(error_json, "\"error\"");
    }

    #[test]
    fn engine_run_outcome_serialize() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 42,
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        assert!(json.contains("\"deterministic\":true"));
        assert!(json.contains("\"duration_us\":42"));
    }

    #[test]
    fn engine_fixture_result_serialize() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 10,
        };
        let result = EngineFixtureResult {
            engine_id: "e1".to_string(),
            display_name: "Engine One".to_string(),
            version_pin: "v1".to_string(),
            derived_seed: 99,
            first_run: outcome.clone(),
            second_run: outcome,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        assert!(json.contains("\"engine_id\":\"e1\""));
        assert!(json.contains("\"derived_seed\":99"));
    }

    #[test]
    fn multi_engine_harness_summary_serialize() {
        let summary = MultiEngineHarnessSummary {
            total_fixtures: 100,
            equivalent_fixtures: 95,
            divergent_fixtures: 3,
            fixtures_with_nondeterminism: 2,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        assert!(json.contains("\"total_fixtures\":100"));
        assert!(json.contains("\"divergent_fixtures\":3"));
    }

    #[test]
    fn fixture_comparison_result_serialize() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 5,
        };
        let result = FixtureComparisonResult {
            fixture_id: "f-1".to_string(),
            family_id: "fam-1".to_string(),
            goal: "script".to_string(),
            source_hash: "sha256:src".to_string(),
            equivalent_across_engines: true,
            nondeterministic_engine_count: 0,
            divergence_reason: None,
            replay_command: "replay f-1".to_string(),
            engine_results: vec![EngineFixtureResult {
                engine_id: "e1".to_string(),
                display_name: "E1".to_string(),
                version_pin: "v1".to_string(),
                derived_seed: 42,
                first_run: outcome.clone(),
                second_run: outcome,
            }],
        };
        let json = serde_json::to_string(&result).expect("serialize");
        assert!(json.contains("\"equivalent_across_engines\":true"));
    }

    #[test]
    fn harness_fixture_spec_deserialize() {
        let json = r#"{
            "id": "fix-1",
            "family_id": "fam-1",
            "goal": "script",
            "source": "var x = 1;",
            "expected_hash": "sha256:abc"
        }"#;
        let spec: HarnessFixtureSpec = serde_json::from_str(json).expect("deserialize");
        assert_eq!(spec.id, "fix-1");
        assert_eq!(spec.goal, "script");
    }

    #[test]
    fn harness_fixture_catalog_deserialize() {
        let json = format!(
            r#"{{
                "schema_version": "{}",
                "parser_mode": "{}",
                "fixtures": [{{
                    "id": "f-1",
                    "family_id": "fam",
                    "goal": "script",
                    "source": "1+1",
                    "expected_hash": "sha256:x"
                }}]
            }}"#,
            EXPECTED_FIXTURE_SCHEMA_VERSION, EXPECTED_FIXTURE_PARSER_MODE
        );
        let catalog: HarnessFixtureCatalog =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(catalog.fixtures.len(), 1);
        assert_eq!(catalog.fixtures[0].id, "f-1");
    }

    // -- Enrichment: error Display --

    #[test]
    fn error_display_decode_catalog() {
        let e = MultiEngineHarnessError::DecodeCatalog("bad json".to_string());
        assert!(e.to_string().contains("bad json"));
    }

    #[test]
    fn error_display_invalid_catalog_schema() {
        let e = MultiEngineHarnessError::InvalidCatalogSchema {
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("v2") && s.contains("v1"));
    }

    #[test]
    fn error_display_invalid_catalog_parser_mode() {
        let e = MultiEngineHarnessError::InvalidCatalogParserMode {
            expected: "scalar_reference".to_string(),
            actual: "tree".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("tree") && s.contains("scalar_reference"));
    }

    #[test]
    fn error_display_empty_fixture_catalog() {
        let e = MultiEngineHarnessError::EmptyFixtureCatalog;
        assert!(e.to_string().contains("must not be empty"));
    }

    #[test]
    fn error_display_duplicate_fixture_id() {
        let e = MultiEngineHarnessError::DuplicateFixtureId {
            fixture_id: "dup-1".to_string(),
        };
        assert!(e.to_string().contains("dup-1"));
    }

    #[test]
    fn error_display_unknown_goal() {
        let e = MultiEngineHarnessError::UnknownGoal {
            fixture_id: "f-1".to_string(),
            goal: "banana".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("f-1") && s.contains("banana"));
    }

    #[test]
    fn error_display_fixture_filter_not_found() {
        let e = MultiEngineHarnessError::FixtureFilterNotFound {
            fixture_id: "missing".to_string(),
        };
        assert!(e.to_string().contains("missing"));
    }

    #[test]
    fn error_display_invalid_config() {
        let e = MultiEngineHarnessError::InvalidConfig("bad seed".to_string());
        assert!(e.to_string().contains("bad seed"));
    }

    #[test]
    fn error_display_external_engine() {
        let e = MultiEngineHarnessError::ExternalEngine {
            engine_id: "ext-1".to_string(),
            detail: "timeout".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("ext-1") && s.contains("timeout"));
    }

    #[test]
    fn error_is_std_error() {
        let e: Box<dyn std::error::Error> =
            Box::new(MultiEngineHarnessError::EmptyFixtureCatalog);
        assert!(!e.to_string().is_empty());
    }

    // -- Enrichment: constructors --

    #[test]
    fn franken_canonical_constructor() {
        let spec = HarnessEngineSpec::franken_canonical("v2.0");
        assert_eq!(spec.engine_id, "franken_canonical");
        assert_eq!(spec.kind, HarnessEngineKind::FrankenCanonical);
        assert_eq!(spec.version_pin, "v2.0");
        assert!(spec.command.is_none());
        assert!(spec.args.is_empty());
    }

    #[test]
    fn fixture_expected_hash_constructor() {
        let spec = HarnessEngineSpec::fixture_expected_hash("v3.0");
        assert_eq!(spec.engine_id, "fixture_expected_hash");
        assert_eq!(spec.kind, HarnessEngineKind::FixtureExpectedHash);
        assert_eq!(spec.version_pin, "v3.0");
    }

    #[test]
    fn with_defaults_config_fields() {
        let config = MultiEngineHarnessConfig::with_defaults(42);
        assert_eq!(config.seed, 42);
        assert_eq!(config.fixture_limit, Some(8));
        assert!(config.fixture_id_filter.is_none());
        assert_eq!(config.locale, "C");
        assert_eq!(config.timezone, "UTC");
        assert!(config.trace_id.starts_with("trace-parser-multi-engine-"));
        assert!(config.decision_id.starts_with("decision-parser-multi-engine-"));
    }

    #[test]
    fn derive_engine_seed_varies_with_fixture() {
        let a = derive_engine_seed(7, "fixture_a", "engine");
        let b = derive_engine_seed(7, "fixture_b", "engine");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_engine_seed_varies_with_engine() {
        let a = derive_engine_seed(7, "fixture", "engine_a");
        let b = derive_engine_seed(7, "fixture", "engine_b");
        assert_ne!(a, b);
    }
}
