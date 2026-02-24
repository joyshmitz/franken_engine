use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::ParseGoal;
use crate::parser::{CanonicalEs2020Parser, ParseErrorCode, ParserMode, ParserOptions};

pub const DEFAULT_FIXTURE_CATALOG_PATH: &str =
    "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OraclePartition {
    Smoke,
    Full,
    Nightly,
}

impl OraclePartition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Full => "full",
            Self::Nightly => "nightly",
        }
    }

    pub const fn fixture_limit(self) -> Option<usize> {
        match self {
            Self::Smoke => Some(4),
            Self::Full | Self::Nightly => None,
        }
    }

    pub const fn metamorphic_pairs(self) -> u32 {
        match self {
            Self::Smoke => 64,
            Self::Full => 256,
            Self::Nightly => 1024,
        }
    }
}

impl std::str::FromStr for OraclePartition {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "smoke" => Ok(Self::Smoke),
            "full" => Ok(Self::Full),
            "nightly" => Ok(Self::Nightly),
            other => Err(format!("unsupported partition `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleGateMode {
    ReportOnly,
    FailClosed,
}

impl OracleGateMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReportOnly => "report_only",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl std::str::FromStr for OracleGateMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "report_only" => Ok(Self::ReportOnly),
            "fail_closed" => Ok(Self::FailClosed),
            other => Err(format!("unsupported gate mode `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftClass {
    Equivalent,
    SemanticDrift,
    DiagnosticsDrift,
    HarnessNondeterminism,
    ArtifactIntegrityFailure,
}

impl DriftClass {
    pub const fn comparator_decision(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::DiagnosticsDrift => "drift_minor",
            Self::SemanticDrift | Self::HarnessNondeterminism | Self::ArtifactIntegrityFailure => {
                "drift_critical"
            }
        }
    }

    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::SemanticDrift | Self::HarnessNondeterminism | Self::ArtifactIntegrityFailure
        )
    }

    pub const fn is_minor(self) -> bool {
        matches!(self, Self::DiagnosticsDrift)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    Promote,
    Hold,
    Reject,
}

impl GateAction {
    const fn rank(self) -> u8 {
        match self {
            Self::Promote => 0,
            Self::Hold => 1,
            Self::Reject => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OracleFixtureSpec {
    pub id: String,
    pub family_id: String,
    pub goal: String,
    pub source: String,
    pub expected_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OracleFixtureCatalog {
    pub schema_version: String,
    pub parser_mode: String,
    pub fixtures: Vec<OracleFixtureSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleFixtureResult {
    pub fixture_id: String,
    pub family_id: String,
    pub goal: String,
    pub parser_mode: String,
    pub derived_seed: u64,
    pub input_hash: String,
    pub expected_hash: String,
    pub observed_hash: Option<String>,
    pub repeated_hash: Option<String>,
    pub parse_error_code: Option<String>,
    pub repeated_error_code: Option<String>,
    pub drift_class: DriftClass,
    pub comparator_decision: String,
    pub latency_ns: u64,
    pub replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleSummary {
    pub total_fixtures: u64,
    pub equivalent_count: u64,
    pub minor_drift_count: u64,
    pub critical_drift_count: u64,
    pub drift_rate_millionths: u64,
    pub counts_by_class: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExpectedLossModel {
    pub promote_loss: f64,
    pub hold_loss: f64,
    pub reject_loss: f64,
    pub recommended_action: GateAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleDecision {
    pub action: GateAction,
    pub promotion_blocked: bool,
    pub fallback_triggered: bool,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ParserOracleReport {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub partition: OraclePartition,
    pub gate_mode: OracleGateMode,
    pub parser_mode: String,
    pub fixture_catalog_path: String,
    pub fixture_catalog_hash: String,
    pub seed: u64,
    pub metamorphic_pair_budget: u32,
    pub fixture_results: Vec<OracleFixtureResult>,
    pub summary: OracleSummary,
    pub expected_loss: ExpectedLossModel,
    pub decision: OracleDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserOracleConfig {
    pub partition: OraclePartition,
    pub gate_mode: OracleGateMode,
    pub fixture_catalog_path: PathBuf,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl ParserOracleConfig {
    pub fn with_defaults(partition: OraclePartition, gate_mode: OracleGateMode, seed: u64) -> Self {
        let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        Self {
            partition,
            gate_mode,
            fixture_catalog_path: PathBuf::from(DEFAULT_FIXTURE_CATALOG_PATH),
            seed,
            trace_id: format!("trace-parser-oracle-{now}"),
            decision_id: format!("decision-parser-oracle-{now}"),
            policy_id: "policy-parser-oracle-v1".to_string(),
        }
    }
}

#[derive(Debug)]
pub enum ParserOracleError {
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
    UnknownGoal {
        fixture_id: String,
        goal: String,
    },
}

impl fmt::Display for ParserOracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "failed to read `{path}`: {source}"),
            Self::DecodeCatalog(message) => {
                write!(
                    f,
                    "failed to decode parser oracle fixture catalog: {message}"
                )
            }
            Self::InvalidCatalogSchema { expected, actual } => {
                write!(
                    f,
                    "invalid parser oracle catalog schema `{actual}` (expected `{expected}`)"
                )
            }
            Self::InvalidCatalogParserMode { expected, actual } => {
                write!(
                    f,
                    "invalid parser oracle catalog parser_mode `{actual}` (expected `{expected}`)"
                )
            }
            Self::EmptyFixtureCatalog => {
                write!(f, "parser oracle fixture catalog must not be empty")
            }
            Self::UnknownGoal { fixture_id, goal } => {
                write!(f, "fixture `{fixture_id}` has unknown parse goal `{goal}`")
            }
        }
    }
}

impl std::error::Error for ParserOracleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseObservation {
    Hash([u8; 32]),
    Error(ParseErrorCode),
}

impl ParseObservation {
    fn hash_hex(self) -> Option<String> {
        match self {
            Self::Hash(hash) => Some(format!("sha256:{}", hex::encode(hash))),
            Self::Error(_) => None,
        }
    }

    fn error_code(self) -> Option<String> {
        match self {
            Self::Hash(_) => None,
            Self::Error(code) => Some(format!("{code:?}")),
        }
    }
}

pub fn run_parser_oracle(
    config: &ParserOracleConfig,
) -> Result<ParserOracleReport, ParserOracleError> {
    let catalog = load_fixture_catalog(config.fixture_catalog_path.as_path())?;
    let fixture_catalog_hash = hash_bytes(
        &fs::read(config.fixture_catalog_path.as_path()).map_err(|source| {
            ParserOracleError::Io {
                path: config.fixture_catalog_path.display().to_string(),
                source,
            }
        })?,
    );
    let fixtures = partition_fixtures(&catalog, config.partition);
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let mut fixture_results = Vec::<OracleFixtureResult>::with_capacity(fixtures.len());
    let mut equivalent_count = 0u64;
    let mut minor_drift_count = 0u64;
    let mut critical_drift_count = 0u64;
    let mut counts_by_class = BTreeMap::<String, u64>::new();

    for fixture in fixtures {
        let parse_goal = parse_goal_from_fixture(&fixture)?;
        let derived_seed = derive_seed(
            config.seed,
            fixture.id.as_str(),
            ParserMode::ScalarReference,
        );
        let replay_command = format!(
            "cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- --partition {} --gate-mode {} --seed {} --fixture-catalog {}",
            config.partition.as_str(),
            config.gate_mode.as_str(),
            config.seed,
            config.fixture_catalog_path.display(),
        );

        let input_hash = hash_bytes(fixture.source.as_bytes());
        let parse_start = Instant::now();
        let first = observe_parse(&parser, fixture.source.as_str(), parse_goal, &options);
        let latency_ns = u64::try_from(parse_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let second = observe_parse(&parser, fixture.source.as_str(), parse_goal, &options);

        let expected_hash = normalize_hash(fixture.expected_hash.as_str());
        let drift_class = classify_observation(expected_hash.as_str(), first, second);
        let entry = counts_by_class
            .entry(format!("{drift_class:?}"))
            .or_insert(0);
        *entry = entry.saturating_add(1);

        if drift_class == DriftClass::Equivalent {
            equivalent_count = equivalent_count.saturating_add(1);
        } else if drift_class.is_minor() {
            minor_drift_count = minor_drift_count.saturating_add(1);
        } else if drift_class.is_critical() {
            critical_drift_count = critical_drift_count.saturating_add(1);
        }

        fixture_results.push(OracleFixtureResult {
            fixture_id: fixture.id.clone(),
            family_id: fixture.family_id.clone(),
            goal: fixture.goal.clone(),
            parser_mode: ParserMode::ScalarReference.as_str().to_string(),
            derived_seed,
            input_hash,
            expected_hash,
            observed_hash: first.hash_hex(),
            repeated_hash: second.hash_hex(),
            parse_error_code: first.error_code(),
            repeated_error_code: second.error_code(),
            drift_class,
            comparator_decision: drift_class.comparator_decision().to_string(),
            latency_ns,
            replay_command,
        });
    }

    let total_fixtures = u64::try_from(fixture_results.len()).unwrap_or(u64::MAX);
    let drift_rate_millionths = if total_fixtures == 0 {
        0
    } else {
        minor_drift_count
            .saturating_add(critical_drift_count)
            .saturating_mul(1_000_000)
            / total_fixtures
    };

    let summary = OracleSummary {
        total_fixtures,
        equivalent_count,
        minor_drift_count,
        critical_drift_count,
        drift_rate_millionths,
        counts_by_class,
    };
    let expected_loss = expected_loss_model(&summary);
    let decision = decide(config.gate_mode, &summary, expected_loss.recommended_action);

    Ok(ParserOracleReport {
        schema_version: "franken-engine.parser-oracle.report.v1".to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        partition: config.partition,
        gate_mode: config.gate_mode,
        parser_mode: ParserMode::ScalarReference.as_str().to_string(),
        fixture_catalog_path: config.fixture_catalog_path.display().to_string(),
        fixture_catalog_hash,
        seed: config.seed,
        metamorphic_pair_budget: config.partition.metamorphic_pairs(),
        fixture_results,
        summary,
        expected_loss,
        decision,
    })
}

pub fn derive_seed(master_seed: u64, fixture_id: &str, parser_mode: ParserMode) -> u64 {
    let payload = format!("{master_seed}:{fixture_id}:{}", parser_mode.as_str());
    let digest = Sha256::digest(payload.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes) ^ master_seed.rotate_left(13)
}

pub fn load_fixture_catalog(path: &Path) -> Result<OracleFixtureCatalog, ParserOracleError> {
    let bytes = fs::read(path).map_err(|source| ParserOracleError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let catalog: OracleFixtureCatalog = serde_json::from_slice(&bytes)
        .map_err(|error| ParserOracleError::DecodeCatalog(error.to_string()))?;
    validate_fixture_catalog(&catalog)?;
    Ok(catalog)
}

pub fn partition_fixtures(
    catalog: &OracleFixtureCatalog,
    partition: OraclePartition,
) -> Vec<OracleFixtureSpec> {
    let mut fixtures = catalog.fixtures.clone();
    fixtures.sort_by(|left, right| left.id.cmp(&right.id));
    if let Some(limit) = partition.fixture_limit() {
        fixtures.truncate(limit.min(fixtures.len()));
    }
    fixtures
}

fn validate_fixture_catalog(catalog: &OracleFixtureCatalog) -> Result<(), ParserOracleError> {
    const EXPECTED_SCHEMA: &str = "franken-engine.parser-phase0.semantic-fixtures.v1";
    let expected_mode = ParserMode::ScalarReference.as_str().to_string();
    if catalog.schema_version != EXPECTED_SCHEMA {
        return Err(ParserOracleError::InvalidCatalogSchema {
            expected: EXPECTED_SCHEMA.to_string(),
            actual: catalog.schema_version.clone(),
        });
    }
    if catalog.parser_mode != expected_mode {
        return Err(ParserOracleError::InvalidCatalogParserMode {
            expected: expected_mode,
            actual: catalog.parser_mode.clone(),
        });
    }
    if catalog.fixtures.is_empty() {
        return Err(ParserOracleError::EmptyFixtureCatalog);
    }
    Ok(())
}

fn parse_goal_from_fixture(fixture: &OracleFixtureSpec) -> Result<ParseGoal, ParserOracleError> {
    match fixture.goal.as_str() {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(ParserOracleError::UnknownGoal {
            fixture_id: fixture.id.clone(),
            goal: other.to_string(),
        }),
    }
}

fn observe_parse(
    parser: &CanonicalEs2020Parser,
    source: &str,
    goal: ParseGoal,
    options: &ParserOptions,
) -> ParseObservation {
    match parser.parse_with_options(source, goal, options) {
        Ok(tree) => {
            let digest = Sha256::digest(tree.canonical_bytes());
            let mut hash = [0u8; 32];
            hash.copy_from_slice(digest.as_slice());
            ParseObservation::Hash(hash)
        }
        Err(error) => ParseObservation::Error(error.code),
    }
}

fn classify_observation(
    expected_hash: &str,
    first: ParseObservation,
    second: ParseObservation,
) -> DriftClass {
    match (first, second) {
        (ParseObservation::Hash(first_hash), ParseObservation::Hash(second_hash)) => {
            if first_hash != second_hash {
                return DriftClass::HarnessNondeterminism;
            }

            let observed_hash = format!("sha256:{}", hex::encode(first_hash));
            if observed_hash != expected_hash {
                return DriftClass::ArtifactIntegrityFailure;
            }

            DriftClass::Equivalent
        }
        (ParseObservation::Error(first_error), ParseObservation::Error(second_error)) => {
            if first_error == second_error {
                DriftClass::DiagnosticsDrift
            } else {
                DriftClass::HarnessNondeterminism
            }
        }
        _ => DriftClass::SemanticDrift,
    }
}

fn expected_loss_model(summary: &OracleSummary) -> ExpectedLossModel {
    let total = summary.total_fixtures.max(1) as f64;
    let p_equivalent = summary.equivalent_count as f64 / total;
    let p_minor = summary.minor_drift_count as f64 / total;
    let p_critical = summary.critical_drift_count as f64 / total;

    let promote_loss = p_minor * 35.0 + p_critical * 120.0;
    let hold_loss = p_equivalent * 6.0 + p_minor * 18.0 + p_critical * 25.0;
    let reject_loss = p_equivalent * 10.0 + p_minor * 7.0 + p_critical * 4.0;

    let candidates = [
        (GateAction::Promote, promote_loss),
        (GateAction::Hold, hold_loss),
        (GateAction::Reject, reject_loss),
    ];

    let mut recommended = candidates[0];
    for candidate in &candidates[1..] {
        let loss_diff = (candidate.1 - recommended.1).abs();
        let better_loss = candidate.1 < recommended.1;
        let better_tie_break =
            loss_diff <= f64::EPSILON && candidate.0.rank() < recommended.0.rank();
        if better_loss || better_tie_break {
            recommended = *candidate;
        }
    }

    ExpectedLossModel {
        promote_loss,
        hold_loss,
        reject_loss,
        recommended_action: recommended.0,
    }
}

fn decide(
    gate_mode: OracleGateMode,
    summary: &OracleSummary,
    recommended_action: GateAction,
) -> OracleDecision {
    let fallback_triggered = summary.critical_drift_count > 0;
    let fallback_reason = if summary.critical_drift_count > 0 {
        Some("critical drift detected".to_string())
    } else if summary.minor_drift_count > 0 {
        Some("minor diagnostics drift detected".to_string())
    } else {
        None
    };

    match gate_mode {
        OracleGateMode::ReportOnly => OracleDecision {
            action: recommended_action,
            promotion_blocked: false,
            fallback_triggered,
            fallback_reason,
        },
        OracleGateMode::FailClosed => {
            if summary.critical_drift_count > 0 {
                return OracleDecision {
                    action: GateAction::Reject,
                    promotion_blocked: true,
                    fallback_triggered: true,
                    fallback_reason: Some("critical drift detected".to_string()),
                };
            }

            if summary.minor_drift_count > 0 {
                return OracleDecision {
                    action: GateAction::Hold,
                    promotion_blocked: true,
                    fallback_triggered: false,
                    fallback_reason: Some("minor diagnostics drift detected".to_string()),
                };
            }

            OracleDecision {
                action: GateAction::Promote,
                promotion_blocked: false,
                fallback_triggered: false,
                fallback_reason: None,
            }
        }
    }
}

fn normalize_hash(raw: &str) -> String {
    if raw.starts_with("sha256:") {
        raw.to_ascii_lowercase()
    } else {
        format!("sha256:{}", raw.to_ascii_lowercase())
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
