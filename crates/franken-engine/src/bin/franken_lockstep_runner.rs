#![forbid(unsafe_code)]

//! `franken_lockstep_runner` is the canonical lockstep harness entrypoint.
//!
//! It reuses the parser multi-engine harness substrate so lockstep runs can
//! compare FrankenEngine against pinned external engines with deterministic
//! seeds, stable drift taxonomy, and replayable JSON reports.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

use frankenengine_engine::parser_multi_engine_harness::{
    DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH, HarnessEngineKind, HarnessEngineSpec,
    MultiEngineHarnessConfig, MultiEngineHarnessReport, run_multi_engine_harness,
};
use serde::{Deserialize, Serialize};

const LOCKSTEP_RUNTIME_SPECS_SCHEMA_VERSION: &str = "franken-engine.lockstep-runtimes.v1";
const LOCKSTEP_EVIDENCE_SCHEMA_VERSION: &str = "franken-engine.lockstep-evidence.v1";
const DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH: &str =
    "crates/franken-engine/tests/fixtures/lockstep_runtimes.toml";

#[derive(Debug)]
struct CliArgs {
    config: MultiEngineHarnessConfig,
    out_path: Option<PathBuf>,
    evidence_jsonl_path: Option<PathBuf>,
    fail_on_divergence: bool,
    preflight_only: bool,
    print_help: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EngineSpecFile {
    Array(Vec<HarnessEngineSpec>),
    Wrapped { engines: Vec<HarnessEngineSpec> },
}

#[derive(Debug, Deserialize)]
struct LockstepRuntimeSpecsFile {
    schema_version: String,
    runtimes: Vec<LockstepRuntimeSpec>,
}

#[derive(Debug, Deserialize)]
struct LockstepRuntimeSpec {
    runtime_id: String,
    display_name: String,
    version_pin: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_runtime_enabled")]
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct LockstepRuntimeVersion {
    engine_id: String,
    version_pin: String,
}

#[derive(Debug, Serialize)]
struct LockstepCategoryMatchRate {
    total_fixtures: u64,
    equivalent_fixtures: u64,
    match_rate_ppm: u64,
}

#[derive(Debug, Serialize)]
struct LockstepEvidenceRecord {
    schema_version: String,
    generated_at_utc: String,
    run_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    fixture_catalog_hash: String,
    parser_mode: String,
    seed: u64,
    locale: String,
    timezone: String,
    fixture_count: u64,
    equivalent_fixtures: u64,
    divergent_fixtures: u64,
    nondeterministic_fixtures: u64,
    divergence_class_distribution: BTreeMap<String, u64>,
    runtime_versions: Vec<LockstepRuntimeVersion>,
    category_match_rates: BTreeMap<String, LockstepCategoryMatchRate>,
}

fn default_runtime_enabled() -> bool {
    true
}

fn main() {
    match run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let args = parse_args(std::env::args().skip(1))?;
    if args.print_help {
        return Ok(0);
    }
    if args.preflight_only {
        run_preflight(&args.config)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "preflight_passed": true,
                "engine_count": args.config.engines.len(),
            }))?
        );
        return Ok(0);
    }

    let mut report = run_multi_engine_harness(&args.config)?;
    rewrite_replay_commands_for_lockstep_runner(&mut report);
    if let Some(evidence_jsonl_path) = &args.evidence_jsonl_path {
        append_lockstep_evidence_jsonl(evidence_jsonl_path, &report)?;
    }
    let json = serde_json::to_string_pretty(&report)?;

    if let Some(out_path) = &args.out_path {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, json.as_bytes())?;
    }

    println!("{json}");

    if args.fail_on_divergence
        && (report.summary.divergent_fixtures > 0
            || report.summary.fixtures_with_nondeterminism > 0)
    {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn rewrite_replay_commands_for_lockstep_runner(report: &mut MultiEngineHarnessReport) {
    for fixture in &mut report.fixture_results {
        fixture.replay_command = fixture.replay_command.replace(
            "--bin franken_parser_multi_engine_harness",
            "--bin franken_lockstep_runner",
        );
    }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut seed = 1_u64;
    let mut fixture_catalog = PathBuf::from(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH);
    let mut fixture_limit = Some(8_usize);
    let mut fixture_id_filter = None::<String>;
    let mut trace_id = None::<String>;
    let mut decision_id = None::<String>;
    let mut policy_id = None::<String>;
    let mut locale = None::<String>;
    let mut timezone = None::<String>;
    let mut engine_specs = None::<Vec<HarnessEngineSpec>>;
    let mut runtime_specs_path = None::<PathBuf>;
    let mut out_path = None::<PathBuf>;
    let mut evidence_jsonl_path = None::<PathBuf>;
    let mut fail_on_divergence = false;
    let mut preflight_only = false;
    let mut print_help_flag = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--fixture-catalog" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-catalog".to_string())?;
                fixture_catalog = PathBuf::from(value);
            }
            "--fixture-limit" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-limit".to_string())?;
                fixture_limit = parse_fixture_limit(value.as_str())?;
            }
            "--fixture-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-id".to_string())?;
                fixture_id_filter = Some(value);
            }
            "--seed" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --seed".to_string())?;
                seed = value.parse::<u64>()?;
            }
            "--trace-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --trace-id".to_string())?;
                trace_id = Some(value);
            }
            "--decision-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --decision-id".to_string())?;
                decision_id = Some(value);
            }
            "--policy-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --policy-id".to_string())?;
                policy_id = Some(value);
            }
            "--locale" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --locale".to_string())?;
                locale = Some(value);
            }
            "--timezone" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --timezone".to_string())?;
                timezone = Some(value);
            }
            "--engine-specs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --engine-specs".to_string())?;
                engine_specs = Some(load_engine_specs(Path::new(value.as_str()))?);
            }
            "--runtime-specs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --runtime-specs".to_string())?;
                runtime_specs_path = Some(PathBuf::from(value));
            }
            "--fail-on-divergence" => {
                fail_on_divergence = true;
            }
            "--preflight-only" => {
                preflight_only = true;
            }
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_path = Some(PathBuf::from(value));
            }
            "--evidence-jsonl" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --evidence-jsonl".to_string())?;
                evidence_jsonl_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_help();
                print_help_flag = true;
            }
            other => {
                return Err(format!("unknown argument `{other}`").into());
            }
        }
    }

    let mut config = MultiEngineHarnessConfig::with_defaults(seed);
    config.fixture_catalog_path = fixture_catalog;
    config.fixture_limit = fixture_limit;
    config.fixture_id_filter = fixture_id_filter;
    if let Some(value) = trace_id {
        config.trace_id = value;
    }
    if let Some(value) = decision_id {
        config.decision_id = value;
    }
    if let Some(value) = policy_id {
        config.policy_id = value;
    }
    if let Some(value) = locale {
        config.locale = value;
    }
    if let Some(value) = timezone {
        config.timezone = value;
    }
    if engine_specs.is_some() && runtime_specs_path.is_some() {
        return Err("cannot combine --engine-specs with --runtime-specs".into());
    }
    if let Some(path) = runtime_specs_path {
        config.engines = load_runtime_engine_specs(path.as_path())?;
    } else if let Some(specs) = engine_specs {
        config.engines = specs;
    } else if Path::new(DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH).exists() {
        config.engines = load_runtime_engine_specs(Path::new(DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH))?;
    }

    Ok(CliArgs {
        config,
        out_path,
        evidence_jsonl_path,
        fail_on_divergence,
        preflight_only,
        print_help: print_help_flag,
    })
}

fn parse_fixture_limit(value: &str) -> Result<Option<usize>, Box<dyn Error>> {
    if value.eq_ignore_ascii_case("none") {
        Ok(None)
    } else {
        Ok(Some(value.parse::<usize>()?))
    }
}

fn run_preflight(config: &MultiEngineHarnessConfig) -> Result<(), Box<dyn Error>> {
    for engine in &config.engines {
        if !matches!(engine.kind, HarnessEngineKind::ExternalCommand) {
            continue;
        }
        let command = engine
            .command
            .as_deref()
            .ok_or_else(|| format!("external engine `{}` has no command", engine.engine_id))?;
        if !command_exists(command) {
            return Err(format!(
                "external engine `{}` command `{}` not found in PATH",
                engine.engine_id, command
            )
            .into());
        }

        for arg in &engine.args {
            if !looks_like_script_path(arg) {
                continue;
            }
            let script_path = Path::new(arg);
            if !script_path.exists() {
                return Err(format!(
                    "external engine `{}` expected script path `{}` to exist (cwd: {})",
                    engine.engine_id,
                    script_path.display(),
                    std::env::current_dir()?.display()
                )
                .into());
            }
        }
    }
    Ok(())
}

fn command_exists(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }

    let command_path = Path::new(command);
    if command_path.is_absolute()
        || command.contains(std::path::MAIN_SEPARATOR)
        || command.contains('/')
        || command.contains('\\')
    {
        return command_path.is_file();
    }

    std::env::var_os("PATH").is_some_and(|path_value| {
        std::env::split_paths(&path_value).any(|entry| entry.join(command).is_file())
    })
}

fn looks_like_script_path(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
}

fn append_lockstep_evidence_jsonl(
    path: &Path,
    report: &MultiEngineHarnessReport,
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let evidence = build_lockstep_evidence_record(report);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    serde_json::to_writer(&mut file, &evidence)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn build_lockstep_evidence_record(report: &MultiEngineHarnessReport) -> LockstepEvidenceRecord {
    let runtime_versions = collect_runtime_versions(report);
    let category_match_rates = collect_category_match_rates(report);
    LockstepEvidenceRecord {
        schema_version: LOCKSTEP_EVIDENCE_SCHEMA_VERSION.to_string(),
        generated_at_utc: report.generated_at_utc.clone(),
        run_id: report.run_id.clone(),
        trace_id: report.trace_id.clone(),
        decision_id: report.decision_id.clone(),
        policy_id: report.policy_id.clone(),
        fixture_catalog_hash: report.fixture_catalog_hash.clone(),
        parser_mode: report.parser_mode.clone(),
        seed: report.seed,
        locale: report.locale.clone(),
        timezone: report.timezone.clone(),
        fixture_count: report.fixture_count,
        equivalent_fixtures: report.summary.equivalent_fixtures,
        divergent_fixtures: report.summary.divergent_fixtures,
        nondeterministic_fixtures: report.summary.fixtures_with_nondeterminism,
        divergence_class_distribution: report.summary.drift_counts_by_category.clone(),
        runtime_versions,
        category_match_rates,
    }
}

fn collect_runtime_versions(report: &MultiEngineHarnessReport) -> Vec<LockstepRuntimeVersion> {
    let mut runtime_versions = report
        .engine_specs
        .iter()
        .map(|engine| LockstepRuntimeVersion {
            engine_id: engine.engine_id.clone(),
            version_pin: engine.version_pin.clone(),
        })
        .collect::<Vec<_>>();
    runtime_versions.sort_by(|left, right| left.engine_id.cmp(&right.engine_id));
    runtime_versions
}

fn collect_category_match_rates(
    report: &MultiEngineHarnessReport,
) -> BTreeMap<String, LockstepCategoryMatchRate> {
    let mut counts = BTreeMap::<String, (u64, u64)>::new();
    for fixture in &report.fixture_results {
        let entry = counts.entry(fixture.family_id.clone()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        if fixture.equivalent_across_engines {
            entry.1 = entry.1.saturating_add(1);
        }
    }

    counts
        .into_iter()
        .map(|(family_id, (total, equivalent))| {
            let match_rate_ppm = if total == 0 {
                0
            } else {
                ((equivalent as u128 * 1_000_000) / total as u128) as u64
            };
            (
                family_id,
                LockstepCategoryMatchRate {
                    total_fixtures: total,
                    equivalent_fixtures: equivalent,
                    match_rate_ppm,
                },
            )
        })
        .collect()
}

fn load_engine_specs(path: &Path) -> Result<Vec<HarnessEngineSpec>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let parsed = serde_json::from_slice::<EngineSpecFile>(&bytes)?;
    let specs = match parsed {
        EngineSpecFile::Array(specs) => specs,
        EngineSpecFile::Wrapped { engines } => engines,
    };
    if specs.is_empty() {
        return Err(format!("engine spec file `{}` must not be empty", path.display()).into());
    }
    Ok(specs)
}

fn load_runtime_engine_specs(path: &Path) -> Result<Vec<HarnessEngineSpec>, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let parsed = toml::from_str::<LockstepRuntimeSpecsFile>(&content)?;
    if parsed.schema_version != LOCKSTEP_RUNTIME_SPECS_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime spec file `{}` has schema_version `{}` (expected `{}`)",
                path.display(),
                parsed.schema_version,
                LOCKSTEP_RUNTIME_SPECS_SCHEMA_VERSION
            ),
        )
        .into());
    }
    if parsed.runtimes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("runtime spec file `{}` must not be empty", path.display()),
        )
        .into());
    }

    let mut engines = vec![HarnessEngineSpec::franken_canonical(
        "frankenengine-engine@workspace",
    )];
    let mut ids = BTreeSet::new();
    ids.insert("franken_canonical".to_string());

    for runtime in parsed
        .runtimes
        .into_iter()
        .filter(|runtime| runtime.enabled)
    {
        if runtime.runtime_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime spec file `{}` has entry with empty runtime_id",
                    path.display()
                ),
            )
            .into());
        }
        if runtime.version_pin.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime `{}` in `{}` has empty version_pin",
                    runtime.runtime_id,
                    path.display()
                ),
            )
            .into());
        }
        if runtime.command.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime `{}` in `{}` has empty command",
                    runtime.runtime_id,
                    path.display()
                ),
            )
            .into());
        }
        if !ids.insert(runtime.runtime_id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime `{}` appears more than once in `{}`",
                    runtime.runtime_id,
                    path.display()
                ),
            )
            .into());
        }
        engines.push(HarnessEngineSpec {
            engine_id: runtime.runtime_id,
            display_name: runtime.display_name,
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: runtime.version_pin,
            command: Some(runtime.command),
            args: runtime.args,
        });
    }

    let mut missing_required = Vec::new();
    for required_runtime in ["node", "bun"] {
        if !ids.contains(required_runtime) {
            missing_required.push(required_runtime);
        }
    }
    if !missing_required.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime spec file `{}` must include enabled runtime_id entries for {}",
                path.display(),
                missing_required.join(", ")
            ),
        )
        .into());
    }

    if engines.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime spec file `{}` must include at least one enabled runtime",
                path.display()
            ),
        )
        .into());
    }

    Ok(engines)
}

fn print_help() {
    println!("franken_lockstep_runner");
    println!("  --fixture-catalog <path>");
    println!("  --fixture-limit <usize|none>");
    println!("  --fixture-id <fixture-id>");
    println!("  --seed <u64>");
    println!("  --trace-id <id>");
    println!("  --decision-id <id>");
    println!("  --policy-id <id>");
    println!("  --locale <locale>");
    println!("  --timezone <timezone>");
    println!("  --engine-specs <path>");
    println!("  --runtime-specs <path>");
    println!("  --fail-on-divergence");
    println!("  --preflight-only");
    println!("  --out <path>");
    println!("  --evidence-jsonl <path>");
    println!("  default runtime-specs path: {DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH}");
}
