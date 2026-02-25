#![forbid(unsafe_code)]

//! `franken_lockstep_runner` is the canonical lockstep harness entrypoint.
//!
//! It reuses the parser multi-engine harness substrate so lockstep runs can
//! compare FrankenEngine against pinned external engines with deterministic
//! seeds, stable drift taxonomy, and replayable JSON reports.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::{collections::BTreeSet, io};

use frankenengine_engine::parser_multi_engine_harness::{
    DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH, HarnessEngineKind, HarnessEngineSpec,
    MultiEngineHarnessConfig, MultiEngineHarnessReport, run_multi_engine_harness,
};
use serde::Deserialize;

const LOCKSTEP_RUNTIME_SPECS_SCHEMA_VERSION: &str = "franken-engine.lockstep-runtimes.v1";
const DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH: &str =
    "crates/franken-engine/tests/fixtures/lockstep_runtimes.toml";

#[derive(Debug)]
struct CliArgs {
    config: MultiEngineHarnessConfig,
    out_path: Option<PathBuf>,
    fail_on_divergence: bool,
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

    let mut report = run_multi_engine_harness(&args.config)?;
    rewrite_replay_commands_for_lockstep_runner(&mut report);
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
    let mut fail_on_divergence = false;
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
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_path = Some(PathBuf::from(value));
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
    }

    Ok(CliArgs {
        config,
        out_path,
        fail_on_divergence,
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
    println!("  --out <path>");
    println!("  default runtime-specs path: {DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH}");
}
