#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::parser_oracle::{
    OracleGateMode, OraclePartition, ParserOracleConfig, run_parser_oracle,
};

#[derive(Debug)]
struct CliArgs {
    config: ParserOracleConfig,
    out_path: Option<PathBuf>,
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
    let report = run_parser_oracle(&args.config)?;
    let json = serde_json::to_string_pretty(&report)?;

    if let Some(out_path) = &args.out_path {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, json.as_bytes())?;
    }

    println!("{json}");

    if args.config.gate_mode == OracleGateMode::FailClosed && report.decision.promotion_blocked {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut partition = OraclePartition::Smoke;
    let mut gate_mode = OracleGateMode::ReportOnly;
    let mut seed = 1u64;
    let mut fixture_catalog =
        PathBuf::from(frankenengine_engine::parser_oracle::DEFAULT_FIXTURE_CATALOG_PATH);
    let mut trace_id = None::<String>;
    let mut decision_id = None::<String>;
    let mut policy_id = None::<String>;
    let mut out_path = None::<PathBuf>;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--partition" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --partition".to_string())?;
                partition = value.parse::<OraclePartition>()?;
            }
            "--gate-mode" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --gate-mode".to_string())?;
                gate_mode = value.parse::<OracleGateMode>()?;
            }
            "--seed" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --seed".to_string())?;
                seed = value.parse::<u64>()?;
            }
            "--fixture-catalog" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-catalog".to_string())?;
                fixture_catalog = PathBuf::from(value);
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
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_help();
                return Ok(CliArgs {
                    config: ParserOracleConfig::with_defaults(partition, gate_mode, seed),
                    out_path,
                });
            }
            other => {
                return Err(format!("unknown argument `{other}`").into());
            }
        }
    }

    let mut config = ParserOracleConfig::with_defaults(partition, gate_mode, seed);
    config.fixture_catalog_path = fixture_catalog;
    if let Some(value) = trace_id {
        config.trace_id = value;
    }
    if let Some(value) = decision_id {
        config.decision_id = value;
    }
    if let Some(value) = policy_id {
        config.policy_id = value;
    }

    Ok(CliArgs { config, out_path })
}

fn print_help() {
    println!("franken_parser_oracle_report");
    println!("  --partition <smoke|full|nightly>");
    println!("  --gate-mode <report_only|fail_closed>");
    println!("  --seed <u64>");
    println!("  --fixture-catalog <path>");
    println!("  --trace-id <id>");
    println!("  --decision-id <id>");
    println!("  --policy-id <id>");
    println!("  --out <path>");
}
