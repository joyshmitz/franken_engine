#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use frankenengine_engine::adversarial_campaign::{
    SuppressionGateConfig, SuppressionGateInput, SuppressionGateResult,
    evaluate_compromise_suppression_gate,
};
use serde::Serialize;

const REPORT_SCHEMA_VERSION: &str = "franken-engine.adversarial-campaign-gate-report.v1";

#[derive(Debug)]
struct CliArgs {
    input_path: PathBuf,
    config_path: Option<PathBuf>,
    out_path: Option<PathBuf>,
    summary: bool,
    print_help: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SuppressionGateCliReport {
    schema_version: String,
    generated_at_utc: String,
    input_path: String,
    config: SuppressionGateConfig,
    result: SuppressionGateResult,
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

    let gate_input = load_json::<SuppressionGateInput>(&args.input_path)?;
    let gate_config = match &args.config_path {
        Some(path) => load_json::<SuppressionGateConfig>(path)?,
        None => SuppressionGateConfig::default(),
    };

    let gate_result = evaluate_compromise_suppression_gate(&gate_input, &gate_config)?;
    let report = SuppressionGateCliReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        input_path: args.input_path.display().to_string(),
        config: gate_config,
        result: gate_result,
    };

    let json = serde_json::to_string_pretty(&report)?;
    if let Some(out_path) = &args.out_path {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, json.as_bytes())?;
    }

    if args.summary {
        println!("suppression_gate.schema_version={}", report.schema_version);
        println!("suppression_gate.input_path={}", report.input_path);
        println!(
            "suppression_gate.release_candidate_id={}",
            report.result.release_candidate_id
        );
        println!(
            "suppression_gate.passed={}",
            if report.result.passed { "true" } else { "false" }
        );
        println!(
            "suppression_gate.failures={}",
            report.result.failures.len()
        );
        println!(
            "suppression_gate.comparisons={}",
            report.result.comparisons.len()
        );
        println!(
            "suppression_gate.events={}",
            report.result.events.len()
        );
    } else {
        println!("{json}");
    }

    if report.result.passed { Ok(0) } else { Ok(2) }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut input_path = None::<PathBuf>;
    let mut config_path = None::<PathBuf>;
    let mut out_path = None::<PathBuf>;
    let mut summary = false;
    let mut print_help_flag = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --input".to_string())?;
                input_path = Some(PathBuf::from(value));
            }
            "--config" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --config".to_string())?;
                config_path = Some(PathBuf::from(value));
            }
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_path = Some(PathBuf::from(value));
            }
            "--summary" => summary = true,
            "--help" | "-h" => {
                print_help();
                print_help_flag = true;
            }
            other => return Err(format!("unknown argument `{other}`").into()),
        }
    }

    let Some(input_path) = input_path else {
        return Err("missing required --input <path>".into());
    };

    Ok(CliArgs {
        input_path,
        config_path,
        out_path,
        summary,
        print_help: print_help_flag,
    })
}

fn load_json<T>(path: &Path) -> Result<T, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice::<T>(&bytes)?)
}

fn print_help() {
    println!("franken_adversarial_campaign_gate");
    println!("  --input <path>     Required suppression gate input JSON");
    println!("  --config <path>    Optional suppression gate config JSON");
    println!("  --out <path>       Optional output path for gate report JSON");
    println!("  --summary          Print stable key=value summary instead of JSON");
    println!("  --help, -h         Show this message");
    println!();
    println!("exit codes:");
    println!("  0   gate passed");
    println!("  2   gate failed (comparisons/failures did not satisfy thresholds)");
    println!("  1   CLI/input/runtime error");
}
