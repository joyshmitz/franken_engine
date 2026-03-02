#![forbid(unsafe_code)]

//! Deterministic CLI wrapper around `validate_artifact_triad`.
//!
//! Exit semantics:
//! - `0` => triad is valid
//! - `2` => triad is invalid (report still emitted)
//! - `1` => CLI/runtime failure

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::rgc_test_harness::{
    HarnessLane, validate_artifact_bundle, validate_artifact_triad,
};
use serde::Serialize;

#[derive(Debug)]
struct CliArgs {
    run_dir: Option<PathBuf>,
    bundle_dir: Option<PathBuf>,
    required_lanes: Vec<HarnessLane>,
    out_path: Option<PathBuf>,
    pretty: bool,
    print_help: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "report_kind", rename_all = "snake_case")]
enum ValidatorReport {
    Triad {
        report: frankenengine_engine::rgc_test_harness::ArtifactValidationReport,
    },
    Bundle {
        report: frankenengine_engine::rgc_test_harness::ArtifactBundleValidationReport,
    },
}

impl ValidatorReport {
    fn valid(&self) -> bool {
        match self {
            Self::Triad { report } => report.valid,
            Self::Bundle { report } => report.valid,
        }
    }
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

    let report = match (&args.run_dir, &args.bundle_dir) {
        (Some(run_dir), None) => ValidatorReport::Triad {
            report: validate_artifact_triad(run_dir),
        },
        (None, Some(bundle_dir)) => ValidatorReport::Bundle {
            report: validate_artifact_bundle(bundle_dir, &args.required_lanes),
        },
        _ => {
            return Err("exactly one of --run-dir or --bundle-dir must be provided".into());
        }
    };

    let encoded = if args.pretty {
        serde_json::to_string_pretty(&report)?
    } else {
        serde_json::to_string(&report)?
    };

    if let Some(out_path) = &args.out_path {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, encoded.as_bytes())?;
    }

    println!("{encoded}");

    if report.valid() { Ok(0) } else { Ok(2) }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut run_dir = None::<PathBuf>;
    let mut bundle_dir = None::<PathBuf>;
    let mut required_lanes = Vec::<HarnessLane>::new();
    let mut out_path = None::<PathBuf>;
    let mut pretty = false;
    let mut print_help_flag = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--run-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --run-dir".to_string())?;
                run_dir = Some(PathBuf::from(value));
            }
            "--bundle-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --bundle-dir".to_string())?;
                bundle_dir = Some(PathBuf::from(value));
            }
            "--required-lanes" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --required-lanes".to_string())?;
                required_lanes = parse_required_lanes(&value)?;
            }
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_path = Some(PathBuf::from(value));
            }
            "--pretty" => {
                pretty = true;
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

    if run_dir.is_some() && bundle_dir.is_some() {
        return Err("`--run-dir` and `--bundle-dir` are mutually exclusive".into());
    }
    if !required_lanes.is_empty() && bundle_dir.is_none() {
        return Err("`--required-lanes` requires `--bundle-dir`".into());
    }

    let (run_dir, bundle_dir) = if print_help_flag {
        (None, None)
    } else {
        if run_dir.is_none() && bundle_dir.is_none() {
            return Err("one of `--run-dir` or `--bundle-dir` is required".into());
        }
        (run_dir, bundle_dir)
    };

    Ok(CliArgs {
        run_dir,
        bundle_dir,
        required_lanes,
        out_path,
        pretty,
        print_help: print_help_flag,
    })
}

fn print_help() {
    println!(
        "Usage: cargo run -p frankenengine-engine --bin rgc_artifact_validator -- \\
  (--run-dir <path> | --bundle-dir <path>) [--required-lanes <csv>] [--out <path>] [--pretty]\n\
\n\
`--run-dir` validates one triad (`run_manifest.json`, `events.jsonl`, `commands.txt`).\n\
`--bundle-dir` validates all child triads plus advanced cross-lane correlation checks.\n\
Use `--required-lanes runtime,security,e2e` to fail when required lanes are absent.\n\
Exit code 2 indicates a deterministic validation failure."
    );
}

fn parse_required_lanes(raw: &str) -> Result<Vec<HarnessLane>, Box<dyn Error>> {
    let mut lanes = Vec::new();
    for token in raw.split(',') {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        let lane = match normalized.as_str() {
            "parser" => HarnessLane::Parser,
            "runtime" => HarnessLane::Runtime,
            "security" => HarnessLane::Security,
            "governance" => HarnessLane::Governance,
            "e2e" => HarnessLane::E2e,
            _ => {
                return Err(format!(
                    "unsupported lane `{}` (expected parser|runtime|security|governance|e2e)",
                    token.trim()
                )
                .into());
            }
        };
        if !lanes.contains(&lane) {
            lanes.push(lane);
        }
    }
    Ok(lanes)
}
