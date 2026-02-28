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

use frankenengine_engine::rgc_test_harness::validate_artifact_triad;

#[derive(Debug)]
struct CliArgs {
    run_dir: PathBuf,
    out_path: Option<PathBuf>,
    pretty: bool,
    print_help: bool,
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

    let report = validate_artifact_triad(&args.run_dir);
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

    if report.valid { Ok(0) } else { Ok(2) }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut run_dir = None::<PathBuf>;
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

    let run_dir = if print_help_flag {
        PathBuf::new()
    } else {
        run_dir.ok_or_else(|| "--run-dir is required".to_string())?
    };

    Ok(CliArgs {
        run_dir,
        out_path,
        pretty,
        print_help: print_help_flag,
    })
}

fn print_help() {
    println!(
        "Usage: cargo run -p frankenengine-engine --bin rgc_artifact_validator -- \\
  --run-dir <path> [--out <path>] [--pretty]\n\
\n\
Validates `run_manifest.json`, `events.jsonl`, and `commands.txt` for a run directory.\n\
Exit code 2 indicates a deterministic validation failure."
    );
}
