#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::frx_lockstep_oracle::{FrxLockstepRunContext, run_lockstep_oracle};

const DEFAULT_TRACES_DIR: &str = "crates/franken-engine/tests/conformance/frx_react_corpus/traces";

#[derive(Debug)]
struct CliArgs {
    react_traces_dir: PathBuf,
    franken_traces_dir: PathBuf,
    fixture_ref: Option<String>,
    out_path: Option<PathBuf>,
    fail_on_divergence: bool,
    context: FrxLockstepRunContext,
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

    let report = run_lockstep_oracle(
        args.react_traces_dir.as_path(),
        args.franken_traces_dir.as_path(),
        args.context,
        args.fixture_ref.as_deref(),
    )?;

    let report_json = serde_json::to_string_pretty(&report)?;
    if let Some(out_path) = args.out_path {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, report_json.as_bytes())?;
    }

    println!("{report_json}");
    if args.fail_on_divergence && report.summary.failed_cases > 0 {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut react_traces_dir = PathBuf::from(DEFAULT_TRACES_DIR);
    let mut franken_traces_dir = PathBuf::from(DEFAULT_TRACES_DIR);
    let mut fixture_ref = None::<String>;
    let mut out_path = None::<PathBuf>;
    let mut fail_on_divergence = false;
    let mut print_help_flag = false;

    let mut trace_id = None::<String>;
    let mut decision_id = None::<String>;
    let mut policy_id = None::<String>;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--react-traces-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --react-traces-dir".to_string())?;
                react_traces_dir = PathBuf::from(value);
            }
            "--franken-traces-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --franken-traces-dir".to_string())?;
                franken_traces_dir = PathBuf::from(value);
            }
            "--fixture-ref" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-ref".to_string())?;
                fixture_ref = Some(value);
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
            "--fail-on-divergence" => {
                fail_on_divergence = true;
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

    let mut context = FrxLockstepRunContext::with_defaults();
    if let Some(value) = trace_id {
        context.trace_id = value;
    }
    if let Some(value) = decision_id {
        context.decision_id = value;
    }
    if let Some(value) = policy_id {
        context.policy_id = value;
    }

    Ok(CliArgs {
        react_traces_dir,
        franken_traces_dir,
        fixture_ref,
        out_path,
        fail_on_divergence,
        context,
        print_help: print_help_flag,
    })
}

fn print_help() {
    println!("frx_lockstep_oracle");
    println!("  --react-traces-dir <path>");
    println!("  --franken-traces-dir <path>");
    println!("  --fixture-ref <fixture-ref>");
    println!("  --trace-id <id>");
    println!("  --decision-id <id>");
    println!("  --policy-id <id>");
    println!("  --out <path>");
    println!("  --fail-on-divergence");
    println!("  default traces dir: {DEFAULT_TRACES_DIR}");
}
