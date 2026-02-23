use std::fs;

use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, render_verdict_summary, verify_receipt_by_id,
};
use frankenengine_engine::third_party_verifier::{
    BenchmarkClaimBundle, ContainmentClaimBundle, ReplayClaimBundle, render_report_summary,
    verify_benchmark_claim, verify_containment_claim, verify_replay_claim,
};
use serde::de::DeserializeOwned;

fn main() {
    let exit_code = match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn run(args: Vec<String>) -> Result<i32, String> {
    if args.is_empty() {
        return Err(usage());
    }

    match args[0].as_str() {
        "receipt" => run_receipt(&args[1..]),
        "benchmark" => run_benchmark(&args[1..]),
        "replay" => run_replay(&args[1..]),
        "containment" => run_containment(&args[1..]),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(0)
        }
        other => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
    }
}

fn usage() -> String {
    [
        "franken-verify usage:",
        "  franken-verify receipt <receipt_id> --input <path> [--summary]",
        "  franken-verify benchmark --input <path> [--summary]",
        "  franken-verify replay --input <path> [--summary]",
        "  franken-verify containment --input <path> [--summary]",
        "",
        "exit codes:",
        "  0   verification passed",
        "  20  signature verification failure",
        "  21  transparency verification failure",
        "  22  attestation verification failure",
        "  23  stale cached data warning/failure",
        "  24  partially verified (checks skipped)",
        "  25  verification failed",
        "  26  inconclusive verification",
        "  2   CLI/input error",
    ]
    .join("\n")
}

fn run_receipt(args: &[String]) -> Result<i32, String> {
    let receipt_id = args
        .first()
        .ok_or_else(|| format!("receipt subcommand requires <receipt_id>\n\n{}", usage()))?;

    let mut input_path: Option<&str> = None;
    let mut summary = false;

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            flag => return Err(format!("unknown flag for receipt: {flag}")),
        }
        index += 1;
    }

    let input_path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(input_path)?;
    let verdict = verify_receipt_by_id(&input, receipt_id).map_err(|error| error.to_string())?;

    if summary {
        println!("{}", render_verdict_summary(&verdict));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&verdict)
                .map_err(|error| format!("failed to encode verifier output: {error}"))?
        );
    }
    Ok(verdict.exit_code)
}

fn run_benchmark(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "benchmark")?;
    let input = load_json::<BenchmarkClaimBundle>(input_path, "benchmark bundle")?;
    let report = verify_benchmark_claim(&input);
    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn run_replay(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "replay")?;
    let input = load_json::<ReplayClaimBundle>(input_path, "replay bundle")?;
    let report = verify_replay_claim(&input);
    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn run_containment(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "containment")?;
    let input = load_json::<ContainmentClaimBundle>(input_path, "containment bundle")?;
    let report = verify_containment_claim(&input);
    print_report(&report, summary)?;
    Ok(report.exit_code())
}

fn parse_input_flags<'a>(args: &'a [String], subcommand: &str) -> Result<(&'a str, bool), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--input requires a path".to_string())?;
                input_path = Some(value);
            }
            "--summary" => summary = true,
            flag => return Err(format!("unknown flag for {subcommand}: {flag}")),
        }
        index += 1;
    }

    let input_path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    Ok((input_path, summary))
}

fn print_report(
    report: &frankenengine_engine::third_party_verifier::ThirdPartyVerificationReport,
    summary: bool,
) -> Result<(), String> {
    if summary {
        println!("{}", render_report_summary(report));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(report)
                .map_err(|error| format!("failed to encode verifier output: {error}"))?
        );
    }
    Ok(())
}

fn load_input(path: &str) -> Result<ReceiptVerifierCliInput, String> {
    load_json::<ReceiptVerifierCliInput>(path, "verifier JSON input")
}

fn load_json<T: DeserializeOwned>(path: &str, label: &str) -> Result<T, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("failed to read '{path}': {error}"))?;
    serde_json::from_str::<T>(&content)
        .map_err(|error| format!("failed to parse '{path}' as {label}: {error}"))
}
