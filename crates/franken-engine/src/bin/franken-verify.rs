use std::fs;

use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, render_verdict_summary, verify_receipt_by_id,
};

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
        "",
        "exit codes:",
        "  0   verification passed",
        "  20  signature verification failure",
        "  21  transparency verification failure",
        "  22  attestation verification failure",
        "  23  stale cached data warning/failure",
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

fn load_input(path: &str) -> Result<ReceiptVerifierCliInput, String> {
    let content =
        fs::read_to_string(path).map_err(|error| format!("failed to read '{path}': {error}"))?;
    serde_json::from_str::<ReceiptVerifierCliInput>(&content)
        .map_err(|error| format!("failed to parse '{path}' as verifier JSON input: {error}"))
}
