use std::collections::BTreeMap;
use std::fs;

use frankenengine_engine::causal_replay::CounterfactualConfig;
use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, render_verdict_summary, verify_receipt_by_id,
};
use frankenengine_engine::third_party_verifier::{
    BenchmarkClaimBundle, ContainmentClaimBundle, ReplayClaimBundle, VerificationAttestation,
    VerificationAttestationInput, generate_attestation, render_attestation_summary,
    render_report_summary, verify_attestation, verify_benchmark_claim, verify_containment_claim,
    verify_replay_claim,
};
use serde::{Deserialize, de::DeserializeOwned};

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
        "attestation" => run_attestation(&args[1..]),
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
        "      [--signature-key-hex <hex> | --signature-key-file <path>]",
        "      [--receipt-key <signer_hex>=<verification_key_hex>]...",
        "      [--receipt-key-file <path>]...",
        "      [--counterfactual-config-file <path>]...",
        "  franken-verify containment --input <path> [--summary]",
        "  franken-verify attestation create --input <path> [--summary]",
        "  franken-verify attestation verify --input <path> [--summary]",
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
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut signature_key_hex: Option<String> = None;
    let mut receipt_key_overrides = Vec::<String>::new();
    let mut receipt_key_files = Vec::<String>::new();
    let mut counterfactual_config_files = Vec::<String>::new();

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
            "--signature-key-hex" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signature-key-hex requires a value".to_string())?;
                signature_key_hex = Some(value.trim().to_string());
            }
            "--signature-key-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signature-key-file requires a path".to_string())?;
                signature_key_hex = Some(load_trimmed_file(value, "signature key file")?);
            }
            "--receipt-key" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    "--receipt-key requires <signer_hex>=<verification_key_hex>".to_string()
                })?;
                receipt_key_overrides.push(value.to_string());
            }
            "--receipt-key-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--receipt-key-file requires a path".to_string())?;
                receipt_key_files.push(value.to_string());
            }
            "--counterfactual-config-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--counterfactual-config-file requires a path".to_string())?;
                counterfactual_config_files.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for replay: {flag}")),
        }
        index += 1;
    }

    let input_path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let mut input = load_json::<ReplayClaimBundle>(input_path, "replay bundle")?;

    if let Some(hex) = signature_key_hex {
        input.signature_verification_key_hex = Some(hex);
    }

    for path in receipt_key_files {
        let parsed = load_receipt_key_map(&path)?;
        input.receipt_verification_keys_hex.extend(parsed);
    }

    for raw in receipt_key_overrides {
        let (signer_id_hex, key_hex) = parse_receipt_key_pair(raw.trim())?;
        input
            .receipt_verification_keys_hex
            .insert(signer_id_hex, key_hex);
    }

    for path in counterfactual_config_files {
        let mut parsed = load_counterfactual_configs(&path)?;
        input.counterfactual_configs.append(&mut parsed);
    }

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

fn run_attestation(args: &[String]) -> Result<i32, String> {
    let mode = args.first().ok_or_else(|| {
        format!(
            "attestation subcommand requires 'create' or 'verify'\n\n{}",
            usage()
        )
    })?;
    match mode.as_str() {
        "create" => run_attestation_create(&args[1..]),
        "verify" => run_attestation_verify(&args[1..]),
        other => Err(format!(
            "unknown attestation mode '{other}' (expected 'create' or 'verify')"
        )),
    }
}

fn run_attestation_create(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "attestation create")?;
    let input = load_json::<VerificationAttestationInput>(input_path, "attestation input")?;
    let attestation = generate_attestation(&input)?;
    if summary {
        println!("{}", render_attestation_summary(&attestation));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&attestation)
                .map_err(|error| format!("failed to encode attestation output: {error}"))?
        );
    }
    Ok(0)
}

fn run_attestation_verify(args: &[String]) -> Result<i32, String> {
    let (input_path, summary) = parse_input_flags(args, "attestation verify")?;
    let input = load_json::<VerificationAttestation>(input_path, "attestation")?;
    let report = verify_attestation(&input);
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

fn parse_receipt_key_pair(raw: &str) -> Result<(String, String), String> {
    let (signer_id_hex, key_hex) = raw
        .split_once('=')
        .ok_or_else(|| "--receipt-key expects <signer_hex>=<verification_key_hex>".to_string())?;
    let signer_id_hex = signer_id_hex.trim();
    let key_hex = key_hex.trim();
    if signer_id_hex.is_empty() || key_hex.is_empty() {
        return Err("--receipt-key requires non-empty signer and key hex values".to_string());
    }
    Ok((signer_id_hex.to_string(), key_hex.to_string()))
}

fn load_receipt_key_map(path: &str) -> Result<BTreeMap<String, String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read receipt-key file '{path}': {error}"))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(format!("receipt-key file '{path}' is empty"));
    }

    if trimmed.starts_with('{') {
        return serde_json::from_str::<BTreeMap<String, String>>(trimmed).map_err(|error| {
            format!("failed to parse receipt-key file '{path}' as JSON signer->key map: {error}")
        });
    }

    let mut parsed = BTreeMap::new();
    for (line_index, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (signer_id_hex, key_hex) = parse_receipt_key_pair(line).map_err(|error| {
            format!(
                "receipt-key file '{path}' line {} is invalid: {error}",
                line_index + 1
            )
        })?;
        parsed.insert(signer_id_hex, key_hex);
    }

    if parsed.is_empty() {
        return Err(format!(
            "receipt-key file '{path}' contains no signer->key entries"
        ));
    }
    Ok(parsed)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CounterfactualConfigFile {
    One(CounterfactualConfig),
    Many(Vec<CounterfactualConfig>),
}

fn load_counterfactual_configs(path: &str) -> Result<Vec<CounterfactualConfig>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read counterfactual config file '{path}': {error}"))?;
    let parsed = serde_json::from_str::<CounterfactualConfigFile>(&content).map_err(|error| {
        format!("failed to parse counterfactual config file '{path}' as JSON object/array: {error}")
    })?;
    let configs = match parsed {
        CounterfactualConfigFile::One(config) => vec![config],
        CounterfactualConfigFile::Many(configs) => configs,
    };
    if configs.is_empty() {
        return Err(format!(
            "counterfactual config file '{path}' must include at least one config"
        ));
    }
    Ok(configs)
}

fn load_trimmed_file(path: &str, label: &str) -> Result<String, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {label} '{path}': {error}"))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} '{path}' is empty"));
    }
    Ok(trimmed.to_string())
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
