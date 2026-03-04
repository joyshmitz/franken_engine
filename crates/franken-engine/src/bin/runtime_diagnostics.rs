use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::runtime_diagnostics_cli::{
    EvidenceExportFilter, OnboardingScorecardInput, OnboardingScorecardSignal,
    RolloutDecisionArtifactInput, RuntimeDiagnosticsCliInput, SupportBundleOutput,
    SupportBundleRedactionPolicy, build_onboarding_scorecard, build_rollout_decision_artifact,
    collect_runtime_diagnostics, export_evidence_bundle, export_support_bundle,
    parse_decision_type, parse_evidence_severity, render_diagnostics_summary,
    render_evidence_summary, render_onboarding_scorecard_summary, render_preflight_summary,
    render_rollout_decision_artifact_summary, render_support_bundle_summary, run_preflight_doctor,
};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(usage());
    }

    match args[0].as_str() {
        "diagnostics" => run_diagnostics(&args[1..]),
        "export-evidence" => run_export(&args[1..]),
        "support-bundle" => run_support_bundle(&args[1..]),
        "doctor" => run_doctor(&args[1..]),
        "onboarding-scorecard" => run_onboarding_scorecard(&args[1..]),
        "rollout-decision-artifact" => run_rollout_decision_artifact(&args[1..]),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
    }
}

fn usage() -> String {
    [
        "runtime_diagnostics usage:",
        "  runtime_diagnostics diagnostics --input <path> [--summary]",
        "  runtime_diagnostics export-evidence --input <path> [--summary]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "  runtime_diagnostics support-bundle --input <path> [--summary] [--out-dir <path>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
        "  runtime_diagnostics doctor --input <path> [--summary] [--out-dir <path>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
        "  runtime_diagnostics onboarding-scorecard --input <path> [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals_json_path>]",
        "  runtime_diagnostics rollout-decision-artifact --input <path> [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals_json_path>] [--advisories <signals_json_path>] [--platform-signals <signals_json_path>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
    ]
    .join("\n")
}

fn run_diagnostics(args: &[String]) -> Result<(), String> {
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
            flag => return Err(format!("unknown flag for diagnostics: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let output = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );

    if summary {
        println!("{}", render_diagnostics_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode diagnostics output: {error}"))?
        );
    }

    Ok(())
}

fn run_export(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut filter = EvidenceExportFilter::default();

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
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            flag => return Err(format!("unknown flag for export-evidence: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let output = export_evidence_bundle(&input, filter);
    if summary {
        println!("{}", render_evidence_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode evidence export output: {error}"))?
        );
    }

    Ok(())
}

fn run_support_bundle(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

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
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for support-bundle: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };
    let output = export_support_bundle(&input, filter, redaction_policy);

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&output, &out_dir)?;
    }

    if summary {
        println!("{}", render_support_bundle_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode support bundle output: {error}"))?
        );
    }

    Ok(())
}

fn run_doctor(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

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
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for doctor: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;

    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };

    let output = run_preflight_doctor(&input, filter, redaction_policy);

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&output.support_bundle, &out_dir)?;
        let report_path = out_dir.join("support_bundle/preflight_report.json");
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create preflight report directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&output)
                .map_err(|error| format!("failed to encode preflight report: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write preflight report '{}': {error}",
                report_path.display()
            )
        })?;
    }

    if summary {
        println!("{}", render_preflight_summary(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| format!("failed to encode preflight doctor output: {error}"))?
        );
    }

    Ok(())
}

fn run_onboarding_scorecard(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut signals_path = None::<String>;
    let mut workload_id = None::<String>;
    let mut package_name = None::<String>;
    let mut target_platforms = Vec::<String>::new();
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

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
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signals requires a value".to_string())?;
                signals_path = Some(value.clone());
            }
            "--workload-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--workload-id requires a value".to_string())?;
                workload_id = Some(value.clone());
            }
            "--package-name" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--package-name requires a value".to_string())?;
                package_name = Some(value.clone());
            }
            "--target-platform" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--target-platform requires a value".to_string())?;
                target_platforms.push(value.clone());
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => return Err(format!("unknown flag for onboarding-scorecard: {flag}")),
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;
    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };
    let preflight = run_preflight_doctor(&input, filter, redaction_policy);

    let external_signals = match signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let workload_id = workload_id.unwrap_or_else(|| input.trace_id.clone());
    let package_name = package_name.unwrap_or_else(|| workload_id.clone());
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id,
        package_name,
        target_platforms,
        preflight: preflight.clone(),
        external_signals,
    });

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&preflight.support_bundle, &out_dir)?;
        let report_path = out_dir.join("support_bundle/preflight_report.json");
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create preflight report directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&preflight)
                .map_err(|error| format!("failed to encode preflight report: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write preflight report '{}': {error}",
                report_path.display()
            )
        })?;

        let scorecard_path = out_dir.join("support_bundle/onboarding_scorecard.json");
        if let Some(parent) = scorecard_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create onboarding scorecard directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &scorecard_path,
            serde_json::to_vec_pretty(&scorecard)
                .map_err(|error| format!("failed to encode onboarding scorecard: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write onboarding scorecard '{}': {error}",
                scorecard_path.display()
            )
        })?;
    }

    if summary {
        println!("{}", render_onboarding_scorecard_summary(&scorecard));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&scorecard).map_err(|error| format!(
                "failed to encode onboarding scorecard output: {error}"
            ))?
        );
    }

    Ok(())
}

fn run_rollout_decision_artifact(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<&str> = None;
    let mut summary = false;
    let mut out_dir = None::<PathBuf>;
    let mut workload_id = None::<String>;
    let mut package_name = None::<String>;
    let mut target_platforms = Vec::<String>::new();
    let mut signals_path = None::<String>;
    let mut advisories_path = None::<String>;
    let mut platform_signals_path = None::<String>;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

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
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--workload-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--workload-id requires a value".to_string())?;
                workload_id = Some(value.to_string());
            }
            "--package-name" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--package-name requires a value".to_string())?;
                package_name = Some(value.to_string());
            }
            "--target-platform" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--target-platform requires a value".to_string())?;
                target_platforms.push(value.to_string());
            }
            "--signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--signals requires a value".to_string())?;
                signals_path = Some(value.to_string());
            }
            "--advisories" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--advisories requires a value".to_string())?;
                advisories_path = Some(value.to_string());
            }
            "--platform-signals" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--platform-signals requires a value".to_string())?;
                platform_signals_path = Some(value.to_string());
            }
            "--extension-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--extension-id requires a value".to_string())?;
                filter.extension_id = Some(value.clone());
            }
            "--trace-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?;
                filter.trace_id = Some(value.clone());
            }
            "--start-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--start-ns requires a value".to_string())?;
                filter.start_timestamp_ns = Some(parse_u64_flag("--start-ns", value)?);
            }
            "--end-ns" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--end-ns requires a value".to_string())?;
                filter.end_timestamp_ns = Some(parse_u64_flag("--end-ns", value)?);
            }
            "--severity" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--severity requires a value".to_string())?;
                filter.severity = Some(parse_evidence_severity(value).ok_or_else(|| {
                    format!("invalid --severity '{value}' (expected info|warning|critical)")
                })?);
            }
            "--decision-type" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--decision-type requires a value".to_string())?;
                filter.decision_type = Some(
                    parse_decision_type(value)
                        .ok_or_else(|| format!("invalid --decision-type '{value}'"))?,
                );
            }
            "--redact-key" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--redact-key requires a value".to_string())?;
                redact_keys.push(value.to_string());
            }
            flag => {
                return Err(format!(
                    "unknown flag for rollout-decision-artifact: {flag}"
                ));
            }
        }
        index += 1;
    }

    let path = input_path.ok_or_else(|| "missing required --input <path>".to_string())?;
    let input = load_input(path)?;
    let redaction_policy = if redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(redact_keys)
    };
    let preflight = run_preflight_doctor(&input, filter, redaction_policy);

    let external_signals = match signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let compatibility_advisories = match advisories_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };
    let platform_matrix_signals = match platform_signals_path {
        Some(path) => load_onboarding_signals(path.as_str())?,
        None => Vec::new(),
    };

    let workload_id = workload_id.unwrap_or_else(|| input.trace_id.clone());
    let package_name = package_name.unwrap_or_else(|| workload_id.clone());
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id,
        package_name,
        target_platforms,
        preflight: preflight.clone(),
        external_signals,
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: scorecard.clone(),
        compatibility_advisories,
        platform_matrix_signals,
    });

    if let Some(out_dir) = out_dir {
        write_support_bundle_files(&preflight.support_bundle, &out_dir)?;

        let report_path = out_dir.join("support_bundle/preflight_report.json");
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create preflight report directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&preflight)
                .map_err(|error| format!("failed to encode preflight report: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write preflight report '{}': {error}",
                report_path.display()
            )
        })?;

        let scorecard_path = out_dir.join("support_bundle/onboarding_scorecard.json");
        if let Some(parent) = scorecard_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create onboarding scorecard directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &scorecard_path,
            serde_json::to_vec_pretty(&scorecard)
                .map_err(|error| format!("failed to encode onboarding scorecard: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write onboarding scorecard '{}': {error}",
                scorecard_path.display()
            )
        })?;

        let artifact_path = out_dir.join("support_bundle/rollout_decision_artifact.json");
        if let Some(parent) = artifact_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create rollout decision artifact directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(
            &artifact_path,
            serde_json::to_vec_pretty(&artifact)
                .map_err(|error| format!("failed to encode rollout decision artifact: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to write rollout decision artifact '{}': {error}",
                artifact_path.display()
            )
        })?;
    }

    if summary {
        println!("{}", render_rollout_decision_artifact_summary(&artifact));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&artifact).map_err(|error| format!(
                "failed to encode rollout decision artifact output: {error}"
            ))?
        );
    }

    Ok(())
}

fn write_support_bundle_files(output: &SupportBundleOutput, out_dir: &Path) -> Result<(), String> {
    for file in &output.files {
        let destination = out_dir.join(&file.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create support bundle directory '{}': {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(&destination, file.content.as_bytes()).map_err(|error| {
            format!(
                "failed to write support bundle file '{}': {error}",
                destination.display()
            )
        })?;
    }
    Ok(())
}

fn parse_u64_flag(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("{flag} expects a u64 value: {error}"))
}

fn load_input(path: &str) -> Result<RuntimeDiagnosticsCliInput, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read input file '{path}': {error}"))?;
    serde_json::from_str::<RuntimeDiagnosticsCliInput>(&content)
        .map_err(|error| format!("failed to parse input file '{path}' as JSON: {error}"))
}

fn load_onboarding_signals(path: &str) -> Result<Vec<OnboardingScorecardSignal>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read signal file '{path}': {error}"))?;
    serde_json::from_str::<Vec<OnboardingScorecardSignal>>(&content)
        .map_err(|error| format!("failed to parse signal file '{path}' as JSON array: {error}"))
}
