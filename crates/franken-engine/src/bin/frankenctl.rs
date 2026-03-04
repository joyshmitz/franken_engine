#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::benchmark_e2e::{
    BenchmarkFamily, BenchmarkSuiteConfig, ScaleProfile, run_benchmark_suite,
    write_evidence_artifacts,
};
use frankenengine_engine::deterministic_replay::{NondeterminismTrace, ReplayEngine, ReplayMode};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineOutput, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParseEventIr, ParserOptions};
use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, render_verdict_summary, verify_receipt_by_id,
};
use frankenengine_engine::region_lifecycle::FinalizeResult;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const FRANKENCTL_SCHEMA_VERSION: &str = "franken-engine.frankenctl.v1";
const COMPILE_ARTIFACT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.compile-artifact.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandSpec {
    Version,
    Help,
    Compile(CompileArgs),
    Run(RunArgs),
    Verify(VerifyArgs),
    Benchmark(BenchmarkArgs),
    Replay(ReplayArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompileArgs {
    input: PathBuf,
    out: PathBuf,
    parse_goal: ParseGoal,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunArgs {
    input: PathBuf,
    extension_id: String,
    parse_goal: ParseGoal,
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifyArgs {
    CompileArtifact {
        input: PathBuf,
    },
    Receipt {
        input: PathBuf,
        receipt_id: String,
        summary: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkArgs {
    run_id: String,
    run_date: String,
    seed: u64,
    out_dir: PathBuf,
    profiles: Vec<ScaleProfile>,
    families: Vec<BenchmarkFamily>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayArgs {
    trace: PathBuf,
    mode: ReplayMode,
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompileArtifactHashes {
    parse_event_ir: String,
    ir0: String,
    ir1: String,
    ir2: String,
    ir3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompileArtifact {
    schema_version: String,
    generated_unix_ns: u64,
    source_path: String,
    parse_goal: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    hashes: CompileArtifactHashes,
    parse_event_ir: ParseEventIr,
    ir0: Ir0Module,
    lowering: LoweringPipelineOutput,
}

#[derive(Debug, Clone, Serialize)]
struct CompileCommandOutput {
    schema_version: String,
    artifact_path: String,
    parse_goal: String,
    hashes: CompileArtifactHashes,
    lowering_event_count: usize,
    lowering_witness_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct RunCommandOutput {
    schema_version: String,
    extension_id: String,
    trace_id: String,
    decision_id: String,
    lane: String,
    lane_reason: String,
    containment_action: String,
    expected_loss_millionths: i64,
    execution_value: String,
    instructions_executed: u64,
    evidence_entries: usize,
    cell_events: usize,
    saga_id: Option<String>,
    finalize_result: Option<FinalizeResult>,
}

#[derive(Debug, Clone, Serialize)]
struct CompileArtifactVerificationOutput {
    schema_version: String,
    artifact_path: String,
    passed: bool,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkCommandOutput {
    schema_version: String,
    run_id: String,
    run_date: String,
    seed: u64,
    blocked: bool,
    total_operations: u64,
    total_duration_us: u64,
    invariant_violations: u64,
    profiles: Vec<String>,
    families: Vec<String>,
    artifacts: BenchmarkArtifactPaths,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkArtifactPaths {
    run_manifest: String,
    evidence_jsonl: String,
    events_jsonl: String,
    commands_txt: String,
    benchmark_env_manifest: String,
    raw_results_archive: String,
    summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayCommandOutput {
    schema_version: String,
    trace_path: String,
    mode: String,
    session_id: String,
    event_count: usize,
    replayed_events: u64,
    divergence_count: usize,
    critical_divergences: usize,
    complete: bool,
}

fn main() {
    let code = match run(env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            2
        }
    };
    std::process::exit(code);
}

fn run(raw_args: Vec<String>) -> Result<i32, String> {
    let invocation_trace_id = default_run_id("frankenctl");
    let command = parse_command(&raw_args).map_err(|error| {
        format_cli_error(
            invocation_trace_id.as_str(),
            "parse",
            error.as_str(),
            "Run `frankenctl --help` for full command usage and required arguments.",
        )
    })?;
    let command_name = command_label(&command);
    let remediation = command_remediation(command_name);

    let outcome = match command {
        CommandSpec::Version => {
            println!("frankenctl {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        CommandSpec::Help => {
            println!("{}", usage());
            Ok(0)
        }
        CommandSpec::Compile(args) => execute_compile(args),
        CommandSpec::Run(args) => execute_run(args),
        CommandSpec::Verify(args) => execute_verify(args),
        CommandSpec::Benchmark(args) => execute_benchmark(args),
        CommandSpec::Replay(args) => execute_replay(args),
    };

    outcome.map_err(|error| {
        format_cli_error(
            invocation_trace_id.as_str(),
            command_name,
            error.as_str(),
            remediation,
        )
    })
}

fn parse_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::Help);
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::Help),
        "version" => Ok(CommandSpec::Version),
        "compile" => parse_compile_args(&args[1..]).map(CommandSpec::Compile),
        "run" => parse_run_args(&args[1..]).map(CommandSpec::Run),
        "verify" => parse_verify_args(&args[1..]).map(CommandSpec::Verify),
        "benchmark" => parse_benchmark_args(&args[1..]).map(CommandSpec::Benchmark),
        "replay" => parse_replay_args(&args[1..]).map(CommandSpec::Replay),
        other => Err(format!("unknown command `{other}`\n\n{}", usage())),
    }
}

fn parse_compile_args(args: &[String]) -> Result<CompileArgs, String> {
    let mut input: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut goal = ParseGoal::Script;
    let mut trace_id = "trace-frankenctl-compile".to_string();
    let mut decision_id = "decision-frankenctl-compile".to_string();
    let mut policy_id = "frankenctl.compile.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            "--help" | "-h" => return Ok(default_compile_help()),
            flag => return Err(format!("unknown compile flag `{flag}`")),
        }
        index += 1;
    }

    let input = input.ok_or_else(|| "compile requires --input <path>".to_string())?;
    let out = out.ok_or_else(|| "compile requires --out <path>".to_string())?;

    Ok(CompileArgs {
        input,
        out,
        parse_goal: goal,
        trace_id,
        decision_id,
        policy_id,
    })
}

fn default_compile_help() -> CompileArgs {
    CompileArgs {
        input: PathBuf::from(""),
        out: PathBuf::from(""),
        parse_goal: ParseGoal::Script,
        trace_id: String::new(),
        decision_id: String::new(),
        policy_id: String::new(),
    }
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut input: Option<PathBuf> = None;
    let mut extension_id: Option<String> = None;
    let mut goal = ParseGoal::Script;
    let mut out: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--extension-id" => extension_id = Some(next_arg(args, &mut index, "--extension-id")?),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            flag => return Err(format!("unknown run flag `{flag}`")),
        }
        index += 1;
    }

    Ok(RunArgs {
        input: input.ok_or_else(|| "run requires --input <path>".to_string())?,
        extension_id: extension_id.ok_or_else(|| "run requires --extension-id <id>".to_string())?,
        parse_goal: goal,
        out,
    })
}

fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, String> {
    if args.is_empty() {
        return Err("verify requires a subcommand: compile-artifact | receipt".to_string());
    }
    match args[0].as_str() {
        "compile-artifact" => {
            let mut input: Option<PathBuf> = None;
            let mut index = 1usize;
            while index < args.len() {
                match args[index].as_str() {
                    "--input" => {
                        input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?))
                    }
                    flag => return Err(format!("unknown verify compile-artifact flag `{flag}`")),
                }
                index += 1;
            }
            Ok(VerifyArgs::CompileArtifact {
                input: input.ok_or_else(|| {
                    "verify compile-artifact requires --input <artifact.json>".to_string()
                })?,
            })
        }
        "receipt" => {
            let mut input: Option<PathBuf> = None;
            let mut receipt_id: Option<String> = None;
            let mut summary = false;
            let mut index = 1usize;
            while index < args.len() {
                match args[index].as_str() {
                    "--input" => {
                        input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?))
                    }
                    "--receipt-id" => {
                        receipt_id = Some(next_arg(args, &mut index, "--receipt-id")?)
                    }
                    "--summary" => summary = true,
                    flag => return Err(format!("unknown verify receipt flag `{flag}`")),
                }
                index += 1;
            }
            Ok(VerifyArgs::Receipt {
                input: input.ok_or_else(|| "verify receipt requires --input <path>".to_string())?,
                receipt_id: receipt_id
                    .ok_or_else(|| "verify receipt requires --receipt-id <id>".to_string())?,
                summary,
            })
        }
        other => Err(format!(
            "unknown verify subcommand `{other}` (expected compile-artifact | receipt)"
        )),
    }
}

fn parse_benchmark_args(args: &[String]) -> Result<BenchmarkArgs, String> {
    if args.first().map(|value| value.as_str()) != Some("run") {
        return Err("benchmark requires subcommand `run`".to_string());
    }

    let mut run_id = default_run_id("benchmark");
    let mut run_date = "1970-01-01".to_string();
    let mut seed = 42_u64;
    let mut out_dir: Option<PathBuf> = None;
    let mut profiles: Vec<ScaleProfile> = Vec::new();
    let mut families: Vec<BenchmarkFamily> = Vec::new();

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--run-id" => run_id = next_arg(args, &mut index, "--run-id")?,
            "--run-date" => run_date = next_arg(args, &mut index, "--run-date")?,
            "--seed" => seed = parse_u64(&next_arg(args, &mut index, "--seed")?, "--seed")?,
            "--out-dir" => out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?)),
            "--profile" => profiles.push(parse_profile(&next_arg(args, &mut index, "--profile")?)?),
            "--family" => families.push(parse_family(&next_arg(args, &mut index, "--family")?)?),
            flag => return Err(format!("unknown benchmark run flag `{flag}`")),
        }
        index += 1;
    }

    let out_dir = out_dir.unwrap_or_else(|| default_benchmark_out_dir(&run_id));

    if profiles.is_empty() {
        profiles = vec![
            ScaleProfile::Small,
            ScaleProfile::Medium,
            ScaleProfile::Large,
        ];
    }
    if families.is_empty() {
        families = BenchmarkFamily::all().to_vec();
    }

    Ok(BenchmarkArgs {
        run_id,
        run_date,
        seed,
        out_dir,
        profiles,
        families,
    })
}

fn parse_replay_args(args: &[String]) -> Result<ReplayArgs, String> {
    if args.first().map(|value| value.as_str()) != Some("run") {
        return Err("replay requires subcommand `run`".to_string());
    }

    let mut trace: Option<PathBuf> = None;
    let mut mode = ReplayMode::Strict;
    let mut out: Option<PathBuf> = None;

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--trace" => trace = Some(PathBuf::from(next_arg(args, &mut index, "--trace")?)),
            "--mode" => mode = parse_replay_mode(&next_arg(args, &mut index, "--mode")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            flag => return Err(format!("unknown replay run flag `{flag}`")),
        }
        index += 1;
    }

    Ok(ReplayArgs {
        trace: trace.ok_or_else(|| "replay run requires --trace <path>".to_string())?,
        mode,
        out,
    })
}

fn execute_compile(args: CompileArgs) -> Result<i32, String> {
    if args.input.as_os_str().is_empty() && args.out.as_os_str().is_empty() {
        println!("{}", compile_usage());
        return Ok(0);
    }

    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;
    let parser_options = ParserOptions::default();
    let parser = CanonicalEs2020Parser;
    let (parse_result, parse_event_ir) =
        parser.parse_with_event_ir(source.as_str(), args.parse_goal, &parser_options);
    let syntax_tree = parse_result.map_err(|error| format!("parse failed: {error}"))?;

    let source_label = args.input.display().to_string();
    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, &source_label);
    let lowering = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            args.trace_id.clone(),
            args.decision_id.clone(),
            args.policy_id.clone(),
        ),
    )
    .map_err(|error| format!("lowering failed: {error}"))?;

    let hashes = CompileArtifactHashes {
        parse_event_ir: parse_event_ir.canonical_hash(),
        ir0: ir0.content_hash().to_string(),
        ir1: lowering.ir1.content_hash().to_string(),
        ir2: lowering.ir2.content_hash().to_string(),
        ir3: lowering.ir3.content_hash().to_string(),
    };

    let artifact = CompileArtifact {
        schema_version: COMPILE_ARTIFACT_SCHEMA_VERSION.to_string(),
        generated_unix_ns: current_unix_ns(),
        source_path: source_label,
        parse_goal: args.parse_goal.as_str().to_string(),
        trace_id: args.trace_id,
        decision_id: args.decision_id,
        policy_id: args.policy_id,
        hashes: hashes.clone(),
        parse_event_ir,
        ir0,
        lowering,
    };

    write_json_file(&args.out, &artifact)?;

    let output = CompileCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        artifact_path: args.out.display().to_string(),
        parse_goal: artifact.parse_goal,
        hashes,
        lowering_event_count: artifact.lowering.events.len(),
        lowering_witness_count: artifact.lowering.witnesses.len(),
    };
    print_json(&output)?;
    Ok(0)
}

fn execute_run(args: RunArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;

    let package = ExtensionPackage {
        extension_id: args.extension_id.clone(),
        source,
        capabilities: Vec::new(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        metadata: BTreeMap::new(),
    };

    let config = OrchestratorConfig {
        parse_goal: args.parse_goal,
        ..OrchestratorConfig::default()
    };
    let mut orchestrator = ExecutionOrchestrator::new(config);
    let result = orchestrator
        .execute(&package)
        .map_err(|error| format!("run failed: {error}"))?;

    let output = RunCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        extension_id: result.extension_id,
        trace_id: result.trace_id,
        decision_id: result.decision_id,
        lane: format!("{:?}", result.lane),
        lane_reason: format!("{:?}", result.lane_reason),
        containment_action: result.containment_action.to_string(),
        expected_loss_millionths: result.expected_loss_millionths,
        execution_value: result.execution_value,
        instructions_executed: result.instructions_executed,
        evidence_entries: result.evidence_entries.len(),
        cell_events: result.cell_events.len(),
        saga_id: result.saga_id,
        finalize_result: result.finalize_result,
    };

    if let Some(out) = args.out {
        write_json_file(&out, &output)?;
    }
    print_json(&output)?;
    Ok(0)
}

fn execute_verify(args: VerifyArgs) -> Result<i32, String> {
    match args {
        VerifyArgs::CompileArtifact { input } => {
            let artifact = load_json_file::<CompileArtifact>(&input)?;
            let errors = validate_compile_artifact(&artifact);
            let output = CompileArtifactVerificationOutput {
                schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
                artifact_path: input.display().to_string(),
                passed: errors.is_empty(),
                errors,
            };
            print_json(&output)?;
            if output.passed { Ok(0) } else { Ok(25) }
        }
        VerifyArgs::Receipt {
            input,
            receipt_id,
            summary,
        } => {
            let verifier_input = load_json_file::<ReceiptVerifierCliInput>(&input)?;
            let verdict = verify_receipt_by_id(&verifier_input, &receipt_id)
                .map_err(|error| format!("receipt verification failed: {error}"))?;
            if summary {
                println!("{}", render_verdict_summary(&verdict));
            } else {
                print_json(&verdict)?;
            }
            Ok(verdict.exit_code)
        }
    }
}

fn execute_benchmark(args: BenchmarkArgs) -> Result<i32, String> {
    let config = BenchmarkSuiteConfig {
        seed: args.seed,
        profiles: args.profiles.clone(),
        families: args.families.clone(),
        run_id: args.run_id.clone(),
        run_date: args.run_date.clone(),
        ..BenchmarkSuiteConfig::default()
    };

    let result = run_benchmark_suite(&config);
    let artifacts = write_evidence_artifacts(&result, &args.out_dir).map_err(|error| {
        format!(
            "failed to write benchmark artifacts to `{}`: {error}",
            args.out_dir.display()
        )
    })?;

    let output = BenchmarkCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        run_id: config.run_id.clone(),
        run_date: config.run_date.clone(),
        seed: config.seed,
        blocked: result.blocked,
        total_operations: result.total_operations,
        total_duration_us: result.total_duration_us,
        invariant_violations: result.invariant_violations,
        profiles: config
            .profiles
            .iter()
            .map(|profile| profile.as_str().to_string())
            .collect(),
        families: config
            .families
            .iter()
            .map(|family| family.as_str().to_string())
            .collect(),
        artifacts: BenchmarkArtifactPaths {
            run_manifest: artifacts.run_manifest_path.display().to_string(),
            evidence_jsonl: artifacts.evidence_path.display().to_string(),
            events_jsonl: artifacts.events_path.display().to_string(),
            commands_txt: artifacts.commands_path.display().to_string(),
            benchmark_env_manifest: artifacts.benchmark_env_manifest_path.display().to_string(),
            raw_results_archive: artifacts.raw_results_archive_path.display().to_string(),
            summary: artifacts.summary_path.display().to_string(),
        },
    };

    print_json(&output)?;
    if result.blocked { Ok(25) } else { Ok(0) }
}

fn execute_replay(args: ReplayArgs) -> Result<i32, String> {
    let trace = load_json_file::<NondeterminismTrace>(&args.trace)?;
    let replay_events = trace.events.clone();
    let session_id = trace.session_id.clone();
    let event_count = trace.events.len();

    let mut engine = ReplayEngine::new(trace, args.mode);
    for event in replay_events {
        engine
            .replay_next(event.source.clone(), &event.value)
            .map_err(|error| format!("replay failed at sequence {}: {error:?}", event.sequence))?;
    }

    let output = ReplayCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        trace_path: args.trace.display().to_string(),
        mode: replay_mode_name(args.mode).to_string(),
        session_id,
        event_count,
        replayed_events: engine.replayed_events,
        divergence_count: engine.divergence_count(),
        critical_divergences: engine.critical_divergences(),
        complete: engine.is_complete(),
    };

    if let Some(path) = args.out {
        write_json_file(&path, &output)?;
    }
    print_json(&output)?;
    Ok(0)
}

fn validate_compile_artifact(artifact: &CompileArtifact) -> Vec<String> {
    let mut errors = Vec::new();

    let expected_parse_hash = artifact.parse_event_ir.canonical_hash();
    if artifact.hashes.parse_event_ir != expected_parse_hash {
        errors.push(format!(
            "parse_event_ir hash mismatch: expected `{expected_parse_hash}`, got `{}`",
            artifact.hashes.parse_event_ir
        ));
    }

    let expected_ir0_hash = artifact.ir0.content_hash().to_string();
    if artifact.hashes.ir0 != expected_ir0_hash {
        errors.push(format!(
            "ir0 hash mismatch: expected `{expected_ir0_hash}`, got `{}`",
            artifact.hashes.ir0
        ));
    }

    let expected_ir1_hash = artifact.lowering.ir1.content_hash().to_string();
    if artifact.hashes.ir1 != expected_ir1_hash {
        errors.push(format!(
            "ir1 hash mismatch: expected `{expected_ir1_hash}`, got `{}`",
            artifact.hashes.ir1
        ));
    }

    let expected_ir2_hash = artifact.lowering.ir2.content_hash().to_string();
    if artifact.hashes.ir2 != expected_ir2_hash {
        errors.push(format!(
            "ir2 hash mismatch: expected `{expected_ir2_hash}`, got `{}`",
            artifact.hashes.ir2
        ));
    }

    let expected_ir3_hash = artifact.lowering.ir3.content_hash().to_string();
    if artifact.hashes.ir3 != expected_ir3_hash {
        errors.push(format!(
            "ir3 hash mismatch: expected `{expected_ir3_hash}`, got `{}`",
            artifact.hashes.ir3
        ));
    }

    for event in &artifact.parse_event_ir.events {
        if event.trace_id.trim().is_empty()
            || event.decision_id.trim().is_empty()
            || event.policy_id.trim().is_empty()
            || event.component.trim().is_empty()
            || event.outcome.trim().is_empty()
        {
            errors.push("parse_event_ir contains event with missing structured fields".to_string());
            break;
        }
    }

    for event in &artifact.lowering.events {
        if event.trace_id.trim().is_empty()
            || event.decision_id.trim().is_empty()
            || event.policy_id.trim().is_empty()
            || event.component.trim().is_empty()
            || event.event.trim().is_empty()
            || event.outcome.trim().is_empty()
        {
            errors.push("lowering event contains missing structured fields".to_string());
            break;
        }
    }

    errors
}

fn parse_goal(value: &str) -> Result<ParseGoal, String> {
    match value {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(format!(
            "invalid parse goal `{other}` (expected script|module)"
        )),
    }
}

fn parse_profile(value: &str) -> Result<ScaleProfile, String> {
    match value {
        "small" | "S" => Ok(ScaleProfile::Small),
        "medium" | "M" => Ok(ScaleProfile::Medium),
        "large" | "L" => Ok(ScaleProfile::Large),
        other => Err(format!(
            "invalid benchmark profile `{other}` (expected small|medium|large)"
        )),
    }
}

fn parse_family(value: &str) -> Result<BenchmarkFamily, String> {
    match value {
        "boot-storm" => Ok(BenchmarkFamily::BootStorm),
        "capability-churn" => Ok(BenchmarkFamily::CapabilityChurn),
        "mixed-cpu-io-agent-mesh" => Ok(BenchmarkFamily::MixedCpuIoAgentMesh),
        "reload-revoke-churn" => Ok(BenchmarkFamily::ReloadRevokeChurn),
        "adversarial-noise-under-load" => Ok(BenchmarkFamily::AdversarialNoiseUnderLoad),
        other => Err(format!("invalid benchmark family `{other}`")),
    }
}

fn parse_replay_mode(value: &str) -> Result<ReplayMode, String> {
    match value {
        "strict" => Ok(ReplayMode::Strict),
        "best-effort" => Ok(ReplayMode::BestEffort),
        "validate" => Ok(ReplayMode::Validate),
        other => Err(format!(
            "invalid replay mode `{other}` (expected strict|best-effort|validate)"
        )),
    }
}

fn replay_mode_name(mode: ReplayMode) -> &'static str {
    match mode {
        ReplayMode::Strict => "strict",
        ReplayMode::BestEffort => "best-effort",
        ReplayMode::Validate => "validate",
    }
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid {flag} value `{value}`: {error}"))
}

fn next_arg(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn default_run_id(prefix: &str) -> String {
    format!("{prefix}-{}", current_unix_ns())
}

fn default_benchmark_out_dir(run_id: &str) -> PathBuf {
    PathBuf::from(format!("artifacts/frankenctl_benchmark/{run_id}"))
}

fn current_unix_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let encoded = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to encode JSON output: {error}"))?;
    println!("{encoded}");
    Ok(())
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
    }
    let encoded = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to encode JSON for `{}`: {error}", path.display()))?;
    fs::write(path, encoded)
        .map_err(|error| format!("failed to write `{}`: {error}", path.display()))?;
    Ok(())
}

fn load_json_file<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read `{}`: {error}", path.display()))?;
    serde_json::from_str::<T>(&content)
        .map_err(|error| format!("failed to parse JSON `{}`: {error}", path.display()))
}

fn usage() -> String {
    [
        "frankenctl usage:",
        "  frankenctl version",
        "  frankenctl compile --input <source.js> --out <artifact.json> [--goal script|module]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "  frankenctl run --input <source.js> --extension-id <id> [--goal script|module] [--out <report.json>]",
        "  frankenctl verify compile-artifact --input <artifact.json>",
        "  frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary]",
        "  frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>]",
        "      [--profile small|medium|large]... [--family <name>]... [--out-dir <path>]",
        "  frankenctl replay run --trace <trace.json> [--mode strict|best-effort|validate] [--out <report.json>]",
        "",
        "benchmark families:",
        "  boot-storm",
        "  capability-churn",
        "  mixed-cpu-io-agent-mesh",
        "  reload-revoke-churn",
        "  adversarial-noise-under-load",
    ]
    .join("\n")
}

fn command_label(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Version => "version",
        CommandSpec::Help => "help",
        CommandSpec::Compile(_) => "compile",
        CommandSpec::Run(_) => "run",
        CommandSpec::Verify(_) => "verify",
        CommandSpec::Benchmark(_) => "benchmark",
        CommandSpec::Replay(_) => "replay",
    }
}

fn command_remediation(command: &str) -> &'static str {
    match command {
        "compile" => "Verify --input/--out paths and parse goal, then rerun `frankenctl compile`.",
        "run" => "Verify extension source path and `--extension-id`, then rerun `frankenctl run`.",
        "verify" => "Inspect input artifact/receipt payload and rerun `frankenctl verify ...`.",
        "benchmark" => {
            "Use constrained profiles/families first, then rerun `frankenctl benchmark run`."
        }
        "replay" => "Validate trace JSON and mode, then rerun `frankenctl replay run`.",
        _ => "Run `frankenctl --help` for command usage details.",
    }
}

fn format_cli_error(trace_id: &str, command: &str, error: &str, remediation: &str) -> String {
    format!(
        "[frankenctl trace_id={trace_id} command={command}] {error}\nremediation: {remediation}"
    )
}

fn compile_usage() -> String {
    [
        "compile usage:",
        "  frankenctl compile --input <source.js> --out <artifact.json> [--goal script|module]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_command() {
        let args = vec!["version".to_string()];
        let parsed = parse_command(&args).expect("version command should parse");
        assert_eq!(parsed, CommandSpec::Version);
    }

    #[test]
    fn parse_compile_command() {
        let args = vec![
            "compile".to_string(),
            "--input".to_string(),
            "demo.js".to_string(),
            "--out".to_string(),
            "out.json".to_string(),
            "--goal".to_string(),
            "module".to_string(),
        ];
        let parsed = parse_command(&args).expect("compile command should parse");
        match parsed {
            CommandSpec::Compile(spec) => {
                assert_eq!(spec.input, PathBuf::from("demo.js"));
                assert_eq!(spec.out, PathBuf::from("out.json"));
                assert_eq!(spec.parse_goal, ParseGoal::Module);
            }
            other => panic!("expected compile command, got {other:?}"),
        }
    }

    #[test]
    fn parse_verify_receipt_command() {
        let args = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--input".to_string(),
            "receipts.json".to_string(),
            "--receipt-id".to_string(),
            "rcpt-1".to_string(),
            "--summary".to_string(),
        ];
        let parsed = parse_command(&args).expect("verify receipt should parse");
        match parsed {
            CommandSpec::Verify(VerifyArgs::Receipt {
                input,
                receipt_id,
                summary,
            }) => {
                assert_eq!(input, PathBuf::from("receipts.json"));
                assert_eq!(receipt_id, "rcpt-1");
                assert!(summary);
            }
            other => panic!("expected verify receipt command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_with_filters() {
        let args = vec![
            "benchmark".to_string(),
            "run".to_string(),
            "--seed".to_string(),
            "123".to_string(),
            "--profile".to_string(),
            "small".to_string(),
            "--profile".to_string(),
            "large".to_string(),
            "--family".to_string(),
            "boot-storm".to_string(),
            "--family".to_string(),
            "reload-revoke-churn".to_string(),
            "--out-dir".to_string(),
            "artifacts/custom".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark command should parse");
        match parsed {
            CommandSpec::Benchmark(spec) => {
                assert_eq!(spec.seed, 123);
                assert_eq!(
                    spec.profiles,
                    vec![ScaleProfile::Small, ScaleProfile::Large]
                );
                assert_eq!(
                    spec.families,
                    vec![
                        BenchmarkFamily::BootStorm,
                        BenchmarkFamily::ReloadRevokeChurn
                    ]
                );
                assert_eq!(spec.out_dir, PathBuf::from("artifacts/custom"));
            }
            other => panic!("expected benchmark command, got {other:?}"),
        }
    }
}
