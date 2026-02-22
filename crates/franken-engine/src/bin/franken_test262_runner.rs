use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::Utc;
use frankenengine_engine::test262_release_gate::{
    Test262EvidenceCollector, Test262GateRunner, Test262HighWaterMark, Test262ObservedResult,
    Test262PinSet, Test262Profile, Test262RunnerConfig, Test262WaiverSet, next_high_water_mark,
};

#[derive(Debug, Clone)]
struct CliArgs {
    pins_path: PathBuf,
    profile_path: PathBuf,
    waivers_path: PathBuf,
    observed_results_path: PathBuf,
    output_root: PathBuf,
    high_water_mark_path: Option<PathBuf>,
    run_date: String,
    worker_count: usize,
    trace_prefix: String,
    policy_id: String,
    acknowledge_pass_regression: bool,
}

fn default_pins_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_conformance_pins.toml")
}

fn default_profile_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_es2020_profile.toml")
}

fn default_waivers_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_conformance_waivers.toml")
}

fn default_observed_results_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_observed_results.jsonl")
}

fn default_output_root() -> PathBuf {
    PathBuf::from("artifacts/test262_es2020_gate")
}

fn usage() -> &'static str {
    "usage: franken_test262_runner [--pins <path>] [--profile <path>] [--waivers <path>] [--observed-results <path>] [--output-root <path>] [--high-water-mark <path>] [--run-date <YYYY-MM-DD>] [--worker-count <n>] [--trace-prefix <prefix>] [--policy-id <id>] [--acknowledge-pass-regression]"
}

fn parse_args() -> Result<CliArgs, String> {
    let mut pins_path = default_pins_path();
    let mut profile_path = default_profile_path();
    let mut waivers_path = default_waivers_path();
    let mut observed_results_path = default_observed_results_path();
    let mut output_root = default_output_root();
    let mut high_water_mark_path = None;
    let mut run_date = Utc::now().format("%Y-%m-%d").to_string();
    let mut worker_count = 8usize;
    let mut trace_prefix = "trace-test262".to_string();
    let mut policy_id = "policy-test262-es2020".to_string();
    let mut acknowledge_pass_regression = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pins" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--pins requires a value".to_string())?;
                pins_path = PathBuf::from(value);
            }
            "--profile" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--profile requires a value".to_string())?;
                profile_path = PathBuf::from(value);
            }
            "--waivers" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--waivers requires a value".to_string())?;
                waivers_path = PathBuf::from(value);
            }
            "--observed-results" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--observed-results requires a value".to_string())?;
                observed_results_path = PathBuf::from(value);
            }
            "--output-root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output-root requires a value".to_string())?;
                output_root = PathBuf::from(value);
            }
            "--high-water-mark" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--high-water-mark requires a value".to_string())?;
                high_water_mark_path = Some(PathBuf::from(value));
            }
            "--run-date" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--run-date requires a value".to_string())?;
                run_date = value;
            }
            "--worker-count" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--worker-count requires a value".to_string())?;
                worker_count = value
                    .parse::<usize>()
                    .map_err(|_| "--worker-count must be a positive integer".to_string())?;
            }
            "--trace-prefix" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--trace-prefix requires a value".to_string())?;
                trace_prefix = value;
            }
            "--policy-id" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--policy-id requires a value".to_string())?;
                policy_id = value;
            }
            "--acknowledge-pass-regression" => {
                acknowledge_pass_regression = true;
            }
            "--help" | "-h" => {
                return Err(usage().to_string());
            }
            other => {
                return Err(format!(
                    "unknown argument: {other}. {usage}",
                    usage = usage()
                ));
            }
        }
    }

    Ok(CliArgs {
        pins_path,
        profile_path,
        waivers_path,
        observed_results_path,
        output_root,
        high_water_mark_path,
        run_date,
        worker_count,
        trace_prefix,
        policy_id,
        acknowledge_pass_regression,
    })
}

fn parse_observed_results(content: &str) -> io::Result<Vec<Test262ObservedResult>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "observed results are empty",
        ));
    }

    if trimmed.starts_with('[') {
        let observed: Vec<Test262ObservedResult> = serde_json::from_str(trimmed)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        if observed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "observed results must include at least one test",
            ));
        }
        return Ok(observed);
    }

    let mut observed = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let result: Test262ObservedResult = serde_json::from_str(line).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("observed results line {line_no} parse error: {err}"),
            )
        })?;
        observed.push(result);
    }

    if observed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "observed results must include at least one test",
        ));
    }

    Ok(observed)
}

fn load_observed_results(path: &Path) -> io::Result<Vec<Test262ObservedResult>> {
    let bytes = fs::read_to_string(path)?;
    parse_observed_results(&bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args =
        parse_args().map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

    let pins = Test262PinSet::load_toml(&args.pins_path)?;
    let profile = Test262Profile::load_toml(&args.profile_path)?;
    let waivers = Test262WaiverSet::load_toml(&args.waivers_path)?;
    let observed = load_observed_results(&args.observed_results_path)?;

    let previous_hwm = match args.high_water_mark_path.as_ref() {
        Some(path) => Test262HighWaterMark::load_json(path)?,
        None => None,
    };

    let runner = Test262GateRunner {
        config: Test262RunnerConfig {
            trace_prefix: args.trace_prefix,
            policy_id: args.policy_id,
            run_date: args.run_date,
            worker_count: args.worker_count,
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            acknowledge_pass_regression: args.acknowledge_pass_regression,
        },
    };

    let run = runner.run(&pins, &profile, &waivers, &observed, previous_hwm.as_ref())?;

    let next_hwm = next_high_water_mark(&run, previous_hwm.as_ref());
    let collector = Test262EvidenceCollector::new(&args.output_root)?;
    let artifacts = collector.collect(&run, &next_hwm)?;

    if let Some(path) = args.high_water_mark_path.as_ref() {
        next_hwm.write_json(path)?;
        println!("test262 canonical_high_water_mark={}", path.display());
    }

    println!("test262 run_id={}", run.run_id);
    println!(
        "test262 total_profile_tests={}",
        run.summary.total_profile_tests
    );
    println!("test262 passed={}", run.summary.passed);
    println!("test262 failed={}", run.summary.failed);
    println!("test262 waived={}", run.summary.waived);
    println!("test262 timed_out={}", run.summary.timed_out);
    println!("test262 crashed={}", run.summary.crashed);
    println!("test262 blocked_failures={}", run.summary.blocked_failures);
    println!("test262 blocked={}", run.blocked);
    println!("test262 profile_hash={}", run.summary.profile_hash);
    println!("test262 waiver_hash={}", run.summary.waiver_hash);
    println!("test262 pin_hash={}", run.summary.pin_hash);
    println!("test262 env_fingerprint={}", run.summary.env_fingerprint);
    println!(
        "test262 run_manifest={}",
        artifacts.run_manifest_path.display()
    );
    println!("test262 evidence={}", artifacts.evidence_path.display());
    println!(
        "test262 high_water_mark={}",
        artifacts.high_water_mark_path.display()
    );

    if run.blocked {
        return Err(io::Error::other(format!(
            "FE-T262-1005: test262 release gate blocked with {} blocking outcome(s)",
            run.summary.blocked_failures
        ))
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_engine::test262_release_gate::Test262ObservedOutcome;

    fn sample_line(test_id: &str, outcome: Test262ObservedOutcome) -> String {
        serde_json::json!({
            "test_id": test_id,
            "es2020_clause": "13.3.1",
            "outcome": outcome,
            "duration_us": 42,
            "error_code": null,
            "error_detail": null,
        })
        .to_string()
    }

    #[test]
    fn parse_jsonl_observed_results() {
        let content = format!(
            "# test262 sample\n\n{}\n{}\n",
            sample_line(
                "language/expressions/optional-chaining/pass.js",
                Test262ObservedOutcome::Pass
            ),
            sample_line(
                "built-ins/Array/prototype/map/basic.js",
                Test262ObservedOutcome::Pass
            )
        );

        let observed = parse_observed_results(&content).expect("parse jsonl");
        assert_eq!(observed.len(), 2);
        assert_eq!(
            observed[0].test_id,
            "language/expressions/optional-chaining/pass.js"
        );
    }

    #[test]
    fn parse_json_array_observed_results() {
        let content = format!(
            "[{},{}]",
            sample_line("language/a.js", Test262ObservedOutcome::Pass),
            sample_line("language/b.js", Test262ObservedOutcome::Fail)
        );

        let observed = parse_observed_results(&content).expect("parse array");
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[1].test_id, "language/b.js");
    }

    #[test]
    fn parse_observed_results_rejects_empty_input() {
        let err = parse_observed_results("\n  \n").expect_err("empty must fail");
        assert!(err.to_string().contains("observed results are empty"));
    }

    #[test]
    fn parse_observed_results_reports_line_number() {
        let content = format!(
            "{}\nnot-json\n",
            sample_line("language/a.js", Test262ObservedOutcome::Pass)
        );
        let err = parse_observed_results(&content).expect_err("invalid line must fail");
        assert!(err.to_string().contains("line 2"));
    }
}
