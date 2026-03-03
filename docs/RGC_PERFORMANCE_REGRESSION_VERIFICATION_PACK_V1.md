# RGC Performance and Regression Verification Pack V1

Status: active  
Primary bead: `bd-1lsy.11.10`  
Machine-readable contract: `docs/rgc_performance_regression_verification_pack_v1.json`

## Scope

This contract defines deterministic performance and regression verification for
benchmark integrity and profiler correctness gates.

The pack is evidence-first:

- validates benchmark integrity inputs before promotion decisions,
- enforces profiler receipt presence for every benchmark workload,
- detects statistically unsupported claims and regression threshold breaches,
- emits replay-stable run-manifest/event/command artifacts.

## Contract Version

- `schema_version`: `franken-engine.rgc-performance-regression-verification-pack.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-rgc-performance-regression-verification-pack-v1`

## Integrity Requirements

All benchmark samples must provide:

- stable workload id,
- non-zero baseline duration,
- profiler receipt id,
- benchmark metadata hash,
- significance bound (`p_value_millionths`) inside policy threshold.

Any integrity violation is fail-closed.

## Regression Classification

Regression is computed in millionths:

`(observed_ns - baseline_ns) * 1_000_000 / baseline_ns` when `observed_ns > baseline_ns`.

Severity bands:

- `warning` when regression >= warning threshold,
- `fail` when regression >= fail threshold.

Fail-band regressions always block publication.

## Structured Logging Contract

Every gate completion event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `path_type`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_performance_regression_verification_pack.sh`

Replay wrapper:

- `scripts/e2e/rgc_performance_regression_verification_pack_replay.sh`

Modes:

- `check`, `test`, `clippy`, `ci`

Strict mode is fail-closed and requires remote execution for heavy cargo
operations (`rch` only, no local fallback).

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `support_bundle/benchmark_report.json`
- `support_bundle/regression_findings.json`

under `artifacts/rgc_performance_regression_verification_pack/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_performance_regression_verification_pack_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_performance_regression_verification_pack \
  cargo test -p frankenengine-engine --test rgc_performance_regression_verification_pack

./scripts/run_rgc_performance_regression_verification_pack.sh ci
./scripts/e2e/rgc_performance_regression_verification_pack_replay.sh ci
```
