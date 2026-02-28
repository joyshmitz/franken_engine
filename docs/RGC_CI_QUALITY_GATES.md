# RGC CI Quality Gates Contract (`bd-1lsy.11.5`)

This contract defines deterministic CI quality-gate behavior for `RGC-055`.
The gate enforces rch-backed heavy Rust verification lanes and emits
artifact-rich failure summaries for fast triage.

## Scope

This lane is implemented by:

- `scripts/run_rgc_ci_quality_gates.sh`
- `scripts/e2e/rgc_ci_quality_gates_replay.sh`
- `docs/RGC_CI_QUALITY_GATES.md`
- `crates/franken-engine/tests/fixtures/rgc_ci_quality_gates_v1.json`
- `crates/franken-engine/tests/rgc_ci_quality_gates.rs`

## Contract Version

- `schema_version`: `franken-engine.rgc-ci-quality-gates.v1`
- `gate_version`: `1.0.0`

## Lane Entry Points

The gate supports deterministic lane modes:

- `check`: `cargo check --all-targets` (rch-backed)
- `clippy`: `cargo clippy --all-targets -- -D warnings` (rch-backed)
- `unit`: `cargo test -p frankenengine-engine --lib` (rch-backed)
- `integration`: focused RGC integration tests (rch-backed)
- `e2e`: deterministic RGC harness suites
- `replay`: deterministic replay wrappers for RGC harness suites
- `regression`: regression-verdict ingestion only
- `ci`: `check + clippy + unit + integration + e2e + replay + regression`

## rch Requirement

All heavy Rust compile/lint/test lanes run through `rch exec -- ...`.
If `rch` reports local fallback semantics, the gate fails closed.

## Regression Verdict Ingestion (RGC-703 hook)

When a verdict file is provided (via `RGC_PERF_REGRESSION_VERDICT_PATH` or
`RGC_CI_QUALITY_REGRESSION_VERDICT_PATH`), the gate blocks on critical/high
regressions using deterministic policy:

- block if `blocking == true` or `is_blocking == true`
- block if `highest_severity`/`severity` is `critical` or `high`
- block if any non-waived regression entry has `severity`/`level` in
  `{critical, high}`

For strict CI enforcement, set:

- `RGC_CI_QUALITY_REQUIRE_REGRESSION_VERDICT=true`

## Structured Log Contract

Events include stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Required Artifacts

Every run emits:

- `artifacts/rgc_ci_quality_gates/<timestamp>/run_manifest.json`
- `artifacts/rgc_ci_quality_gates/<timestamp>/events.jsonl`
- `artifacts/rgc_ci_quality_gates/<timestamp>/commands.txt`
- `artifacts/rgc_ci_quality_gates/<timestamp>/failure_summary.json`

`failure_summary.json` provides machine-readable triage routing:

- failed lane
- owner hint
- failing command/detail
- replay command

## Deterministic Replay Contract

```bash
./scripts/e2e/rgc_ci_quality_gates_replay.sh ci
```

## Operator Verification

```bash
./scripts/run_rgc_ci_quality_gates.sh ci
cat artifacts/rgc_ci_quality_gates/<timestamp>/run_manifest.json
cat artifacts/rgc_ci_quality_gates/<timestamp>/events.jsonl
cat artifacts/rgc_ci_quality_gates/<timestamp>/commands.txt
cat artifacts/rgc_ci_quality_gates/<timestamp>/failure_summary.json
./scripts/e2e/rgc_ci_quality_gates_replay.sh ci
```

## Dependency Note

`bd-1lsy.11.5` is upstream-blocked by `bd-1lsy.11.14` and `bd-1lsy.8.3`.
This gate ships prework scaffold + ingestion hooks so full fail-closed closure
can happen immediately once those dependencies land.
