# Parser User-Impact Baseline Dashboard (`bd-2mds.1.10.5.1`)

This document defines the deterministic baseline dashboard and metric
instrumentation contract for parser user-impact quality.

## Scope

Baseline dashboard artifacts are owned by:

- `docs/PARSER_USER_IMPACT_BASELINE_DASHBOARD.md`
- `crates/franken-engine/tests/fixtures/parser_user_impact_baseline_dashboard_v1.json`
- `crates/franken-engine/tests/parser_user_impact_baseline_dashboard.rs`
- `scripts/run_parser_user_impact_baseline_dashboard.sh`

This contract is binding for PSRP-10.5 baseline instrumentation rollout.

## Contract Version

- `schema_version`: `franken-engine.parser-user-impact-baseline-dashboard.v1`
- `dashboard_version`: `1.0.0`
- `metric_schema_version`: `franken-engine.parser-user-impact-metrics.v1`

## Required Metrics

Metrics are scored in millionths (`0..=1_000_000`) and weighted to a composite
dashboard score.

Required metric IDs:

- `diagnostic_quality`
- `recovery_usefulness`
- `integration_friction`

Metric definitions must be versioned, stable, and include:

- `metric_id`
- `description`
- `unit`
- `direction`
- `weight_millionths`

All metric weights must sum to `1_000_000`.

## Deterministic Baseline Workflows

The baseline fixture must include:

- diagnostics samples with expected parser error/diagnostic codes
- integration samples with expected parse success/failure outcomes
- deterministic e2e scenarios (fixture payload + expected pass/fail + replay command)

Determinism requirements:

- repeated scenario execution with identical seed yields identical event streams and digest
- required structured log keys are present in all scenario events
- dashboard snapshot scores are stable across repeated evaluation

## Structured Log Keys

Baseline scenarios must include these keys in event payloads:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Baseline Delta Policy

Fixture-defined `baseline_scores_millionths` are the reference line for:

- each required metric
- `composite`

Gate behavior:

- compute current metric/composite scores
- compute delta (`current - baseline`) for each tracked score
- fail if delta is lower than `-max_allowed_regression_millionths`

## Deterministic Execution Contract

All heavy Rust checks/tests must run through `rch`.

Canonical command:

```bash
./scripts/run_parser_user_impact_baseline_dashboard.sh ci
```

Modes:

- `check`: compile focused dashboard test target
- `test`: execute focused dashboard tests
- `clippy`: lint focused dashboard target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run must publish:

- `artifacts/parser_user_impact_baseline_dashboard/<timestamp>/run_manifest.json`
- `artifacts/parser_user_impact_baseline_dashboard/<timestamp>/events.jsonl`
- `artifacts/parser_user_impact_baseline_dashboard/<timestamp>/commands.txt`

`run_manifest.json` must include:

- schema/version identifiers
- bead id, toolchain, mode, target-dir
- git commit + dirty-worktree state
- exact command transcript
- deterministic replay command

## Operator Verification

```bash
./scripts/run_parser_user_impact_baseline_dashboard.sh ci
cat artifacts/parser_user_impact_baseline_dashboard/<timestamp>/run_manifest.json
cat artifacts/parser_user_impact_baseline_dashboard/<timestamp>/events.jsonl
cat artifacts/parser_user_impact_baseline_dashboard/<timestamp>/commands.txt
```

The run is invalid if required artifact files or required structured log keys
are missing.
