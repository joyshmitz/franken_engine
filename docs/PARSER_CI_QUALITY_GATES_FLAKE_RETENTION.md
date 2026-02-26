# Parser CI Quality Gates, Flake Triage, and Evidence Retention Contract (`bd-2mds.1.9.4`)

This document defines deterministic CI quality-gate behavior for parser lanes,
including flaky-test triage and long-horizon evidence retention semantics.

## Scope

This lane is implemented by:

- `docs/PARSER_CI_QUALITY_GATES_FLAKE_RETENTION.md`
- `crates/franken-engine/tests/fixtures/parser_ci_quality_gates_v1.json`
- `crates/franken-engine/tests/parser_ci_quality_gates.rs`
- `scripts/run_parser_ci_quality_gates.sh`
- `scripts/e2e/parser_ci_quality_gates_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-ci-quality-gates.v1`
- `gate_version`: `1.0.0`

## CI Gate Determinism Contract

The gate computes deterministic outcomes from fixture-defined run history:

- latest epoch must include both `unit` and `e2e` suites
- promotion requires all latest `unit` + `e2e` cases to pass
- flaky cases are detected from mixed pass/fail history per case
- gate blockers are stable and lexicographically ordered

Gate outcomes:

- `promote`: latest suites are green and no high-severity flakes remain
- `hold`: any required suite is not green or high-severity flakes exist

## Flake Classification Contract

For each case:

- `flake_rate_millionths = min(pass_count, fail_count) * 1_000_000 / total_runs`
- case is flaky iff both pass and fail counts are non-zero
- severity:
  - `high` when `flake_rate_millionths >= high_flake_threshold_millionths`
  - `warning` otherwise

Actionable metadata for each flaky case:

- case id + suite kind
- pass/fail counts and flake rate
- severity
- dominant error signature
- replay command
- evidence bundle ids
- quarantine action (`quarantine-immediate` for high severity)

## Promotion Policy Contract

Promotion is denied (`hold`) unless:

1. latest `unit` suite is green
2. latest `e2e` suite is green
3. no `high` severity flaky case remains unresolved

## Evidence Retention and Searchability Contract

Every run references a retention bundle record that includes:

- bundle id
- run id
- creation timestamp
- TTL in days (`>= min_retention_days`)
- searchable tokens

Retention index must support deterministic token -> bundle lookup for
root-cause triage queries (error signatures, case ids, and run identifiers).

## Trend Dashboard Signals

The lane emits deterministic aggregates for long-horizon reliability dashboards:

- pass-rate trend (latest epoch and rolling window)
- flake-rate trend (overall and high-severity subsets)
- mean-time-to-reproduce proxy from retained replay bundles

These aggregates are derived only from retained fixture-normalized evidence.

## Structured Log Contract

Required keys for emitted events:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Deterministic Replay Contract

The lane provides a one-command replay wrapper:

```bash
./scripts/e2e/parser_ci_quality_gates_replay.sh
```

Replay scenarios must declare expected pass/fail outcomes and remain stable.

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane run via `rch`.

Canonical command:

```bash
./scripts/run_parser_ci_quality_gates.sh ci
```

Modes:

- `check`: compile focused CI-quality-gate test target
- `test`: execute focused CI-quality-gate tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run emits:

- `artifacts/parser_ci_quality_gates/<timestamp>/run_manifest.json`
- `artifacts/parser_ci_quality_gates/<timestamp>/events.jsonl`
- `artifacts/parser_ci_quality_gates/<timestamp>/commands.txt`

The manifest includes deterministic gate metadata, command transcript,
replay command, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_parser_ci_quality_gates.sh ci
cat artifacts/parser_ci_quality_gates/<timestamp>/run_manifest.json
cat artifacts/parser_ci_quality_gates/<timestamp>/events.jsonl
cat artifacts/parser_ci_quality_gates/<timestamp>/commands.txt
./scripts/e2e/parser_ci_quality_gates_replay.sh
```
