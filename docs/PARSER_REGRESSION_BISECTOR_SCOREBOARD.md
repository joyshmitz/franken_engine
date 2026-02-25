# Parser Regression Bisector and Scoreboard Contract (`bd-2mds.1.6.4`)

This document defines deterministic regression attribution and scoreboard
publication semantics for parser telemetry runs.

## Scope

This contract is implemented by:

- `docs/PARSER_REGRESSION_BISECTOR_SCOREBOARD.md`
- `crates/franken-engine/tests/fixtures/parser_regression_bisector_scoreboard_v1.json`
- `crates/franken-engine/tests/parser_regression_bisector_scoreboard.rs`
- `scripts/run_parser_regression_bisector_scoreboard.sh`
- `scripts/e2e/parser_regression_bisector_scoreboard_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-regression-bisector-scoreboard.v1`
- `scoreboard_version`: `1.0.0`
- `metric_schema_version`: `franken-engine.parser-telemetry.v1`

## Regression Attribution Inputs

The bisector operates on a deterministic ordered run history where each row
contains:

- commit id
- run id and UTC timestamp
- telemetry metric vector
- replay command
- artifact pointers (manifest + report)

Metric definitions must declare:

- `metric_id`
- `direction` (`higher_is_better` or `lower_is_better`)
- `weight_millionths`

Weights must sum to `1_000_000`.

## Bisector Determinism Contract

1. A baseline commit and candidate commit define the search window.
2. Metric scoring is computed against the baseline with deterministic arithmetic.
3. A commit is "bad" when composite delta is below
   `-max_allowed_regression_millionths`.
4. Binary search midpoint selection and search path order are stable.
5. The first bad commit output must be replayable via fixture-provided commands.

## Scoreboard Publication Contract

The scoreboard publication snapshot must include:

- per-commit composite score and baseline delta
- regression classification (`regression` or `within_budget`)
- top improvement commit
- worst regression commit
- alert commit set (regression commits)

Sorting and ranking rules must be deterministic for equal deltas and commit ids.

## Structured Log Contract

Required keys for emitted bisector and scoreboard events:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Deterministic Replay Drills

The fixture must include replay drills with one-command invocation and expected
pass/fail outcomes for:

- bisect path stability
- first-bad commit attribution stability
- scoreboard ranking stability

## Deterministic Execution Contract

All heavy Rust checks/tests for this gate must run via `rch` wrappers.

Canonical command:

```bash
./scripts/run_parser_regression_bisector_scoreboard.sh ci
```

Modes:

- `check`: compile focused regression-bisector scoreboard test target
- `test`: execute focused regression-bisector scoreboard tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

Deterministic replay wrapper:

```bash
./scripts/e2e/parser_regression_bisector_scoreboard_replay.sh
```

## Required Artifacts

Each gate run must emit:

- `artifacts/parser_regression_bisector_scoreboard/<timestamp>/run_manifest.json`
- `artifacts/parser_regression_bisector_scoreboard/<timestamp>/events.jsonl`
- `artifacts/parser_regression_bisector_scoreboard/<timestamp>/commands.txt`

The manifest must include command transcript, deterministic replay command,
component metadata, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_parser_regression_bisector_scoreboard.sh ci
cat artifacts/parser_regression_bisector_scoreboard/<timestamp>/run_manifest.json
cat artifacts/parser_regression_bisector_scoreboard/<timestamp>/events.jsonl
cat artifacts/parser_regression_bisector_scoreboard/<timestamp>/commands.txt
./scripts/e2e/parser_regression_bisector_scoreboard_replay.sh
```
