# Parser Diagnostics Quality Rubric (`bd-2mds.1.10.1`)

This document defines the deterministic quality rubric and golden-test contract
for parser diagnostics UX regression control.

## Scope

Rubric artifacts are owned by:

- `docs/PARSER_DIAGNOSTICS_QUALITY_RUBRIC.md`
- `crates/franken-engine/tests/fixtures/parser_diagnostics_quality_rubric_v1.json`
- `crates/franken-engine/tests/parser_diagnostics_quality_rubric.rs`
- `scripts/run_parser_diagnostics_quality_rubric.sh`

This contract is binding for parser diagnostics quality gating and downstream
PSRP-10.* release readiness checks.

## Contract Version

- `schema_version`: `franken-engine.parser-diagnostics-quality-rubric.v1`
- `rubric_version`: `1.0.0`
- diagnostics taxonomy dependency:
  `franken-engine.parser-diagnostics.taxonomy.v1`
- normalized diagnostics dependency:
  `franken-engine.parser-diagnostics.schema.v1`

## Rubric Dimensions

Each diagnostics case receives millionths scores (`0..=1_000_000`) for:

- `location_precision`
- `message_clarity`
- `actionable_hints`
- `deterministic_wording`

Composite score is the weighted sum of dimensions using fixture-defined
`weight_millionths` values that must sum to `1_000_000`.

## Golden Diagnostics Corpus Families

The golden corpus must include parser diagnostics scenarios across at least:

- `input` (empty/invalid input cases)
- `goal` (goal-mode mismatch diagnostics)
- `syntax` (unsupported syntax diagnostics)
- `resource` (budget/limit diagnostics)

Each case carries:

- stable `case_id`
- `family_id`
- parse `goal`
- deterministic source text
- expected parser error code + diagnostic code
- replay command

## Baseline Delta and Regression Alarm Policy

Rubric fixtures define `baseline_scores_millionths` for each dimension and
composite quality.

Gate behavior:

- compute current aggregate scores from the golden corpus
- compute `delta = current - baseline` per dimension and composite
- fail if any delta is below `-max_allowed_regression_millionths`

This ensures baseline-vs-current drift is explicit and alarmed.

## Structured Log Contract

User-journey e2e diagnostics scenarios must emit structured records containing:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Recommended additional keys:

- `case_id`
- `family_id`
- `diagnostic_hash`
- `scores_millionths`
- `composite_score_millionths`
- `replay_command`

## Deterministic Execution Contract

All heavy Rust diagnostics rubric checks/tests must run through `rch` wrappers.

Canonical command:

```bash
./scripts/run_parser_diagnostics_quality_rubric.sh ci
```

Modes:

- `check`: compile focused diagnostics rubric test target
- `test`: execute focused diagnostics rubric tests
- `clippy`: lint focused diagnostics rubric target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run must publish:

- `artifacts/parser_diagnostics_quality_rubric/<timestamp>/run_manifest.json`
- `artifacts/parser_diagnostics_quality_rubric/<timestamp>/events.jsonl`
- `artifacts/parser_diagnostics_quality_rubric/<timestamp>/commands.txt`

`run_manifest.json` must include:

- schema/version identifiers
- toolchain/target-dir/mode
- git commit and dirty-worktree state
- exact executed command list
- operator replay commands

## Operator Verification

```bash
./scripts/run_parser_diagnostics_quality_rubric.sh ci
cat artifacts/parser_diagnostics_quality_rubric/<timestamp>/run_manifest.json
cat artifacts/parser_diagnostics_quality_rubric/<timestamp>/events.jsonl
cat artifacts/parser_diagnostics_quality_rubric/<timestamp>/commands.txt
```

The run is invalid if required artifact files or required structured event keys
are missing.
