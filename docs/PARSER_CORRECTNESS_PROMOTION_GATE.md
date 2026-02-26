# Parser Correctness Promotion Gate (`bd-2mds.1.8.2`)

This document defines the deterministic correctness gate contract for parser
supremacy promotion.

## Scope

This lane is implemented by:

- `docs/PARSER_CORRECTNESS_PROMOTION_GATE.md`
- `crates/franken-engine/tests/fixtures/parser_correctness_promotion_gate_v1.json`
- `crates/franken-engine/tests/parser_correctness_promotion_gate.rs`
- `scripts/run_parser_correctness_promotion_gate.sh`
- `scripts/e2e/parser_correctness_promotion_gate_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-correctness-promotion-gate.v1`
- `gate_version`: `1.0.0`

## Promotion Policy

Promotion is fail-closed.

The gate emits:

- `promote`: no unresolved high-severity drift and all required evidence lanes are green
- `hold`: any unresolved high-severity drift, invalid waiver, or non-green evidence lane

## Evidence Requirements

The following evidence lanes are mandatory and must be `pass`:

- `parser_oracle`
- `event_ast_equivalence`
- `parallel_fallback_parity`
- `differential_harness`

Missing or non-green lanes are blockers.

## Drift and Waiver Semantics

High-severity classes are `critical` and `high`.

Unresolved high-severity drift means:

- severity is in high-severity classes, and
- status is not `resolved` and not `waived`

Waivers are valid only when all fields are present:

- `waiver_id`
- `approved_by`
- `remediation_due_utc`
- `rationale`

Waiver due date must be strictly later than drift detection timestamp.

## Structured Log Contract

Each gate decision event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `drift_inventory`
- `waiver_inventory`
- `failing_fixture_ids`
- `replay_pointers`

## Deterministic Replay Contract

One-command replay wrapper:

```bash
./scripts/e2e/parser_correctness_promotion_gate_replay.sh
```

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane run through `rch`.

Canonical command:

```bash
./scripts/run_parser_correctness_promotion_gate.sh ci
```

Modes:

- `check`: compile focused correctness-gate tests
- `test`: run focused correctness-gate tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run emits:

- `artifacts/parser_correctness_promotion_gate/<timestamp>/run_manifest.json`
- `artifacts/parser_correctness_promotion_gate/<timestamp>/events.jsonl`
- `artifacts/parser_correctness_promotion_gate/<timestamp>/commands.txt`

Manifest includes gate mode, deterministic replay command, command transcript,
structured policy identifiers, and pass/fail outcome.

## Operator Verification

```bash
./scripts/run_parser_correctness_promotion_gate.sh ci
cat artifacts/parser_correctness_promotion_gate/<timestamp>/run_manifest.json
cat artifacts/parser_correctness_promotion_gate/<timestamp>/events.jsonl
cat artifacts/parser_correctness_promotion_gate/<timestamp>/commands.txt
./scripts/e2e/parser_correctness_promotion_gate_replay.sh
```
