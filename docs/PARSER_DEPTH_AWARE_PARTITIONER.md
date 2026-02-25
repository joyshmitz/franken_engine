# Parser Depth-Aware Partitioner Contract (PSRP-05.1)

This document defines the deterministic depth-aware partitioning contract for
`bd-2mds.1.5.1`.

## Scope

- Bead: `bd-2mds.1.5.1`
- Core implementation:
  - `crates/franken-engine/src/parallel_parser.rs`
- Focused integration coverage:
  - `crates/franken-engine/tests/parallel_parser_integration.rs`
- Deterministic gate runner:
  - `scripts/run_parser_depth_partitioner_gate.sh`

## Objective

Build deterministic chunk plans that preserve syntactic boundaries better than
newline-only splitting while remaining replayable and auditable.

## Depth-Aware Split Rules

Partition candidates are collected from source bytes with deterministic scanner
state:

- quote/comment awareness:
  - skip split candidates inside single/double/template strings
  - skip split candidates inside line/block comments
- depth tracking:
  - track `()`, `{}`, `[]` nesting depth
  - record depth at candidate split points
- candidate delimiters:
  - newline (`\n`)
  - statement terminator (`;`)
  - block boundary (`}`)

For each planned chunk boundary, candidate selection is deterministic by
lexicographic score:

1. lower nesting depth first
2. prefer boundaries at or after ideal size target
3. lower distance from ideal target
4. block boundary (`}`) then statement (`;`) then newline
5. lower byte offset as stable tie-breaker

If no deterministic split points exist, planner fails closed to a single chunk.

## Invariants

Chunk plans must satisfy:

- deterministic plan hash for identical input/worker count
- full input coverage from `0..len`
- contiguous non-overlapping chunk intervals
- non-final boundaries always drawn from validated split-point catalog

## Structured Logging Contract

Gate/event artifacts must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Recommended keys:

- `scenario_id`
- `plan_hash`
- `worker_count`
- `replay_command`

## Operator Verification

```bash
./scripts/run_parser_depth_partitioner_gate.sh ci
cat artifacts/parser_depth_partitioner/<timestamp>/run_manifest.json
cat artifacts/parser_depth_partitioner/<timestamp>/events.jsonl
cat artifacts/parser_depth_partitioner/<timestamp>/commands.txt
```

Replay one-command instruction is persisted in run manifest and events.
