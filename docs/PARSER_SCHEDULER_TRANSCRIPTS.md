# Parser Deterministic Scheduler Transcript Contract

This document defines the PSRP-05.2 contract for deterministic scheduler
transcripts in `crates/franken-engine/src/parallel_parser.rs`.

## Scope

- Construct deterministic schedule transcripts from `(seed, chunk_plan)`.
- Persist worker-dispatch decisions and transcript hash witnesses.
- Validate replay invariants fail-closed before execution.
- Provide one-command reproducible verification artifacts.

## Transcript Schema

`ScheduleTranscript` records:

- `seed`: schedule seed used for ranking.
- `worker_count`: effective worker count from `ChunkPlan`.
- `plan_hash`: deterministic chunk-plan hash witness.
- `execution_order`: deterministic permutation of chunk indices.
- `dispatches`: per-step dispatch tuple `(step_index, chunk_index, worker_slot)`.
- `transcript_hash`: content hash over all transcript payload fields.

## Deterministic Ordering Rules

Execution order is derived by ranking each chunk index with deterministic key:

1. Mix `(seed, plan_hash-word, chunk_index)` using fixed-width integer arithmetic.
2. Sort by `(rank, chunk_index)` to resolve ties deterministically.
3. Assign `worker_slot = step_index % worker_count`.

No runtime randomness, wall-clock, or platform-dependent sources are used.

## Replay Validation Invariants

`replay_schedule_transcript` must reject transcripts when any invariant fails:

- `plan_hash` mismatch against supplied `ChunkPlan`.
- `worker_count` mismatch.
- `execution_order.len() != chunk_count`.
- `dispatches.len() != execution_order.len()`.
- out-of-range chunk index.
- duplicate or missing chunk index coverage.
- dispatch step/chunk mismatch against execution order.
- worker slot out of range.
- recomputed `transcript_hash` mismatch.

Successful replay returns deterministic execution order used by parse execution.

## Gate and Artifacts

Primary gate script:

```bash
./scripts/run_parser_scheduler_transcript_gate.sh ci
```

Artifacts are emitted under:

- `artifacts/parser_scheduler_transcript/<timestamp>/run_manifest.json`
- `artifacts/parser_scheduler_transcript/<timestamp>/events.jsonl`
- `artifacts/parser_scheduler_transcript/<timestamp>/commands.txt`

The manifest must include deterministic environment fields and replay command.
