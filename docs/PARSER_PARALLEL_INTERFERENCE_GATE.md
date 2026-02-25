# Parser Parallel Interference and Parity Matrix Contract

This document defines the PSRP-05.4.2 contract for worker/seed parity-matrix
execution and adversarial determinism stress validation in:

- `crates/franken-engine/src/parallel_interference_gate.rs`
- `crates/franken-engine/src/parallel_parser.rs`

## Scope

- Execute deterministic parity matrices across worker-count and seed dimensions.
- Assert adversarial-profile stability and witness-diff explainability.
- Emit replayable, schema-stable gate artifacts for downstream correctness and
  cross-architecture gates.
- Fail closed on unresolved interference incidents or flake-rate violations.

## Matrix Dimensions

Baseline campaign dimensions for this lane:

- worker counts: `2`, `4`, `8`
- seeds: deterministic sequence `0..(seed_count-1)`
- repeats per seed: deterministic fixed count
- adversarial profiles:
  - operators-and-strings stress payloads
  - synthetic witness-diff mismatch explanation coverage

The gate runner records the active matrix profile in run-manifest metadata.

## Determinism and Drift-Explanation Contract

Each mismatch must remain diagnosable through structured evidence:

- interference class (`merge-order`, `scheduler`, `data-structure-iteration`,
  `artifact-pipeline`, `timeout-race`, `backpressure-drift`)
- severity (`info`, `warning`, `critical`)
- `(seed, worker_count, run_index)` coordinate
- expected/actual output witnesses
- triage hint + remediation playbook ID
- one-command replay pointer

Witness and transcript diffs are represented by `WitnessDiff` and transcript
comparison entries; operator summaries must rank root-cause hints by incident
frequency and severity.

## Replay and Escalation Hooks

Replay bundles must provide deterministic rerun material for every incident:

- failing seed set
- failing worker-count set
- replay command list

Rollback integration is fail-closed:

- `promote` resets rollback failure counter
- `hold`/`reject` increments failure counter
- threshold crossing triggers serial rollback posture

## Gate and Artifacts

Primary gate script:

```bash
./scripts/run_parser_parallel_interference_gate.sh ci
```

Artifacts are emitted under:

- `artifacts/parser_parallel_interference/<timestamp>/run_manifest.json`
- `artifacts/parser_parallel_interference/<timestamp>/events.jsonl`
- `artifacts/parser_parallel_interference/<timestamp>/commands.txt`

The manifest includes deterministic environment fingerprinting and a one-command
replay entry suitable for PSRP-07.2 and PSRP-08.2 consumption.
