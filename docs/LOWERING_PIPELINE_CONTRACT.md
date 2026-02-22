# Lowering Pipeline Contract (bd-ug9)

This document defines the deterministic IR lowering pipeline contract for FrankenEngine.

## Goal

Provide a deterministic, per-pass verifiable lowering path:
- `IR0 (SyntaxIR) -> IR1 (SpecIR)`
- `IR1 (SpecIR) -> IR2 (CapabilityIR)`
- `IR2 (CapabilityIR) -> IR3 (ExecIR)`

Each pass emits machine-checkable witnesses and isomorphism-ledger entries.

## Current Scope

Implemented in `crates/franken-engine/src/lowering_pipeline.rs`:
- deterministic pass functions for each lowering stage
- pass-level invariants and deterministic failure semantics
- witness artifact emission per pass:
  - `pass_id`
  - `input_hash`
  - `output_hash`
  - `rollback_token`
  - `invariant_checks`
- isomorphism-ledger entry emission per pass:
  - input/output hashes
  - input/output op counts
- structured pass events with stable keys:
  - `trace_id`
  - `decision_id`
  - `policy_id`
  - `component`
  - `event`
  - `outcome`
  - `error_code`

## Per-Pass Semantics

- **IR0 -> IR1**
  - resolves deterministic root scope (`global` or `module`)
  - lowers statements into IR1 operation stream
  - verifies IR1 source-hash linkage against IR0 hash
- **IR1 -> IR2**
  - annotates effects/capabilities/flow envelopes for each op
  - enforces hostcall-effect capability presence
  - emits deterministic required-capability set
- **IR2 -> IR3**
  - lowers into deterministic execution instruction stream
  - appends deterministic `main` function descriptor and terminal `Halt`
  - verifies IR3 specialization linkage constraints

## Test Coverage

`crates/franken-engine/tests/lowering_pipeline.rs` covers:
- end-to-end lowering across all passes
- capability-intent preservation for hostcall-like literals
- deterministic repeatability across runs
- structured event field presence
- deterministic failure for invalid IR0 (`empty body`)

`crates/franken-engine/src/lowering_pipeline.rs` unit tests cover:
- each pass witness emission
- invariants per pass
- deterministic pipeline outputs

## Suite Runner

```bash
./scripts/run_lowering_pipeline_suite.sh check
./scripts/run_lowering_pipeline_suite.sh test
./scripts/run_lowering_pipeline_suite.sh ci
```

Artifacts:
- `artifacts/lowering_pipeline/<timestamp>/run_manifest.json`
- `artifacts/lowering_pipeline/<timestamp>/events.jsonl`
- `artifacts/lowering_pipeline/<timestamp>/commands.txt`

## Next Steps

- enrich IR0->IR1 lowering with fuller ES2020 semantic op coverage
- strengthen isomorphism checks with golden-corpus behavior proofs
- add incremental lowering-cache hooks for rapid extension-edit rebuilds
