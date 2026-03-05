# RGC Exception and Diagnostic Semantics V1

Status: active  
Primary bead: `bd-1lsy.4.5`  
Machine-readable contract: `docs/rgc_exception_diagnostics_semantics_v1.json`

## Scope

This gate defines deterministic verification for runtime exception propagation,
stack trace stitching across sync/async/hostcall boundaries, and machine-stable
diagnostic metadata (`error_class`, `error_code`, location, correlation IDs,
stack fragments).

It operationalizes `bd-1lsy.4.5` with replay-first vectors and deterministic
artifact output for operator triage.

## Contract Version

- `schema_version`: `franken-engine.rgc-exception-diagnostics-semantics.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-rgc-exception-diagnostics-semantics-v1`

## Required Semantics Classes

Vectors must cover all classes below:

- `sync_exception_propagation`
- `async_exception_propagation`
- `diagnostic_metadata_stability`

## Structured Logging Contract

Every gate completion event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `lane`
- `error_class`
- `error_code`
- `outcome`

## Differential Conformance Rules

For each vector, run the scenario on both direct lanes (`quickjs`, `v8`) and
classify the result:

- `compatible`: normalized diagnostic semantics (class/code/location/stack) are identical.
- `intentional_divergence`: only lane-local correlation metadata differs; remediation guidance required.
- `incompatible`: normalized semantics diverge and gate fails closed.

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_exception_diagnostics_semantics.sh`

Replay wrapper:

- `scripts/e2e/rgc_exception_diagnostics_semantics_replay.sh`

Supported modes:

- `check`, `test`, `clippy`, `ci`

Heavy cargo operations are remote-only (`rch`) and fail closed on local
fallback detection.

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `diagnostic_trace.json`
- `step_logs/step_*.log`

under `artifacts/rgc_exception_diagnostics_semantics/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_exception_diagnostics_semantics_v1.json
jq empty docs/rgc_exception_diagnostics_semantics_vectors_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_exception_diagnostics_semantics \
  cargo test -p frankenengine-engine --test rgc_exception_diagnostics_semantics

./scripts/run_rgc_exception_diagnostics_semantics.sh ci
./scripts/e2e/rgc_exception_diagnostics_semantics_replay.sh ci
```
