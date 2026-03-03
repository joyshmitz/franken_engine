# RGC Runtime Semantics Verification Pack V1

Status: active  
Primary bead: `bd-1lsy.11.7`  
Machine-readable contract: `docs/rgc_runtime_semantics_verification_pack_v1.json`

## Scope

This pack defines deterministic runtime-semantics verification for arithmetic and
control-flow behavior, object and closure interaction correctness, and async
error-path replay stability.

It operationalizes `bd-1lsy.11.7` with deterministic vectors, replay-first gate
execution, and structured triage artifacts.

## Contract Version

- `schema_version`: `franken-engine.rgc-runtime-semantics-verification-pack.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-rgc-runtime-semantics-verification-pack-v1`

## Required Semantics Classes

The vectors must cover all classes below:

- `arithmetic_control_flow`
- `object_closure_semantics`
- `async_error_path`

## Structured Logging Contract

Every gate completion event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `semantics_class`
- `path_type`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_runtime_semantics_verification_pack.sh`

Replay wrapper:

- `scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh`

Supported modes:

- `check`, `test`, `clippy`, `ci`

Heavy cargo operations are remote-only (`rch`) and fail closed on local
fallback detection.

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `runtime_semantics_verification_report.json`
- `step_logs/step_*.log`

under `artifacts/rgc_runtime_semantics_verification_pack/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_runtime_semantics_verification_pack_v1.json
jq empty docs/rgc_runtime_semantics_verification_vectors_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_runtime_semantics_verification_pack \
  cargo test -p frankenengine-engine --test rgc_runtime_semantics_verification_pack

./scripts/run_rgc_runtime_semantics_verification_pack.sh ci
./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh ci
```
