# RGC Fault-Injection and Chaos Verification Pack V1

Status: active  
Primary bead: `bd-1lsy.11.6`  
Machine-readable contract: `docs/rgc_fault_injection_chaos_verification_pack_v1.json`

## Scope

This pack defines deterministic chaos and fault-injection verification for
security containment, degraded-mode behavior, and recovery correctness.

It operationalizes `bd-1lsy.11.6` with a reusable contract and gate artifacts
compatible with the shared deterministic e2e harness.

## Contract Version

- `schema_version`: `franken-engine.rgc-fault-injection-chaos-verification-pack.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-rgc-fault-injection-chaos-verification-pack-v1`

## Required Chaos Classes

The vectors must cover all classes below:

- `containment_trigger`
- `fault_containment`
- `degraded_mode_recovery`

## Structured Logging Contract

Every gate completion event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `chaos_class`
- `path_type`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_fault_injection_chaos_verification_pack.sh`

Replay wrapper:

- `scripts/e2e/rgc_fault_injection_chaos_verification_pack_replay.sh`

Supported modes:

- `check`, `test`, `clippy`, `ci`

Heavy cargo operations are remote-only (`rch`) and fail closed on local
fallback detection.

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `chaos_verification_report.json`
- `step_logs/step_*.log`

under `artifacts/rgc_fault_injection_chaos_verification_pack/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_fault_injection_chaos_verification_pack_v1.json
jq empty docs/rgc_fault_injection_chaos_verification_vectors_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_fault_injection_chaos_verification_pack \
  cargo test -p frankenengine-engine --test rgc_fault_injection_chaos_verification_pack

./scripts/run_rgc_fault_injection_chaos_verification_pack.sh ci
./scripts/e2e/rgc_fault_injection_chaos_verification_pack_replay.sh ci
```
