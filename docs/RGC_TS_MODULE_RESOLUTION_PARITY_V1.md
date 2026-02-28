# RGC TS Module Resolution Parity V1

Status: active
Primary bead: bd-1lsy.3.2
Track id: RGC-202
Machine-readable contract: `docs/rgc_ts_module_resolution_parity_v1.json`

## Purpose

`RGC-202` defines deterministic TypeScript module-resolution behavior for
`frankenengine-engine` so import failures are diagnosed in the resolver lane
instead of surfacing later as ambiguous runtime faults.

This contract requires stable resolver decisions, stable trace fields, and
replayable drift artifacts against a reference toolchain.

## Resolution Semantics

The resolver implementation in this lane must preserve all of the following:

- `paths` alias support with wildcard capture and deterministic precedence
- `baseUrl` fallback candidate generation when alias/package lookup misses
- extension probe ordering split by request style (`import` vs `require`)
- package `exports` condition selection by request style and configured order
- deterministic trace emission for every decision branch and probe outcome

Stable trace fields expected by downstream tooling:

- `trace_id`, `decision_id`, `policy_id`
- `component`, `event`, `outcome`, `error_code`

## Drift Classification and Remediation

Observed candidate probes are compared against reference candidates and mapped
into deterministic classes:

- `no_drift`
- `candidate_order_mismatch`
- `missing_target`
- `extra_target`
- `full_mismatch`

Each class includes operator-facing remediation guidance in
`drift_report.json` so triage can proceed without reverse-engineering resolver
internals.

## Artifact Contract

Each parity scenario must emit:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `ts_resolution_trace.jsonl`

This lane also emits `drift_report.json` for drift class + remediation details.

`run_manifest.json` must include schema version, scenario id, generated time,
trace count, drift class, and artifact path mappings.

## Operator Verification

```bash
jq empty docs/rgc_ts_module_resolution_parity_v1.json

rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/data/tmp/rch_target_ts_module_resolution_parity \
  cargo test -p frankenengine-engine --test ts_module_resolution_parity
```
