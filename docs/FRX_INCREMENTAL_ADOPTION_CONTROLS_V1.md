# FRX Incremental Adoption Controls v1

Status: active
Primary bead: bd-mjh3.7.4
Track id: FRX-07.4
Machine-readable contract: `docs/frx_incremental_adoption_controls_v1.json`

## Scope

FRX-07.4 defines deterministic rollout controls for gradual adoption, canarying,
rollback safety, and migration diagnostics. The contract is fail-closed: unknown
or unstable classes must route to conservative fallback mode.

## Rollout Axes and Opt-In Granularity

Supported rollout axes:

- `file`
- `component`
- `route`
- `policy`

Each axis must support explicit opt-in plus policy-based opt-out.

## Policy Opt-Out and Force-Fallback Toggles

Required toggles:

1. `force_fallback` for immediate deterministic demotion.
2. `policy_opt_out` for class- or lane-level rollback.
3. `denylist_opt_out` for temporary exclusion while migration proceeds.
4. `canary_pause` for halting progression without dropping telemetry.

## Canary and Rollback Flow

Required rollout stages:

- `shadow`
- `canary`
- `ramp`
- `active`

Rollback transitions must be explicit and deterministic:

- `canary` -> `shadow`
- `ramp` -> `canary`
- `active` -> `canary`

## Migration Diagnostics and Remediation UX

Diagnostics are actionable only if each record includes:

- stable `diagnostic_code`
- `compatibility_class`
- deterministic `fallback_route`
- `remediation_id`
- remediation guidance text
- ownership + target milestone

## Deterministic Logging and Evidence Contract

Required structured log fields:

- `schema_version`
- `scenario_id`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `decision_path`
- `seed`
- `timing_us`
- `outcome`
- `error_code`

Artifacts are emitted under:

`artifacts/frx_incremental_adoption_controls/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

## Operator Verification

```bash
./scripts/run_frx_incremental_adoption_controls_suite.sh ci
./scripts/e2e/frx_incremental_adoption_controls_replay.sh ci
jq empty docs/frx_incremental_adoption_controls_v1.json
```
