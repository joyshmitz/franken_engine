# FRX Pilot App Program and A/B Rollout Harness v1

Status: active
Primary bead: bd-mjh3.9.1
Track id: FRX-09.1
Machine-readable contract: `docs/frx_pilot_rollout_harness_v1.json`

## Scope

FRX-09.1 defines a deterministic pilot rollout program that supports causal
interpretation of outcomes, not only raw online delta tracking.

The gate is fail-closed: incomplete telemetry, unstable assignment assumptions,
or insufficient sequential evidence must force stop/rollback behavior.

## Pilot Portfolio Stratification

Pilot coverage is stratified by workload archetype and risk profile.

Each pilot stratum must declare:

- inclusion criteria
- exclusion criteria
- risk tier
- target traffic share

Required strata:

- low-risk transactional dashboard workloads
- medium-risk data-sync + optimistic UI workloads
- high-risk collaboration or concurrent editing workloads
- security-sensitive admin or policy-control workloads

## A/B and Shadow-Run Harness Contract

The harness must support two deterministic experiment modes:

- `ab_online`: treatment and control both user-visible
- `shadow_run`: treatment observes identical traffic but does not affect users

Assignment must be replay-stable and include:

- `assignment_id`
- `cohort_id`
- `variant`
- `propensity_millionths`
- `policy_snapshot_id`

## Telemetry Contract for Causal and Off-Policy Safety Analysis

Per-decision telemetry must include enough information for causal and
counterfactual analysis:

- treatment assignment
- observed reward/cost terms
- action probability (propensity)
- context hash and rollout stage
- safety outcomes (incident/escalation/rollback)
- latency and resource usage deltas

## Off-Policy Evaluator Contract (IPS + Doubly Robust)

The gate requires explicit support for:

- inverse propensity scoring (`ips`)
- doubly robust estimation (`doubly_robust`)

Safety constraints:

1. propensities below a minimum clip threshold are rejected.
2. missing propensity or missing baseline predictions fail closed.
3. insufficient effective sample size blocks promotion.

## Sequential-Valid Monitoring and Decision Policies

Monitoring must be anytime-valid and produce explicit policy actions:

- `stop`: freeze rollout progression
- `promote`: advance cohort/stage
- `rollback`: demote to conservative mode

Decisions are loss-aware and require deterministic thresholds for:

- compatibility regressions
- tail latency risk
- incident-rate deltas
- sequential evidence confidence

## Incident Linkage and Replay/Evidence Artifacts

Every pilot incident must link to deterministic replay/evidence surfaces:

- `trace_id`
- `incident_id`
- `decision_id`
- `replay_bundle_id`
- `evidence_bundle_id`
- `run_manifest_id`

## Deterministic Logging and Artifact Contract

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

`artifacts/frx_pilot_rollout_harness/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

## Operator Verification

```bash
./scripts/run_frx_pilot_rollout_harness_suite.sh ci
./scripts/e2e/frx_pilot_rollout_harness_replay.sh ci
jq empty docs/frx_pilot_rollout_harness_v1.json
```
