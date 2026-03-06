# FRX Pilot App Program and A/B Rollout Harness v1

Status: active
Primary bead: bd-mjh3.9.1
Track id: FRX-09.1
Machine-readable contract: `docs/frx_pilot_rollout_harness_v1.json`

RGC alignment: this FRX contract is reused as dependency-safe prework for
`bd-1lsy.10.3` / `RGC-903` so the staged rollout lane has an explicit artifact
and rollback schema before the runtime-facing prerequisites fully close.

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

## Rollout Phase Contract (Shadow -> Canary -> Active)

Pilot progression is explicit and ordered:

1. `shadow`
2. `canary`
3. `active`

Every phase must declare:

- deterministic traffic share / exposure budget
- a phase-exit scorecard identifier
- required migration-readiness inputs
- promotion requirements with quantitative thresholds
- rollback trigger identifiers
- automatic rollback semantics

The gate fails closed if any phase is missing its scorecard, if phase ordering is
violated, or if the forced-regression rollback drill has not been recorded.

## Migration Readiness Inputs and Remediation Queue

Promotion decisions must correlate user-facing migration-readiness surfaces, not
only internal telemetry.

Required readiness inputs:

- `preflight_verdict`
- `compatibility_advisories`
- `onboarding_scorecard`
- `support_bundle_ref`

Blocked workloads must emit an explicit remediation queue entry with the
blocking signal, owner, recommended action, evidence reference, and replay
command. Missing readiness inputs or missing remediation plans are fail-closed
conditions.

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
- `phase_exit_scorecards.json`
- `migration_readiness_inputs.json`
- `blocked_workload_remediation_queue.json`
- `forced_regression_rollback_drill.json`
- `pilot_cohort_manifest.json`

The forced-regression drill must prove automatic rollback and incident capture
end-to-end before broader pilot promotion is considered credible.

## Operator Verification

```bash
./scripts/run_frx_pilot_rollout_harness_suite.sh ci
./scripts/e2e/frx_pilot_rollout_harness_replay.sh ci
jq empty docs/frx_pilot_rollout_harness_v1.json
```
