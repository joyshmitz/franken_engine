# RGC Operator Incident Runbook (`bd-1lsy.10.2`)

This runbook defines replay-first operator workflows for release-critical incidents
in the Reality Gap Closure (`RGC`) program.

## Scope

This runbook is the operational contract for `RGC-902` and covers five core
incident classes:

- semantic drift
- performance regression
- containment false positive
- lockstep divergence
- replay mismatch

Implementation surfaces:

- `scripts/run_rgc_operator_incident_runbook.sh`
- `scripts/e2e/rgc_operator_incident_runbook_replay.sh`
- `crates/franken-engine/tests/rgc_operator_incident_runbook.rs`
- `crates/franken-engine/tests/fixtures/rgc_operator_incident_runbook_v1.json`

## Deterministic Environment And Log Contract

All drills bootstrap deterministic env controls via
`scripts/e2e/parser_deterministic_env.sh` and emit stable structured log keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Required policy ID:

- `policy-rgc-operator-incident-runbook-v1`

## Fresh-Operator Dry Run

```bash
./scripts/run_rgc_operator_incident_runbook.sh ci
```

Expected artifacts:

- `artifacts/rgc_operator_incident_runbook/<timestamp>/run_manifest.json`
- `artifacts/rgc_operator_incident_runbook/<timestamp>/events.jsonl`
- `artifacts/rgc_operator_incident_runbook/<timestamp>/commands.txt`
- `artifacts/rgc_operator_incident_runbook/<timestamp>/incident_timeline.json`

## Replay-First Incident Decision Tree

1. **Semantic drift**
   - `./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh`
2. **Performance regression**
   - `./scripts/e2e/rgc_performance_regression_verification_pack_replay.sh`
3. **Containment false positive**
   - `./scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh`
4. **Lockstep divergence**
   - `./scripts/e2e/rgc_module_interop_verification_matrix_replay.sh`
5. **Replay mismatch**
   - `./scripts/e2e/rgc_execution_waves_coordination_replay.sh`

## Scriptable Drill Lane

```bash
./scripts/run_rgc_operator_incident_runbook.sh drill
./scripts/e2e/rgc_operator_incident_runbook_replay.sh drill
```

## Escalation, Rollback, And Handoff

- Any failed replay command sets release posture to **hold**.
- If containment posture is ambiguous, enforce **fail-closed** safety posture.
- Rollback requires explicit owner handoff with evidence links in
  `incident_timeline.json`.
- Incident closure requires replay confirmation plus manifest/event artifacts.

## Operator Verification Checklist

```bash
./scripts/run_rgc_operator_incident_runbook.sh ci
cat artifacts/rgc_operator_incident_runbook/<timestamp>/run_manifest.json
cat artifacts/rgc_operator_incident_runbook/<timestamp>/events.jsonl
cat artifacts/rgc_operator_incident_runbook/<timestamp>/commands.txt
cat artifacts/rgc_operator_incident_runbook/<timestamp>/incident_timeline.json
./scripts/e2e/rgc_operator_incident_runbook_replay.sh ci
```
