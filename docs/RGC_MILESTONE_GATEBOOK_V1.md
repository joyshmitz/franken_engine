# RGC Milestone Gatebook V1

Status: active
Primary bead: bd-1lsy.1.2
Track id: RGC-012
Machine-readable contract: `docs/rgc_milestone_gatebook_v1.json`

## Purpose

`RGC-012` defines deterministic stop/go and rollback governance for milestones
M1 through M5.

This gatebook is executable by design:
- every milestone has explicit pass predicates and blocker classes,
- every milestone has codified rollback triggers with probe commands,
- every milestone defines decision authority,
- every milestone exposes a CI gate contract (workflow id + command +
  report-only to fail-closed transition dates).

## Gate Model

The gatebook JSON contract includes:

- `blocker_classes` with fail predicates and required evidence
- `milestones[].pass_predicates` with metric comparators and thresholds
- `milestones[].rollback_triggers` with testable condition expressions
- `milestones[].ci_gate` with automation commands and transition timestamps
- `automation` defaults for required logs, artifact triad, and mode transitions

All promotion decisions are fail-closed once a milestone transitions out of
report-only mode.

## Blocker Classes

The following blocker classes are mandatory across milestones:

- `correctness_regression`
- `security_enforcement_failure`
- `artifact_incompleteness`
- `performance_claim_instability`

Any active blocker class invalidates promotion for the current milestone.

## Milestone Stop/Go Matrix

| Milestone | Objective | Minimum stop/go metric examples | CI gate |
|---|---|---|---|
| M1 | Baseline parse->lower->execute viability | `baseline_corpus_pass_rate >= 0.99`, `artifact_completeness_ratio == 1.0` | `rgc-m1-gate` |
| M2 | Module + semantics practical parity | `module_resolution_drift_rate <= 0.01`, `module_interop_pass_rate >= 0.99` | `rgc-m2-gate` |
| M3 | In-band security enforcement | `capability_fail_open_rate == 0.0`, `containment_latency_p95_ms <= 250` | `rgc-m3-gate` |
| M4 | Performance claims with statistical validity | `benchmark_claim_validity_rate == 1.0`, `regression_budget_violations == 0` | `rgc-m4-gate` |
| M5 | GA reproducibility and evidence closure | `third_party_replay_success_rate >= 0.99`, `claim_evidence_coverage == 1.0` | `rgc-m5-gate` |

## Rollback Trigger Contract

Each milestone includes at least two rollback triggers with:

- `trigger_id`
- `condition_expression` (machine-evaluable predicate)
- `required_probe_command` (replay/check command)
- `rollback_action` (deterministic remediation action)

Rollback triggers are testable and must be evaluated from structured gate events.

## CI/Release Automation Contract

The contract is consumable by automation via stable fields:

- `automation.required_structured_log_fields`
- `automation.required_artifact_triad`
- `automation.decision_event_required_fields`
- `milestones[].ci_gate.workflow_id`
- `milestones[].ci_gate.command`
- `milestones[].ci_gate.report_only_until_utc`
- `milestones[].ci_gate.fail_closed_after_utc`

Automation transitions follow `report_only_then_fail_closed` with explicit,
per-milestone calendar boundaries.

## Operator Verification

```bash
jq empty docs/rgc_milestone_gatebook_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_gatebook \
  cargo test -p frankenengine-engine --test rgc_milestone_gatebook

./scripts/run_phase_a_exit_gate.sh check
```
