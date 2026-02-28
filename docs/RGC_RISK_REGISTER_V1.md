# RGC Risk Register V1

Status: active
Primary bead: bd-1lsy.1.3
Track id: RGC-013
Machine-readable contract: `docs/rgc_risk_register_v1.json`

## Purpose

`RGC-013` provides the program-level risk register for the Reality Gap Closure
(RGC) track and ties each material risk to concrete mitigation beads.

This artifact exists to prevent reactive firefighting under milestone pressure:
risk ownership, mitigation path, rollback action, and review cadence are all
explicit and machine-checkable.

## Risk Model

Each risk record includes:

- `risk_id`, `title`, `domain`
- `likelihood` and `impact`
- `risk_level` (`high`, `medium`, `low`)
- `owner_role`
- `mitigation_beads` (concrete executable mitigation path)
- `mitigation_summary`
- `rollback_plan`
- review metadata: `last_reviewed_utc`, `next_review_due_utc`,
  `milestones_pending`, `open_actions`

## Top-20 Coverage

The register includes 20 active program risks spanning:

- correctness (parser, TS lane, runtime parity, lockstep)
- security (capabilities, IFC, containment latency, safe-mode behavior)
- performance (tier-up correctness, benchmark claim validity)
- operations (artifact integrity, runbook clarity, reproducibility)
- program governance (dependency drift, contract drift)

## High-Risk Mitigation Linkage

All `high` risks are required to link to one or more concrete RGC beads.
No high-risk entry is valid without:

- non-empty `mitigation_beads`
- at least one executable mitigation path under `bd-1lsy.*`
- explicit rollback action

## Milestone Review Cadence

Risk review is mandatory at each milestone gate:

- M1 (`rgc-m1-gate`)
- M2 (`rgc-m2-gate`)
- M3 (`rgc-m3-gate`)
- M4 (`rgc-m4-gate`)
- M5 (`rgc-m5-gate`)

Policy:

- fail closed when a risk review is stale beyond 14 days,
- require pre-gate and post-gate review evidence,
- require structured review records containing `trace_id`, `decision_id`,
  `risk_ids_reviewed`, and `actions`.

## Operator Verification

```bash
jq empty docs/rgc_risk_register_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_risk_register \
  cargo test -p frankenengine-engine --test rgc_risk_register

./scripts/run_phase_a_exit_gate.sh check
```
