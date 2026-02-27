# FRX Release Operations Gatebook and Publication Workflow V1

Status: active
Primary bead: bd-mjh3.9.2
Track id: FRX-09.2
Machine-readable contract: `docs/frx_release_operations_gatebook_v1.json`

## Scope

FRX-09.2 operationalizes release and publication workflows by consuming FRX-12
cut-line decisions and evidence artifacts. This lane does not define parallel
promotion logic; it executes release operations from signed stage-gate outputs.

The workflow is fail-closed: missing, stale, unsigned, or contradictory inputs
must block release and publication.

## FRX-12 Consumption Contract

Release operations must consume:

- cut-line automation decision records (`bd-mjh3.12.7`)
- GA readiness and evidence-bound claim publication gate outputs (`bd-mjh3.12.5`)
- milestone/release test-evidence integrator outputs (`bd-mjh3.20.6`)

Consumption rules:

1. stage decisions are accepted only when signatures and schema versions match.
2. release operations must verify cut-line progression (`alpha -> beta -> ga`).
3. contradictory stage decisions force immediate promotion halt.

## Release Packet Channels

Every release packet must include these channels:

- FRX-12 stage decision bundle and gate rationale
- proof-carrying artifact gate output (`bd-mjh3.5.4`)
- pilot rollout harness evidence (`bd-mjh3.9.1`)
- tail-latency/memory hardening evidence (`bd-mjh3.6.4`)
- observability demotion quality channel (`bd-mjh3.17.4`)
- catastrophic-tail adversarial tournament channel (`bd-mjh3.18.4`)
- semantic-twin rollback synthesis channel (`bd-mjh3.19.4`)
- FRX-20 unit/e2e/logging integrity and flake diagnostics (`bd-mjh3.20.6`)

If any mandatory channel is missing, stale, or unsigned, release operations fail
closed.

## Stage Checklists and Publication Workflow

### Alpha

- requires minimum cut-line `C2`
- requires canary scope, halt conditions, and incident escalation contacts
- publication output: internal preview claim packet only

### Beta

- requires minimum cut-line `C3`
- requires rollback drill evidence and oncall readiness attestation
- requires observability-demotion and adversarial-tail channels to be green
- publication output: limited external claim packet with explicit risk qualifiers

### GA

- requires minimum cut-line `C4`
- requires all mandatory channels and signed claim reproducibility bundle links
- publication output: public claim registry entry with replay commands

## Incident-Response and Rollback Communication Discipline

Release operations must attach communication artifacts with deterministic fields:

- incident communication: `incident_id`, `severity`, `decision_id`, `owner`,
  `escalation_path`, `first_response_deadline_s`
- rollback communication: `rollback_id`, `trigger_signal`, `rollback_command`,
  `safe_mode_target`, `eta_recovery_s`
- publication communications: `claim_id`, `release_stage`, `bundle_digest`,
  `public_statement_ref`

Operator acknowledgements are mandatory before stage promotion.

## Claim Publication and Reproducibility Linkage

Every published claim must include:

- `claim_id`
- `stage_gate_decision_id`
- `reproducibility_bundle_id`
- `evidence_bundle_ids`
- `release_packet_digest`
- `replay_command`
- `publication_timestamp_utc`
- signer identity and signature reference

Claims without complete reproducibility linkage are blocked from publication.

## Fail-Closed Validation Rules

Failure code: `FE-FRX-09-2-RELEASE-OPS-0001`

Promotion and publication are denied when any rule fails:

- required channel missing
- channel age exceeds freshness budget
- signature absent or invalid on required channels
- stage checklist item missing or marked failed
- publication record missing required fields
- release packet digest mismatch against signed manifest

## Deterministic Logging and Artifact Contract

Required structured log fields:

- `schema_version`
- `scenario_id`
- `trace_id`
- `decision_id`
- `policy_id`
- `release_stage`
- `publication_id`
- `component`
- `event`
- `outcome`
- `error_code`

Artifacts are emitted under:

`artifacts/frx_release_operations_gatebook/<UTC_TIMESTAMP>/`

with:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

## Dependencies and Prerequisites

- `bd-mjh3.20.6`
- `bd-mjh3.12.7`
- `bd-mjh3.12.5`
- `bd-mjh3.5.4`
- `bd-mjh3.9.1`
- `bd-mjh3.6.4`

## Operator Verification

```bash
./scripts/run_frx_release_operations_gatebook_suite.sh ci
./scripts/e2e/frx_release_operations_gatebook_replay.sh ci
jq empty docs/frx_release_operations_gatebook_v1.json
```
