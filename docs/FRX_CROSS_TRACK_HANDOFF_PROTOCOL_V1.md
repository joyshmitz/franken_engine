# FRX Cross-Track Handoff Protocol v1

Status: active
Primary beads: bd-mjh3.11.7, bd-1lsy.1.5

## Purpose

Define deterministic handoff behavior across tracks A-F with measurable WIP limits and escalation semantics.

## Handoff Packet Schema

Canonical schema: `docs/frx_handoff_packet_schema_v1.json`

Required packet fields:

- producer/consumer track IDs and explicit owner IDs
- explicit `wave_id` (`wave_0` .. `wave_3`)
- entry criteria and exit criteria lists (criterion_id + bead_id + status + artifact)
- criteria attestations proving criterion satisfaction at handoff time
- deterministic handoff package (changed beads, artifact links, open risks, next-step recommendations)
- confidence stamp and completeness score
- deadline/SLA metadata

## WIP and Queue Discipline

1. Maximum active handoffs per track: `3`.
2. Maximum unresolved inbound handoffs per track: `5`.
3. New handoffs are rejected when limits are exceeded.
4. Queue order: severity first, then dependency criticality, then age.

## Escalation Matrix

1. `warn`: handoff waiting > 4h.
2. `escalate`: handoff waiting > 8h.
3. `reprioritize`: handoff waiting > 16h.
4. `freeze`: conflicting high-severity integration demands unresolved for > 24h.

Escalation ownership:

- Track owner initiates escalation.
- Governance lane arbitrates conflicting tie-breaks.
- Swarm control loop records rationale deltas.

## Tie-Break Rules

1. Compatibility/safety invariants outrank pure performance gains.
2. Deterministic replay and evidence-linkage obligations outrank throughput targets.
3. If still tied, oldest blocking dependency wins.

## Wave Model

Wave execution model for RGC governance:

1. `wave_0`: scope and gatebook stabilization.
2. `wave_1`: frontend/language-lane buildout.
3. `wave_2`: runtime/security/performance hardening.
4. `wave_3`: productization and GA evidence closure.

Each wave transition is fail-closed and requires a valid handoff packet.

## Wave Entry Criteria

Entry criteria must be explicit and tied to bead status + artifacts:

1. upstream dependency beads for the wave are at required state (`in_progress` or `closed` per criterion).
2. required upstream artifacts are present and linked in packet attestations.
3. prior wave risk register entries are either resolved or explicitly carried forward.
4. ownership routing is explicit (`producer_owner`, `consumer_owner`) with no empty identities.

## Wave Exit Criteria

Exit criteria must be explicit and tied to bead status + artifacts:

1. all wave-owned mandatory criteria have attested bead status and matching artifact references.
2. handoff package completeness score meets threshold (`>= 850` milli by default).
3. changed bead list, artifact links, and next-step recommendations are all non-empty.
4. unresolved risks are enumerated (use `none` sentinel when clear) and escalation tier is stated if non-empty.

## Mandatory Handoff Package

The handoff package is mandatory for every wave transition and must include:

1. `changed_beads`: concrete bead IDs modified or closed in the handoff window.
2. `artifact_links`: deterministic artifact/doc paths required to reproduce state.
3. `open_risks`: unresolved risk items (or `none`).
4. `next_step_recommendations`: concrete next actions for receiving owner.
5. `criteria_attestations`: criterion_id -> bead/status/artifact mapping proving entry/exit satisfaction.

Missing or weak handoff packages are rejected.

## Automated Validation and Failure Policy

Validation runs fail-closed with error code `FE-RGC-015-HANDOFF-0001` when:

1. mandatory packet fields are absent/empty,
2. completeness score is below threshold,
3. mandatory entry/exit criteria are missing attestations,
4. attested bead status mismatches required status,
5. required criterion artifacts are not present in artifact links.

Validation emits deterministic structured events:

- `handoff_received`
- `criteria_validated`
- `ownership_transition_committed` or `ownership_transition_rejected`

## Telemetry and Audit

Each handoff must emit:

- start timestamp
- acceptance/rejection decision
- latency-to-accept
- latency-to-close
- escalation tier reached (if any)

Required structured fields:

- `schema_version`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `wave_id`
- `packet_id`

## Operator Verification

```bash
./scripts/run_frx_cross_track_handoff_protocol_suite.sh ci
./scripts/e2e/frx_cross_track_handoff_protocol_replay.sh test
jq empty docs/frx_handoff_packet_schema_v1.json
```
