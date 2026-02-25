# FRX Cross-Track Handoff Protocol v1

Status: active
Primary bead: bd-mjh3.11.7

## Purpose

Define deterministic handoff behavior across tracks A-F with measurable WIP limits and escalation semantics.

## Handoff Packet Schema

Canonical schema: `docs/frx_handoff_packet_schema_v1.json`

Required packet fields:

- producer track and consumer track IDs
- artifact IDs and contract version
- confidence stamp
- readiness class (`ready_now`, `ready_next`, `gated`)
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

## Telemetry and Audit

Each handoff must emit:

- start timestamp
- acceptance/rejection decision
- latency-to-accept
- latency-to-close
- escalation tier reached (if any)

