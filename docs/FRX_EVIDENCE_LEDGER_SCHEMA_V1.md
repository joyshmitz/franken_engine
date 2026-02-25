# FRX Evidence Ledger Schema v1

Status: active
Primary bead: bd-mjh3.8.1

## Purpose

Define a normalized, replay-compatible evidence event shape for compile/runtime/fallback/governance decisions.

## Canonical Schema

- Event JSON Schema: `docs/frx_evidence_ledger_event_v1.schema.json`
- Schema version: `frx.evidence.ledger.event.v1`

## Mandatory Linkage Keys

1. `claim_id`
2. `evidence_id`
3. `policy_id`
4. `trace_id`
5. `decision_id`
6. `artifact_hash`
7. `signer`

## Adaptive Decision Mandatory Fields

For adaptive decisions, these fields are required:

- `calibration.ece`
- `calibration.brier`
- `calibration.coverage`
- `assumptions` (non-empty)
- `rejected_alternatives` (non-empty)

## Determinism and Replay Contract

1. Event ordering key is deterministic for a trace.
2. Integrity fields must verify prior to gate consumption.
3. Missing mandatory fields force fail-closed gate behavior.

## Evolution Policy

- Breaking schema changes require version bump.
- Prior schema readers must reject incompatible major versions.
- Migration docs are required for every new version.

