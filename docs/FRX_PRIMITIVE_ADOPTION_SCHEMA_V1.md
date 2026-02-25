# FRX Primitive Adoption Schema v1

This document defines the machine-readable primitive-adoption schema and
activation gate contract for `bd-mjh3.16.1`.

## Scope

- Bead: `bd-mjh3.16.1`
- Schema contract file: `docs/frx_primitive_adoption_schema_v1.json`
- Runtime validation module:
  - `crates/franken-engine/src/primitive_adoption_schema.rs`
- Focused contract tests:
  - `crates/franken-engine/tests/frx_primitive_adoption_schema.rs`
- Hermetic runner:
  - `scripts/run_frx_primitive_adoption_schema_gate.sh`

## Required Metadata

Each primitive-adoption record must include:

1. Verification checklist metadata:
   - `checklist_version`
   - `primary_paper_verified=true`
   - `independent_replication_completed`
   - `verification_notes`
2. EV/relevance/risk scoring:
   - `ev_millionths`
   - `relevance_millionths` (0..=1_000_000)
   - `risk_millionths` (0..=1_000_000)
3. Deterministic fallback metadata:
   - `trigger`
   - `deterministic_mode`
   - `max_retry_count`
   - `time_budget_ms`
   - `memory_budget_mb`
4. Reuse scan outcome:
   - required for S/A-tier primitives
   - includes `catalog_version`, `decision`, `rationale`
   - `candidate_crates` required when decision is `adopt_existing_crate`
5. `adopt_vs_build_rationale`

## Activation Gate Rules

Activation is fail-closed when any required metadata is absent or invalid.

Deterministic error taxonomy:

- `FE-FRX-16-VERIFY-0001`: missing/invalid verification metadata.
- `FE-FRX-16-FALLBACK-0001`: missing/invalid fallback metadata.
- `FE-FRX-16-REUSE-0001`: missing/invalid reuse-scan outcome for required tiers.
- `FE-FRX-16-SCORE-0001`: score-range contract violation.
- `FE-FRX-16-METADATA-0001`: invalid required metadata field.

## Crate Reuse Scan Contract

- Reuse scan is mandatory for S/A-tier records before implementation activation.
- Reuse decision must be explicit (`adopt_existing_crate|build_new|not_applicable`).
- Adopt-vs-build rationale must be persisted with the record.
- Missing scan outcome blocks activation for required tiers.

## Structured Logging Contract

Gate/event streams must include stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Recommended additional fields:

- `scenario_id`
- `primitive_id`
- `tier`
- `replay_command`

## Operator Verification

```bash
./scripts/run_frx_primitive_adoption_schema_gate.sh ci
cat artifacts/frx_primitive_adoption_schema/<timestamp>/run_manifest.json
cat artifacts/frx_primitive_adoption_schema/<timestamp>/events.jsonl
cat artifacts/frx_primitive_adoption_schema/<timestamp>/commands.txt
```

The run is invalid if required metadata checks are not enforced or if
structured event keys are missing.
