# RGC Structured Logging Contract v1

`RGC-054A` defines the baseline structured logging contract used by RGC verification and promotion lanes.

## Scope

- Versioned machine-readable schema for structured runtime and verification log events.
- Stable correlation keys required across lane boundaries.
- Deterministic validation hooks with fail-closed outcomes.
- Backward-compatible evolution checks to prevent silent contract drift and preserve compatibility.

## Required Event Fields

Every contract-compliant event requires:

- `schema_version`
- `scenario_id`
- `fixture_id`
- `trace_id`
- `decision_id`
- `policy_id`
- `lane`
- `component`
- `event`
- `outcome`
- `error_code`
- `seed`
- `timing_us`
- `timestamp_unix_ms`

## Correlation Keys

The deterministic correlation key uses:

- `scenario_id`
- `trace_id`
- `decision_id`
- `policy_id`
- `seed`

Cross-lane mismatches on these keys are fail-closed validation failures.

## Validation Hooks

The baseline hooks are implemented in `crates/franken-engine/src/test_logging_schema.rs`:

- `validate_event`
- `validate_correlation`
- `validate_redaction`
- `validate_logging_contract`
- `validate_schema_evolution`

Failure code for contract-level violations:

- `FE-RGC-054A-LOG-SCHEMA-0001`

## Backward-Compatible Evolution Rules

1. Required fields and required correlation IDs are additive-only.
2. Correlation key fields must remain deterministic and aligned with required correlation IDs.
3. Secret redaction rules must remain strict (`drop`) across schema revisions.
4. Relaxing `require_redaction_for_sensitive` or enabling raw seed retention is disallowed without explicit major-contract migration.
5. Event-schema changes require a compatible major-version strategy and migration evidence.

## Operator Verification

```bash
./scripts/run_rgc_structured_logging_contract_gate.sh ci
./scripts/e2e/rgc_structured_logging_contract_replay.sh
jq empty docs/rgc_structured_logging_contract_v1.json
```

Expected artifacts:

- `artifacts/rgc_structured_logging_contract/<UTC_TIMESTAMP>/run_manifest.json`
- `artifacts/rgc_structured_logging_contract/<UTC_TIMESTAMP>/events.jsonl`
- `artifacts/rgc_structured_logging_contract/<UTC_TIMESTAMP>/commands.txt`
