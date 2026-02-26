# FRX Test Logging Schema v1

`FRX-20.4` defines a deterministic, evidence-grade logging schema for unit and e2e suites.

## Scope

- Versioned machine-readable event schema for unit/e2e test logs.
- Mandatory correlation IDs spanning compiler/runtime/router/governance lanes.
- Explicit retention and redaction rules for sensitive log payloads.
- Fail-closed validation policy for CI artifact acceptance.

## Required Event Fields

Every test/e2e event must include:

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

Optional but recommended:

- `failure_taxonomy`

## Correlation Rules

1. Cross-lane validation is mandatory for `scenario_id`, `trace_id`, `decision_id`, `policy_id`, and `seed`.
2. Any mismatch across compiler/runtime/router/governance/e2e streams is a fail-closed gate violation.
3. Correlation keys are deterministic and replay-stable.

## Retention and Redaction Policy

1. Minimum retention window is 30 days.
2. Sensitive fields must be redacted or hashed before artifact persistence.
3. Secret fields must be dropped from stored logs.
4. Raw secret-bearing payloads are never gate-acceptable artifacts.

## CI Gate and Failure Policy

The gate runs schema validation, correlation checks, and redaction validation.

Failure mode is `fail-closed` with error code:

- `FE-FRX-20-4-LOG-SCHEMA-0001`

Gate blocks on:

- missing required fields
- cross-lane correlation mismatch
- retention/redaction policy violations

## Operator Verification

```bash
./scripts/run_frx_test_logging_schema_suite.sh ci
./scripts/e2e/frx_test_logging_schema_replay.sh
jq empty docs/frx_test_logging_schema_v1.json
```

Expected artifacts:

- `artifacts/frx_test_logging_schema/<UTC_TIMESTAMP>/run_manifest.json`
- `artifacts/frx_test_logging_schema/<UTC_TIMESTAMP>/events.jsonl`
- `artifacts/frx_test_logging_schema/<UTC_TIMESTAMP>/commands.txt`
