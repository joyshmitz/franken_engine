# Parser User-Impact Regression Alarms + SLO Guardrails (`bd-2mds.1.10.5.2`)

This document defines the deterministic regression-alarm and SLO-guardrail
contract for parser user-impact quality, building on
`bd-2mds.1.10.5.1` baseline dashboard instrumentation.

## Scope

Alarm/SLO artifacts are owned by:

- `docs/PARSER_USER_IMPACT_REGRESSION_ALARMS_SLO_GUARDRAILS.md`
- `crates/franken-engine/tests/fixtures/parser_user_impact_regression_alarms_v1.json`
- `crates/franken-engine/tests/parser_user_impact_regression_alarms.rs`
- `scripts/run_parser_user_impact_regression_alarms.sh`
- `scripts/e2e/parser_user_impact_regression_alarms_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-user-impact-regression-alarms.v1`
- `pipeline_version`: `1.0.0`
- `log_schema_version`: `franken-engine.parser-log-event.v1`

## Alarm Policy Model

Each alarm policy row defines deterministic threshold semantics:

- `alarm_id`
- `slo_id`
- `metric_key`
- `comparator` (`min` or `max`)
- `threshold_millionths`
- `severity` (`warning`, `high`, `critical`)
- `escalation_action`
- `error_code`
- `replay_command`

Policy evaluation rules:

- `min`: breach when `observed_value < threshold`
- `max`: breach when `observed_value > threshold`
- warning alarms are non-blocking and logged for trend pressure
- high/critical alarms are blocking for release/readiness gate posture

## SLO Guardrail Semantics

The latest deterministic observation window controls gate posture:

- `pass`: zero high/critical breaches in latest window
- `hold`: one or more high/critical breaches in latest window

Gate output must include explicit downstream consumption status:

- `psrp_10_4_status`: `ready` or `blocked`
- `psrp_8_4_status`: `ready` or `blocked`

`hold` must map to `blocked` for both downstream statuses.

## Deterministic Incident Simulations

Fixture-defined incident scenarios must include deterministic e2e harness
payloads and replay commands.

Required behavior:

- repeated runs of same scenario/seed produce identical event stream + digest
- expected pass/fail per scenario is enforced
- incident replay command is present and non-empty for every scenario

## Structured Log Contract

Alarm pipeline logs must be emitted as structured objects containing:

- `schema_version`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `replay_command`
- `alarm_id`
- `slo_id`

## Deterministic Execution Contract

All heavy Rust checks/tests run through `rch`.

Canonical command:

```bash
./scripts/run_parser_user_impact_regression_alarms.sh ci
```

Modes:

- `check`: compile focused alarm/SLO test target
- `test`: execute focused alarm/SLO tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run publishes:

- `artifacts/parser_user_impact_regression_alarms/<timestamp>/run_manifest.json`
- `artifacts/parser_user_impact_regression_alarms/<timestamp>/events.jsonl`
- `artifacts/parser_user_impact_regression_alarms/<timestamp>/commands.txt`

Run manifest must include:

- schema/version identifiers
- bead id, mode, toolchain, target-dir, timeout
- trace/policy identity
- command transcript + deterministic replay command
- contract, fixture, test, and replay wrapper pointers

## Operator Verification

```bash
./scripts/run_parser_user_impact_regression_alarms.sh ci
cat artifacts/parser_user_impact_regression_alarms/<timestamp>/run_manifest.json
cat artifacts/parser_user_impact_regression_alarms/<timestamp>/events.jsonl
cat artifacts/parser_user_impact_regression_alarms/<timestamp>/commands.txt
./scripts/e2e/parser_user_impact_regression_alarms_replay.sh
```

A run is invalid if required artifacts or required structured-log keys are
missing.
