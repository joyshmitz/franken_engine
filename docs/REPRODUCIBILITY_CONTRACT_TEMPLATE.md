# Reproducibility Contract Template

Use this template set to build a deterministic reproducibility bundle for benchmark, security, compatibility, and replay claims.

Required files:
- `env.json`
- `manifest.json`
- `repro.lock`

Recommended supporting files:
- `commands.txt`
- `results.json`
- `README.md`

## Directory Layout

```text
artifacts/<bundle_id>/
  env.json
  manifest.json
  repro.lock
  commands.txt
  results.json
  README.md
  payload/
    ...
```

## Schema Compatibility Rules

- Current schema majors:
  - `franken-engine.env.v1`
  - `franken-engine.manifest.v1`
  - `franken-engine.repro-lock.v1`
- Optional additive fields are allowed within a major.
- Required-field changes require a major version bump.
- Validation is fail-closed for missing required fields.

## Canonicalization Rules

Contract files must serialize as canonical JSON:
- UTF-8
- lexicographic key ordering
- LF newlines
- stable array ordering
- `sha256` digests computed over full canonical bytes

## 1) `env.json` Template

`env.json` captures runtime environment and policy context.

Required fields:
- `schema_version`
- `schema_hash`
- `captured_at_utc`
- `project`
- `host`
- `toolchain`
- `runtime`
- `policy`

Template file: `docs/templates/env.json.template`

## 2) `manifest.json` Template

`manifest.json` is the authority index for claim metadata, provenance linkage, and artifact digests.

Required fields:
- `schema_version`
- `schema_hash`
- `manifest_id`
- `generated_at_utc`
- `claim`
- `source_revision`
- `provenance`
- `artifacts`
- `inputs`
- `outputs`
- `canonicalization`
- `validation`
- `retention`

Template file: `docs/templates/manifest.json.template`

## 3) `repro.lock` Template

`repro.lock` freezes the deterministic command recipe and expected outputs.

Required fields:
- `schema_version`
- `schema_hash`
- `generated_at_utc`
- `lock_id`
- `manifest_id`
- `source_commit`
- `determinism`
- `commands`
- `inputs`
- `expected_outputs`
- `replay`
- `verification`

Template file: `docs/templates/repro.lock.template`

## Provenance Linkage Requirements

`manifest.json.provenance` must include:
- `trace_id`
- `decision_id`
- `policy_id`
- `replay_pointer`
- `evidence_pointer`
- `receipt_ids`

`manifest.json.artifacts` must reference `env.json` and `repro.lock` with matching digests.

## Validator Contract (Deterministic)

One-command verifier flow:

```bash
frankenctl repro verify --bundle artifacts/<bundle_id> --output artifacts/<bundle_id>/verify_report.json
```

Validator output must include stable fields:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Stable error taxonomy:
- `FE-REPRO-0001` through `FE-REPRO-0008` (see `docs/REPRODUCIBILITY_CONTRACT.md`)

## Fail-Closed and Degraded Mode

- Missing/partial/stale/inconsistent bundles fail validation.
- Degraded mode is diagnostic-only and cannot publish `observed` claims.
- Any override must emit explicit override artifact with operator rationale.

## CI Gate Contract

CI must fail if:
- required files are missing,
- schema validation fails,
- any hash mismatch occurs,
- locked commands fail,
- expected outputs do not match declared digests.

## Retention and Rotation

- Minimum retention for published bundles: 365 days.
- High-impact security/replay bundles: 730 days.
- Rotation must keep content-addressable retrieval and audit traceability.

## Operator Checklist

1. Fill all template placeholders.
2. Run deterministic verifier command.
3. Confirm pass verdict and hash matches.
4. Attach bundle path and verifier report to claim publication context.
5. If validation fails, downgrade to intent-language.
