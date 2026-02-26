# Parser Differential Nightly Governance Contract (`bd-2mds.1.2.4.2`)

This document defines the deterministic nightly differential-operations lane that
follows the parser multi-engine minimizer/repro-pack pipeline.

## Scope

This lane is implemented by:

- `docs/PARSER_DIFFERENTIAL_NIGHTLY_GOVERNANCE.md`
- `crates/franken-engine/tests/fixtures/parser_differential_nightly_governance_v1.json`
- `crates/franken-engine/tests/parser_differential_nightly_governance.rs`
- `scripts/run_parser_differential_nightly_governance.sh`
- `scripts/e2e/parser_differential_nightly_governance_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-differential-nightly-governance.v1`
- `governance_version`: `1.0.0`

## Deterministic Nightly Schedule

Nightly runs use a deterministic environment manifest:

- fixed locale (`C`)
- fixed timezone (`UTC`)
- fixed seed transcript root
- explicit partition map (`smoke`, `full`, `promotion-candidates`)
- deterministic partition ordering

The schedule manifest is fingerprinted with a deterministic digest and emitted in
fixtures/artifacts so independent operators can recompute it.

## Governance and Escalation Policy

Every drift finding is evaluated against severity + waiver state:

- `critical` and unwaived findings hard-block promotion
- expired waivers are treated as unwaived and emit explicit expiry blockers
- `minor` findings route to owner remediation and remain visible in governance
  events
- valid waivers can suppress escalation but still emit auditable structured logs

Escalations are deterministic and owner-routed (`page_owner:<owner_hint>`).

## Remediation Promotion Contract

For each unwaived finding:

- if a remediation bead already exists for the finding fingerprint, the lane
  emits an `update` action
- otherwise the lane emits a deterministic `create` action with a stable
  generated bead id (`bd-auto-<fingerprint-prefix>`)

Every remediation action includes replay command + artifact pointers.

## Structured Logging Contract

Required governance event keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Parser differential findings additionally include:

- `finding_id`
- `fingerprint`
- `severity`
- `owner_hint`
- `replay_command`
- `remediation_action`

## Deterministic Replay

One-command replay wrapper:

```bash
./scripts/e2e/parser_differential_nightly_governance_replay.sh
```

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane run via `rch`.

Canonical command:

```bash
./scripts/run_parser_differential_nightly_governance.sh ci
```

Modes:

- `check`: compile focused governance test target
- `test`: execute focused governance tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run emits:

- `artifacts/parser_differential_nightly_governance/<timestamp>/run_manifest.json`
- `artifacts/parser_differential_nightly_governance/<timestamp>/events.jsonl`
- `artifacts/parser_differential_nightly_governance/<timestamp>/commands.txt`

## Operator Verification

```bash
./scripts/run_parser_differential_nightly_governance.sh ci
cat artifacts/parser_differential_nightly_governance/<timestamp>/run_manifest.json
cat artifacts/parser_differential_nightly_governance/<timestamp>/events.jsonl
cat artifacts/parser_differential_nightly_governance/<timestamp>/commands.txt
./scripts/e2e/parser_differential_nightly_governance_replay.sh
```
