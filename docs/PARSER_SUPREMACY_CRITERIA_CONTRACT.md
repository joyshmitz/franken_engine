# Parser Supremacy Criteria Contract (`bd-2mds.1.8.1`)

This document defines the parser supremacy criteria specification and mandatory
machine-evaluable evidence contract.

## Contract Version

- `schema_version`: `franken-engine.parser-supremacy-criteria-contract.v1`
- `criteria_version`: `0.1.0`
- `log_schema_version`: `franken-engine.parser-supremacy-criteria.log-event.v1`

## Required Criteria Dimensions

The criteria contract must evaluate these dimensions:

- correctness
- determinism
- performance
- reproducibility
- verification_rigor
- user_facing_quality

Each rule must declare:

- `rule_id`
- `rule_class`
- `description`
- `minimum_millionths`
- `weight_millionths`

All rule weights must sum to `1_000_000`.

## Machine-Checkable Evaluator

The evaluator must:

- deterministically score each artifact bundle against every rule
- produce a weighted composite score in millionths
- emit verdicts: `pass`, `hold`, or `fail`
- enforce hard-fail classes (`correctness`, `determinism`, `reproducibility`)

Verdict policy:

- `fail`: any hard-fail class is below its required threshold
- `hold`: no hard-fail breach, but at least one non-hard rule fails or weighted score below policy minimum
- `pass`: all rules pass and weighted score meets policy minimum

## Deterministic Gate Simulation

Criteria evaluation must include deterministic e2e simulation:

- repeated evaluation over identical bundles produces identical verdicts/log events
- each bundle includes replay command and immutable bundle identifier
- gate outputs are replayable from emitted artifacts

## Criteria Changelog Policy

Every criteria-version entry must include:

- `version`
- `rationale`
- `impact_assessment`
- `compatibility_notes`
- `changed_at_utc`

Criteria changes are invalid if any field is missing or empty.

## Structured Log Contract

Each gate decision event must include:

- `run_id`
- `criteria_version`
- `git_sha`
- `artifact_bundle_id`
- `verdict`
- `replay_command`

## Deterministic Execution Contract

All heavy Rust checks/tests must run through `rch`.

Canonical command:

```bash
./scripts/run_parser_supremacy_criteria_gate.sh ci
```

Modes:

- `check`: compile focused supremacy criteria test target
- `test`: run focused supremacy criteria tests
- `clippy`: lint focused supremacy criteria target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run must publish:

- `artifacts/parser_supremacy_criteria/<timestamp>/run_manifest.json`
- `artifacts/parser_supremacy_criteria/<timestamp>/events.jsonl`
- `artifacts/parser_supremacy_criteria/<timestamp>/commands.txt`

`run_manifest.json` must include:

- schema/version identifiers
- bead id, criteria version, mode, target-dir, git commit
- deterministic replay command
- command transcript and outcome

## Operator Verification

```bash
./scripts/run_parser_supremacy_criteria_gate.sh ci
cat artifacts/parser_supremacy_criteria/<timestamp>/run_manifest.json
cat artifacts/parser_supremacy_criteria/<timestamp>/events.jsonl
cat artifacts/parser_supremacy_criteria/<timestamp>/commands.txt
```
