# Parser API Compatibility Contract (`bd-2mds.1.10.3`)

This document defines the deterministic compatibility and migration contract for
public parser APIs consumed by downstream integration surfaces.

## Scope

Parser API compatibility artifacts are owned by:

- `docs/PARSER_API_COMPATIBILITY_CONTRACT.md`
- `crates/franken-engine/tests/fixtures/parser_api_compatibility_contract_v1.json`
- `crates/franken-engine/tests/parser_api_compatibility_contract.rs`
- `scripts/run_parser_api_compatibility_gate.sh`

This contract is binding for PSRP-10.3 parser API stabilization and for
downstream PSRP-10.4/10.5 release readiness gates.

## Contract Version

- `schema_version`: `franken-engine.parser-api-compatibility-contract.v1`
- `contract_version`: `1.0.0`
- parser API surface id: `franken-engine.parser-public-api.v1`
- parser diagnostics dependency:
  `franken-engine.parser-diagnostics.schema.v1`
- parser event-IR dependency:
  `franken-engine.parser-event-ir.schema.v2`

## Stable Public API Surface

PSRP-10.3 protects these entrypoints as compatibility-critical:

- `Es2020Parser::parse`
- `CanonicalEs2020Parser::parse_with_options`
- `CanonicalEs2020Parser::parse_with_event_ir`
- `CanonicalEs2020Parser::parse_with_materialized_ast`
- `CanonicalEs2020Parser::scalar_reference_grammar_matrix`
- input adapters:
  - `&str`
  - `String`
  - `&Path` / `PathBuf`
  - `StreamInput<R: Read>`

Any contract drift in these APIs requires explicit migration notes and fixture
updates in the same change.

## Compatibility Matrix

Compatibility tests must exercise stable behavior for:

- `script` and `module` goals
- success/failure result envelopes
- deterministic canonical hashes for successful parses
- deterministic normalized diagnostics for failing parses
- deterministic event-IR envelopes (`trace_id`, `decision_id`, `policy_id`,
  `component`, `outcome`, `error_code`)

The matrix is encoded in
`tests/fixtures/parser_api_compatibility_contract_v1.json`.

## Migration Policy

Public parser API changes must follow this fail-closed policy:

1. Deprecate before removal for at least one contract version.
2. Publish migration notes with old/new API mapping and replay verification
   commands.
3. Keep deterministic behavior claims explicit (or document the intentional
   drift with a contract version bump).
4. Reject silent compatibility breaks; CI gate must fail without updated
   migration notes and fixtures.

## Ergonomics SLOs

The compatibility gate tracks millionths-based SLOs:

- `integration_success_rate`
- `input_adapter_coverage`
- `migration_readability`

The fixture sets baseline + allowed regression budget; gate fails if any score
drops below baseline minus budget.

## Structured Log Contract

Compatibility vectors must expose stable parse event keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `kind`
- `outcome`
- `error_code`

## Deterministic Execution Contract

All heavy Rust compatibility checks/tests must run through `rch` wrappers.

Canonical command:

```bash
./scripts/run_parser_api_compatibility_gate.sh ci
```

Modes:

- `check`: compile focused parser API compatibility test target
- `test`: execute focused parser API compatibility tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + test + clippy

## Required Artifacts

Each run must publish:

- `artifacts/parser_api_compatibility/<timestamp>/run_manifest.json`
- `artifacts/parser_api_compatibility/<timestamp>/events.jsonl`
- `artifacts/parser_api_compatibility/<timestamp>/commands.txt`

`run_manifest.json` must include:

- schema/version ids
- bead id and parser API surface id
- toolchain + mode + target-dir
- git commit + dirty-worktree state
- exact executed command list
- deterministic replay command

## Operator Verification

```bash
./scripts/run_parser_api_compatibility_gate.sh ci
cat artifacts/parser_api_compatibility/<timestamp>/run_manifest.json
cat artifacts/parser_api_compatibility/<timestamp>/events.jsonl
cat artifacts/parser_api_compatibility/<timestamp>/commands.txt
```

The run is invalid if required files are missing or event records do not contain
the required structured keys.
