# Parser Frontier Deterministic Environment Contract

This document defines the deterministic environment bootstrap required for
parser-frontier gate and e2e scripts.

## Scope

- Applies to parser-frontier execution beads under epic `bd-2mds`.
- Current implementation is wired into the parser phase1 arena suite:
  - `scripts/run_parser_phase1_arena_suite.sh`
  - `scripts/e2e/parser_phase1_arena_*.sh`
- Bootstrap helper source of truth:
  - `scripts/e2e/parser_deterministic_env.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-frontier.env-contract.v1`

## Required Controls

Every parser-frontier gate/e2e run must set and record:

1. Locale/time:
- `TZ=UTC`
- `LANG=C.UTF-8`
- `LC_ALL=C.UTF-8`

2. Reproducible build timestamp baseline:
- `SOURCE_DATE_EPOCH=0` (unless explicitly overridden by caller)

3. Toolchain/runtime fingerprint metadata:
- `rustc_version`
- `cargo_version`
- `rust_host` target triple host
- `cpu_fingerprint` (stable hash of CPU identity/features)
- `rustc_verbose_hash`
- `toolchain_fingerprint`

4. Seed contract:
- `seed_transcript_checksum` must be present in manifest payload.
- Use `null` only when a scenario does not produce a seed transcript.

## Manifest Requirements

Run manifests emitted by parser-frontier suites must include:

- `deterministic_env_schema_version`
- `deterministic_environment` object with all required fields above

## Operator Verification

1. Run an e2e wrapper, for example:
```bash
./scripts/e2e/parser_phase1_arena_smoke.sh
```
2. Open emitted manifest under `artifacts/parser_phase1_arena/<timestamp>/run_manifest.json`.
3. Confirm:
- `deterministic_env_schema_version` equals `franken-engine.parser-frontier.env-contract.v1`
- `deterministic_environment.timezone` is `UTC`
- `deterministic_environment.lang` and `lc_all` are `C.UTF-8`
- `deterministic_environment.toolchain_fingerprint` is populated
- `deterministic_environment.seed_transcript_checksum` is present

