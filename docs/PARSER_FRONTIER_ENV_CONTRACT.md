# Parser Frontier Deterministic Environment Contract

This document defines the deterministic environment bootstrap required for
parser-frontier gate and e2e scripts.

## Scope

- Applies to parser-frontier execution beads under epic `bd-2mds`.
- Current implementation is wired into parser phase1/event-materializer suites:
  - `scripts/run_parser_phase1_arena_suite.sh`
  - `scripts/e2e/parser_phase1_arena_*.sh`
  - `scripts/run_parser_event_materializer_lane.sh`
  - `scripts/e2e/parser_event_materializer_replay.sh`
- Hermetic wrapper + environment-manifest contract for `PSRP-07.1`:
  - `scripts/run_parser_benchmark_protocol.sh`
  - `crates/franken-engine/tests/parser_hermetic_wrapper_contract.rs`
  - `crates/franken-engine/tests/fixtures/parser_hermetic_env_manifest_v1.json`
- Cross-architecture reproducibility matrix contract for `PSRP-07.2`:
  - `scripts/run_parser_cross_arch_repro_matrix.sh`
  - `scripts/e2e/parser_cross_arch_repro_matrix_replay.sh`
  - `crates/franken-engine/tests/parser_cross_arch_repro_matrix.rs`
  - `crates/franken-engine/tests/fixtures/parser_cross_arch_repro_matrix_v1.json`
- Third-party rerun kit contract for `PSRP-07.3`:
  - `docs/PARSER_THIRD_PARTY_RERUN_KIT.md`
  - `scripts/run_parser_third_party_rerun_kit.sh`
  - `scripts/e2e/parser_third_party_rerun_kit_replay.sh`
  - `crates/franken-engine/tests/parser_third_party_rerun_kit.rs`
  - `crates/franken-engine/tests/fixtures/parser_third_party_rerun_kit_v1.json`
- Bootstrap helper source of truth:
  - `scripts/e2e/parser_deterministic_env.sh`
- Verification architecture reference:
  - `docs/PARSER_VERIFICATION_ARCHITECTURE.md` (`PSRP-09.1`)
- Logging schema/redaction reference:
  - `docs/PARSER_LOGGING_SCHEMA_V1.md` (`PSRP-09.5.1`)

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

## Hermetic Wrapper Contract (PSRP-07.1)

Parser wrappers participating in this contract must:

1. Source and bootstrap deterministic env from `scripts/e2e/parser_deterministic_env.sh`.
2. Execute heavy Rust commands through `rch`.
3. Emit stable manifest keys:
   - `deterministic_env_schema_version`
   - `deterministic_environment`
   - `replay_command`
4. Emit event rows that include parser logging base keys plus `replay_command`.
5. Publish deterministic artifacts:
   - `run_manifest.json`
   - `events.jsonl`
   - `commands.txt`
6. Provide one-command operator replay via `replay_command`.

## Manifest Requirements

Run manifests emitted by parser-frontier suites must include:

- `deterministic_env_schema_version`
- `deterministic_environment` object with all required fields above

## Event Logging Requirements

Parser-frontier gate event streams must include required stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

See `docs/PARSER_VERIFICATION_ARCHITECTURE.md` for full parser verification
schema, subsystem coverage map, and escalation model.

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

Parser benchmark-protocol hermetic wrapper verification:

```bash
CARGO_TARGET_DIR=/data/tmp/rch_target_franken_engine_parser_benchmark_protocol \
  ./scripts/run_parser_benchmark_protocol.sh test
cat artifacts/parser_benchmark_protocol/<timestamp>/run_manifest.json
cat artifacts/parser_benchmark_protocol/<timestamp>/events.jsonl
cat artifacts/parser_benchmark_protocol/<timestamp>/commands.txt
```

Confirm manifest includes:
- `deterministic_env_schema_version`
- `deterministic_environment` object with required fields
- `replay_command`
