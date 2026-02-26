# Parser Third-Party Rerun Kit Contract

This document defines the `PSRP-07.3` execution contract for producing a
third-party rerun kit that external verifiers can execute without insider
knowledge.

## Scope

`PSRP-07.3` packages deterministic outputs from upstream parser lanes into a
single verification bundle:

- Hermetic environment contract:
  - `docs/PARSER_FRONTIER_ENV_CONTRACT.md`
  - `scripts/e2e/parser_deterministic_env.sh`
- Cross-architecture reproducibility matrix lane (`PSRP-07.2`):
  - `docs/PARSER_CROSS_ARCH_REPRO_MATRIX.md`
  - `scripts/run_parser_cross_arch_repro_matrix.sh`
  - `scripts/e2e/parser_cross_arch_repro_matrix_replay.sh`
- Third-party rerun kit lane (`PSRP-07.3`):
  - `scripts/run_parser_third_party_rerun_kit.sh`
  - `scripts/e2e/parser_third_party_rerun_kit_replay.sh`
  - `crates/franken-engine/tests/parser_third_party_rerun_kit.rs`
  - `crates/franken-engine/tests/fixtures/parser_third_party_rerun_kit_v1.json`

## Contract Version

- `schema_version`: `franken-engine.parser-third-party-rerun-kit.v1`
- `policy_id`: `policy-parser-third-party-rerun-kit-v1`

## Upstream Dependencies

Primary upstream inputs are matrix artifacts emitted by `PSRP-07.2`:

- `matrix_summary.json`
- `matrix_lane_deltas.jsonl`
- `run_manifest.json`

`PSRP-07.3` is allowed to run in prework mode before upstream matrix evidence
is complete, but it must classify readiness deterministically and fail closed
for promotion-critical states.

## Kit Contents

Each run emits a deterministic bundle with:

- run metadata and environment fingerprint (`run_manifest.json`)
- structured event stream (`events.jsonl`)
- exact executed commands (`commands.txt`)
- machine-readable kit index (`rerun_kit_index.json`)
- operator/verifier notes (`verifier_notes.md`)

The kit index must include:

- matrix input paths and presence booleans
- deterministic `matrix_input_status`
- replay command pointers
- explicit fail-closed guidance for unresolved critical deltas

## Matrix Input Status Model

`matrix_input_status` is deterministic and must be one of:

- `pending_upstream_matrix`: matrix summary was not provided.
- `incomplete_matrix`: matrix summary exists but reports incomplete coverage.
- `blocked_critical_deltas`: matrix summary reports one or more critical deltas.
- `ready_for_external_rerun`: matrix complete and critical delta count is zero.

Promotion-relevant tooling must treat all statuses except
`ready_for_external_rerun` as fail-closed.

## Replay and Execution

Primary gate script:

```bash
./scripts/run_parser_third_party_rerun_kit.sh ci
```

Package-focused mode with explicit matrix inputs:

```bash
PARSER_RERUN_KIT_MATRIX_SUMMARY=artifacts/.../matrix_summary.json \
PARSER_RERUN_KIT_MATRIX_DELTAS=artifacts/.../matrix_lane_deltas.jsonl \
PARSER_RERUN_KIT_MATRIX_MANIFEST=artifacts/.../run_manifest.json \
./scripts/run_parser_third_party_rerun_kit.sh package
```

One-command replay wrapper:

```bash
./scripts/e2e/parser_third_party_rerun_kit_replay.sh
```

All heavy Rust build/test/lint commands must execute through `rch`.

## Required Artifacts

Each run emits:

- `artifacts/parser_third_party_rerun_kit/<timestamp>/run_manifest.json`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/events.jsonl`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/commands.txt`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/rerun_kit_index.json`
- `artifacts/parser_third_party_rerun_kit/<timestamp>/verifier_notes.md`

## Operator Verification

1. Run `./scripts/run_parser_third_party_rerun_kit.sh ci`.
2. Optionally rerun in `package` mode with explicit matrix artifact inputs.
3. Confirm:
   - `run_manifest.json` has deterministic env fields and replay command.
   - `rerun_kit_index.json` has expected `matrix_input_status`.
   - `events.jsonl` validates with `scripts/validate_parser_log_schema.sh`.
4. Replay through:

```bash
./scripts/e2e/parser_third_party_rerun_kit_replay.sh
```
