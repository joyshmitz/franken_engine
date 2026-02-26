# Parser Cross-Architecture Reproducibility Matrix Contract

This document defines the `PSRP-07.2` execution contract for cross-architecture
parser reproducibility checks across `x86_64` and `aarch64` targets.

## Scope

`PSRP-07.2` consumes deterministic evidence from upstream parser lanes and
produces an auditable matrix summary with drift classification:

- Event->AST equivalence lane:
  - `scripts/run_parser_event_ast_equivalence.sh`
  - `docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md`
- Parallel interference lane:
  - `scripts/run_parser_parallel_interference_gate.sh`
  - `docs/PARSER_PARALLEL_INTERFERENCE_GATE.md`
- Cross-arch matrix lane:
  - `scripts/run_parser_cross_arch_repro_matrix.sh`
  - `scripts/e2e/parser_cross_arch_repro_matrix_replay.sh`
  - `crates/franken-engine/tests/parser_cross_arch_repro_matrix.rs`
  - `crates/franken-engine/tests/fixtures/parser_cross_arch_repro_matrix_v1.json`

## Contract Version

- `schema_version`: `franken-engine.parser-cross-arch-repro-matrix.v1`
- `policy_id`: `policy-parser-cross-arch-repro-matrix-v1`

## Matrix Dimensions

- Architectures:
  - `x86_64-unknown-linux-gnu`
  - `aarch64-unknown-linux-gnu`
- Required lanes:
  - `parser_event_ast_equivalence`
  - `parser_parallel_interference`

For each lane, the matrix compares deterministic outcomes and witness digests
from both architectures and classifies the delta.

## Drift Classification

Delta classes are deterministic and explicit:

- `none` (`info`): outcomes, error-codes, and witness digests match.
- `toolchain_fingerprint_delta` (`warning`): outcomes/error-codes match but
  witness digest differs while toolchain fingerprints differ.
- `digest_delta_unexplained` (`critical`): outcomes/error-codes match but
  witness digest differs without a toolchain-fingerprint explanation.
- `upstream_lane_regression` (`critical`): outcome or error-code diverges.
- `missing_input` (`critical`): required architecture-lane manifest is absent.

`digest_delta_unexplained`, `upstream_lane_regression`, and `missing_input`
must fail-closed in `matrix` mode.

## Structured Logging Contract

Event streams for this lane must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Each lane-delta row must also include a deterministic replay pointer.

## Replay and Execution

Primary gate script:

```bash
./scripts/run_parser_cross_arch_repro_matrix.sh ci
```

Matrix execution mode (requires explicit manifest inputs for both
architectures):

```bash
PARSER_CROSS_ARCH_X86_EVENT_AST_MANIFEST=artifacts/.../x86_event_ast_run_manifest.json \
PARSER_CROSS_ARCH_ARM64_EVENT_AST_MANIFEST=artifacts/.../arm64_event_ast_run_manifest.json \
PARSER_CROSS_ARCH_X86_PARALLEL_INTERFERENCE_MANIFEST=artifacts/.../x86_parallel_run_manifest.json \
PARSER_CROSS_ARCH_ARM64_PARALLEL_INTERFERENCE_MANIFEST=artifacts/.../arm64_parallel_run_manifest.json \
./scripts/run_parser_cross_arch_repro_matrix.sh matrix
```

One-command replay wrapper:

```bash
./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh
```

All heavy Rust checks/tests are executed through `rch`.

## Required Artifacts

Each run emits:

- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/run_manifest.json`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/events.jsonl`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/commands.txt`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/matrix_lane_deltas.jsonl`
- `artifacts/parser_cross_arch_repro_matrix/<timestamp>/matrix_summary.json`

## Operator Verification

1. Run `./scripts/run_parser_cross_arch_repro_matrix.sh ci` to validate fixture,
   delta-classification logic, and replay contract tests.
2. Run `./scripts/run_parser_cross_arch_repro_matrix.sh matrix` with explicit
   `x86_64` and `aarch64` lane-manifest inputs.
3. Confirm:
   - `run_manifest.json` shows `matrix_complete=true`.
   - `matrix_summary.json` has expected architecture/lane coverage.
   - no critical unresolved deltas are present.
4. Run replay wrapper:

```bash
./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh
```
