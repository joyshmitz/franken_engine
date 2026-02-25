# Parser Verification Architecture and Coverage Map

This document defines the verification architecture for parser-frontier work
under `bd-2mds.1.9.1` and acts as the execution contract for `PSRP-09`
(verification matrix and evidence logging hardening).

## Scope

Applies to parser-facing subsystems in `crates/franken-engine`:

- `simd_lexer.rs` (byte classification/tokenization)
- `parser.rs` (core parser behavior)
- `ast.rs` (AST contracts and canonicalization)
- `parser_error_recovery.rs` (diagnostics and recovery behavior)
- `parser_arena.rs` + `parser_arena_phase1.rs` (arena and deterministic memory behavior)
- `parallel_parser.rs` + `parallel_interference_gate.rs` (parallel scheduling/merge behavior)
- `parser_oracle.rs` + `franken_parser_oracle_report` (semantic equivalence oracle)

## Verification Layers

The stack is cumulative: higher layers are not substitutes for lower layers.

| Layer | Purpose | Primary Signals | Fail Semantics |
|---|---|---|---|
| `L0` Compile/lint | Static correctness and hygiene | `cargo check`, `cargo clippy`, `cargo fmt --check` | fail-closed for touched parser surfaces |
| `L1` Unit tests | Local invariant checks per subsystem | deterministic `#[test]` in module files | fail-closed |
| `L2` Property/metamorphic | Input-space drift and nondeterminism detection | parser-phase0 metamorphic + oracle relations | fail-closed for semantic/nondeterminism classes |
| `L3` Integration | Cross-subsystem behavior and serialization contracts | `crates/franken-engine/tests/*parser*` integration files | fail-closed |
| `L4` Gate/e2e | Reproducible operator-facing gate runs | parser phase0/oracle/phase1 suite scripts | fail-closed in gate modes marked blocking |
| `L5` Evidence/audit | Deterministic artifacts and replayability | manifests/events/commands/proof notes | fail-closed on missing required artifacts |

## Subsystem Coverage Map

Each subsystem must have at least one active lane in each applicable layer.

| Subsystem | Unit / Local | Property / Metamorphic | Integration | Gate / E2E | Required Artifacts |
|---|---|---|---|---|---|
| SIMD lexer | `src/simd_lexer.rs` tests | parser phase0 metamorphic corpus | `tests/simd_lexer_integration.rs` | `scripts/run_parser_phase0_gate.sh` (`test`,`ci`) | phase0 `run_manifest.json`, `events.jsonl`, `commands.txt` |
| Parser core semantics | `src/parser.rs`, `src/ast.rs` tests | parser oracle fixture + metamorphic relation set + seeded property/regression generation in `tests/parser_property_regression.rs` | `tests/parser_trait_ast.rs`, `tests/parser_edge_cases.rs`, `tests/ast_integration.rs`, `tests/parser_property_regression.rs` | `scripts/run_parser_phase0_gate.sh`, `scripts/run_parser_oracle_gate.sh` | parser-oracle `baseline.json`, `relation_report.json`, `metamorphic_evidence.jsonl`, `manifest.json` |
| Benchmark protocol + corpus tiers | protocol fixture/test contract in `tests/parser_benchmark_protocol.rs` | deterministic tier/case parseability checks via fixture corpus | `tests/parser_benchmark_protocol.rs` | `scripts/run_parser_benchmark_protocol.sh` (`check`,`test`,`clippy`,`ci`) | parser-benchmark-protocol `run_manifest.json`, `events.jsonl`, `commands.txt` |
| Hermetic run wrappers + env manifests | deterministic env helper contract in `scripts/e2e/parser_deterministic_env.sh` | fixture contract in `tests/fixtures/parser_hermetic_env_manifest_v1.json` | `tests/parser_hermetic_wrapper_contract.rs` | `scripts/run_parser_benchmark_protocol.sh` (`test`,`ci`) | parser-benchmark-protocol `run_manifest.json`, `events.jsonl`, `commands.txt` with deterministic env + replay fields |
| Event IR + AST materialization | `src/ast.rs` tests | parser oracle semantic drift taxonomy | `tests/parser_trait_ast.rs`, `tests/parser_phase0_semantic_fixtures.rs` | parser oracle `ci` and replay-failure e2e | oracle `relation_events.jsonl`, `minimized_failures/`, `golden_checksums.txt` |
| Diagnostics + recovery | `src/parser_error_recovery.rs` tests | diagnostics drift checks in oracle | `tests/parser_error_recovery_integration.rs`, `tests/runtime_diagnostics_cli.rs` | parser oracle full/nightly e2e | oracle `proof_note.md` + replay command envelope |
| Arena allocator / memory determinism | `src/parser_arena.rs` tests | deterministic scenario replay (smoke/parity/budget/corruption) | `tests/parser_arena_integration.rs`, `tests/parser_arena_phase1.rs` | `scripts/run_parser_phase1_arena_suite.sh` and `scripts/e2e/parser_phase1_arena_*.sh` | phase1 `run_manifest.json`, `events.jsonl`, `commands.txt` |
| Parallel scheduler / merge / failover | `src/parallel_parser.rs` tests | deterministic depth-aware split-point, scheduler-transcript replay, source-order merge, merge-witness-hash assertions, deterministic failover trigger/transition controls | `tests/parallel_parser_integration.rs`, `tests/parallel_interference_gate_integration.rs` | `scripts/run_parser_depth_partitioner_gate.sh`, `scripts/run_parser_scheduler_transcript_gate.sh`, `scripts/run_parser_merge_witness_gate.sh`, `scripts/run_parser_failover_controls_gate.sh` + phase0/oracle backstops | parser-depth-partitioner + parser-scheduler-transcript + parser-merge-witness + parser-failover-controls `run_manifest.json`, `events.jsonl`, `commands.txt` |
| Oracle + differential harness | `src/parser_oracle.rs` tests | semantic/drift/metamorphic relation coverage | `tests/parser_oracle_integration.rs`, `tests/parser_oracle_gate.rs` | `scripts/run_parser_oracle_gate.sh`, `scripts/e2e/parser_oracle_*.sh` | `manifest.json`, `env.json`, `repro.lock`, `metamorphic_evidence.jsonl` |

## Boundary Definitions

Use these boundaries to prevent overlap and blind spots:

- **Unit boundary (`L1`)**: one module file, deterministic logic, no external artifact files.
- **Property/metamorphic boundary (`L2`)**: generated or transformed inputs proving invariants over input families.
- **Integration boundary (`L3`)**: at least two parser subsystems interacting (e.g., parser + AST, parser + arena).
- **E2E boundary (`L4`)**: scripted gate execution with reproducibility artifacts and operator replay command.

## Mandatory Logging Schema (Parser Verification v1)

All parser verification gate and benchmark runs must emit these keys in run
events (JSONL), regardless of mode:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Strongly recommended parser fields (required for parser-frontier gates):

- `workload_id` or `scenario`
- `corpus` or `partition`
- `replay_command`
- `deterministic_env_schema_version` (for hermetic wrapper lanes)
- `schema_version`
- `generated_at_utc`

Artifacts without the required base keys are invalid and must fail the run.

For parser subsystem property/regression tests (`bd-2mds.1.9.2`), assertion
failure context must be machine-parseable JSON that includes:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `seed`
- `replay_command`

## Coverage Ownership and Escalation Model

Coverage failures are triaged by failure class and escalated predictably.

### Failure Classes

1. `semantic_regression`: parser output/AST semantics drift.
2. `diagnostics_regression`: diagnostics format or recoverability drift.
3. `harness_nondeterminism`: repeated identical runs produce divergent output.
4. `artifact_contract_break`: required manifest/events schema missing or malformed.
5. `infrastructure_failure`: toolchain/rch/environment issue.

### Ownership Rules

1. The active bead assignee touching the affected subsystem owns first response.
2. If the failure is in shared gate infrastructure (`scripts/run_parser_*`), owner escalates to the active `PSRP-09.*` assignee.
3. If unresolved or owner is inactive, escalate to the parent epic owner (`bd-2mds`).

### Escalation Workflow

1. Add bead comment with command, failure code, artifact path, and replay command.
2. Send agent-mail update in coordination thread with affected files and blocker class.
3. If blocked by unrelated global drift, record exact file:line blockers and continue non-overlapping bead work.

## Execution Contract (CI and Local)

Primary parser verification entrypoints:

```bash
./scripts/run_parser_phase0_gate.sh ci
./scripts/run_parser_oracle_gate.sh ci
./scripts/run_parser_phase1_arena_suite.sh ci
./scripts/run_parser_benchmark_protocol.sh ci
./scripts/run_parser_depth_partitioner_gate.sh ci
./scripts/run_parser_scheduler_transcript_gate.sh ci
./scripts/run_parser_merge_witness_gate.sh ci
./scripts/run_parser_failover_controls_gate.sh ci
```

E2E wrappers:

```bash
./scripts/e2e/parser_oracle_smoke.sh
./scripts/e2e/parser_oracle_full.sh
./scripts/e2e/parser_phase1_arena_smoke.sh
./scripts/e2e/parser_phase1_arena_rollback_rehearsal.sh
```

All heavy Cargo operations in parser gate scripts must run via `rch`.

## Acceptance Gate for PSRP-09.1

`bd-2mds.1.9.1` is considered satisfied when:

1. This architecture + coverage map is published.
2. Mandatory logging schema fields are explicitly defined and referenced by parser gate docs.
3. Ownership/escalation model is documented and executable.
4. Existing parser gate docs remain consistent with this contract.
