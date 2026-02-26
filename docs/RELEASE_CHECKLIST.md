# FrankenEngine Release Checklist

This checklist is a release gate artifact. A release is blocked until every item
below is satisfied or an approved, linked exception is present.

## Machine-Readable Gate (`bd-ag4`)

Release candidates must publish a machine-readable checklist artifact with:

- schema version `franken-engine.release-checklist.v1`
- release tag (`release_tag`)
- UTC generation timestamp (`generated_at_utc`)
- structured checklist items (status + artifact references + optional waiver)

Recommended path:

- `artifacts/releases/<release_tag>/release_checklist.json`

Deterministic gate runner (all heavy Rust commands are offloaded via `rch`):

```bash
./scripts/run_release_checklist_gate.sh ci
./scripts/run_release_checklist_gate.sh check
./scripts/run_release_checklist_gate.sh test
./scripts/run_release_checklist_gate.sh clippy
```

Machine-readable required item IDs:

- `security.conformance_suite`
- `security.adversarial_corpus`
- `security.containment_latency`
- `security.ifc_coverage`
- `security.plas_witness_coverage`
- `performance.benchmark_suite`
- `performance.speedup_gate_3x`
- `performance.flamegraph_comparisons`
- `performance.gc_pause_budget`
- `reproducibility.env_json`
- `reproducibility.manifest_json`
- `reproducibility.repro_lock`
- `operational.safe_mode_test`
- `operational.diagnostics_cli_test`
- `operational.evidence_export_test`

## Core Validation Gate

- [ ] `rch exec -- ... cargo fmt --check`
- [ ] `rch exec -- ... cargo check --all-targets`
- [ ] `rch exec -- ... cargo test`
- [ ] `rch exec -- ... cargo clippy --all-targets -- -D warnings`
- [ ] Reproducibility artifacts recorded per `docs/REPRODUCIBILITY_CONTRACT.md`

## Adversarial Suppression Gate (`bd-3rd`)

- [ ] `./scripts/run_adversarial_campaign_gate.sh ci`
- [ ] `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_adversarial_gate cargo run -p frankenengine-engine --bin franken_adversarial_campaign_gate -- --input crates/franken-engine/tests/fixtures/adversarial_campaign_gate_input_v1.json --out artifacts/adversarial_campaign_gate/<timestamp>/gate_result.json`
- [ ] Per-attack-category compromise rate suppression versus `node_lts` and `bun_stable` with `p <= 0.05`.
- [ ] Continuous-run evidence present (minimum two trend points and current release-candidate run).
- [ ] Successful FrankenEngine exploit findings trigger escalation workflow inside configured SLA.

Deterministic gate thresholds:

| Metric | Threshold |
| --- | --- |
| Required baseline runtimes | `>= 2` (`node_lts`, `bun_stable`) |
| Statistical significance | `p_value_millionths <= 50000` (`p <= 0.05`) |
| Continuous-run requirement | `continuous_run = true` |
| Trend coverage | `trend_points >= 2` |
| Escalation SLA | `escalation_latency_seconds <= 3600` |

Operator verification commands:

```bash
cat artifacts/adversarial_campaign_gate/<timestamp>/run_manifest.json
cat artifacts/adversarial_campaign_gate/<timestamp>/gate_result.json
```

## Reuse Vs Reimplement Decisions

Record every release-scope PR that introduces new infrastructure in one of the
tracked categories.

| PR/Change | Category | Canonical sibling repo | Decision (reuse/reimplement) | ADR / exception reference | Exception artifact link | Justification link |
| --- | --- | --- | --- | --- | --- | --- |
| | Operator TUI surface | `/dp/frankentui` | | `ADR-0003` | | |
| | SQLite persistence path | `/dp/frankensqlite` | | `ADR-0004` | | |
| | Service/API control surface | `/dp/fastapi_rust` | | `ADR-0002` | | |

### Validation Rules

1. If a release includes a new TUI, SQLite, or service/API infrastructure path,
the table above must include an entry for that change.
2. `Decision (reuse/reimplement)` is required for every entry.
3. Any `reimplement` entry must include:
   - an approved ADR exception reference
   - an exception artifact link
   - a written justification link
4. Release gate fails if any reimplement decision lacks exception or justification evidence.

## Sign-Off

- [ ] Release owner reviewed all reuse/reimplement entries.
- [ ] Governance reviewer confirmed ADR/exception traceability.
