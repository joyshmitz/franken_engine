# Runtime Diagnostics and Evidence Export CLI (`bd-2mm`)

Deterministic diagnostics and evidence export surface for Section 10.8 item 1.

## Binary

```bash
cargo run -p frankenengine-engine --bin runtime_diagnostics -- help
```

Subcommands:

- `diagnostics`: emit runtime-state diagnostics
- `export-evidence`: export evidence bundle with deterministic filtering/sorting

## Input Contract

The binary reads a deterministic JSON input file matching
`RuntimeDiagnosticsCliInput` from `crates/franken-engine/src/runtime_diagnostics_cli.rs`.

Input includes:

- runtime state snapshot:
  - loaded extensions + containment state
  - active policy IDs
  - security epoch
  - GC pressure samples
  - scheduler lane samples
- evidence sources:
  - decision receipts (evidence ledger entries)
  - hostcall telemetry envelopes
  - containment receipt envelopes
  - replay artifact pointers

## Commands

Diagnostics JSON output:

```bash
runtime_diagnostics diagnostics --input artifacts/runtime_input.json
```

Diagnostics human summary:

```bash
runtime_diagnostics diagnostics --input artifacts/runtime_input.json --summary
```

Evidence export JSON output:

```bash
runtime_diagnostics export-evidence --input artifacts/runtime_input.json
```

Evidence export with filters:

```bash
runtime_diagnostics export-evidence \
  --input artifacts/runtime_input.json \
  --extension-id ext-a \
  --trace-id trace-incident \
  --start-ns 1100 \
  --end-ns 1200 \
  --severity warning \
  --decision-type security_action
```

Evidence export summary mode:

```bash
runtime_diagnostics export-evidence --input artifacts/runtime_input.json --summary
```

## Determinism Rules

- Stable output ordering:
  - diagnostics tables sorted by deterministic keys
  - evidence records sorted by `(timestamp_ns, kind, trace_id, decision_id, extension_id)`
- Filters are pure and deterministic for identical inputs.
- Re-running the same command over the same input yields byte-identical JSON output.

## Structured Log Fields

Both diagnostics and export emit log events with required stable fields:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Suite Runner

```bash
./scripts/run_runtime_diagnostics_suite.sh ci
```

Modes:

- `check`
- `test`
- `clippy`
- `ci`

Runner uses `rch` when available and falls back to local execution where `rch`
is unavailable (for hosted CI environments).

## Reproducibility Artifacts

Each run writes:

- `artifacts/runtime_diagnostics/<timestamp>/commands.txt`
- `artifacts/runtime_diagnostics/<timestamp>/events.jsonl`
- `artifacts/runtime_diagnostics/<timestamp>/run_manifest.json`

`run_manifest.json` includes operator verification commands.
