# Observability Information-Theoretic Channel Contract

## Scope

This contract captures the FRX-17 observability design:

- `observability_channel_model.rs`: rate-distortion envelopes and channel constitutions
- `observability_probe_design.rs`: budget-constrained probe selection and multimode schedules
- `entropy_evidence_compressor.rs`: entropy-bound compression certificates
- `observability_quality_sentinel.rs`: fail-closed quality monitoring and deterministic demotion

## Deterministic Invariants

1. Every evidence family has an explicit distortion metric and a bounded rate-distortion envelope.
2. Lossless-only channels (replay, security, legal provenance) reject lossy emissions.
3. Probe schedules are selected from a declared objective under explicit latency/memory/count budgets.
4. Compression artifacts emit machine-checkable certificates with Kraft and Shannon-bound fields.
5. Sentinel quality breaches deterministically produce degradation artifacts and demotion receipts.

## Evidence Families and Distortion Policy

Required evidence families:

- `decision`
- `replay`
- `optimization`
- `security`
- `legal_provenance`

Lossless constraints:

- `replay`: `max_distortion_millionths = 0`, `lossy_permitted = false`
- `security`: `max_distortion_millionths = 0`, `lossy_permitted = false`
- `legal_provenance`: `max_distortion_millionths = 0`, `lossy_permitted = false`

## Probe Objective Contract

Probe selection is not heuristic. It must be explainable by:

- Utility term: forensic utility (`forensic_utility_millionths`)
- Resource constraints: latency, memory, probe count
- Coverage term: event-space coverage in millionths
- Mode-aware budgets: `normal`, `degraded`, `incident`

Expected monotonic behavior:

- `incident` mode must provide coverage greater than or equal to `normal` mode
- schedule hashes and multimode manifest hashes must be deterministic for the same universe

## Compression Certificate Contract

Required certificate fields:

- `entropy_millibits_per_symbol`
- `shannon_lower_bound_bits`
- `achieved_bits`
- `overhead_ratio_millionths`
- `kraft_sum_millionths`
- `kraft_satisfied`
- `certificate_hash`

Gate semantics:

- Kraft must be satisfied (`kraft_sum_millionths <= 1_000_000 + tolerance`)
- Overhead ratio checks must fail closed when lower bounds are degenerate

## Quality Sentinel Contract

Signal quality dimensions:

- `signal_fidelity`
- `blind_spot_ratio`
- `reconstruction_ambiguity`
- `tail_undercoverage`
- `evidence_staleness`

Fail-closed behavior:

- quality breaches produce deterministic degradation artifacts
- matching demotion rules produce deterministic demotion receipts
- severe fidelity degradation triggers `full_replay_capture`
- gate fails when sentinel reports degraded state

## Verification and Artifacts

Run the FRX-17 gate script:

```bash
./scripts/run_observability_information_theoretic_gate.sh ci
```

Artifacts are emitted under:

- `artifacts/observability_information_theoretic/<timestamp>/run_manifest.json`
- `artifacts/observability_information_theoretic/<timestamp>/events.jsonl`
- `artifacts/observability_information_theoretic/<timestamp>/commands.txt`

Primary integration test:

- `crates/franken-engine/tests/observability_channel_model.rs`

Bead reference:

- `bd-mjh3.17`
