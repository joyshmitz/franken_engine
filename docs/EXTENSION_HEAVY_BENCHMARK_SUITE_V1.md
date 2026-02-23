# Extension-Heavy Benchmark Suite v1.0 (Normative)

This document is the normative publication contract for FrankenEngine Extension-Heavy Benchmark Suite v1.0.

It defines what must be measured, how scores are computed, and which artifacts are required before any benchmark claim can be published as `observed`.

## Normative Status

- This document is binding for Section 14 benchmark publication and claim gating.
- Implementation harness details remain in implementation-owner beads (for example `bd-2ql`, `bd-mhz4`).
- Any claim that does not satisfy this contract must be downgraded to intent-language.

## Required Benchmark Families

| Family ID | Purpose | Required Profiles |
| --- | --- | --- |
| `boot-storm` | Extension cold-start and initialization under load. | `S`, `M`, `L` |
| `capability-churn` | Rapid capability grant/revoke cycles and policy pressure. | `S`, `M`, `L` |
| `mixed-cpu-io-agent-mesh` | Combined CPU/I/O workload simulating agent mesh traffic. | `S`, `M`, `L` |
| `reload-revoke-churn` | Hot-reload and revocation while traffic remains continuous. | `S`, `M`, `L` |
| `adversarial-noise-under-load` | Legitimate workload with adversarial extension noise injected. | `S`, `M`, `L` |

## Threat Scenario Matrix (Normative)

Security workloads and adversarial tracks must include the following scenario classes:
1. credential theft attempt with escalating sophistication
2. privilege escalation via hostcall sequence abuse
3. data exfiltration via covert channel construction
4. policy evasion via benign-mimicking behavior
5. supply-chain compromise via dependency poisoning

Each scenario execution must declare:
- `attack_category`
- `scenario_id`
- `expected_detection_outcome`
- `expected_containment_outcome`
- `expected_latency_bound_ms`
- `corpus_checksum_sha256`

## Scale Profile Matrix (Normative Defaults)

| Profile | Extension Count | Event Rate (events/sec) | Dependency Graph Size | Policy Complexity Tier |
| --- | --- | --- | --- | --- |
| `S` | 10 | 1_000 | 200 edges | `baseline` |
| `M` | 100 | 10_000 | 2_000 edges | `hardened` |
| `L` | 1_000 | 50_000 | 20_000 edges | `stress` |

Overrides are allowed only when explicitly declared in manifest artifacts and published with rationale.

## Canonical Workload and Golden Manifests

The normative machine-readable manifests for this suite are:
- `docs/extension_heavy_workload_matrix_v1.json`
- `docs/extension_heavy_golden_outputs_v1.json`

Contract requirements:
- workload matrix must contain exactly five families with `S/M/L` profiles (`15` total workload IDs)
- every workload must declare deterministic `dataset_checksum_sha256` and `seed_transcript_sha256`
- every workload must reference a `golden_output_id`
- every golden output entry must publish `correctness_digest_sha256`, `result_digest_sha256`, and behavior-equivalence verdict fields

## Per-Case Publication Requirements

Every benchmark case must publish:
- throughput
- latency (`p50`, `p95`, `p99`)
- allocation bytes and peak memory
- correctness digest
- security-event envelope

## Behavior-Equivalence Hard Gates

For every baseline-vs-engine comparison, all gates below are mandatory:
1. equivalent external output digest
2. equivalent side-effect trace class (`fs`, `network`, `process`, `policy`)
3. equivalent error-class semantics for negative/exceptional cases
4. no work dropping
5. no relaxed durability and no disabled policy checks

Any gate failure invalidates the case for score publication.

## Scoring Formula (Binding)

Primary comparative score uses weighted geometric mean:

`score(engine, baseline) = exp(sum_i w_i * ln(throughput_engine_i / throughput_baseline_i))`

Constraints:
- `sum_i w_i = 1`
- all weights must be declared in result artifacts

Claim acceptance requires both conditions:
- `score_vs_node >= 3.0`
- `score_vs_bun >= 3.0`

## Transparent Scoring Governance

- Published weights are mandatory for every score component and must be present in result artifacts.
- No hidden or post-hoc adjustments are allowed after run completion.
- Normalization and aggregation formulas are fixed per benchmark version.
- Score methodology changes require explicit version bump and changelog entry.
- Benchmark methodology updates require public review notes (RFC-style summary + disposition).

## Fairness and Denominator Contract

- Baselines pinned to declared versions (Node LTS, Bun stable).
- Identical hardware and OS envelope for all compared runs.
- Fixed dataset checksums and seed transcripts.
- Warm-cache and cold-cache protocols both required.
- Median and dispersion must be published over repeated runs.
- Raw per-run artifacts are mandatory.

## Required Metric Families

Each publication batch must include metrics from all families:
1. throughput/latency under extension-heavy load
2. containment quality (`time_to_detect`, `time_to_contain`, FP/FN envelopes)
3. replay correctness (determinism pass rate, artifact completeness)
4. revocation/quarantine propagation freshness and convergence
5. adversarial resilience (campaign success-rate suppression)
6. information-flow security (unauthorized-flow block rate, declassification envelopes)
7. security-proof specialization uplift (specialized vs ambient-authority delta)

## Workload and Result Schema Contract

Required manifest fields for each benchmark case:
- `workload_id`
- `family_id`
- `profile`
- `dataset_checksum_sha256`
- `seed_transcript_sha256`
- `baseline_engine`
- `candidate_engine`
- `correctness_digest_sha256`
- `result_digest_sha256`

Required result fields:
- `throughput`
- `latency_p50_ms`
- `latency_p95_ms`
- `latency_p99_ms`
- `allocation_bytes`
- `peak_memory_bytes`
- `behavior_equivalence_verdict`
- `security_envelope`

## Structured Event Contract

Benchmark workflows must emit stable event keys:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Reproducibility and Verifier Workflow

Every published benchmark claim must include:
- `env.json`
- `manifest.json`
- `repro.lock`
- `commands.txt`
- `results.json`
- verifier report JSON

One-command verifier flow:

```bash
frankenctl benchmark verify --bundle artifacts/<bundle_id> --output artifacts/<bundle_id>/verify_report.json
```

## CI Publication Gate

CI must fail publication if any of the following occur:
- missing family/profile coverage
- missing required metrics
- behavior-equivalence gate failure
- score computation mismatch
- missing reproducibility bundle artifacts
- verifier command failure

## Failure Semantics and Rollback

Fail-closed semantics:
- invalid or partial benchmark bundle => no publication
- score-calculation mismatch => no publication
- replay/verifier failure => no publication

If a previously published claim is invalidated:
1. mark claim `UNDER_REVIEW`
2. publish corrected status with linked evidence
3. rerun suite and republish only on passing artifacts

## Publication and Standardization Contract

- Specification is published as an open, machine-verifiable contract under `docs/`.
- Reference harness behavior is exercised by repository test/suite scripts and evidence manifests.
- Result submission bundles must include reproducibility artifacts and deterministic verifier outputs.
- Claim language must follow `docs/CLAIM_LANGUAGE_POLICY.md`.
- Published benchmark runs must include a submission record with:
  - `submission_id`
  - `benchmark_version`
  - `runtime_versions`
  - `score_bundle_digest`
  - `verifier_report_digest`

## Independent Verifier Onboarding

Third-party operators must be able to:
1. obtain bundle + verifier command
2. rerun verification without internal repository context
3. reproduce the published score deterministically
4. inspect structured events for every gate stage

## Operator Checklist

Before publishing benchmark claims:
1. Confirm all five families are present with `S/M/L` profiles.
2. Confirm hard behavior-equivalence gates passed for scored cases.
3. Confirm weighted geometric mean score artifacts are reproducible.
4. Confirm Node and Bun threshold checks (`>= 3.0`) pass.
5. Confirm verifier output is `pass` and attached in publication context.
