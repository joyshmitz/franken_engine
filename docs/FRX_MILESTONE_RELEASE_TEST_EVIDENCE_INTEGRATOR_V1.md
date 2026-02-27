# FRX Milestone/Release Test-Evidence Integrator v1

## Scope

`bd-mjh3.20.6` binds FRX testing and evidence lanes into C0-C5 cut-line and release
workflows so promotion is blocked unless complete, fresh, and signed test evidence
is available.

This contract consumes outputs from:
- `bd-mjh3.20.2` unit-test depth gate
- `bd-mjh3.20.3` end-to-end scenario matrix
- `bd-mjh3.20.4` test logging schema gate
- `bd-mjh3.20.5` flake quarantine workflow
- `bd-mjh3.5.4` proof-carrying artifact gate

## Required Signal Sources

All five signal sources are mandatory:
- `unit_depth_gate`
- `end_to_end_scenario_matrix`
- `test_logging_schema`
- `flake_quarantine_workflow`
- `proof_carrying_artifact_gate`

If any source is missing, the integrator fails closed.

## Fail-Closed Validation Rules

The integrator denies promotion when any rule fails:
- missing required signal source
- stale signal or artifact (`age > max_signal_age_ns`)
- schema-major incompatibility (`schema_major < min_schema_major`)
- missing artifact hash/path identifiers
- unsigned or invalid signatures when `require_signed_artifacts=true`
- malformed flake burden metadata
- aggregate quality score below cut-line threshold

Failure code: `FE-FRX-20-6-TEST-EVIDENCE-INTEGRATOR-0001`.

## Quality Aggregation and Delta Contract

Per-run quality summary fields (millionths):
- `unit_depth_score_millionths`
- `e2e_stability_score_millionths`
- `logging_integrity_score_millionths`
- `flake_resilience_score_millionths`
- `artifact_integrity_score_millionths`
- `aggregate_score_millionths`

Weighted aggregate:
- unit depth: 30%
- e2e stability: 30%
- logging integrity: 20%
- flake resilience: 10%
- artifact integrity: 10%

Queue/risk output:
- `queue_risk_millionths = 1_000_000 - aggregate_score_millionths`

The integrator emits per-field deltas relative to the previous milestone summary
when prior state is supplied.

## Cut-Line and Release Workflow Binding

Cut-line binding:
- Converts FRX signal outputs into `cut_line_automation::GateInput` records.
- Emits categories required by cut-line gates (`compiler_correctness`,
  `runtime_parity`, `deterministic_replay`, `observability_integrity`,
  `flake_burden`, `governance_compliance`, `handoff_readiness`).

Release binding:
- Applies fail-closed statuses to release checklist items automatically:
  - `security.conformance_suite`
  - `operational.diagnostics_cli_test`
  - `operational.evidence_export_test`
  - `security.adversarial_corpus`
  - `reproducibility.manifest_json`

## Signed Evidence Linkage

For each signal source, the integrator links signed artifacts to gate categories.
Each signed linkage includes:
- source identifier
- gate category
- `artifact_id`
- artifact `sha256`
- signer identity
- signature reference

Gate decisions are only `allow` when signed evidence linkage is complete under the
active policy.

## Structured Event Contract

Event schema: `frx.milestone-release-test-evidence-integrator.event.v1`

Required fields:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `cut_line`
- `release_tag`
- `blocker_count`
- `aggregate_score_millionths`
- `queue_risk_millionths`

## Operator Verification

```bash
# FRX-20.6 gate (rch-backed check + test + clippy)
./scripts/run_frx_milestone_release_test_evidence_integrator_suite.sh ci

# deterministic replay wrapper
./scripts/e2e/frx_milestone_release_test_evidence_integrator_replay.sh ci
```

Artifacts are emitted under:
- `artifacts/frx_milestone_release_test_evidence_integrator/<timestamp>/run_manifest.json`
- `artifacts/frx_milestone_release_test_evidence_integrator/<timestamp>/events.jsonl`
- `artifacts/frx_milestone_release_test_evidence_integrator/<timestamp>/commands.txt`
