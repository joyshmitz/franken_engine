# Donor Extraction Scope (V8/QuickJS Semantic Harvesting)

This document is the normative scope contract for donor-informed work in `franken_engine`.

It permits behavior-level semantic harvesting from donor corpora and forbids architectural/runtime transplantation into FrankenEngine core execution.

Plan references:
- `PLAN_TO_CREATE_FRANKEN_ENGINE.md` section `4.1` (Spec-First Hybrid Bootstrap)
- `PLAN_TO_CREATE_FRANKEN_ENGINE.md` section `10.1` item `bd-10a`

## 1. Policy Objective

Use donor engines as semantic oracles, not architecture templates.

Allowed:
- extract observable language/runtime behavior needed for compatibility and conformance
- translate extracted behavior into native Rust implementation contracts

Forbidden:
- importing donor runtime architecture, optimizer pipelines, or engine-internal execution ownership patterns

## 2. Allowlist: Permitted Donor Outputs

The following outputs are explicitly in scope:

1. Observable semantics.
- ES2020-visible behavior, edge-case semantics, ordering guarantees, and error behavior.

2. Compatibility-critical edge cases.
- Cases required for parity claims, lockstep diffs, and reproducible conformance outcomes.

3. Conformance vectors and fixtures.
- `test262` mappings, lockstep fixtures, deterministic corpus seeds, expected-output baselines.

4. Behavioral equivalence statements.
- Human-readable and machine-checkable behavior statements tied to concrete fixtures.

5. Deterministic acceptance thresholds.
- Pass/fail expectations for parity gates that measure behavior, not architecture.

6. Security-relevant externally visible semantics.
- Observable policy/runtime outcomes for capability checks, revocation effects, and replay-visible decisions.

## 3. Denylist: Prohibited Donor Imports

The following are explicitly out of scope and must not enter FrankenEngine core:

1. Runtime architecture internals.
- hidden classes/shapes
- inline-cache architecture
- optimizer pipeline structure (for example Turbofan/Ignition decomposition)
- donor GC algorithms/internal object layouts
- donor bytecode formats and execution artifacts

2. Scheduling/execution ownership assumptions.
- donor-specific scheduler contracts or event-loop ownership transplanted into core architecture

3. Hidden compatibility shims.
- silent fallback-to-delegate behavior in GA paths
- binding-led execution paths masquerading as native behavior

4. Code transplantation.
- line-by-line donor code translation
- copy/paste of donor implementation logic beyond minimal legal excerpts for documentation context

5. Reintroduction of forbidden core dependencies.
- `rusty_v8`, `rquickjs`, or equivalent binding-led core execution backends

## 4. Required Provenance Record For Donor-Informed Changes

Every donor-informed implementation or policy change must include a provenance record with these required fields:

1. `source_corpus_ref`
- precise donor corpus path/version/commit reference

2. `extracted_behavior`
- behavior statement in observable terms (not donor internals)

3. `native_mapping`
- target FrankenEngine module/path implementing the behavior

4. `equivalence_artifact_ref`
- fixture/suite proving behavior parity or documented waiver

5. `trace_id`
6. `decision_id`
7. `policy_id`
8. `component`
9. `event`
10. `outcome`
11. `error_code`

Canonical log fields (`trace_id`, `decision_id`, `policy_id`, `component`, `event`, `outcome`, `error_code`) are mandatory for audit replay.

## 5. Workflow Stages (Collect -> Normalize -> Approve -> Integrate)

All donor-informed work must flow through these stages in order.

1. `collect`
- Owner: semantics extractor
- Input: donor behavior observations + reproducible fixtures
- Output: raw extraction note with `source_corpus_ref` and `extracted_behavior`

2. `normalize`
- Owner: runtime architect/reviewer
- Input: raw extraction note
- Output: normalized behavior contract that removes donor-internal phrasing and maps to native interfaces

3. `approve`
- Owner: governance approver (not the extractor)
- Input: normalized contract + denylist/allowlist checks + equivalence plan
- Output: approval record with `decision_id`, `policy_id`, and any explicit waiver scope

4. `integrate`
- Owner: implementation author
- Input: approved contract
- Output: native Rust implementation + tests + evidence pointers + structured audit event

No integration is allowed without an `approve` artifact.

## 6. PR/Review Gate Checklist (Blocking)

Each donor-informed PR must pass all checks:

1. Contains a provenance record with all required fields in section 4.
2. References only allowlist outputs; no denylist terms appear in implementation rationale.
3. Demonstrates native mapping (`native_mapping`) without donor architecture mirroring.
4. Includes conformance/equivalence artifacts or an explicit waiver approved via exception policy.
5. Emits or updates structured audit logs with stable required keys.
6. Confirms GA path has no hidden fallback-to-delegate behavior.
7. Links any exception to a time-bounded ADR with rollback steps.

Failure of any checklist item is merge-blocking.

## 7. CI Guardrails And Audit Logging

CI policy guardrails must enforce donor-scope hygiene with deterministic failure codes.

Primary policy suite:
- `./scripts/run_donor_extraction_scope_suite.sh ci`

Reserved failure-code namespace:
- `FE-DONOR-SCOPE-0001`: required scope sections missing
- `FE-DONOR-SCOPE-0002`: allowlist/denylist contract incomplete
- `FE-DONOR-SCOPE-0003`: plan/governance linkage missing
- `FE-DONOR-SCOPE-0004`: donor change record policy violation
- `FE-DONOR-SCOPE-0005`: structured audit field contract missing
- `FE-DONOR-SCOPE-0006`: suite execution failure

Audit events for donor-scope controls must include:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## 8. Exception Policy (Strict, Time-Bounded)

Exceptions are allowed only with explicit approval and bounded scope.

Requirements:

1. ADR linkage is mandatory.
- Include `docs/adr/` reference that states why the exception is needed.

2. Time-bound expiry is mandatory.
- Maximum default exception window: 14 days unless explicitly renewed.

3. Rollback path is mandatory.
- Include deterministic rollback commands and artifact locations.

4. Scope minimization is mandatory.
- Exception applies only to the minimum file/module scope required.

5. Audit emission is mandatory.
- Exception approval and closure must emit structured events with required fields.

Expired exceptions are invalid and must fail governance checks until renewed or removed.

## 9. Anti-Drift Policy

To prevent architecture drift, donor outputs may inform semantics only.

Mandatory controls:

1. Native ownership assertion in design notes.
- Every donor-informed change states why core runtime ownership remains native.

2. Architecture-mirroring ban.
- Reviews reject donor pipeline/data-structure transplantation, even if behaviorally equivalent.

3. Regression checks.
- Periodic governance checks verify donor-informed changes still satisfy denylist constraints.

4. Split-contract compatibility.
- Changes must preserve one-way dependency direction (`franken_node -> franken_engine`).

## 10. Operator Verification Runbook

1. Run policy suite:

```bash
./scripts/run_donor_extraction_scope_suite.sh ci
```

2. Inspect generated artifacts:

```bash
ls -la artifacts/donor_extraction_scope/
cat artifacts/donor_extraction_scope/<timestamp>/run_manifest.json
cat artifacts/donor_extraction_scope/<timestamp>/donor_extraction_scope_events.jsonl
```

3. Verify plan linkage:

```bash
rg -n "donor-extraction scope document" PLAN_TO_CREATE_FRANKEN_ENGINE.md
```

## 11. Source Of Truth

This scope contract is binding alongside:
- `AGENTS.md`
- `PLAN_TO_CREATE_FRANKEN_ENGINE.md`
- `docs/RUNTIME_CHARTER.md`
- `docs/REPO_SPLIT_CONTRACT.md`
