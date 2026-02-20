# FrankenEngine Runtime Charter

This charter defines the non-negotiable runtime governance rules for `franken_engine`.
It is the implementation contract for architecture changes, release decisions, and code review.

## 1. Mission Boundary

`franken_engine` exists to provide a native Rust execution substrate for adversarial extension workloads with deterministic replay and evidence-first security controls.

Product compatibility UX is owned by `/dp/franken_node`; this repository owns engine/runtime semantics.

## 2. Native-Only Core Execution Rule

The core execution path must remain native Rust.

Prohibited as core execution backends:
- `rusty_v8`
- `rquickjs`
- Any equivalent embedding/binding-led engine path

`legacy_v8/` and `legacy_quickjs/` are reference corpora only. They may inform semantics and tests, but they must not become runtime dependencies for core execution.

## 3. Security + Determinism Contract

All high-impact containment and policy actions must be:
- replayable from deterministic artifacts
- represented by explicit decision contracts
- linked to auditable evidence artifacts

Adaptive behavior is allowed only when deterministic safe-mode fallback exists and replay obligations remain satisfied.

## 4. Repository Split Contract

Dependency direction is one-way:
- allowed: `franken_node -> franken_engine`
- forbidden: `franken_engine -> franken_node`

Forked engine crates must not be reintroduced into `/dp/franken_node`.

## 5. Reuse Contract For Sibling Repositories

When relevant, `franken_engine` must reuse:
- `/dp/frankentui` for advanced operator/TUI surfaces
- `/dp/frankensqlite` for SQLite-backed persistence contracts
- `/dp/sqlmodel_rust` for typed schema/model layers when correctness and migration guarantees benefit
- `/dp/fastapi_rust` for service/API control surfaces

Parallel local replacements require explicit approval.

## 6. Evidence Requirement For Claims

Performance and security claims are invalid without reproducible artifacts.

Required publication posture:
- benchmark methodology and denominator disclosure
- reproducible manifests/inputs
- verifiable outputs sufficient for third-party rerun

## 7. Claim-Language Policy (Binding)

Claim text in docs, release notes, benchmarks, and operator guidance must match available evidence.

### 7.1 Required wording by claim state

- `observed`: use when results were measured in a declared environment and artifact bundle is attached.
- `target`: use for design goals or SLOs not yet proven by released artifacts.
- `hypothesis`: use for projected outcomes that are not yet validated.

### 7.2 Forbidden wording without matching artifacts

Do not use absolute or superiority language (`guarantees`, `unbreakable`, `always`, `proves`, `category-defining`, `>=Nx faster`) unless artifacts explicitly demonstrate the claim under stated conditions.

### 7.3 Mandatory claim annotation fields

Every high-impact claim must include or reference:
- claim scope (`performance`, `security`, `compatibility`, `replay`, `operations`)
- environment and denominator
- artifact handle/path (benchmark manifest, replay trace, conformance report, or evidence bundle)
- publication date and code/policy revision

### 7.4 Failure handling

If an artifact cannot reproduce a published claim, claim language must be downgraded immediately (`observed` -> `target`/`hypothesis`) and corrected in the same change set that records the discrepancy.

## 8. Change Acceptance Gate

A runtime-facing change is acceptable only if it:
1. Preserves native-only execution ownership.
2. Preserves deterministic replay guarantees on relevant paths.
3. Preserves decision/evidence linkage for high-impact actions.
4. Respects repository split and sibling-reuse contracts.
5. Uses claim language consistent with evidence policy and artifact availability.
6. Ships tests and artifacts proportional to risk and claim scope.

If any gate fails, the change is rejected or explicitly scoped as non-runtime/prototype work.

## 9. Source Of Truth

This charter is binding alongside:
- `AGENTS.md`
- `PLAN_TO_CREATE_FRANKEN_ENGINE.md`
- `docs/REPO_SPLIT_CONTRACT.md`
- `docs/adr/ADR-0002-fastapi-rust-reuse-scope.md`
- `docs/adr/ADR-0003-frankentui-reuse-scope.md`
- `docs/adr/ADR-0004-frankensqlite-reuse-scope.md`
