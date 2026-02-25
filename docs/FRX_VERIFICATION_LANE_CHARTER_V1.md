# FRX Verification/Formal Lane Charter v1

Status: active
Primary bead: bd-mjh3.10.4
Lane id: FRX-10.4
Program constitution reference: `docs/FRX_PROGRAM_CONSTITUTION_V1.md`
Machine-readable contract: `docs/frx_verification_lane_contract_v1.json`

## Charter Scope

This lane is the final authority for semantic non-regression evidence and
formal assurance artifacts that gate FRX promotion decisions.

## Decision Rights

The lane has unilateral authority to:

1. Approve or reject differential-equivalence confidence for a promotion
   window.
2. Approve or reject metamorphic/property campaign sufficiency for a release
   claim.
3. Block promotion when formal invariants are missing, stale, or contradicted
   by counterexamples.
4. Publish deterministic risk advisories and required remediation classes.

## Responsibilities

1. Own lockstep differential oracle quality and divergence triage taxonomy.
2. Own metamorphic/property/fuzz campaign design and corpus evolution policy.
3. Own formal/model-checked invariants for scheduler and reactivity critical
   sections.
4. Emit reproducible counterexample bundles with minimized traces and clear
   remediation handoff guidance.

## Inputs

- Compatibility corpus, forbidden regression index, and runtime execution
  traces.
- Compiler witness bundles, FRIR lineage metadata, and compile/fallback
  decision artifacts.
- Milestone gate definitions, promotion claim requirements, and governance risk
  thresholds.

## Outputs

- Reproducible divergence reports with minimized repro traces.
- Metamorphic/property/fuzz confidence reports with deterministic seeds and
  sampling policy metadata.
- Formal assurance packets (proof attempts, model-check outputs, and invariant
  status map).
- Risk advisories with explicit block/allow recommendations.

## Differential and Metamorphic Evidence Obligations

Every promotion window must publish:

- differential lockstep summary with confidence score and class-tagged
  divergence counts
- metamorphic campaign summary with deterministic seed ledger and invariant hit
  matrix
- counterexample index with replay command, trace id, and minimum reproducer id

Missing any required evidence bundle is a promotion blocker.

## Formal Assurance Obligations

1. Each critical invariant must have one of: proved, model-checked, or
   explicitly waived with governance rationale.
2. Waivers require deterministic expiration criteria and owner assignment.
3. Failed proofs or violated invariants are fail-closed until remediation
   evidence is attached.

## Counterexample Triage and Reproducibility

Counterexample artifacts must include:

- divergence taxonomy label
- deterministic replay command
- minimized reproduction payload
- suspected lane owner and recommended remediation class
- confidence impact delta

Artifacts that cannot be replayed are treated as invalid and must not be used
for promotion decisions.

## Promotion Blocking Policy

1. If confidence degrades below gate threshold, block promotion.
2. If any mandatory evidence artifact is missing, block promotion.
3. If formal invariant status is violated or unknown for critical sections,
   block promotion.
4. Unblock only after deterministic remediation evidence passes rerun gates.

## Interface Contracts

1. Compiler lane provides witness linkage and FRIR lineage metadata consumed by
   verification runs.
2. Runtime lane provides execution traces and scheduler telemetry used for
   differential and metamorphic checks.
3. Governance lane consumes risk advisories, block decisions, and waiver
   expirations.
4. Toolchain lane consumes counterexample bundles and remediation guidance for
   operator-facing diagnostics.
