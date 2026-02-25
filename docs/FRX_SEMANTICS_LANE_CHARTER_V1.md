# FRX Semantics/Compatibility Lane Charter v1

Status: active
Primary bead: bd-mjh3.10.1
Program constitution reference: `docs/FRX_PROGRAM_CONSTITUTION_V1.md`

## Charter Scope

This lane is the final authority for user-visible React semantic equivalence contracts.

## Decision Rights

The lane has unilateral authority to:

1. Accept or reject semantic-compatibility claims.
2. Publish/modify forbidden regression entries.
3. Declare compile-legal vs fallback-required boundaries.
4. Trigger semantic-confidence halts for promotion flows.

## Responsibilities

1. Maintain `FRX_COMPATIBILITY_CONSTITUTION_V1` and ensure alignment with
   `FRX_PROGRAM_CONSTITUTION_V1`.
2. Maintain fixture namespaces for invariants and edge cases.
3. Review and sign semantic policy updates before downstream adoption.
4. Publish deterministic fallback triggers when confidence is insufficient.

## Inputs

- Canonical behavior corpus and lockstep traces.
- Cross-version compatibility matrix updates.
- Ecosystem edge-case reports.

## Outputs

- Versioned semantic contracts.
- Forbidden regression updates.
- Fallback trigger policy updates.
- Change-impact advisories for compiler/runtime/verification lanes.

## Interfaces to Downstream Lanes

1. Compiler lane consumes compile/fallback table and invariant IDs.
2. Runtime lane consumes fallback triggers and semantic confidence signals.
3. Verification lane consumes invariant fixtures and forbidden regression IDs.
4. Governance lane consumes signed semantic-version advisories.

## Escalation and Safety Policy

- If semantic confidence drops below threshold, this lane issues a promotion halt and deterministic conservative fallback recommendation.
- Any disputed semantic interpretation is escalated to governance with evidence trace linkage.
