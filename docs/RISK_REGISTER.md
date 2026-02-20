# FrankenEngine Program Risk Register

This is the authoritative, living risk register for program-level risks in
FrankenEngine. It is a release/governance control artifact and must stay aligned
with Section 12 of `PLAN_TO_CREATE_FRANKEN_ENGINE.md`.

## Risk Schema

Every active risk entry must include:

- `Risk ID`: Stable identifier (`R-###`)
- `Title`: Short risk name
- `Severity`: `Critical | High | Medium | Low`
- `Likelihood`: `High | Medium | Low`
- `Impact Summary`: User/operator impact if realized
- `Countermeasure Beads`: One or more bead IDs implementing mitigations
- `Owner`: Accountable maintainer role
- `Monitor`: Concrete metric/signal reviewed on cadence
- `Review Cadence`: Expected review interval
- `Status`: `Open | Mitigating | Accepted | Closed`
- `Last Reviewed`: `YYYY-MM-DD`
- `Evidence`: Artifact pointer (run manifest, report, or checklist evidence)

## Active Risks

| Risk ID | Title | Severity | Likelihood | Impact Summary | Countermeasure Beads | Owner | Monitor | Review Cadence | Status | Last Reviewed | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | Scope explosion | High | Medium | Phase work expands faster than gate closure, delaying delivery and hardening. | bd-51gj | Program lead | Scope additions vs phase-gate completion delta per week. | Weekly + per-phase-gate | Mitigating | 2026-02-20 | docs/RELEASE_CHECKLIST.md |
| R-002 | False confidence from heuristic security | Critical | Medium | Miscalibrated safety controls could allow high-impact incidents or false assurances. | bd-1blo | Security lead | Calibration quality, false-positive/false-negative rates on adversarial corpora. | Weekly + per-phase-gate | Open | 2026-02-20 | docs/RUNTIME_CHARTER.md |
| R-003 | Performance regressions from over-hardening | High | Medium | Guardrails exceed p95/p99 latency budgets and reduce operator trust/adoption. | bd-27ks | Performance lead | Security subsystem overhead budgets and p95/p99 regression trend. | Weekly + per-phase-gate | Mitigating | 2026-02-20 | docs/CLAIM_LANGUAGE_POLICY.md |
| R-004 | Operational complexity | High | Medium | Operators cannot diagnose incidents quickly, increasing MTTR and error rates. | bd-15vm | Operations lead | Operator burden metrics, fallback activation frequency, drill completion rate. | Weekly + per-phase-gate | Open | 2026-02-20 | docs/REPRODUCIBILITY_CONTRACT.md |
| R-005 | Delegate-path entrenchment | High | Medium | Temporary delegate paths become permanent and block native-runtime completion. | bd-256n | Runtime lead | Native slot coverage and time-since-last-promotion per slot. | Weekly + per-phase-gate | Open | 2026-02-20 | docs/REPO_SPLIT_CONTRACT.md |
| R-006 | IFC over-constraint false denies | High | Medium | Benign integrations are denied, causing ecosystem friction and unsafe workarounds. | bd-37go | Policy lead | Benign false-deny rate, declassification request volume. | Weekly + per-phase-gate | Open | 2026-02-20 | docs/CLAIM_LANGUAGE_POLICY.md |
| R-007 | Stale/invalid proofs causing unsound specialization | Critical | Medium | Invalid optimization proofs could violate security invariants or replay guarantees. | bd-1md2 | Verification lead | Proof invalidation rate and specialization fallback frequency. | Weekly + per-phase-gate | Open | 2026-02-20 | docs/RUNTIME_CHARTER.md |

## Review Cadence

- Weekly: review active risk indicators and update status/owner actions.
- Per-phase-gate: complete full risk review before gate sign-off.
- Per-incident: add or amend risks discovered during incident analysis.

## Phase Gate Review Log

| Phase | Gate Status | Gate Date | Register Review Date | Reviewer | Evidence Link | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| A | Pending | pending | pending | pending | pending | Native VM substrate gate not crossed yet. |
| B | Pending | pending | pending | pending | pending | Security-first extension runtime gate not crossed yet. |
| C | Pending | pending | pending | pending | pending | Performance uplift gate not crossed yet. |
| D | Pending | pending | pending | pending | pending | Node/Bun surface superset gate not crossed yet. |
| E | Pending | pending | pending | pending | pending | Production hardening gate not crossed yet. |

## Update Procedure

1. Update relevant risk rows after each weekly review, incident, or gate event.
2. If any phase `Gate Status` changes to `Crossed`, set:
   - `Gate Date`
   - `Register Review Date`
   - `Reviewer`
   - `Evidence Link`
3. Keep `Countermeasure Beads` aligned with active implementation beads.
