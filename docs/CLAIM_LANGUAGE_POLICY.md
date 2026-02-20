# FrankenEngine Claim Language Policy

## Purpose

This policy governs all published claims about FrankenEngine security, performance, compatibility, reliability, and governance posture. Claims are valid only when backed by reproducible evidence artifacts.

Without evidence artifacts, statements must be framed as goals, hypotheses, or roadmap intent.

## Scope

Applies to:
- `README.md`, docs, release notes, benchmarks, blog posts, talks, demos, and issue comments representing project posture.
- Internal and external artifacts published under the FrankenEngine name.

Does not apply to:
- Purely procedural statements (for example: "this command builds the workspace").
- Explicit future intent statements marked as non-validated (for example: "planned", "targeting", "intended").

## Claim Classes

Each substantive statement must declare a claim class:

| Class | Description | Evidence Required |
|---|---|---|
| `SECURITY` | Containment, isolation, attack resistance, policy correctness | Security test corpus results, incident/replay artifacts, policy config snapshot |
| `PERFORMANCE` | Latency, throughput, resource usage, speedup or regression claims | Benchmark harness outputs, workload manifest, environment capture |
| `COMPATIBILITY` | Behavior parity/diff against Node/Bun/other runtime references | Differential run artifacts, corpus IDs, waiver set |
| `DETERMINISM` | Replay or outcome stability claims | Deterministic replay transcripts and hash-matched outputs |
| `GOVERNANCE` | Process guarantees (review gates, enforcement paths, release policy) | Signed or versioned policy documents and approval trail |

## Allowed Claim Language

Allowed only with evidence:
- "measured"
- "verified"
- "reproduced"
- "demonstrated"
- "enforced"
- "proven in artifacts"

Allowed without evidence only when clearly marked as intent:
- "target"
- "goal"
- "planned"
- "proposed"
- "experimental"

Forbidden unless evidence is linked inline:
- "guaranteed"
- "always"
- "unbreakable"
- "bulletproof"
- "zero risk"
- "category-defining" (when used as a factual present-tense claim)

## Mandatory Evidence Bundle

Every `SECURITY`, `PERFORMANCE`, `COMPATIBILITY`, or `DETERMINISM` claim must link an evidence bundle directory containing at minimum:

- `manifest.json`
  - Claim ID, claim class, source commit, policy version, artifact hash list.
- `env.json`
  - OS/kernel, CPU model, memory, toolchain versions, feature flags, runtime mode.
- `repro.lock`
  - Frozen dependency and command execution lock info for deterministic replay.
- `commands.txt`
  - Exact commands used to generate claim evidence.
- `results.json`
  - Machine-readable outcomes with pass/fail criteria.
- `README.md`
  - Human-readable summary of scope, assumptions, and known limits.

Recommended:
- `attestation.json` for signed provenance/attestation flows.
- `waivers.json` for explicit compatibility exceptions.

## Claim Publication Gate

A claim is publishable only if all checks pass:

1. Claim class is declared.
2. Evidence bundle exists and is linked from the claim context.
3. Artifact hashes in `manifest.json` match stored files.
4. Reproduction commands run successfully from `commands.txt`.
5. Reviewer sign-off is recorded (maintainer or delegated owner).

If any check fails, statement must be downgraded to intent-language.

## Review and Approval Roles

- Author:
  - Prepares claim text and evidence bundle.
  - Ensures language matches claim status (validated vs intent).
- Reviewer:
  - Verifies reproducibility and evidence completeness.
  - Rejects over-assertive wording not supported by artifacts.
- Maintainer:
  - Final publish/no-publish authority.
  - Can require stronger evidence for high-impact claims.

## Violation Handling

If a non-compliant claim is discovered:

1. Mark claim status as `UNDER_REVIEW`.
2. Add correction note in the same publication channel.
3. Either:
   - attach missing evidence and restore compliant wording, or
   - downgrade to intent-language.
4. Record incident in project notes for process improvement.

Repeated violations should trigger stricter reviewer gatekeeping for the source channel.

## Change Control

Changes to this policy require:

1. Pull request diff with rationale.
2. Explicit note on backward impact to existing claim artifacts.
3. Reviewer + maintainer approval.

Major policy revisions should include migration guidance for previously published claims.
