# FRX Track B Compiler/FRIR Spine Charter v1

Status: active
Primary bead: bd-mjh3.11.2
Track id: FRX-11.2
Machine-readable contract: `docs/frx_track_b_compiler_frir_spine_v1.json`

## Charter Scope

Track B owns the deterministic source-to-FRIR spine used by downstream runtime
tracks. It defines how canonical binder outputs are lowered into FRIR, how
witness bundles are emitted, and how fail-closed behavior is enforced when
compile obligations are unmet.

## Decision Rights

This track can:

1. Approve or reject canonical binder representation changes that impact FRIR
   lowering.
2. Approve or reject FRIR schema version updates and compatibility posture.
3. Block promotion when witness bundle linkage is incomplete or invalid.
4. Trigger deterministic fallback lowering when isomorphism checks fail.

## Responsibilities

1. Keep canonical binder representation stable and machine-checkable.
2. Maintain FRIR lowering determinism across repeated runs and hosts.
3. Emit witness bundles for every lowering pass with replay linkage metadata.
4. Publish fail-closed diagnostics with stable governance keys.

## Inputs

- Semantics/contracts from Track A (`bd-mjh3.11.1`) and lane ownership contracts
  from FRX-10.2.
- Parser normalization outputs and pass budget policy.
- Runtime consumer schema expectations and verification gate requirements.

## Outputs

- Stable FRIR schema version and compatibility declaration.
- Lowering witness bundle with pass-level hash linkage.
- Deterministic diagnostics envelope for compile/fallback decisions.
- Replay command metadata for every blocked promotion outcome.

## Canonical Binder Contract

1. Binder output must be canonical and deterministic for identical source input.
2. Binder nodes must expose stable IDs and effect metadata required by FRIR
   lowering.
3. Any binder schema change requires explicit compatibility mode and migration
   notes.

## FRIR Lowering and Witness Contract

1. Every lowering pass emits `pass_id`, `input_hash`, `output_hash`, and
   invariant results.
2. Witness bundle linkage must include replay metadata and producer track id.
3. FRIR schema version stability is required for downstream runtime lanes.
4. Missing witness linkage blocks promotion.

## Optimization Budget and Isomorphism Guard

1. Budgeted optimizations are allowed only when semantic isomorphism checks
   remain green.
2. If isomorphism checks fail, the track must fail closed and emit deterministic
   fallback rationale.
3. Optimization budget breaches must be recorded in witness metadata.

## Promotion Blocking and Rollback

1. Missing witness bundle metadata, schema incompatibility, or failed
   isomorphism checks are hard promotion blockers.
2. When blockers trigger, emit deterministic rollback guidance and replay command.
3. If fallback lowering cannot satisfy contracts, promotion remains rejected.

## Interface Contracts

1. Runtime tracks consume FRIR schema metadata and lowering witness bundles.
2. Verification tracks consume witness linkage, invariant outcomes, and replay
   metadata.
3. Toolchain/governance tracks consume deterministic diagnostics plus
   fail-closed rationale events.
