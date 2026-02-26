# FRX Cross-Version Compatibility Matrix V1

`FRX-02.4` defines the machine-readable compatibility matrix for React-version,
browser API, and edge API-family behavior used by semantic test selection and
release-claim eligibility.

## Source of Truth

- Matrix file: `docs/frx_cross_version_compatibility_matrix_v1.json`
- Schema: `franken-engine.frx-cross-version-compat-matrix.v1`
- Policy: `policy-frx-cross-version-compat-v1`

## Dimensions

- React versions: `18.3`, `19.0`
- Browsers: `chromium`, `firefox`, `webkit`
- API families:
  - hooks/effects core
  - legacy class components
  - portals/refs
  - concurrent primitives
  - browser render observers
- Compatibility routes:
  - `compile_native`
  - `compatibility_fallback`
  - `deterministic_safe_mode`

## Required Matrix Guarantees

1. Each matrix case must provide both `test_selector_tags` and
   `release_claim_tags`.
2. Every API family in the declared dimensions must appear in at least one case.
3. Case IDs and tag lists must be deterministic (stable ordering and no hidden
   randomization in selection projection).
4. Cases marked `fallback_only` or `guarded` must explicitly declare a fallback
   route and whether deterministic fallback is required.

## Test-Selection and Release-Claim Projections

The matrix drives two deterministic outputs:

- test-selection projection: union of `test_selector_tags` with per-tag case
  mapping
- release-claim projection: union of `release_claim_tags` with per-claim case
  mapping

These projections are asserted by integration tests for deterministic behavior.

## Replay and Gate Commands

Primary replay command:

```bash
./scripts/e2e/frx_cross_version_compatibility_matrix_replay.sh ci
```

Supported modes:

- `check`
- `test`
- `clippy`
- `replay`
- `ci`

All heavy cargo operations are executed through `rch` only.

## Evidence Pack

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

under:

`artifacts/frx_cross_version_compatibility_matrix/<UTC_TIMESTAMP>/`

## Operator Verification

1. Run replay command in `ci` mode.
2. Confirm manifest `outcome=pass`.
3. Confirm parser-log schema validation pass on `events.jsonl`.
4. Confirm matrix tests assert coverage + deterministic projections.
