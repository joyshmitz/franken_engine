# Reproducibility Contract

This document defines the minimum artifact contract for reproducible FrankenEngine claims and incident analysis.

The required bundle consists of:
- `env.json`: execution environment and toolchain snapshot
- `manifest.json`: declared experiment/run metadata, inputs, and outputs
- `repro.lock`: immutable content-lock mapping for all referenced artifacts

These templates satisfy PLAN `10.1` reproducibility contract requirements and are intended to be copied into each benchmark, conformance, replay, or security evidence bundle.

## 1. Required files

1. `env.json`
2. `manifest.json`
3. `repro.lock`

All three files are required for a claim to be classified as `observed`.

## 2. Determinism rules

- Use UTC timestamps in RFC3339 format.
- Use explicit semantic versions for tools and schemas.
- Pin source revisions by immutable commit hash.
- Record every file digest with `sha256`.
- Never mutate published bundles in place; publish a new bundle with a new manifest ID.

## 3. Template locations

- `docs/templates/env.json.template`
- `docs/templates/manifest.json.template`
- `docs/templates/repro.lock.template`

## 4. Validation checklist

Before publishing claims:
1. Confirm all template placeholders are replaced.
2. Recompute `sha256` entries after final artifact generation.
3. Verify all manifest-listed files exist in the bundle.
4. Ensure `repro.lock` entries match `manifest.json` artifacts and inputs exactly.
5. Include bundle path/ID in public claim text.
