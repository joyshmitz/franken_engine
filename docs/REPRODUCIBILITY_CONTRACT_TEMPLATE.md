# Reproducibility Contract Template

This document defines the required contract for evidence bundles used to support FrankenEngine claims and deterministic replay workflows.

Required files per bundle:
- `env.json`
- `manifest.json`
- `repro.lock`

Optional supporting files:
- `commands.txt`
- `results.json`
- `README.md`

## Directory Layout

```text
artifacts/<claim_or_run_id>/
  env.json
  manifest.json
  repro.lock
  commands.txt           # recommended
  results.json           # recommended
  README.md              # recommended
  payload/               # referenced artifacts
    ...
```

## 1) `env.json` Template

`env.json` captures execution environment and runtime mode. Values should be concrete, not inferred.

```json
{
  "schema_version": "1.0",
  "captured_at_utc": "2026-02-20T07:00:00Z",
  "host": {
    "os": "linux",
    "kernel": "6.8.0",
    "arch": "x86_64",
    "cpu_model": "AMD EPYC ...",
    "logical_cores": 32,
    "memory_bytes": 137438953472
  },
  "toolchain": {
    "rustc": "1.87.0-nightly",
    "cargo": "1.87.0-nightly",
    "frankenengine_git_commit": "abc123...",
    "frankenengine_git_dirty": false
  },
  "runtime": {
    "mode": "secure",
    "lane": "hybrid",
    "features": ["quickjs-native", "v8-native"]
  },
  "policy": {
    "policy_version": "policy-2026-02-20",
    "policy_digest_sha256": "..."
  }
}
```

Validation rules:
- `schema_version`, `captured_at_utc`, `toolchain.frankenengine_git_commit`, and `runtime.mode` are required.
- `captured_at_utc` must be RFC3339 UTC timestamp.
- `frankenengine_git_dirty` must be explicitly true/false.

## 2) `manifest.json` Template

`manifest.json` is the canonical index of artifact files, hashes, and claim metadata.

```json
{
  "schema_version": "1.0",
  "bundle_id": "claim-2026-02-20-001",
  "claim": {
    "class": "PERFORMANCE",
    "statement": "Hybrid routing median latency <= 250ms under defined workload",
    "source_location": "README.md#L359"
  },
  "source": {
    "git_commit": "abc123...",
    "git_branch": "main"
  },
  "files": [
    {
      "path": "env.json",
      "sha256": "..."
    },
    {
      "path": "repro.lock",
      "sha256": "..."
    },
    {
      "path": "results.json",
      "sha256": "..."
    }
  ],
  "generator": {
    "name": "frankenctl",
    "version": "0.1.0"
  }
}
```

Validation rules:
- `bundle_id` must be unique within artifact store.
- Every listed file must exist and hash-match.
- `claim.class` must be one of:
  - `SECURITY`
  - `PERFORMANCE`
  - `COMPATIBILITY`
  - `DETERMINISM`
  - `GOVERNANCE`

## 3) `repro.lock` Template

`repro.lock` freezes command sequence and inputs used to regenerate results.

```json
{
  "schema_version": "1.0",
  "lock_id": "repro-2026-02-20-001",
  "inputs": {
    "dataset_ids": ["workload-ext-heavy-v1"],
    "config_files": [
      {
        "path": "runtime/franken-engine.toml",
        "sha256": "..."
      }
    ],
    "policy_files": [
      {
        "path": "policies/default.toml",
        "sha256": "..."
      }
    ]
  },
  "commands": [
    "frankenctl benchmark run --suite extension-heavy --out ./artifacts/results.json",
    "frankenctl replay run --trace trace_01J..."
  ],
  "expected_outputs": [
    {
      "path": "results.json",
      "sha256": "..."
    }
  ],
  "constraints": {
    "allow_network": false,
    "allow_time_drift_seconds": 0
  }
}
```

Validation rules:
- `commands` must be complete and ordered.
- Input hashes must resolve to present files.
- `expected_outputs` hashes must match generated artifacts.

## Generation Workflow

1. Generate or collect runtime outputs.
2. Capture environment metadata into `env.json`.
3. Freeze reproduction recipe into `repro.lock`.
4. Compute all hashes and emit `manifest.json`.
5. Verify bundle by replaying `commands` and checking `expected_outputs`.

## Publication Checklist

- Claim references bundle path and `bundle_id`.
- `manifest.json` hashes validate.
- Replay from `repro.lock` reproduces expected outputs.
- Reviewer records pass/fail decision in release notes or PR discussion.

If checklist is incomplete, claim must be downgraded to intent-language.
