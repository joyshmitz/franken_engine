#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

artifact_dir="artifacts/parser_phase0"
mkdir -p "$artifact_dir"

baseline_json="$artifact_dir/baseline.json"
flamegraph_svg="$artifact_dir/flamegraph.svg"
golden_checksums="$artifact_dir/golden_checksums.txt"
proof_note="$artifact_dir/proof_note.md"
env_json="$artifact_dir/env.json"
manifest_json="$artifact_dir/manifest.json"
repro_lock="$artifact_dir/repro.lock"
provenance_json="$artifact_dir/provenance.json"
fixture_catalog="crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json"

cargo run -p frankenengine-engine --bin franken_parser_phase0_report --quiet > "$baseline_json"

cat > "$flamegraph_svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="160" viewBox="0 0 1280 160" role="img" aria-label="parser phase0 flamegraph placeholder">
  <rect x="0" y="0" width="1280" height="160" fill="#111827" />
  <rect x="40" y="72" width="1200" height="24" fill="#22c55e" />
  <text x="52" y="89" fill="#f9fafb" font-size="14" font-family="monospace">
    parser_phase0 scalar_reference baseline lane (placeholder flamegraph artifact)
  </text>
</svg>
SVG

completeness_millionths="$(jq -r '.grammar_completeness.completeness_millionths' "$baseline_json")"
family_count="$(jq -r '.grammar_completeness.family_count' "$baseline_json")"
supported_families="$(jq -r '.grammar_completeness.supported_families' "$baseline_json")"
partial_families="$(jq -r '.grammar_completeness.partially_supported_families' "$baseline_json")"
unsupported_families="$(jq -r '.grammar_completeness.unsupported_families' "$baseline_json")"
fixture_count="$(jq -r '.fixture_count' "$baseline_json")"
p50_ns="$(jq -r '.latency.p50_ns' "$baseline_json")"
p95_ns="$(jq -r '.latency.p95_ns' "$baseline_json")"
p99_ns="$(jq -r '.latency.p99_ns' "$baseline_json")"

cat > "$proof_note" <<EOF_MD
# Parser Phase0 Proof Note

- claim_id: claim.parser.scalar_reference_deterministic
- demo_id: demo.parser.scalar_reference
- parser_mode: scalar_reference

## Grammar Completeness Snapshot

- family_count: $family_count
- supported_families: $supported_families
- partially_supported_families: $partial_families
- unsupported_families: $unsupported_families
- completeness_millionths: $completeness_millionths

## Determinism Evidence

- fixture_catalog: $fixture_catalog
- fixture_count: $fixture_count
- canonical fixture hashes pinned in fixture catalog and verified in
  \`crates/franken-engine/tests/parser_phase0_semantic_fixtures.rs\`.

## Latency Snapshot (local reference only)

- p50_ns: $p50_ns
- p95_ns: $p95_ns
- p99_ns: $p99_ns

## Isomorphism / Safety Notes

- Parser output remains canonicalized through \`SyntaxTree::canonical_hash\`.
- Budget failures emit \`ParseErrorCode::BudgetExceeded\` with deterministic witness payload.
- Script/Module goal restrictions for import/export remain explicit and deterministic.
EOF_MD

commit_sha="$(git rev-parse HEAD)"
dirty=false
if ! git diff --quiet || ! git diff --cached --quiet; then
  dirty=true
fi

kernel="$(uname -r)"
os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
cpu_model="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //')"
if [[ -z "${cpu_model}" ]]; then
  cpu_model="unknown"
fi
cores="$(nproc 2>/dev/null || echo 0)"
mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
mem_bytes="$((mem_kb * 1024))"
rustc_version="$(rustc --version | sed 's/^rustc //')"
cargo_version="$(cargo --version | sed 's/^cargo //')"

jq -n \
  --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg commit "$commit_sha" \
  --argjson dirty "$dirty" \
  --arg os "$os_name" \
  --arg kernel "$kernel" \
  --arg arch "$arch" \
  --arg cpu_model "$cpu_model" \
  --argjson cores "$cores" \
  --argjson memory_bytes "$mem_bytes" \
  --arg rustc "$rustc_version" \
  --arg cargo "$cargo_version" \
  '{
    schema_version: "franken-engine.env.v1",
    schema_hash: "sha256:env-schema-v1",
    captured_at_utc: $captured_at,
    project: {
      name: "franken_engine",
      repo_url: "https://github.com/Dicklesworthstone/franken_engine",
      commit: $commit,
      dirty: $dirty
    },
    host: {
      os: $os,
      kernel: $kernel,
      arch: $arch,
      cpu_model: $cpu_model,
      cpu_cores_logical: $cores,
      memory_bytes: $memory_bytes
    },
    toolchain: {
      rustc: $rustc,
      cargo: $cargo,
      llvm: "unknown",
      target_triple: "x86_64-unknown-linux-gnu",
      profile: "dev"
    },
    runtime: {
      mode: "secure",
      lane: "scalar_reference",
      safe_mode_enabled: true,
      feature_flags: ["parser.scalar_reference"]
    },
    policy: {
      policy_id: "policy.parser.scalar_reference.v1",
      policy_digest_sha256: "sha256:parser-policy-v1"
    }
  }' > "$env_json"

baseline_sha="$(sha256sum "$baseline_json" | awk '{print $1}')"
flamegraph_sha="$(sha256sum "$flamegraph_svg" | awk '{print $1}')"
fixture_sha="$(sha256sum "$fixture_catalog" | awk '{print $1}')"
proof_sha="$(sha256sum "$proof_note" | awk '{print $1}')"
env_sha="$(sha256sum "$env_json" | awk '{print $1}')"

jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg baseline_sha "$baseline_sha" \
  --arg flamegraph_sha "$flamegraph_sha" \
  --arg fixture_sha "$fixture_sha" \
  --arg proof_sha "$proof_sha" \
  --arg claim_id "claim.parser.scalar_reference_deterministic" \
  --arg demo_id "demo.parser.scalar_reference" \
  '{
    schema_version: "franken-engine.parser-phase0.provenance.v1",
    generated_at_utc: $generated_at,
    claim_id: $claim_id,
    demo_id: $demo_id,
    artifact_hashes: {
      baseline_json: ("sha256:" + $baseline_sha),
      flamegraph_svg: ("sha256:" + $flamegraph_sha),
      fixture_catalog: ("sha256:" + $fixture_sha),
      proof_note: ("sha256:" + $proof_sha)
    },
    evidence_links: {
      fixture_suite: "crates/franken-engine/tests/parser_phase0_semantic_fixtures.rs",
      parser_module: "crates/franken-engine/src/parser.rs"
    }
  }' > "$provenance_json"

provenance_sha="$(sha256sum "$provenance_json" | awk '{print $1}')"

cat > "$repro_lock" <<EOF_LOCK
{
  "schema_version": "franken-engine.repro-lock.v1",
  "schema_hash": "sha256:repro-lock-schema-v1",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lock_id": "parser-phase0-lock-v1",
  "manifest_id": "parser-phase0-manifest-v1",
  "source_commit": "$commit_sha",
  "determinism": {
    "allow_network": false,
    "allow_wall_clock": false,
    "allow_randomness": false,
    "max_clock_skew_seconds": 0
  },
  "commands": [
    "cargo run -p frankenengine-engine --bin franken_parser_phase0_report --quiet",
    "cargo test -p frankenengine-engine --test parser_trait_ast --test parser_edge_cases --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic"
  ],
  "inputs": [
    {
      "path": "$fixture_catalog",
      "sha256": "sha256:$fixture_sha",
      "kind": "input"
    }
  ],
  "expected_outputs": [
    {
      "path": "$baseline_json",
      "sha256": "sha256:$baseline_sha",
      "kind": "output"
    },
    {
      "path": "$provenance_json",
      "sha256": "sha256:$provenance_sha",
      "kind": "output"
    }
  ],
  "replay": {
    "trace_id": "trace.parser.phase0",
    "replay_pointer": "replay://parser-phase0"
  },
  "verification": {
    "command": "cargo test -p frankenengine-engine --test parser_trait_ast --test parser_edge_cases --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic",
    "expected_verdict": "pass"
  }
}
EOF_LOCK

repro_sha="$(sha256sum "$repro_lock" | awk '{print $1}')"

cat > "$golden_checksums" <<EOF_SUM
$baseline_sha  $baseline_json
$flamegraph_sha  $flamegraph_svg
$fixture_sha  $fixture_catalog
$proof_sha  $proof_note
$env_sha  $env_json
$provenance_sha  $provenance_json
$repro_sha  $repro_lock
EOF_SUM

golden_sha="$(sha256sum "$golden_checksums" | awk '{print $1}')"

cat > "$manifest_json" <<EOF_MANIFEST
{
  "schema_version": "franken-engine.manifest.v1",
  "schema_hash": "sha256:manifest-schema-v1",
  "manifest_id": "parser-phase0-manifest-v1",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "claim": {
    "claim_id": "claim.parser.scalar_reference_deterministic",
    "class": "DETERMINISM",
    "statement": "Scalar reference parser yields deterministic canonical AST hashes for pinned phase0 fixture corpus.",
    "status": "observed",
    "bundle_root": "$artifact_dir"
  },
  "source_revision": {
    "repo": "franken_engine",
    "branch": "main",
    "commit": "$commit_sha"
  },
  "provenance": {
    "trace_id": "trace.parser.phase0",
    "decision_id": "decision.parser.phase0",
    "policy_id": "policy.parser.scalar_reference.v1",
    "replay_pointer": "replay://parser-phase0",
    "evidence_pointer": "evidence://parser-phase0",
    "receipt_ids": [
      "rcpt-parser-phase0"
    ]
  },
  "artifacts": {
    "baseline": {
      "path": "$baseline_json",
      "sha256": "sha256:$baseline_sha"
    },
    "flamegraph": {
      "path": "$flamegraph_svg",
      "sha256": "sha256:$flamegraph_sha"
    },
    "golden_checksums": {
      "path": "$golden_checksums",
      "sha256": "sha256:$golden_sha"
    },
    "proof_note": {
      "path": "$proof_note",
      "sha256": "sha256:$proof_sha"
    },
    "env": {
      "path": "$env_json",
      "sha256": "sha256:$env_sha"
    },
    "repro_lock": {
      "path": "$repro_lock",
      "sha256": "sha256:$repro_sha"
    },
    "provenance": {
      "path": "$provenance_json",
      "sha256": "sha256:$provenance_sha"
    }
  },
  "inputs": [
    {
      "path": "$fixture_catalog",
      "sha256": "sha256:$fixture_sha"
    }
  ],
  "outputs": [
    {
      "path": "$baseline_json",
      "sha256": "sha256:$baseline_sha"
    },
    {
      "path": "$provenance_json",
      "sha256": "sha256:$provenance_sha"
    }
  ],
  "canonicalization": {
    "format": "json",
    "key_order": "lexicographic",
    "newline": "lf",
    "hash_algorithm": "sha256"
  },
  "validation": {
    "validator": "cargo test -p frankenengine-engine --test parser_trait_ast --test parser_edge_cases --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic",
    "error_taxonomy": "ParseErrorCode + FE-REPRO-0001..FE-REPRO-0008"
  },
  "retention": {
    "min_days": 365,
    "high_impact_min_days": 730,
    "rotation_policy": "archive-with-addressable-retrieval"
  }
}
EOF_MANIFEST

echo "parser phase0 artifact bundle generated at: $artifact_dir"
