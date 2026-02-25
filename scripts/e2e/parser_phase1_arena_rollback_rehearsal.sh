#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="artifacts/parser_phase1_arena_rollback/${timestamp}"
pre_artifact_root="${artifact_root}/pre"
post_artifact_root="${artifact_root}/post"
rehearsal_manifest="${artifact_root}/rollback_rehearsal_manifest.json"

mkdir -p "$artifact_root"

run_replay_phase() {
  local rollback_token="$1"
  local allocator_epoch="$2"
  local target_root="$3"

  PARSER_PHASE1_ARENA_SCENARIO="replay" \
    PARSER_PHASE1_ARENA_ROLLBACK_TOKEN="${rollback_token}" \
    PARSER_PHASE1_ARENA_ALLOCATOR_EPOCH="${allocator_epoch}" \
    PARSER_PHASE1_ARENA_ARTIFACT_ROOT="${target_root}" \
    ./scripts/run_parser_phase1_arena_suite.sh test
}

run_replay_phase "parser-phase1-arena-rollback-disabled" "phase1-v1" "${pre_artifact_root}"
run_replay_phase "parser-phase1-arena-rollback-rehearsal-v1" "phase1-rollback-v1" "${post_artifact_root}"

pre_manifest="$(find "${pre_artifact_root}" -name run_manifest.json -type f | sort | tail -n1)"
post_manifest="$(find "${post_artifact_root}" -name run_manifest.json -type f | sort | tail -n1)"

if [[ -z "${pre_manifest}" || -z "${post_manifest}" ]]; then
  echo "rollback rehearsal failed: missing pre/post run manifests" >&2
  exit 2
fi

if ! grep -q '"scenario": "replay"' "${pre_manifest}" || ! grep -q '"scenario": "replay"' "${post_manifest}"; then
  echo "rollback rehearsal failed: replay scenario mismatch in manifests" >&2
  exit 3
fi

if ! grep -q '"outcome": "pass"' "${pre_manifest}" || ! grep -q '"outcome": "pass"' "${post_manifest}"; then
  echo "rollback rehearsal failed: pre/post replay runs did not both pass" >&2
  exit 4
fi

cat >"${rehearsal_manifest}" <<EOF
{
  "schema_version": "franken-engine.parser-phase1-arena.rollback-rehearsal.v1",
  "bead_id": "bd-drjd",
  "generated_at_utc": "${timestamp}",
  "pre_rollback_manifest": "${pre_manifest}",
  "post_rollback_manifest": "${post_manifest}",
  "rollback_token_before": "parser-phase1-arena-rollback-disabled",
  "rollback_token_after": "parser-phase1-arena-rollback-rehearsal-v1",
  "parity_validation": "pre_and_post_replay_passed",
  "outcome": "pass",
  "operator_verification": [
    "cat ${pre_manifest}",
    "cat ${post_manifest}",
    "cat ${rehearsal_manifest}"
  ]
}
EOF

echo "rollback rehearsal manifest: ${rehearsal_manifest}"
