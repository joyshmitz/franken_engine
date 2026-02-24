#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

tmp_catalog="$(mktemp)"
trap 'rm -f "$tmp_catalog"' EXIT

jq '
  .fixtures[0].expected_hash = "sha256:deadbeef"
' crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json >"$tmp_catalog"

set +e
PARSER_ORACLE_PARTITION="smoke" \
PARSER_ORACLE_GATE_MODE="fail_closed" \
PARSER_ORACLE_FIXTURE_CATALOG="$tmp_catalog" \
PARSER_ORACLE_SEED="${PARSER_ORACLE_SEED:-1}" \
  ./scripts/run_parser_oracle_gate.sh ci
exit_code=$?
set -e

if [[ "$exit_code" -eq 0 ]]; then
  echo "expected fail-closed parser oracle run to fail with corrupted fixture catalog" >&2
  exit 1
fi

echo "parser oracle failure replay succeeded (run failed as expected with exit=${exit_code})"

