#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

bootstrap_script="${root_dir}/scripts/e2e/parser_oracle_env_bootstrap.sh"
# shellcheck source=/dev/null
source "$bootstrap_script"
parser_oracle_apply_deterministic_env

PARSER_ORACLE_PARTITION="full" \
PARSER_ORACLE_GATE_MODE="fail_closed" \
PARSER_ORACLE_SEED="${PARSER_ORACLE_SEED:-1}" \
  ./scripts/run_parser_oracle_gate.sh ci
