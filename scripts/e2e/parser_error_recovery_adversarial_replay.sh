#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO="replay" \
  ./scripts/run_parser_error_recovery_adversarial_e2e.sh test
