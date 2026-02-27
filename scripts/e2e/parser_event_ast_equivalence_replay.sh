#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

source "${root_dir}/scripts/e2e/parser_deterministic_env.sh"
parser_frontier_bootstrap_env

scenario="${1:-replay}"

case "${scenario}" in
  parity|malformed|tamper|replay|full)
    ;;
  *)
    echo "usage: $0 [parity|malformed|tamper|replay|full]" >&2
    exit 2
    ;;
esac

PARSER_EVENT_AST_EQUIVALENCE_SCENARIO="${scenario}" \
  ./scripts/run_parser_event_ast_equivalence.sh test
