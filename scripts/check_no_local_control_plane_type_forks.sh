#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

pattern='\b(struct|type)\s+(TraceId|DecisionId|PolicyId|SchemaVersion|Budget|Cx)\b'
mapfile -t matches < <(rg -n "$pattern" crates --glob '*.rs' || true)

# Explicit migration debt that must be removed over time.
allowlist_substrings=(
  "crates/franken-engine/src/remote_computation_registry.rs:"
  "crates/franken-engine/src/proof_schema.rs:"
  "crates/franken-engine/src/evidence_ledger.rs:"
)

violations=()
legacy=()

for line in "${matches[@]}"; do
  allowed=0
  for token in "${allowlist_substrings[@]}"; do
    if [[ "$line" == *"$token"* && "$line" == *"SchemaVersion"* ]]; then
      allowed=1
      legacy+=("$line")
      break
    fi
  done

  if [[ "$allowed" -eq 0 ]]; then
    violations+=("$line")
  fi
done

if [[ "${#legacy[@]}" -gt 0 ]]; then
  echo "Known migration debt (allowed for now, must be removed over time):"
  printf '  %s\n' "${legacy[@]}"
fi

if [[ "${#violations[@]}" -gt 0 ]]; then
  echo "ERROR: forbidden local control-plane type definitions detected:"
  printf '  %s\n' "${violations[@]}"
  exit 1
fi

echo "no-local-fork policy check passed (no new forbidden definitions detected)"
