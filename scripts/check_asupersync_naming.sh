#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

errors=0

echo "Checking Cargo package naming for asupersync crates..."
while IFS= read -r cargo_toml; do
  bad_keys="$(rg -n '^\s*franken_(kernel|decision|evidence)\s*=' "$cargo_toml" || true)"
  if [[ -n "$bad_keys" ]]; then
    echo "ERROR: underscored dependency key found in $cargo_toml"
    echo "$bad_keys"
    errors=1
  fi

  bad_package_values="$(
    rg -n 'package\s*=\s*"franken_(kernel|decision|evidence)"' "$cargo_toml" || true
  )"
  if [[ -n "$bad_package_values" ]]; then
    echo "ERROR: underscored package value found in $cargo_toml"
    echo "$bad_package_values"
    errors=1
  fi
done < <(find . -name Cargo.toml -not -path './target/*' | sort)

echo "Checking Rust crate path naming for asupersync crates..."
bad_rust_paths="$(
  rg -n --glob '*.rs' '\b(use|extern crate)\s+franken-(kernel|decision|evidence)\b' . || true
)"
if [[ -n "$bad_rust_paths" ]]; then
  echo "ERROR: hyphenated crate path used in Rust source"
  echo "$bad_rust_paths"
  errors=1
fi

if [[ "$errors" -ne 0 ]]; then
  echo "asupersync naming lint failed"
  exit 1
fi

echo "asupersync naming lint passed"
