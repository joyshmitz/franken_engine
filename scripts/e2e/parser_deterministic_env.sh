#!/usr/bin/env bash
set -euo pipefail

# Deterministic environment bootstrap for parser-frontier e2e/gate scripts.
# This script is intentionally dependency-light so it can be sourced from any
# parser phase wrapper before invoking rch/cargo commands.

parser_frontier_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | awk '{print $NF}'
  else
    cksum | awk '{print $1}'
  fi
}

parser_frontier_cpu_fingerprint() {
  local cpu_blob=""
  if [[ -r /proc/cpuinfo ]]; then
    cpu_blob="$(
      {
        awk -F': ' '/^model name/ {print "model_name="$2; exit}' /proc/cpuinfo
        awk -F': ' '/^cpu family/ {print "cpu_family="$2; exit}' /proc/cpuinfo
        awk -F': ' '/^model[[:space:]]/ {print "model="$2; exit}' /proc/cpuinfo
        awk -F': ' '/^stepping/ {print "stepping="$2; exit}' /proc/cpuinfo
        awk -F': ' '/^flags/ {print "flags="$2; exit}' /proc/cpuinfo
      } 2>/dev/null
    )"
  elif command -v sysctl >/dev/null 2>&1; then
    cpu_blob="$(
      {
        printf 'model_name=%s\n' "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
        printf 'features=%s\n' "$(sysctl -n machdep.cpu.features 2>/dev/null || true)"
        printf 'leaf7_features=%s\n' "$(sysctl -n machdep.cpu.leaf7_features 2>/dev/null || true)"
      }
    )"
  fi

  if [[ -z "$cpu_blob" ]]; then
    cpu_blob="$(uname -srm 2>/dev/null || echo unknown-cpu)"
  fi
  printf '%s' "$cpu_blob" | parser_frontier_sha256
}

parser_frontier_bootstrap_env() {
  export TZ="UTC"
  export LANG="C.UTF-8"
  export LC_ALL="C.UTF-8"
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
  export PARSER_FRONTIER_ENV_SCHEMA_VERSION="franken-engine.parser-frontier.env-contract.v1"

  local rustc_verbose rustc_version cargo_version rust_host cpu_fingerprint
  rustc_verbose="$(rustc -vV 2>/dev/null || true)"
  rustc_version="$(rustc -V 2>/dev/null || true)"
  cargo_version="$(cargo -V 2>/dev/null || true)"
  rust_host="$(printf '%s\n' "$rustc_verbose" | awk -F': ' '/^host:/ {print $2; exit}')"
  cpu_fingerprint="$(parser_frontier_cpu_fingerprint)"

  export PARSER_FRONTIER_RUSTC_VERSION="${rustc_version:-unknown}"
  export PARSER_FRONTIER_CARGO_VERSION="${cargo_version:-unknown}"
  export PARSER_FRONTIER_RUST_HOST="${rust_host:-unknown}"
  export PARSER_FRONTIER_CPU_FINGERPRINT="${cpu_fingerprint:-unknown}"
  export PARSER_FRONTIER_RUSTC_VERBOSE_HASH="$(printf '%s' "$rustc_verbose" | parser_frontier_sha256)"
  export PARSER_FRONTIER_TOOLCHAIN_FINGERPRINT="$(
    printf '%s|%s|%s|%s|%s|%s|%s|%s' \
      "$TZ" \
      "$LANG" \
      "$LC_ALL" \
      "$SOURCE_DATE_EPOCH" \
      "$PARSER_FRONTIER_RUSTC_VERSION" \
      "$PARSER_FRONTIER_CARGO_VERSION" \
      "$PARSER_FRONTIER_RUST_HOST" \
      "$PARSER_FRONTIER_CPU_FINGERPRINT" \
      | parser_frontier_sha256
  )"
}
