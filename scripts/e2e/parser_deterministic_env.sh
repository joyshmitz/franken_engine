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

parser_frontier_json_escape() {
  local value="${1-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

parser_frontier_seed_checksum_json() {
  local seed_checksum="${1-}"
  if [[ -z "$seed_checksum" || "$seed_checksum" == "null" ]]; then
    printf 'null'
  else
    printf '"%s"' "$(parser_frontier_json_escape "$seed_checksum")"
  fi
}

# Emit deterministic_environment JSON fields (inner object only).
# Caller is responsible for writing surrounding braces.
parser_frontier_emit_manifest_environment_fields() {
  local indent="${1:-    }"
  local seed_checksum="${2:-null}"
  local seed_checksum_json
  seed_checksum_json="$(parser_frontier_seed_checksum_json "$seed_checksum")"

  echo "${indent}\"timezone\": \"$(parser_frontier_json_escape "${TZ}")\","
  echo "${indent}\"lang\": \"$(parser_frontier_json_escape "${LANG}")\","
  echo "${indent}\"lc_all\": \"$(parser_frontier_json_escape "${LC_ALL}")\","
  echo "${indent}\"source_date_epoch\": \"$(parser_frontier_json_escape "${SOURCE_DATE_EPOCH}")\","
  echo "${indent}\"rustc_version\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_RUSTC_VERSION}")\","
  echo "${indent}\"cargo_version\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_CARGO_VERSION}")\","
  echo "${indent}\"rust_host\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_RUST_HOST}")\","
  echo "${indent}\"cpu_fingerprint\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_CPU_FINGERPRINT}")\","
  echo "${indent}\"rustc_verbose_hash\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_RUSTC_VERBOSE_HASH}")\","
  echo "${indent}\"toolchain_fingerprint\": \"$(parser_frontier_json_escape "${PARSER_FRONTIER_TOOLCHAIN_FINGERPRINT}")\","
  echo "${indent}\"seed_transcript_checksum\": ${seed_checksum_json}"
}
