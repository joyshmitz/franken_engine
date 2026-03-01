#!/usr/bin/env bash
set -euo pipefail

parser_oracle_apply_deterministic_env() {
  export TZ="${TZ:-UTC}"
  export LANG="${LANG:-C}"
  export LC_ALL="${LC_ALL:-C}"
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"
  export PARSER_ORACLE_ENV_BOOTSTRAP_VERSION="${PARSER_ORACLE_ENV_BOOTSTRAP_VERSION:-franken-engine.parser-oracle.env-bootstrap.v1}"
  export PARSER_ORACLE_LOCALE_FINGERPRINT="${PARSER_ORACLE_LOCALE_FINGERPRINT:-${LANG}/${LC_ALL}}"

  # Keep generated artifacts world-readable and stable across reruns.
  umask 022
}
