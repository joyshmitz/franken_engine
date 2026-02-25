#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Validate parser verification event logs against schema/redaction policy.

Usage:
  ./scripts/validate_parser_log_schema.sh --events <events.jsonl> [--schema-prefix <prefix>]

Options:
  --events <path>         Path to JSONL event stream (required).
  --schema-prefix <text>  Required prefix for schema_version when present.
                          Default: franken-engine.parser
  -h, --help              Show this help.
EOF
}

events_path=""
schema_prefix="franken-engine.parser"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --events)
      events_path="${2:-}"
      shift 2
      ;;
    --schema-prefix)
      schema_prefix="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$events_path" ]]; then
  echo "missing required --events path" >&2
  usage >&2
  exit 2
fi

if [[ ! -f "$events_path" ]]; then
  echo "events file not found: $events_path" >&2
  exit 2
fi

required_keys=(
  schema_version
  trace_id
  decision_id
  policy_id
  component
  event
  outcome
  error_code
)

line_no=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line_no=$((line_no + 1))
  [[ -z "${line// }" ]] && continue

  if ! jq -e . >/dev/null 2>&1 <<<"$line"; then
    echo "invalid JSON at ${events_path}:${line_no}" >&2
    exit 1
  fi

  for key in "${required_keys[@]}"; do
    if [[ "$key" == "error_code" ]]; then
      if ! jq -e --arg key "$key" '
        has($key) and
        (
          .[$key] == null or
          (
            (.[$key] | type) == "string" and
            ((.[$key] | length) > 0)
          )
        )
      ' >/dev/null 2>&1 <<<"$line"; then
        echo "missing or invalid required key '${key}' at ${events_path}:${line_no}" >&2
        exit 1
      fi
    else
      if ! jq -e --arg key "$key" '
        has($key) and
        (.[$key] | type) == "string" and
        ((.[$key] | length) > 0)
      ' >/dev/null 2>&1 <<<"$line"; then
        echo "missing or invalid required key '${key}' at ${events_path}:${line_no}" >&2
        exit 1
      fi
    fi
  done

  if jq -e 'has("schema_version")' >/dev/null 2>&1 <<<"$line"; then
    if ! jq -e --arg prefix "$schema_prefix" '
      (.schema_version | type) == "string" and
      (.schema_version | startswith($prefix))
    ' >/dev/null 2>&1 <<<"$line"; then
      echo "invalid schema_version prefix at ${events_path}:${line_no}" >&2
      exit 1
    fi
  fi

  sensitive_key_hits="$(
    jq -r '
      paths
      | .[-1] // empty
      | strings
    ' <<<"$line" | grep -Ei \
      '^(password|passphrase|secret|api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|bearer[_-]?token|session[_-]?cookie|raw_source|source_code|code_snippet|env|environment|env_vars)$' || true
  )"
  if [[ -n "$sensitive_key_hits" ]]; then
    echo "sensitive key present at ${events_path}:${line_no}: ${sensitive_key_hits%%$'\n'*}" >&2
    exit 1
  fi

  if ! jq -e '
    def redacted:
      (type == "string") and
      (
        test("^\\[REDACTED(:[A-Z_]+)?\\]$") or
        test("^sha256:[0-9a-f]{64}$")
      );
    [
      paths(scalars) as $p
      | select((($p[-1] | tostring) | test("^(source|source_code|raw_source|code_snippet)$"; "i")))
      | getpath($p)
      | redacted
    ] | all
  ' >/dev/null 2>&1 <<<"$line"; then
    echo "unredacted source/code field detected at ${events_path}:${line_no}" >&2
    exit 1
  fi

  if jq -r '.. | strings' <<<"$line" | grep -Eiq \
    '(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-|password[[:space:]]*[=:]|secret[[:space:]]*[=:])'; then
    echo "sensitive token pattern detected in values at ${events_path}:${line_no}" >&2
    exit 1
  fi
done <"$events_path"

echo "parser log schema validation passed: $events_path"
