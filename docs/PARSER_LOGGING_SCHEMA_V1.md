# Parser Logging Schema v1

This document defines the canonical parser verification event schema and
redaction policy introduced by `bd-2mds.1.9.5.1`.

## Schema Identifier

- Event schema: `franken-engine.parser-log-event.v1`
- Validation entrypoint: `scripts/validate_parser_log_schema.sh`

## Required Event Fields

Every parser gate event line (`events.jsonl`) must contain:

| Field | Type | Requirement |
|---|---|---|
| `schema_version` | string | Must start with `franken-engine.parser` |
| `trace_id` | string | Non-empty deterministic trace identifier |
| `decision_id` | string | Non-empty deterministic decision identifier |
| `policy_id` | string | Non-empty policy contract identifier |
| `component` | string | Non-empty component emitter identifier |
| `event` | string | Non-empty event name |
| `outcome` | string | Event outcome (`pass`, `fail`, etc.) |
| `error_code` | string or null | Stable failure code for failed outcomes; `null` allowed for success |

## Recommended Parser Fields

Parser lanes should also emit:

- `scenario` or `workload_id`
- `partition` or `corpus`
- `replay_command`
- lane-specific context fields (e.g., allocator epoch, fragmentation ratio)

## Redaction Policy

### Forbidden Top-Level or Nested Keys

Events must not include direct sensitive fields:

- `password`, `passphrase`
- `secret`
- `api_key`
- `private_key`
- `access_token`, `refresh_token`, `bearer_token`
- `session_cookie`
- `raw_source`, `source_code`, `code_snippet`
- `env`, `environment`, `env_vars`

### Source/Code Handling

If a source-like field is ever emitted in future schemas, values must be either:

- `[REDACTED]` (or `[REDACTED:<CLASS>]`)
- `sha256:<64-hex>`

### Sensitive Value Pattern Rejection

Validation rejects lines containing common leaked-secret patterns, including:

- private key PEM headers
- AWS access key format (`AKIA...`)
- GitHub personal token prefix (`ghp_...`)
- Slack token prefixes (`xox...`)
- inline `password=` / `secret=` patterns

## Validator Contract

Use:

```bash
./scripts/validate_parser_log_schema.sh --events <path-to-events.jsonl>
```

Behavior:

- exits `0` when all lines conform
- exits non-zero when malformed, unsafe, or missing required fields
- prints first failing line context to stderr

## Parser Gate Integration

The following parser gate scripts run validation and fail closed on violations:

- `scripts/run_parser_phase0_gate.sh`
- `scripts/run_parser_oracle_gate.sh`
- `scripts/run_parser_phase1_arena_suite.sh`

If validation fails, gate manifests are rewritten with failure outcome and
the script returns non-zero.
