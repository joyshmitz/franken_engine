# Parser Deterministic Fallback and Failover Controls Contract

This document defines the PSRP-05.4.1 contract for deterministic fallback
trigger semantics and serial failover control behavior in
`crates/franken-engine/src/parallel_parser.rs`.

## Scope

- Define stable fallback trigger taxonomy for deterministic failover decisions.
- Record explicit failover transition states and replay command hints.
- Ensure failover paths preserve correctness evidence instead of masking drift.
- Provide one-command reproducible failover verification artifacts.

## Trigger Taxonomy Contract

`FailoverTriggerClass` is the stable trigger taxonomy:

- `timeout`
- `transcript-divergence`
- `witness-mismatch`
- `safety-policy-violation`
- `parity-mismatch`
- `resource-limit`

Each emitted failover decision must include:

- trigger class
- deterministic detail string
- deterministic witness ID list
- one-command replay hint

## State Transition Contract

Failover controller transitions are explicit and ordered:

1. `parallel-attempted`
2. `trigger-classified`
3. `serial-fallback-requested`
4. `serial-fallback-completed`

The transition path is persisted in `FailoverDecision.transition_path` and must
be projected into structured logs for every failover decision.

## Correctness Visibility Contract

Failover must not hide correctness defects:

- parity-driven failover keeps mismatch signal via `fallback_cause` and
  `parity_result`.
- transcript divergence failover preserves divergence detail in
  `SerialReason::TranscriptDivergence` and `FallbackCause::TranscriptDivergence`.
- replay envelope must include failover decision metadata when fallback occurs.

Structured parse logs must emit these failover fields when present:

- `failover_trigger`
- `failover_transition_path`
- `failover_witness_ids`
- `replay_command`

## Gate and Artifacts

Primary gate script:

```bash
./scripts/run_parser_failover_controls_gate.sh ci
```

Artifacts are emitted under:

- `artifacts/parser_failover_controls/<timestamp>/run_manifest.json`
- `artifacts/parser_failover_controls/<timestamp>/events.jsonl`
- `artifacts/parser_failover_controls/<timestamp>/commands.txt`

The manifest must include deterministic environment fields and replay command.
