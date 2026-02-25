# Parser Oracle Proof Note

- trace_id: trace-parser-oracle-20260224T205638Z
- decision_id: decision-parser-oracle-20260224T205638Z
- policy_id: policy-parser-oracle-v1
- partition: smoke
- gate_mode: report_only
- fixture_catalog: crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json

## Drift Summary

- equivalent_count: 0
- minor_drift_count: 0
- critical_drift_count: 0
- decision_action: unknown
- fallback_reason: none

## Replay

```bash
cargo run -p frankenengine-engine --bin franken_parser_oracle_report --   --partition smoke   --gate-mode report_only   --seed 1   --trace-id trace-parser-oracle-20260224T205638Z   --decision-id decision-parser-oracle-20260224T205638Z   --policy-id policy-parser-oracle-v1   --fixture-catalog crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json
```
