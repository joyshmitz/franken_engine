# Parser Third-Party Rerun Kit Notes

Generated at: 20260226T192947Z
Bead: bd-2mds.1.7.3
Policy: policy-parser-third-party-rerun-kit-v1
Matrix input status: pending_upstream_matrix

## Inputs

- Matrix summary: <not provided>
- Matrix deltas: <not provided>
- Matrix run manifest: <not provided>

## Replay Commands

- ./scripts/e2e/parser_third_party_rerun_kit_replay.sh package
- ./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh

## Fail-Closed Guidance

Promotion and claim workflows must fail closed unless
`matrix_input_status == ready_for_external_rerun`.
