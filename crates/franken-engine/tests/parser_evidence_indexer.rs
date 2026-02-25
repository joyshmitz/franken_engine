use frankenengine_engine::parser_evidence_indexer::{
    ParserEvidenceIndexBuilder, SchemaMigrationStep,
};

fn manifest(run_id: &str, schema_version: &str, replay_command: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": schema_version,
        "run_id": run_id,
        "replay_command": replay_command,
        "generated_at_utc": "2026-02-25T00:00:00Z",
        "outcome": "pass"
    })
}

#[test]
fn e2e_index_build_and_correlation_round_trip() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-20260225-a",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_a.sh",
            ),
            "artifacts/a/run_manifest.json",
            "artifacts/a/events.jsonl",
            "artifacts/a/commands.txt",
        )
        .unwrap();
    builder
        .add_run(
            &manifest(
                "run-20260225-b",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_b.sh",
            ),
            "artifacts/b/run_manifest.json",
            "artifacts/b/events.jsonl",
            "artifacts/b/commands.txt",
        )
        .unwrap();

    let event_a = r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-a","decision_id":"decision-a","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"drift_detected","outcome":"fail","error_code":"FE-PARSER-DRIFT-0001","scenario_id":"fixture-foo","replay_command":"./scripts/replay_a.sh"}"#;
    let event_b = r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-b","decision_id":"decision-b","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"drift_detected","outcome":"fail","error_code":"FE-PARSER-DRIFT-0001","scenario_id":"fixture-foo","replay_command":"./scripts/replay_b.sh"}"#;

    builder.add_events_jsonl("run-20260225-a", event_a).unwrap();
    builder.add_events_jsonl("run-20260225-b", event_b).unwrap();

    let index = builder.build();
    let json = serde_json::to_string_pretty(&index).unwrap();
    let back: frankenengine_engine::parser_evidence_indexer::ParserEvidenceIndex =
        serde_json::from_str(&json).unwrap();

    assert_eq!(back.runs.len(), 2);
    assert_eq!(back.events.len(), 2);

    let clusters = back.correlate_regressions();
    assert_eq!(clusters.len(), 1);
    let cluster = &clusters[0];
    assert_eq!(cluster.run_count, 2);
    assert_eq!(cluster.occurrence_count, 2);
    assert_eq!(cluster.key.component, "parser_evidence_indexer");
    assert_eq!(cluster.key.event, "drift_detected");
    assert_eq!(
        cluster.key.error_code.as_deref(),
        Some("FE-PARSER-DRIFT-0001")
    );
    assert_eq!(cluster.key.scenario_id.as_deref(), Some("fixture-foo"));
}

#[test]
fn migration_pipeline_supports_multi_hop_event_upgrade() {
    let mut builder = ParserEvidenceIndexBuilder::new();
    builder
        .add_run(
            &manifest(
                "run-20260225-migrate",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_migrate.sh",
            ),
            "artifacts/m/run_manifest.json",
            "artifacts/m/events.jsonl",
            "artifacts/m/commands.txt",
        )
        .unwrap();

    let events = r#"
{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-1","decision_id":"decision-1","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"index_started","outcome":"pass","error_code":null}
{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-2","decision_id":"decision-2","policy_id":"policy-v1","component":"parser_evidence_indexer","event":"index_finished","outcome":"pass","error_code":null}
"#;
    builder
        .add_events_jsonl("run-20260225-migrate", events)
        .unwrap();

    let mut index = builder.build();
    let receipts = index
        .migrate_event_schemas(
            "franken-engine.parser-log-event.v3",
            &[
                SchemaMigrationStep {
                    migration_id: "mig-parser-log-v1-v2".to_string(),
                    from_schema: "franken-engine.parser-log-event.v1".to_string(),
                    to_schema: "franken-engine.parser-log-event.v2".to_string(),
                },
                SchemaMigrationStep {
                    migration_id: "mig-parser-log-v2-v3".to_string(),
                    from_schema: "franken-engine.parser-log-event.v2".to_string(),
                    to_schema: "franken-engine.parser-log-event.v3".to_string(),
                },
            ],
        )
        .unwrap();

    assert_eq!(receipts.len(), 2);
    assert!(
        index
            .events
            .iter()
            .all(|event| event.schema_version == "franken-engine.parser-log-event.v3")
    );
    assert!(index.schema_migrations.is_empty());
}

#[test]
fn deterministic_ordering_is_stable_across_insertion_order() {
    let mut left = ParserEvidenceIndexBuilder::new();
    left.add_run(
        &manifest(
            "run-z",
            "franken-engine.parser-evidence-index.run.v1",
            "./scripts/replay_z.sh",
        ),
        "artifacts/z/run_manifest.json",
        "artifacts/z/events.jsonl",
        "artifacts/z/commands.txt",
    )
    .unwrap();
    left.add_run(
        &manifest(
            "run-a",
            "franken-engine.parser-evidence-index.run.v1",
            "./scripts/replay_a.sh",
        ),
        "artifacts/a/run_manifest.json",
        "artifacts/a/events.jsonl",
        "artifacts/a/commands.txt",
    )
    .unwrap();

    left.add_events_jsonl(
        "run-z",
        r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-z","decision_id":"decision-z","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
    )
    .unwrap();
    left.add_events_jsonl(
        "run-a",
        r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-a","decision_id":"decision-a","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
    )
    .unwrap();

    let left_index = left.build();

    let mut right = ParserEvidenceIndexBuilder::new();
    right
        .add_run(
            &manifest(
                "run-a",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_a.sh",
            ),
            "artifacts/a/run_manifest.json",
            "artifacts/a/events.jsonl",
            "artifacts/a/commands.txt",
        )
        .unwrap();
    right
        .add_run(
            &manifest(
                "run-z",
                "franken-engine.parser-evidence-index.run.v1",
                "./scripts/replay_z.sh",
            ),
            "artifacts/z/run_manifest.json",
            "artifacts/z/events.jsonl",
            "artifacts/z/commands.txt",
        )
        .unwrap();

    right
        .add_events_jsonl(
            "run-a",
            r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-a","decision_id":"decision-a","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
        )
        .unwrap();
    right
        .add_events_jsonl(
            "run-z",
            r#"{"schema_version":"franken-engine.parser-log-event.v1","trace_id":"trace-z","decision_id":"decision-z","policy_id":"policy-v1","component":"idx","event":"done","outcome":"pass","error_code":null}"#,
        )
        .unwrap();

    let right_index = right.build();

    let left_json = serde_json::to_string(&left_index).unwrap();
    let right_json = serde_json::to_string(&right_index).unwrap();
    assert_eq!(left_json, right_json);
}
