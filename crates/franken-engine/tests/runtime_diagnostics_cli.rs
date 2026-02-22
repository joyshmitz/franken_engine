use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::containment_executor::{ContainmentReceipt, ContainmentState};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEntry, EvidenceEntryBuilder, Witness,
};
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_telemetry::{
    FlowLabel, HostcallResult, HostcallTelemetryRecord, HostcallType, RecordInput, RecorderConfig,
    ResourceDelta, TelemetryRecorder,
};
use frankenengine_engine::runtime_diagnostics_cli::{
    ContainmentReceiptEnvelope, GcPressureSample, HostcallTelemetryEnvelope, ReplayArtifactRecord,
    RuntimeDiagnosticsCliInput, RuntimeExtensionState, RuntimeStateInput, SchedulerLaneSample,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn build_sample_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-runtime-cli".to_string(),
        decision_id: "decision-runtime-cli".to_string(),
        policy_id: "policy-runtime-cli".to_string(),
        runtime_state: RuntimeStateInput {
            snapshot_timestamp_ns: 20_000,
            loaded_extensions: vec![
                RuntimeExtensionState {
                    extension_id: "ext-a".to_string(),
                    containment_state: ContainmentState::Running,
                },
                RuntimeExtensionState {
                    extension_id: "ext-b".to_string(),
                    containment_state: ContainmentState::Sandboxed,
                },
            ],
            active_policies: vec!["policy-main".to_string(), "policy-main".to_string()],
            security_epoch: SecurityEpoch::from_raw(11),
            gc_pressure: vec![
                GcPressureSample {
                    extension_id: "ext-b".to_string(),
                    used_bytes: 900,
                    budget_bytes: 1_000,
                },
                GcPressureSample {
                    extension_id: "ext-a".to_string(),
                    used_bytes: 120,
                    budget_bytes: 1_000,
                },
            ],
            scheduler_lanes: vec![
                SchedulerLaneSample {
                    lane: "ready".to_string(),
                    queue_depth: 40,
                    max_depth: 100,
                    tasks_submitted: 80,
                    tasks_scheduled: 60,
                    tasks_completed: 58,
                    tasks_timed_out: 2,
                },
                SchedulerLaneSample {
                    lane: "cancel".to_string(),
                    queue_depth: 1,
                    max_depth: 8,
                    tasks_submitted: 5,
                    tasks_scheduled: 5,
                    tasks_completed: 5,
                    tasks_timed_out: 0,
                },
            ],
        },
        evidence_entries: sample_evidence_entries(),
        hostcall_records: vec![sample_hostcall_envelope()],
        containment_receipts: vec![sample_containment_envelope()],
        replay_artifacts: vec![ReplayArtifactRecord {
            trace_id: "trace-incident".to_string(),
            extension_id: "ext-a".to_string(),
            timestamp_ns: 1_104,
            artifact_id: "replay-1".to_string(),
            replay_pointer: "artifacts/replay/trace-incident.json".to_string(),
        }],
    }
}

fn sample_evidence_entries() -> Vec<EvidenceEntry> {
    vec![
        EvidenceEntryBuilder::new(
            "trace-incident",
            "dec-101",
            "policy-main",
            SecurityEpoch::from_raw(11),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1_101)
        .candidate(CandidateAction::new("sandbox", 120_000))
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 120_000,
            rationale: "min-loss".to_string(),
        })
        .witness(Witness {
            witness_id: "w-1".to_string(),
            witness_type: "posterior".to_string(),
            value: "0.91".to_string(),
        })
        .meta("extension_id", "ext-a")
        .build()
        .expect("security entry should build"),
        EvidenceEntryBuilder::new(
            "trace-incident",
            "dec-102",
            "policy-main",
            SecurityEpoch::from_raw(11),
            DecisionType::PolicyUpdate,
        )
        .timestamp_ns(1_102)
        .candidate(CandidateAction::new("rotate", 1))
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 1,
            rationale: "rotation".to_string(),
        })
        .build()
        .expect("policy entry should build"),
    ]
}

fn sample_hostcall_envelope() -> HostcallTelemetryEnvelope {
    let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
    recorder
        .record(
            1_103,
            RecordInput {
                extension_id: "ext-a".to_string(),
                hostcall_type: HostcallType::FsRead,
                capability_used: frankenengine_engine::capability::RuntimeCapability::FsRead,
                arguments_hash: ContentHash::compute(b"args"),
                result_status: HostcallResult::Denied {
                    reason: "policy".to_string(),
                },
                duration_ns: 5_000,
                resource_delta: ResourceDelta::default(),
                flow_label: FlowLabel::new("public", "public"),
                decision_id: Some("dec-101".to_string()),
            },
        )
        .expect("record should succeed");
    let record: HostcallTelemetryRecord = recorder.records()[0].clone();

    HostcallTelemetryEnvelope {
        trace_id: "trace-incident".to_string(),
        policy_id: "policy-main".to_string(),
        record,
    }
}

fn sample_containment_envelope() -> ContainmentReceiptEnvelope {
    let mut metadata = BTreeMap::new();
    metadata.insert("decision_id".to_string(), "dec-101".to_string());

    let receipt = ContainmentReceipt {
        receipt_id: "cr-1".to_string(),
        action: ContainmentAction::Sandbox,
        target_extension_id: "ext-a".to_string(),
        previous_state: ContainmentState::Running,
        new_state: ContainmentState::Sandboxed,
        timestamp_ns: 1_104,
        duration_ns: 0,
        success: true,
        cooperative: false,
        evidence_refs: vec!["ev-1".to_string()],
        epoch: SecurityEpoch::from_raw(11),
        content_hash: ContentHash::compute(b"cr-1"),
        metadata,
    };

    ContainmentReceiptEnvelope {
        trace_id: "trace-incident".to_string(),
        policy_id: "policy-main".to_string(),
        receipt,
    }
}

fn write_input_file(input: &RuntimeDiagnosticsCliInput) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!(
        "runtime_diagnostics_cli_test_{}_{}.json",
        std::process::id(),
        nonce
    ));

    fs::write(
        &path,
        serde_json::to_vec_pretty(input).expect("sample input should serialize"),
    )
    .expect("input file should be written");

    path
}

#[test]
fn diagnostics_command_outputs_runtime_state_json() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args(["diagnostics", "--input"])
        .arg(&input_path)
        .output()
        .expect("diagnostics command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");

    let security_epoch = json["security_epoch"]
        .as_u64()
        .or_else(|| json["security_epoch"]["epoch"].as_u64());
    assert_eq!(security_epoch, Some(11));
    assert_eq!(json["loaded_extensions"].as_array().map(Vec::len), Some(2));
    assert_eq!(json["active_policies"].as_array().map(Vec::len), Some(1));

    let _ = fs::remove_file(input_path);
}

#[test]
fn evidence_export_filters_by_extension_trace_and_time() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "export-evidence",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--extension-id",
            "ext-a",
            "--trace-id",
            "trace-incident",
            "--start-ns",
            "1103",
            "--end-ns",
            "1104",
            "--severity",
            "warning",
        ])
        .output()
        .expect("export command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");
    let records = json["records"]
        .as_array()
        .expect("records should be an array");

    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| {
        record["trace_id"] == "trace-incident"
            && record["extension_id"] == "ext-a"
            && (record["timestamp_ns"] == 1103 || record["timestamp_ns"] == 1104)
            && record["severity"] == "warning"
    }));

    let _ = fs::remove_file(input_path);
}

#[test]
fn evidence_export_is_deterministic_for_same_query() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let run = |path: &PathBuf| {
        Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
            .args(["export-evidence", "--input"])
            .arg(path)
            .output()
            .expect("export command should execute")
    };

    let first = run(&input_path);
    let second = run(&input_path);

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);

    let _ = fs::remove_file(input_path);
}

#[test]
fn export_summary_reports_empty_result_as_valid() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "export-evidence",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--extension-id",
            "missing-ext",
            "--summary",
        ])
        .output()
        .expect("export command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert_eq!(
        stdout.trim(),
        "No evidence entries found for the specified filters."
    );

    let _ = fs::remove_file(input_path);
}

#[test]
fn export_output_contains_all_required_evidence_categories() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args(["export-evidence", "--input"])
        .arg(&input_path)
        .output()
        .expect("export command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");
    let records = json["records"]
        .as_array()
        .expect("records should be an array");

    let mut kinds = BTreeMap::<String, u64>::new();
    for record in records {
        let kind = record["kind"]
            .as_str()
            .expect("kind should be a string")
            .to_string();
        *kinds.entry(kind).or_insert(0) += 1;
    }

    for required in [
        "decision_receipt",
        "policy_change",
        "hostcall_telemetry",
        "containment_action",
        "replay_artifact",
    ] {
        assert!(
            kinds.contains_key(required),
            "missing required kind {required}"
        );
    }

    let _ = fs::remove_file(input_path);
}
