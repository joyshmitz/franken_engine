use std::collections::BTreeMap;

use frankenengine_engine::fork_detection::{
    ForkDetector, RecordCheckpointInput, SafeModeExitCheckInput, SafeModeStartupInput,
    SafeModeStartupSource, evaluate_safe_mode_exit, evaluate_safe_mode_startup,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::{
    CheckpointBuilder, DeterministicTimestamp, PolicyCheckpoint, PolicyHead, PolicyType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

fn make_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_policy_head(policy_type: PolicyType, version: u64) -> PolicyHead {
    let hash_input = format!("{policy_type}-v{version}");
    PolicyHead {
        policy_type,
        policy_hash: ContentHash::compute(hash_input.as_bytes()),
        policy_version: version,
    }
}

fn genesis(keys: &[SigningKey], zone: &str) -> PolicyCheckpoint {
    CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(keys)
        .expect("genesis checkpoint")
}

fn checkpoint_after(
    prev: &PolicyCheckpoint,
    seq: u64,
    epoch: SecurityEpoch,
    tick: u64,
    keys: &[SigningKey],
    zone: &str,
    version: u64,
) -> PolicyCheckpoint {
    CheckpointBuilder::after(prev, seq, epoch, DeterministicTimestamp(tick), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, version))
        .build(keys)
        .expect("checkpoint")
}

#[test]
fn startup_cli_flag_has_precedence_over_environment() {
    let mut environment = BTreeMap::new();
    environment.insert("FRANKEN_SAFE_MODE".to_string(), "0".to_string());
    environment.insert("FRANKENENGINE_SAFE_MODE".to_string(), "false".to_string());
    let input = SafeModeStartupInput {
        trace_id: "trace-safe-startup-precedence".to_string(),
        decision_id: "decision-safe-startup-precedence".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment,
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.safe_mode_active);
    assert_eq!(artifact.source, SafeModeStartupSource::CliFlag);
}

#[test]
fn startup_artifact_preserves_evidence_logs_and_state() {
    let input = SafeModeStartupInput {
        trace_id: "trace-safe-startup-preservation".to_string(),
        decision_id: "decision-safe-startup-preservation".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.evidence_preserved);
    assert!(artifact.logs_preserved);
    assert!(artifact.state_preserved);
    assert!(
        artifact
            .restricted_features
            .contains(&"extension_auto_promotion".to_string())
    );
    assert!(
        artifact
            .exit_procedure
            .contains(&"switch_runtime_to_normal_mode".to_string())
    );
}

#[test]
fn incident_recovery_flow_enters_safe_mode_and_exits_after_checks() {
    let startup = evaluate_safe_mode_startup(&SafeModeStartupInput {
        trace_id: "trace-safe-startup-incident".to_string(),
        decision_id: "decision-safe-startup-incident".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    })
    .expect("startup artifact");
    assert!(startup.safe_mode_active);

    let signing_key = make_signing_key(7);
    let base = genesis(std::slice::from_ref(&signing_key), "zone-a");
    let cp1 = checkpoint_after(
        &base,
        1,
        SecurityEpoch::GENESIS,
        200,
        std::slice::from_ref(&signing_key),
        "zone-a",
        2,
    );
    let cp1_divergent = checkpoint_after(
        &base,
        1,
        SecurityEpoch::GENESIS,
        220,
        std::slice::from_ref(&signing_key),
        "zone-a",
        99,
    );

    let mut detector = ForkDetector::with_defaults();
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &base,
            accepted: true,
            frontier_seq: 0,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 100,
            trace_id: "trace-checkpoint-genesis",
        })
        .expect("record genesis");
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1,
            accepted: true,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 200,
            trace_id: "trace-checkpoint-cp1",
        })
        .expect("record cp1");
    let report = detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_divergent,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 220,
            trace_id: "trace-checkpoint-divergent",
        })
        .expect_err("divergent checkpoint must trigger safe mode");
    assert!(detector.is_safe_mode("zone-a"));

    let blocked_exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-safe-exit-blocked".to_string(),
        decision_id: "decision-safe-exit-blocked".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: detector.unacknowledged_incidents("zone-a").len(),
        pending_quarantines: 1,
        evidence_ledger_flushed: false,
    })
    .expect("blocked exit artifact");
    assert!(!blocked_exit.can_exit);
    assert_eq!(blocked_exit.event.outcome, "fail");

    assert!(detector.acknowledge_incident("zone-a", &report.incident_id));
    let pass_exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-safe-exit-pass".to_string(),
        decision_id: "decision-safe-exit-pass".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: detector.unacknowledged_incidents("zone-a").len(),
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .expect("pass exit artifact");
    assert!(pass_exit.can_exit);
    detector
        .exit_safe_mode("zone-a", "trace-safe-exit-pass")
        .expect("exit safe mode");
    assert!(!detector.is_safe_mode("zone-a"));
}
