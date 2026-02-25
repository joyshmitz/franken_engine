use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::entropy_evidence_compressor::{
    ArithmeticCoder, CompressionCertificate, EntropyEstimator,
};
use frankenengine_engine::observability_channel_model::{
    ChannelState, PayloadFamily, canonical_channel_specs,
    generate_report as generate_channel_report,
};
use frankenengine_engine::observability_probe_design::{
    CandidateProbe, MultiModeManifest, ProbeDomain, ProbeGranularity, ProbeUniverse,
};
use frankenengine_engine::observability_quality_sentinel::{
    DegradationRegime, DemotionTarget, ObservabilityQualitySentinel, QualityDimension,
    QualityObservation, canonical_demotion_policy, generate_report as generate_sentinel_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn probe_id(label: &str) -> EngineObjectId {
    let schema =
        SchemaId::from_definition(b"franken-engine.observability-channel-model.integration.v1");
    derive_id(
        ObjectDomain::EvidenceRecord,
        "tests.observability_channel_model",
        &schema,
        label.as_bytes(),
    )
    .expect("derive deterministic probe id")
}

fn add_probe(
    universe: &mut ProbeUniverse,
    name: &str,
    domain: ProbeDomain,
    utility_millionths: i64,
    latency_micros: u64,
    memory_bytes: u64,
    events: &[&str],
) {
    let probe = CandidateProbe {
        id: probe_id(name),
        name: name.to_string(),
        domain,
        granularity: ProbeGranularity::Medium,
        forensic_utility_millionths: utility_millionths,
        latency_overhead_micros: latency_micros,
        memory_overhead_bytes: memory_bytes,
        covers_events: events.iter().map(|event| (*event).to_string()).collect(),
        metadata: BTreeMap::new(),
    };
    universe.add_probe(probe).expect("add probe to universe");
}

fn probe_universe() -> ProbeUniverse {
    let mut universe = ProbeUniverse::new();
    add_probe(
        &mut universe,
        "compiler_frontier_probe",
        ProbeDomain::Compiler,
        900_000,
        120,
        2_048,
        &["compile_start", "compile_end", "ir_emit"],
    );
    add_probe(
        &mut universe,
        "runtime_guardplane_probe",
        ProbeDomain::Runtime,
        880_000,
        150,
        2_048,
        &["decision_start", "decision_end", "policy_violation"],
    );
    add_probe(
        &mut universe,
        "evidence_chain_probe",
        ProbeDomain::EvidencePipeline,
        860_000,
        90,
        1_536,
        &["artifact_write", "artifact_hash", "artifact_publish"],
    );
    add_probe(
        &mut universe,
        "governance_audit_probe",
        ProbeDomain::Governance,
        910_000,
        130,
        2_560,
        &["policy_gate", "demotion_receipt", "replay_request"],
    );
    universe
}

#[test]
fn canonical_specs_cover_required_families_and_fail_closed_on_lossy_replay() {
    let specs = canonical_channel_specs();
    let families: BTreeSet<PayloadFamily> = specs.iter().map(|spec| spec.family).collect();

    assert_eq!(families.len(), 5);
    assert!(families.contains(&PayloadFamily::Decision));
    assert!(families.contains(&PayloadFamily::Replay));
    assert!(families.contains(&PayloadFamily::Optimization));
    assert!(families.contains(&PayloadFamily::Security));
    assert!(families.contains(&PayloadFamily::LegalProvenance));

    let replay_spec = specs
        .iter()
        .find(|spec| spec.family == PayloadFamily::Replay)
        .expect("replay channel spec");
    assert!(!replay_spec.lossy_permitted);
    assert_eq!(replay_spec.envelope.max_distortion_millionths, 0);

    let epoch = SecurityEpoch::from_raw(17);
    let mut replay_state = ChannelState::new(replay_spec.channel_id.clone(), epoch);
    replay_state
        .emit(replay_spec, 1)
        .expect_err("replay channel must fail closed on any lossy emission");

    let mut states = BTreeMap::new();
    states.insert(replay_spec.channel_id.clone(), replay_state);
    let report = generate_channel_report(&specs, &states, epoch);

    assert!(!report.gate_pass);
    assert!(report.total_violations >= 1);
}

#[test]
fn multi_mode_manifest_is_deterministic_and_incident_mode_expands_coverage() {
    let universe = probe_universe();
    let manifest_a = MultiModeManifest::build(&universe);
    let manifest_b = MultiModeManifest::build(&universe);

    assert_eq!(manifest_a.manifest_hash, manifest_b.manifest_hash);
    assert!(manifest_a.normal_schedule.within_budget);
    assert!(manifest_a.degraded_schedule.within_budget);
    assert!(manifest_a.incident_schedule.within_budget);
    assert!(
        manifest_a.incident_schedule.event_coverage_millionths
            >= manifest_a.normal_schedule.event_coverage_millionths
    );
    assert!(manifest_a.incident_schedule.probe_count() >= manifest_a.normal_schedule.probe_count());
}

#[test]
fn entropy_certificate_and_quality_sentinel_fail_closed_in_fidelity_emergency() {
    let mut estimator = EntropyEstimator::new();
    let symbols: Vec<u32> = (0..420).map(|index| (index % 7) as u32).collect();
    for symbol in &symbols {
        estimator.observe(*symbol);
    }

    let coder = ArithmeticCoder::from_estimator(&estimator).expect("build arithmetic coder");
    let compressed = coder.encode(&symbols).expect("encode symbols");
    let kraft_sum = coder
        .verify_kraft_inequality()
        .expect("verify kraft inequality");
    let certificate = CompressionCertificate::build(&estimator, &compressed, kraft_sum);

    assert!(certificate.kraft_satisfied);
    assert!(certificate.shannon_lower_bound_bits > 0);
    assert!(certificate.achieved_bits > 0);
    assert!(
        certificate.is_within_factor(8_000_000),
        "compression should remain within an 8x bound of the Shannon lower bound",
    );

    let policy = canonical_demotion_policy(SecurityEpoch::from_raw(23));
    let mut sentinel = ObservabilityQualitySentinel::new(policy);
    let mut saw_replay_demotion = false;

    let baseline = QualityObservation {
        dimension: QualityDimension::SignalFidelity,
        value_millionths: 950_000,
        timestamp_ns: 1_000,
        channel_id: "ch-replay-verifier".to_string(),
    };
    sentinel.observe(&baseline);

    for step in 0..14u64 {
        let low_fidelity = QualityObservation {
            dimension: QualityDimension::SignalFidelity,
            value_millionths: 300_000,
            timestamp_ns: 2_000 + step,
            channel_id: "ch-replay-verifier".to_string(),
        };
        let (_artifacts, receipts) = sentinel.observe(&low_fidelity);
        if receipts
            .iter()
            .any(|receipt| receipt.new_mode == DemotionTarget::FullReplayCapture)
        {
            saw_replay_demotion = true;
        }
    }

    assert!(
        saw_replay_demotion,
        "fidelity emergency should trigger full replay capture demotion",
    );

    let report = generate_sentinel_report(&sentinel);
    assert_eq!(report.overall_regime, DegradationRegime::Emergency);
    assert!(!report.gate_pass);
}
