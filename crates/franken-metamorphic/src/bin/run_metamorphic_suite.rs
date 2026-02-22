use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_metamorphic::build_enabled_relations;
use frankenengine_metamorphic::catalog::RelationCatalog;
use frankenengine_metamorphic::relation::MetamorphicRelation;
use frankenengine_metamorphic::runner::{
    MinimizerConfig, RunContext, evidence_entries_for_suite, relation_log_events_for_suite,
    run_suite, write_evidence_jsonl,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut pairs_override = None::<u32>;
    let mut seed = 1u64;
    let mut trace_id = String::from("trace-metamorphic-default");
    let mut decision_id = String::from("decision-metamorphic-default");
    let mut policy_id = String::from("policy-metamorphic-v1");
    let mut evidence_path = PathBuf::from("artifacts/metamorphic/metamorphic_evidence.jsonl");
    let mut events_path = PathBuf::from("artifacts/metamorphic/relation_events.jsonl");
    let mut failures_dir = PathBuf::from("artifacts/metamorphic/failures");
    let mut relation_filters = Vec::<String>::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pairs" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --pairs".into());
                };
                pairs_override = Some(value.parse::<u32>()?);
            }
            "--seed" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --seed".into());
                };
                seed = value.parse::<u64>()?;
            }
            "--trace-id" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --trace-id".into());
                };
                trace_id = value;
            }
            "--decision-id" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --decision-id".into());
                };
                decision_id = value;
            }
            "--policy-id" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --policy-id".into());
                };
                policy_id = value;
            }
            "--evidence" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --evidence".into());
                };
                evidence_path = PathBuf::from(value);
            }
            "--events" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --events".into());
                };
                events_path = PathBuf::from(value);
            }
            "--failures-dir" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --failures-dir".into());
                };
                failures_dir = PathBuf::from(value);
            }
            "--relation" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --relation".into());
                };
                relation_filters.push(value);
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }

    let catalog = RelationCatalog::load_default()?;
    let catalog_hash = catalog.content_hash();

    let all_relations = build_enabled_relations(&catalog);
    let selected_relations = if relation_filters.is_empty() {
        all_relations
    } else {
        all_relations
            .into_iter()
            .filter(|relation| {
                relation_filters
                    .iter()
                    .any(|filter| relation.spec().id == *filter)
            })
            .collect::<Vec<_>>()
    };

    if selected_relations.is_empty() {
        return Err("no relations selected for execution".into());
    }

    if let Some(parent) = evidence_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = events_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(&failures_dir)?;

    let context = RunContext::new(
        trace_id,
        decision_id,
        policy_id,
        "metamorphic_suite",
        catalog_hash,
        seed,
    );

    let relation_refs: Vec<&dyn MetamorphicRelation> = selected_relations
        .iter()
        .map(|relation| relation as &dyn MetamorphicRelation)
        .collect();

    let suite = run_suite(
        &relation_refs,
        &context,
        pairs_override,
        Some(&failures_dir),
        MinimizerConfig::default(),
    )?;

    let evidence_entries = evidence_entries_for_suite(&suite);
    write_evidence_jsonl(&evidence_path, &evidence_entries)?;

    let events = relation_log_events_for_suite(&suite);
    write_events_jsonl(&events_path, &events)?;

    println!(
        "metamorphic suite relations={} total_pairs={} violations={} evidence={} events={} failures_dir={}",
        suite.relation_executions.len(),
        suite.total_pairs,
        suite.total_violations,
        evidence_path.display(),
        events_path.display(),
        failures_dir.display()
    );

    if suite.total_violations > 0 {
        return Err(format!(
            "metamorphic violations detected: {}",
            suite.total_violations
        )
        .into());
    }

    Ok(())
}

fn write_events_jsonl(
    events_path: &std::path::Path,
    events: &[frankenengine_metamorphic::runner::RelationLogEvent],
) -> std::io::Result<()> {
    let mut payload = String::new();
    for event in events {
        payload
            .push_str(&serde_json::to_string(event).expect("event serialization should succeed"));
        payload.push('\n');
    }

    fs::write(events_path, payload)
}
