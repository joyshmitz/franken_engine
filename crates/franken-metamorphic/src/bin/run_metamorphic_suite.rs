use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_metamorphic::build_enabled_relations;
use frankenengine_metamorphic::catalog::RelationCatalog;
use frankenengine_metamorphic::relation::MetamorphicRelation;
use frankenengine_metamorphic::relations::CatalogBackedRelation;
use frankenengine_metamorphic::runner::{
    evidence_entries_for_suite, relation_log_events_for_suite, run_suite,
    seed_transcript_entries_for_suite, write_evidence_jsonl, write_seed_transcript_jsonl,
    MinimizerConfig, RunContext,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut pairs_override = None::<u32>;
    let mut seed = 1u64;
    let mut trace_id = String::from("trace-metamorphic-default");
    let mut decision_id = String::from("decision-metamorphic-default");
    let mut policy_id = String::from("policy-metamorphic-v1");
    let mut evidence_path = PathBuf::from("artifacts/metamorphic/metamorphic_evidence.jsonl");
    let mut events_path = PathBuf::from("artifacts/metamorphic/relation_events.jsonl");
    let mut seed_transcript_path = PathBuf::from("artifacts/metamorphic/seed_transcript.jsonl");
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
            "--seed-transcript" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --seed-transcript".into());
                };
                seed_transcript_path = PathBuf::from(value);
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
    let selected_relations = select_relations(&all_relations, &relation_filters)?;

    if selected_relations.is_empty() {
        return Err("no relations selected for execution".into());
    }

    if let Some(parent) = evidence_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = events_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = seed_transcript_path.parent() {
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
    let seed_transcript = seed_transcript_entries_for_suite(&suite);
    write_seed_transcript_jsonl(&seed_transcript_path, &seed_transcript)?;

    println!(
        "metamorphic suite relations={} total_pairs={} violations={} evidence={} events={} seed_transcript={} failures_dir={}",
        suite.relation_executions.len(),
        suite.total_pairs,
        suite.total_violations,
        evidence_path.display(),
        events_path.display(),
        seed_transcript_path.display(),
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

fn select_relations(
    all_relations: &[CatalogBackedRelation],
    relation_filters: &[String],
) -> Result<Vec<CatalogBackedRelation>, String> {
    if relation_filters.is_empty() {
        return Ok(all_relations.to_vec());
    }

    let mut selected = Vec::new();
    let mut unknown = Vec::new();
    let mut seen = BTreeSet::new();

    for relation_filter in relation_filters {
        if !seen.insert(relation_filter.clone()) {
            continue;
        }

        match all_relations
            .iter()
            .find(|relation| relation.spec().id.as_str() == relation_filter.as_str())
        {
            Some(relation) => selected.push(relation.clone()),
            None => unknown.push(relation_filter.clone()),
        }
    }

    if !unknown.is_empty() {
        let available = all_relations
            .iter()
            .map(|relation| relation.spec().id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "unknown relation filter(s): {}. available enabled relations: {available}",
            unknown.join(", ")
        ));
    }

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use frankenengine_metamorphic::build_enabled_relations;
    use frankenengine_metamorphic::catalog::RelationCatalog;
    use frankenengine_metamorphic::relation::MetamorphicRelation;

    use super::select_relations;

    #[test]
    fn select_relations_returns_all_when_filters_are_empty() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let all_relations = build_enabled_relations(&catalog);
        let selected = select_relations(&all_relations, &[]).expect("selection should succeed");
        assert_eq!(selected.len(), all_relations.len());
    }

    #[test]
    fn select_relations_rejects_unknown_filter_even_if_some_valid() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let all_relations = build_enabled_relations(&catalog);
        let filters = vec![
            "parser_whitespace_invariance".to_string(),
            "nonexistent_relation".to_string(),
        ];

        let error = select_relations(&all_relations, &filters).expect_err("selection should fail");
        assert!(error.contains("unknown relation filter(s): nonexistent_relation"));
        assert!(error.contains("available enabled relations:"));
    }

    #[test]
    fn select_relations_deduplicates_filters_preserving_first_seen_order() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let all_relations = build_enabled_relations(&catalog);
        let filters = vec![
            "execution_gc_timing_independence".to_string(),
            "execution_gc_timing_independence".to_string(),
            "parser_comment_invariance".to_string(),
        ];

        let selected = select_relations(&all_relations, &filters).expect("selection should pass");
        let selected_ids = selected
            .iter()
            .map(|relation| relation.spec().id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            selected_ids,
            vec![
                "execution_gc_timing_independence",
                "parser_comment_invariance"
            ]
        );
    }
}
