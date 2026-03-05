use std::{fs, path::PathBuf};

#[test]
fn frankensqlite_inventory_contains_required_stores_and_sections() {
    let inventory_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let inventory = fs::read_to_string(&inventory_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", inventory_path.display()));

    let required_sections = [
        "## Database Topology",
        "## Store Inventory",
        "## Decision Boundary: Shared Vs Isolated",
        "## Review Gate Requirements",
        "## Traceability Matrix (10.15)",
    ];
    for section in required_sections {
        assert!(
            inventory.contains(section),
            "Inventory must contain required section: {section}"
        );
    }

    let required_stores = [
        "replay index",
        "evidence index",
        "benchmark ledger",
        "policy artifact cache",
        "PLAS witness store",
        "replacement lineage log",
        "IFC provenance index",
        "specialization index",
    ];
    for store in required_stores {
        assert!(
            inventory.contains(store),
            "Inventory must include required store entry: {store}"
        );
    }

    let required_columns = [
        "Model layer",
        "Data model",
        "Access pattern",
        "Consistency requirement",
        "Retention policy",
        "Frankensqlite integration point",
        "Migration strategy",
        "Deterministic replay requirement",
    ];
    for column in required_columns {
        assert!(
            inventory.contains(column),
            "Inventory must include required mapping field: {column}"
        );
    }
}

#[test]
fn frankensqlite_inventory_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(!content.is_empty());
}

#[test]
fn frankensqlite_inventory_references_traceability() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Traceability"));
}

#[test]
fn frankensqlite_inventory_references_deterministic_replay() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Deterministic replay"));
}

#[test]
fn frankensqlite_inventory_has_database_topology_content() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Database Topology"));
}

#[test]
fn frankensqlite_inventory_has_shared_vs_isolated_decision() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Shared Vs Isolated"));
}

#[test]
fn frankensqlite_inventory_has_review_gate_requirements() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Review Gate Requirements"));
}

#[test]
fn frankensqlite_inventory_lists_shared_control_plane_db() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("control_plane.db"));
}

#[test]
fn frankensqlite_inventory_lists_isolated_databases() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("benchmark_ledger.db"));
    assert!(content.contains("plas_witness.db"));
    assert!(content.contains("replacement_lineage.db"));
}

#[test]
fn frankensqlite_inventory_has_operator_verification_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Operator Verification"));
}

#[test]
fn frankensqlite_inventory_mentions_scope_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Scope"));
}

#[test]
fn frankensqlite_inventory_references_upstream_adr() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("ADR-0004-frankensqlite-reuse-scope.md"));
}

#[test]
fn frankensqlite_inventory_mentions_retention_policy() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Retention policy"));
}

#[test]
fn frankensqlite_inventory_has_store_inventory_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Store Inventory"));
}

#[test]
fn frankensqlite_inventory_has_traceability_matrix_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Traceability Matrix"));
}

#[test]
fn frankensqlite_inventory_has_database_topology_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Database Topology"));
}
