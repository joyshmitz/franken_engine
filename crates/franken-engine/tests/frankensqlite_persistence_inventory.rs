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
