use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn adr_defines_sqlmodel_rust_boundary_rules_and_examples() {
    let adr_path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_clauses = [
        "## Companion Decision: `sqlmodel_rust` Boundary",
        "Use `sqlmodel_rust` (typed model layer on frankensqlite) when one or more are true:",
        "Use raw `/dp/frankensqlite` primitives when all are true:",
        "replay index",
        "benchmark ledger",
        "replacement lineage log",
        "IFC provenance index",
    ];

    for clause in required_clauses {
        assert!(
            adr.contains(clause),
            "ADR must include required sqlmodel boundary clause: {clause}"
        );
    }
}

#[test]
fn inventory_tracks_model_layer_choice_for_each_store() {
    let inventory_path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let inventory = fs::read_to_string(&inventory_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", inventory_path.display()));

    let required_clauses = [
        "Model layer",
        "raw frankensqlite",
        "sqlmodel_rust on frankensqlite",
        "Set the `Model layer` (`raw frankensqlite` or `sqlmodel_rust on frankensqlite`) with rationale.",
    ];

    for clause in required_clauses {
        assert!(
            inventory.contains(clause),
            "Inventory must include required sqlmodel traceability clause: {clause}"
        );
    }
}
