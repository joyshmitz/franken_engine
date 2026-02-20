use std::{fs, path::PathBuf};

#[test]
fn fastapi_reuse_scope_adr_contains_required_sections() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_sections = [
        "## In-Scope Endpoint Classes",
        "## Out-of-Scope Interfaces",
        "## Required `fastapi_rust` Conventions and Components",
        "## Exception Process",
        "## Review Gate",
    ];
    for section in required_sections {
        assert!(
            adr.contains(section),
            "ADR must contain required section: {section}"
        );
    }

    let required_endpoint_classes = [
        "Health checks",
        "Control actions (`start`/`stop`/`quarantine`)",
        "Evidence export APIs",
        "Replay control APIs",
        "Benchmark result APIs",
    ];
    for endpoint_class in required_endpoint_classes {
        assert!(
            adr.contains(endpoint_class),
            "ADR must define in-scope endpoint class `{endpoint_class}`"
        );
    }
}
