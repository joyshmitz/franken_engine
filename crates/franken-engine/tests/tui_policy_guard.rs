use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

const POLICY_ID: &str = "policy-frankentui-first-v1";
const TRACE_PREFIX: &str = "trace-tui-policy";
const COMPONENT: &str = "tui_policy_guard";

const FORBIDDEN_TUI_DEPENDENCIES: &[&str] = &[
    "crossterm",
    "ratatui",
    "cursive",
    "termion",
    "tuirealm",
    "tui-realm",
    "console_engine",
    "tui",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestInput {
    path: String,
    content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExceptionDocumentInput {
    path: String,
    content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExceptionScope {
    Dependency(String),
    ModulePattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedException {
    scopes: Vec<ExceptionScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PolicyGuardEvent {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    subject: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyViolation {
    error_code: &'static str,
    subject: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyGuardReport {
    events: Vec<PolicyGuardEvent>,
    violations: Vec<PolicyViolation>,
}

impl PolicyGuardReport {
    fn as_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.events {
            let line =
                serde_json::to_string(event).expect("policy guard event serialization should work");
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn dependency_section(section: &str) -> bool {
    section == "dependencies"
        || section == "dev-dependencies"
        || section == "build-dependencies"
        || section == "workspace.dependencies"
        || section.ends_with(".dependencies")
        || section.ends_with(".dev-dependencies")
        || section.ends_with(".build-dependencies")
}

fn dependency_names(manifest: &str) -> Vec<String> {
    let mut section = String::new();
    let mut deps = Vec::new();

    for raw_line in manifest.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if !dependency_section(section.as_str()) {
            continue;
        }

        let Some((raw_key, _raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim().trim_matches('"');
        if key.is_empty() {
            continue;
        }
        deps.push(key.to_string());
    }

    deps
}

fn parse_exception_docs(docs: &[ExceptionDocumentInput]) -> Vec<ParsedException> {
    docs.iter()
        .filter_map(parse_exception_doc)
        .collect()
}

fn parse_exception_doc(doc: &ExceptionDocumentInput) -> Option<ParsedException> {
    let normalized_path = doc.path.replace('\\', "/");
    if !normalized_path.starts_with("docs/adr/exceptions/ADR-EXCEPTION-TUI-")
        || !normalized_path.ends_with(".md")
    {
        return None;
    }

    let mut approved = false;
    let mut scopes = Vec::new();

    for raw_line in doc.content.lines() {
        let normalized = raw_line.trim().trim_start_matches('-').trim();
        if normalized.eq_ignore_ascii_case("Status: Approved") {
            approved = true;
            continue;
        }

        let lower = normalized.to_ascii_lowercase();
        if let Some(scope_raw) = lower.strip_prefix("scope:") {
            let scope_raw = scope_raw.trim();
            if let Some(dep) = scope_raw.strip_prefix("dependency:") {
                scopes.push(ExceptionScope::Dependency(dep.trim().to_string()));
            } else if let Some(path_pattern) = scope_raw.strip_prefix("module:") {
                scopes.push(ExceptionScope::ModulePattern(
                    path_pattern.trim().to_string(),
                ));
            }
        }
    }

    if approved && !scopes.is_empty() {
        Some(ParsedException { scopes })
    } else {
        None
    }
}

fn is_forbidden_tui_dependency(dep: &str) -> bool {
    let dep = dep.to_ascii_lowercase();
    if dep.starts_with("frankentui") {
        return false;
    }
    FORBIDDEN_TUI_DEPENDENCIES
        .iter()
        .any(|forbidden| *forbidden == dep)
}

fn dependency_exception_allowed(dep: &str, exceptions: &[ParsedException]) -> bool {
    let dep = dep.to_ascii_lowercase();
    exceptions.iter().any(|exception| {
        exception
            .scopes
            .iter()
            .any(|scope| matches!(scope, ExceptionScope::Dependency(allowed) if *allowed == dep))
    })
}

fn is_blocked_local_tui_module(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    if !normalized.ends_with(".rs") {
        return false;
    }
    if !normalized.starts_with("crates/") {
        return false;
    }
    if !normalized.contains("/src/") {
        return false;
    }
    if normalized.contains("frankentui") {
        return false;
    }
    normalized.contains("tui")
        || normalized.contains("ratatui")
        || normalized.contains("crossterm")
        || normalized.contains("cursive")
        || normalized.contains("termion")
}

fn pattern_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        value == pattern
    }
}

fn module_exception_allowed(path: &str, exceptions: &[ParsedException]) -> bool {
    exceptions.iter().any(|exception| {
        exception.scopes.iter().any(|scope| match scope {
            ExceptionScope::ModulePattern(pattern) => pattern_match(pattern.as_str(), path),
            ExceptionScope::Dependency(_) => false,
        })
    })
}

fn evaluate_guard(
    manifests: &[ManifestInput],
    module_paths: &[String],
    exception_docs: &[ExceptionDocumentInput],
) -> PolicyGuardReport {
    let mut events = Vec::new();
    let mut violations = Vec::new();
    let mut next_id = 1usize;
    let exceptions = parse_exception_docs(exception_docs);

    for manifest in manifests {
        for dep in dependency_names(manifest.content.as_str()) {
            if !is_forbidden_tui_dependency(dep.as_str()) {
                continue;
            }
            if dependency_exception_allowed(dep.as_str(), &exceptions) {
                events.push(PolicyGuardEvent {
                    trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                    decision_id: format!("decision-{next_id:04}"),
                    policy_id: POLICY_ID.to_string(),
                    component: COMPONENT.to_string(),
                    event: "dependency_scan".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                    subject: dep,
                    detail: format!(
                        "forbidden dependency allowed via approved ADR exception ({})",
                        manifest.path
                    ),
                });
                next_id += 1;
                continue;
            }

            let detail = format!(
                "forbidden local TUI framework dependency found in {}",
                manifest.path
            );
            events.push(PolicyGuardEvent {
                trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                decision_id: format!("decision-{next_id:04}"),
                policy_id: POLICY_ID.to_string(),
                component: COMPONENT.to_string(),
                event: "dependency_scan".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-TUI-DEPENDENCY-FORBIDDEN".to_string()),
                subject: dep.clone(),
                detail: detail.clone(),
            });
            next_id += 1;

            violations.push(PolicyViolation {
                error_code: "FE-TUI-DEPENDENCY-FORBIDDEN",
                subject: dep,
                detail,
            });
        }
    }

    for path in module_paths {
        if !is_blocked_local_tui_module(path) {
            continue;
        }
        if module_exception_allowed(path.as_str(), &exceptions) {
            events.push(PolicyGuardEvent {
                trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
                decision_id: format!("decision-{next_id:04}"),
                policy_id: POLICY_ID.to_string(),
                component: COMPONENT.to_string(),
                event: "module_scan".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                subject: path.clone(),
                detail: "blocked module pattern allowed via approved ADR exception".to_string(),
            });
            next_id += 1;
            continue;
        }

        let detail = "blocked local interactive TUI module path detected".to_string();
        events.push(PolicyGuardEvent {
            trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
            decision_id: format!("decision-{next_id:04}"),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "module_scan".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("FE-TUI-MODULE-FORBIDDEN".to_string()),
            subject: path.clone(),
            detail: detail.clone(),
        });
        next_id += 1;

        violations.push(PolicyViolation {
            error_code: "FE-TUI-MODULE-FORBIDDEN",
            subject: path.clone(),
            detail,
        });
    }

    events.push(PolicyGuardEvent {
        trace_id: format!("{TRACE_PREFIX}-{next_id:04}"),
        decision_id: format!("decision-{next_id:04}"),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "guard_summary".to_string(),
        outcome: if violations.is_empty() {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if violations.is_empty() {
            None
        } else {
            Some("FE-TUI-GUARD-BLOCKED".to_string())
        },
        subject: "frankenengine-repo".to_string(),
        detail: format!("violations={}", violations.len()),
    });

    PolicyGuardReport { events, violations }
}

fn collect_rs_files(root: &Path, out: &mut Vec<String>) {
    if !root.exists() {
        return;
    }
    let entries =
        fs::read_dir(root).unwrap_or_else(|err| panic!("failed to read {}: {err}", root.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|err| panic!("failed to read dir entry in {}: {err}", root.display()));
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(path.as_path(), out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let relative = path
                .strip_prefix(repo_root())
                .unwrap_or_else(|_| panic!("path must be under repo root: {}", path.display()))
                .to_string_lossy()
                .replace('\\', "/");
            out.push(relative);
        }
    }
}

fn repo_manifests() -> Vec<ManifestInput> {
    let root = repo_root();
    let manifest_paths = [
        root.join("Cargo.toml"),
        root.join("crates/franken-engine/Cargo.toml"),
        root.join("crates/franken-extension-host/Cargo.toml"),
    ];

    let mut manifests = Vec::new();
    for path in manifest_paths {
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let relative = path
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("path must be under repo root: {}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        manifests.push(ManifestInput {
            path: relative,
            content,
        });
    }
    manifests
}

fn repo_exception_docs() -> Vec<ExceptionDocumentInput> {
    let root = repo_root();
    let exceptions_root = root.join("docs/adr/exceptions");
    if !exceptions_root.exists() {
        return Vec::new();
    }

    let mut docs = Vec::new();
    let entries = fs::read_dir(&exceptions_root)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", exceptions_root.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!(
                "failed to read dir entry in {}: {err}",
                exceptions_root.display()
            )
        });
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let relative = path
            .strip_prefix(&root)
            .unwrap_or_else(|_| panic!("path must be under repo root: {}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        docs.push(ExceptionDocumentInput {
            path: relative,
            content,
        });
    }
    docs
}

#[test]
fn ratatui_dependency_is_blocked_without_approved_adr_exception() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
ratatui = "0.29"
"#
        .to_string(),
    }];

    let report = evaluate_guard(&manifests, &[], &[]);

    assert_eq!(report.violations.len(), 1);
    assert_eq!(
        report.violations[0].error_code,
        "FE-TUI-DEPENDENCY-FORBIDDEN"
    );
    assert!(report.events.iter().any(|event| {
        event.event == "dependency_scan"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("FE-TUI-DEPENDENCY-FORBIDDEN")
    }));
}

#[test]
fn frankentui_dependency_is_allowed() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
frankentui = "0.1"
"#
        .to_string(),
    }];

    let report = evaluate_guard(&manifests, &[], &[]);

    assert!(report.violations.is_empty());
    assert!(report.events.iter().any(|event| {
        event.event == "guard_summary"
            && event.outcome == "pass"
            && event.error_code.is_none()
            && event.detail == "violations=0"
    }));
}

#[test]
fn approved_adr_exception_can_bypass_forbidden_dependency() {
    let manifests = vec![ManifestInput {
        path: "crates/franken-engine/Cargo.toml".to_string(),
        content: r#"
[dependencies]
ratatui = "0.29"
"#
        .to_string(),
    }];
    let exception_docs = vec![ExceptionDocumentInput {
        path: "docs/adr/exceptions/ADR-EXCEPTION-TUI-0001.md".to_string(),
        content: r#"
# ADR Exception
Status: Approved
Scope: dependency:ratatui
"#
        .to_string(),
    }];

    let report = evaluate_guard(&manifests, &[], &exception_docs);

    assert!(report.violations.is_empty());
    assert!(report.events.iter().any(|event| {
        event.event == "dependency_scan"
            && event.outcome == "pass"
            && event.error_code.is_none()
            && event.subject == "ratatui"
    }));
}

#[test]
fn module_pattern_violation_is_blocked_without_exception() {
    let report = evaluate_guard(
        &[],
        &[String::from(
            "crates/franken-engine/src/local_tui_dashboard.rs",
        )],
        &[],
    );

    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].error_code, "FE-TUI-MODULE-FORBIDDEN");
    assert!(report.events.iter().any(|event| {
        event.event == "module_scan"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("FE-TUI-MODULE-FORBIDDEN")
    }));
}

#[test]
fn repository_tui_policy_guard_passes() {
    let manifests = repo_manifests();

    let mut module_paths = Vec::new();
    collect_rs_files(repo_root().join("crates").as_path(), &mut module_paths);
    module_paths.sort();

    let exceptions = repo_exception_docs();
    let report = evaluate_guard(&manifests, &module_paths, &exceptions);

    assert!(
        report.violations.is_empty(),
        "TUI policy guard violations detected:\n{}",
        report.as_jsonl()
    );
    assert!(report.events.iter().any(|event| {
        event.event == "guard_summary"
            && event.outcome == "pass"
            && event.error_code.is_none()
            && event.policy_id == POLICY_ID
            && event.component == COMPONENT
    }));
}
