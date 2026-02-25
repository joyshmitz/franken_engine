//! Compile-time ambient-authority audit gate.
//!
//! Statically detects forbidden direct calls (raw syscalls, unmediated I/O,
//! global state mutation) in security-critical modules.  Ensures no code
//! path bypasses the capability-profile system (bd-1i2).
//!
//! The audit scans source text for forbidden patterns and produces structured
//! findings.  Exemptions are tracked in a machine-readable registry.
//!
//! Plan references: Section 10.11 item 2, 9G.1 (capability-context-first
//! runtime), Top-10 #2 (guardplane), #7 (capability lattice).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ForbiddenCallCategory — categories of forbidden ambient authority
// ---------------------------------------------------------------------------

/// Category of a forbidden ambient-authority call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ForbiddenCallCategory {
    /// Direct filesystem I/O (std::fs).
    FileSystem,
    /// Direct network access (std::net).
    Network,
    /// Process spawning (std::process).
    Process,
    /// Global mutable state (static mut, lazy_static with mutation).
    GlobalMutableState,
    /// Environment variable access (std::env).
    Environment,
    /// Raw pointer operations with external state.
    RawPointerExternalState,
    /// Direct time access (std::time::SystemTime, Instant for non-virtual).
    DirectTime,
}

impl fmt::Display for ForbiddenCallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Network => write!(f, "network"),
            Self::Process => write!(f, "process"),
            Self::GlobalMutableState => write!(f, "global_mutable_state"),
            Self::Environment => write!(f, "environment"),
            Self::RawPointerExternalState => write!(f, "raw_pointer_external_state"),
            Self::DirectTime => write!(f, "direct_time"),
        }
    }
}

// ---------------------------------------------------------------------------
// ForbiddenPattern — a pattern to detect in source
// ---------------------------------------------------------------------------

/// A forbidden call pattern to detect in source text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ForbiddenPattern {
    /// Pattern identifier (e.g., "std_fs_read").
    pub pattern_id: String,
    /// Category of ambient authority.
    pub category: ForbiddenCallCategory,
    /// The text pattern to search for in source.
    pub pattern: String,
    /// Human-readable description of why this is forbidden.
    pub reason: String,
    /// Suggested capability-mediated alternative.
    pub suggested_alternative: String,
}

// ---------------------------------------------------------------------------
// Exemption — an allowed exception to the audit
// ---------------------------------------------------------------------------

/// An exemption allowing a specific forbidden pattern at a specific location.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Exemption {
    /// Exemption identifier.
    pub exemption_id: String,
    /// Module path where the exemption applies.
    pub module_path: String,
    /// Pattern ID being exempted.
    pub pattern_id: String,
    /// Human-readable reason for the exemption.
    pub reason: String,
    /// Witness reference (signed exemption artifact).
    pub witness: String,
    /// Line number (if specific line; 0 for module-wide).
    pub line: usize,
}

// ---------------------------------------------------------------------------
// ExemptionRegistry — tracks all exemptions
// ---------------------------------------------------------------------------

/// Registry of all exemptions, keyed by (module_path, pattern_id).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExemptionRegistry {
    exemptions: Vec<Exemption>,
}

impl ExemptionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            exemptions: Vec::new(),
        }
    }

    /// Add an exemption.
    pub fn add(&mut self, exemption: Exemption) {
        self.exemptions.push(exemption);
    }

    /// Check if a finding is exempted.
    pub fn is_exempted(&self, module_path: &str, pattern_id: &str, line: usize) -> bool {
        self.exemptions.iter().any(|e| {
            e.module_path == module_path
                && e.pattern_id == pattern_id
                && (e.line == 0 || e.line == line)
        })
    }

    /// All exemptions.
    pub fn exemptions(&self) -> &[Exemption] {
        &self.exemptions
    }

    /// Number of exemptions.
    pub fn len(&self) -> usize {
        self.exemptions.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.exemptions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AuditFinding — a detected violation
// ---------------------------------------------------------------------------

/// A detected forbidden-call violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuditFinding {
    /// Module path where the violation was found.
    pub module_path: String,
    /// Forbidden API that was detected.
    pub forbidden_api: String,
    /// Pattern ID that matched.
    pub pattern_id: String,
    /// Category of the violation.
    pub category: ForbiddenCallCategory,
    /// File path containing the violation.
    pub file_path: String,
    /// Line number of the violation.
    pub line: usize,
    /// The source line containing the violation.
    pub source_line: String,
    /// Suggested capability-mediated alternative.
    pub suggested_alternative: String,
    /// Whether this finding is exempted.
    pub exempted: bool,
}

// ---------------------------------------------------------------------------
// AuditConfig — configuration for the audit gate
// ---------------------------------------------------------------------------

/// Configuration for the ambient-authority audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Forbidden patterns to check.
    pub patterns: Vec<ForbiddenPattern>,
    /// Modules to audit (by path prefix).
    pub audited_modules: BTreeSet<String>,
}

impl AuditConfig {
    /// Create a default config with standard forbidden patterns.
    pub fn standard() -> Self {
        let patterns = vec![
            ForbiddenPattern {
                pattern_id: "std_fs".to_string(),
                category: ForbiddenCallCategory::FileSystem,
                pattern: "std::fs::".to_string(),
                reason: "Direct filesystem access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated FileSystemCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "fs_read".to_string(),
                category: ForbiddenCallCategory::FileSystem,
                pattern: "fs::read".to_string(),
                reason: "Direct filesystem read bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated FileSystemCap::read".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "fs_write".to_string(),
                category: ForbiddenCallCategory::FileSystem,
                pattern: "fs::write".to_string(),
                reason: "Direct filesystem write bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated FileSystemCap::write".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "std_net".to_string(),
                category: ForbiddenCallCategory::Network,
                pattern: "std::net::".to_string(),
                reason: "Direct network access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated NetworkCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "tcp_stream".to_string(),
                category: ForbiddenCallCategory::Network,
                pattern: "TcpStream::".to_string(),
                reason: "Direct TCP access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated NetworkCap::connect".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "udp_socket".to_string(),
                category: ForbiddenCallCategory::Network,
                pattern: "UdpSocket::".to_string(),
                reason: "Direct UDP access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated NetworkCap::bind_udp".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "std_process".to_string(),
                category: ForbiddenCallCategory::Process,
                pattern: "std::process::".to_string(),
                reason: "Direct process spawning bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated ProcessCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "command_new".to_string(),
                category: ForbiddenCallCategory::Process,
                pattern: "Command::new".to_string(),
                reason: "Direct command execution bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated ProcessCap::spawn".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "std_env".to_string(),
                category: ForbiddenCallCategory::Environment,
                pattern: "std::env::".to_string(),
                reason: "Direct environment access bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated EnvCap".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "env_var".to_string(),
                category: ForbiddenCallCategory::Environment,
                pattern: "env::var".to_string(),
                reason: "Direct env var read bypasses capability checks".to_string(),
                suggested_alternative: "Use capability-mediated EnvCap::get".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "static_mut".to_string(),
                category: ForbiddenCallCategory::GlobalMutableState,
                pattern: "static mut ".to_string(),
                reason: "Global mutable state violates capability isolation".to_string(),
                suggested_alternative: "Use scoped state via Cx parameter".to_string(),
            },
            ForbiddenPattern {
                pattern_id: "system_time".to_string(),
                category: ForbiddenCallCategory::DirectTime,
                pattern: "SystemTime::now".to_string(),
                reason: "Direct time access breaks deterministic replay".to_string(),
                suggested_alternative: "Use virtual time from Cx::clock()".to_string(),
            },
        ];

        Self {
            patterns,
            audited_modules: BTreeSet::new(),
        }
    }

    /// Add a module to the audit scope.
    pub fn audit_module(&mut self, module_path: impl Into<String>) {
        self.audited_modules.insert(module_path.into());
    }

    /// Add a custom forbidden pattern.
    pub fn add_pattern(&mut self, pattern: ForbiddenPattern) {
        self.patterns.push(pattern);
    }
}

// ---------------------------------------------------------------------------
// AuditResult — complete audit output
// ---------------------------------------------------------------------------

/// Complete result of an ambient-authority audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResult {
    /// All findings (including exempted).
    pub findings: Vec<AuditFinding>,
    /// Number of unexempted violations.
    pub violation_count: usize,
    /// Number of exempted findings.
    pub exemption_count: usize,
    /// Modules audited.
    pub modules_audited: Vec<String>,
    /// Whether the audit passed (zero unexempted violations).
    pub passed: bool,
}

// ---------------------------------------------------------------------------
// SourceAuditor — the audit engine
// ---------------------------------------------------------------------------

/// Source-text auditor for ambient-authority violations.
///
/// Scans source text for forbidden patterns and produces structured findings.
#[derive(Debug)]
pub struct SourceAuditor {
    config: AuditConfig,
    exemptions: ExemptionRegistry,
}

impl SourceAuditor {
    /// Create a new auditor.
    pub fn new(config: AuditConfig, exemptions: ExemptionRegistry) -> Self {
        Self { config, exemptions }
    }

    /// Audit a single source file.
    ///
    /// - `module_path`: logical module path (e.g., "franken_engine::gc").
    /// - `file_path`: filesystem path to the source file.
    /// - `source`: the source text to scan.
    pub fn audit_source(
        &self,
        module_path: &str,
        file_path: &str,
        source: &str,
    ) -> Vec<AuditFinding> {
        let mut findings = Vec::new();

        for (line_num_0, line) in source.lines().enumerate() {
            let line_num = line_num_0 + 1;
            let trimmed = line.trim();

            // Skip comments.
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!")
            {
                continue;
            }

            for pattern in &self.config.patterns {
                if line.contains(&pattern.pattern) {
                    let exempted =
                        self.exemptions
                            .is_exempted(module_path, &pattern.pattern_id, line_num);

                    findings.push(AuditFinding {
                        module_path: module_path.to_string(),
                        forbidden_api: pattern.pattern.clone(),
                        pattern_id: pattern.pattern_id.clone(),
                        category: pattern.category,
                        file_path: file_path.to_string(),
                        line: line_num,
                        source_line: trimmed.to_string(),
                        suggested_alternative: pattern.suggested_alternative.clone(),
                        exempted,
                    });
                }
            }
        }

        // Sort for deterministic output.
        findings.sort();
        findings
    }

    /// Run a full audit across multiple source files.
    ///
    /// `sources` is a map from (module_path, file_path) -> source text.
    pub fn audit_all(&self, sources: &BTreeMap<(String, String), String>) -> AuditResult {
        let mut all_findings = Vec::new();
        let mut modules_audited = BTreeSet::new();

        for ((module_path, file_path), source) in sources {
            modules_audited.insert(module_path.clone());
            let findings = self.audit_source(module_path, file_path, source);
            all_findings.extend(findings);
        }

        let violation_count = all_findings.iter().filter(|f| !f.exempted).count();
        let exemption_count = all_findings.iter().filter(|f| f.exempted).count();

        AuditResult {
            findings: all_findings,
            violation_count,
            exemption_count,
            modules_audited: modules_audited.into_iter().collect(),
            passed: violation_count == 0,
        }
    }

    /// Configuration.
    pub fn config(&self) -> &AuditConfig {
        &self.config
    }

    /// Exemption registry.
    pub fn exemptions(&self) -> &ExemptionRegistry {
        &self.exemptions
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_auditor() -> SourceAuditor {
        SourceAuditor::new(AuditConfig::standard(), ExemptionRegistry::new())
    }

    // -- ForbiddenCallCategory --

    #[test]
    fn category_display() {
        assert_eq!(ForbiddenCallCategory::FileSystem.to_string(), "filesystem");
        assert_eq!(ForbiddenCallCategory::Network.to_string(), "network");
        assert_eq!(ForbiddenCallCategory::Process.to_string(), "process");
        assert_eq!(
            ForbiddenCallCategory::GlobalMutableState.to_string(),
            "global_mutable_state"
        );
        assert_eq!(
            ForbiddenCallCategory::Environment.to_string(),
            "environment"
        );
        assert_eq!(ForbiddenCallCategory::DirectTime.to_string(), "direct_time");
    }

    // -- Clean source passes --

    #[test]
    fn clean_source_produces_no_findings() {
        let auditor = standard_auditor();
        let source = r#"
            fn compute(x: i64) -> i64 {
                x * 2 + 1
            }

            fn process_data(data: &[u8]) -> Vec<u8> {
                data.to_vec()
            }
        "#;

        let findings = auditor.audit_source("engine::compute", "src/compute.rs", source);
        assert!(findings.is_empty());
    }

    // -- Filesystem detection --

    #[test]
    fn detects_std_fs_usage() {
        let auditor = standard_auditor();
        let source = r#"
            use std::fs::read_to_string;
            fn load() { let _ = std::fs::read("file.txt"); }
        "#;

        let findings = auditor.audit_source("engine::loader", "src/loader.rs", source);
        assert!(!findings.is_empty());
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::FileSystem)
        );
    }

    // -- Network detection --

    #[test]
    fn detects_tcp_stream() {
        let auditor = standard_auditor();
        let source = r#"
            let stream = TcpStream::connect("127.0.0.1:8080");
        "#;

        let findings = auditor.audit_source("engine::net", "src/net.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Network)
        );
    }

    // -- Process detection --

    #[test]
    fn detects_command_new() {
        let auditor = standard_auditor();
        let source = r#"
            let output = Command::new("ls").output();
        "#;

        let findings = auditor.audit_source("engine::exec", "src/exec.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Process)
        );
    }

    // -- Environment detection --

    #[test]
    fn detects_env_var() {
        let auditor = standard_auditor();
        let source = r#"
            let val = std::env::var("HOME");
        "#;

        let findings = auditor.audit_source("engine::env", "src/env.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Environment)
        );
    }

    // -- Global mutable state --

    #[test]
    fn detects_static_mut() {
        let auditor = standard_auditor();
        let source = r#"
            static mut COUNTER: u64 = 0;
        "#;

        let findings = auditor.audit_source("engine::state", "src/state.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::GlobalMutableState)
        );
    }

    // -- Time detection --

    #[test]
    fn detects_system_time_now() {
        let auditor = standard_auditor();
        let source = r#"
            let now = SystemTime::now();
        "#;

        let findings = auditor.audit_source("engine::clock", "src/clock.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::DirectTime)
        );
    }

    // -- Comments are skipped --

    #[test]
    fn comments_are_not_flagged() {
        let auditor = standard_auditor();
        let source = r#"
            // This uses std::fs::read for documentation purposes
            /// Example: std::net::TcpStream::connect
            //! Module docs: std::process::Command
            fn clean_function() {}
        "#;

        let findings = auditor.audit_source("engine::docs", "src/docs.rs", source);
        assert!(findings.is_empty());
    }

    // -- Exemptions --

    #[test]
    fn exempted_finding_is_marked() {
        let mut exemptions = ExemptionRegistry::new();
        exemptions.add(Exemption {
            exemption_id: "ex-001".to_string(),
            module_path: "engine::bootstrap".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "Bootstrap requires one-time filesystem access".to_string(),
            witness: "signed:bootstrap-exempt-v1".to_string(),
            line: 0, // module-wide
        });
        exemptions.add(Exemption {
            exemption_id: "ex-001b".to_string(),
            module_path: "engine::bootstrap".to_string(),
            pattern_id: "fs_read".to_string(),
            reason: "Bootstrap requires one-time filesystem access".to_string(),
            witness: "signed:bootstrap-exempt-v1".to_string(),
            line: 0,
        });

        let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
        let source = r#"
            let config = std::fs::read_to_string("config.toml");
        "#;

        let findings = auditor.audit_source("engine::bootstrap", "src/bootstrap.rs", source);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.exempted));
    }

    #[test]
    fn line_specific_exemption() {
        let mut exemptions = ExemptionRegistry::new();
        exemptions.add(Exemption {
            exemption_id: "ex-002".to_string(),
            module_path: "engine::init".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "Init needs config load".to_string(),
            witness: "signed:init-exempt-v1".to_string(),
            line: 2, // only line 2
        });

        let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
        let source =
            "fn init() {\n    let _ = std::fs::read(\"x\");\n    let _ = std::fs::read(\"y\");\n}";

        let findings = auditor.audit_source("engine::init", "src/init.rs", source);
        // Line 2 exempted, line 3 not
        let exempted = findings.iter().filter(|f| f.exempted).count();
        let violations = findings.iter().filter(|f| !f.exempted).count();
        assert_eq!(exempted, 1);
        assert!(violations >= 1);
    }

    // -- Audit result --

    #[test]
    fn audit_all_aggregates() {
        let auditor = standard_auditor();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("engine::clean".to_string(), "src/clean.rs".to_string()),
            "fn ok() { 1 + 1; }".to_string(),
        );
        sources.insert(
            ("engine::dirty".to_string(), "src/dirty.rs".to_string()),
            "let _ = std::fs::read(\"x\");".to_string(),
        );

        let result = auditor.audit_all(&sources);
        assert!(!result.passed);
        assert!(result.violation_count >= 1); // multiple patterns may match
        assert_eq!(result.modules_audited.len(), 2);
    }

    #[test]
    fn clean_audit_passes() {
        let auditor = standard_auditor();
        let mut sources = BTreeMap::new();
        sources.insert(
            ("engine::pure".to_string(), "src/pure.rs".to_string()),
            "fn add(a: i64, b: i64) -> i64 { a + b }".to_string(),
        );

        let result = auditor.audit_all(&sources);
        assert!(result.passed);
        assert_eq!(result.violation_count, 0);
    }

    // -- Finding structure --

    #[test]
    fn finding_contains_actionable_info() {
        let auditor = standard_auditor();
        let source = "let _ = std::fs::read(\"x\");";

        let findings = auditor.audit_source("engine::io", "src/io.rs", source);
        let finding = &findings[0];

        assert_eq!(finding.module_path, "engine::io");
        assert_eq!(finding.file_path, "src/io.rs");
        assert_eq!(finding.line, 1);
        assert!(!finding.suggested_alternative.is_empty());
        assert!(!finding.forbidden_api.is_empty());
    }

    // -- Deterministic output --

    #[test]
    fn deterministic_output() {
        let auditor = standard_auditor();
        let source = r#"
            let _ = std::fs::read("a");
            let _ = TcpStream::connect("b");
            let _ = Command::new("c");
        "#;

        let f1 = auditor.audit_source("m", "f.rs", source);
        let f2 = auditor.audit_source("m", "f.rs", source);
        assert_eq!(f1, f2);
    }

    // -- Custom pattern --

    #[test]
    fn custom_pattern_detected() {
        let mut config = AuditConfig::standard();
        config.add_pattern(ForbiddenPattern {
            pattern_id: "custom_dangerous".to_string(),
            category: ForbiddenCallCategory::RawPointerExternalState,
            pattern: "dangerous_call()".to_string(),
            reason: "Custom dangerous function".to_string(),
            suggested_alternative: "Use safe_call() instead".to_string(),
        });

        let auditor = SourceAuditor::new(config, ExemptionRegistry::new());
        let source = "fn bad() { dangerous_call(); }";

        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.pattern_id == "custom_dangerous"));
    }

    // -- ExemptionRegistry --

    #[test]
    fn empty_registry() {
        let reg = ExemptionRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(!reg.is_exempted("m", "p", 1));
    }

    #[test]
    fn module_wide_exemption() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        assert!(reg.is_exempted("m", "p", 1));
        assert!(reg.is_exempted("m", "p", 99));
        assert!(!reg.is_exempted("m", "other", 1));
    }

    // -- Error display --

    #[test]
    fn category_ordering() {
        assert!(ForbiddenCallCategory::FileSystem < ForbiddenCallCategory::Network);
        assert!(ForbiddenCallCategory::Network < ForbiddenCallCategory::Process);
    }

    // -- Serialization --

    #[test]
    fn category_serialization_round_trip() {
        let categories = vec![
            ForbiddenCallCategory::FileSystem,
            ForbiddenCallCategory::Network,
            ForbiddenCallCategory::Process,
            ForbiddenCallCategory::GlobalMutableState,
            ForbiddenCallCategory::Environment,
            ForbiddenCallCategory::RawPointerExternalState,
            ForbiddenCallCategory::DirectTime,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).expect("serialize");
            let restored: ForbiddenCallCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*cat, restored);
        }
    }

    #[test]
    fn exemption_serialization_round_trip() {
        let ex = Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "test".to_string(),
            witness: "w".to_string(),
            line: 42,
        };
        let json = serde_json::to_string(&ex).expect("serialize");
        let restored: Exemption = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ex, restored);
    }

    #[test]
    fn audit_finding_serialization_round_trip() {
        let finding = AuditFinding {
            module_path: "m".to_string(),
            forbidden_api: "std::fs::read".to_string(),
            pattern_id: "std_fs".to_string(),
            category: ForbiddenCallCategory::FileSystem,
            file_path: "src/m.rs".to_string(),
            line: 10,
            source_line: "let _ = std::fs::read(\"x\");".to_string(),
            suggested_alternative: "Use FileSystemCap".to_string(),
            exempted: false,
        };
        let json = serde_json::to_string(&finding).expect("serialize");
        let restored: AuditFinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(finding, restored);
    }

    #[test]
    fn audit_result_serialization_round_trip() {
        let result = AuditResult {
            findings: vec![],
            violation_count: 0,
            exemption_count: 0,
            modules_audited: vec!["m".to_string()],
            passed: true,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: AuditResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn audit_config_serialization_round_trip() {
        let config = AuditConfig::standard();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: AuditConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display covers RawPointerExternalState
    // -----------------------------------------------------------------------

    #[test]
    fn category_display_raw_pointer() {
        assert_eq!(
            ForbiddenCallCategory::RawPointerExternalState.to_string(),
            "raw_pointer_external_state"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for remaining types
    // -----------------------------------------------------------------------

    #[test]
    fn forbidden_pattern_serde_roundtrip() {
        let pattern = ForbiddenPattern {
            pattern_id: "test_p".to_string(),
            category: ForbiddenCallCategory::Network,
            pattern: "test_pattern".to_string(),
            reason: "test reason".to_string(),
            suggested_alternative: "use safe api".to_string(),
        };
        let json = serde_json::to_string(&pattern).unwrap();
        let restored: ForbiddenPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(pattern, restored);
    }

    #[test]
    fn exemption_registry_serde_roundtrip() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        let json = serde_json::to_string(&reg).unwrap();
        let restored: ExemptionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ExemptionRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn exemption_registry_default_is_empty() {
        let reg = ExemptionRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn exemption_registry_exemptions_accessor() {
        let mut reg = ExemptionRegistry::new();
        reg.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "p".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 5,
        });
        assert_eq!(reg.exemptions().len(), 1);
        assert_eq!(reg.exemptions()[0].exemption_id, "e1");
    }

    // -----------------------------------------------------------------------
    // Enrichment: AuditConfig
    // -----------------------------------------------------------------------

    #[test]
    fn standard_config_has_twelve_patterns() {
        let config = AuditConfig::standard();
        assert_eq!(config.patterns.len(), 12);
        assert!(config.audited_modules.is_empty());
    }

    #[test]
    fn audit_module_adds_to_scope() {
        let mut config = AuditConfig::standard();
        config.audit_module("engine::core");
        config.audit_module("engine::gc");
        assert_eq!(config.audited_modules.len(), 2);
        assert!(config.audited_modules.contains("engine::core"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: additional detection patterns
    // -----------------------------------------------------------------------

    #[test]
    fn detects_udp_socket() {
        let auditor = standard_auditor();
        let source = "let socket = UdpSocket::bind(\"0.0.0.0:0\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(
            findings
                .iter()
                .any(|f| f.category == ForbiddenCallCategory::Network)
        );
    }

    #[test]
    fn detects_std_net() {
        let auditor = standard_auditor();
        let source = "use std::net::TcpListener;";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.pattern_id == "std_net"));
    }

    #[test]
    fn detects_std_process() {
        let auditor = standard_auditor();
        let source = "use std::process::exit;";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.iter().any(|f| f.pattern_id == "std_process"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple findings on same line
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_patterns_on_same_line() {
        let auditor = standard_auditor();
        // Both std::fs:: and fs::read patterns match here.
        let source = "let _ = std::fs::read(\"x\");";
        let findings = auditor.audit_source("m", "f.rs", source);
        assert!(findings.len() >= 2); // std_fs and fs_read both match
    }

    // -----------------------------------------------------------------------
    // Enrichment: audit_all edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn audit_all_empty_sources_passes() {
        let auditor = standard_auditor();
        let sources = BTreeMap::new();
        let result = auditor.audit_all(&sources);
        assert!(result.passed);
        assert_eq!(result.violation_count, 0);
        assert!(result.modules_audited.is_empty());
    }

    #[test]
    fn audit_all_counts_exemptions() {
        let mut exemptions = ExemptionRegistry::new();
        exemptions.add(Exemption {
            exemption_id: "e1".to_string(),
            module_path: "m".to_string(),
            pattern_id: "std_fs".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });
        exemptions.add(Exemption {
            exemption_id: "e2".to_string(),
            module_path: "m".to_string(),
            pattern_id: "fs_read".to_string(),
            reason: "ok".to_string(),
            witness: "w".to_string(),
            line: 0,
        });

        let auditor = SourceAuditor::new(AuditConfig::standard(), exemptions);
        let mut sources = BTreeMap::new();
        sources.insert(
            ("m".to_string(), "f.rs".to_string()),
            "let _ = std::fs::read(\"x\");".to_string(),
        );

        let result = auditor.audit_all(&sources);
        assert!(result.passed);
        assert_eq!(result.violation_count, 0);
        assert!(result.exemption_count >= 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: SourceAuditor accessors
    // -----------------------------------------------------------------------

    #[test]
    fn auditor_accessors() {
        let config = AuditConfig::standard();
        let exemptions = ExemptionRegistry::new();
        let auditor = SourceAuditor::new(config.clone(), exemptions);
        assert_eq!(*auditor.config(), config);
        assert!(auditor.exemptions().is_empty());
    }
}
