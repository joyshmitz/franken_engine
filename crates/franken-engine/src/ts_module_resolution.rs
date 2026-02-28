#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

const COMPONENT: &str = "ts_module_resolver";
const SCHEMA_VERSION: &str = "rgc.ts-module-resolution.parity.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TsModuleResolutionMode {
    Node16,
    #[default]
    NodeNext,
    Bundler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsRequestStyle {
    Import,
    Require,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResolutionContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl TsResolutionContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsModuleRequest {
    pub specifier: String,
    pub referrer: Option<String>,
    pub style: TsRequestStyle,
}

impl TsModuleRequest {
    pub fn new(specifier: impl Into<String>, style: TsRequestStyle) -> Self {
        Self {
            specifier: specifier.into(),
            referrer: None,
            style,
        }
    }

    pub fn with_referrer(mut self, referrer: impl Into<String>) -> Self {
        self.referrer = Some(referrer.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsModuleResolutionConfig {
    pub project_root: String,
    pub base_url: String,
    pub mode: TsModuleResolutionMode,
    pub paths: BTreeMap<String, Vec<String>>,
    pub import_conditions: Vec<String>,
    pub require_conditions: Vec<String>,
    pub import_extensions: Vec<String>,
    pub require_extensions: Vec<String>,
}

impl Default for TsModuleResolutionConfig {
    fn default() -> Self {
        Self {
            project_root: "/".to_string(),
            base_url: ".".to_string(),
            mode: TsModuleResolutionMode::NodeNext,
            paths: BTreeMap::new(),
            import_conditions: vec![
                "import".to_string(),
                "types".to_string(),
                "default".to_string(),
            ],
            require_conditions: vec!["require".to_string(), "default".to_string()],
            import_extensions: vec![
                ".ts".to_string(),
                ".tsx".to_string(),
                ".mts".to_string(),
                ".js".to_string(),
                ".mjs".to_string(),
                "/index.ts".to_string(),
                "/index.tsx".to_string(),
                "/index.js".to_string(),
                "/index.mjs".to_string(),
            ],
            require_extensions: vec![
                ".cts".to_string(),
                ".cjs".to_string(),
                ".ts".to_string(),
                ".js".to_string(),
                "/index.cts".to_string(),
                "/index.cjs".to_string(),
                "/index.ts".to_string(),
                "/index.js".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TsPackageExportTarget {
    pub condition_targets: BTreeMap<String, String>,
    pub fallback_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsPackageDefinition {
    pub package_name: String,
    pub package_root: String,
    pub exports: BTreeMap<String, TsPackageExportTarget>,
}

impl TsPackageDefinition {
    pub fn new(package_name: impl Into<String>, package_root: impl Into<String>) -> Self {
        Self {
            package_name: package_name.into(),
            package_root: package_root.into(),
            exports: BTreeMap::new(),
        }
    }

    pub fn with_export(
        mut self,
        export_key: impl Into<String>,
        export_target: TsPackageExportTarget,
    ) -> Self {
        self.exports.insert(export_key.into(), export_target);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResolutionTraceEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub detail: String,
    pub candidate: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsResolutionErrorCode {
    EmptySpecifier,
    MissingReferrer,
    InvalidReferrer,
    PackageResolutionFailed,
    ModuleNotFound,
}

impl TsResolutionErrorCode {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::EmptySpecifier => "FE-TSRES-0001",
            Self::MissingReferrer => "FE-TSRES-0002",
            Self::InvalidReferrer => "FE-TSRES-0003",
            Self::PackageResolutionFailed => "FE-TSRES-0004",
            Self::ModuleNotFound => "FE-TSRES-0005",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsModuleResolutionError {
    pub code: TsResolutionErrorCode,
    pub message: String,
    pub traces: Vec<TsResolutionTraceEvent>,
}

impl fmt::Display for TsModuleResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.stable_code(), self.message)
    }
}

impl std::error::Error for TsModuleResolutionError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsModuleResolutionOutcome {
    pub request_specifier: String,
    pub resolved_path: String,
    pub style: TsRequestStyle,
    pub package_name: Option<String>,
    pub selected_condition: Option<String>,
    pub traces: Vec<TsResolutionTraceEvent>,
}

impl TsModuleResolutionOutcome {
    pub fn probe_sequence(&self) -> Vec<String> {
        self.traces
            .iter()
            .filter(|event| event.event == "extension_probe")
            .filter_map(|event| event.candidate.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicTsModuleResolver {
    config: TsModuleResolutionConfig,
    files: BTreeSet<String>,
    packages: BTreeMap<String, TsPackageDefinition>,
}

impl DeterministicTsModuleResolver {
    pub fn new(mut config: TsModuleResolutionConfig) -> Self {
        config.project_root = normalize_absolute_path(&config.project_root);
        if config.base_url.trim().is_empty() {
            config.base_url = ".".to_string();
        }

        Self {
            config,
            files: BTreeSet::new(),
            packages: BTreeMap::new(),
        }
    }

    pub fn register_file(&mut self, path: impl AsRef<str>) {
        self.files.insert(self.to_workspace_path(path.as_ref()));
    }

    pub fn register_package(&mut self, mut package: TsPackageDefinition) {
        package.package_root = self.to_workspace_path(&package.package_root);
        self.packages.insert(package.package_name.clone(), package);
    }

    pub fn resolve(
        &self,
        request: &TsModuleRequest,
        context: &TsResolutionContext,
    ) -> Result<TsModuleResolutionOutcome, TsModuleResolutionError> {
        let mut traces = Vec::new();
        let specifier = request.specifier.trim();
        if specifier.is_empty() {
            push_trace(
                &mut traces,
                context,
                "validate_specifier",
                "deny",
                TsResolutionErrorCode::EmptySpecifier.stable_code(),
                "module specifier must not be empty",
                None,
            );
            return Err(TsModuleResolutionError {
                code: TsResolutionErrorCode::EmptySpecifier,
                message: "module specifier must not be empty".to_string(),
                traces,
            });
        }

        let mut candidate_bases = Vec::new();
        if is_relative_specifier(specifier) {
            let Some(referrer) = request.referrer.as_deref() else {
                push_trace(
                    &mut traces,
                    context,
                    "resolve_relative",
                    "deny",
                    TsResolutionErrorCode::MissingReferrer.stable_code(),
                    "relative specifier requires referrer",
                    Some(specifier.to_string()),
                );
                return Err(TsModuleResolutionError {
                    code: TsResolutionErrorCode::MissingReferrer,
                    message: format!("relative specifier '{}' requires referrer", request.specifier),
                    traces,
                });
            };

            let Some(referrer_dir) = resolve_referrer_directory(referrer, &self.config.project_root)
            else {
                push_trace(
                    &mut traces,
                    context,
                    "resolve_relative",
                    "deny",
                    TsResolutionErrorCode::InvalidReferrer.stable_code(),
                    format!("invalid referrer '{}'", referrer),
                    Some(referrer.to_string()),
                );
                return Err(TsModuleResolutionError {
                    code: TsResolutionErrorCode::InvalidReferrer,
                    message: format!("invalid referrer '{}'", referrer),
                    traces,
                });
            };

            let base = normalize_absolute_path(&join_paths(&referrer_dir, specifier));
            push_trace(
                &mut traces,
                context,
                "relative_base",
                "allow",
                "none",
                "resolved relative base",
                Some(base.clone()),
            );
            candidate_bases.push(CandidateBase::new(base, "relative"));
        } else if specifier.starts_with('/') {
            let base = normalize_absolute_path(specifier);
            push_trace(
                &mut traces,
                context,
                "absolute_base",
                "allow",
                "none",
                "resolved absolute base",
                Some(base.clone()),
            );
            candidate_bases.push(CandidateBase::new(base, "absolute"));
        } else {
            for alias in self.path_alias_candidates(specifier) {
                push_trace(
                    &mut traces,
                    context,
                    "paths_alias_match",
                    "allow",
                    "none",
                    format!("matched alias '{}'", alias.pattern),
                    Some(alias.path.clone()),
                );
                candidate_bases.push(CandidateBase::new(alias.path, "paths_alias"));
            }

            match self.package_candidate(specifier, request.style) {
                Ok(Some(package_candidate)) => {
                    push_trace(
                        &mut traces,
                        context,
                        "package_condition_selected",
                        "allow",
                        "none",
                        format!(
                            "selected package condition '{}' for '{}'",
                            package_candidate
                                .selected_condition
                                .as_deref()
                                .unwrap_or("fallback"),
                            package_candidate.package_name.as_deref().unwrap_or("<unknown>")
                        ),
                        Some(package_candidate.base.clone()),
                    );
                    candidate_bases.push(package_candidate);
                }
                Ok(None) => {}
                Err(message) => {
                    push_trace(
                        &mut traces,
                        context,
                        "package_resolution",
                        "deny",
                        TsResolutionErrorCode::PackageResolutionFailed.stable_code(),
                        message.clone(),
                        Some(specifier.to_string()),
                    );
                    return Err(TsModuleResolutionError {
                        code: TsResolutionErrorCode::PackageResolutionFailed,
                        message,
                        traces,
                    });
                }
            }

            let fallback_base = normalize_absolute_path(&join_paths(&self.base_url_dir(), specifier));
            push_trace(
                &mut traces,
                context,
                "base_url_fallback",
                "allow",
                "none",
                "added baseUrl fallback candidate",
                Some(fallback_base.clone()),
            );
            candidate_bases.push(CandidateBase::new(fallback_base, "base_url_fallback"));
        }

        let probe_suffixes = effective_probe_suffixes(self.probe_suffixes_for(request.style));
        let mut seen = BTreeSet::new();
        for candidate_base in candidate_bases {
            for candidate in probe_candidate_paths(&candidate_base.base, &probe_suffixes) {
                if !seen.insert(candidate.clone()) {
                    continue;
                }

                if self.files.contains(&candidate) {
                    push_trace(
                        &mut traces,
                        context,
                        "extension_probe",
                        "allow",
                        "none",
                        format!("resolved from {}", candidate_base.source),
                        Some(candidate.clone()),
                    );
                    return Ok(TsModuleResolutionOutcome {
                        request_specifier: request.specifier.clone(),
                        resolved_path: candidate,
                        style: request.style,
                        package_name: candidate_base.package_name,
                        selected_condition: candidate_base.selected_condition,
                        traces,
                    });
                }

                push_trace(
                    &mut traces,
                    context,
                    "extension_probe",
                    "miss",
                    "none",
                    format!("candidate missing from {}", candidate_base.source),
                    Some(candidate),
                );
            }
        }

        push_trace(
            &mut traces,
            context,
            "module_not_found",
            "deny",
            TsResolutionErrorCode::ModuleNotFound.stable_code(),
            format!("unable to resolve '{}'", request.specifier),
            Some(request.specifier.clone()),
        );
        Err(TsModuleResolutionError {
            code: TsResolutionErrorCode::ModuleNotFound,
            message: format!("unable to resolve '{}'", request.specifier),
            traces,
        })
    }

    fn path_alias_candidates(&self, specifier: &str) -> Vec<PathAliasCandidate> {
        let mut matches = Vec::new();
        for (pattern, replacements) in &self.config.paths {
            let Some(capture) = capture_single_wildcard(pattern, specifier) else {
                continue;
            };

            for (replacement_index, replacement) in replacements.iter().enumerate() {
                let rendered = apply_wildcard_capture(replacement, &capture);
                let path = normalize_absolute_path(&join_paths(&self.base_url_dir(), &rendered));
                matches.push(PathAliasCandidate {
                    pattern: pattern.clone(),
                    score: pattern_specificity(pattern),
                    replacement_index,
                    path,
                });
            }
        }

        matches.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then(left.pattern.cmp(&right.pattern))
                .then(left.replacement_index.cmp(&right.replacement_index))
                .then(left.path.cmp(&right.path))
        });
        matches
    }

    fn package_candidate(
        &self,
        specifier: &str,
        style: TsRequestStyle,
    ) -> Result<Option<CandidateBase>, String> {
        let Some((package_name, export_key)) = parse_package_specifier(specifier) else {
            return Ok(None);
        };

        let Some(package) = self.packages.get(&package_name) else {
            return Ok(None);
        };

        let Some((export_target, capture)) = resolve_export_target(&package.exports, &export_key)
        else {
            return Err(format!(
                "package '{}' has no export entry for '{}'",
                package_name, export_key
            ));
        };

        for condition in self.condition_order_for(style) {
            if let Some(path_template) = export_target.condition_targets.get(condition) {
                let rendered = apply_wildcard_capture(path_template, &capture);
                let base = normalize_absolute_path(&join_paths(&package.package_root, &rendered));
                return Ok(Some(
                    CandidateBase::new(base, "package_exports")
                        .with_package(package_name.clone(), condition.clone()),
                ));
            }
        }

        if let Some(fallback_template) = export_target.fallback_target.as_deref() {
            let rendered = apply_wildcard_capture(fallback_template, &capture);
            let base = normalize_absolute_path(&join_paths(&package.package_root, &rendered));
            return Ok(Some(
                CandidateBase::new(base, "package_exports")
                    .with_package(package_name.clone(), "fallback".to_string()),
            ));
        }

        Err(format!(
            "package '{}' export '{}' has no matching condition target",
            package_name, export_key
        ))
    }

    fn condition_order_for(&self, style: TsRequestStyle) -> &[String] {
        match style {
            TsRequestStyle::Import => &self.config.import_conditions,
            TsRequestStyle::Require => &self.config.require_conditions,
        }
    }

    fn probe_suffixes_for(&self, style: TsRequestStyle) -> &[String] {
        match style {
            TsRequestStyle::Import => &self.config.import_extensions,
            TsRequestStyle::Require => &self.config.require_extensions,
        }
    }

    fn base_url_dir(&self) -> String {
        if self.config.base_url == "." {
            return self.config.project_root.clone();
        }

        if self.config.base_url.starts_with('/') {
            return normalize_absolute_path(&self.config.base_url);
        }

        normalize_absolute_path(&join_paths(&self.config.project_root, &self.config.base_url))
    }

    fn to_workspace_path(&self, value: &str) -> String {
        if value.starts_with('/') {
            normalize_absolute_path(value)
        } else {
            normalize_absolute_path(&join_paths(&self.config.project_root, value))
        }
    }
}

#[derive(Debug, Clone)]
struct CandidateBase {
    base: String,
    source: String,
    package_name: Option<String>,
    selected_condition: Option<String>,
}

impl CandidateBase {
    fn new(base: String, source: impl Into<String>) -> Self {
        Self {
            base,
            source: source.into(),
            package_name: None,
            selected_condition: None,
        }
    }

    fn with_package(mut self, package_name: impl Into<String>, condition: String) -> Self {
        self.package_name = Some(package_name.into());
        self.selected_condition = Some(condition);
        self
    }
}

#[derive(Debug, Clone)]
struct PathAliasCandidate {
    pattern: String,
    score: usize,
    replacement_index: usize,
    path: String,
}

fn parse_package_specifier(specifier: &str) -> Option<(String, String)> {
    if specifier.starts_with('.') || specifier.starts_with('/') {
        return None;
    }

    let mut segments = specifier.split('/');
    let first = segments.next()?;
    if first.is_empty() {
        return None;
    }

    let (package_name, tail) = if first.starts_with('@') {
        let second = segments.next()?;
        (
            format!("{first}/{second}"),
            segments.collect::<Vec<_>>().join("/"),
        )
    } else {
        (first.to_string(), segments.collect::<Vec<_>>().join("/"))
    };

    let export_key = if tail.is_empty() {
        ".".to_string()
    } else {
        format!("./{tail}")
    };

    Some((package_name, export_key))
}

fn resolve_export_target<'a>(
    exports: &'a BTreeMap<String, TsPackageExportTarget>,
    export_key: &str,
) -> Option<(&'a TsPackageExportTarget, String)> {
    if let Some(exact) = exports.get(export_key) {
        return Some((exact, String::new()));
    }

    let mut wildcard_matches = Vec::new();
    for (pattern, target) in exports {
        let Some(capture) = capture_single_wildcard(pattern, export_key) else {
            continue;
        };
        wildcard_matches.push((pattern_specificity(pattern), pattern, target, capture));
    }

    wildcard_matches.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(right.1)));
    wildcard_matches
        .into_iter()
        .next()
        .map(|(_, _, target, capture)| (target, capture))
}

fn resolve_referrer_directory(referrer: &str, project_root: &str) -> Option<String> {
    if referrer.trim().is_empty()
        || referrer.starts_with("builtin:")
        || referrer.starts_with("external:")
    {
        return None;
    }

    let absolute = if referrer.starts_with('/') {
        normalize_absolute_path(referrer)
    } else {
        normalize_absolute_path(&join_paths(project_root, referrer))
    };
    Some(parent_dir(&absolute))
}

#[cfg(test)]
fn referrer_directory(referrer: &str, project_root: &str) -> Option<String> {
    resolve_referrer_directory(referrer, project_root)
}

fn effective_probe_suffixes(configured: &[String]) -> Vec<String> {
    if configured.is_empty() {
        return vec![
            ".ts".to_string(),
            ".js".to_string(),
            "/index.ts".to_string(),
            "/index.js".to_string(),
        ];
    }
    configured.to_vec()
}

#[cfg(test)]
fn probe_extensions(configured: &[String]) -> Vec<String> {
    effective_probe_suffixes(configured)
}

fn probe_candidate_paths(base: &str, suffixes: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();

    let mut push = |path: String| {
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    };

    push(base.to_string());
    for suffix in suffixes {
        push(format!("{base}{suffix}"));
    }

    paths
}

#[cfg(test)]
fn probe_candidates(base: &str, extensions: &[String]) -> Vec<String> {
    probe_candidate_paths(base, extensions)
}

fn push_trace(
    traces: &mut Vec<TsResolutionTraceEvent>,
    context: &TsResolutionContext,
    event: &str,
    outcome: &str,
    error_code: &str,
    detail: impl Into<String>,
    candidate: Option<String>,
) {
    traces.push(TsResolutionTraceEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.to_string(),
        detail: detail.into(),
        candidate,
    });
}

fn is_relative_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../")
}

#[cfg(test)]
fn is_relative(specifier: &str) -> bool {
    is_relative_specifier(specifier)
}

fn capture_single_wildcard(pattern: &str, value: &str) -> Option<String> {
    let wildcard_index = pattern.find('*')?;
    if pattern[wildcard_index + 1..].contains('*') {
        return None;
    }

    let prefix = &pattern[..wildcard_index];
    let suffix = &pattern[wildcard_index + 1..];
    if !value.starts_with(prefix) || !value.ends_with(suffix) {
        return None;
    }

    let capture_start = prefix.len();
    let capture_end = value.len().checked_sub(suffix.len())?;
    if capture_start > capture_end {
        return None;
    }

    Some(value[capture_start..capture_end].to_string())
}

#[cfg(test)]
fn capture_wildcard(pattern: &str, value: &str) -> Option<String> {
    capture_single_wildcard(pattern, value)
}

fn apply_wildcard_capture(template: &str, capture: &str) -> String {
    match template.find('*') {
        Some(index) => {
            let mut output = String::new();
            output.push_str(&template[..index]);
            output.push_str(capture);
            output.push_str(&template[index + 1..]);
            output
        }
        None => template.to_string(),
    }
}

#[cfg(test)]
fn apply_wildcard(template: &str, capture: &str) -> String {
    apply_wildcard_capture(template, capture)
}

fn pattern_specificity(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

fn join_paths(base: &str, child: &str) -> String {
    if child.starts_with('/') {
        return child.to_string();
    }

    if base.ends_with('/') {
        format!("{base}{child}")
    } else {
        format!("{base}/{child}")
    }
}

fn normalize_absolute_path(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut segments = Vec::new();

    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if !segments.is_empty() {
                    segments.pop();
                }
            }
            _ => segments.push(segment),
        }
    }

    if segments.is_empty() {
        if is_absolute {
            "/".to_string()
        } else {
            ".".to_string()
        }
    } else if is_absolute {
        format!("/{}", segments.join("/"))
    } else {
        segments.join("/")
    }
}

fn parent_dir(path: &str) -> String {
    let normalized = normalize_absolute_path(path);
    if normalized == "/" {
        return normalized;
    }

    match normalized.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => normalized[..index].to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsResolutionDriftClass {
    NoDrift,
    CandidateOrderMismatch,
    MissingTarget,
    ExtraTarget,
    FullMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResolutionDriftReport {
    pub drift_detected: bool,
    pub class: TsResolutionDriftClass,
    pub reference_candidates: Vec<String>,
    pub observed_candidates: Vec<String>,
    pub remediation: String,
}

pub fn classify_resolution_drift(
    reference_candidates: &[String],
    observed_candidates: &[String],
) -> TsResolutionDriftReport {
    let drift_class = if reference_candidates == observed_candidates {
        TsResolutionDriftClass::NoDrift
    } else {
        let reference_set: BTreeSet<&str> = reference_candidates.iter().map(String::as_str).collect();
        let observed_set: BTreeSet<&str> = observed_candidates.iter().map(String::as_str).collect();

        if reference_set == observed_set && reference_candidates.len() == observed_candidates.len() {
            TsResolutionDriftClass::CandidateOrderMismatch
        } else if observed_set.is_subset(&reference_set) {
            TsResolutionDriftClass::MissingTarget
        } else if reference_set.is_subset(&observed_set) {
            TsResolutionDriftClass::ExtraTarget
        } else {
            TsResolutionDriftClass::FullMismatch
        }
    };

    let remediation = match drift_class {
        TsResolutionDriftClass::NoDrift => {
            "No action required; parity with reference resolver maintained."
        }
        TsResolutionDriftClass::CandidateOrderMismatch => {
            "Align alias precedence and extension probe ordering with reference toolchain."
        }
        TsResolutionDriftClass::MissingTarget => {
            "Add missing alias/package targets or extension probes required by reference behavior."
        }
        TsResolutionDriftClass::ExtraTarget => {
            "Remove permissive fallback probes that introduce non-reference candidates."
        }
        TsResolutionDriftClass::FullMismatch => {
            "Reconcile paths/baseUrl/package conditions configuration and rerun parity traces."
        }
    }
    .to_string();

    TsResolutionDriftReport {
        drift_detected: drift_class != TsResolutionDriftClass::NoDrift,
        class: drift_class,
        reference_candidates: reference_candidates.to_vec(),
        observed_candidates: observed_candidates.to_vec(),
        remediation,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResolutionArtifactPaths {
    pub run_manifest: String,
    pub events: String,
    pub commands: String,
    pub ts_resolution_trace: String,
    pub drift_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResolutionRunManifest {
    pub schema_version: String,
    pub scenario_id: String,
    pub generated_at_utc: String,
    pub trace_count: usize,
    pub drift_class: TsResolutionDriftClass,
    pub artifact_paths: TsResolutionArtifactPaths,
}

#[derive(Debug, Clone, Serialize)]
struct StableTraceRecord<'a> {
    trace_id: &'a str,
    decision_id: &'a str,
    policy_id: &'a str,
    component: &'a str,
    event: &'a str,
    outcome: &'a str,
    error_code: &'a str,
}

pub fn write_ts_resolution_artifacts(
    output_dir: &Path,
    scenario_id: &str,
    generated_at_utc: &str,
    commands: &[String],
    traces: &[TsResolutionTraceEvent],
    drift_report: &TsResolutionDriftReport,
) -> io::Result<TsResolutionRunManifest> {
    fs::create_dir_all(output_dir)?;

    let artifact_paths = TsResolutionArtifactPaths {
        run_manifest: "run_manifest.json".to_string(),
        events: "events.jsonl".to_string(),
        commands: "commands.txt".to_string(),
        ts_resolution_trace: "ts_resolution_trace.jsonl".to_string(),
        drift_report: "drift_report.json".to_string(),
    };

    let mut commands_file = File::create(output_dir.join(&artifact_paths.commands))?;
    for command in commands {
        writeln!(commands_file, "{command}")?;
    }

    let mut events_file = File::create(output_dir.join(&artifact_paths.events))?;
    for trace in traces {
        let stable = StableTraceRecord {
            trace_id: &trace.trace_id,
            decision_id: &trace.decision_id,
            policy_id: &trace.policy_id,
            component: &trace.component,
            event: &trace.event,
            outcome: &trace.outcome,
            error_code: &trace.error_code,
        };
        let line = serde_json::to_string(&stable)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        writeln!(events_file, "{line}")?;
    }

    let mut trace_file = File::create(output_dir.join(&artifact_paths.ts_resolution_trace))?;
    for trace in traces {
        let line = serde_json::to_string(trace)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        writeln!(trace_file, "{line}")?;
    }

    let drift_payload = serde_json::to_vec_pretty(drift_report)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    fs::write(output_dir.join(&artifact_paths.drift_report), drift_payload)?;

    let manifest = TsResolutionRunManifest {
        schema_version: SCHEMA_VERSION.to_string(),
        scenario_id: scenario_id.to_string(),
        generated_at_utc: generated_at_utc.to_string(),
        trace_count: traces.len(),
        drift_class: drift_report.class,
        artifact_paths,
    };

    let manifest_payload = serde_json::to_vec_pretty(&manifest)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    fs::write(
        output_dir.join(&manifest.artifact_paths.run_manifest),
        manifest_payload,
    )?;

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> TsResolutionContext {
        TsResolutionContext::new("trace-test", "decision-test", "policy-test")
    }

    fn default_resolver() -> DeterministicTsModuleResolver {
        DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
            project_root: "/project".to_string(),
            ..Default::default()
        })
    }

    fn import_request(specifier: &str) -> TsModuleRequest {
        TsModuleRequest::new(specifier, TsRequestStyle::Import)
    }

    fn require_request(specifier: &str) -> TsModuleRequest {
        TsModuleRequest::new(specifier, TsRequestStyle::Require)
    }

    // Section 1: Type Construction and Serde

    #[test]
    fn resolution_mode_default_is_node_next() {
        assert_eq!(
            TsModuleResolutionMode::default(),
            TsModuleResolutionMode::NodeNext
        );
    }

    #[test]
    fn resolution_mode_serde_roundtrip() {
        for mode in [
            TsModuleResolutionMode::Node16,
            TsModuleResolutionMode::NodeNext,
            TsModuleResolutionMode::Bundler,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: TsModuleResolutionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn request_style_serde_roundtrip() {
        for style in [TsRequestStyle::Import, TsRequestStyle::Require] {
            let json = serde_json::to_string(&style).unwrap();
            let back: TsRequestStyle = serde_json::from_str(&json).unwrap();
            assert_eq!(style, back);
        }
    }

    #[test]
    fn resolution_context_new() {
        let ctx = TsResolutionContext::new("t", "d", "p");
        assert_eq!(ctx.trace_id, "t");
        assert_eq!(ctx.decision_id, "d");
        assert_eq!(ctx.policy_id, "p");
    }

    #[test]
    fn module_request_new() {
        let req = TsModuleRequest::new("./foo", TsRequestStyle::Import);
        assert_eq!(req.specifier, "./foo");
        assert!(req.referrer.is_none());
        assert_eq!(req.style, TsRequestStyle::Import);
    }

    #[test]
    fn module_request_with_referrer() {
        let req = import_request("./bar").with_referrer("/src/main.ts");
        assert_eq!(req.referrer.as_deref(), Some("/src/main.ts"));
    }

    #[test]
    fn config_default_has_expected_extensions() {
        let config = TsModuleResolutionConfig::default();
        assert!(config.import_extensions.contains(&".ts".to_string()));
        assert!(config.import_extensions.contains(&".tsx".to_string()));
        assert!(config.require_extensions.contains(&".cts".to_string()));
    }

    #[test]
    fn config_default_conditions() {
        let config = TsModuleResolutionConfig::default();
        assert!(config.import_conditions.contains(&"import".to_string()));
        assert!(config.require_conditions.contains(&"require".to_string()));
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = TsModuleResolutionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TsModuleResolutionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn package_definition_new() {
        let pkg = TsPackageDefinition::new("react", "/node_modules/react");
        assert_eq!(pkg.package_name, "react");
        assert_eq!(pkg.package_root, "/node_modules/react");
        assert!(pkg.exports.is_empty());
    }

    #[test]
    fn package_definition_with_export() {
        let target = TsPackageExportTarget {
            condition_targets: {
                let mut m = BTreeMap::new();
                m.insert("import".to_string(), "./dist/index.mjs".to_string());
                m
            },
            fallback_target: None,
        };
        let pkg = TsPackageDefinition::new("pkg", "/nm/pkg").with_export(".", target);
        assert!(pkg.exports.contains_key("."));
    }

    #[test]
    fn error_code_stable_codes() {
        assert_eq!(TsResolutionErrorCode::EmptySpecifier.stable_code(), "FE-TSRES-0001");
        assert_eq!(TsResolutionErrorCode::MissingReferrer.stable_code(), "FE-TSRES-0002");
        assert_eq!(TsResolutionErrorCode::InvalidReferrer.stable_code(), "FE-TSRES-0003");
        assert_eq!(TsResolutionErrorCode::PackageResolutionFailed.stable_code(), "FE-TSRES-0004");
        assert_eq!(TsResolutionErrorCode::ModuleNotFound.stable_code(), "FE-TSRES-0005");
    }

    #[test]
    fn error_display() {
        let err = TsModuleResolutionError {
            code: TsResolutionErrorCode::EmptySpecifier,
            message: "specifier empty".to_string(),
            traces: vec![],
        };
        let display = format!("{err}");
        assert!(display.contains("FE-TSRES-0001"));
        assert!(display.contains("specifier empty"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = TsModuleResolutionError {
            code: TsResolutionErrorCode::ModuleNotFound,
            message: "not found".to_string(),
            traces: vec![],
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: TsModuleResolutionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // Section 2: Resolver — File Registration and Resolution

    #[test]
    fn resolver_new_normalizes_root() {
        let resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
            project_root: "/a/b/../c".to_string(),
            ..Default::default()
        });
        let json = serde_json::to_string(&resolver).unwrap();
        assert!(json.contains("/a/c"));
    }

    #[test]
    fn resolver_register_file_relative() {
        let mut resolver = default_resolver();
        resolver.register_file("src/index.ts");
        let req = import_request("./src/index").with_referrer("/project/package.json");
        let result = resolver.resolve(&req, &ctx());
        assert!(result.is_ok());
    }

    #[test]
    fn resolver_register_file_absolute() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/lib/utils.ts");
        let req = import_request("./lib/utils").with_referrer("/project/src/main.ts");
        let result = resolver.resolve(&req, &ctx());
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_relative_specifier() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/src/helper.ts");
        let req = import_request("./helper").with_referrer("/project/src/main.ts");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/src/helper.ts");
        assert_eq!(outcome.style, TsRequestStyle::Import);
    }

    #[test]
    fn resolve_relative_parent_dir() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/utils.ts");
        let req = import_request("../utils").with_referrer("/project/src/deep/file.ts");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/utils.ts");
    }

    #[test]
    fn resolve_absolute_specifier() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/absolute.ts");
        let req = import_request("/project/absolute");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/absolute.ts");
    }

    #[test]
    fn resolve_with_index_extension() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/src/components/index.ts");
        let req = import_request("./components").with_referrer("/project/src/main.ts");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/src/components/index.ts");
    }

    #[test]
    fn resolve_tsx_extension() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/src/App.tsx");
        let req = import_request("./App").with_referrer("/project/src/main.ts");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/src/App.tsx");
    }

    #[test]
    fn resolve_require_uses_cts_extension() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/src/config.cts");
        let req = require_request("./config").with_referrer("/project/src/main.ts");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/src/config.cts");
    }

    // Section 3: Error Cases

    #[test]
    fn empty_specifier_rejects() {
        let resolver = default_resolver();
        let req = import_request("");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
        assert!(!err.traces.is_empty());
    }

    #[test]
    fn whitespace_specifier_rejects() {
        let resolver = default_resolver();
        let req = import_request("   ");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
    }

    #[test]
    fn relative_without_referrer_rejects() {
        let resolver = default_resolver();
        let req = import_request("./foo");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::MissingReferrer);
    }

    #[test]
    fn module_not_found_for_missing_file() {
        let resolver = default_resolver();
        let req = import_request("./nonexistent").with_referrer("/project/src/main.ts");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::ModuleNotFound);
    }

    #[test]
    fn builtin_referrer_rejects() {
        let resolver = default_resolver();
        let req = import_request("./foo").with_referrer("builtin:fs");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
    }

    #[test]
    fn external_referrer_rejects() {
        let resolver = default_resolver();
        let req = import_request("./foo").with_referrer("external:something");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
    }

    // Section 4: Package Exports

    #[test]
    fn resolve_package_import_condition() {
        let mut resolver = default_resolver();
        let mut targets = BTreeMap::new();
        targets.insert("import".to_string(), "./dist/index.mjs".to_string());
        targets.insert("require".to_string(), "./dist/index.cjs".to_string());
        let target = TsPackageExportTarget {
            condition_targets: targets,
            fallback_target: None,
        };
        let pkg = TsPackageDefinition::new("react", "/project/node_modules/react")
            .with_export(".", target);
        resolver.register_package(pkg);
        resolver.register_file("/project/node_modules/react/dist/index.mjs");

        let req = import_request("react");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/node_modules/react/dist/index.mjs");
        assert_eq!(outcome.package_name.as_deref(), Some("react"));
        assert_eq!(outcome.selected_condition.as_deref(), Some("import"));
    }

    #[test]
    fn resolve_package_require_condition() {
        let mut resolver = default_resolver();
        let mut targets = BTreeMap::new();
        targets.insert("import".to_string(), "./dist/index.mjs".to_string());
        targets.insert("require".to_string(), "./dist/index.cjs".to_string());
        let target = TsPackageExportTarget {
            condition_targets: targets,
            fallback_target: None,
        };
        let pkg = TsPackageDefinition::new("lodash", "/project/node_modules/lodash")
            .with_export(".", target);
        resolver.register_package(pkg);
        resolver.register_file("/project/node_modules/lodash/dist/index.cjs");

        let req = require_request("lodash");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/node_modules/lodash/dist/index.cjs");
        assert_eq!(outcome.selected_condition.as_deref(), Some("require"));
    }

    #[test]
    fn resolve_package_fallback_target() {
        let mut resolver = default_resolver();
        let target = TsPackageExportTarget {
            condition_targets: BTreeMap::new(),
            fallback_target: Some("./lib/main.js".to_string()),
        };
        let pkg = TsPackageDefinition::new("fallback-pkg", "/project/node_modules/fallback-pkg")
            .with_export(".", target);
        resolver.register_package(pkg);
        resolver.register_file("/project/node_modules/fallback-pkg/lib/main.js");

        let req = import_request("fallback-pkg");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/node_modules/fallback-pkg/lib/main.js");
    }

    #[test]
    fn resolve_scoped_package() {
        let mut resolver = default_resolver();
        let mut targets = BTreeMap::new();
        targets.insert("import".to_string(), "./index.mjs".to_string());
        let target = TsPackageExportTarget {
            condition_targets: targets,
            fallback_target: None,
        };
        let pkg = TsPackageDefinition::new("@scope/pkg", "/project/node_modules/@scope/pkg")
            .with_export(".", target);
        resolver.register_package(pkg);
        resolver.register_file("/project/node_modules/@scope/pkg/index.mjs");

        let req = import_request("@scope/pkg");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.package_name.as_deref(), Some("@scope/pkg"));
    }

    #[test]
    fn resolve_package_subpath() {
        let mut resolver = default_resolver();
        let mut targets = BTreeMap::new();
        targets.insert("import".to_string(), "./utils.mjs".to_string());
        let target = TsPackageExportTarget {
            condition_targets: targets,
            fallback_target: None,
        };
        let pkg = TsPackageDefinition::new("toolkit", "/project/node_modules/toolkit")
            .with_export("./utils", target);
        resolver.register_package(pkg);
        resolver.register_file("/project/node_modules/toolkit/utils.mjs");

        let req = import_request("toolkit/utils");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/node_modules/toolkit/utils.mjs");
    }

    #[test]
    fn package_no_matching_export_rejects() {
        let mut resolver = default_resolver();
        let target = TsPackageExportTarget {
            condition_targets: BTreeMap::new(),
            fallback_target: None,
        };
        let pkg = TsPackageDefinition::new("strict-pkg", "/project/node_modules/strict-pkg")
            .with_export(".", target);
        resolver.register_package(pkg);

        let req = import_request("strict-pkg");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::PackageResolutionFailed);
    }

    // Section 5: Path Aliasing

    #[test]
    fn path_alias_simple_wildcard() {
        let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
            project_root: "/project".to_string(),
            paths: {
                let mut m = BTreeMap::new();
                m.insert("@utils/*".to_string(), vec!["src/utils/*".to_string()]);
                m
            },
            ..Default::default()
        });
        resolver.register_file("/project/src/utils/math.ts");

        let req = import_request("@utils/math");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/src/utils/math.ts");
    }

    #[test]
    fn path_alias_multiple_replacements() {
        let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
            project_root: "/project".to_string(),
            paths: {
                let mut m = BTreeMap::new();
                m.insert(
                    "@lib/*".to_string(),
                    vec!["src/lib/*".to_string(), "lib/*".to_string()],
                );
                m
            },
            ..Default::default()
        });
        resolver.register_file("/project/lib/foo.ts");

        let req = import_request("@lib/foo");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert_eq!(outcome.resolved_path, "/project/lib/foo.ts");
    }

    // Section 6: Trace Events

    #[test]
    fn successful_resolution_has_traces() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/src/found.ts");
        let req = import_request("./src/found").with_referrer("/project/package.json");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        assert!(!outcome.traces.is_empty());
        for trace in &outcome.traces {
            assert_eq!(trace.trace_id, "trace-test");
            assert_eq!(trace.component, "ts_module_resolver");
        }
    }

    #[test]
    fn error_resolution_has_traces() {
        let resolver = default_resolver();
        let req = import_request("");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert!(!err.traces.is_empty());
        let deny_trace = err.traces.iter().find(|t| t.outcome == "deny");
        assert!(deny_trace.is_some());
    }

    #[test]
    fn probe_sequence_from_outcome() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/src/a.tsx");
        let req = import_request("./a").with_referrer("/project/src/main.ts");
        let outcome = resolver.resolve(&req, &ctx()).unwrap();
        let probes = outcome.probe_sequence();
        assert!(!probes.is_empty());
    }

    #[test]
    fn trace_event_serde_roundtrip() {
        let event = TsResolutionTraceEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "ts_module_resolver".to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: "none".to_string(),
            detail: "test detail".to_string(),
            candidate: Some("/a/b.ts".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: TsResolutionTraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // Section 7: Drift Detection

    #[test]
    fn drift_no_drift_when_equal() {
        let report = classify_resolution_drift(
            &["a".to_string(), "b".to_string()],
            &["a".to_string(), "b".to_string()],
        );
        assert!(!report.drift_detected);
        assert_eq!(report.class, TsResolutionDriftClass::NoDrift);
    }

    #[test]
    fn drift_candidate_order_mismatch() {
        let report = classify_resolution_drift(
            &["a".to_string(), "b".to_string()],
            &["b".to_string(), "a".to_string()],
        );
        assert!(report.drift_detected);
        assert_eq!(report.class, TsResolutionDriftClass::CandidateOrderMismatch);
    }

    #[test]
    fn drift_missing_target() {
        let report = classify_resolution_drift(
            &["a".to_string(), "b".to_string(), "c".to_string()],
            &["a".to_string(), "b".to_string()],
        );
        assert!(report.drift_detected);
        assert_eq!(report.class, TsResolutionDriftClass::MissingTarget);
    }

    #[test]
    fn drift_extra_target() {
        let report = classify_resolution_drift(
            &["a".to_string()],
            &["a".to_string(), "b".to_string()],
        );
        assert!(report.drift_detected);
        assert_eq!(report.class, TsResolutionDriftClass::ExtraTarget);
    }

    #[test]
    fn drift_full_mismatch() {
        let report = classify_resolution_drift(
            &["a".to_string(), "b".to_string()],
            &["c".to_string(), "d".to_string()],
        );
        assert!(report.drift_detected);
        assert_eq!(report.class, TsResolutionDriftClass::FullMismatch);
    }

    #[test]
    fn drift_empty_both() {
        let report = classify_resolution_drift(&[], &[]);
        assert!(!report.drift_detected);
        assert_eq!(report.class, TsResolutionDriftClass::NoDrift);
    }

    #[test]
    fn drift_report_serde_roundtrip() {
        let report = classify_resolution_drift(&["a".to_string()], &["b".to_string()]);
        let json = serde_json::to_string(&report).unwrap();
        let back: TsResolutionDriftReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn drift_remediation_messages_not_empty() {
        let real = classify_resolution_drift(&["a".to_string()], &["a".to_string()]);
        assert!(!real.remediation.is_empty());
    }

    // Section 8: Internal Helpers

    #[test]
    fn normalize_path_removes_dots() {
        assert_eq!(normalize_absolute_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_absolute_path("/a/./b"), "/a/b");
        assert_eq!(normalize_absolute_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn normalize_path_empty_segments() {
        assert_eq!(normalize_absolute_path("/a//b"), "/a/b");
    }

    #[test]
    fn normalize_path_root() {
        assert_eq!(normalize_absolute_path("/"), "/");
        assert_eq!(normalize_absolute_path("/."), "/");
    }

    #[test]
    fn normalize_relative_path() {
        assert_eq!(normalize_absolute_path("a/b"), "a/b");
        assert_eq!(normalize_absolute_path("a/../b"), "b");
    }

    #[test]
    fn join_paths_basic() {
        assert_eq!(join_paths("/a", "b"), "/a/b");
        assert_eq!(join_paths("/a/", "b"), "/a/b");
    }

    #[test]
    fn join_paths_absolute_child() {
        assert_eq!(join_paths("/a", "/b"), "/b");
    }

    #[test]
    fn parent_dir_basic() {
        assert_eq!(parent_dir("/a/b/c"), "/a/b");
        assert_eq!(parent_dir("/a"), "/");
        assert_eq!(parent_dir("/"), "/");
    }

    #[test]
    fn is_relative_checks() {
        assert!(is_relative("./foo"));
        assert!(is_relative("../bar"));
        assert!(!is_relative("react"));
        assert!(!is_relative("/absolute"));
    }

    #[test]
    fn capture_wildcard_basic() {
        assert_eq!(capture_wildcard("@utils/*", "@utils/math"), Some("math".to_string()));
    }

    #[test]
    fn capture_wildcard_no_match() {
        assert_eq!(capture_wildcard("@utils/*", "react"), None);
    }

    #[test]
    fn capture_wildcard_double_star_rejects() {
        assert_eq!(capture_wildcard("**/*", "a/b"), None);
    }

    #[test]
    fn apply_wildcard_basic() {
        assert_eq!(apply_wildcard("src/*", "math"), "src/math");
    }

    #[test]
    fn apply_wildcard_no_star() {
        assert_eq!(apply_wildcard("exact", "ignored"), "exact");
    }

    #[test]
    fn pattern_specificity_counts_non_star() {
        assert_eq!(pattern_specificity("@utils/*"), 7);
        assert_eq!(pattern_specificity("*"), 0);
        assert_eq!(pattern_specificity("exact"), 5);
    }

    #[test]
    fn parse_package_specifier_bare() {
        let (name, key) = parse_package_specifier("react").unwrap();
        assert_eq!(name, "react");
        assert_eq!(key, ".");
    }

    #[test]
    fn parse_package_specifier_subpath() {
        let (name, key) = parse_package_specifier("react/jsx-runtime").unwrap();
        assert_eq!(name, "react");
        assert_eq!(key, "./jsx-runtime");
    }

    #[test]
    fn parse_package_specifier_scoped() {
        let (name, key) = parse_package_specifier("@scope/pkg").unwrap();
        assert_eq!(name, "@scope/pkg");
        assert_eq!(key, ".");
    }

    #[test]
    fn parse_package_specifier_scoped_subpath() {
        let (name, key) = parse_package_specifier("@scope/pkg/utils").unwrap();
        assert_eq!(name, "@scope/pkg");
        assert_eq!(key, "./utils");
    }

    #[test]
    fn parse_package_specifier_relative_returns_none() {
        assert!(parse_package_specifier("./local").is_none());
        assert!(parse_package_specifier("../parent").is_none());
        assert!(parse_package_specifier("/absolute").is_none());
    }

    #[test]
    fn probe_extensions_default_fallback() {
        let probes = probe_extensions(&[]);
        assert!(probes.contains(&".ts".to_string()));
        assert!(probes.contains(&".js".to_string()));
    }

    #[test]
    fn probe_extensions_custom() {
        let custom = vec![".mjs".to_string()];
        let probes = probe_extensions(&custom);
        assert_eq!(probes, vec![".mjs".to_string()]);
    }

    #[test]
    fn probe_candidates_deduplicates() {
        let candidates = probe_candidates("/a/b", &[".ts".to_string(), ".ts".to_string()]);
        let unique_count = candidates.len();
        let dedup_set: BTreeSet<_> = candidates.iter().collect();
        assert_eq!(unique_count, dedup_set.len());
    }

    // Section 9: Outcome Serde

    #[test]
    fn outcome_serde_roundtrip() {
        let outcome = TsModuleResolutionOutcome {
            request_specifier: "react".to_string(),
            resolved_path: "/nm/react/index.mjs".to_string(),
            style: TsRequestStyle::Import,
            package_name: Some("react".to_string()),
            selected_condition: Some("import".to_string()),
            traces: vec![],
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: TsModuleResolutionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }

    #[test]
    fn resolver_serde_roundtrip() {
        let mut resolver = default_resolver();
        resolver.register_file("/project/src/a.ts");
        let json = serde_json::to_string(&resolver).unwrap();
        let back: DeterministicTsModuleResolver = serde_json::from_str(&json).unwrap();
        assert_eq!(resolver, back);
    }

    // Section 10: Artifact Writing

    #[test]
    fn run_manifest_serde_roundtrip() {
        let manifest = TsResolutionRunManifest {
            schema_version: SCHEMA_VERSION.to_string(),
            scenario_id: "test".to_string(),
            generated_at_utc: "2026-02-28T00:00:00Z".to_string(),
            trace_count: 5,
            drift_class: TsResolutionDriftClass::NoDrift,
            artifact_paths: TsResolutionArtifactPaths {
                run_manifest: "m.json".to_string(),
                events: "e.jsonl".to_string(),
                commands: "c.txt".to_string(),
                ts_resolution_trace: "t.jsonl".to_string(),
                drift_report: "d.json".to_string(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: TsResolutionRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn write_artifacts_creates_files() {
        let dir = std::env::temp_dir().join("frx_ts_res_test_artifacts");
        let _ = fs::remove_dir_all(&dir);
        let drift = classify_resolution_drift(&["a".to_string()], &["a".to_string()]);
        let traces = vec![TsResolutionTraceEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "test".to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: "none".to_string(),
            detail: "test".to_string(),
            candidate: None,
        }];
        let result = write_ts_resolution_artifacts(
            &dir,
            "scenario-1",
            "2026-01-01T00:00:00Z",
            &["cmd1".to_string()],
            &traces,
            &drift,
        );
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.trace_count, 1);
        assert!(dir.join("run_manifest.json").exists());
        assert!(dir.join("events.jsonl").exists());
        assert!(dir.join("commands.txt").exists());
        assert!(dir.join("drift_report.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    // Section 11: Referrer Edge Cases

    #[test]
    fn empty_referrer_rejects() {
        let resolver = default_resolver();
        let req = import_request("./foo").with_referrer("");
        let err = resolver.resolve(&req, &ctx()).unwrap_err();
        assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
    }

    #[test]
    fn referrer_directory_for_valid_path() {
        let dir = referrer_directory("/project/src/main.ts", "/project");
        assert_eq!(dir, Some("/project/src".to_string()));
    }

    #[test]
    fn referrer_directory_root_file() {
        let dir = referrer_directory("/main.ts", "/");
        assert_eq!(dir, Some("/".to_string()));
    }

    #[test]
    fn drift_class_serde_roundtrip() {
        for class in [
            TsResolutionDriftClass::NoDrift,
            TsResolutionDriftClass::CandidateOrderMismatch,
            TsResolutionDriftClass::MissingTarget,
            TsResolutionDriftClass::ExtraTarget,
            TsResolutionDriftClass::FullMismatch,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: TsResolutionDriftClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }
}
