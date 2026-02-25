//! Deterministic module resolver trait with policy hooks.
//!
//! This module defines resolution contracts for ES module `import` and
//! CommonJS `require` semantics, with capability-aware policy checks at
//! resolution time.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

pub type ResolutionResult<T> = Result<T, Box<ResolutionError>>;
pub type RegistryResult<T> = Result<T, RegistryError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSyntax {
    EsModule,
    CommonJs,
}

impl ModuleSyntax {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EsModule => "esm",
            Self::CommonJs => "cjs",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStyle {
    Import,
    Require,
}

impl ImportStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Require => "require",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSourceKind {
    BuiltIn,
    Workspace,
    ExternalRegistry,
}

impl ModuleSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "builtin",
            Self::Workspace => "workspace",
            Self::ExternalRegistry => "external_registry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleProvenance {
    pub kind: ModuleSourceKind,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDependency {
    pub specifier: String,
    pub style: ImportStyle,
}

impl ModuleDependency {
    pub fn new(specifier: impl Into<String>, style: ImportStyle) -> Self {
        Self {
            specifier: specifier.into(),
            style,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDefinition {
    pub syntax: ModuleSyntax,
    pub source: String,
    pub dependencies: Vec<ModuleDependency>,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub provenance_origin: String,
}

impl ModuleDefinition {
    pub fn new(syntax: ModuleSyntax, source: impl Into<String>) -> Self {
        Self {
            syntax,
            source: source.into(),
            dependencies: Vec::new(),
            required_capabilities: BTreeSet::new(),
            provenance_origin: "<unspecified>".to_string(),
        }
    }

    pub fn with_dependency(mut self, dependency: ModuleDependency) -> Self {
        self.dependencies.push(dependency);
        self
    }

    pub fn require_capability(mut self, capability: RuntimeCapability) -> Self {
        self.required_capabilities.insert(capability);
        self
    }

    pub fn with_provenance(mut self, provenance_origin: impl Into<String>) -> Self {
        self.provenance_origin = provenance_origin.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub id: String,
    pub syntax: ModuleSyntax,
    pub source: String,
    pub dependencies: Vec<ModuleDependency>,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub provenance: ModuleProvenance,
}

impl ModuleRecord {
    fn from_definition(
        id: String,
        source_kind: ModuleSourceKind,
        definition: ModuleDefinition,
    ) -> Self {
        Self {
            id,
            syntax: definition.syntax,
            source: definition.source,
            dependencies: definition.dependencies,
            required_capabilities: definition.required_capabilities,
            provenance: ModuleProvenance {
                kind: source_kind,
                origin: definition.provenance_origin,
            },
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("id".to_string(), CanonicalValue::String(self.id.clone()));
        map.insert(
            "syntax".to_string(),
            CanonicalValue::String(self.syntax.as_str().to_string()),
        );
        map.insert(
            "source".to_string(),
            CanonicalValue::String(self.source.clone()),
        );

        let dependencies = self
            .dependencies
            .iter()
            .map(|dep| {
                let mut entry = BTreeMap::new();
                entry.insert(
                    "specifier".to_string(),
                    CanonicalValue::String(dep.specifier.clone()),
                );
                entry.insert(
                    "style".to_string(),
                    CanonicalValue::String(dep.style.as_str().to_string()),
                );
                CanonicalValue::Map(entry)
            })
            .collect();
        map.insert(
            "dependencies".to_string(),
            CanonicalValue::Array(dependencies),
        );

        let required_caps = self
            .required_capabilities
            .iter()
            .map(|cap| CanonicalValue::String(cap.to_string()))
            .collect();
        map.insert(
            "required_capabilities".to_string(),
            CanonicalValue::Array(required_caps),
        );

        let mut provenance = BTreeMap::new();
        provenance.insert(
            "kind".to_string(),
            CanonicalValue::String(self.provenance.kind.as_str().to_string()),
        );
        provenance.insert(
            "origin".to_string(),
            CanonicalValue::String(self.provenance.origin.clone()),
        );
        map.insert("provenance".to_string(), CanonicalValue::Map(provenance));

        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRequest {
    pub specifier: String,
    pub referrer: Option<String>,
    pub style: ImportStyle,
}

impl ModuleRequest {
    pub fn new(specifier: impl Into<String>, style: ImportStyle) -> Self {
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
pub struct ResolutionContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl ResolutionContext {
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
pub struct ResolutionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedModule {
    pub request_specifier: String,
    pub canonical_specifier: String,
    pub record: ModuleRecord,
    pub content_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionOutcome {
    pub module: ResolvedModule,
    pub event: ResolutionEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionErrorCode {
    EmptySpecifier,
    InvalidReferrer,
    UnsupportedSpecifier,
    ModuleNotFound,
    PolicyDenied,
}

impl ResolutionErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::EmptySpecifier => "FE-MODRES-0001",
            Self::InvalidReferrer => "FE-MODRES-0002",
            Self::UnsupportedSpecifier => "FE-MODRES-0003",
            Self::ModuleNotFound => "FE-MODRES-0004",
            Self::PolicyDenied => "FE-MODRES-0005",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionError {
    pub code: ResolutionErrorCode,
    pub message: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub event: ResolutionEvent,
}

impl ResolutionError {
    fn new(
        code: ResolutionErrorCode,
        message: impl Into<String>,
        context: &ResolutionContext,
    ) -> Self {
        let message = message.into();
        let event = error_event(context, code);
        Self {
            code,
            message,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            event,
        }
    }
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (trace_id={}, decision_id={}, policy_id={})",
            self.code.stable_code(),
            self.message,
            self.trace_id,
            self.decision_id,
            self.policy_id
        )
    }
}

impl std::error::Error for ResolutionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryErrorCode {
    EmptyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryError {
    pub code: RegistryErrorCode,
    pub message: String,
}

impl RegistryError {
    fn empty_key() -> Self {
        Self {
            code: RegistryErrorCode::EmptyKey,
            message: "module key must not be empty".to_string(),
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for RegistryError {}

pub trait ModulePolicyHook {
    fn authorize(
        &self,
        request: &ModuleRequest,
        resolved: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AllowAllPolicy;

impl ModulePolicyHook for AllowAllPolicy {
    fn authorize(
        &self,
        _request: &ModuleRequest,
        _resolved: &ModuleRecord,
        _context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPolicyHook {
    pub granted_capabilities: BTreeSet<RuntimeCapability>,
    pub denied_specifiers: BTreeSet<String>,
}

impl CapabilityPolicyHook {
    pub fn new(granted_capabilities: BTreeSet<RuntimeCapability>) -> Self {
        Self {
            granted_capabilities,
            denied_specifiers: BTreeSet::new(),
        }
    }

    pub fn deny_specifier(mut self, specifier: impl Into<String>) -> Self {
        self.denied_specifiers.insert(specifier.into());
        self
    }
}

impl ModulePolicyHook for CapabilityPolicyHook {
    fn authorize(
        &self,
        request: &ModuleRequest,
        resolved: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        if self.denied_specifiers.contains(&request.specifier)
            || self.denied_specifiers.contains(&resolved.id)
        {
            return Err(Box::new(ResolutionError::new(
                ResolutionErrorCode::PolicyDenied,
                format!(
                    "resolution denied by policy deny-list for specifier '{}'",
                    request.specifier
                ),
                context,
            )));
        }

        let missing: Vec<RuntimeCapability> = resolved
            .required_capabilities
            .difference(&self.granted_capabilities)
            .copied()
            .collect();
        if missing.is_empty() {
            return Ok(());
        }

        let missing_list = missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Err(Box::new(ResolutionError::new(
            ResolutionErrorCode::PolicyDenied,
            format!(
                "resolution denied due to missing capabilities [{}] for module '{}'",
                missing_list, resolved.id
            ),
            context,
        )))
    }
}

pub trait ModuleResolver {
    fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<ResolutionOutcome>;

    fn resolve_chain(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicModuleResolver {
    root_dir: String,
    builtins: BTreeMap<String, ModuleRecord>,
    workspace_modules: BTreeMap<String, ModuleRecord>,
    external_modules: BTreeMap<String, ModuleRecord>,
}

impl Default for DeterministicModuleResolver {
    fn default() -> Self {
        Self::new("/")
    }
}

impl DeterministicModuleResolver {
    pub fn new(root_dir: impl Into<String>) -> Self {
        Self {
            root_dir: normalize_absolute_path(&root_dir.into()),
            builtins: BTreeMap::new(),
            workspace_modules: BTreeMap::new(),
            external_modules: BTreeMap::new(),
        }
    }

    pub fn root_dir(&self) -> &str {
        &self.root_dir
    }

    pub fn register_builtin(
        &mut self,
        specifier: impl Into<String>,
        definition: ModuleDefinition,
    ) -> RegistryResult<()> {
        let specifier = specifier.into();
        if specifier.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }
        let id = format!("builtin:{specifier}");
        let record = ModuleRecord::from_definition(id, ModuleSourceKind::BuiltIn, definition);
        self.builtins.insert(specifier, record);
        Ok(())
    }

    pub fn register_workspace_module(
        &mut self,
        path: impl Into<String>,
        definition: ModuleDefinition,
    ) -> RegistryResult<()> {
        let path = path.into();
        if path.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }

        let absolute_path = if path.starts_with('/') {
            normalize_absolute_path(&path)
        } else {
            normalize_absolute_path(&join_paths(&self.root_dir, &path))
        };

        let record = ModuleRecord::from_definition(
            absolute_path.clone(),
            ModuleSourceKind::Workspace,
            definition,
        );
        self.workspace_modules.insert(absolute_path, record);
        Ok(())
    }

    pub fn register_external_module(
        &mut self,
        specifier: impl Into<String>,
        definition: ModuleDefinition,
    ) -> RegistryResult<()> {
        let specifier = specifier.into();
        if specifier.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }

        let id = format!("external:{specifier}");
        let record =
            ModuleRecord::from_definition(id, ModuleSourceKind::ExternalRegistry, definition);
        self.external_modules.insert(specifier, record);
        Ok(())
    }

    fn resolve_candidate<'a>(
        &'a self,
        request: &ModuleRequest,
        context: &ResolutionContext,
    ) -> ResolutionResult<(String, &'a ModuleRecord)> {
        let specifier = request.specifier.trim();
        if specifier.is_empty() {
            return Err(Box::new(ResolutionError::new(
                ResolutionErrorCode::EmptySpecifier,
                "module specifier must not be empty",
                context,
            )));
        }

        if let Some(record) = self.builtins.get(specifier) {
            return Ok((specifier.to_string(), record));
        }

        if is_relative_specifier(specifier) {
            let referrer = request.referrer.as_deref().ok_or_else(|| {
                Box::new(ResolutionError::new(
                    ResolutionErrorCode::InvalidReferrer,
                    format!(
                        "relative specifier '{}' requires a referrer module",
                        request.specifier
                    ),
                    context,
                ))
            })?;
            let base_dir = self.referrer_directory(referrer, context)?;
            let resolved_base = normalize_absolute_path(&join_paths(&base_dir, specifier));
            return self
                .lookup_workspace_candidate(&resolved_base, request.style)
                .ok_or_else(|| {
                    Box::new(ResolutionError::new(
                        ResolutionErrorCode::ModuleNotFound,
                        format!(
                            "unable to resolve relative specifier '{}' from '{}'",
                            request.specifier, referrer
                        ),
                        context,
                    ))
                });
        }

        if specifier.starts_with('/') {
            let resolved_base = normalize_absolute_path(specifier);
            return self
                .lookup_workspace_candidate(&resolved_base, request.style)
                .ok_or_else(|| {
                    Box::new(ResolutionError::new(
                        ResolutionErrorCode::ModuleNotFound,
                        format!("unable to resolve absolute specifier '{specifier}'"),
                        context,
                    ))
                });
        }

        if let Some(candidate) = self.lookup_external_candidate(specifier, request.style) {
            return Ok(candidate);
        }

        let workspace_base = normalize_absolute_path(&join_paths(&self.root_dir, specifier));
        if let Some(candidate) = self.lookup_workspace_candidate(&workspace_base, request.style) {
            return Ok(candidate);
        }

        Err(Box::new(ResolutionError::new(
            ResolutionErrorCode::ModuleNotFound,
            format!("unable to resolve bare specifier '{specifier}'"),
            context,
        )))
    }

    fn referrer_directory(
        &self,
        referrer: &str,
        context: &ResolutionContext,
    ) -> ResolutionResult<String> {
        if referrer.starts_with("builtin:") || referrer.starts_with("external:") {
            return Err(Box::new(ResolutionError::new(
                ResolutionErrorCode::UnsupportedSpecifier,
                format!(
                    "relative resolution from non-workspace referrer '{}' is not supported",
                    referrer
                ),
                context,
            )));
        }

        let normalized = if referrer.starts_with('/') {
            normalize_absolute_path(referrer)
        } else {
            normalize_absolute_path(&join_paths(&self.root_dir, referrer))
        };
        Ok(parent_directory(&normalized))
    }

    fn lookup_workspace_candidate<'a>(
        &'a self,
        resolved_base: &str,
        style: ImportStyle,
    ) -> Option<(String, &'a ModuleRecord)> {
        let candidates = candidate_paths(resolved_base, style);
        for candidate in candidates {
            if let Some(record) = self.workspace_modules.get(&candidate) {
                return Some((candidate, record));
            }
        }
        None
    }

    fn lookup_external_candidate<'a>(
        &'a self,
        specifier: &str,
        style: ImportStyle,
    ) -> Option<(String, &'a ModuleRecord)> {
        if let Some(record) = self.external_modules.get(specifier) {
            return Some((specifier.to_string(), record));
        }

        let candidates = candidate_paths(specifier, style);
        for candidate in candidates {
            if let Some(record) = self.external_modules.get(&candidate) {
                return Some((candidate, record));
            }
        }
        None
    }
}

impl ModuleResolver for DeterministicModuleResolver {
    fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<ResolutionOutcome> {
        let (canonical_specifier, record) = self.resolve_candidate(request, context)?;
        policy.authorize(request, record, context)?;

        let resolved = ResolvedModule {
            request_specifier: request.specifier.clone(),
            canonical_specifier,
            record: record.clone(),
            content_hash: record.canonical_hash(),
        };

        Ok(ResolutionOutcome {
            module: resolved,
            event: success_event(context),
        })
    }

    fn resolve_chain(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>> {
        let mut queue = VecDeque::new();
        queue.push_back(entry_request.clone());

        let mut outcomes = Vec::new();
        let mut visited = BTreeSet::new();

        while let Some(request) = queue.pop_front() {
            let outcome = self.resolve(&request, context, policy)?;
            let module_id = outcome.module.record.id.clone();
            if !visited.insert(module_id.clone()) {
                continue;
            }

            for dependency in &outcome.module.record.dependencies {
                queue.push_back(
                    ModuleRequest::new(dependency.specifier.clone(), dependency.style)
                        .with_referrer(module_id.clone()),
                );
            }

            outcomes.push(outcome);
        }

        Ok(outcomes)
    }
}

fn success_event(context: &ResolutionContext) -> ResolutionEvent {
    ResolutionEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: "module_resolver".to_string(),
        event: "module_resolution".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
    }
}

fn error_event(context: &ResolutionContext, code: ResolutionErrorCode) -> ResolutionEvent {
    ResolutionEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: "module_resolver".to_string(),
        event: "module_resolution".to_string(),
        outcome: "deny".to_string(),
        error_code: code.stable_code().to_string(),
    }
}

fn is_relative_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../")
}

fn candidate_paths(base: &str, style: ImportStyle) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();

    let mut push = |candidate: String| {
        if seen.insert(candidate.clone()) {
            candidates.push(candidate);
        }
    };

    push(base.to_string());

    let suffixes: &[&str] = match style {
        ImportStyle::Import => &[".mjs", ".js", "/index.mjs", "/index.js"],
        ImportStyle::Require => &[".cjs", ".js", "/index.cjs", "/index.js"],
    };

    for suffix in suffixes {
        push(format!("{base}{suffix}"));
    }

    candidates
}

fn normalize_absolute_path(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            value => stack.push(value),
        }
    }

    if stack.is_empty() {
        return "/".to_string();
    }

    format!("/{}", stack.join("/"))
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

fn parent_directory(path: &str) -> String {
    let normalized = normalize_absolute_path(path);
    if normalized == "/" {
        return normalized;
    }

    match normalized.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => normalized[..index].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ResolutionContext {
        ResolutionContext::new("trace-1", "decision-1", "policy-1")
    }

    #[test]
    fn builtin_resolution_is_deterministic() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        resolver
            .register_builtin(
                "franken:std/fs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const read = true;")
                    .require_capability(RuntimeCapability::FsRead)
                    .with_provenance("builtin:franken:std/fs"),
            )
            .unwrap();

        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);

        let request = ModuleRequest::new("franken:std/fs", ImportStyle::Import);
        let first = resolver.resolve(&request, &context(), &policy).unwrap();
        let second = resolver.resolve(&request, &context(), &policy).unwrap();

        assert_eq!(first.module.canonical_specifier, "franken:std/fs");
        assert_eq!(first.module.record.id, "builtin:franken:std/fs");
        assert_eq!(first.module.content_hash, second.module.content_hash);
        assert_eq!(first.event.component, "module_resolver");
        assert_eq!(first.event.outcome, "allow");
        assert_eq!(first.event.error_code, "none");
    }

    #[test]
    fn import_and_require_use_style_specific_resolution() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './lib';"),
            )
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/lib.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .unwrap();

        let import_request =
            ModuleRequest::new("./lib", ImportStyle::Import).with_referrer("/app/main.mjs");
        let import_outcome = resolver
            .resolve(&import_request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(import_outcome.module.canonical_specifier, "/app/lib.mjs");

        let require_request =
            ModuleRequest::new("./lib", ImportStyle::Require).with_referrer("/app/main.mjs");
        let require_outcome = resolver
            .resolve(&require_request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(require_outcome.module.canonical_specifier, "/app/lib.cjs");
    }

    #[test]
    fn policy_denies_missing_capabilities_with_stable_error_fields() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/secure.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 7;")
                    .require_capability(RuntimeCapability::FsWrite),
            )
            .unwrap();

        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);

        let request = ModuleRequest::new("/app/secure.js", ImportStyle::Require);
        let error = resolver
            .resolve(&request, &context(), &policy)
            .expect_err("expected policy denial");

        assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(error.event.component, "module_resolver");
        assert_eq!(error.event.event, "module_resolution");
        assert_eq!(error.event.outcome, "deny");
        assert_eq!(
            error.event.error_code,
            ResolutionErrorCode::PolicyDenied.stable_code()
        );
        assert!(error.message.contains("fs_write"));
    }

    #[test]
    fn external_resolution_preserves_provenance() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        resolver
            .register_external_module(
                "left-pad",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = function(){};")
                    .with_provenance("registry:npm:left-pad@1.3.0"),
            )
            .unwrap();

        let request = ModuleRequest::new("left-pad", ImportStyle::Require);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();

        assert_eq!(
            outcome.module.record.provenance.kind,
            ModuleSourceKind::ExternalRegistry
        );
        assert_eq!(
            outcome.module.record.provenance.origin,
            "registry:npm:left-pad@1.3.0"
        );
    }

    #[test]
    fn relative_resolution_requires_referrer() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("./dep", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("missing referrer should fail");

        assert_eq!(error.code, ResolutionErrorCode::InvalidReferrer);
        assert_eq!(
            error.event.error_code,
            ResolutionErrorCode::InvalidReferrer.stable_code()
        );
    }

    // -----------------------------------------------------------------------
    // Empty specifier rejection
    // -----------------------------------------------------------------------

    #[test]
    fn empty_specifier_returns_empty_specifier_error() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("empty specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::EmptySpecifier);
        assert_eq!(error.code.stable_code(), "FE-MODRES-0001");
    }

    #[test]
    fn whitespace_only_specifier_returns_empty_specifier_error() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("   ", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("whitespace-only specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::EmptySpecifier);
    }

    // -----------------------------------------------------------------------
    // Empty key rejection for register methods
    // -----------------------------------------------------------------------

    #[test]
    fn register_builtin_with_empty_key_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_builtin("", ModuleDefinition::new(ModuleSyntax::EsModule, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    #[test]
    fn register_workspace_module_with_empty_path_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_workspace_module("", ModuleDefinition::new(ModuleSyntax::EsModule, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    #[test]
    fn register_external_module_with_empty_specifier_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_external_module("", ModuleDefinition::new(ModuleSyntax::CommonJs, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    // -----------------------------------------------------------------------
    // Module not found
    // -----------------------------------------------------------------------

    #[test]
    fn unresolvable_bare_specifier_returns_module_not_found() {
        let resolver = DeterministicModuleResolver::new("/workspace");
        let request = ModuleRequest::new("nonexistent-package", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("unregistered specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(error.code.stable_code(), "FE-MODRES-0004");
    }

    #[test]
    fn unresolvable_relative_specifier_returns_module_not_found() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, ""),
            )
            .unwrap();
        let request =
            ModuleRequest::new("./missing", ImportStyle::Import).with_referrer("/app/main.js");
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("missing relative should fail");
        assert_eq!(error.code, ResolutionErrorCode::ModuleNotFound);
    }

    // -----------------------------------------------------------------------
    // Absolute specifier resolution
    // -----------------------------------------------------------------------

    #[test]
    fn absolute_specifier_resolves_workspace_module() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/lib/util.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/lib/util.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.module.canonical_specifier, "/app/lib/util.js");
    }

    // -----------------------------------------------------------------------
    // Bare specifier resolved from workspace
    // -----------------------------------------------------------------------

    #[test]
    fn bare_specifier_resolves_from_workspace_with_extension_probing() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/utils.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 42;"),
            )
            .unwrap();

        let request = ModuleRequest::new("utils", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.module.canonical_specifier, "/app/utils.js");
    }

    // -----------------------------------------------------------------------
    // Index file probing
    // -----------------------------------------------------------------------

    #[test]
    fn import_probes_index_mjs_for_directory_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/lib/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

        let request =
            ModuleRequest::new("./lib", ImportStyle::Import).with_referrer("/app/main.js");
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.module.canonical_specifier, "/app/lib/index.mjs");
    }

    #[test]
    fn require_probes_index_cjs_for_directory_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/lib/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .unwrap();

        let request =
            ModuleRequest::new("./lib", ImportStyle::Require).with_referrer("/app/main.js");
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.module.canonical_specifier, "/app/lib/index.cjs");
    }

    // -----------------------------------------------------------------------
    // Relative resolution from non-workspace referrer
    // -----------------------------------------------------------------------

    #[test]
    fn relative_from_builtin_referrer_returns_unsupported_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_builtin(
                "franken:fs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const read = true;"),
            )
            .unwrap();

        let request =
            ModuleRequest::new("./sub", ImportStyle::Import).with_referrer("builtin:franken:fs");
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("relative from builtin referrer should fail");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert_eq!(error.code.stable_code(), "FE-MODRES-0003");
    }

    // -----------------------------------------------------------------------
    // resolve_chain
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_chain_traverses_dependencies() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/entry.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './dep';")
                    .with_dependency(ModuleDependency::new("./dep", ImportStyle::Import)),
            )
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/dep.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/entry.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .unwrap();

        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].module.canonical_specifier, "/app/entry.js");
        assert_eq!(chain[1].module.canonical_specifier, "/app/dep.js");
    }

    #[test]
    fn resolve_chain_deduplicates_circular_dependencies() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/a.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './b';")
                    .with_dependency(ModuleDependency::new("./b", ImportStyle::Import)),
            )
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/b.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './a';")
                    .with_dependency(ModuleDependency::new("./a", ImportStyle::Import)),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/a.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .unwrap();

        // Should resolve both but not loop infinitely
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn resolve_chain_single_module_no_deps() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/leaf.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/leaf.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(chain.len(), 1);
    }

    // -----------------------------------------------------------------------
    // CapabilityPolicyHook deny-list
    // -----------------------------------------------------------------------

    #[test]
    fn capability_policy_denies_listed_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/allowed.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

        let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("/app/allowed.js");

        let request = ModuleRequest::new("/app/allowed.js", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &policy)
            .expect_err("deny-listed specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
    }

    // -----------------------------------------------------------------------
    // AllowAllPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn allow_all_policy_permits_any_module() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/anything.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .require_capability(RuntimeCapability::FsWrite)
                    .require_capability(RuntimeCapability::NetworkEgress),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/anything.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.event.outcome, "allow");
    }

    // -----------------------------------------------------------------------
    // ModuleSyntax / ImportStyle / ModuleSourceKind as_str
    // -----------------------------------------------------------------------

    #[test]
    fn module_syntax_as_str() {
        assert_eq!(ModuleSyntax::EsModule.as_str(), "esm");
        assert_eq!(ModuleSyntax::CommonJs.as_str(), "cjs");
    }

    #[test]
    fn import_style_as_str() {
        assert_eq!(ImportStyle::Import.as_str(), "import");
        assert_eq!(ImportStyle::Require.as_str(), "require");
    }

    #[test]
    fn module_source_kind_as_str() {
        assert_eq!(ModuleSourceKind::BuiltIn.as_str(), "builtin");
        assert_eq!(ModuleSourceKind::Workspace.as_str(), "workspace");
        assert_eq!(
            ModuleSourceKind::ExternalRegistry.as_str(),
            "external_registry"
        );
    }

    // -----------------------------------------------------------------------
    // ModuleRecord canonical value/hash determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_record_canonical_hash_is_deterministic() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/det.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .with_provenance("workspace:/app/det.js"),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/det.js", ImportStyle::Import);
        let r1 = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        let r2 = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(r1.module.content_hash, r2.module.content_hash);
        assert_eq!(
            r1.module.record.canonical_bytes(),
            r2.module.record.canonical_bytes()
        );
    }

    // -----------------------------------------------------------------------
    // ResolutionErrorCode stable codes
    // -----------------------------------------------------------------------

    #[test]
    fn all_resolution_error_codes_have_fe_modres_prefix() {
        let codes = [
            ResolutionErrorCode::EmptySpecifier,
            ResolutionErrorCode::InvalidReferrer,
            ResolutionErrorCode::UnsupportedSpecifier,
            ResolutionErrorCode::ModuleNotFound,
            ResolutionErrorCode::PolicyDenied,
        ];
        for code in &codes {
            let stable = code.stable_code();
            assert!(
                stable.starts_with("FE-MODRES-"),
                "stable_code {} must start with FE-MODRES-",
                stable
            );
        }
    }

    #[test]
    fn resolution_error_codes_are_unique() {
        let codes = [
            ResolutionErrorCode::EmptySpecifier.stable_code(),
            ResolutionErrorCode::InvalidReferrer.stable_code(),
            ResolutionErrorCode::UnsupportedSpecifier.stable_code(),
            ResolutionErrorCode::ModuleNotFound.stable_code(),
            ResolutionErrorCode::PolicyDenied.stable_code(),
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "all stable codes must be unique");
    }

    // -----------------------------------------------------------------------
    // ResolutionError Display
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_error_display_includes_stable_code_and_trace() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("empty specifier should fail");
        let display = format!("{error}");
        assert!(display.contains("FE-MODRES-0001"));
        assert!(display.contains("trace-1"));
        assert!(display.contains("decision-1"));
        assert!(display.contains("policy-1"));
    }

    // -----------------------------------------------------------------------
    // Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn module_syntax_serde_round_trip() {
        for syntax in &[ModuleSyntax::EsModule, ModuleSyntax::CommonJs] {
            let json = serde_json::to_string(syntax).expect("serialize");
            let decoded: ModuleSyntax = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, syntax);
        }
    }

    #[test]
    fn import_style_serde_round_trip() {
        for style in &[ImportStyle::Import, ImportStyle::Require] {
            let json = serde_json::to_string(style).expect("serialize");
            let decoded: ImportStyle = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, style);
        }
    }

    #[test]
    fn resolution_error_code_serde_round_trip() {
        let codes = [
            ResolutionErrorCode::EmptySpecifier,
            ResolutionErrorCode::InvalidReferrer,
            ResolutionErrorCode::UnsupportedSpecifier,
            ResolutionErrorCode::ModuleNotFound,
            ResolutionErrorCode::PolicyDenied,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serialize");
            let decoded: ResolutionErrorCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn module_definition_builder_chain() {
        let def = ModuleDefinition::new(ModuleSyntax::EsModule, "import 'x'; export default 1;")
            .with_dependency(ModuleDependency::new("x", ImportStyle::Import))
            .require_capability(RuntimeCapability::FsRead)
            .with_provenance("test:origin");

        assert_eq!(def.dependencies.len(), 1);
        assert_eq!(def.dependencies[0].specifier, "x");
        assert!(
            def.required_capabilities
                .contains(&RuntimeCapability::FsRead)
        );
        assert_eq!(def.provenance_origin, "test:origin");
    }

    // -----------------------------------------------------------------------
    // Path normalization
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_absolute_path_resolves_dotdot() {
        assert_eq!(normalize_absolute_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_absolute_path("/a/./b/./c"), "/a/b/c");
        assert_eq!(normalize_absolute_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn normalize_absolute_path_root() {
        assert_eq!(normalize_absolute_path("/"), "/");
        assert_eq!(normalize_absolute_path("///"), "/");
    }

    #[test]
    fn parent_directory_of_file() {
        assert_eq!(parent_directory("/a/b/c.js"), "/a/b");
        assert_eq!(parent_directory("/a.js"), "/");
        assert_eq!(parent_directory("/"), "/");
    }

    // -----------------------------------------------------------------------
    // Workspace module with relative path
    // -----------------------------------------------------------------------

    #[test]
    fn register_workspace_module_with_relative_path_normalizes_to_absolute() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        resolver
            .register_workspace_module(
                "src/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

        let request = ModuleRequest::new("/workspace/src/lib.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.module.canonical_specifier, "/workspace/src/lib.js");
    }

    // -----------------------------------------------------------------------
    // Duplicate registration overwrites
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_builtin_registration_overwrites_previous() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_builtin(
                "franken:util",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 1;"),
            )
            .unwrap();
        resolver
            .register_builtin(
                "franken:util",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 2;"),
            )
            .unwrap();

        let request = ModuleRequest::new("franken:util", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.module.record.source, "export const v = 2;");
    }

    // -----------------------------------------------------------------------
    // Default resolver root dir
    // -----------------------------------------------------------------------

    #[test]
    fn default_resolver_has_root_dir_slash() {
        let resolver = DeterministicModuleResolver::default();
        assert_eq!(resolver.root_dir(), "/");
    }

    // -- Enrichment: ordering --

    #[test]
    fn module_syntax_ordering() {
        assert!(ModuleSyntax::EsModule < ModuleSyntax::CommonJs);
    }

    #[test]
    fn import_style_ordering() {
        assert!(ImportStyle::Import < ImportStyle::Require);
    }

    #[test]
    fn module_source_kind_ordering() {
        assert!(ModuleSourceKind::BuiltIn < ModuleSourceKind::Workspace);
        assert!(ModuleSourceKind::Workspace < ModuleSourceKind::ExternalRegistry);
    }

    // -- Enrichment: error trait --

    #[test]
    fn resolution_error_is_std_error() {
        let event = ResolutionEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "resolver".to_string(),
            event: "resolve".to_string(),
            outcome: "error".to_string(),
            error_code: "FE_MODRES_EMPTY".to_string(),
        };
        let err = ResolutionError {
            code: ResolutionErrorCode::EmptySpecifier,
            message: "empty".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            event,
        };
        let e: Box<dyn std::error::Error> = Box::new(err);
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn registry_error_is_std_error() {
        let err = RegistryError {
            code: RegistryErrorCode::EmptyKey,
            message: "key empty".to_string(),
        };
        let e: Box<dyn std::error::Error> = Box::new(err);
        assert!(!e.to_string().is_empty());
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn module_provenance_serde_roundtrip() {
        let mp = ModuleProvenance {
            kind: ModuleSourceKind::BuiltIn,
            origin: "franken:core".to_string(),
        };
        let json = serde_json::to_string(&mp).expect("serialize");
        let restored: ModuleProvenance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mp, restored);
    }

    #[test]
    fn module_dependency_serde_roundtrip() {
        let md = ModuleDependency {
            specifier: "./utils.js".to_string(),
            style: ImportStyle::Import,
        };
        let json = serde_json::to_string(&md).expect("serialize");
        let restored: ModuleDependency = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(md, restored);
    }

    #[test]
    fn module_request_serde_roundtrip() {
        let mr = ModuleRequest::new("franken:core", ImportStyle::Import);
        let json = serde_json::to_string(&mr).expect("serialize");
        let restored: ModuleRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mr, restored);
    }

    #[test]
    fn resolution_context_serde_roundtrip() {
        let ctx = ResolutionContext {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
        };
        let json = serde_json::to_string(&ctx).expect("serialize");
        let restored: ResolutionContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ctx, restored);
    }

    #[test]
    fn registry_error_serde_roundtrip() {
        let err = RegistryError {
            code: RegistryErrorCode::EmptyKey,
            message: "key must not be empty".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: RegistryError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    #[test]
    fn allow_all_policy_default_serde() {
        let p = AllowAllPolicy::default();
        let json = serde_json::to_string(&p).expect("serialize");
        let restored: AllowAllPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, restored);
    }

    #[test]
    fn module_source_kind_serde_roundtrip() {
        for kind in [
            ModuleSourceKind::BuiltIn,
            ModuleSourceKind::Workspace,
            ModuleSourceKind::ExternalRegistry,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: ModuleSourceKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }
}
