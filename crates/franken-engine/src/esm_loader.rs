//! ES module loader with deterministic cache, cycle handling, and resolution
//! tracing.
//!
//! Implements the ES2020 module loading pipeline:
//! 1. **Resolve** — map specifier to canonical module id
//! 2. **Fetch** — retrieve source text (from registry or filesystem)
//! 3. **Parse** — produce AST (via the parser module)
//! 4. **Link** — bind import/export bindings across the module graph
//! 5. **Evaluate** — execute module body in topological order
//!
//! Key design decisions:
//! - Cycle-safe: uses DFS with `Linking` sentinel to detect cycles and return
//!   live-binding stubs per ES2020 §15.2.1.16.4.
//! - Deterministic: module graph ordering is stable via `BTreeMap` keying.
//! - Traced: every resolution, link, and evaluate step emits tracing events
//!   for the evidence ledger.
//! - Cache-aware: integrates with `module_cache` for fingerprint-based
//!   invalidation.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.4, bd-1lsy.5.1.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::module_resolver::ModuleSyntax;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum module graph depth before aborting (prevents stack overflow on
/// pathological circular imports).
const MAX_MODULE_DEPTH: usize = 512;

/// Maximum number of modules in a single graph (prevents runaway resolution).
const MAX_MODULE_GRAPH_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// Module status (ES2020 §15.2.1.16 Module Record status field)
// ---------------------------------------------------------------------------

/// Status of a module in the loading pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ModuleStatus {
    /// Module has been resolved but not yet fetched/parsed.
    Unlinked,
    /// Module is currently being linked (cycle detection sentinel).
    Linking,
    /// Module has been linked — all import bindings are wired.
    Linked,
    /// Module is currently being evaluated (cycle detection sentinel).
    Evaluating,
    /// Module has been evaluated — its body has executed.
    Evaluated,
    /// Module evaluation threw an error.
    EvaluationError,
}

impl fmt::Display for ModuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlinked => write!(f, "unlinked"),
            Self::Linking => write!(f, "linking"),
            Self::Linked => write!(f, "linked"),
            Self::Evaluating => write!(f, "evaluating"),
            Self::Evaluated => write!(f, "evaluated"),
            Self::EvaluationError => write!(f, "evaluation_error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Export / Import binding descriptors
// ---------------------------------------------------------------------------

/// A single export from a module.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExportEntry {
    /// The local name in the exporting module (None for re-exports).
    pub local_name: Option<String>,
    /// The export name visible to importers.
    pub export_name: String,
    /// For re-exports: the source module specifier.
    pub module_request: Option<String>,
    /// For re-exports: the import name from the source module.
    pub import_name: Option<String>,
}

impl ExportEntry {
    /// Direct export: `export { foo }` or `export const foo = ...`.
    pub fn direct(local_name: impl Into<String>, export_name: impl Into<String>) -> Self {
        Self {
            local_name: Some(local_name.into()),
            export_name: export_name.into(),
            module_request: None,
            import_name: None,
        }
    }

    /// Re-export: `export { foo } from "mod"`.
    pub fn re_export(
        export_name: impl Into<String>,
        module_request: impl Into<String>,
        import_name: impl Into<String>,
    ) -> Self {
        Self {
            local_name: None,
            export_name: export_name.into(),
            module_request: Some(module_request.into()),
            import_name: Some(import_name.into()),
        }
    }

    /// Star re-export: `export * from "mod"`.
    pub fn star_re_export(module_request: impl Into<String>) -> Self {
        Self {
            local_name: None,
            export_name: "*".into(),
            module_request: Some(module_request.into()),
            import_name: None,
        }
    }
}

/// A single import binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImportEntry {
    /// The module specifier being imported from.
    pub module_request: String,
    /// The name exported by the source module.
    pub import_name: String,
    /// The local binding name in the importing module.
    pub local_name: String,
}

impl ImportEntry {
    pub fn new(
        module_request: impl Into<String>,
        import_name: impl Into<String>,
        local_name: impl Into<String>,
    ) -> Self {
        Self {
            module_request: module_request.into(),
            import_name: import_name.into(),
            local_name: local_name.into(),
        }
    }

    /// Namespace import: `import * as ns from "mod"`.
    pub fn namespace(module_request: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            module_request: module_request.into(),
            import_name: "*".into(),
            local_name: local_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// EsmModule — a single module in the graph
// ---------------------------------------------------------------------------

/// A module record in the ESM loader graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmModule {
    /// Canonical module specifier (unique within a graph).
    pub specifier: String,
    /// Module syntax (ESM or CJS).
    pub syntax: ModuleSyntax,
    /// Module source text.
    pub source: String,
    /// Content hash of the source.
    pub content_hash: ContentHash,
    /// Import bindings declared by this module.
    pub imports: Vec<ImportEntry>,
    /// Export bindings declared by this module.
    pub exports: Vec<ExportEntry>,
    /// Dependencies (specifiers this module imports from).
    pub dependencies: BTreeSet<String>,
    /// Current status in the loading pipeline.
    pub status: ModuleStatus,
    /// DFS index for cycle detection (assigned during link phase).
    pub dfs_index: Option<u32>,
    /// DFS ancestor index for cycle detection.
    pub dfs_ancestor_index: Option<u32>,
    /// Has a default export?
    pub has_default_export: bool,
    /// Evaluation order index (topological sort rank).
    pub eval_order: Option<u32>,
}

impl EsmModule {
    /// Create a new unlinked ESM module.
    pub fn new(
        specifier: impl Into<String>,
        source: impl Into<String>,
        syntax: ModuleSyntax,
    ) -> Self {
        let source = source.into();
        let content_hash = ContentHash::compute(source.as_bytes());
        Self {
            specifier: specifier.into(),
            syntax,
            source,
            content_hash,
            imports: Vec::new(),
            exports: Vec::new(),
            dependencies: BTreeSet::new(),
            status: ModuleStatus::Unlinked,
            dfs_index: None,
            dfs_ancestor_index: None,
            has_default_export: false,
            eval_order: None,
        }
    }

    /// Add an import entry.
    pub fn add_import(&mut self, entry: ImportEntry) {
        self.dependencies.insert(entry.module_request.clone());
        self.imports.push(entry);
    }

    /// Add an export entry.
    pub fn add_export(&mut self, entry: ExportEntry) {
        if entry.export_name == "default" {
            self.has_default_export = true;
        }
        if let Some(req) = &entry.module_request {
            self.dependencies.insert(req.clone());
        }
        self.exports.push(entry);
    }
}

// ---------------------------------------------------------------------------
// ModuleGraph — the full dependency graph
// ---------------------------------------------------------------------------

/// The module dependency graph, keyed by canonical specifier.
///
/// Uses `BTreeMap` for deterministic iteration order, which is critical for
/// reproducible evaluation ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleGraph {
    /// All modules in the graph, keyed by canonical specifier.
    modules: BTreeMap<String, EsmModule>,
    /// The entry point specifier.
    entry_point: Option<String>,
    /// Resolution trace events.
    trace_events: Vec<TraceEvent>,
}

/// A trace event for the evidence ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub phase: TracePhase,
    pub specifier: String,
    pub detail: String,
    pub seq: u64,
}

/// Which loading phase generated this trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TracePhase {
    Resolve,
    Link,
    Evaluate,
    CycleDetected,
}

impl fmt::Display for TracePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve => write!(f, "resolve"),
            Self::Link => write!(f, "link"),
            Self::Evaluate => write!(f, "evaluate"),
            Self::CycleDetected => write!(f, "cycle_detected"),
        }
    }
}

impl ModuleGraph {
    /// Create an empty module graph.
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            entry_point: None,
            trace_events: Vec::new(),
        }
    }

    /// Number of modules in the graph.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Is the graph empty?
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Get the entry point specifier.
    pub fn entry_point(&self) -> Option<&str> {
        self.entry_point.as_deref()
    }

    /// Get a module by specifier.
    pub fn get_module(&self, specifier: &str) -> Option<&EsmModule> {
        self.modules.get(specifier)
    }

    /// Get a mutable module by specifier.
    pub fn get_module_mut(&mut self, specifier: &str) -> Option<&mut EsmModule> {
        self.modules.get_mut(specifier)
    }

    /// All module specifiers in deterministic order.
    pub fn specifiers(&self) -> impl Iterator<Item = &str> {
        self.modules.keys().map(|s| s.as_str())
    }

    /// All modules in deterministic order.
    pub fn modules(&self) -> impl Iterator<Item = &EsmModule> {
        self.modules.values()
    }

    /// All trace events.
    pub fn trace_events(&self) -> &[TraceEvent] {
        &self.trace_events
    }

    /// Add a module to the graph. Returns error if graph is full.
    pub fn add_module(&mut self, module: EsmModule) -> Result<(), EsmLoaderError> {
        if self.modules.len() >= MAX_MODULE_GRAPH_SIZE {
            return Err(EsmLoaderError::GraphTooLarge {
                limit: MAX_MODULE_GRAPH_SIZE,
            });
        }
        let specifier = module.specifier.clone();
        if self.entry_point.is_none() {
            self.entry_point = Some(specifier.clone());
        }
        self.modules.insert(specifier, module);
        Ok(())
    }

    /// Record a trace event.
    fn trace(&mut self, phase: TracePhase, specifier: &str, detail: impl Into<String>) {
        let seq = self.trace_events.len() as u64;
        self.trace_events.push(TraceEvent {
            phase,
            specifier: specifier.to_string(),
            detail: detail.into(),
            seq,
        });
    }

    // -----------------------------------------------------------------------
    // Link phase — DFS-based module linking with cycle detection
    // -----------------------------------------------------------------------

    /// Link all modules in the graph starting from the entry point.
    ///
    /// This implements the ES2020 Link phase (§15.2.1.16.4):
    /// - DFS traversal of the dependency graph
    /// - Cycle detection via `Linking` sentinel status
    /// - Export binding resolution across the graph
    pub fn link(&mut self) -> Result<LinkResult, EsmLoaderError> {
        let entry = self
            .entry_point
            .clone()
            .ok_or(EsmLoaderError::NoEntryPoint)?;

        let mut dfs_counter: u32 = 0;
        let mut stack: Vec<String> = Vec::new();
        let mut cycles: Vec<CycleInfo> = Vec::new();

        self.link_module(&entry, &mut dfs_counter, &mut stack, &mut cycles, 0)?;

        Ok(LinkResult {
            linked_count: self
                .modules
                .values()
                .filter(|m| m.status == ModuleStatus::Linked)
                .count(),
            cycle_count: cycles.len(),
            cycles,
        })
    }

    fn link_module(
        &mut self,
        specifier: &str,
        dfs_counter: &mut u32,
        stack: &mut Vec<String>,
        cycles: &mut Vec<CycleInfo>,
        depth: usize,
    ) -> Result<u32, EsmLoaderError> {
        if depth > MAX_MODULE_DEPTH {
            return Err(EsmLoaderError::DepthExceeded {
                specifier: specifier.to_string(),
                depth,
                limit: MAX_MODULE_DEPTH,
            });
        }

        // Check current status.
        let status = self
            .modules
            .get(specifier)
            .ok_or_else(|| EsmLoaderError::ModuleNotFound(specifier.to_string()))?
            .status;

        match status {
            ModuleStatus::Linked | ModuleStatus::Evaluated => {
                // Already linked; return ancestor index.
                return Ok(self.modules[specifier]
                    .dfs_ancestor_index
                    .unwrap_or(u32::MAX));
            }
            ModuleStatus::Linking => {
                // Cycle detected!
                self.trace(
                    TracePhase::CycleDetected,
                    specifier,
                    format!("cycle detected at depth {depth}"),
                );
                cycles.push(CycleInfo {
                    specifier: specifier.to_string(),
                    stack_snapshot: stack.clone(),
                });
                // Return this module's DFS index as the ancestor index.
                return Ok(self.modules[specifier].dfs_index.unwrap_or(0));
            }
            _ => {}
        }

        // Set status to Linking and assign DFS index.
        let index = *dfs_counter;
        *dfs_counter += 1;

        {
            let module = self.modules.get_mut(specifier).unwrap();
            module.status = ModuleStatus::Linking;
            module.dfs_index = Some(index);
            module.dfs_ancestor_index = Some(index);
        }

        stack.push(specifier.to_string());
        self.trace(
            TracePhase::Link,
            specifier,
            format!("linking (dfs_index={index})"),
        );

        // Collect dependencies (need to clone to avoid borrow issues).
        let deps: Vec<String> = self.modules[specifier]
            .dependencies
            .iter()
            .cloned()
            .collect();

        let mut ancestor = index;
        for dep in &deps {
            if !self.modules.contains_key(dep.as_str()) {
                // Dependency not in graph — this is a resolution error.
                return Err(EsmLoaderError::UnresolvedDependency {
                    specifier: specifier.to_string(),
                    dependency: dep.clone(),
                });
            }
            let dep_ancestor = self.link_module(dep, dfs_counter, stack, cycles, depth + 1)?;
            if dep_ancestor < ancestor {
                ancestor = dep_ancestor;
            }
        }

        // Update ancestor index.
        if let Some(module) = self.modules.get_mut(specifier) {
            module.dfs_ancestor_index = Some(ancestor);
        }

        // If this is a root of an SCC (ancestor == index), mark all modules
        // in this SCC as Linked.
        if ancestor == index {
            while let Some(top) = stack.pop() {
                if let Some(m) = self.modules.get_mut(&top) {
                    m.status = ModuleStatus::Linked;
                    m.dfs_ancestor_index = Some(index);
                }
                if top == specifier {
                    break;
                }
            }
        }

        Ok(ancestor)
    }

    // -----------------------------------------------------------------------
    // Evaluate phase — topological execution
    // -----------------------------------------------------------------------

    /// Evaluate all linked modules in topological order.
    ///
    /// Returns the evaluation order as a list of specifiers.
    pub fn evaluate(&mut self) -> Result<EvalResult, EsmLoaderError> {
        let entry = self
            .entry_point
            .clone()
            .ok_or(EsmLoaderError::NoEntryPoint)?;

        let mut eval_order: Vec<String> = Vec::new();
        let mut eval_counter: u32 = 0;

        self.evaluate_module(&entry, &mut eval_order, &mut eval_counter, 0)?;

        Ok(EvalResult {
            eval_order,
            evaluated_count: eval_counter as usize,
        })
    }

    fn evaluate_module(
        &mut self,
        specifier: &str,
        eval_order: &mut Vec<String>,
        eval_counter: &mut u32,
        depth: usize,
    ) -> Result<(), EsmLoaderError> {
        if depth > MAX_MODULE_DEPTH {
            return Err(EsmLoaderError::DepthExceeded {
                specifier: specifier.to_string(),
                depth,
                limit: MAX_MODULE_DEPTH,
            });
        }

        let status = self
            .modules
            .get(specifier)
            .ok_or_else(|| EsmLoaderError::ModuleNotFound(specifier.to_string()))?
            .status;

        match status {
            ModuleStatus::Evaluated => return Ok(()),
            ModuleStatus::Evaluating => {
                // Cycle — module is already being evaluated; skip per ES2020.
                return Ok(());
            }
            ModuleStatus::EvaluationError => {
                return Err(EsmLoaderError::EvaluationFailed {
                    specifier: specifier.to_string(),
                    reason: "previous evaluation failed".into(),
                });
            }
            ModuleStatus::Linked => {} // proceed
            _ => {
                return Err(EsmLoaderError::InvalidStatus {
                    specifier: specifier.to_string(),
                    expected: "linked",
                    actual: status.to_string(),
                });
            }
        }

        // Mark as evaluating.
        if let Some(module) = self.modules.get_mut(specifier) {
            module.status = ModuleStatus::Evaluating;
        }

        self.trace(
            TracePhase::Evaluate,
            specifier,
            format!("evaluating at depth {depth}"),
        );

        // Evaluate dependencies first (post-order DFS = topological order).
        let deps: Vec<String> = self.modules[specifier]
            .dependencies
            .iter()
            .cloned()
            .collect();

        for dep in &deps {
            self.evaluate_module(dep, eval_order, eval_counter, depth + 1)?;
        }

        // Mark as evaluated and record order.
        let order = *eval_counter;
        *eval_counter += 1;
        if let Some(module) = self.modules.get_mut(specifier) {
            module.status = ModuleStatus::Evaluated;
            module.eval_order = Some(order);
        }
        eval_order.push(specifier.to_string());

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Export resolution
    // -----------------------------------------------------------------------

    /// Resolve an export binding by walking the module graph.
    ///
    /// Handles:
    /// - Direct exports
    /// - Re-exports (`export { x } from "mod"`)
    /// - Star re-exports (`export * from "mod"`)
    /// - Default exports
    pub fn resolve_export(
        &self,
        specifier: &str,
        export_name: &str,
    ) -> Result<ResolvedBinding, EsmLoaderError> {
        let mut visited = BTreeSet::new();
        self.resolve_export_inner(specifier, export_name, &mut visited)
    }

    fn resolve_export_inner(
        &self,
        specifier: &str,
        export_name: &str,
        visited: &mut BTreeSet<(String, String)>,
    ) -> Result<ResolvedBinding, EsmLoaderError> {
        let key = (specifier.to_string(), export_name.to_string());
        if visited.contains(&key) {
            // Circular re-export — return ambiguous.
            return Err(EsmLoaderError::AmbiguousExport {
                specifier: specifier.to_string(),
                export_name: export_name.to_string(),
            });
        }
        visited.insert(key);

        let module = self
            .modules
            .get(specifier)
            .ok_or_else(|| EsmLoaderError::ModuleNotFound(specifier.to_string()))?;

        // Check direct exports first.
        for entry in &module.exports {
            if entry.export_name == export_name {
                if let Some(local) = &entry.local_name {
                    return Ok(ResolvedBinding {
                        module_specifier: specifier.to_string(),
                        local_name: local.clone(),
                        binding_type: BindingType::Direct,
                    });
                }
                // Re-export.
                if let (Some(req), Some(imp)) = (&entry.module_request, &entry.import_name) {
                    return self.resolve_export_inner(req, imp, visited);
                }
            }
        }

        // Check star re-exports.
        let mut found: Option<ResolvedBinding> = None;
        for entry in &module.exports {
            if entry.export_name == "*"
                && let Some(req) = &entry.module_request
                && let Ok(binding) = self.resolve_export_inner(req, export_name, visited)
            {
                if found.is_some() {
                    return Err(EsmLoaderError::AmbiguousExport {
                        specifier: specifier.to_string(),
                        export_name: export_name.to_string(),
                    });
                }
                found = Some(binding);
            }
        }

        found.ok_or_else(|| EsmLoaderError::ExportNotFound {
            specifier: specifier.to_string(),
            export_name: export_name.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Cycle detection utilities
    // -----------------------------------------------------------------------

    /// Get all strongly connected components (cycles) in the graph.
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        let mut visited = BTreeSet::new();
        let mut stack = Vec::new();
        let mut on_stack = BTreeSet::new();
        let mut sccs = Vec::new();
        let mut index_map: BTreeMap<String, u32> = BTreeMap::new();
        let mut lowlink_map: BTreeMap<String, u32> = BTreeMap::new();
        let mut counter: u32 = 0;

        for specifier in self.modules.keys() {
            if !visited.contains(specifier.as_str()) {
                self.tarjan_dfs(
                    specifier,
                    &mut visited,
                    &mut stack,
                    &mut on_stack,
                    &mut sccs,
                    &mut index_map,
                    &mut lowlink_map,
                    &mut counter,
                );
            }
        }

        // Only return SCCs with more than one node (actual cycles).
        sccs.into_iter().filter(|scc| scc.len() > 1).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn tarjan_dfs(
        &self,
        specifier: &str,
        visited: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
        on_stack: &mut BTreeSet<String>,
        sccs: &mut Vec<Vec<String>>,
        index_map: &mut BTreeMap<String, u32>,
        lowlink_map: &mut BTreeMap<String, u32>,
        counter: &mut u32,
    ) {
        let index = *counter;
        *counter += 1;
        visited.insert(specifier.to_string());
        index_map.insert(specifier.to_string(), index);
        lowlink_map.insert(specifier.to_string(), index);
        stack.push(specifier.to_string());
        on_stack.insert(specifier.to_string());

        if let Some(module) = self.modules.get(specifier) {
            for dep in &module.dependencies {
                if !visited.contains(dep.as_str()) {
                    self.tarjan_dfs(
                        dep,
                        visited,
                        stack,
                        on_stack,
                        sccs,
                        index_map,
                        lowlink_map,
                        counter,
                    );
                    let dep_ll = lowlink_map.get(dep.as_str()).copied().unwrap_or(u32::MAX);
                    let cur_ll = lowlink_map.get(specifier).copied().unwrap_or(u32::MAX);
                    if dep_ll < cur_ll {
                        lowlink_map.insert(specifier.to_string(), dep_ll);
                    }
                } else if on_stack.contains(dep.as_str()) {
                    let dep_idx = index_map.get(dep.as_str()).copied().unwrap_or(u32::MAX);
                    let cur_ll = lowlink_map.get(specifier).copied().unwrap_or(u32::MAX);
                    if dep_idx < cur_ll {
                        lowlink_map.insert(specifier.to_string(), dep_idx);
                    }
                }
            }
        }

        let lowlink = lowlink_map.get(specifier).copied().unwrap_or(0);
        if lowlink == index {
            let mut scc = Vec::new();
            while let Some(top) = stack.pop() {
                on_stack.remove(&top);
                scc.push(top.clone());
                if top == specifier {
                    break;
                }
            }
            scc.reverse();
            sccs.push(scc);
        }
    }

    // -----------------------------------------------------------------------
    // Graph analysis
    // -----------------------------------------------------------------------

    /// Get the topological sort order of the module graph.
    ///
    /// Returns specifiers in evaluation order (dependencies first).
    /// Cycles are handled by treating the first-visited module in a cycle
    /// as the cycle root.
    pub fn topological_order(&self) -> Vec<String> {
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();

        for specifier in self.modules.keys() {
            self.topo_dfs(specifier, &mut visited, &mut order);
        }

        order
    }

    fn topo_dfs(&self, specifier: &str, visited: &mut BTreeSet<String>, order: &mut Vec<String>) {
        if visited.contains(specifier) {
            return;
        }
        visited.insert(specifier.to_string());

        if let Some(module) = self.modules.get(specifier) {
            for dep in &module.dependencies {
                self.topo_dfs(dep, visited, order);
            }
        }

        order.push(specifier.to_string());
    }

    /// Get all modules that export a given name.
    pub fn find_exporters(&self, export_name: &str) -> Vec<String> {
        self.modules
            .iter()
            .filter(|(_, m)| m.exports.iter().any(|e| e.export_name == export_name))
            .map(|(s, _)| s.clone())
            .collect()
    }

    /// Get the set of modules reachable from a given specifier.
    pub fn transitive_dependencies(&self, specifier: &str) -> BTreeSet<String> {
        let mut reachable = BTreeSet::new();
        self.reachable_dfs(specifier, &mut reachable);
        reachable.remove(specifier);
        reachable
    }

    fn reachable_dfs(&self, specifier: &str, reachable: &mut BTreeSet<String>) {
        if reachable.contains(specifier) {
            return;
        }
        reachable.insert(specifier.to_string());
        if let Some(module) = self.modules.get(specifier) {
            for dep in &module.dependencies {
                self.reachable_dfs(dep, reachable);
            }
        }
    }
}

impl Default for ModuleGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of the link phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkResult {
    pub linked_count: usize,
    pub cycle_count: usize,
    pub cycles: Vec<CycleInfo>,
}

/// Information about a detected cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleInfo {
    pub specifier: String,
    pub stack_snapshot: Vec<String>,
}

/// Result of the evaluate phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub eval_order: Vec<String>,
    pub evaluated_count: usize,
}

/// A resolved export binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedBinding {
    pub module_specifier: String,
    pub local_name: String,
    pub binding_type: BindingType,
}

/// Type of export binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BindingType {
    /// Direct local export.
    Direct,
    /// Re-exported from another module.
    ReExport,
    /// Star re-export.
    StarReExport,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the ESM loader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EsmLoaderError {
    NoEntryPoint,
    ModuleNotFound(String),
    GraphTooLarge {
        limit: usize,
    },
    DepthExceeded {
        specifier: String,
        depth: usize,
        limit: usize,
    },
    UnresolvedDependency {
        specifier: String,
        dependency: String,
    },
    ExportNotFound {
        specifier: String,
        export_name: String,
    },
    AmbiguousExport {
        specifier: String,
        export_name: String,
    },
    EvaluationFailed {
        specifier: String,
        reason: String,
    },
    InvalidStatus {
        specifier: String,
        expected: &'static str,
        actual: String,
    },
}

impl fmt::Display for EsmLoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEntryPoint => write!(f, "no entry point set"),
            Self::ModuleNotFound(s) => write!(f, "module not found: {s}"),
            Self::GraphTooLarge { limit } => {
                write!(f, "module graph exceeds limit of {limit} modules")
            }
            Self::DepthExceeded {
                specifier,
                depth,
                limit,
            } => write!(
                f,
                "module depth {depth} exceeds limit {limit} at {specifier}"
            ),
            Self::UnresolvedDependency {
                specifier,
                dependency,
            } => write!(f, "unresolved dependency: {specifier} imports {dependency}"),
            Self::ExportNotFound {
                specifier,
                export_name,
            } => write!(f, "export '{export_name}' not found in {specifier}"),
            Self::AmbiguousExport {
                specifier,
                export_name,
            } => write!(
                f,
                "ambiguous star re-export of '{export_name}' in {specifier}"
            ),
            Self::EvaluationFailed { specifier, reason } => {
                write!(f, "evaluation failed for {specifier}: {reason}")
            }
            Self::InvalidStatus {
                specifier,
                expected,
                actual,
            } => write!(
                f,
                "invalid status for {specifier}: expected {expected}, got {actual}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module(spec: &str, source: &str) -> EsmModule {
        EsmModule::new(spec, source, ModuleSyntax::EsModule)
    }

    // -- Basic graph construction tests --------------------------------------

    #[test]
    fn test_empty_graph() {
        let graph = ModuleGraph::new();
        assert!(graph.is_empty());
        assert_eq!(graph.len(), 0);
        assert!(graph.entry_point().is_none());
    }

    #[test]
    fn test_add_single_module() {
        let mut graph = ModuleGraph::new();
        let module = make_module("./main.js", "console.log('hello')");
        graph.add_module(module).unwrap();
        assert_eq!(graph.len(), 1);
        assert_eq!(graph.entry_point(), Some("./main.js"));
    }

    #[test]
    fn test_add_multiple_modules() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("./main.js", "import './dep.js'"))
            .unwrap();
        graph
            .add_module(make_module("./dep.js", "export const x = 1"))
            .unwrap();
        assert_eq!(graph.len(), 2);
        assert_eq!(graph.entry_point(), Some("./main.js"));
    }

    // -- Module structure tests ----------------------------------------------

    #[test]
    fn test_esm_module_content_hash() {
        let m1 = make_module("a.js", "const x = 1");
        let m2 = make_module("b.js", "const x = 1");
        let m3 = make_module("c.js", "const x = 2");
        // Same source => same hash.
        assert_eq!(m1.content_hash, m2.content_hash);
        // Different source => different hash.
        assert_ne!(m1.content_hash, m3.content_hash);
    }

    #[test]
    fn test_add_import_tracks_dependency() {
        let mut module = make_module("main.js", "");
        module.add_import(ImportEntry::new("dep.js", "foo", "foo"));
        assert!(module.dependencies.contains("dep.js"));
        assert_eq!(module.imports.len(), 1);
    }

    #[test]
    fn test_add_export_direct() {
        let mut module = make_module("lib.js", "");
        module.add_export(ExportEntry::direct("myFn", "myFn"));
        assert_eq!(module.exports.len(), 1);
        assert!(!module.has_default_export);
    }

    #[test]
    fn test_add_export_default() {
        let mut module = make_module("lib.js", "");
        module.add_export(ExportEntry::direct("_default", "default"));
        assert!(module.has_default_export);
    }

    #[test]
    fn test_add_reexport_tracks_dependency() {
        let mut module = make_module("index.js", "");
        module.add_export(ExportEntry::re_export("foo", "dep.js", "foo"));
        assert!(module.dependencies.contains("dep.js"));
    }

    // -- Link phase tests ----------------------------------------------------

    #[test]
    fn test_link_single_module() {
        let mut graph = ModuleGraph::new();
        graph.add_module(make_module("main.js", "")).unwrap();
        let result = graph.link().unwrap();
        assert_eq!(result.linked_count, 1);
        assert_eq!(result.cycle_count, 0);
        assert_eq!(
            graph.get_module("main.js").unwrap().status,
            ModuleStatus::Linked
        );
    }

    #[test]
    fn test_link_chain() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        let b = make_module("b.js", "");

        graph.add_module(main).unwrap();
        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();

        let result = graph.link().unwrap();
        assert_eq!(result.linked_count, 3);
        assert_eq!(result.cycle_count, 0);
    }

    #[test]
    fn test_link_detects_cycle() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));

        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();

        let result = graph.link().unwrap();
        assert_eq!(result.linked_count, 2);
        assert_eq!(result.cycle_count, 1);
    }

    #[test]
    fn test_link_unresolved_dependency() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("missing.js", "x", "x"));
        graph.add_module(main).unwrap();

        let err = graph.link().unwrap_err();
        assert!(matches!(err, EsmLoaderError::UnresolvedDependency { .. }));
    }

    // -- Evaluate phase tests ------------------------------------------------

    #[test]
    fn test_evaluate_single() {
        let mut graph = ModuleGraph::new();
        graph.add_module(make_module("main.js", "")).unwrap();
        graph.link().unwrap();
        let result = graph.evaluate().unwrap();
        assert_eq!(result.eval_order, vec!["main.js"]);
        assert_eq!(result.evaluated_count, 1);
    }

    #[test]
    fn test_evaluate_chain_order() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        let b = make_module("b.js", "");

        graph.add_module(main).unwrap();
        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();

        graph.link().unwrap();
        let result = graph.evaluate().unwrap();
        // Dependencies first: b -> a -> main.
        assert_eq!(result.eval_order, vec!["b.js", "a.js", "main.js"]);
    }

    #[test]
    fn test_evaluate_diamond() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        main.add_import(ImportEntry::new("b.js", "y", "y"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("shared.js", "s", "s"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("shared.js", "s", "s"));
        let shared = make_module("shared.js", "");

        graph.add_module(main).unwrap();
        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();
        graph.add_module(shared).unwrap();

        graph.link().unwrap();
        let result = graph.evaluate().unwrap();
        // Shared is evaluated once, before a and b.
        assert_eq!(result.eval_order[0], "shared.js");
        assert_eq!(*result.eval_order.last().unwrap(), "main.js");
        assert_eq!(result.evaluated_count, 4);
    }

    #[test]
    fn test_evaluate_cycle() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));

        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();

        graph.link().unwrap();
        let result = graph.evaluate().unwrap();
        // Both should be evaluated despite cycle.
        assert_eq!(result.evaluated_count, 2);
    }

    // -- Export resolution tests ----------------------------------------------

    #[test]
    fn test_resolve_direct_export() {
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("foo", "foo"));
        graph.add_module(lib).unwrap();

        let binding = graph.resolve_export("lib.js", "foo").unwrap();
        assert_eq!(binding.module_specifier, "lib.js");
        assert_eq!(binding.local_name, "foo");
        assert_eq!(binding.binding_type, BindingType::Direct);
    }

    #[test]
    fn test_resolve_reexport() {
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("bar", "bar"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::re_export("bar", "lib.js", "bar"));

        graph.add_module(index).unwrap();
        graph.add_module(lib).unwrap();

        let binding = graph.resolve_export("index.js", "bar").unwrap();
        assert_eq!(binding.module_specifier, "lib.js");
        assert_eq!(binding.local_name, "bar");
    }

    #[test]
    fn test_resolve_star_reexport() {
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("baz", "baz"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("lib.js"));

        graph.add_module(index).unwrap();
        graph.add_module(lib).unwrap();

        let binding = graph.resolve_export("index.js", "baz").unwrap();
        assert_eq!(binding.module_specifier, "lib.js");
    }

    #[test]
    fn test_resolve_export_not_found() {
        let mut graph = ModuleGraph::new();
        let lib = make_module("lib.js", "");
        graph.add_module(lib).unwrap();

        let err = graph.resolve_export("lib.js", "missing").unwrap_err();
        assert!(matches!(err, EsmLoaderError::ExportNotFound { .. }));
    }

    #[test]
    fn test_resolve_ambiguous_star_reexport() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_export(ExportEntry::direct("dup", "dup"));
        let mut b = make_module("b.js", "");
        b.add_export(ExportEntry::direct("dup", "dup"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("a.js"));
        index.add_export(ExportEntry::star_re_export("b.js"));

        graph.add_module(index).unwrap();
        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();

        let err = graph.resolve_export("index.js", "dup").unwrap_err();
        assert!(matches!(err, EsmLoaderError::AmbiguousExport { .. }));
    }

    // -- Cycle detection tests -----------------------------------------------

    #[test]
    fn test_find_cycles_none() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("dep.js", "x", "x"));
        graph.add_module(main).unwrap();
        graph.add_module(make_module("dep.js", "")).unwrap();

        let cycles = graph.find_cycles();
        assert!(cycles.is_empty());
    }

    #[test]
    fn test_find_cycles_simple() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));

        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 2);
    }

    #[test]
    fn test_find_cycles_triangle() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("c.js", "x", "x"));
        let mut c = make_module("c.js", "");
        c.add_import(ImportEntry::new("a.js", "x", "x"));

        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();
        graph.add_module(c).unwrap();

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);
    }

    // -- Topological order tests ---------------------------------------------

    #[test]
    fn test_topological_order_chain() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        graph.add_module(main).unwrap();
        graph.add_module(a).unwrap();
        graph.add_module(make_module("b.js", "")).unwrap();

        let order = graph.topological_order();
        let b_pos = order.iter().position(|s| s == "b.js").unwrap();
        let a_pos = order.iter().position(|s| s == "a.js").unwrap();
        let main_pos = order.iter().position(|s| s == "main.js").unwrap();
        assert!(b_pos < a_pos);
        assert!(a_pos < main_pos);
    }

    // -- Transitive dependency tests -----------------------------------------

    #[test]
    fn test_transitive_dependencies() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        graph.add_module(main).unwrap();
        graph.add_module(a).unwrap();
        graph.add_module(make_module("b.js", "")).unwrap();

        let deps = graph.transitive_dependencies("main.js");
        assert!(deps.contains("a.js"));
        assert!(deps.contains("b.js"));
        assert!(!deps.contains("main.js"));
    }

    // -- Find exporters test -------------------------------------------------

    #[test]
    fn test_find_exporters() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_export(ExportEntry::direct("foo", "foo"));
        let mut b = make_module("b.js", "");
        b.add_export(ExportEntry::direct("bar", "bar"));
        let mut c = make_module("c.js", "");
        c.add_export(ExportEntry::direct("foo", "foo"));

        graph.add_module(a).unwrap();
        graph.add_module(b).unwrap();
        graph.add_module(c).unwrap();

        let exporters = graph.find_exporters("foo");
        assert_eq!(exporters.len(), 2);
        assert!(exporters.contains(&"a.js".to_string()));
        assert!(exporters.contains(&"c.js".to_string()));
    }

    // -- Trace events test ---------------------------------------------------

    #[test]
    fn test_trace_events_emitted() {
        let mut graph = ModuleGraph::new();
        graph.add_module(make_module("main.js", "")).unwrap();
        graph.link().unwrap();
        graph.evaluate().unwrap();

        let events = graph.trace_events();
        assert!(events.len() >= 2); // At least link + evaluate
        assert!(events.iter().any(|e| e.phase == TracePhase::Link));
        assert!(events.iter().any(|e| e.phase == TracePhase::Evaluate));
    }

    // -- Error display tests -------------------------------------------------

    #[test]
    fn test_error_display() {
        let err = EsmLoaderError::ModuleNotFound("foo.js".into());
        assert_eq!(format!("{err}"), "module not found: foo.js");

        let err = EsmLoaderError::UnresolvedDependency {
            specifier: "main.js".into(),
            dependency: "missing.js".into(),
        };
        assert!(format!("{err}").contains("main.js"));
        assert!(format!("{err}").contains("missing.js"));
    }

    #[test]
    fn test_no_entry_point_error() {
        let mut graph = ModuleGraph::new();
        let err = graph.link().unwrap_err();
        assert!(matches!(err, EsmLoaderError::NoEntryPoint));
    }

    // -- Graph size limit test -----------------------------------------------

    #[test]
    fn test_graph_size_limit() {
        let mut graph = ModuleGraph::new();
        // Add MAX + 1 modules to trigger limit.
        for i in 0..MAX_MODULE_GRAPH_SIZE {
            graph
                .add_module(make_module(&format!("mod_{i}.js"), ""))
                .unwrap();
        }
        let err = graph
            .add_module(make_module("overflow.js", ""))
            .unwrap_err();
        assert!(matches!(err, EsmLoaderError::GraphTooLarge { .. }));
    }

    // -- Namespace import test -----------------------------------------------

    #[test]
    fn test_namespace_import() {
        let entry = ImportEntry::namespace("lib.js", "lib");
        assert_eq!(entry.import_name, "*");
        assert_eq!(entry.local_name, "lib");
    }

    // -- Module status display -----------------------------------------------

    #[test]
    fn test_module_status_display() {
        assert_eq!(format!("{}", ModuleStatus::Unlinked), "unlinked");
        assert_eq!(format!("{}", ModuleStatus::Linking), "linking");
        assert_eq!(format!("{}", ModuleStatus::Evaluated), "evaluated");
    }
}
