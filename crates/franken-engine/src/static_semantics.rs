//! ES2020 static-semantics enforcement (early errors, scope resolution, binding validation).
//!
//! This module validates an AST (IR0 `SyntaxTree`) before lowering to IR1.
//! It catches early errors per the ES2020 spec and builds the scope/binding
//! resolution map that feeds into IR1 `SpecIR`.
//!
//! # Covered checks
//!
//! - Duplicate `let`/`const` bindings in the same scope
//! - `const` declarations without initializer
//! - `import`/`export` only in module goal
//! - `import`/`export` not nested inside non-top-level contexts
//! - Duplicate `export` names
//! - `await` outside async context
//! - TDZ violations for `let`/`const` (use-before-declare detection)
//! - Name collision between `let`/`const` and `var` in same scope
//! - Empty declarator list
//! - Strict-mode reserved words used as bindings

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ast::{
    ExportKind, Expression, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind,
};
use crate::deterministic_serde::CanonicalValue;
use crate::ir_contract::{BindingId, BindingKind, ResolvedBinding, ScopeId, ScopeKind, ScopeNode};

// ---------------------------------------------------------------------------
// Contract constants
// ---------------------------------------------------------------------------

/// Schema version for static-semantics analysis artifacts.
pub const STATIC_SEMANTICS_CONTRACT_VERSION: &str = "franken-engine.static-semantics.contract.v1";

/// Bead reference for this module.
pub const STATIC_SEMANTICS_BEAD_ID: &str = "bd-1lsy.2.2";

/// Component identifier for structured logging.
pub const STATIC_SEMANTICS_COMPONENT: &str = "static_semantics";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Classification of static-semantic errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StaticErrorKind {
    /// Duplicate `let`/`const` binding in same scope.
    DuplicateBinding,
    /// `const` declaration with no initializer.
    ConstWithoutInitializer,
    /// `import` statement in Script goal.
    ImportInScript,
    /// `export` statement in Script goal.
    ExportInScript,
    /// Duplicate export name.
    DuplicateExport,
    /// `await` expression outside async context.
    AwaitOutsideAsync,
    /// Reference to a `let`/`const` binding before its declaration (TDZ).
    TemporalDeadZone,
    /// Collision between `let`/`const` and `var` binding with same name.
    LexicalVarCollision,
    /// Empty declarator list in variable declaration.
    EmptyDeclaratorList,
    /// Reserved word used as binding name in strict mode.
    ReservedWordBinding,
    /// Redeclaration of an import binding.
    ImportRedeclaration,
}

impl StaticErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateBinding => "duplicate_binding",
            Self::ConstWithoutInitializer => "const_without_initializer",
            Self::ImportInScript => "import_in_script",
            Self::ExportInScript => "export_in_script",
            Self::DuplicateExport => "duplicate_export",
            Self::AwaitOutsideAsync => "await_outside_async",
            Self::TemporalDeadZone => "temporal_dead_zone",
            Self::LexicalVarCollision => "lexical_var_collision",
            Self::EmptyDeclaratorList => "empty_declarator_list",
            Self::ReservedWordBinding => "reserved_word_binding",
            Self::ImportRedeclaration => "import_redeclaration",
        }
    }

    /// Stable diagnostic code for structured logging.
    pub fn diagnostic_code(self) -> &'static str {
        match self {
            Self::DuplicateBinding => "FE-STATIC-DIAG-DUP-BINDING-0001",
            Self::ConstWithoutInitializer => "FE-STATIC-DIAG-CONST-INIT-0002",
            Self::ImportInScript => "FE-STATIC-DIAG-IMPORT-SCRIPT-0003",
            Self::ExportInScript => "FE-STATIC-DIAG-EXPORT-SCRIPT-0004",
            Self::DuplicateExport => "FE-STATIC-DIAG-DUP-EXPORT-0005",
            Self::AwaitOutsideAsync => "FE-STATIC-DIAG-AWAIT-ASYNC-0006",
            Self::TemporalDeadZone => "FE-STATIC-DIAG-TDZ-0007",
            Self::LexicalVarCollision => "FE-STATIC-DIAG-LEX-VAR-0008",
            Self::EmptyDeclaratorList => "FE-STATIC-DIAG-EMPTY-DECL-0009",
            Self::ReservedWordBinding => "FE-STATIC-DIAG-RESERVED-0010",
            Self::ImportRedeclaration => "FE-STATIC-DIAG-IMPORT-REDECL-0011",
        }
    }
}

impl std::fmt::Display for StaticErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single static-semantic error with location and descriptive message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticError {
    pub kind: StaticErrorKind,
    pub message: String,
    pub span: SourceSpan,
}

impl StaticError {
    pub fn new(kind: StaticErrorKind, message: impl Into<String>, span: SourceSpan) -> Self {
        Self {
            kind,
            message: message.into(),
            span,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "diagnostic_code".to_string(),
            CanonicalValue::String(self.kind.diagnostic_code().to_string()),
        );
        map.insert(
            "kind".to_string(),
            CanonicalValue::String(self.kind.as_str().to_string()),
        );
        map.insert(
            "message".to_string(),
            CanonicalValue::String(self.message.clone()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

impl std::fmt::Display for StaticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} (line {}:{})",
            self.kind.diagnostic_code(),
            self.message,
            self.span.start_line,
            self.span.start_column,
        )
    }
}

// ---------------------------------------------------------------------------
// Analysis output
// ---------------------------------------------------------------------------

/// Result of static-semantic analysis: scope tree + binding map + errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    /// Resolved scope tree (ready for IR1 consumption).
    pub scopes: Vec<ScopeNode>,
    /// All resolved bindings indexed by `BindingId`.
    pub bindings: Vec<ResolvedBinding>,
    /// Collected errors (empty means analysis passed).
    pub errors: Vec<StaticError>,
    /// Whether the tree was analyzed in module goal.
    pub is_module: bool,
}

impl StaticAnalysisResult {
    pub fn passed(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "bindings".to_string(),
            CanonicalValue::Array(
                self.bindings
                    .iter()
                    .map(ResolvedBinding::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "errors".to_string(),
            CanonicalValue::Array(
                self.errors
                    .iter()
                    .map(StaticError::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "is_module".to_string(),
            CanonicalValue::Bool(self.is_module),
        );
        map.insert(
            "scopes".to_string(),
            CanonicalValue::Array(self.scopes.iter().map(ScopeNode::canonical_value).collect()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Strict-mode reserved words
// ---------------------------------------------------------------------------

/// ES2020 strict-mode reserved words that cannot be used as binding names.
const STRICT_RESERVED_WORDS: &[&str] = &[
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "yield",
];

/// ES2020 keywords that cannot appear as binding identifiers.
const KEYWORD_BINDINGS: &[&str] = &[
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
];

fn is_reserved_binding(name: &str, is_module: bool) -> bool {
    // Module code is always strict
    if is_module && STRICT_RESERVED_WORDS.contains(&name) {
        return true;
    }
    KEYWORD_BINDINGS.contains(&name)
}

// ---------------------------------------------------------------------------
// Analyzer state
// ---------------------------------------------------------------------------

struct AnalyzerState {
    scopes: Vec<ScopeNode>,
    bindings: Vec<ResolvedBinding>,
    errors: Vec<StaticError>,
    is_module: bool,
    next_binding_id: BindingId,
    next_scope_index: u32,
    /// Export names seen so far (for duplicate detection).
    export_names: BTreeSet<String>,
    /// Import bindings (name -> span) for redeclaration detection.
    import_bindings: BTreeMap<String, SourceSpan>,
}

impl AnalyzerState {
    fn new(is_module: bool) -> Self {
        Self {
            scopes: Vec::new(),
            bindings: Vec::new(),
            errors: Vec::new(),
            is_module,
            next_binding_id: 0,
            next_scope_index: 0,
            export_names: BTreeSet::new(),
            import_bindings: BTreeMap::new(),
        }
    }

    fn alloc_binding_id(&mut self) -> BindingId {
        let id = self.next_binding_id;
        self.next_binding_id += 1;
        id
    }

    fn alloc_scope_id(&mut self, depth: u32) -> ScopeId {
        let id = ScopeId {
            depth,
            index: self.next_scope_index,
        };
        self.next_scope_index += 1;
        id
    }

    fn push_error(&mut self, kind: StaticErrorKind, message: impl Into<String>, span: SourceSpan) {
        self.errors.push(StaticError::new(kind, message, span));
    }
}

// ---------------------------------------------------------------------------
// Core analysis
// ---------------------------------------------------------------------------

/// Run static-semantic analysis on an IR0 syntax tree.
///
/// Returns a `StaticAnalysisResult` with scope tree, bindings, and any errors.
/// The caller should check `result.passed()` before proceeding to lowering.
pub fn analyze(tree: &SyntaxTree) -> StaticAnalysisResult {
    let is_module = tree.goal == ParseGoal::Module;
    let mut state = AnalyzerState::new(is_module);

    // Create top-level scope
    let top_scope_kind = if is_module {
        ScopeKind::Module
    } else {
        ScopeKind::Global
    };
    let top_scope_id = state.alloc_scope_id(0);

    // First pass: collect declarations in top scope
    let mut top_bindings: Vec<ResolvedBinding> = Vec::new();
    // Track names to detect duplicates
    let mut lexical_names: BTreeMap<String, SourceSpan> = BTreeMap::new();
    let mut var_names: BTreeMap<String, SourceSpan> = BTreeMap::new();

    for stmt in &tree.body {
        analyze_statement(
            &mut state,
            stmt,
            top_scope_id,
            &mut top_bindings,
            &mut lexical_names,
            &mut var_names,
        );
    }

    // Second pass: detect TDZ violations in expression statements
    let declared_before: BTreeSet<String> = BTreeSet::new();
    detect_tdz_violations(&mut state, &tree.body, &declared_before);

    let top_scope = ScopeNode {
        scope_id: top_scope_id,
        parent: None,
        kind: top_scope_kind,
        bindings: top_bindings.clone(),
    };
    state.scopes.push(top_scope);
    state.bindings.extend(top_bindings);

    StaticAnalysisResult {
        scopes: state.scopes,
        bindings: state.bindings,
        errors: state.errors,
        is_module,
    }
}

fn analyze_statement(
    state: &mut AnalyzerState,
    stmt: &Statement,
    scope_id: ScopeId,
    bindings: &mut Vec<ResolvedBinding>,
    lexical_names: &mut BTreeMap<String, SourceSpan>,
    var_names: &mut BTreeMap<String, SourceSpan>,
) {
    match stmt {
        Statement::Import(import) => {
            // Import only valid in Module goal
            if !state.is_module {
                state.push_error(
                    StaticErrorKind::ImportInScript,
                    "import declarations are only allowed in module code",
                    import.span.clone(),
                );
            }

            // Register import binding if present
            if let Some(ref binding_name) = import.binding {
                check_reserved(state, binding_name, &import.span);

                // Check for duplicate import binding
                if let Some(prev_span) = state.import_bindings.get(binding_name) {
                    state.push_error(
                        StaticErrorKind::ImportRedeclaration,
                        format!(
                            "import binding '{}' already declared at line {}",
                            binding_name, prev_span.start_line
                        ),
                        import.span.clone(),
                    );
                } else {
                    state
                        .import_bindings
                        .insert(binding_name.clone(), import.span.clone());
                }

                // Check for collision with lexical bindings
                if let Some(prev_span) = lexical_names.get(binding_name) {
                    state.push_error(
                        StaticErrorKind::DuplicateBinding,
                        format!(
                            "identifier '{}' already declared as lexical binding at line {}",
                            binding_name, prev_span.start_line
                        ),
                        import.span.clone(),
                    );
                } else {
                    lexical_names.insert(binding_name.clone(), import.span.clone());
                }

                let bid = state.alloc_binding_id();
                bindings.push(ResolvedBinding {
                    name: binding_name.clone(),
                    binding_id: bid,
                    scope: scope_id,
                    kind: BindingKind::Import,
                });
            }
        }

        Statement::Export(export) => {
            // Export only valid in Module goal
            if !state.is_module {
                state.push_error(
                    StaticErrorKind::ExportInScript,
                    "export declarations are only allowed in module code",
                    export.span.clone(),
                );
            }

            // Duplicate export name detection
            match &export.kind {
                ExportKind::Default(_) => {
                    let name = "default".to_string();
                    if !state.export_names.insert(name) {
                        state.push_error(
                            StaticErrorKind::DuplicateExport,
                            "duplicate default export",
                            export.span.clone(),
                        );
                    }
                }
                ExportKind::NamedClause(name) => {
                    if !state.export_names.insert(name.clone()) {
                        state.push_error(
                            StaticErrorKind::DuplicateExport,
                            format!("duplicate export name '{}'", name),
                            export.span.clone(),
                        );
                    }
                }
            }

            // Check for await in export default expression
            if let ExportKind::Default(ref expr) = export.kind {
                check_await_in_expression(state, expr, &export.span);
            }
        }

        Statement::VariableDeclaration(decl) => {
            analyze_variable_declaration(state, decl, scope_id, bindings, lexical_names, var_names);
        }

        Statement::Expression(expr_stmt) => {
            check_await_in_expression(state, &expr_stmt.expression, &expr_stmt.span);
        }
    }
}

fn analyze_variable_declaration(
    state: &mut AnalyzerState,
    decl: &VariableDeclaration,
    scope_id: ScopeId,
    bindings: &mut Vec<ResolvedBinding>,
    lexical_names: &mut BTreeMap<String, SourceSpan>,
    var_names: &mut BTreeMap<String, SourceSpan>,
) {
    // Empty declarator list check
    if decl.declarations.is_empty() {
        state.push_error(
            StaticErrorKind::EmptyDeclaratorList,
            format!("{} declaration has no declarators", decl.kind.as_str()),
            decl.span.clone(),
        );
        return;
    }

    let binding_kind = match decl.kind {
        VariableDeclarationKind::Var => BindingKind::Var,
        VariableDeclarationKind::Let => BindingKind::Let,
        VariableDeclarationKind::Const => BindingKind::Const,
    };

    let is_lexical = matches!(
        decl.kind,
        VariableDeclarationKind::Let | VariableDeclarationKind::Const
    );

    for declarator in &decl.declarations {
        let name = &declarator.name;

        // Reserved word check
        check_reserved(state, name, &declarator.span);

        // const without initializer
        if decl.kind == VariableDeclarationKind::Const && declarator.initializer.is_none() {
            state.push_error(
                StaticErrorKind::ConstWithoutInitializer,
                format!("const declaration '{}' must have an initializer", name),
                declarator.span.clone(),
            );
        }

        if is_lexical {
            // Check duplicate lexical binding
            if let Some(prev_span) = lexical_names.get(name) {
                state.push_error(
                    StaticErrorKind::DuplicateBinding,
                    format!(
                        "identifier '{}' has already been declared at line {}",
                        name, prev_span.start_line
                    ),
                    declarator.span.clone(),
                );
            } else {
                lexical_names.insert(name.clone(), declarator.span.clone());
            }

            // Check collision with var
            if let Some(prev_span) = var_names.get(name) {
                state.push_error(
                    StaticErrorKind::LexicalVarCollision,
                    format!(
                        "lexical binding '{}' collides with var declaration at line {}",
                        name, prev_span.start_line
                    ),
                    declarator.span.clone(),
                );
            }

            // Check collision with import
            if let Some(prev_span) = state.import_bindings.get(name) {
                state.push_error(
                    StaticErrorKind::DuplicateBinding,
                    format!(
                        "identifier '{}' already declared as import binding at line {}",
                        name, prev_span.start_line
                    ),
                    declarator.span.clone(),
                );
            }
        } else {
            // var declaration
            if let Some(prev_span) = lexical_names.get(name) {
                state.push_error(
                    StaticErrorKind::LexicalVarCollision,
                    format!(
                        "var '{}' collides with lexical declaration at line {}",
                        name, prev_span.start_line
                    ),
                    declarator.span.clone(),
                );
            }
            var_names.insert(name.clone(), declarator.span.clone());
        }

        // Check await in initializer
        if let Some(ref init_expr) = declarator.initializer {
            check_await_in_expression(state, init_expr, &declarator.span);
        }

        let bid = state.alloc_binding_id();
        bindings.push(ResolvedBinding {
            name: name.clone(),
            binding_id: bid,
            scope: scope_id,
            kind: binding_kind,
        });
    }
}

fn check_reserved(state: &mut AnalyzerState, name: &str, span: &SourceSpan) {
    if is_reserved_binding(name, state.is_module) {
        state.push_error(
            StaticErrorKind::ReservedWordBinding,
            format!(
                "'{}' is a reserved word and cannot be used as a binding name",
                name
            ),
            span.clone(),
        );
    }
}

fn check_await_in_expression(state: &mut AnalyzerState, expr: &Expression, span: &SourceSpan) {
    // Top-level await is valid in modules; in scripts it's an error
    if let Expression::Await(_) = expr
        && !state.is_module
    {
        state.push_error(
            StaticErrorKind::AwaitOutsideAsync,
            "await is only valid in async functions or module top-level",
            span.clone(),
        );
    }
}

/// Detect TDZ violations: identifier references that appear before `let`/`const`
/// declarations in textual order.
fn detect_tdz_violations(
    state: &mut AnalyzerState,
    body: &[Statement],
    _declared_before: &BTreeSet<String>,
) {
    // Build the set of let/const names with their declaration positions (statement index)
    let mut decl_positions: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, stmt) in body.iter().enumerate() {
        if let Statement::VariableDeclaration(decl) = stmt
            && matches!(
                decl.kind,
                VariableDeclarationKind::Let | VariableDeclarationKind::Const
            )
        {
            for declarator in &decl.declarations {
                decl_positions.entry(declarator.name.clone()).or_insert(idx);
            }
        }
    }

    // Now scan expression statements for references that precede declarations
    for (idx, stmt) in body.iter().enumerate() {
        if let Statement::Expression(expr_stmt) = stmt
            && let Expression::Identifier(name) = &expr_stmt.expression
            && let Some(&decl_idx) = decl_positions.get(name.as_str())
            && idx < decl_idx
        {
            state.push_error(
                StaticErrorKind::TemporalDeadZone,
                format!("cannot access '{}' before initialization", name),
                expr_stmt.span.clone(),
            );
        }

        // Also check initializers of variable declarations
        if let Statement::VariableDeclaration(decl) = stmt {
            for declarator in &decl.declarations {
                if let Some(init_expr) = &declarator.initializer
                    && let Expression::Identifier(name) = init_expr
                    && let Some(&decl_idx) = decl_positions.get(name.as_str())
                    && idx < decl_idx
                {
                    state.push_error(
                        StaticErrorKind::TemporalDeadZone,
                        format!("cannot access '{}' before initialization", name),
                        declarator.span.clone(),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Structured logging event
// ---------------------------------------------------------------------------

/// Structured log event for static-semantic analysis runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticSemanticsEvent {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_count: u64,
    pub binding_count: u64,
    pub scope_count: u64,
    pub is_module: bool,
}

impl StaticSemanticsEvent {
    pub fn from_result(result: &StaticAnalysisResult) -> Self {
        Self {
            component: STATIC_SEMANTICS_COMPONENT.to_string(),
            event: "analysis_complete".to_string(),
            outcome: if result.passed() {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_count: result.errors.len() as u64,
            binding_count: result.bindings.len() as u64,
            scope_count: result.scopes.len() as u64,
            is_module: result.is_module,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "binding_count".to_string(),
            CanonicalValue::U64(self.binding_count),
        );
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "error_count".to_string(),
            CanonicalValue::U64(self.error_count),
        );
        map.insert(
            "event".to_string(),
            CanonicalValue::String(self.event.clone()),
        );
        map.insert(
            "is_module".to_string(),
            CanonicalValue::Bool(self.is_module),
        );
        map.insert(
            "outcome".to_string(),
            CanonicalValue::String(self.outcome.clone()),
        );
        map.insert(
            "scope_count".to_string(),
            CanonicalValue::U64(self.scope_count),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{
        ExportDeclaration, ExportKind, ExpressionStatement, ImportDeclaration, ParseGoal,
        SourceSpan, Statement, SyntaxTree, VariableDeclaration, VariableDeclarationKind,
        VariableDeclarator,
    };

    fn span(line: u64) -> SourceSpan {
        SourceSpan::new(0, 10, line, 1, line, 10)
    }

    fn make_tree(goal: ParseGoal, body: Vec<Statement>) -> SyntaxTree {
        SyntaxTree {
            goal,
            body,
            span: SourceSpan::new(0, 100, 1, 1, 10, 1),
        }
    }

    fn var_decl(
        kind: VariableDeclarationKind,
        name: &str,
        init: Option<Expression>,
        line: u64,
    ) -> Statement {
        Statement::VariableDeclaration(VariableDeclaration {
            kind,
            declarations: vec![VariableDeclarator {
                name: name.to_string(),
                initializer: init,
                span: span(line),
            }],
            span: span(line),
        })
    }

    fn import_stmt(binding: Option<&str>, source: &str, line: u64) -> Statement {
        Statement::Import(ImportDeclaration {
            binding: binding.map(ToString::to_string),
            source: source.to_string(),
            span: span(line),
        })
    }

    fn export_default(expr: Expression, line: u64) -> Statement {
        Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(expr),
            span: span(line),
        })
    }

    fn export_named(name: &str, line: u64) -> Statement {
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(name.to_string()),
            span: span(line),
        })
    }

    fn expr_stmt(expr: Expression, line: u64) -> Statement {
        Statement::Expression(ExpressionStatement {
            expression: expr,
            span: span(line),
        })
    }

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    #[test]
    fn empty_script_passes() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.scopes.len(), 1);
        assert_eq!(result.scopes[0].kind, ScopeKind::Global);
        assert!(!result.is_module);
    }

    #[test]
    fn empty_module_passes() {
        let tree = make_tree(ParseGoal::Module, vec![]);
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.scopes.len(), 1);
        assert_eq!(result.scopes[0].kind, ScopeKind::Module);
        assert!(result.is_module);
    }

    #[test]
    fn single_var_declaration() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(42)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].name, "x");
        assert_eq!(result.bindings[0].kind, BindingKind::Var);
    }

    #[test]
    fn single_let_declaration() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "y",
                Some(Expression::StringLiteral("hello".to_string())),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].name, "y");
        assert_eq!(result.bindings[0].kind, BindingKind::Let);
    }

    #[test]
    fn single_const_with_initializer() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Const,
                "z",
                Some(Expression::BooleanLiteral(true)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].kind, BindingKind::Const);
    }

    #[test]
    fn module_import_and_export() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("foo"), "./foo.js", 1),
                export_named("bar", 2),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 1);
        assert_eq!(result.bindings[0].name, "foo");
        assert_eq!(result.bindings[0].kind, BindingKind::Import);
    }

    #[test]
    fn multiple_var_same_name_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 2);
    }

    #[test]
    fn distinct_let_bindings() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "a",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "b",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 2);
    }

    #[test]
    fn module_with_multiple_named_exports() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                export_named("a", 1),
                export_named("b", 2),
                export_named("c", 3),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn module_default_and_named_exports() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                export_default(Expression::NumericLiteral(42), 1),
                export_named("foo", 2),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn top_level_await_in_module() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![expr_stmt(
                Expression::Await(Box::new(Expression::Identifier("promise".to_string()))),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn expression_statement_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::NumericLiteral(42), 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn import_without_binding() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![import_stmt(None, "./side-effect.js", 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.bindings.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Error: const without initializer
    // -----------------------------------------------------------------------

    #[test]
    fn const_without_initializer() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Const, "x", None, 1)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(
            result.errors[0].kind,
            StaticErrorKind::ConstWithoutInitializer
        );
    }

    #[test]
    fn const_without_initializer_multiple() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(VariableDeclarationKind::Const, "a", None, 1),
                var_decl(VariableDeclarationKind::Const, "b", None, 2),
            ],
        );
        let result = analyze(&tree);
        assert_eq!(result.errors.len(), 2);
        assert!(
            result
                .errors
                .iter()
                .all(|e| e.kind == StaticErrorKind::ConstWithoutInitializer)
        );
    }

    // -----------------------------------------------------------------------
    // Error: duplicate let/const bindings
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_let_binding() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::DuplicateBinding);
    }

    #[test]
    fn duplicate_const_binding() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Const,
                    "y",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Const,
                    "y",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
        );
    }

    #[test]
    fn let_const_collision() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "z",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Const,
                    "z",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
        );
    }

    // -----------------------------------------------------------------------
    // Error: import/export in script
    // -----------------------------------------------------------------------

    #[test]
    fn import_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![import_stmt(Some("foo"), "./foo.js", 1)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::ImportInScript);
    }

    #[test]
    fn export_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![export_default(Expression::NumericLiteral(42), 1)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::ExportInScript);
    }

    #[test]
    fn export_named_in_script() {
        let tree = make_tree(ParseGoal::Script, vec![export_named("foo", 1)]);
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::ExportInScript);
    }

    // -----------------------------------------------------------------------
    // Error: duplicate exports
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_named_export() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![export_named("foo", 1), export_named("foo", 2)],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::DuplicateExport);
    }

    #[test]
    fn duplicate_default_export() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                export_default(Expression::NumericLiteral(1), 1),
                export_default(Expression::NumericLiteral(2), 2),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::DuplicateExport);
    }

    // -----------------------------------------------------------------------
    // Error: await outside async (in Script)
    // -----------------------------------------------------------------------

    #[test]
    fn await_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(
                Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::AwaitOutsideAsync);
    }

    // -----------------------------------------------------------------------
    // Error: lexical/var collision
    // -----------------------------------------------------------------------

    #[test]
    fn let_var_collision() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::LexicalVarCollision)
        );
    }

    #[test]
    fn var_let_collision() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::LexicalVarCollision)
        );
    }

    // -----------------------------------------------------------------------
    // Error: TDZ violation
    // -----------------------------------------------------------------------

    #[test]
    fn tdz_use_before_let() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(Expression::Identifier("x".to_string()), 1),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn tdz_use_before_const() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(Expression::Identifier("y".to_string()), 1),
                var_decl(
                    VariableDeclarationKind::Const,
                    "y",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn no_tdz_for_var() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                expr_stmt(Expression::Identifier("x".to_string()), 1),
                var_decl(
                    VariableDeclarationKind::Var,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        // var declarations are hoisted, no TDZ
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    #[test]
    fn tdz_in_initializer() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "a",
                    Some(Expression::Identifier("b".to_string())),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "b",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
        );
    }

    // -----------------------------------------------------------------------
    // Error: empty declarator list
    // -----------------------------------------------------------------------

    #[test]
    fn empty_declarator_list() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![],
                span: span(1),
            })],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::EmptyDeclaratorList);
    }

    // -----------------------------------------------------------------------
    // Error: reserved words as bindings
    // -----------------------------------------------------------------------

    #[test]
    fn keyword_as_binding() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "class",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::ReservedWordBinding);
    }

    #[test]
    fn strict_reserved_in_module() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "interface",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors[0].kind, StaticErrorKind::ReservedWordBinding);
    }

    #[test]
    fn strict_reserved_allowed_in_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "interface",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    // -----------------------------------------------------------------------
    // Error: import redeclaration
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_import_binding() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("foo"), "./a.js", 1),
                import_stmt(Some("foo"), "./b.js", 2),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ImportRedeclaration)
        );
    }

    #[test]
    fn import_then_let_collision() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("x"), "./x.js", 1),
                var_decl(
                    VariableDeclarationKind::Let,
                    "x",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
        );
    }

    // -----------------------------------------------------------------------
    // Multiple errors in one tree
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_errors_combined() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                import_stmt(Some("a"), "./a.js", 1), // import in script
                var_decl(VariableDeclarationKind::Const, "b", None, 2), // const no init
                var_decl(
                    VariableDeclarationKind::Let,
                    "c",
                    Some(Expression::NumericLiteral(1)),
                    3,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "c",
                    Some(Expression::NumericLiteral(2)),
                    4,
                ), // duplicate let
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert!(result.errors.len() >= 3);
    }

    // -----------------------------------------------------------------------
    // Scope structure
    // -----------------------------------------------------------------------

    #[test]
    fn scope_has_correct_kind_for_script() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        assert_eq!(result.scopes[0].kind, ScopeKind::Global);
    }

    #[test]
    fn scope_has_correct_kind_for_module() {
        let tree = make_tree(ParseGoal::Module, vec![]);
        let result = analyze(&tree);
        assert_eq!(result.scopes[0].kind, ScopeKind::Module);
    }

    #[test]
    fn top_scope_has_no_parent() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        assert!(result.scopes[0].parent.is_none());
    }

    #[test]
    fn bindings_have_incremental_ids() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "a",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "b",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "c",
                    Some(Expression::NumericLiteral(3)),
                    3,
                ),
            ],
        );
        let result = analyze(&tree);
        assert_eq!(result.bindings[0].binding_id, 0);
        assert_eq!(result.bindings[1].binding_id, 1);
        assert_eq!(result.bindings[2].binding_id, 2);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_kind_serde() {
        let kinds = [
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: StaticErrorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn static_error_serde() {
        let err = StaticError::new(StaticErrorKind::DuplicateBinding, "test error", span(5));
        let json = serde_json::to_string(&err).unwrap();
        let back: StaticError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn analysis_result_serde() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        );
        let result = analyze(&tree);
        let json = serde_json::to_string(&result).unwrap();
        let back: StaticAnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // -----------------------------------------------------------------------
    // Display / canonical_value
    // -----------------------------------------------------------------------

    #[test]
    fn static_error_display() {
        let err = StaticError::new(
            StaticErrorKind::ConstWithoutInitializer,
            "const must have init",
            span(3),
        );
        let s = err.to_string();
        assert!(s.contains("FE-STATIC-DIAG-CONST-INIT-0002"));
        assert!(s.contains("const must have init"));
        assert!(s.contains("line 3"));
    }

    #[test]
    fn static_error_kind_display() {
        assert_eq!(
            StaticErrorKind::DuplicateBinding.to_string(),
            "duplicate_binding"
        );
    }

    #[test]
    fn canonical_value_not_empty() {
        let err = StaticError::new(StaticErrorKind::DuplicateBinding, "dup", span(1));
        let cv = err.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("kind"));
            assert!(map.contains_key("message"));
            assert!(map.contains_key("span"));
            assert!(map.contains_key("diagnostic_code"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn analysis_result_canonical_value_keys() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        let cv = result.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("bindings"));
            assert!(map.contains_key("errors"));
            assert!(map.contains_key("is_module"));
            assert!(map.contains_key("scopes"));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // Structured logging event
    // -----------------------------------------------------------------------

    #[test]
    fn event_from_passing_result() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        assert_eq!(event.component, "static_semantics");
        assert_eq!(event.event, "analysis_complete");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_count, 0);
    }

    #[test]
    fn event_from_failing_result() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Const, "x", None, 1)],
        );
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        assert_eq!(event.outcome, "fail");
        assert_eq!(event.error_count, 1);
    }

    #[test]
    fn event_canonical_value_keys() {
        let tree = make_tree(ParseGoal::Script, vec![]);
        let result = analyze(&tree);
        let event = StaticSemanticsEvent::from_result(&result);
        let cv = event.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("component"));
            assert!(map.contains_key("event"));
            assert!(map.contains_key("outcome"));
            assert!(map.contains_key("error_count"));
            assert!(map.contains_key("binding_count"));
            assert!(map.contains_key("scope_count"));
            assert!(map.contains_key("is_module"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn event_serde_round_trip() {
        let event = StaticSemanticsEvent {
            component: "static_semantics".to_string(),
            event: "analysis_complete".to_string(),
            outcome: "pass".to_string(),
            error_count: 0,
            binding_count: 3,
            scope_count: 1,
            is_module: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: StaticSemanticsEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // -----------------------------------------------------------------------
    // Contract constants
    // -----------------------------------------------------------------------

    #[test]
    fn contract_constants_non_empty() {
        assert!(!STATIC_SEMANTICS_CONTRACT_VERSION.is_empty());
        assert!(!STATIC_SEMANTICS_BEAD_ID.is_empty());
        assert!(!STATIC_SEMANTICS_COMPONENT.is_empty());
    }

    // -----------------------------------------------------------------------
    // Diagnostic codes are unique
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostic_codes_are_unique() {
        let kinds = [
            StaticErrorKind::DuplicateBinding,
            StaticErrorKind::ConstWithoutInitializer,
            StaticErrorKind::ImportInScript,
            StaticErrorKind::ExportInScript,
            StaticErrorKind::DuplicateExport,
            StaticErrorKind::AwaitOutsideAsync,
            StaticErrorKind::TemporalDeadZone,
            StaticErrorKind::LexicalVarCollision,
            StaticErrorKind::EmptyDeclaratorList,
            StaticErrorKind::ReservedWordBinding,
            StaticErrorKind::ImportRedeclaration,
        ];
        let codes: BTreeSet<&str> = kinds.iter().map(|k| k.diagnostic_code()).collect();
        assert_eq!(codes.len(), kinds.len(), "diagnostic codes must be unique");
    }

    // -----------------------------------------------------------------------
    // Passed / error_count helpers
    // -----------------------------------------------------------------------

    #[test]
    fn passed_and_error_count() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(VariableDeclarationKind::Const, "a", None, 1),
                var_decl(VariableDeclarationKind::Const, "b", None, 2),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.error_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn let_without_initializer_is_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Let, "x", None, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn var_without_initializer_is_allowed() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Var, "x", None, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn raw_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::Raw("some code".to_string()), 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn null_literal_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::NullLiteral, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn undefined_literal_expression_passes() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![expr_stmt(Expression::UndefinedLiteral, 1)],
        );
        let result = analyze(&tree);
        assert!(result.passed());
    }

    #[test]
    fn await_in_export_default_script() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![export_default(
                Expression::Await(Box::new(Expression::Identifier("p".to_string()))),
                1,
            )],
        );
        let result = analyze(&tree);
        // Both export-in-script and await-outside-async
        assert!(!result.passed());
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::ExportInScript)
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.kind == StaticErrorKind::AwaitOutsideAsync)
        );
    }

    #[test]
    fn is_reserved_binding_covers_keywords() {
        assert!(is_reserved_binding("class", false));
        assert!(is_reserved_binding("function", false));
        assert!(is_reserved_binding("return", false));
        assert!(is_reserved_binding("var", false));
        assert!(is_reserved_binding("const", false));
    }

    #[test]
    fn is_reserved_binding_strict_in_module() {
        assert!(is_reserved_binding("interface", true));
        assert!(is_reserved_binding("implements", true));
        assert!(is_reserved_binding("yield", true));
        assert!(!is_reserved_binding("interface", false));
    }

    #[test]
    fn is_reserved_binding_normal_names() {
        assert!(!is_reserved_binding("foo", false));
        assert!(!is_reserved_binding("bar", true));
        assert!(!is_reserved_binding("myVar", false));
    }

    #[test]
    fn mixed_valid_and_invalid_bindings() {
        let tree = make_tree(
            ParseGoal::Script,
            vec![
                var_decl(
                    VariableDeclarationKind::Let,
                    "validName",
                    Some(Expression::NumericLiteral(1)),
                    1,
                ),
                var_decl(
                    VariableDeclarationKind::Let,
                    "class",
                    Some(Expression::NumericLiteral(2)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(!result.passed());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, StaticErrorKind::ReservedWordBinding);
        // Valid binding still registered
        assert_eq!(result.bindings.len(), 2);
    }

    #[test]
    fn scope_bindings_match_top_level() {
        let tree = make_tree(
            ParseGoal::Module,
            vec![
                import_stmt(Some("a"), "./a.js", 1),
                var_decl(
                    VariableDeclarationKind::Const,
                    "b",
                    Some(Expression::NumericLiteral(1)),
                    2,
                ),
            ],
        );
        let result = analyze(&tree);
        assert!(result.passed());
        assert_eq!(result.scopes[0].bindings.len(), 2);
        assert_eq!(result.scopes[0].bindings[0].name, "a");
        assert_eq!(result.scopes[0].bindings[1].name, "b");
    }
}
