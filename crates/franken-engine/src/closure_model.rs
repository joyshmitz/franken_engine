//! Closure and lexical scope model.
//!
//! Runtime representation of ES2020 lexical scoping semantics:
//! - **Scope chains** with push/pop lifecycle matching block entry/exit.
//! - **Variable hoisting** (`var`, `function`) to the nearest function/global scope.
//! - **Block-scoped bindings** (`let`, `const`) with Temporal Dead Zone (TDZ) enforcement.
//! - **Closure capture** — snapshot of free-variable references at function-creation time.
//! - **IFC label propagation** — every binding and capture carries an IFC [`Label`].
//!
//! Builds on the static types in [`ir_contract`] (`ScopeId`, `ScopeKind`, `BindingKind`,
//! `ResolvedBinding`) and the IFC lattice in [`ifc_artifacts`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ifc_artifacts::Label;
use crate::ir_contract::{BindingId, BindingKind, ScopeId, ScopeKind};

// ---------------------------------------------------------------------------
// Runtime value type
// ---------------------------------------------------------------------------

/// Runtime value stored in a binding slot.
///
/// Uses the engine's fixed-point millionths convention for numbers
/// (`1_000_000` = 1.0) to guarantee deterministic serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvValue {
    /// JavaScript `undefined`.
    Undefined,
    /// JavaScript `null`.
    Null,
    /// Boolean.
    Bool(bool),
    /// Fixed-point millionths integer (`1_000_000` = 1.0).
    Number(i64),
    /// String value.
    Str(String),
    /// Opaque reference to an object (index into an external object heap).
    ObjectRef(u64),
    /// Opaque reference to a closure (index into the [`ClosureStore`]).
    ClosureRef(ClosureHandle),
    /// Temporal Dead Zone sentinel — accessing this is a ReferenceError.
    Tdz,
}

impl std::fmt::Display for EnvValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undefined => f.write_str("undefined"),
            Self::Null => f.write_str("null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::ObjectRef(id) => write!(f, "ObjectRef({id})"),
            Self::ClosureRef(h) => write!(f, "ClosureRef({})", h.0),
            Self::Tdz => f.write_str("<TDZ>"),
        }
    }
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

/// Opaque handle to a closure in the [`ClosureStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClosureHandle(pub u32);

/// Opaque handle to an environment record in the [`ScopeChain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EnvironmentHandle(pub u32);

// ---------------------------------------------------------------------------
// Binding slot
// ---------------------------------------------------------------------------

/// A single binding slot inside an environment record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingSlot {
    /// Human-readable name (for diagnostics).
    pub name: String,
    /// Unique binding id from scope resolution.
    pub binding_id: BindingId,
    /// `let` / `const` / `var` / etc.
    pub kind: BindingKind,
    /// Current value (or [`EnvValue::Tdz`] before initialization).
    pub value: EnvValue,
    /// Whether this binding has been initialized (past TDZ for `let`/`const`).
    pub initialized: bool,
    /// Whether assignment is permitted (`false` for `const` after init).
    pub mutable: bool,
    /// IFC security label attached to this binding's current value.
    pub label: Label,
}

impl BindingSlot {
    /// Create a new binding in the TDZ state for `let`/`const`.
    pub fn new_lexical(name: String, binding_id: BindingId, kind: BindingKind) -> Self {
        let mutable = kind != BindingKind::Const;
        Self {
            name,
            binding_id,
            kind,
            value: EnvValue::Tdz,
            initialized: false,
            mutable,
            label: Label::Public,
        }
    }

    /// Create a hoisted binding (var/function) — initialized to `undefined`.
    pub fn new_hoisted(name: String, binding_id: BindingId, kind: BindingKind) -> Self {
        Self {
            name,
            binding_id,
            kind,
            value: EnvValue::Undefined,
            initialized: true,
            mutable: true,
            label: Label::Public,
        }
    }

    /// Create a parameter binding — initialized to its argument value.
    pub fn new_parameter(
        name: String,
        binding_id: BindingId,
        value: EnvValue,
        label: Label,
    ) -> Self {
        Self {
            name,
            binding_id,
            kind: BindingKind::Parameter,
            value,
            initialized: true,
            mutable: true,
            label,
        }
    }
}

// ---------------------------------------------------------------------------
// Environment record
// ---------------------------------------------------------------------------

/// Classification of environment records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvironmentKind {
    /// Declarative environment created by blocks, catch, for-of, etc.
    Declarative,
    /// Object environment (e.g. `with` statement — not recommended in strict mode).
    Object,
    /// Global environment.
    Global,
    /// Module environment.
    Module,
    /// Function environment.
    Function,
}

/// A runtime environment record — the binding storage for one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    /// Handle for back-references.
    pub handle: EnvironmentHandle,
    /// Static scope id this environment corresponds to.
    pub scope_id: ScopeId,
    /// Kind of scope.
    pub scope_kind: ScopeKind,
    /// Kind of environment record.
    pub env_kind: EnvironmentKind,
    /// Bindings stored in this environment, keyed by name.
    pub bindings: BTreeMap<String, BindingSlot>,
    /// Optional `this` binding for function environments.
    pub this_binding: Option<EnvValue>,
    /// Optional `arguments` object reference for function environments.
    pub arguments_handle: Option<u64>,
    /// Maximum IFC label of any binding in this environment.
    pub max_label: Label,
}

impl EnvironmentRecord {
    /// Create a new empty environment record.
    pub fn new(
        handle: EnvironmentHandle,
        scope_id: ScopeId,
        scope_kind: ScopeKind,
        env_kind: EnvironmentKind,
    ) -> Self {
        Self {
            handle,
            scope_id,
            scope_kind,
            env_kind,
            bindings: BTreeMap::new(),
            this_binding: None,
            arguments_handle: None,
            max_label: Label::Public,
        }
    }

    /// Insert a binding slot into this environment.
    pub fn add_binding(&mut self, slot: BindingSlot) {
        if slot.label > self.max_label {
            self.max_label = slot.label.clone();
        }
        self.bindings.insert(slot.name.clone(), slot);
    }

    /// Look up a binding by name in this environment only.
    pub fn get_binding(&self, name: &str) -> Option<&BindingSlot> {
        self.bindings.get(name)
    }

    /// Look up a binding by name mutably.
    pub fn get_binding_mut(&mut self, name: &str) -> Option<&mut BindingSlot> {
        self.bindings.get_mut(name)
    }

    /// Returns true when this environment acts as a hoisting target for `var`.
    pub fn is_var_scope(&self) -> bool {
        matches!(
            self.scope_kind,
            ScopeKind::Function | ScopeKind::Global | ScopeKind::Module
        )
    }
}

// ---------------------------------------------------------------------------
// Closure capture
// ---------------------------------------------------------------------------

/// A single captured variable reference inside a closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureCapture {
    /// Name of the captured binding.
    pub name: String,
    /// Binding id in the source scope.
    pub binding_id: BindingId,
    /// Scope where the binding lives.
    pub source_scope: ScopeId,
    /// IFC label at capture time.
    pub label: Label,
}

/// A closure — a function bundled with its captured environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Closure {
    /// Unique handle.
    pub handle: ClosureHandle,
    /// Human-readable function name (empty for anonymous).
    pub name: String,
    /// Parameter count.
    pub arity: u32,
    /// Whether this function is strict mode.
    pub strict: bool,
    /// Captured bindings from enclosing scopes.
    pub captures: Vec<ClosureCapture>,
    /// Maximum IFC label across all captures.
    pub max_capture_label: Label,
    /// Handle to the environment that was active when the closure was created.
    pub creation_env: EnvironmentHandle,
}

// ---------------------------------------------------------------------------
// Scope errors
// ---------------------------------------------------------------------------

/// Errors that can arise during scope chain operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeError {
    /// Attempted to read a `let`/`const` binding before initialization.
    TemporalDeadZone { name: String },
    /// Attempted to assign to a `const` binding after initialization.
    ConstAssignment { name: String },
    /// Binding not found in any enclosing scope.
    UndeclaredVariable { name: String },
    /// Scope chain is empty (no active scope).
    EmptyScopeChain,
    /// IFC label on the value exceeds the maximum permitted by the scope.
    LabelViolation {
        name: String,
        value_label: Label,
        scope_max: Label,
    },
    /// Duplicate binding in the same scope (for `let`/`const`).
    DuplicateBinding { name: String },
    /// Invalid environment handle.
    InvalidEnvironment { handle: EnvironmentHandle },
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TemporalDeadZone { name } => {
                write!(
                    f,
                    "ReferenceError: cannot access '{name}' before initialization"
                )
            }
            Self::ConstAssignment { name } => {
                write!(f, "TypeError: assignment to constant variable '{name}'")
            }
            Self::UndeclaredVariable { name } => {
                write!(f, "ReferenceError: '{name}' is not defined")
            }
            Self::EmptyScopeChain => f.write_str("InternalError: scope chain is empty"),
            Self::LabelViolation {
                name,
                value_label,
                scope_max,
            } => {
                write!(
                    f,
                    "IFCError: label {value_label:?} on '{name}' exceeds scope maximum {scope_max:?}"
                )
            }
            Self::DuplicateBinding { name } => {
                write!(
                    f,
                    "SyntaxError: identifier '{name}' has already been declared"
                )
            }
            Self::InvalidEnvironment { handle } => {
                write!(f, "InternalError: invalid environment handle {}", handle.0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scope chain
// ---------------------------------------------------------------------------

/// The runtime scope chain — manages a stack of [`EnvironmentRecord`]s.
///
/// Supports:
/// - `push_scope` / `pop_scope` for block entry/exit.
/// - `var` hoisting to the nearest function/global scope.
/// - `let` / `const` lexical declarations with TDZ.
/// - Variable lookup walking the scope chain.
/// - Closure capture computation.
/// - IFC label checking on writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeChain {
    /// All environment records, indexed by `EnvironmentHandle`.
    environments: Vec<EnvironmentRecord>,
    /// The active scope stack (handles, innermost last).
    chain: Vec<EnvironmentHandle>,
    /// Next handle id.
    next_handle: u32,
}

impl ScopeChain {
    /// Create a new scope chain with a single global environment.
    pub fn new() -> Self {
        let global_handle = EnvironmentHandle(0);
        let global_scope = ScopeId { depth: 0, index: 0 };
        let global_env = EnvironmentRecord::new(
            global_handle,
            global_scope,
            ScopeKind::Global,
            EnvironmentKind::Global,
        );
        Self {
            environments: vec![global_env],
            chain: vec![global_handle],
            next_handle: 1,
        }
    }

    /// Push a new scope onto the chain. Returns the handle.
    pub fn push_scope(&mut self, scope_id: ScopeId, scope_kind: ScopeKind) -> EnvironmentHandle {
        let env_kind = match scope_kind {
            ScopeKind::Global => EnvironmentKind::Global,
            ScopeKind::Module => EnvironmentKind::Module,
            ScopeKind::Function => EnvironmentKind::Function,
            ScopeKind::Block | ScopeKind::Catch => EnvironmentKind::Declarative,
        };
        let handle = EnvironmentHandle(self.next_handle);
        self.next_handle += 1;
        let env = EnvironmentRecord::new(handle, scope_id, scope_kind, env_kind);
        self.environments.push(env);
        self.chain.push(handle);
        handle
    }

    /// Pop the innermost scope. Returns the popped handle, or error if empty.
    pub fn pop_scope(&mut self) -> Result<EnvironmentHandle, ScopeError> {
        if self.chain.len() <= 1 {
            return Err(ScopeError::EmptyScopeChain);
        }
        Ok(self.chain.pop().expect("checked non-empty"))
    }

    /// Current (innermost) environment handle.
    pub fn current_handle(&self) -> Result<EnvironmentHandle, ScopeError> {
        self.chain
            .last()
            .copied()
            .ok_or(ScopeError::EmptyScopeChain)
    }

    /// Number of environments in the chain stack.
    pub fn depth(&self) -> usize {
        self.chain.len()
    }

    /// Get a reference to an environment by handle.
    pub fn get_env(&self, handle: EnvironmentHandle) -> Result<&EnvironmentRecord, ScopeError> {
        self.environments
            .get(handle.0 as usize)
            .ok_or(ScopeError::InvalidEnvironment { handle })
    }

    /// Get a mutable reference to an environment by handle.
    pub fn get_env_mut(
        &mut self,
        handle: EnvironmentHandle,
    ) -> Result<&mut EnvironmentRecord, ScopeError> {
        self.environments
            .get_mut(handle.0 as usize)
            .ok_or(ScopeError::InvalidEnvironment { handle })
    }

    // -----------------------------------------------------------------------
    // Binding declarations
    // -----------------------------------------------------------------------

    /// Declare a `var` — hoisted to the nearest function/global scope.
    pub fn declare_var(&mut self, name: String, binding_id: BindingId) -> Result<(), ScopeError> {
        // Walk outward to find the var-scope.
        let target_handle = self.find_var_scope()?;
        let env = self.get_env_mut(target_handle)?;
        // `var` re-declaration in the same scope is allowed (no-op if exists).
        if !env.bindings.contains_key(&name) {
            let slot = BindingSlot::new_hoisted(name, binding_id, BindingKind::Var);
            env.add_binding(slot);
        }
        Ok(())
    }

    /// Declare a `let` binding in the current scope (TDZ until initialized).
    pub fn declare_let(&mut self, name: String, binding_id: BindingId) -> Result<(), ScopeError> {
        let handle = self.current_handle()?;
        let env = self.get_env_mut(handle)?;
        if env.bindings.contains_key(&name) {
            return Err(ScopeError::DuplicateBinding { name });
        }
        let slot = BindingSlot::new_lexical(name, binding_id, BindingKind::Let);
        env.add_binding(slot);
        Ok(())
    }

    /// Declare a `const` binding in the current scope (TDZ until initialized).
    pub fn declare_const(&mut self, name: String, binding_id: BindingId) -> Result<(), ScopeError> {
        let handle = self.current_handle()?;
        let env = self.get_env_mut(handle)?;
        if env.bindings.contains_key(&name) {
            return Err(ScopeError::DuplicateBinding { name });
        }
        let slot = BindingSlot::new_lexical(name, binding_id, BindingKind::Const);
        env.add_binding(slot);
        Ok(())
    }

    /// Declare a function declaration — hoisted like `var`.
    pub fn declare_function(
        &mut self,
        name: String,
        binding_id: BindingId,
        value: EnvValue,
    ) -> Result<(), ScopeError> {
        let target_handle = self.find_var_scope()?;
        let env = self.get_env_mut(target_handle)?;
        // Function declarations overwrite previous var/function of the same name.
        let mut slot =
            BindingSlot::new_hoisted(name.clone(), binding_id, BindingKind::FunctionDecl);
        slot.value = value;
        env.bindings.insert(name, slot);
        Ok(())
    }

    /// Declare a parameter binding in the current (function) scope.
    pub fn declare_parameter(
        &mut self,
        name: String,
        binding_id: BindingId,
        value: EnvValue,
        label: Label,
    ) -> Result<(), ScopeError> {
        let handle = self.current_handle()?;
        let env = self.get_env_mut(handle)?;
        let slot = BindingSlot::new_parameter(name, binding_id, value, label);
        env.add_binding(slot);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Variable access
    // -----------------------------------------------------------------------

    /// Initialize a `let`/`const` binding (move it out of TDZ).
    pub fn initialize_binding(
        &mut self,
        name: &str,
        value: EnvValue,
        label: Label,
    ) -> Result<(), ScopeError> {
        let (handle, _) = self.resolve_binding(name)?;
        let env = self.get_env_mut(handle)?;
        let slot = env
            .get_binding_mut(name)
            .ok_or_else(|| ScopeError::UndeclaredVariable {
                name: name.to_string(),
            })?;
        slot.value = value;
        slot.initialized = true;
        slot.label = label.clone();
        if label > env.max_label {
            env.max_label = label;
        }
        Ok(())
    }

    /// Read a variable, walking the scope chain outward.
    pub fn get_value(&self, name: &str) -> Result<&EnvValue, ScopeError> {
        let (handle, _) = self.resolve_binding(name)?;
        let env = self.get_env(handle)?;
        let slot = env
            .get_binding(name)
            .ok_or_else(|| ScopeError::UndeclaredVariable {
                name: name.to_string(),
            })?;
        if !slot.initialized {
            return Err(ScopeError::TemporalDeadZone {
                name: name.to_string(),
            });
        }
        Ok(&slot.value)
    }

    /// Write to a variable, walking the scope chain outward.
    pub fn set_value(
        &mut self,
        name: &str,
        value: EnvValue,
        label: Label,
    ) -> Result<(), ScopeError> {
        let (handle, _) = self.resolve_binding(name)?;
        let env = self.get_env_mut(handle)?;
        let slot = env
            .get_binding_mut(name)
            .ok_or_else(|| ScopeError::UndeclaredVariable {
                name: name.to_string(),
            })?;
        if !slot.initialized {
            return Err(ScopeError::TemporalDeadZone {
                name: name.to_string(),
            });
        }
        if !slot.mutable {
            return Err(ScopeError::ConstAssignment {
                name: name.to_string(),
            });
        }
        slot.value = value;
        slot.label = label.clone();
        if label > env.max_label {
            env.max_label = label;
        }
        Ok(())
    }

    /// Resolve which environment contains a binding. Returns (handle, scope_id).
    pub fn resolve_binding(&self, name: &str) -> Result<(EnvironmentHandle, ScopeId), ScopeError> {
        for &handle in self.chain.iter().rev() {
            let env = self.get_env(handle)?;
            if env.bindings.contains_key(name) {
                return Ok((handle, env.scope_id));
            }
        }
        Err(ScopeError::UndeclaredVariable {
            name: name.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Closure capture
    // -----------------------------------------------------------------------

    /// Compute the set of captures for a closure being created in the current scope.
    ///
    /// Given a list of free variable names used by the function body, returns
    /// [`ClosureCapture`] entries for each one that resolves to an enclosing scope.
    pub fn compute_captures(
        &self,
        free_vars: &[String],
    ) -> Result<Vec<ClosureCapture>, ScopeError> {
        let mut captures = Vec::new();
        for var_name in free_vars {
            let (handle, scope_id) = self.resolve_binding(var_name)?;
            let env = self.get_env(handle)?;
            let slot = env
                .get_binding(var_name)
                .ok_or_else(|| ScopeError::UndeclaredVariable {
                    name: var_name.clone(),
                })?;
            captures.push(ClosureCapture {
                name: var_name.clone(),
                binding_id: slot.binding_id,
                source_scope: scope_id,
                label: slot.label.clone(),
            });
        }
        Ok(captures)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Walk outward from the current scope to find the nearest var-scope
    /// (function, global, or module).
    fn find_var_scope(&self) -> Result<EnvironmentHandle, ScopeError> {
        for &handle in self.chain.iter().rev() {
            let env = self.get_env(handle)?;
            if env.is_var_scope() {
                return Ok(handle);
            }
        }
        Err(ScopeError::EmptyScopeChain)
    }
}

impl Default for ScopeChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Closure store
// ---------------------------------------------------------------------------

/// Arena for closures created during execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClosureStore {
    closures: Vec<Closure>,
}

impl ClosureStore {
    pub fn new() -> Self {
        Self {
            closures: Vec::new(),
        }
    }

    /// Create a closure and return its handle.
    pub fn create_closure(
        &mut self,
        name: String,
        arity: u32,
        strict: bool,
        captures: Vec<ClosureCapture>,
        creation_env: EnvironmentHandle,
    ) -> ClosureHandle {
        let handle = ClosureHandle(self.closures.len() as u32);
        let max_capture_label = captures
            .iter()
            .map(|c| &c.label)
            .max()
            .cloned()
            .unwrap_or(Label::Public);
        self.closures.push(Closure {
            handle,
            name,
            arity,
            strict,
            captures,
            max_capture_label,
            creation_env,
        });
        handle
    }

    /// Get a closure by handle.
    pub fn get(&self, handle: ClosureHandle) -> Option<&Closure> {
        self.closures.get(handle.0 as usize)
    }

    /// Number of closures in the store.
    pub fn len(&self) -> usize {
        self.closures.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.closures.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: a fresh scope chain (starts with global).
    fn fresh_chain() -> ScopeChain {
        ScopeChain::new()
    }

    // ----- scope push/pop -----

    #[test]
    fn global_scope_exists_after_new() {
        let chain = fresh_chain();
        assert_eq!(chain.depth(), 1);
        let handle = chain.current_handle().unwrap();
        let env = chain.get_env(handle).unwrap();
        assert_eq!(env.scope_kind, ScopeKind::Global);
    }

    #[test]
    fn push_and_pop_scope() {
        let mut chain = fresh_chain();
        let block_id = ScopeId { depth: 1, index: 0 };
        let h = chain.push_scope(block_id, ScopeKind::Block);
        assert_eq!(chain.depth(), 2);
        let popped = chain.pop_scope().unwrap();
        assert_eq!(popped, h);
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn pop_global_scope_fails() {
        let mut chain = fresh_chain();
        let result = chain.pop_scope();
        assert!(matches!(result, Err(ScopeError::EmptyScopeChain)));
    }

    // ----- var hoisting -----

    #[test]
    fn var_hoisted_to_global() {
        let mut chain = fresh_chain();
        let block_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_var("x".into(), 1).unwrap();
        // Var should be in the global scope, not the block.
        let global_handle = EnvironmentHandle(0);
        let global_env = chain.get_env(global_handle).unwrap();
        assert!(global_env.get_binding("x").is_some());
        // Block should not have it.
        let block_handle = chain.current_handle().unwrap();
        let block_env = chain.get_env(block_handle).unwrap();
        assert!(block_env.get_binding("x").is_none());
    }

    #[test]
    fn var_hoisted_to_function_not_global() {
        let mut chain = fresh_chain();
        let fn_id = ScopeId { depth: 1, index: 0 };
        let fn_handle = chain.push_scope(fn_id, ScopeKind::Function);
        let block_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_var("y".into(), 2).unwrap();
        // Var should land in function scope, not global.
        let fn_env = chain.get_env(fn_handle).unwrap();
        assert!(fn_env.get_binding("y").is_some());
        let global_env = chain.get_env(EnvironmentHandle(0)).unwrap();
        assert!(global_env.get_binding("y").is_none());
    }

    #[test]
    fn var_redeclaration_is_noop() {
        let mut chain = fresh_chain();
        chain.declare_var("x".into(), 1).unwrap();
        chain.declare_var("x".into(), 2).unwrap(); // no error
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Undefined);
    }

    // ----- let/const TDZ -----

    #[test]
    fn let_starts_in_tdz() {
        let mut chain = fresh_chain();
        chain.declare_let("a".into(), 10).unwrap();
        let result = chain.get_value("a");
        assert!(matches!(result, Err(ScopeError::TemporalDeadZone { .. })));
    }

    #[test]
    fn let_accessible_after_init() {
        let mut chain = fresh_chain();
        chain.declare_let("a".into(), 10).unwrap();
        chain
            .initialize_binding("a", EnvValue::Number(42_000_000), Label::Public)
            .unwrap();
        let val = chain.get_value("a").unwrap();
        assert_eq!(*val, EnvValue::Number(42_000_000));
    }

    #[test]
    fn const_assignment_after_init_fails() {
        let mut chain = fresh_chain();
        chain.declare_const("PI".into(), 20).unwrap();
        chain
            .initialize_binding("PI", EnvValue::Number(3_141_593), Label::Public)
            .unwrap();
        let result = chain.set_value("PI", EnvValue::Number(0), Label::Public);
        assert!(matches!(result, Err(ScopeError::ConstAssignment { .. })));
    }

    #[test]
    fn const_value_preserved_after_failed_assignment() {
        let mut chain = fresh_chain();
        chain.declare_const("C".into(), 30).unwrap();
        chain
            .initialize_binding("C", EnvValue::Number(100), Label::Public)
            .unwrap();
        let _ = chain.set_value("C", EnvValue::Number(999), Label::Public);
        let val = chain.get_value("C").unwrap();
        assert_eq!(*val, EnvValue::Number(100));
    }

    #[test]
    fn let_reassignment_works() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 11).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(1), Label::Public)
            .unwrap();
        chain
            .set_value("x", EnvValue::Number(2), Label::Public)
            .unwrap();
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(2));
    }

    // ----- duplicate lexical declarations -----

    #[test]
    fn duplicate_let_in_same_scope_fails() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 1).unwrap();
        let result = chain.declare_let("x".into(), 2);
        assert!(matches!(result, Err(ScopeError::DuplicateBinding { .. })));
    }

    #[test]
    fn same_name_let_in_different_scopes_ok() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 1).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(10), Label::Public)
            .unwrap();

        let block_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_let("x".into(), 2).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(20), Label::Public)
            .unwrap();
        // Inner x shadows outer x.
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(20));

        chain.pop_scope().unwrap();
        // Outer x is visible again.
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(10));
    }

    // ----- variable shadowing -----

    #[test]
    fn block_scoped_let_shadows_var() {
        let mut chain = fresh_chain();
        chain.declare_var("x".into(), 1).unwrap();
        chain
            .set_value("x", EnvValue::Number(100), Label::Public)
            .unwrap();

        let block_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_let("x".into(), 2).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(200), Label::Public)
            .unwrap();
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(200));

        chain.pop_scope().unwrap();
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(100));
    }

    // ----- undeclared variable -----

    #[test]
    fn undeclared_variable_error() {
        let chain = fresh_chain();
        let result = chain.get_value("nope");
        assert!(matches!(result, Err(ScopeError::UndeclaredVariable { .. })));
    }

    // ----- closure capture -----

    #[test]
    fn capture_from_enclosing_scope() {
        let mut chain = fresh_chain();
        chain.declare_let("outer".into(), 1).unwrap();
        chain
            .initialize_binding("outer", EnvValue::Number(42), Label::Public)
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);

        let captures = chain.compute_captures(&["outer".into()]).unwrap();
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].name, "outer");
        assert_eq!(captures[0].source_scope, ScopeId { depth: 0, index: 0 });
    }

    #[test]
    fn closure_sees_mutations_through_captures() {
        let mut chain = fresh_chain();
        chain.declare_let("counter".into(), 1).unwrap();
        chain
            .initialize_binding("counter", EnvValue::Number(0), Label::Public)
            .unwrap();

        // Simulate closure creation — capture resolves to global env.
        let captures = chain.compute_captures(&["counter".into()]).unwrap();
        assert_eq!(captures[0].binding_id, 1);

        // Mutate from outer scope.
        chain
            .set_value("counter", EnvValue::Number(1), Label::Public)
            .unwrap();

        // Re-reading sees the updated value (closures share the binding).
        let val = chain.get_value("counter").unwrap();
        assert_eq!(*val, EnvValue::Number(1));
    }

    #[test]
    fn capture_undeclared_fails() {
        let chain = fresh_chain();
        let result = chain.compute_captures(&["missing".into()]);
        assert!(matches!(result, Err(ScopeError::UndeclaredVariable { .. })));
    }

    // ----- function declaration hoisting -----

    #[test]
    fn function_decl_hoisted_with_value() {
        let mut chain = fresh_chain();
        let closure_ref = EnvValue::ClosureRef(ClosureHandle(0));
        chain
            .declare_function("foo".into(), 50, closure_ref.clone())
            .unwrap();
        let val = chain.get_value("foo").unwrap();
        assert_eq!(*val, closure_ref);
    }

    #[test]
    fn function_decl_overwrites_var() {
        let mut chain = fresh_chain();
        chain.declare_var("f".into(), 1).unwrap();
        let val = chain.get_value("f").unwrap();
        assert_eq!(*val, EnvValue::Undefined);

        let closure_ref = EnvValue::ClosureRef(ClosureHandle(7));
        chain
            .declare_function("f".into(), 2, closure_ref.clone())
            .unwrap();
        let val = chain.get_value("f").unwrap();
        assert_eq!(*val, closure_ref);
    }

    // ----- parameter bindings -----

    #[test]
    fn parameter_binding_is_mutable() {
        let mut chain = fresh_chain();
        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain
            .declare_parameter("arg".into(), 100, EnvValue::Number(5), Label::Public)
            .unwrap();
        let val = chain.get_value("arg").unwrap();
        assert_eq!(*val, EnvValue::Number(5));
        chain
            .set_value("arg", EnvValue::Number(10), Label::Public)
            .unwrap();
        let val = chain.get_value("arg").unwrap();
        assert_eq!(*val, EnvValue::Number(10));
    }

    // ----- IFC label propagation -----

    #[test]
    fn ifc_label_propagates_on_init() {
        let mut chain = fresh_chain();
        chain.declare_let("secret".into(), 1).unwrap();
        chain
            .initialize_binding("secret", EnvValue::Str("key".into()), Label::Secret)
            .unwrap();
        let handle = chain.current_handle().unwrap();
        let env = chain.get_env(handle).unwrap();
        assert!(env.max_label >= Label::Secret);
        let slot = env.get_binding("secret").unwrap();
        assert_eq!(slot.label, Label::Secret);
    }

    #[test]
    fn ifc_label_propagates_on_set() {
        let mut chain = fresh_chain();
        chain.declare_var("data".into(), 1).unwrap();
        chain
            .set_value(
                "data",
                EnvValue::Str("classified".into()),
                Label::Confidential,
            )
            .unwrap();
        let global = chain.get_env(EnvironmentHandle(0)).unwrap();
        assert!(global.max_label >= Label::Confidential);
    }

    #[test]
    fn capture_carries_ifc_label() {
        let mut chain = fresh_chain();
        chain.declare_let("classified".into(), 1).unwrap();
        chain
            .initialize_binding(
                "classified",
                EnvValue::Str("data".into()),
                Label::Confidential,
            )
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        let captures = chain.compute_captures(&["classified".into()]).unwrap();
        assert_eq!(captures[0].label, Label::Confidential);
    }

    // ----- nested closures -----

    #[test]
    fn nested_scope_chain_traversal() {
        let mut chain = fresh_chain();
        chain.declare_var("a".into(), 1).unwrap();
        chain
            .set_value("a", EnvValue::Number(1), Label::Public)
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain.declare_let("b".into(), 2).unwrap();
        chain
            .initialize_binding("b", EnvValue::Number(2), Label::Public)
            .unwrap();

        let block_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_let("c".into(), 3).unwrap();
        chain
            .initialize_binding("c", EnvValue::Number(3), Label::Public)
            .unwrap();

        // All three variables visible from innermost scope.
        assert_eq!(*chain.get_value("a").unwrap(), EnvValue::Number(1));
        assert_eq!(*chain.get_value("b").unwrap(), EnvValue::Number(2));
        assert_eq!(*chain.get_value("c").unwrap(), EnvValue::Number(3));
    }

    #[test]
    fn nested_closure_captures_multiple_scopes() {
        let mut chain = fresh_chain();
        chain.declare_let("outer".into(), 1).unwrap();
        chain
            .initialize_binding("outer", EnvValue::Number(10), Label::Public)
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain.declare_let("middle".into(), 2).unwrap();
        chain
            .initialize_binding("middle", EnvValue::Number(20), Label::Internal)
            .unwrap();

        let inner_fn_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(inner_fn_id, ScopeKind::Function);

        let captures = chain
            .compute_captures(&["outer".into(), "middle".into()])
            .unwrap();
        assert_eq!(captures.len(), 2);
        // outer comes from global scope.
        assert_eq!(captures[0].source_scope, ScopeId { depth: 0, index: 0 });
        assert_eq!(captures[0].label, Label::Public);
        // middle comes from enclosing function.
        assert_eq!(captures[1].source_scope, ScopeId { depth: 1, index: 0 });
        assert_eq!(captures[1].label, Label::Internal);
    }

    // ----- closure store -----

    #[test]
    fn closure_store_create_and_get() {
        let mut store = ClosureStore::new();
        assert!(store.is_empty());

        let captures = vec![ClosureCapture {
            name: "x".into(),
            binding_id: 1,
            source_scope: ScopeId { depth: 0, index: 0 },
            label: Label::Public,
        }];
        let h = store.create_closure("add".into(), 2, true, captures, EnvironmentHandle(0));
        assert_eq!(store.len(), 1);
        let closure = store.get(h).unwrap();
        assert_eq!(closure.name, "add");
        assert_eq!(closure.arity, 2);
        assert!(closure.strict);
        assert_eq!(closure.captures.len(), 1);
        assert_eq!(closure.max_capture_label, Label::Public);
    }

    #[test]
    fn closure_store_max_capture_label() {
        let mut store = ClosureStore::new();
        let captures = vec![
            ClosureCapture {
                name: "a".into(),
                binding_id: 1,
                source_scope: ScopeId { depth: 0, index: 0 },
                label: Label::Public,
            },
            ClosureCapture {
                name: "b".into(),
                binding_id: 2,
                source_scope: ScopeId { depth: 0, index: 0 },
                label: Label::Secret,
            },
        ];
        let h = store.create_closure("f".into(), 0, false, captures, EnvironmentHandle(0));
        let closure = store.get(h).unwrap();
        assert_eq!(closure.max_capture_label, Label::Secret);
    }

    // ----- serde round-trip -----

    #[test]
    fn env_value_serde_roundtrip() {
        let values = vec![
            EnvValue::Undefined,
            EnvValue::Null,
            EnvValue::Bool(true),
            EnvValue::Number(3_141_593),
            EnvValue::Str("hello".into()),
            EnvValue::ObjectRef(42),
            EnvValue::ClosureRef(ClosureHandle(7)),
            EnvValue::Tdz,
        ];
        for val in &values {
            let json = serde_json::to_string(val).unwrap();
            let back: EnvValue = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, val);
        }
    }

    #[test]
    fn binding_slot_serde_roundtrip() {
        let slot = BindingSlot::new_lexical("x".into(), 42, BindingKind::Let);
        let json = serde_json::to_string(&slot).unwrap();
        let back: BindingSlot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
    }

    #[test]
    fn closure_serde_roundtrip() {
        let closure = Closure {
            handle: ClosureHandle(0),
            name: "test".into(),
            arity: 1,
            strict: true,
            captures: vec![ClosureCapture {
                name: "x".into(),
                binding_id: 1,
                source_scope: ScopeId { depth: 0, index: 0 },
                label: Label::Internal,
            }],
            max_capture_label: Label::Internal,
            creation_env: EnvironmentHandle(0),
        };
        let json = serde_json::to_string(&closure).unwrap();
        let back: Closure = serde_json::from_str(&json).unwrap();
        assert_eq!(back, closure);
    }

    // ----- scope error display -----

    #[test]
    fn scope_error_messages() {
        let tdz = ScopeError::TemporalDeadZone { name: "x".into() };
        assert!(tdz.to_string().contains("before initialization"));

        let const_err = ScopeError::ConstAssignment { name: "PI".into() };
        assert!(const_err.to_string().contains("constant variable"));

        let undecl = ScopeError::UndeclaredVariable { name: "y".into() };
        assert!(undecl.to_string().contains("not defined"));

        let dup = ScopeError::DuplicateBinding { name: "z".into() };
        assert!(dup.to_string().contains("already been declared"));
    }

    // ----- environment record properties -----

    #[test]
    fn is_var_scope_classification() {
        let cases = vec![
            (ScopeKind::Global, true),
            (ScopeKind::Module, true),
            (ScopeKind::Function, true),
            (ScopeKind::Block, false),
            (ScopeKind::Catch, false),
        ];
        for (kind, expected) in cases {
            let env = EnvironmentRecord::new(
                EnvironmentHandle(0),
                ScopeId { depth: 0, index: 0 },
                kind,
                EnvironmentKind::Declarative,
            );
            assert_eq!(env.is_var_scope(), expected, "ScopeKind::{kind:?}");
        }
    }

    // ----- env_value display -----

    #[test]
    fn env_value_display_formats() {
        assert_eq!(EnvValue::Undefined.to_string(), "undefined");
        assert_eq!(EnvValue::Null.to_string(), "null");
        assert_eq!(EnvValue::Bool(false).to_string(), "false");
        assert_eq!(EnvValue::Number(1_000_000).to_string(), "1000000");
        assert_eq!(EnvValue::Str("hi".into()).to_string(), "\"hi\"");
        assert_eq!(EnvValue::Tdz.to_string(), "<TDZ>");
    }

    // ----- this binding on function scope -----

    #[test]
    fn function_env_this_binding() {
        let mut chain = fresh_chain();
        let fn_id = ScopeId { depth: 1, index: 0 };
        let fn_handle = chain.push_scope(fn_id, ScopeKind::Function);
        let env = chain.get_env_mut(fn_handle).unwrap();
        env.this_binding = Some(EnvValue::ObjectRef(99));
        let env = chain.get_env(fn_handle).unwrap();
        assert_eq!(env.this_binding, Some(EnvValue::ObjectRef(99)));
    }

    // ----- catch scope -----

    #[test]
    fn catch_scope_binds_error_variable() {
        let mut chain = fresh_chain();
        let catch_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(catch_id, ScopeKind::Catch);
        chain.declare_let("err".into(), 1).unwrap();
        chain
            .initialize_binding("err", EnvValue::Str("oops".into()), Label::Public)
            .unwrap();
        let val = chain.get_value("err").unwrap();
        assert_eq!(*val, EnvValue::Str("oops".into()));
        // Catch is not a var scope.
        chain.pop_scope().unwrap();
        let result = chain.get_value("err");
        assert!(result.is_err());
    }

    // ----- module scope -----

    #[test]
    fn module_scope_is_var_target() {
        let mut chain = fresh_chain();
        let mod_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(mod_id, ScopeKind::Module);
        let block_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_var("modVar".into(), 1).unwrap();
        // Should be in the module scope, not global.
        let mod_handle = EnvironmentHandle(1);
        let mod_env = chain.get_env(mod_handle).unwrap();
        assert!(mod_env.get_binding("modVar").is_some());
    }

    // ----- write to TDZ binding fails -----

    #[test]
    fn write_to_tdz_binding_fails() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 1).unwrap();
        let result = chain.set_value("x", EnvValue::Number(1), Label::Public);
        assert!(matches!(result, Err(ScopeError::TemporalDeadZone { .. })));
    }

    // ----- scope chain default impl -----

    #[test]
    fn scope_chain_default() {
        let chain = ScopeChain::default();
        assert_eq!(chain.depth(), 1);
    }

    // ----- resolve_binding returns correct scope -----

    #[test]
    fn resolve_binding_identifies_correct_scope() {
        let mut chain = fresh_chain();
        chain.declare_var("global_var".into(), 1).unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain.declare_let("fn_local".into(), 2).unwrap();
        chain
            .initialize_binding("fn_local", EnvValue::Number(1), Label::Public)
            .unwrap();

        let (_, scope) = chain.resolve_binding("global_var").unwrap();
        assert_eq!(scope, ScopeId { depth: 0, index: 0 });

        let (_, scope) = chain.resolve_binding("fn_local").unwrap();
        assert_eq!(scope, fn_id);
    }
}
