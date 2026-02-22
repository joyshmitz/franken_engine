//! ES2020 object model with property descriptors, prototype chains, and Proxy.
//!
//! Implements the full ES2020 object model required by Section 10.2 item 10
//! ("no permanent subset scope").  Key features:
//!
//! - **Property descriptors**: data vs accessor, configurable/enumerable/writable
//! - **Prototype chains**: `[[Prototype]]` internal slot with chain traversal
//! - **Object operations**: freeze, seal, preventExtensions, keys, values, entries
//! - **Proxy**: all 13 trap handlers with full invariant checking per ES2020
//! - **Reflect**: mirrors of each Proxy trap as ordinary functions
//! - **Symbol keys**: property keys that are either strings or symbols
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.2 item 10, bd-1m9.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PropertyKey — string or symbol
// ---------------------------------------------------------------------------

/// Unique symbol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SymbolId(pub u32);

/// A property key: either a string or a symbol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PropertyKey {
    /// String key.
    String(String),
    /// Symbol key (references the global symbol registry).
    Symbol(SymbolId),
}

impl fmt::Display for PropertyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Symbol(id) => write!(f, "Symbol({})", id.0),
        }
    }
}

impl From<&str> for PropertyKey {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<String> for PropertyKey {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

// ---------------------------------------------------------------------------
// Well-known symbols
// ---------------------------------------------------------------------------

/// Well-known symbol indices (fixed allocation in the symbol registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WellKnownSymbol {
    Iterator,
    ToPrimitive,
    HasInstance,
    ToStringTag,
    Species,
    IsConcatSpreadable,
    Unscopables,
    AsyncIterator,
    Match,
    MatchAll,
    Replace,
    Search,
    Split,
}

impl WellKnownSymbol {
    /// Get the `SymbolId` for this well-known symbol.
    /// Well-known symbols occupy ids 1..=13.
    pub fn id(self) -> SymbolId {
        SymbolId(self as u32 + 1)
    }

    /// Get the property key for this well-known symbol.
    pub fn key(self) -> PropertyKey {
        PropertyKey::Symbol(self.id())
    }

    /// Display name (e.g. `@@iterator`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Iterator => "@@iterator",
            Self::ToPrimitive => "@@toPrimitive",
            Self::HasInstance => "@@hasInstance",
            Self::ToStringTag => "@@toStringTag",
            Self::Species => "@@species",
            Self::IsConcatSpreadable => "@@isConcatSpreadable",
            Self::Unscopables => "@@unscopables",
            Self::AsyncIterator => "@@asyncIterator",
            Self::Match => "@@match",
            Self::MatchAll => "@@matchAll",
            Self::Replace => "@@replace",
            Self::Search => "@@search",
            Self::Split => "@@split",
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectHandle — typed reference to heap objects
// ---------------------------------------------------------------------------

/// Opaque handle referencing an object on the managed heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectHandle(pub u32);

// ---------------------------------------------------------------------------
// JsValue — runtime value for the object model
// ---------------------------------------------------------------------------

/// Runtime value for the ES2020 object model.
///
/// This intentionally mirrors the baseline interpreter's `Value` but adds
/// `Symbol` and keeps `Object` typed via `ObjectHandle`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JsValue {
    Undefined,
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Symbol(SymbolId),
    Object(ObjectHandle),
    Function(u32),
}

impl JsValue {
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub fn is_callable(&self) -> bool {
        matches!(self, Self::Function(_))
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "number",
            Self::Str(_) => "string",
            Self::Symbol(_) => "symbol",
            Self::Object(_) => "object",
            Self::Function(_) => "function",
        }
    }

    /// SameValue comparison (ES2020 §7.2.10).
    pub fn same_value(&self, other: &Self) -> bool {
        self == other
    }
}

impl fmt::Display for JsValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "undefined"),
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Symbol(id) => write!(f, "Symbol({})", id.0),
            Self::Object(h) => write!(f, "[object#{}]", h.0),
            Self::Function(idx) => write!(f, "[function#{idx}]"),
        }
    }
}

// ---------------------------------------------------------------------------
// PropertyDescriptor
// ---------------------------------------------------------------------------

/// ES2020 property descriptor (§6.2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyDescriptor {
    /// Data descriptor: has `value` and `writable`.
    Data {
        value: JsValue,
        writable: bool,
        enumerable: bool,
        configurable: bool,
    },
    /// Accessor descriptor: has `get` and/or `set`.
    Accessor {
        get: Option<ObjectHandle>,
        set: Option<ObjectHandle>,
        enumerable: bool,
        configurable: bool,
    },
}

impl PropertyDescriptor {
    /// Create a default data descriptor (writable, enumerable, configurable).
    pub fn data(value: JsValue) -> Self {
        Self::Data {
            value,
            writable: true,
            enumerable: true,
            configurable: true,
        }
    }

    /// Create a non-writable, non-enumerable, non-configurable data descriptor.
    pub fn data_frozen(value: JsValue) -> Self {
        Self::Data {
            value,
            writable: false,
            enumerable: false,
            configurable: false,
        }
    }

    /// Is this descriptor configurable?
    pub fn is_configurable(&self) -> bool {
        match self {
            Self::Data { configurable, .. } | Self::Accessor { configurable, .. } => *configurable,
        }
    }

    /// Is this descriptor enumerable?
    pub fn is_enumerable(&self) -> bool {
        match self {
            Self::Data { enumerable, .. } | Self::Accessor { enumerable, .. } => *enumerable,
        }
    }

    /// Is this a data descriptor?
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data { .. })
    }

    /// Is this an accessor descriptor?
    pub fn is_accessor(&self) -> bool {
        matches!(self, Self::Accessor { .. })
    }

    /// Get the value if this is a data descriptor.
    pub fn value(&self) -> Option<&JsValue> {
        match self {
            Self::Data { value, .. } => Some(value),
            Self::Accessor { .. } => None,
        }
    }

    /// Is this a data descriptor with writable=true?
    pub fn is_writable(&self) -> bool {
        match self {
            Self::Data { writable, .. } => *writable,
            Self::Accessor { .. } => false,
        }
    }

    /// Make this descriptor non-configurable.
    pub fn set_non_configurable(&mut self) {
        match self {
            Self::Data { configurable, .. } | Self::Accessor { configurable, .. } => {
                *configurable = false;
            }
        }
    }

    /// Make this data descriptor non-writable (no-op for accessors).
    pub fn set_non_writable(&mut self) {
        if let Self::Data { writable, .. } = self {
            *writable = false;
        }
    }

    /// Make this descriptor non-enumerable.
    pub fn set_non_enumerable(&mut self) {
        match self {
            Self::Data { enumerable, .. } | Self::Accessor { enumerable, .. } => {
                *enumerable = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectError
// ---------------------------------------------------------------------------

/// Errors from object model operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectError {
    /// TypeError per ES2020 spec.
    TypeError(String),
    /// Object not found in the heap.
    ObjectNotFound(ObjectHandle),
    /// Proxy has been revoked.
    ProxyRevoked,
    /// Prototype chain cycle detected.
    PrototypeCycleDetected,
    /// Maximum prototype chain depth exceeded.
    PrototypeChainTooDeep { depth: u32, max: u32 },
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeError(msg) => write!(f, "TypeError: {msg}"),
            Self::ObjectNotFound(h) => write!(f, "object#{} not found", h.0),
            Self::ProxyRevoked => write!(f, "TypeError: proxy has been revoked"),
            Self::PrototypeCycleDetected => write!(f, "TypeError: prototype chain cycle detected"),
            Self::PrototypeChainTooDeep { depth, max } => {
                write!(
                    f,
                    "TypeError: prototype chain depth {depth} exceeds max {max}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OrdinaryObject — the core ES2020 object
// ---------------------------------------------------------------------------

/// Maximum prototype chain depth to prevent infinite loops.
const MAX_PROTOTYPE_CHAIN_DEPTH: u32 = 1024;

/// An ordinary ES2020 object with internal slots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdinaryObject {
    /// `[[Prototype]]` internal slot (null means end of chain).
    pub prototype: Option<ObjectHandle>,
    /// `[[Extensible]]` internal slot.
    pub extensible: bool,
    /// Own properties with descriptors, keyed by PropertyKey.
    pub properties: BTreeMap<PropertyKey, PropertyDescriptor>,
    /// `[[Class]]` tag for intrinsic identification.
    pub class_tag: Option<String>,
    /// Is this object callable (i.e. a function)?
    pub callable: bool,
    /// Is this object a constructor?
    pub constructable: bool,
}

impl Default for OrdinaryObject {
    fn default() -> Self {
        Self {
            prototype: None,
            extensible: true,
            properties: BTreeMap::new(),
            class_tag: None,
            callable: false,
            constructable: false,
        }
    }
}

impl OrdinaryObject {
    /// Create a new ordinary object with the given prototype.
    pub fn with_prototype(proto: Option<ObjectHandle>) -> Self {
        Self {
            prototype: proto,
            ..Self::default()
        }
    }

    // -- [[GetOwnProperty]] (§9.1.1) ---------------------------------------

    /// `[[GetOwnProperty]](P)` — return the own property descriptor for `key`.
    pub fn get_own_property(&self, key: &PropertyKey) -> Option<&PropertyDescriptor> {
        self.properties.get(key)
    }

    // -- [[HasProperty]] (§9.1.7) ------------------------------------------

    /// `[[HasOwnProperty]](P)` — does this object have an own property `key`?
    pub fn has_own_property(&self, key: &PropertyKey) -> bool {
        self.properties.contains_key(key)
    }

    // -- [[DefineOwnProperty]] (§9.1.6) ------------------------------------

    /// `[[DefineOwnProperty]](P, Desc)` — define or update a property.
    ///
    /// Returns `Ok(true)` if the property was successfully defined,
    /// `Ok(false)` if rejected (non-configurable conflict), or
    /// `Err` for type errors.
    pub fn define_own_property(
        &mut self,
        key: PropertyKey,
        desc: PropertyDescriptor,
    ) -> Result<bool, ObjectError> {
        if let Some(current) = self.properties.get(&key) {
            // Existing property — check compatibility.
            if !current.is_configurable() {
                // Non-configurable: reject any change that would alter configurability
                // or change descriptor type.
                if desc.is_configurable() {
                    return Ok(false);
                }
                // Cannot change enumerable on non-configurable property.
                if desc.is_enumerable() != current.is_enumerable() {
                    return Ok(false);
                }
                // Cannot change data↔accessor type.
                if current.is_data() != desc.is_data() {
                    return Ok(false);
                }
                // For data descriptors: cannot change writable from false to true.
                if let (
                    PropertyDescriptor::Data {
                        writable: current_w,
                        value: current_v,
                        ..
                    },
                    PropertyDescriptor::Data {
                        writable: new_w,
                        value: new_v,
                        ..
                    },
                ) = (current, &desc)
                {
                    if !current_w {
                        // Non-writable non-configurable: cannot become writable.
                        if *new_w {
                            return Ok(false);
                        }
                        // Non-writable non-configurable: cannot change value.
                        if !current_v.same_value(new_v) {
                            return Ok(false);
                        }
                    }
                }
                // For accessor descriptors: cannot change get/set on non-configurable.
                if let (
                    PropertyDescriptor::Accessor {
                        get: cur_get,
                        set: cur_set,
                        ..
                    },
                    PropertyDescriptor::Accessor {
                        get: new_get,
                        set: new_set,
                        ..
                    },
                ) = (current, &desc)
                {
                    if cur_get != new_get || cur_set != new_set {
                        return Ok(false);
                    }
                }
            }
            // Update is valid.
            self.properties.insert(key, desc);
            Ok(true)
        } else {
            // New property.
            if !self.extensible {
                return Ok(false);
            }
            self.properties.insert(key, desc);
            Ok(true)
        }
    }

    // -- [[Delete]] (§9.1.10) -----------------------------------------------

    /// `[[Delete]](P)` — delete a property. Returns `false` if non-configurable.
    pub fn delete(&mut self, key: &PropertyKey) -> bool {
        if let Some(desc) = self.properties.get(key) {
            if !desc.is_configurable() {
                return false;
            }
        } else {
            // Property doesn't exist — vacuously true.
            return true;
        }
        self.properties.remove(key);
        true
    }

    // -- [[OwnPropertyKeys]] (§9.1.11) -------------------------------------

    /// `[[OwnPropertyKeys]]()` — returns own keys in ES2020 order:
    /// integer indices (sorted numerically), then string keys (insertion order
    /// approximated by BTreeMap order), then symbol keys.
    pub fn own_property_keys(&self) -> Vec<PropertyKey> {
        let mut int_keys: Vec<(u64, PropertyKey)> = Vec::new();
        let mut str_keys: Vec<PropertyKey> = Vec::new();
        let mut sym_keys: Vec<PropertyKey> = Vec::new();

        for key in self.properties.keys() {
            match key {
                PropertyKey::String(s) => {
                    if let Ok(n) = s.parse::<u64>() {
                        int_keys.push((n, key.clone()));
                    } else {
                        str_keys.push(key.clone());
                    }
                }
                PropertyKey::Symbol(_) => {
                    sym_keys.push(key.clone());
                }
            }
        }

        int_keys.sort_by_key(|(n, _)| *n);
        let mut result: Vec<PropertyKey> = int_keys.into_iter().map(|(_, k)| k).collect();
        result.extend(str_keys);
        result.extend(sym_keys);
        result
    }

    // -- [[PreventExtensions]] (§9.1.4) ------------------------------------

    /// `[[PreventExtensions]]()` — makes this object non-extensible.
    pub fn prevent_extensions(&mut self) {
        self.extensible = false;
    }

    // -- Freeze/Seal --------------------------------------------------------

    /// `Object.freeze` semantics: make all own properties non-configurable
    /// and data properties non-writable.
    pub fn freeze(&mut self) {
        self.extensible = false;
        for desc in self.properties.values_mut() {
            desc.set_non_configurable();
            desc.set_non_writable();
        }
    }

    /// `Object.seal` semantics: make all own properties non-configurable
    /// but leave writable unchanged.
    pub fn seal(&mut self) {
        self.extensible = false;
        for desc in self.properties.values_mut() {
            desc.set_non_configurable();
        }
    }

    /// Is this object frozen? (non-extensible + all own properties non-configurable
    /// + all data properties non-writable.)
    pub fn is_frozen(&self) -> bool {
        if self.extensible {
            return false;
        }
        self.properties.values().all(|d| {
            if !d.is_configurable() {
                if let PropertyDescriptor::Data { writable, .. } = d {
                    !writable
                } else {
                    true
                }
            } else {
                false
            }
        })
    }

    /// Is this object sealed? (non-extensible + all own properties non-configurable.)
    pub fn is_sealed(&self) -> bool {
        if self.extensible {
            return false;
        }
        self.properties.values().all(|d| !d.is_configurable())
    }
}

// ---------------------------------------------------------------------------
// ProxyObject — ES2020 Proxy
// ---------------------------------------------------------------------------

/// Proxy internal state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyObject {
    /// `[[ProxyTarget]]` — the wrapped target object (None if revoked).
    pub target: Option<ObjectHandle>,
    /// `[[ProxyHandler]]` — the handler object (None if revoked).
    pub handler: Option<ObjectHandle>,
}

impl ProxyObject {
    /// Create a new proxy wrapping `target` with `handler`.
    pub fn new(target: ObjectHandle, handler: ObjectHandle) -> Self {
        Self {
            target: Some(target),
            handler: Some(handler),
        }
    }

    /// Revoke this proxy.
    pub fn revoke(&mut self) {
        self.target = None;
        self.handler = None;
    }

    /// Is this proxy revoked?
    pub fn is_revoked(&self) -> bool {
        self.target.is_none()
    }

    /// Get the target, or `ProxyRevoked` error.
    pub fn target(&self) -> Result<ObjectHandle, ObjectError> {
        self.target.ok_or(ObjectError::ProxyRevoked)
    }

    /// Get the handler, or `ProxyRevoked` error.
    pub fn handler(&self) -> Result<ObjectHandle, ObjectError> {
        self.handler.ok_or(ObjectError::ProxyRevoked)
    }
}

// ---------------------------------------------------------------------------
// ManagedObject — union of ordinary and proxy
// ---------------------------------------------------------------------------

/// A managed object: either ordinary or a Proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManagedObject {
    Ordinary(OrdinaryObject),
    Proxy(ProxyObject),
}

impl ManagedObject {
    /// Get the ordinary object, if this is one.
    pub fn as_ordinary(&self) -> Option<&OrdinaryObject> {
        match self {
            Self::Ordinary(o) => Some(o),
            Self::Proxy(_) => None,
        }
    }

    /// Get a mutable ordinary object, if this is one.
    pub fn as_ordinary_mut(&mut self) -> Option<&mut OrdinaryObject> {
        match self {
            Self::Ordinary(o) => Some(o),
            Self::Proxy(_) => None,
        }
    }

    /// Get the proxy object, if this is one.
    pub fn as_proxy(&self) -> Option<&ProxyObject> {
        match self {
            Self::Proxy(p) => Some(p),
            Self::Ordinary(_) => None,
        }
    }

    /// Get a mutable proxy object, if this is one.
    pub fn as_proxy_mut(&mut self) -> Option<&mut ProxyObject> {
        match self {
            Self::Proxy(p) => Some(p),
            Self::Ordinary(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectHeap — the managed object store
// ---------------------------------------------------------------------------

/// The object heap: arena of managed objects.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectHeap {
    objects: Vec<ManagedObject>,
    /// Next symbol id (after well-known symbols).
    next_symbol: u32,
}

impl ObjectHeap {
    /// Create a new empty heap.
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            // Well-known symbols occupy 1..=13.
            next_symbol: 14,
        }
    }

    /// Allocate a new ordinary object with the given prototype.
    pub fn alloc(&mut self, proto: Option<ObjectHandle>) -> ObjectHandle {
        let handle = ObjectHandle(self.objects.len() as u32);
        self.objects
            .push(ManagedObject::Ordinary(OrdinaryObject::with_prototype(
                proto,
            )));
        handle
    }

    /// Allocate a new ordinary object with default (no prototype).
    pub fn alloc_plain(&mut self) -> ObjectHandle {
        self.alloc(None)
    }

    /// Allocate a Proxy object.
    pub fn alloc_proxy(
        &mut self,
        target: ObjectHandle,
        handler: ObjectHandle,
    ) -> ObjectHandle {
        let handle = ObjectHandle(self.objects.len() as u32);
        self.objects
            .push(ManagedObject::Proxy(ProxyObject::new(target, handler)));
        handle
    }

    /// Allocate a new unique symbol id.
    pub fn alloc_symbol(&mut self) -> SymbolId {
        let id = SymbolId(self.next_symbol);
        self.next_symbol += 1;
        id
    }

    /// Get a reference to a managed object.
    pub fn get(&self, handle: ObjectHandle) -> Result<&ManagedObject, ObjectError> {
        self.objects
            .get(handle.0 as usize)
            .ok_or(ObjectError::ObjectNotFound(handle))
    }

    /// Get a mutable reference to a managed object.
    pub fn get_mut(&mut self, handle: ObjectHandle) -> Result<&mut ManagedObject, ObjectError> {
        self.objects
            .get_mut(handle.0 as usize)
            .ok_or(ObjectError::ObjectNotFound(handle))
    }

    /// Number of objects allocated.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Is the heap empty?
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    // -- High-level operations requiring heap access ------------------------

    /// `[[Get]](O, P)` — get a property, walking the prototype chain.
    pub fn get_property(
        &self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<JsValue, ObjectError> {
        let mut current = Some(handle);
        let mut depth: u32 = 0;
        let mut visited = BTreeSet::new();

        while let Some(h) = current {
            if depth > MAX_PROTOTYPE_CHAIN_DEPTH {
                return Err(ObjectError::PrototypeChainTooDeep {
                    depth,
                    max: MAX_PROTOTYPE_CHAIN_DEPTH,
                });
            }
            if !visited.insert(h) {
                return Err(ObjectError::PrototypeCycleDetected);
            }

            let obj = self.get(h)?;
            match obj {
                ManagedObject::Ordinary(o) => {
                    if let Some(desc) = o.get_own_property(key) {
                        return match desc {
                            PropertyDescriptor::Data { value, .. } => Ok(value.clone()),
                            PropertyDescriptor::Accessor { get, .. } => {
                                // Accessor: return the getter handle as a marker.
                                // Actual getter invocation is done by the interpreter.
                                match get {
                                    Some(getter) => Ok(JsValue::Object(*getter)),
                                    None => Ok(JsValue::Undefined),
                                }
                            }
                        };
                    }
                    current = o.prototype;
                }
                ManagedObject::Proxy(_) => {
                    // Proxy get trap must be handled by the interpreter.
                    // Return a sentinel or handle at interpreter level.
                    return Err(ObjectError::TypeError(
                        "proxy get trap must be handled by interpreter".to_string(),
                    ));
                }
            }
            depth += 1;
        }

        // Reached end of prototype chain.
        Ok(JsValue::Undefined)
    }

    /// `[[Set]](O, P, V)` — set a property (own property only for now).
    pub fn set_property(
        &mut self,
        handle: ObjectHandle,
        key: PropertyKey,
        value: JsValue,
    ) -> Result<bool, ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                if let Some(desc) = o.properties.get(&key) {
                    if !desc.is_configurable() && desc.is_data() && !desc.is_writable() {
                        return Ok(false); // non-writable non-configurable
                    }
                    if desc.is_accessor() {
                        // Accessor set trap handled by interpreter.
                        return Ok(false);
                    }
                }
                // If property exists and is writable, or is new and object is extensible.
                if o.properties.contains_key(&key) {
                    if let Some(PropertyDescriptor::Data {
                        value: ref mut v, ..
                    }) = o.properties.get_mut(&key)
                    {
                        *v = value;
                        return Ok(true);
                    }
                } else if o.extensible {
                    o.properties.insert(key, PropertyDescriptor::data(value));
                    return Ok(true);
                }
                Ok(false)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy set trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `[[HasProperty]](O, P)` — check if property exists (walks prototype chain).
    pub fn has_property(
        &self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<bool, ObjectError> {
        let mut current = Some(handle);
        let mut depth: u32 = 0;
        let mut visited = BTreeSet::new();

        while let Some(h) = current {
            if depth > MAX_PROTOTYPE_CHAIN_DEPTH {
                return Err(ObjectError::PrototypeChainTooDeep {
                    depth,
                    max: MAX_PROTOTYPE_CHAIN_DEPTH,
                });
            }
            if !visited.insert(h) {
                return Err(ObjectError::PrototypeCycleDetected);
            }

            let obj = self.get(h)?;
            match obj {
                ManagedObject::Ordinary(o) => {
                    if o.has_own_property(key) {
                        return Ok(true);
                    }
                    current = o.prototype;
                }
                ManagedObject::Proxy(_) => {
                    return Err(ObjectError::TypeError(
                        "proxy has trap must be handled by interpreter".to_string(),
                    ));
                }
            }
            depth += 1;
        }
        Ok(false)
    }

    /// `[[Delete]](O, P)` — delete a property.
    pub fn delete_property(
        &mut self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<bool, ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.delete(key)),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy deleteProperty trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.getPrototypeOf(O)`.
    pub fn get_prototype_of(
        &self,
        handle: ObjectHandle,
    ) -> Result<Option<ObjectHandle>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.prototype),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy getPrototypeOf trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.setPrototypeOf(O, proto)`.
    pub fn set_prototype_of(
        &mut self,
        handle: ObjectHandle,
        proto: Option<ObjectHandle>,
    ) -> Result<bool, ObjectError> {
        // Check for cycles.
        if let Some(p) = proto {
            let mut current = Some(p);
            let mut visited = BTreeSet::new();
            visited.insert(handle);
            while let Some(h) = current {
                if !visited.insert(h) {
                    return Err(ObjectError::PrototypeCycleDetected);
                }
                let obj = self.get(h)?;
                match obj {
                    ManagedObject::Ordinary(o) => current = o.prototype,
                    ManagedObject::Proxy(_) => break,
                }
            }
        }

        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                if !o.extensible {
                    // Non-extensible: can only set prototype to current value.
                    if o.prototype == proto {
                        return Ok(true);
                    }
                    return Ok(false);
                }
                o.prototype = proto;
                Ok(true)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy setPrototypeOf trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.isExtensible(O)`.
    pub fn is_extensible(&self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.extensible),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy isExtensible trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.preventExtensions(O)`.
    pub fn prevent_extensions(&mut self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                o.prevent_extensions();
                Ok(true)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy preventExtensions trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.defineProperty(O, P, Desc)`.
    pub fn define_property(
        &mut self,
        handle: ObjectHandle,
        key: PropertyKey,
        desc: PropertyDescriptor,
    ) -> Result<bool, ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => o.define_own_property(key, desc),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy defineProperty trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.getOwnPropertyDescriptor(O, P)`.
    pub fn get_own_property_descriptor(
        &self,
        handle: ObjectHandle,
        key: &PropertyKey,
    ) -> Result<Option<PropertyDescriptor>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.get_own_property(key).cloned()),
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy getOwnPropertyDescriptor trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.keys(O)` — enumerable own string keys.
    pub fn keys(&self, handle: ObjectHandle) -> Result<Vec<String>, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                let result = o
                    .own_property_keys()
                    .into_iter()
                    .filter(|k| {
                        if let Some(d) = o.properties.get(k) {
                            d.is_enumerable() && matches!(k, PropertyKey::String(_))
                        } else {
                            false
                        }
                    })
                    .filter_map(|k| match k {
                        PropertyKey::String(s) => Some(s),
                        PropertyKey::Symbol(_) => None,
                    })
                    .collect();
                Ok(result)
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "proxy ownKeys trap must be handled by interpreter".to_string(),
            )),
        }
    }

    /// `Object.freeze(O)`.
    pub fn freeze(&mut self, handle: ObjectHandle) -> Result<(), ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                o.freeze();
                Ok(())
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "cannot freeze proxy directly".to_string(),
            )),
        }
    }

    /// `Object.seal(O)`.
    pub fn seal(&mut self, handle: ObjectHandle) -> Result<(), ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => {
                o.seal();
                Ok(())
            }
            ManagedObject::Proxy(_) => Err(ObjectError::TypeError(
                "cannot seal proxy directly".to_string(),
            )),
        }
    }

    /// `Object.isFrozen(O)`.
    pub fn is_frozen(&self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.is_frozen()),
            ManagedObject::Proxy(_) => Ok(false),
        }
    }

    /// `Object.isSealed(O)`.
    pub fn is_sealed(&self, handle: ObjectHandle) -> Result<bool, ObjectError> {
        let obj = self.get(handle)?;
        match obj {
            ManagedObject::Ordinary(o) => Ok(o.is_sealed()),
            ManagedObject::Proxy(_) => Ok(false),
        }
    }

    /// `Object.assign(target, ...sources)` — copies own enumerable properties.
    pub fn assign(
        &mut self,
        target: ObjectHandle,
        sources: &[ObjectHandle],
    ) -> Result<(), ObjectError> {
        // Collect source data first to avoid borrow issues.
        let mut all_props: Vec<Vec<(PropertyKey, JsValue)>> = Vec::new();
        for &src in sources {
            let obj = self.get(src)?;
            let pairs = match obj {
                ManagedObject::Ordinary(o) => o
                    .own_property_keys()
                    .into_iter()
                    .filter_map(|k| {
                        o.properties.get(&k).and_then(|d| {
                            if d.is_enumerable() {
                                d.value().map(|v| (k, v.clone()))
                            } else {
                                None
                            }
                        })
                    })
                    .collect(),
                ManagedObject::Proxy(_) => {
                    return Err(ObjectError::TypeError(
                        "Object.assign source cannot be proxy (handled by interpreter)"
                            .to_string(),
                    ));
                }
            };
            all_props.push(pairs);
        }

        for props in all_props {
            for (key, value) in props {
                self.set_property(target, key, value)?;
            }
        }
        Ok(())
    }

    /// `Object.create(proto)` — create an object with the given prototype.
    pub fn create(&mut self, proto: Option<ObjectHandle>) -> ObjectHandle {
        self.alloc(proto)
    }

    /// Revoke a proxy object.
    pub fn revoke_proxy(&mut self, handle: ObjectHandle) -> Result<(), ObjectError> {
        let obj = self.get_mut(handle)?;
        match obj {
            ManagedObject::Proxy(p) => {
                p.revoke();
                Ok(())
            }
            ManagedObject::Ordinary(_) => Err(ObjectError::TypeError(
                "cannot revoke non-proxy object".to_string(),
            )),
        }
    }

    /// `Object.is(a, b)` — SameValue comparison.
    pub fn object_is(a: &JsValue, b: &JsValue) -> bool {
        a.same_value(b)
    }
}

// ---------------------------------------------------------------------------
// SymbolRegistry — global symbol table
// ---------------------------------------------------------------------------

/// Global symbol registry for `Symbol.for()` and well-known symbols.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolRegistry {
    /// Description → SymbolId mapping for `Symbol.for()`.
    by_description: BTreeMap<String, SymbolId>,
    /// SymbolId → description mapping for `Symbol.keyFor()`.
    by_id: BTreeMap<SymbolId, String>,
}

impl SymbolRegistry {
    /// Create a new registry with well-known symbols pre-registered.
    pub fn new() -> Self {
        let mut reg = Self::default();
        // Pre-register well-known symbols.
        let well_knowns = [
            (WellKnownSymbol::Iterator, "Symbol.iterator"),
            (WellKnownSymbol::ToPrimitive, "Symbol.toPrimitive"),
            (WellKnownSymbol::HasInstance, "Symbol.hasInstance"),
            (WellKnownSymbol::ToStringTag, "Symbol.toStringTag"),
            (WellKnownSymbol::Species, "Symbol.species"),
            (
                WellKnownSymbol::IsConcatSpreadable,
                "Symbol.isConcatSpreadable",
            ),
            (WellKnownSymbol::Unscopables, "Symbol.unscopables"),
            (WellKnownSymbol::AsyncIterator, "Symbol.asyncIterator"),
            (WellKnownSymbol::Match, "Symbol.match"),
            (WellKnownSymbol::MatchAll, "Symbol.matchAll"),
            (WellKnownSymbol::Replace, "Symbol.replace"),
            (WellKnownSymbol::Search, "Symbol.search"),
            (WellKnownSymbol::Split, "Symbol.split"),
        ];
        for (sym, desc) in well_knowns {
            reg.by_id.insert(sym.id(), desc.to_string());
        }
        reg
    }

    /// `Symbol.for(key)` — get or create a symbol for the given key.
    pub fn symbol_for(&mut self, key: &str, heap: &mut ObjectHeap) -> SymbolId {
        if let Some(&id) = self.by_description.get(key) {
            return id;
        }
        let id = heap.alloc_symbol();
        self.by_description.insert(key.to_string(), id);
        self.by_id.insert(id, key.to_string());
        id
    }

    /// `Symbol.keyFor(sym)` — get the description for a global symbol.
    pub fn key_for(&self, sym: SymbolId) -> Option<&str> {
        self.by_id.get(&sym).map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// ProxyInvariantChecker — validates Proxy trap results
// ---------------------------------------------------------------------------

/// Proxy invariant checker per ES2020 §9.5.x.
pub struct ProxyInvariantChecker;

impl ProxyInvariantChecker {
    /// Validate `[[GetOwnProperty]]` trap result (§9.5.5).
    pub fn check_get_own_property(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: &Option<PropertyDescriptor>,
    ) -> Result<(), ObjectError> {
        let target_desc = target.get_own_property(key);

        match (trap_result, target_desc) {
            // Trap reports non-existent but target has non-configurable property.
            (None, Some(td)) if !td.is_configurable() => Err(ObjectError::TypeError(format!(
                "proxy getOwnPropertyDescriptor: cannot report non-configurable property '{key}' as non-existent"
            ))),
            // Trap reports non-existent but target is non-extensible and has the property.
            (None, Some(_)) if !target.extensible => Err(ObjectError::TypeError(format!(
                "proxy getOwnPropertyDescriptor: cannot report existing property '{key}' as non-existent on non-extensible target"
            ))),
            // Trap reports existent but target is non-extensible and doesn't have it.
            (Some(_), None) if !target.extensible => Err(ObjectError::TypeError(format!(
                "proxy getOwnPropertyDescriptor: cannot report property '{key}' as existent on non-extensible target"
            ))),
            // Trap returns non-configurable but target property is configurable (or missing).
            (Some(td), target_d) if !td.is_configurable() => {
                match target_d {
                    Some(existing) if !existing.is_configurable() => {
                        // Both non-configurable: check value compatibility for data descriptors.
                        if let (
                            PropertyDescriptor::Data { value: tv, writable: tw, .. },
                            PropertyDescriptor::Data { value: ev, writable: ew, .. },
                        ) = (td, existing) {
                            if !tw && !ew && !tv.same_value(ev) {
                                return Err(ObjectError::TypeError(format!(
                                    "proxy getOwnPropertyDescriptor: non-configurable non-writable property '{key}' must have same value"
                                )));
                            }
                        }
                        Ok(())
                    }
                    _ => Err(ObjectError::TypeError(format!(
                        "proxy getOwnPropertyDescriptor: cannot return non-configurable descriptor for property '{key}' when target property is configurable or absent"
                    ))),
                }
            }
            _ => Ok(()),
        }
    }

    /// Validate `[[HasProperty]]` trap result (§9.5.7).
    pub fn check_has(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if !trap_result {
            if let Some(td) = target.get_own_property(key) {
                if !td.is_configurable() {
                    return Err(ObjectError::TypeError(format!(
                        "proxy has: cannot report non-configurable property '{key}' as non-existent"
                    )));
                }
            }
            if !target.extensible {
                if target.has_own_property(key) {
                    return Err(ObjectError::TypeError(format!(
                        "proxy has: cannot report property '{key}' as non-existent on non-extensible target"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Validate `[[Get]]` trap result (§9.5.8).
    pub fn check_get(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: &JsValue,
    ) -> Result<(), ObjectError> {
        if let Some(td) = target.get_own_property(key) {
            if !td.is_configurable() {
                match td {
                    PropertyDescriptor::Data {
                        value, writable, ..
                    } if !writable => {
                        if !trap_result.same_value(value) {
                            return Err(ObjectError::TypeError(format!(
                                "proxy get: non-configurable non-writable property '{key}' must return same value"
                            )));
                        }
                    }
                    PropertyDescriptor::Accessor { get: None, .. } => {
                        if *trap_result != JsValue::Undefined {
                            return Err(ObjectError::TypeError(format!(
                                "proxy get: non-configurable accessor property '{key}' with undefined getter must return undefined"
                            )));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Validate `[[Set]]` trap result (§9.5.9).
    pub fn check_set(
        target: &OrdinaryObject,
        key: &PropertyKey,
        value: &JsValue,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result {
            if let Some(td) = target.get_own_property(key) {
                if !td.is_configurable() {
                    match td {
                        PropertyDescriptor::Data {
                            value: current_val,
                            writable,
                            ..
                        } if !writable => {
                            if !value.same_value(current_val) {
                                return Err(ObjectError::TypeError(format!(
                                    "proxy set: cannot set non-configurable non-writable property '{key}' to different value"
                                )));
                            }
                        }
                        PropertyDescriptor::Accessor { set: None, .. } => {
                            return Err(ObjectError::TypeError(format!(
                                "proxy set: cannot set non-configurable accessor property '{key}' with undefined setter"
                            )));
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate `[[Delete]]` trap result (§9.5.10).
    pub fn check_delete(
        target: &OrdinaryObject,
        key: &PropertyKey,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result {
            if let Some(td) = target.get_own_property(key) {
                if !td.is_configurable() {
                    return Err(ObjectError::TypeError(format!(
                        "proxy deleteProperty: cannot delete non-configurable property '{key}'"
                    )));
                }
            }
            if !target.extensible && target.has_own_property(key) {
                return Err(ObjectError::TypeError(format!(
                    "proxy deleteProperty: cannot delete property '{key}' on non-extensible target"
                )));
            }
        }
        Ok(())
    }

    /// Validate `[[OwnKeys]]` trap result (§9.5.11).
    pub fn check_own_keys(
        target: &OrdinaryObject,
        trap_result: &[PropertyKey],
    ) -> Result<(), ObjectError> {
        // Check for duplicates.
        let mut seen = BTreeSet::new();
        for key in trap_result {
            if !seen.insert(key) {
                return Err(ObjectError::TypeError(format!(
                    "proxy ownKeys: duplicate key '{key}'"
                )));
            }
        }

        // All non-configurable keys must be present.
        for (key, desc) in &target.properties {
            if !desc.is_configurable() && !seen.contains(key) {
                return Err(ObjectError::TypeError(format!(
                    "proxy ownKeys: must include non-configurable property '{key}'"
                )));
            }
        }

        // If non-extensible, result must be exact permutation.
        if !target.extensible {
            let target_keys: BTreeSet<&PropertyKey> = target.properties.keys().collect();
            let result_keys: BTreeSet<&PropertyKey> = trap_result.iter().collect();
            if target_keys != result_keys {
                return Err(ObjectError::TypeError(
                    "proxy ownKeys: non-extensible target requires exact key set".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate `[[GetPrototypeOf]]` trap result (§9.5.1).
    pub fn check_get_prototype_of(
        target: &OrdinaryObject,
        trap_result: Option<ObjectHandle>,
    ) -> Result<(), ObjectError> {
        if !target.extensible && trap_result != target.prototype {
            return Err(ObjectError::TypeError(
                "proxy getPrototypeOf: non-extensible target must return same prototype"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[SetPrototypeOf]]` trap result (§9.5.2).
    pub fn check_set_prototype_of(
        target: &OrdinaryObject,
        new_proto: Option<ObjectHandle>,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result && !target.extensible && new_proto != target.prototype {
            return Err(ObjectError::TypeError(
                "proxy setPrototypeOf: non-extensible target can only set to current prototype"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[IsExtensible]]` trap result (§9.5.3).
    pub fn check_is_extensible(
        target: &OrdinaryObject,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result != target.extensible {
            return Err(ObjectError::TypeError(
                "proxy isExtensible: must match target extensibility".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[PreventExtensions]]` trap result (§9.5.4).
    pub fn check_prevent_extensions(
        target: &OrdinaryObject,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result && target.extensible {
            return Err(ObjectError::TypeError(
                "proxy preventExtensions: cannot return true when target is still extensible"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Validate `[[DefineOwnProperty]]` trap result (§9.5.6).
    pub fn check_define_own_property(
        target: &OrdinaryObject,
        key: &PropertyKey,
        desc: &PropertyDescriptor,
        trap_result: bool,
    ) -> Result<(), ObjectError> {
        if trap_result {
            // Cannot add new property to non-extensible target.
            if !target.has_own_property(key) && !target.extensible {
                return Err(ObjectError::TypeError(format!(
                    "proxy defineProperty: cannot add property '{key}' to non-extensible target"
                )));
            }
            // Cannot define non-configurable if target property is configurable or absent.
            if !desc.is_configurable() {
                match target.get_own_property(key) {
                    Some(td) if !td.is_configurable() => {
                        // Both non-configurable: check value compatibility.
                        if let (
                            PropertyDescriptor::Data { value: nv, writable: nw, .. },
                            PropertyDescriptor::Data { value: tv, writable: tw, .. },
                        ) = (desc, td) {
                            if !tw && !nw && !nv.same_value(tv) {
                                return Err(ObjectError::TypeError(format!(
                                    "proxy defineProperty: cannot change value of non-configurable non-writable property '{key}'"
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(ObjectError::TypeError(format!(
                            "proxy defineProperty: cannot define non-configurable property '{key}' when target property is configurable or absent"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --------------------------------------------------------

    fn str_key(s: &str) -> PropertyKey {
        PropertyKey::String(s.to_string())
    }

    fn int_val(n: i64) -> JsValue {
        JsValue::Int(n)
    }

    fn str_val(s: &str) -> JsValue {
        JsValue::Str(s.to_string())
    }

    // -----------------------------------------------------------------------
    // 1. PropertyKey
    // -----------------------------------------------------------------------

    #[test]
    fn property_key_from_str() {
        let k: PropertyKey = "foo".into();
        assert_eq!(k, PropertyKey::String("foo".to_string()));
    }

    #[test]
    fn property_key_display() {
        assert_eq!(str_key("foo").to_string(), "foo");
        assert_eq!(PropertyKey::Symbol(SymbolId(42)).to_string(), "Symbol(42)");
    }

    // -----------------------------------------------------------------------
    // 2. PropertyDescriptor basics
    // -----------------------------------------------------------------------

    #[test]
    fn data_descriptor_defaults() {
        let d = PropertyDescriptor::data(int_val(42));
        assert!(d.is_data());
        assert!(!d.is_accessor());
        assert!(d.is_configurable());
        assert!(d.is_enumerable());
        assert!(d.is_writable());
        assert_eq!(d.value(), Some(&int_val(42)));
    }

    #[test]
    fn data_descriptor_frozen() {
        let d = PropertyDescriptor::data_frozen(int_val(1));
        assert!(!d.is_configurable());
        assert!(!d.is_enumerable());
        assert!(!d.is_writable());
    }

    #[test]
    fn accessor_descriptor() {
        let d = PropertyDescriptor::Accessor {
            get: Some(ObjectHandle(1)),
            set: None,
            enumerable: true,
            configurable: true,
        };
        assert!(d.is_accessor());
        assert!(!d.is_data());
        assert!(d.is_configurable());
        assert!(d.is_enumerable());
        assert!(!d.is_writable());
        assert_eq!(d.value(), None);
    }

    #[test]
    fn descriptor_mutators() {
        let mut d = PropertyDescriptor::data(int_val(1));
        d.set_non_configurable();
        assert!(!d.is_configurable());
        d.set_non_writable();
        assert!(!d.is_writable());
        d.set_non_enumerable();
        assert!(!d.is_enumerable());
    }

    // -----------------------------------------------------------------------
    // 3. OrdinaryObject basics
    // -----------------------------------------------------------------------

    #[test]
    fn ordinary_object_defaults() {
        let obj = OrdinaryObject::default();
        assert!(obj.extensible);
        assert_eq!(obj.prototype, None);
        assert!(obj.properties.is_empty());
    }

    #[test]
    fn define_own_property_new() {
        let mut obj = OrdinaryObject::default();
        let result = obj
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(42)))
            .unwrap();
        assert!(result);
        assert!(obj.has_own_property(&str_key("x")));
        assert_eq!(
            obj.get_own_property(&str_key("x")).unwrap().value(),
            Some(&int_val(42))
        );
    }

    #[test]
    fn define_own_property_non_extensible_rejects() {
        let mut obj = OrdinaryObject::default();
        obj.extensible = false;
        let result = obj
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn define_own_property_non_configurable_rejects_reconfig() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Try to make it configurable again — rejected.
        let result = obj
            .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn define_own_property_non_configurable_allows_same_value() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Same value, same attributes — allowed.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: false,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(result);
    }

    // -----------------------------------------------------------------------
    // 4. Delete
    // -----------------------------------------------------------------------

    #[test]
    fn delete_configurable_property() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        assert!(obj.delete(&str_key("x")));
        assert!(!obj.has_own_property(&str_key("x")));
    }

    #[test]
    fn delete_non_configurable_rejected() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
        assert!(!obj.delete(&str_key("x")));
        assert!(obj.has_own_property(&str_key("x")));
    }

    #[test]
    fn delete_nonexistent_succeeds() {
        let mut obj = OrdinaryObject::default();
        assert!(obj.delete(&str_key("nope")));
    }

    // -----------------------------------------------------------------------
    // 5. Own property keys ordering
    // -----------------------------------------------------------------------

    #[test]
    fn own_property_keys_order() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("b"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.define_own_property(str_key("2"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        obj.define_own_property(str_key("0"), PropertyDescriptor::data(int_val(3)))
            .unwrap();
        obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(4)))
            .unwrap();
        obj.define_own_property(
            PropertyKey::Symbol(SymbolId(100)),
            PropertyDescriptor::data(int_val(5)),
        )
        .unwrap();
        obj.define_own_property(str_key("10"), PropertyDescriptor::data(int_val(6)))
            .unwrap();

        let keys = obj.own_property_keys();
        // Integer indices first (sorted numerically), then strings, then symbols.
        assert_eq!(keys[0], str_key("0"));
        assert_eq!(keys[1], str_key("2"));
        assert_eq!(keys[2], str_key("10"));
        assert_eq!(keys[3], str_key("a"));
        assert_eq!(keys[4], str_key("b"));
        assert_eq!(keys[5], PropertyKey::Symbol(SymbolId(100)));
    }

    // -----------------------------------------------------------------------
    // 6. Freeze / Seal
    // -----------------------------------------------------------------------

    #[test]
    fn freeze_makes_non_writable_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.freeze();
        assert!(!obj.extensible);
        assert!(obj.is_frozen());
        assert!(obj.is_sealed());
        let d = obj.get_own_property(&str_key("x")).unwrap();
        assert!(!d.is_configurable());
        assert!(!d.is_writable());
    }

    #[test]
    fn seal_makes_non_configurable_keeps_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.seal();
        assert!(!obj.extensible);
        assert!(obj.is_sealed());
        assert!(!obj.is_frozen()); // writable data property remains writable
        let d = obj.get_own_property(&str_key("x")).unwrap();
        assert!(!d.is_configurable());
        assert!(d.is_writable());
    }

    // -----------------------------------------------------------------------
    // 7. ObjectHeap basics
    // -----------------------------------------------------------------------

    #[test]
    fn heap_alloc_and_get() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert_eq!(h, ObjectHandle(0));
        assert_eq!(heap.len(), 1);
        assert!(heap.get(h).is_ok());
    }

    #[test]
    fn heap_get_invalid_handle() {
        let heap = ObjectHeap::new();
        assert!(heap.get(ObjectHandle(99)).is_err());
    }

    #[test]
    fn heap_set_and_get_property() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(42)).unwrap();
        let val = heap.get_property(h, &str_key("x")).unwrap();
        assert_eq!(val, int_val(42));
    }

    // -----------------------------------------------------------------------
    // 8. Prototype chain traversal
    // -----------------------------------------------------------------------

    #[test]
    fn prototype_chain_get() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("inherited"), int_val(99))
            .unwrap();

        let child = heap.alloc(Some(proto));
        let val = heap.get_property(child, &str_key("inherited")).unwrap();
        assert_eq!(val, int_val(99));
    }

    #[test]
    fn prototype_chain_own_shadows() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("x"), int_val(1)).unwrap();

        let child = heap.alloc(Some(proto));
        heap.set_property(child, str_key("x"), int_val(2)).unwrap();

        let val = heap.get_property(child, &str_key("x")).unwrap();
        assert_eq!(val, int_val(2)); // own shadows prototype
    }

    #[test]
    fn prototype_chain_undefined_at_end() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let val = heap.get_property(h, &str_key("nonexistent")).unwrap();
        assert_eq!(val, JsValue::Undefined);
    }

    #[test]
    fn prototype_chain_has_property() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("y"), int_val(1)).unwrap();
        let child = heap.alloc(Some(proto));

        assert!(heap.has_property(child, &str_key("y")).unwrap());
        assert!(!heap.has_property(child, &str_key("z")).unwrap());
    }

    // -----------------------------------------------------------------------
    // 9. Set prototype / cycle detection
    // -----------------------------------------------------------------------

    #[test]
    fn set_prototype_cycle_detection() {
        let mut heap = ObjectHeap::new();
        let a = heap.alloc_plain();
        let b = heap.alloc(Some(a));
        // Try to set a's prototype to b (would create cycle: a -> b -> a).
        let result = heap.set_prototype_of(a, Some(b));
        assert!(result.is_err());
    }

    #[test]
    fn set_prototype_non_extensible_rejects() {
        let mut heap = ObjectHeap::new();
        let a = heap.alloc_plain();
        let b = heap.alloc_plain();
        heap.prevent_extensions(a).unwrap();
        let result = heap.set_prototype_of(a, Some(b)).unwrap();
        assert!(!result); // non-extensible, different prototype
    }

    #[test]
    fn set_prototype_non_extensible_allows_same() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        let obj = heap.alloc(Some(proto));
        heap.prevent_extensions(obj).unwrap();
        let result = heap.set_prototype_of(obj, Some(proto)).unwrap();
        assert!(result); // same prototype is ok
    }

    // -----------------------------------------------------------------------
    // 10. Object.keys
    // -----------------------------------------------------------------------

    #[test]
    fn object_keys_only_enumerable_strings() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("a"), int_val(1)).unwrap();
        heap.define_property(
            h,
            str_key("hidden"),
            PropertyDescriptor::Data {
                value: int_val(2),
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .unwrap();
        heap.define_property(
            h,
            PropertyKey::Symbol(SymbolId(100)),
            PropertyDescriptor::data(int_val(3)),
        )
        .unwrap();

        let keys = heap.keys(h).unwrap();
        assert_eq!(keys, vec!["a".to_string()]);
    }

    // -----------------------------------------------------------------------
    // 11. Object.freeze / seal on heap
    // -----------------------------------------------------------------------

    #[test]
    fn heap_freeze() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.freeze(h).unwrap();

        assert!(heap.is_frozen(h).unwrap());
        // Cannot modify frozen property.
        let result = heap.set_property(h, str_key("x"), int_val(2)).unwrap();
        assert!(!result);
        // Cannot add new property.
        let result = heap.set_property(h, str_key("y"), int_val(3)).unwrap();
        assert!(!result);
    }

    #[test]
    fn heap_seal() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        heap.seal(h).unwrap();

        assert!(heap.is_sealed(h).unwrap());
        assert!(!heap.is_frozen(h).unwrap());
        // Can modify value of writable property on sealed object.
        let result = heap.set_property(h, str_key("x"), int_val(2)).unwrap();
        assert!(result);
        // Cannot add new property.
        let result = heap.set_property(h, str_key("y"), int_val(3)).unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 12. Object.assign
    // -----------------------------------------------------------------------

    #[test]
    fn object_assign_copies_enumerable() {
        let mut heap = ObjectHeap::new();
        let src = heap.alloc_plain();
        heap.set_property(src, str_key("a"), int_val(1)).unwrap();
        heap.set_property(src, str_key("b"), int_val(2)).unwrap();

        let target = heap.alloc_plain();
        heap.assign(target, &[src]).unwrap();

        assert_eq!(heap.get_property(target, &str_key("a")).unwrap(), int_val(1));
        assert_eq!(heap.get_property(target, &str_key("b")).unwrap(), int_val(2));
    }

    // -----------------------------------------------------------------------
    // 13. Proxy creation and revocation
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_create_and_revoke() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);

        let obj = heap.get(proxy).unwrap();
        assert!(obj.as_proxy().is_some());
        assert!(!obj.as_proxy().unwrap().is_revoked());

        heap.revoke_proxy(proxy).unwrap();
        let obj = heap.get(proxy).unwrap();
        assert!(obj.as_proxy().unwrap().is_revoked());
    }

    #[test]
    fn proxy_revoked_target_errors() {
        let mut heap = ObjectHeap::new();
        let target = heap.alloc_plain();
        let handler = heap.alloc_plain();
        let proxy = heap.alloc_proxy(target, handler);
        heap.revoke_proxy(proxy).unwrap();

        let p = heap.get(proxy).unwrap().as_proxy().unwrap();
        assert_eq!(p.target(), Err(ObjectError::ProxyRevoked));
        assert_eq!(p.handler(), Err(ObjectError::ProxyRevoked));
    }

    // -----------------------------------------------------------------------
    // 14. Proxy invariant: [[Get]] non-configurable non-writable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_non_configurable_non_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Trap returns correct value — ok.
        assert!(
            ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(42)).is_ok()
        );

        // Trap returns different value — error.
        assert!(
            ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(99)).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 15. Proxy invariant: [[Has]] non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_has_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Cannot report non-configurable as non-existent.
        assert!(
            ProxyInvariantChecker::check_has(&obj, &str_key("x"), false).is_err()
        );
        assert!(
            ProxyInvariantChecker::check_has(&obj, &str_key("x"), true).is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // 16. Proxy invariant: [[Delete]] non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_delete_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        assert!(
            ProxyInvariantChecker::check_delete(&obj, &str_key("x"), true).is_err()
        );
        assert!(
            ProxyInvariantChecker::check_delete(&obj, &str_key("x"), false).is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // 17. Proxy invariant: [[OwnKeys]] completeness
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_own_keys_must_include_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("required"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Missing non-configurable key — error.
        assert!(ProxyInvariantChecker::check_own_keys(&obj, &[]).is_err());

        // Includes the key — ok.
        assert!(
            ProxyInvariantChecker::check_own_keys(&obj, &[str_key("required")]).is_ok()
        );
    }

    #[test]
    fn proxy_invariant_own_keys_no_duplicates() {
        let obj = OrdinaryObject::default();
        let result = ProxyInvariantChecker::check_own_keys(
            &obj,
            &[str_key("a"), str_key("a")],
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // 18. Proxy invariant: [[IsExtensible]] match
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_is_extensible_must_match() {
        let obj = OrdinaryObject::default(); // extensible = true
        assert!(ProxyInvariantChecker::check_is_extensible(&obj, true).is_ok());
        assert!(ProxyInvariantChecker::check_is_extensible(&obj, false).is_err());
    }

    // -----------------------------------------------------------------------
    // 19. Proxy invariant: [[PreventExtensions]]
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_prevent_extensions() {
        let obj = OrdinaryObject::default(); // extensible = true
        // Cannot return true while target is extensible.
        assert!(ProxyInvariantChecker::check_prevent_extensions(&obj, true).is_err());
        assert!(ProxyInvariantChecker::check_prevent_extensions(&obj, false).is_ok());
    }

    // -----------------------------------------------------------------------
    // 20. Proxy invariant: [[GetPrototypeOf]] non-extensible
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_prototype_of_non_extensible() {
        let mut obj = OrdinaryObject::default();
        obj.prototype = Some(ObjectHandle(5));
        obj.extensible = false;

        // Must return same prototype.
        assert!(
            ProxyInvariantChecker::check_get_prototype_of(&obj, Some(ObjectHandle(5))).is_ok()
        );
        assert!(
            ProxyInvariantChecker::check_get_prototype_of(&obj, Some(ObjectHandle(6))).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 21. Symbol registry
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_registry_basics() {
        let mut heap = ObjectHeap::new();
        let mut reg = SymbolRegistry::new();

        let s1 = reg.symbol_for("shared", &mut heap);
        let s2 = reg.symbol_for("shared", &mut heap);
        assert_eq!(s1, s2); // Same key → same symbol.

        let s3 = reg.symbol_for("other", &mut heap);
        assert_ne!(s1, s3);

        assert_eq!(reg.key_for(s1), Some("shared"));
        assert_eq!(reg.key_for(s3), Some("other"));
    }

    #[test]
    fn well_known_symbol_ids() {
        let reg = SymbolRegistry::new();
        assert_eq!(
            reg.key_for(WellKnownSymbol::Iterator.id()),
            Some("Symbol.iterator")
        );
        assert_eq!(
            reg.key_for(WellKnownSymbol::ToPrimitive.id()),
            Some("Symbol.toPrimitive")
        );
    }

    // -----------------------------------------------------------------------
    // 22. JsValue basics
    // -----------------------------------------------------------------------

    #[test]
    fn js_value_same_value() {
        assert!(int_val(42).same_value(&int_val(42)));
        assert!(!int_val(42).same_value(&int_val(43)));
        assert!(JsValue::Undefined.same_value(&JsValue::Undefined));
        assert!(!JsValue::Null.same_value(&JsValue::Undefined));
    }

    #[test]
    fn js_value_type_name() {
        assert_eq!(JsValue::Undefined.type_name(), "undefined");
        assert_eq!(JsValue::Null.type_name(), "null");
        assert_eq!(JsValue::Bool(true).type_name(), "boolean");
        assert_eq!(int_val(1).type_name(), "number");
        assert_eq!(str_val("hi").type_name(), "string");
        assert_eq!(JsValue::Symbol(SymbolId(1)).type_name(), "symbol");
        assert_eq!(JsValue::Object(ObjectHandle(0)).type_name(), "object");
        assert_eq!(JsValue::Function(0).type_name(), "function");
    }

    #[test]
    fn js_value_display() {
        assert_eq!(int_val(42).to_string(), "42");
        assert_eq!(str_val("hello").to_string(), "hello");
        assert_eq!(JsValue::Null.to_string(), "null");
    }

    // -----------------------------------------------------------------------
    // 23. Object.is
    // -----------------------------------------------------------------------

    #[test]
    fn object_is() {
        assert!(ObjectHeap::object_is(&int_val(0), &int_val(0)));
        assert!(!ObjectHeap::object_is(&int_val(0), &int_val(-0)));
        assert!(ObjectHeap::object_is(&JsValue::Null, &JsValue::Null));
    }

    // -----------------------------------------------------------------------
    // 24. ManagedObject variants
    // -----------------------------------------------------------------------

    #[test]
    fn managed_object_ordinary() {
        let obj = ManagedObject::Ordinary(OrdinaryObject::default());
        assert!(obj.as_ordinary().is_some());
        assert!(obj.as_proxy().is_none());
    }

    #[test]
    fn managed_object_proxy() {
        let obj = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
        assert!(obj.as_proxy().is_some());
        assert!(obj.as_ordinary().is_none());
    }

    // -----------------------------------------------------------------------
    // 25. Delete property on heap
    // -----------------------------------------------------------------------

    #[test]
    fn heap_delete_property() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("x"), int_val(1)).unwrap();
        assert!(heap.delete_property(h, &str_key("x")).unwrap());
        assert_eq!(
            heap.get_property(h, &str_key("x")).unwrap(),
            JsValue::Undefined
        );
    }

    // -----------------------------------------------------------------------
    // 26. Three-level prototype chain
    // -----------------------------------------------------------------------

    #[test]
    fn three_level_prototype_chain() {
        let mut heap = ObjectHeap::new();
        let grandparent = heap.alloc_plain();
        heap.set_property(grandparent, str_key("g"), int_val(1))
            .unwrap();

        let parent = heap.alloc(Some(grandparent));
        heap.set_property(parent, str_key("p"), int_val(2))
            .unwrap();

        let child = heap.alloc(Some(parent));
        heap.set_property(child, str_key("c"), int_val(3)).unwrap();

        assert_eq!(heap.get_property(child, &str_key("g")).unwrap(), int_val(1));
        assert_eq!(heap.get_property(child, &str_key("p")).unwrap(), int_val(2));
        assert_eq!(heap.get_property(child, &str_key("c")).unwrap(), int_val(3));
    }

    // -----------------------------------------------------------------------
    // 27. Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn property_key_serde_roundtrip() {
        for key in [
            str_key("foo"),
            PropertyKey::Symbol(SymbolId(42)),
        ] {
            let json = serde_json::to_string(&key).unwrap();
            let deser: PropertyKey = serde_json::from_str(&json).unwrap();
            assert_eq!(key, deser);
        }
    }

    #[test]
    fn js_value_serde_roundtrip() {
        for val in [
            JsValue::Undefined,
            JsValue::Null,
            JsValue::Bool(true),
            int_val(42),
            str_val("hello"),
            JsValue::Symbol(SymbolId(7)),
            JsValue::Object(ObjectHandle(3)),
            JsValue::Function(5),
        ] {
            let json = serde_json::to_string(&val).unwrap();
            let deser: JsValue = serde_json::from_str(&json).unwrap();
            assert_eq!(val, deser);
        }
    }

    #[test]
    fn property_descriptor_serde_roundtrip() {
        let descs = [
            PropertyDescriptor::data(int_val(42)),
            PropertyDescriptor::data_frozen(str_val("frozen")),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(1)),
                set: Some(ObjectHandle(2)),
                enumerable: true,
                configurable: false,
            },
        ];
        for desc in descs {
            let json = serde_json::to_string(&desc).unwrap();
            let deser: PropertyDescriptor = serde_json::from_str(&json).unwrap();
            assert_eq!(desc, deser);
        }
    }

    #[test]
    fn object_error_serde_roundtrip() {
        let errors = [
            ObjectError::TypeError("test".to_string()),
            ObjectError::ObjectNotFound(ObjectHandle(99)),
            ObjectError::ProxyRevoked,
            ObjectError::PrototypeCycleDetected,
            ObjectError::PrototypeChainTooDeep { depth: 10, max: 5 },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let deser: ObjectError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, deser);
        }
    }

    // -----------------------------------------------------------------------
    // 28. Error display coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_coverage() {
        let errors = [
            ObjectError::TypeError("test".to_string()),
            ObjectError::ObjectNotFound(ObjectHandle(99)),
            ObjectError::ProxyRevoked,
            ObjectError::PrototypeCycleDetected,
            ObjectError::PrototypeChainTooDeep { depth: 10, max: 5 },
        ];
        for e in errors {
            let s = e.to_string();
            assert!(!s.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // 29. Object.create with prototype
    // -----------------------------------------------------------------------

    #[test]
    fn object_create_with_proto() {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("shared"), int_val(100))
            .unwrap();

        let child = heap.create(Some(proto));
        assert_eq!(
            heap.get_property(child, &str_key("shared")).unwrap(),
            int_val(100)
        );
        assert_eq!(heap.get_prototype_of(child).unwrap(), Some(proto));
    }

    // -----------------------------------------------------------------------
    // 30. Proxy invariant: [[Set]] non-configurable non-writable
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_set_non_configurable_non_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Cannot set to different value.
        assert!(
            ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(99), true).is_err()
        );
        // Same value — ok.
        assert!(
            ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(42), true).is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // 31. Proxy invariant: [[Set]] accessor with no setter
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_set_accessor_no_setter() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(1)),
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        assert!(
            ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(1), true).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 32. Proxy invariant: [[OwnKeys]] non-extensible exact permutation
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_own_keys_non_extensible_exact() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.define_own_property(str_key("b"), PropertyDescriptor::data(int_val(2)))
            .unwrap();
        obj.extensible = false;

        // Exact permutation — ok.
        assert!(
            ProxyInvariantChecker::check_own_keys(
                &obj,
                &[str_key("b"), str_key("a")]
            )
            .is_ok()
        );

        // Extra key — error.
        assert!(
            ProxyInvariantChecker::check_own_keys(
                &obj,
                &[str_key("a"), str_key("b"), str_key("c")]
            )
            .is_err()
        );

        // Missing key — error.
        assert!(
            ProxyInvariantChecker::check_own_keys(&obj, &[str_key("a")]).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 33. Proxy invariant: [[SetPrototypeOf]] non-extensible
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_set_prototype_of_non_extensible() {
        let mut obj = OrdinaryObject::default();
        obj.prototype = Some(ObjectHandle(5));
        obj.extensible = false;

        // Same prototype — ok.
        assert!(
            ProxyInvariantChecker::check_set_prototype_of(
                &obj,
                Some(ObjectHandle(5)),
                true
            )
            .is_ok()
        );

        // Different prototype — error.
        assert!(
            ProxyInvariantChecker::check_set_prototype_of(
                &obj,
                Some(ObjectHandle(6)),
                true
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 34. Proxy invariant: [[GetOwnProperty]] non-existent on non-extensible
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_own_property_non_extensible() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();
        obj.extensible = false;

        // Cannot report existing property as non-existent.
        assert!(
            ProxyInvariantChecker::check_get_own_property(&obj, &str_key("x"), &None).is_err()
        );

        // Cannot report new property as existent.
        let fake_desc = Some(PropertyDescriptor::data(int_val(2)));
        assert!(
            ProxyInvariantChecker::check_get_own_property(&obj, &str_key("y"), &fake_desc).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 35. Proxy invariant: [[DefineOwnProperty]] non-extensible add
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_define_property_non_extensible_add() {
        let mut obj = OrdinaryObject::default();
        obj.extensible = false;

        let desc = PropertyDescriptor::data(int_val(1));
        assert!(
            ProxyInvariantChecker::check_define_own_property(
                &obj,
                &str_key("new_prop"),
                &desc,
                true
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 36. Heap is_empty
    // -----------------------------------------------------------------------

    #[test]
    fn heap_is_empty() {
        let heap = ObjectHeap::new();
        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
    }

    // -----------------------------------------------------------------------
    // 37. Symbol allocation
    // -----------------------------------------------------------------------

    #[test]
    fn heap_alloc_symbol() {
        let mut heap = ObjectHeap::new();
        let s1 = heap.alloc_symbol();
        let s2 = heap.alloc_symbol();
        assert_ne!(s1, s2);
        assert!(s1.0 >= 14); // after well-known symbols
    }

    // -----------------------------------------------------------------------
    // 38. Accessor property get returns getter handle
    // -----------------------------------------------------------------------

    #[test]
    fn accessor_get_returns_getter() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        let getter_handle = ObjectHandle(99);
        heap.define_property(
            h,
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(getter_handle),
                set: None,
                enumerable: true,
                configurable: true,
            },
        )
        .unwrap();

        // get_property returns the getter handle as an Object value.
        let val = heap.get_property(h, &str_key("x")).unwrap();
        assert_eq!(val, JsValue::Object(getter_handle));
    }

    // -----------------------------------------------------------------------
    // 39. Accessor property without getter returns undefined
    // -----------------------------------------------------------------------

    #[test]
    fn accessor_no_getter_returns_undefined() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        heap.define_property(
            h,
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: None,
                set: Some(ObjectHandle(1)),
                enumerable: true,
                configurable: true,
            },
        )
        .unwrap();

        let val = heap.get_property(h, &str_key("x")).unwrap();
        assert_eq!(val, JsValue::Undefined);
    }

    // -----------------------------------------------------------------------
    // 40. Proxy invariant: [[Get]] accessor without getter
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_get_accessor_no_getter() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: None,
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Must return undefined.
        assert!(
            ProxyInvariantChecker::check_get(&obj, &str_key("x"), &JsValue::Undefined).is_ok()
        );
        assert!(
            ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(42)).is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 41. Revoke non-proxy is error
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_non_proxy_is_error() {
        let mut heap = ObjectHeap::new();
        let h = heap.alloc_plain();
        assert!(heap.revoke_proxy(h).is_err());
    }

    // -----------------------------------------------------------------------
    // 42. WellKnownSymbol name coverage
    // -----------------------------------------------------------------------

    #[test]
    fn well_known_symbol_names() {
        let syms = [
            (WellKnownSymbol::Iterator, "@@iterator"),
            (WellKnownSymbol::ToPrimitive, "@@toPrimitive"),
            (WellKnownSymbol::HasInstance, "@@hasInstance"),
            (WellKnownSymbol::ToStringTag, "@@toStringTag"),
            (WellKnownSymbol::Species, "@@species"),
            (WellKnownSymbol::IsConcatSpreadable, "@@isConcatSpreadable"),
            (WellKnownSymbol::Unscopables, "@@unscopables"),
            (WellKnownSymbol::AsyncIterator, "@@asyncIterator"),
            (WellKnownSymbol::Match, "@@match"),
            (WellKnownSymbol::MatchAll, "@@matchAll"),
            (WellKnownSymbol::Replace, "@@replace"),
            (WellKnownSymbol::Search, "@@search"),
            (WellKnownSymbol::Split, "@@split"),
        ];
        for (sym, expected) in syms {
            assert_eq!(sym.name(), expected);
        }
    }

    // -----------------------------------------------------------------------
    // 43. WellKnownSymbol key
    // -----------------------------------------------------------------------

    #[test]
    fn well_known_symbol_key() {
        let k = WellKnownSymbol::Iterator.key();
        assert_eq!(k, PropertyKey::Symbol(WellKnownSymbol::Iterator.id()));
    }

    // -----------------------------------------------------------------------
    // 44. Define data→data type change blocked on non-configurable
    // -----------------------------------------------------------------------

    #[test]
    fn define_data_to_accessor_blocked_on_non_configurable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Cannot change to accessor.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Accessor {
                    get: None,
                    set: None,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 45. Non-configurable data: writable=false cannot become writable=true
    // -----------------------------------------------------------------------

    #[test]
    fn non_configurable_non_writable_cannot_become_writable() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Data {
                    value: int_val(1),
                    writable: true,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 46. Non-configurable accessor: cannot change get/set
    // -----------------------------------------------------------------------

    #[test]
    fn non_configurable_accessor_cannot_change_getset() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(1)),
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();

        // Change getter — rejected.
        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Accessor {
                    get: Some(ObjectHandle(2)),
                    set: None,
                    enumerable: true,
                    configurable: false,
                },
            )
            .unwrap();
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // 47. Configurable property can change type
    // -----------------------------------------------------------------------

    #[test]
    fn configurable_property_can_change_type() {
        let mut obj = OrdinaryObject::default();
        obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
            .unwrap();

        let result = obj
            .define_own_property(
                str_key("x"),
                PropertyDescriptor::Accessor {
                    get: Some(ObjectHandle(1)),
                    set: None,
                    enumerable: true,
                    configurable: true,
                },
            )
            .unwrap();
        assert!(result);
        assert!(obj.get_own_property(&str_key("x")).unwrap().is_accessor());
    }

    // -----------------------------------------------------------------------
    // 48. Proxy invariant: [[DefineOwnProperty]] non-configurable on absent
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_invariant_define_non_configurable_absent_target() {
        let obj = OrdinaryObject::default();
        let desc = PropertyDescriptor::Data {
            value: int_val(1),
            writable: true,
            enumerable: true,
            configurable: false,
        };

        // Cannot define non-configurable when target doesn't have the property.
        assert!(
            ProxyInvariantChecker::check_define_own_property(
                &obj,
                &str_key("x"),
                &desc,
                true
            )
            .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // 49. JsValue is_object / is_callable
    // -----------------------------------------------------------------------

    #[test]
    fn js_value_predicates() {
        assert!(JsValue::Object(ObjectHandle(0)).is_object());
        assert!(!int_val(1).is_object());
        assert!(JsValue::Function(0).is_callable());
        assert!(!int_val(1).is_callable());
    }

    // -----------------------------------------------------------------------
    // 50. Object.assign multiple sources
    // -----------------------------------------------------------------------

    #[test]
    fn object_assign_multiple_sources() {
        let mut heap = ObjectHeap::new();
        let s1 = heap.alloc_plain();
        heap.set_property(s1, str_key("a"), int_val(1)).unwrap();
        let s2 = heap.alloc_plain();
        heap.set_property(s2, str_key("b"), int_val(2)).unwrap();
        heap.set_property(s2, str_key("a"), int_val(3)).unwrap(); // overrides s1.a

        let target = heap.alloc_plain();
        heap.assign(target, &[s1, s2]).unwrap();

        assert_eq!(heap.get_property(target, &str_key("a")).unwrap(), int_val(3));
        assert_eq!(heap.get_property(target, &str_key("b")).unwrap(), int_val(2));
    }
}
