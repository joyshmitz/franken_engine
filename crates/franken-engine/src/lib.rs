#![forbid(unsafe_code)]

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Execution lanes are de novo native Rust implementations inspired by
/// proven ideas from QuickJS and V8, not FFI wrappers over external engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineKind {
    QuickJsInspiredNative,
    V8InspiredNative,
    Hybrid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalOutcome {
    pub engine: EngineKind,
    pub value: String,
}

pub trait JsEngine {
    fn kind(&self) -> EngineKind;
    fn eval(&mut self, source: &str) -> Result<EvalOutcome>;
}

#[derive(Debug, Default)]
pub struct QuickJsInspiredNativeEngine;

#[derive(Debug, Default)]
pub struct V8InspiredNativeEngine;

impl JsEngine for QuickJsInspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::QuickJsInspiredNative
    }

    fn eval(&mut self, source: &str) -> Result<EvalOutcome> {
        if source.trim().is_empty() {
            bail!("source is empty");
        }
        Ok(EvalOutcome {
            engine: EngineKind::QuickJsInspiredNative,
            value: source.trim().to_string(),
        })
    }
}

impl JsEngine for V8InspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::V8InspiredNative
    }

    fn eval(&mut self, source: &str) -> Result<EvalOutcome> {
        if source.trim().is_empty() {
            bail!("source is empty");
        }
        Ok(EvalOutcome {
            engine: EngineKind::V8InspiredNative,
            value: source.trim().to_string(),
        })
    }
}

#[derive(Debug)]
pub struct HybridRouter {
    quickjs_lineage: QuickJsInspiredNativeEngine,
    v8_lineage: V8InspiredNativeEngine,
}

impl Default for HybridRouter {
    fn default() -> Self {
        Self {
            quickjs_lineage: QuickJsInspiredNativeEngine,
            v8_lineage: V8InspiredNativeEngine,
        }
    }
}

impl HybridRouter {
    pub fn eval(&mut self, source: &str) -> Result<EvalOutcome> {
        let prefers_v8 = source.contains("import ") || source.contains("await ");
        if prefers_v8 {
            return self.v8_lineage.eval(source);
        }
        self.quickjs_lineage.eval(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_routes_simple_input_to_quickjs() {
        let mut router = HybridRouter::default();
        let out = router.eval("1 + 1").expect("eval");
        assert_eq!(out.engine, EngineKind::QuickJsInspiredNative);
    }

    #[test]
    fn hybrid_routes_import_to_v8() {
        let mut router = HybridRouter::default();
        let out = router.eval("import x from 'y'").expect("eval");
        assert_eq!(out.engine, EngineKind::V8InspiredNative);
    }
}
