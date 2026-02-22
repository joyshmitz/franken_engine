use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    Parser,
    Ir,
    Execution,
}

impl Subsystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Ir => "ir",
            Self::Execution => "execution",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleKind {
    AstEquality,
    IrEquality,
    CanonicalOutputEquality,
    SideEffectTraceEquality,
}

impl OracleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AstEquality => "ast_equality",
            Self::IrEquality => "ir_equality",
            Self::CanonicalOutputEquality => "canonical_output_equality",
            Self::SideEffectTraceEquality => "side_effect_trace_equality",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationSpec {
    pub id: String,
    pub subsystem: Subsystem,
    pub description: String,
    pub oracle: OracleKind,
    pub budget_pairs: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedPair {
    pub input_source: String,
    pub variant_source: String,
}

impl GeneratedPair {
    pub fn size_metric(&self) -> usize {
        self.input_source
            .len()
            .saturating_add(self.variant_source.len())
    }

    pub fn ast_node_metric(&self) -> usize {
        let left = self
            .input_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .count();
        let right = self
            .variant_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .count();
        left.saturating_add(right)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Equivalence {
    Equivalent,
    Diverged { detail: String },
}

impl Equivalence {
    pub fn is_equivalent(&self) -> bool {
        matches!(self, Self::Equivalent)
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Equivalent => None,
            Self::Diverged { detail } => Some(detail.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationRunOutcome {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: Subsystem,
    pub oracle: OracleKind,
    pub seed: u64,
    pub pair: GeneratedPair,
    pub equivalence: Equivalence,
}

pub trait MetamorphicRelation {
    fn spec(&self) -> &RelationSpec;

    fn generate_pair(&self, seed: u64) -> GeneratedPair;

    fn oracle(&self, pair: &GeneratedPair) -> Equivalence;

    fn validate_program(&self, source: &str) -> bool;

    fn run_once(
        &self,
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
        component: &str,
        seed: u64,
    ) -> RelationRunOutcome {
        let pair = self.generate_pair(seed);
        let equivalence = self.oracle(&pair);
        let outcome = if equivalence.is_equivalent() {
            "pass"
        } else {
            "fail"
        };

        RelationRunOutcome {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: component.to_string(),
            event: "pair_evaluated".to_string(),
            outcome: outcome.to_string(),
            error_code: if equivalence.is_equivalent() {
                None
            } else {
                Some("FE-META-0001".to_string())
            },
            relation_id: self.spec().id.clone(),
            subsystem: self.spec().subsystem,
            oracle: self.spec().oracle,
            seed,
            pair,
            equivalence,
        }
    }
}
