use serde::Serialize;

use crate::relation::{Equivalence, GeneratedPair, MetamorphicRelation, RelationSpec};

pub struct ParserWhitespaceInvariance {
    spec: RelationSpec,
}

impl ParserWhitespaceInvariance {
    pub fn new(spec: RelationSpec) -> Self {
        Self { spec }
    }

    fn semantic_signature(source: &str) -> Result<String, String> {
        if source.trim().is_empty() {
            return Err("source is empty after whitespace normalization".to_string());
        }

        #[derive(Serialize)]
        struct SemanticProgram {
            statements: Vec<SemanticStatement>,
        }

        #[derive(Serialize)]
        struct SemanticStatement {
            expression: String,
        }

        let statements = source
            .split(';')
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(|segment| SemanticStatement {
                expression: Self::semantic_expression(segment),
            })
            .collect::<Vec<_>>();

        if statements.is_empty() {
            return Err("no statements remain after segmentation".to_string());
        }

        serde_json::to_string(&SemanticProgram { statements })
            .map_err(|error| format!("semantic serialization failed: {error}"))
    }

    fn semantic_expression(expression: &str) -> String {
        let normalized = Self::canonicalize_whitespace(expression);

        if let Some(value) = Self::parse_quoted_string(&normalized) {
            return format!("string:{value}");
        }

        if let Ok(value) = normalized.parse::<i64>() {
            return format!("int:{value}");
        }

        if let Some(rest) = normalized.strip_prefix("await ") {
            return format!("await:{}", Self::semantic_expression(rest));
        }

        if Self::is_identifier(&normalized) {
            return format!("ident:{normalized}");
        }

        format!("raw:{normalized}")
    }

    fn parse_quoted_string(input: &str) -> Option<String> {
        if input.len() < 2 {
            return None;
        }

        let first = input.as_bytes()[0];
        let last = input.as_bytes()[input.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            let inner = &input[1..input.len() - 1];
            if inner.contains('\n') || inner.contains('\r') {
                return None;
            }
            return Some(inner.to_string());
        }

        None
    }

    fn is_identifier(input: &str) -> bool {
        let mut chars = input.chars();
        let Some(first) = chars.next() else {
            return false;
        };

        if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
            return false;
        }

        chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    }

    fn canonicalize_whitespace(input: &str) -> String {
        input.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn check_equivalence(&self, pair: &GeneratedPair) -> Equivalence {
        let input_signature = match Self::semantic_signature(&pair.input_source) {
            Ok(signature) => signature,
            Err(error) => {
                return Equivalence::Diverged {
                    detail: format!("input normalization failure: {error}"),
                };
            }
        };

        let variant_signature = match Self::semantic_signature(&pair.variant_source) {
            Ok(signature) => signature,
            Err(error) => {
                return Equivalence::Diverged {
                    detail: format!("variant normalization failure: {error}"),
                };
            }
        };

        if input_signature == variant_signature {
            Equivalence::Equivalent
        } else {
            Equivalence::Diverged {
                detail: format!(
                    "semantic signatures differ: input={input_signature} variant={variant_signature}"
                ),
            }
        }
    }
}

impl MetamorphicRelation for ParserWhitespaceInvariance {
    fn spec(&self) -> &RelationSpec {
        &self.spec
    }

    fn generate_pair(&self, seed: u64) -> GeneratedPair {
        const IDENTIFIERS: [&str; 8] = [
            "alpha", "beta", "gamma", "delta", "theta", "sigma", "omega", "kappa",
        ];

        let lhs = IDENTIFIERS[(seed as usize) % IDENTIFIERS.len()];
        let rhs = IDENTIFIERS[((seed >> 8) as usize) % IDENTIFIERS.len()];

        let style = (seed % 3) as u8;
        let (input_source, variant_source) = match style {
            0 => (format!("{lhs};"), format!("  {lhs}  ;")),
            1 => (format!("await {lhs};"), format!("await   {lhs}  ;")),
            _ => (
                format!("\"{lhs}_{rhs}\";"),
                format!("   \"{lhs}_{rhs}\"   ;"),
            ),
        };

        GeneratedPair {
            input_source,
            variant_source,
        }
    }

    fn oracle(&self, pair: &GeneratedPair) -> Equivalence {
        self.check_equivalence(pair)
    }
}

#[cfg(test)]
mod tests {
    use crate::relation::{GeneratedPair, MetamorphicRelation, RelationSpec, Subsystem};

    use super::ParserWhitespaceInvariance;

    fn relation() -> ParserWhitespaceInvariance {
        ParserWhitespaceInvariance::new(RelationSpec {
            id: "parser_whitespace_invariance".to_string(),
            subsystem: Subsystem::Parser,
            description: "test relation".to_string(),
            budget_pairs: 1000,
            enabled: true,
        })
    }

    #[test]
    fn generation_is_deterministic_for_seed() {
        let relation = relation();
        let left = relation.generate_pair(42);
        let right = relation.generate_pair(42);
        assert_eq!(left, right);
    }

    #[test]
    fn curated_pairs_hold_whitespace_invariance() {
        let relation = relation();
        let curated = [
            ("alpha;", "   alpha ;"),
            ("await alpha;", "await   alpha;"),
            ("\"hello\";", " \"hello\"   ;"),
            ("123;", "   123 ;"),
            ("beta;", "beta     ;"),
        ];

        for (input_source, variant_source) in curated {
            let pair = GeneratedPair {
                input_source: input_source.to_string(),
                variant_source: variant_source.to_string(),
            };
            assert!(
                relation.oracle(&pair).is_equivalent(),
                "pair should be equivalent"
            );
        }
    }

    #[test]
    fn divergent_semantics_are_reported() {
        let relation = relation();
        let pair = GeneratedPair {
            input_source: "alpha+beta;".to_string(),
            variant_source: "alpha-beta;".to_string(),
        };
        assert!(!relation.oracle(&pair).is_equivalent());
    }

    #[test]
    fn run_once_preserves_trace_and_relation_metadata() {
        let relation = relation();
        let outcome = relation.run_once("trace-1", 7);
        assert_eq!(outcome.trace_id, "trace-1");
        assert_eq!(outcome.relation_id, "parser_whitespace_invariance");
        assert_eq!(outcome.subsystem, Subsystem::Parser);
    }
}
