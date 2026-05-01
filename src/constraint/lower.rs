//! Condition lowering: CFG/SSA branch conditions → structured [`ConditionExpr`].
//!
//! This is the **only** module where `condition_text` is parsed. Everything
//! downstream operates on structured types with [`SsaValue`] keys.
//!
//! ## Lowering hierarchy (structured first, text fallback)
//!
//! 1. **Structural:** `condition_negated` (AST-level boolean)
//! 2. **Structural:** `condition_vars` (AST-extracted identifiers)
//! 3. **Structural:** compound decomposition (already handled by
//!    `build_condition_chain`, each leaf is a separate Block/Branch)
//! 4. **Structural:** `value_defs`, resolve var names to [`SsaValue`]s
//! 5. **Structural:** `const_values`, augment with known constants
//! 6. **Text fallback:** `condition_text`, parse comparison operator and
//!    literal operand. Necessary because individual comparisons are NOT
//!    decomposed into separate SSA operations (condition nodes → `Nop`).

#![allow(clippy::collapsible_if)]

use crate::cfg::NodeInfo;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::{BlockId, SsaBody, SsaValue};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

use super::domain::ConstValue;

// ── Operand ─────────────────────────────────────────────────────────────

/// An operand in a condition expression.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    /// A resolved SSA value.
    Value(SsaValue),
    /// A constant literal extracted from the condition.
    Const(ConstValue),
    /// Could not resolve.
    Unknown,
}

// ── CompOp ──────────────────────────────────────────────────────────────

/// Comparison operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompOp {
    Eq,
    Neq,
    Lt,
    Gt,
    Le,
    Ge,
}

impl CompOp {
    /// Flip the operator (swap operands): `a < b` becomes `b > a`.
    pub fn flip(self) -> Self {
        match self {
            Self::Lt => Self::Gt,
            Self::Gt => Self::Lt,
            Self::Le => Self::Ge,
            Self::Ge => Self::Le,
            other => other, // Eq, Neq are symmetric
        }
    }

    /// Negate the operator: `<` becomes `>=`.
    pub fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Neq,
            Self::Neq => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Ge => Self::Lt,
            Self::Gt => Self::Le,
            Self::Le => Self::Gt,
        }
    }
}

// ── ConditionExpr ───────────────────────────────────────────────────────

/// Structured condition expression with SSA-resolved operands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionExpr {
    /// `lhs op rhs`, e.g., `x > 5`, `x == y`.
    Comparison {
        lhs: Operand,
        op: CompOp,
        rhs: Operand,
    },
    /// Null check: `x == null` / `x != null`.
    NullCheck { var: SsaValue, is_null: bool },
    /// Type check: `typeof x === "string"`.
    TypeCheck {
        var: SsaValue,
        type_name: String,
        positive: bool,
    },
    /// Boolean truthiness test: `if (x)`.
    BoolTest { var: SsaValue },
    /// Could not parse or resolve, conservatively no refinement.
    Unknown,
}

impl ConditionExpr {
    /// Structurally negate a condition expression.
    pub fn negate(&self) -> Self {
        match self {
            Self::Comparison { lhs, op, rhs } => Self::Comparison {
                lhs: lhs.clone(),
                op: op.negate(),
                rhs: rhs.clone(),
            },
            Self::NullCheck { var, is_null } => Self::NullCheck {
                var: *var,
                is_null: !is_null,
            },
            Self::TypeCheck {
                var,
                type_name,
                positive,
            } => Self::TypeCheck {
                var: *var,
                type_name: type_name.clone(),
                positive: !positive,
            },
            // BoolTest negation: handled by the solver using polarity
            Self::BoolTest { .. } | Self::Unknown => self.clone(),
        }
    }
}

// ── Condition lowering ──────────────────────────────────────────────────

/// Lower a branch condition from CFG metadata to a structured
/// [`ConditionExpr`] with SSA-resolved operands.
///
/// Uses structured metadata first (condition_negated, condition_vars,
/// value_defs, const_values), falling back to condition_text parsing
/// for comparison operators and literals.
pub fn lower_condition(
    cond_info: &NodeInfo,
    ssa: &SsaBody,
    branch_block: BlockId,
    const_values: Option<&HashMap<SsaValue, ConstLattice>>,
) -> ConditionExpr {
    let text = match cond_info.condition_text.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return ConditionExpr::Unknown,
    };

    if cond_info.condition_vars.is_empty() {
        return ConditionExpr::Unknown;
    }

    // Step 1: Resolve condition variable names to SsaValues
    let resolved = resolve_condition_vars(&cond_info.condition_vars, ssa, branch_block);

    // Step 2: Build a name→SsaValue lookup
    let var_lookup: HashMap<&str, SsaValue> = resolved
        .iter()
        .map(|(name, val)| (name.as_str(), *val))
        .collect();

    // Step 3: Check if any resolved values have known constants
    let const_lookup: HashMap<SsaValue, ConstValue> = if let Some(cv) = const_values {
        resolved
            .iter()
            .filter_map(|(_, v)| {
                cv.get(v)
                    .and_then(ConstValue::from_const_lattice)
                    .map(|c| (*v, c))
            })
            .collect()
    } else {
        HashMap::new()
    };

    // Step 4: Try structured patterns, then text fallback
    let lower = text.to_ascii_lowercase();

    let expr = try_lower_null_check(text, &lower, &var_lookup)
        .or_else(|| try_lower_type_check(text, &lower, &var_lookup))
        .or_else(|| try_lower_comparison(text, &var_lookup, &const_lookup))
        .unwrap_or_else(|| {
            // Fallback: if exactly one condition_var, treat as BoolTest
            if resolved.len() == 1 {
                ConditionExpr::BoolTest { var: resolved[0].1 }
            } else {
                ConditionExpr::Unknown
            }
        });

    // Apply structural negation from condition_negated
    if cond_info.condition_negated {
        expr.negate()
    } else {
        expr
    }
}

/// Lower a branch condition using var_stacks from SSA construction.
///
/// Called during SSA lowering when the full [`SsaBody`] is not yet available.
/// Resolves variables via `var_stacks[name].last()` (the current reaching
/// definition) instead of scanning `value_defs`. Does not use `const_values`
/// (unavailable at lowering time); constants are seeded into [`PathEnv`]
/// separately via `seed_from_optimization`.
pub fn lower_condition_with_stacks(
    cond_info: &NodeInfo,
    var_stacks: &HashMap<String, Vec<SsaValue>>,
) -> ConditionExpr {
    let text = match cond_info.condition_text.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return ConditionExpr::Unknown,
    };

    if cond_info.condition_vars.is_empty() {
        return ConditionExpr::Unknown;
    }

    // Resolve via var_stacks: each var's current reaching definition
    let resolved: Vec<(String, SsaValue)> = cond_info
        .condition_vars
        .iter()
        .filter_map(|name| {
            var_stacks
                .get(name)
                .and_then(|stack| stack.last().copied())
                .map(|v| (name.clone(), v))
        })
        .collect();

    if resolved.is_empty() {
        return ConditionExpr::Unknown;
    }

    let var_lookup: HashMap<&str, SsaValue> = resolved
        .iter()
        .map(|(name, val)| (name.as_str(), *val))
        .collect();

    // No const_values at lowering time, empty lookup
    let const_lookup: HashMap<SsaValue, super::domain::ConstValue> = HashMap::new();

    let lower = text.to_ascii_lowercase();

    let expr = try_lower_null_check(text, &lower, &var_lookup)
        .or_else(|| try_lower_type_check(text, &lower, &var_lookup))
        .or_else(|| try_lower_comparison(text, &var_lookup, &const_lookup))
        .unwrap_or_else(|| {
            if resolved.len() == 1 {
                ConditionExpr::BoolTest { var: resolved[0].1 }
            } else {
                ConditionExpr::Unknown
            }
        });

    if cond_info.condition_negated {
        expr.negate()
    } else {
        expr
    }
}

// ── Variable resolution ─────────────────────────────────────────────────

/// Resolve condition variable names to their reaching SSA definitions.
///
/// Uses `ssa.value_defs` (SSA structural metadata) to find definitions,
/// not instruction body scanning. For each variable name:
///
/// 1. Find all definitions with that name via `value_defs`.
/// 2. Prefer the definition in the current block (reaching def at block end).
/// 3. If no def in current block, take the highest-indexed def whose
///    block precedes the current block (approximate dominator walk).
pub fn resolve_condition_vars(
    vars: &[String],
    ssa: &SsaBody,
    block: BlockId,
) -> SmallVec<[(String, SsaValue); 4]> {
    let mut result = SmallVec::new();

    for var_name in vars {
        if let Some(val) = resolve_single_var(var_name, ssa, block) {
            result.push((var_name.clone(), val));
        }
    }

    result
}

fn resolve_single_var(var_name: &str, ssa: &SsaBody, block: BlockId) -> Option<SsaValue> {
    let mut best_in_block: Option<SsaValue> = None;
    let mut best_outside: Option<SsaValue> = None;

    for (idx, vd) in ssa.value_defs.iter().enumerate() {
        if vd.var_name.as_deref() != Some(var_name) {
            continue;
        }
        let v = SsaValue(idx as u32);
        if vd.block == block {
            // Prefer highest index in current block (last definition)
            best_in_block = Some(match best_in_block {
                Some(existing) if existing.0 > v.0 => existing,
                _ => v,
            });
        } else {
            // Outside current block: take highest index (approximate)
            best_outside = Some(match best_outside {
                Some(existing) if existing.0 > v.0 => existing,
                _ => v,
            });
        }
    }

    best_in_block.or(best_outside)
}

// ── Null check lowering ─────────────────────────────────────────────────

fn try_lower_null_check(
    text: &str,
    lower: &str,
    var_lookup: &HashMap<&str, SsaValue>,
) -> Option<ConditionExpr> {
    // Patterns: "x == null", "x === null", "x != null", "x !== null"
    //           "x is None", "x is not None", "x == nil", "x != nil"

    let is_null;
    let var_name;

    // Python "is None" / "is not None"
    if lower.contains(" is not none") {
        is_null = false;
        var_name = extract_before(text, " is not ");
    } else if lower.contains(" is none") {
        is_null = true;
        var_name = extract_before(text, " is ");
    }
    // JS/TS/Java null checks
    else if let Some((lhs, rhs, negated)) = try_split_equality(text) {
        let lhs_t = lhs.trim();
        let rhs_t = rhs.trim();
        let lhs_lower = lhs_t.to_ascii_lowercase();
        let rhs_lower = rhs_t.to_ascii_lowercase();

        let (null_side, var_side) =
            if lhs_lower == "null" || lhs_lower == "nil" || lhs_lower == "none" {
                (true, rhs_t)
            } else if rhs_lower == "null" || rhs_lower == "nil" || rhs_lower == "none" {
                (true, lhs_t)
            } else {
                return None; // Not a null check
            };

        if !null_side {
            return None;
        }
        var_name = Some(var_side);
        is_null = !negated;
    } else {
        return None;
    }

    let var_name = var_name?;
    let var_name_trimmed = var_name.trim();
    let ssa_val = var_lookup.get(var_name_trimmed)?;
    Some(ConditionExpr::NullCheck {
        var: *ssa_val,
        is_null,
    })
}

// ── Type check lowering ─────────────────────────────────────────────────

fn try_lower_type_check(
    text: &str,
    lower: &str,
    var_lookup: &HashMap<&str, SsaValue>,
) -> Option<ConditionExpr> {
    // Pattern: "typeof x === 'string'"
    if lower.starts_with("typeof ") {
        let rest = &text[7..]; // skip "typeof "
        let (lhs, rhs, negated) = try_split_equality(rest)?;
        let var_part = lhs.trim();
        let type_part = rhs.trim();
        // Strip quotes from type
        let type_name = strip_quotes(type_part)?;
        let ssa_val = var_lookup.get(var_part)?;
        return Some(ConditionExpr::TypeCheck {
            var: *ssa_val,
            type_name: type_name.to_string(),
            positive: !negated,
        });
    }

    // Pattern: "isinstance(x, int)" (Python)
    if lower.starts_with("isinstance(") && lower.ends_with(')') {
        let inner = &text[11..text.len() - 1]; // strip isinstance( ... )
        let comma = inner.find(',')?;
        let var_part = inner[..comma].trim();
        let type_part = inner[comma + 1..].trim();
        let ssa_val = var_lookup.get(var_part)?;
        return Some(ConditionExpr::TypeCheck {
            var: *ssa_val,
            type_name: type_part.to_string(),
            positive: true,
        });
    }

    // Pattern: PHP "is_numeric(x)", "is_string(x)", etc.
    if lower.starts_with("is_") && lower.ends_with(')') {
        if let Some(paren) = text.find('(') {
            let type_part = &text[3..paren]; // "numeric", "string", etc.
            let var_part = text[paren + 1..text.len() - 1].trim();
            let ssa_val = var_lookup.get(var_part)?;
            return Some(ConditionExpr::TypeCheck {
                var: *ssa_val,
                type_name: type_part.to_string(),
                positive: true,
            });
        }
    }

    // Pattern: "x instanceof String" (Java/TypeScript)
    if let Some(pos) = lower.find(" instanceof ") {
        let var_part = text[..pos].trim();
        let type_part = text[pos + " instanceof ".len()..].trim();
        if let Some(ssa_val) = var_lookup.get(var_part) {
            return Some(ConditionExpr::TypeCheck {
                var: *ssa_val,
                type_name: type_part.to_string(),
                positive: true,
            });
        }
    }

    // Pattern: "x.is_a?(Integer)" / "x.kind_of?(Integer)" (Ruby)
    for method in &[".is_a?(", ".kind_of?("] {
        if let Some(dot_pos) = lower.find(method) {
            let var_part = text[..dot_pos].trim();
            let after = dot_pos + method.len();
            if let Some(close) = text[after..].find(')') {
                let type_part = text[after..after + close].trim();
                if let Some(ssa_val) = var_lookup.get(var_part) {
                    return Some(ConditionExpr::TypeCheck {
                        var: *ssa_val,
                        type_name: type_part.to_string(),
                        positive: true,
                    });
                }
            }
        }
    }

    None
}

// ── Comparison lowering ─────────────────────────────────────────────────

fn try_lower_comparison(
    text: &str,
    var_lookup: &HashMap<&str, SsaValue>,
    const_lookup: &HashMap<SsaValue, ConstValue>,
) -> Option<ConditionExpr> {
    // Find comparison operator (longest first to avoid prefix conflicts)
    let operators = ["===", "!==", "==", "!=", ">=", "<=", ">", "<"];
    let mut found_op = None;
    let mut found_pos = 0;
    let mut found_len = 0;

    for op_str in &operators {
        if let Some(pos) = text.find(op_str) {
            // Avoid matching inside strings
            if found_op.is_none() || op_str.len() > found_len {
                found_op = Some(*op_str);
                found_pos = pos;
                found_len = op_str.len();
            }
        }
    }

    let op_str = found_op?;
    let lhs = text[..found_pos].trim();
    let rhs = text[found_pos + found_len..].trim();

    let op = match op_str {
        "===" | "==" => CompOp::Eq,
        "!==" | "!=" => CompOp::Neq,
        "<" => CompOp::Lt,
        ">" => CompOp::Gt,
        "<=" => CompOp::Le,
        ">=" => CompOp::Ge,
        _ => return None,
    };

    // Resolve operands
    let lhs_op = resolve_operand(lhs, var_lookup, const_lookup);
    let rhs_op = resolve_operand(rhs, var_lookup, const_lookup);

    // Need at least one Value operand
    // If both unknown, nothing useful
    if matches!(&lhs_op, Operand::Unknown) && matches!(&rhs_op, Operand::Unknown) {
        return None;
    }

    Some(ConditionExpr::Comparison {
        lhs: lhs_op,
        op,
        rhs: rhs_op,
    })
}

fn resolve_operand(
    text: &str,
    var_lookup: &HashMap<&str, SsaValue>,
    const_lookup: &HashMap<SsaValue, ConstValue>,
) -> Operand {
    // Try as variable first
    if let Some(&ssa_val) = var_lookup.get(text) {
        // Check if we know its constant value (structured knowledge)
        if let Some(cv) = const_lookup.get(&ssa_val) {
            return Operand::Const(cv.clone());
        }
        return Operand::Value(ssa_val);
    }

    // Try as literal
    if let Some(cv) = ConstValue::parse_literal(text) {
        return Operand::Const(cv);
    }

    // Try stripping quotes (for string literals inside conditions)
    if let Some(s) = strip_quotes(text) {
        return Operand::Const(ConstValue::Str(s.to_string()));
    }

    Operand::Unknown
}

// ── Text parsing helpers ────────────────────────────────────────────────

/// Try to split on an equality/inequality operator.
/// Returns (lhs, rhs, is_negated).
fn try_split_equality(text: &str) -> Option<(&str, &str, bool)> {
    // Try longest operators first
    for (op, negated) in &[("!==", true), ("===", false), ("!=", true), ("==", false)] {
        if let Some(pos) = text.find(op) {
            return Some((&text[..pos], &text[pos + op.len()..], *negated));
        }
    }
    None
}

/// Extract the text before a case-insensitive marker.
fn extract_before<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let lower = text.to_ascii_lowercase();
    let marker_lower = marker.to_ascii_lowercase();
    lower.find(&marker_lower).map(|pos| &text[..pos])
}

/// Strip surrounding quotes from a string.
fn strip_quotes(text: &str) -> Option<&str> {
    let t = text.trim();
    if t.len() >= 2 {
        if (t.starts_with('"') && t.ends_with('"'))
            || (t.starts_with('\'') && t.ends_with('\''))
            || (t.starts_with('`') && t.ends_with('`'))
        {
            return Some(&t[1..t.len() - 1]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{NodeInfo, StmtKind};
    use crate::ssa::ir::{BlockId, SsaBlock, SsaBody, SsaValue, Terminator, ValueDef};
    use petgraph::graph::NodeIndex;
    use smallvec::SmallVec;

    /// Helper: build a minimal SsaBody with value_defs for the given variable
    /// names, all assigned to block 0.
    fn make_ssa_body(var_names: &[&str]) -> SsaBody {
        let value_defs: Vec<ValueDef> = var_names
            .iter()
            .enumerate()
            .map(|(i, name)| ValueDef {
                var_name: Some(name.to_string()),
                cfg_node: NodeIndex::new(i),
                block: BlockId(0),
            })
            .collect();

        SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs,
            cfg_node_map: std::collections::HashMap::new(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        }
    }

    /// Helper: build a minimal NodeInfo for a condition.
    fn make_cond_info(text: &str, vars: &[&str]) -> NodeInfo {
        NodeInfo {
            kind: StmtKind::If,
            condition_text: Some(text.to_string()),
            condition_vars: vars.iter().map(|v| v.to_string()).collect(),
            ..Default::default()
        }
    }

    // ── instanceof pattern ───────────────────────────────────────────────

    #[test]
    fn lower_instanceof_string() {
        let ssa = make_ssa_body(&["x"]);
        let info = make_cond_info("x instanceof String", &["x"]);
        let expr = lower_condition(&info, &ssa, BlockId(0), None);
        match expr {
            ConditionExpr::TypeCheck {
                var,
                type_name,
                positive,
            } => {
                assert_eq!(var, SsaValue(0));
                assert_eq!(type_name, "String");
                assert!(positive);
            }
            other => panic!("expected TypeCheck, got {:?}", other),
        }
    }

    // ── .is_a? pattern (Ruby) ────────────────────────────────────────────

    #[test]
    fn lower_is_a_integer() {
        let ssa = make_ssa_body(&["user_id"]);
        let info = make_cond_info("user_id.is_a?(Integer)", &["user_id"]);
        let expr = lower_condition(&info, &ssa, BlockId(0), None);
        match expr {
            ConditionExpr::TypeCheck {
                var,
                type_name,
                positive,
            } => {
                assert_eq!(var, SsaValue(0));
                assert_eq!(type_name, "Integer");
                assert!(positive);
            }
            other => panic!("expected TypeCheck, got {:?}", other),
        }
    }

    // ── .kind_of? pattern (Ruby) ─────────────────────────────────────────

    #[test]
    fn lower_kind_of_float() {
        let ssa = make_ssa_body(&["x"]);
        let info = make_cond_info("x.kind_of?(Float)", &["x"]);
        let expr = lower_condition(&info, &ssa, BlockId(0), None);
        match expr {
            ConditionExpr::TypeCheck {
                var,
                type_name,
                positive,
            } => {
                assert_eq!(var, SsaValue(0));
                assert_eq!(type_name, "Float");
                assert!(positive);
            }
            other => panic!("expected TypeCheck, got {:?}", other),
        }
    }
}
