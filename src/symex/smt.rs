//! SMT Solver Integration via Z3 with string theory support.
//!
//! Provides a hybrid constraint solving architecture: [`PathEnv`] handles the
//! fast path (~95% of branches), and Z3 is invoked as a secondary solver for
//! cases that involve relationships PathEnv cannot decide.
//!
//! ## Architecture
//!
//! - **Capability-based escalation**: SMT is invoked when accumulated path
//!   constraints contain comparisons that the translator can lower to Z3
//!   (integer or string operands with at least one `Value`).
//! - **Integer + string sorts**: Both `Z3Int` and `Z3Str` variables
//!   are supported. Sort is inferred from PathEnv evidence, constant operands,
//!   or comparison-context hints.
//! - **Strict sort safety**: Z3 variables are only created when the sort is
//!   known with confidence. Unknown-sort variables are skipped entirely.
//!   Sort conflicts (same SSA value used as both int and string) cause the
//!   constraint to be skipped conservatively.
//! - **Sound infeasibility**: Z3 `Unsat` → path is infeasible. Anything else
//!   (Sat, Unknown, timeout, translation failure) → continue as before.
//!   This can never suppress a real finding.
//!
//! ## Scope boundary
//!
//! This module supports direct `Operand`-level string guard reasoning only.
//! It does NOT translate `SymbolicValue` expression trees (Concat, Substr,
//! Replace, etc.) into Z3 terms. If a `SymbolicValue` was already folded to
//! `ConcreteStr` by the symbolic engine, it flows through as a
//! `ConstValue::Str` operand and is handled.
#![allow(
    clippy::needless_borrows_for_generic_args,
    clippy::new_without_default,
    dead_code
)]

use std::collections::HashMap;

use z3::ast::Int as Z3Int;
use z3::ast::String as Z3Str;
use z3::{Config, Params, SatResult, Solver};

use crate::constraint::{CompOp, ConditionExpr, ConstValue, Operand, PathEnv, RelOp};
use crate::ssa::ir::SsaValue;
use crate::ssa::type_facts::TypeKind;

use super::state::{PathConstraint, SymbolicState};

//  Constants

/// Maximum SMT queries per finding (across all paths).
const MAX_SMT_QUERIES_PER_FINDING: u32 = 10;

/// Per-query timeout in milliseconds (integer-only queries).
const SMT_QUERY_TIMEOUT_MS: u32 = 500;

/// Per-query timeout for queries involving string theory (ms).
/// String theory (especially lexicographic ordering) is more expensive.
const SMT_STRING_QUERY_TIMEOUT_MS: u32 = 500;

//  Types

/// Result of an SMT satisfiability check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtResult {
    /// Path constraints are satisfiable (path is feasible).
    Sat,
    /// Path constraints are unsatisfiable (path is provably infeasible).
    Unsat,
    /// Solver returned unknown (timeout, resource limit, etc.).
    /// Treated conservatively as Sat.
    Unknown,
    /// Per-finding query budget exhausted.
    BudgetExhausted,
}

/// Z3 context and budget tracking for one finding's exploration.
///
/// Created once per `explore_finding()` call, shared across all paths explored
/// for that finding. A fresh `Solver` is created per `check_path_feasibility()`
/// call (reset-and-replay strategy).
///
/// The z3 0.19 crate uses a thread-local context model via `with_z3_config`.
/// We store the `Config` and create a scoped context per query.
pub struct SmtContext {
    cfg: Config,
    queries_used: u32,
    timeout_ms: u32,
}

/// Tracks the Z3 sort assigned to each SSA variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarSort {
    Int,
    Str,
}

/// Polymorphic Z3 variable, either integer or string sort.
enum Z3Var {
    Int(Z3Int),
    Str(Z3Str),
}

/// Polymorphic Z3 expression returned by operand translation.
enum Z3Expr {
    Int(Z3Int),
    Str(Z3Str),
}

/// Variable map: SSA value → Z3 variable with implicit sort.
type VarMap = HashMap<SsaValue, Z3Var>;

/// Pay bundled Z3 static-init cost once per process so the first real
/// `check_path_feasibility()` call doesn't blow the per-query timeout.
fn warm_z3() {
    static WARM: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARM.get_or_init(|| {
        let cfg = Config::new();
        z3::with_z3_config(&cfg, || {
            let _ = Solver::new().check();
        });
    });
}

//  SmtContext

impl SmtContext {
    /// Create a new SMT context for one finding's exploration.
    pub fn new() -> Self {
        SmtContext {
            cfg: Config::new(),
            queries_used: 0,
            #[cfg(not(test))]
            timeout_ms: SMT_QUERY_TIMEOUT_MS,
            #[cfg(test)]
            timeout_ms: 5_000,
        }
    }

    /// Check whether the query budget has remaining capacity.
    pub fn has_budget(&self) -> bool {
        self.queries_used < MAX_SMT_QUERIES_PER_FINDING
    }

    /// Check path feasibility using Z3.
    ///
    /// Translates accumulated path constraints and PathEnv facts into Z3
    /// assertions, then checks satisfiability. Returns `Unsat` only when Z3
    /// proves the constraints are contradictory.
    ///
    /// Constraints that cannot be fully translated (unknown sorts, sort
    /// conflicts, etc.) are silently skipped, this is sound because omitting
    /// a constraint can only make Z3 return `Sat` when the actual result
    /// might be `Unsat`, never the reverse.
    pub fn check_path_feasibility(
        &mut self,
        constraints: &[PathConstraint],
        _sym_state: &SymbolicState,
        env: &PathEnv,
    ) -> SmtResult {
        if !self.has_budget() {
            return SmtResult::BudgetExhausted;
        }
        self.queries_used += 1;
        warm_z3();

        // Use with_z3_config to create a scoped Z3 context for this query.
        let base_timeout_ms = self.timeout_ms;
        z3::with_z3_config(&self.cfg, || {
            let solver = Solver::new();

            // Build variable map from constraints + PathEnv.
            let mut var_map: VarMap = HashMap::new();

            // Seed from PathEnv facts (interval bounds, exact values, string facts).
            seed_from_path_env(&solver, &mut var_map, env);

            // Translate path constraints.
            for pc in constraints {
                assert_path_constraint(&solver, &mut var_map, pc, env);
            }

            // Determine timeout: use string timeout if any string vars present.
            let has_string_vars = var_map.values().any(|v| matches!(v, Z3Var::Str(_)));
            let effective_timeout = if has_string_vars {
                base_timeout_ms.max(SMT_STRING_QUERY_TIMEOUT_MS)
            } else {
                base_timeout_ms
            };

            let mut params = Params::new();
            params.set_u32("timeout", effective_timeout);
            solver.set_params(&params);

            // Check satisfiability.
            match solver.check() {
                SatResult::Unsat => SmtResult::Unsat,
                SatResult::Sat => SmtResult::Sat,
                SatResult::Unknown => SmtResult::Unknown,
            }
        })
    }
}

//  Sort inference

/// Try to determine that an SSA value is an integer from PathEnv facts.
fn is_known_int(v: SsaValue, env: &PathEnv) -> bool {
    let fact = env.get(v);
    // Has interval bounds → definitely numeric.
    if fact.lo.is_some() || fact.hi.is_some() {
        return true;
    }
    // Has an exact integer value.
    if matches!(fact.exact, Some(ConstValue::Int(_))) {
        return true;
    }
    false
}

/// Try to determine that an SSA value is a string from PathEnv facts.
fn is_known_str(v: SsaValue, env: &PathEnv) -> bool {
    let fact = env.get(v);
    // Has an exact string value.
    if matches!(fact.exact, Some(ConstValue::Str(_))) {
        return true;
    }
    // Has singleton String type evidence.
    if fact.types.is_singleton_of(&TypeKind::String) {
        return true;
    }
    false
}

/// Get or create a Z3 integer variable for an SSA value, but only if the
/// sort is known to be Int. Returns `None` if the sort is unknown or
/// conflicts with an existing string assignment.
fn ensure_int_var(var_map: &mut VarMap, v: SsaValue, env: &PathEnv) -> Option<Z3Int> {
    match var_map.get(&v) {
        Some(Z3Var::Int(z)) => return Some(z.clone()),
        Some(Z3Var::Str(_)) => return None, // sort conflict
        None => {}
    }
    // Only create if we have evidence this is an integer.
    if is_known_int(v, env) {
        let z3_var = Z3Int::new_const(format!("v{}", v.0));
        var_map.insert(v, Z3Var::Int(z3_var.clone()));
        return Some(z3_var);
    }
    None
}

/// Create a Z3 integer variable unconditionally (used when context proves
/// the sort, e.g., both sides of an integer comparison).
/// Returns `None` on sort conflict (variable already assigned as string).
fn force_int_var(var_map: &mut VarMap, v: SsaValue) -> Option<Z3Int> {
    match var_map.get(&v) {
        Some(Z3Var::Int(z)) => return Some(z.clone()),
        Some(Z3Var::Str(_)) => return None, // sort conflict
        None => {}
    }
    let z3_var = Z3Int::new_const(format!("v{}", v.0));
    var_map.insert(v, Z3Var::Int(z3_var.clone()));
    Some(z3_var)
}

/// Get or create a Z3 string variable for an SSA value, but only if the
/// sort is known to be Str. Returns `None` if the sort is unknown or
/// conflicts with an existing integer assignment.
fn ensure_str_var(var_map: &mut VarMap, v: SsaValue, env: &PathEnv) -> Option<Z3Str> {
    match var_map.get(&v) {
        Some(Z3Var::Str(z)) => return Some(z.clone()),
        Some(Z3Var::Int(_)) => return None, // sort conflict
        None => {}
    }
    // Only create if we have evidence this is a string.
    if is_known_str(v, env) {
        let z3_var = Z3Str::new_const(format!("v{}", v.0));
        var_map.insert(v, Z3Var::Str(z3_var.clone()));
        return Some(z3_var);
    }
    None
}

/// Create a Z3 string variable unconditionally (used when comparison context
/// proves the sort). Returns `None` on sort conflict.
fn force_str_var(var_map: &mut VarMap, v: SsaValue) -> Option<Z3Str> {
    match var_map.get(&v) {
        Some(Z3Var::Str(z)) => return Some(z.clone()),
        Some(Z3Var::Int(_)) => return None, // sort conflict
        None => {}
    }
    let z3_var = Z3Str::new_const(format!("v{}", v.0));
    var_map.insert(v, Z3Var::Str(z3_var.clone()));
    Some(z3_var)
}

//  PathEnv seeding

/// Seed Z3 solver with known facts from PathEnv.
///
/// Seeds both integer-typed and string-typed facts. Unknown-sort values are
/// skipped.
fn seed_from_path_env(solver: &Solver, var_map: &mut VarMap, env: &PathEnv) {
    // Interval bounds, exact values, and excluded values.
    for &(v, ref fact) in env.facts() {
        // Integer evidence path.
        let has_int_evidence = fact.lo.is_some()
            || fact.hi.is_some()
            || matches!(fact.exact, Some(ConstValue::Int(_)));

        if has_int_evidence {
            if let Some(z3_var) = force_int_var(var_map, v) {
                if let Some(lo) = fact.lo {
                    if fact.lo_strict {
                        solver.assert(&z3_var.gt(&Z3Int::from_i64(lo)));
                    } else {
                        solver.assert(&z3_var.ge(&Z3Int::from_i64(lo)));
                    }
                }
                if let Some(hi) = fact.hi {
                    if fact.hi_strict {
                        solver.assert(&z3_var.lt(&Z3Int::from_i64(hi)));
                    } else {
                        solver.assert(&z3_var.le(&Z3Int::from_i64(hi)));
                    }
                }
                if let Some(ConstValue::Int(n)) = &fact.exact {
                    solver.assert(&z3_var.eq(&Z3Int::from_i64(*n)));
                }

                // Excluded integer values.
                for excl in &fact.excluded {
                    if let ConstValue::Int(n) = excl {
                        solver.assert(&z3_var.ne(&Z3Int::from_i64(*n)));
                    }
                }
            }
            continue;
        }

        // String evidence path.
        let has_str_evidence = matches!(fact.exact, Some(ConstValue::Str(_)))
            || fact.types.is_singleton_of(&TypeKind::String);

        if has_str_evidence {
            if let Some(z3_var) = force_str_var(var_map, v) {
                // Exact string value.
                if let Some(ConstValue::Str(s)) = &fact.exact {
                    solver.assert(&z3_var.eq(Z3Str::from(s.as_str())));
                }

                // Excluded string values.
                for excl in &fact.excluded {
                    if let ConstValue::Str(s) = excl {
                        solver.assert(&z3_var.ne(Z3Str::from(s.as_str())));
                    }
                }
            }
        }
    }

    // Equality classes from UnionFind.
    let known_vars: Vec<SsaValue> = var_map.keys().copied().collect();
    for &v in &known_vars {
        let root = env.uf.find_immutable(v);
        if root != v {
            match (var_map.get(&root), var_map.get(&v)) {
                (Some(Z3Var::Int(r)), Some(Z3Var::Int(vi))) => {
                    solver.assert(&vi.eq(r));
                }
                (Some(Z3Var::Str(r)), Some(Z3Var::Str(vi))) => {
                    solver.assert(&vi.eq(r));
                }
                _ => {} // Sort mismatch or missing, skip.
            }
        }
    }

    // Disequalities.
    for &(a, b) in env.disequalities() {
        match (var_map.get(&a), var_map.get(&b)) {
            (Some(Z3Var::Int(za)), Some(Z3Var::Int(zb))) => {
                solver.assert(&za.ne(zb));
            }
            (Some(Z3Var::Str(za)), Some(Z3Var::Str(zb))) => {
                solver.assert(&za.ne(zb));
            }
            _ => {} // Sort mismatch or missing, skip.
        }
    }

    // Relational constraints (integer-domain only: Lt/Le).
    for &(a, op, b) in env.relational() {
        if let (Some(Z3Var::Int(za)), Some(Z3Var::Int(zb))) = (var_map.get(&a), var_map.get(&b)) {
            match op {
                RelOp::Lt => solver.assert(&za.lt(zb)),
                RelOp::Le => solver.assert(&za.le(zb)),
            }
        }
    }
}

//  Constraint translation

/// Translate a single path constraint into a Z3 assertion.
///
/// Skips constraints that cannot be fully translated (unknown sort, sort
/// conflict, etc.). This is sound, see module-level docs.
fn assert_path_constraint(
    solver: &Solver,
    var_map: &mut VarMap,
    pc: &PathConstraint,
    env: &PathEnv,
) {
    match &pc.condition {
        ConditionExpr::Comparison { lhs, op, rhs } => {
            // Determine sort hints from the opposite operand.
            let lhs_hint = operand_sort_hint(rhs);
            let rhs_hint = operand_sort_hint(lhs);

            let z_lhs = translate_operand_with_hint(var_map, lhs, env, lhs_hint);
            let z_rhs = translate_operand_with_hint(var_map, rhs, env, rhs_hint);

            if let (Some(z_l), Some(z_r)) = (z_lhs, z_rhs) {
                if let Some(cmp) = build_comparison_poly(&z_l, *op, &z_r) {
                    if pc.polarity {
                        solver.assert(&cmp);
                    } else {
                        solver.assert(&cmp.not());
                    }
                }
            }
            // If either operand can't be translated, skip (conservative).
        }
        ConditionExpr::BoolTest { var } => {
            // Model as var != 0 if var is known int.
            if let Some(z_var) = ensure_int_var(var_map, *var, env) {
                let test = z_var.ne(&Z3Int::from_i64(0));
                if pc.polarity {
                    solver.assert(&test);
                } else {
                    solver.assert(&test.not());
                }
            }
        }
        // NullCheck, TypeCheck, Unknown, skip (not modeled).
        ConditionExpr::NullCheck { .. }
        | ConditionExpr::TypeCheck { .. }
        | ConditionExpr::Unknown => {}
    }
}

/// Infer a sort hint from a constant operand.
///
/// When one side of a comparison is a known constant, it hints the sort of
/// the other side (a `Value`). This is the lowest-priority evidence, used
/// only when var_map and PathEnv provide no information.
fn operand_sort_hint(op: &Operand) -> Option<VarSort> {
    match op {
        Operand::Const(ConstValue::Str(_)) => Some(VarSort::Str),
        Operand::Const(ConstValue::Int(_) | ConstValue::Bool(_)) => Some(VarSort::Int),
        _ => None,
    }
}

/// Translate a constraint operand to a polymorphic Z3 expression.
///
/// Sort resolution precedence for `Value` operands:
/// 1. Existing var_map entry (already assigned sort)
/// 2. PathEnv evidence (`is_known_str` / `is_known_int`)
/// 3. Unknown → return `None` (caller may apply context hint)
fn translate_operand(var_map: &mut VarMap, op: &Operand, env: &PathEnv) -> Option<Z3Expr> {
    match op {
        Operand::Const(ConstValue::Int(n)) => Some(Z3Expr::Int(Z3Int::from_i64(*n))),
        Operand::Const(ConstValue::Bool(b)) => {
            Some(Z3Expr::Int(Z3Int::from_i64(if *b { 1 } else { 0 })))
        }
        Operand::Const(ConstValue::Str(s)) => Some(Z3Expr::Str(Z3Str::from(s.as_str()))),
        Operand::Value(v) => {
            // 1. Existing var_map entry wins.
            match var_map.get(v) {
                Some(Z3Var::Int(z)) => return Some(Z3Expr::Int(z.clone())),
                Some(Z3Var::Str(z)) => return Some(Z3Expr::Str(z.clone())),
                None => {}
            }
            // 2. PathEnv evidence.
            if is_known_str(*v, env) {
                return force_str_var(var_map, *v).map(Z3Expr::Str);
            }
            if is_known_int(*v, env) {
                return force_int_var(var_map, *v).map(Z3Expr::Int);
            }
            // 3. Unknown sort, return None; caller may apply hint.
            None
        }
        Operand::Const(ConstValue::Null) | Operand::Unknown => None,
    }
}

/// Translate an operand with a sort hint from the comparison context.
///
/// Falls back to `translate_operand` first. If that returns `None` for a
/// `Value` operand, applies the sort hint. When no hint is available
/// (e.g., both sides are Values), defaults to Int for backward
/// compatibility with pre-string-theory behavior.
fn translate_operand_with_hint(
    var_map: &mut VarMap,
    op: &Operand,
    env: &PathEnv,
    hint: Option<VarSort>,
) -> Option<Z3Expr> {
    // Try the standard path first (respects precedence 1 and 2).
    if let Some(expr) = translate_operand(var_map, op, env) {
        return Some(expr);
    }
    // Precedence 3: comparison-context hint for unresolved Value operands.
    if let Operand::Value(v) = op {
        // Only apply hint if the variable has no var_map entry yet.
        if !var_map.contains_key(v) {
            match hint {
                Some(VarSort::Str) => return force_str_var(var_map, *v).map(Z3Expr::Str),
                Some(VarSort::Int) | None => {
                    // Default to Int when no hint is available (e.g., Value vs
                    // Value comparisons). This preserves backward compatibility:
                    // pre-string-theory, all Value operands were forced to Int.
                    return force_int_var(var_map, *v).map(Z3Expr::Int);
                }
            }
        }
    }
    None
}

/// Build a Z3 boolean expression for a comparison, dispatching on sort.
///
/// Returns `None` on sort mismatch (int vs string).
fn build_comparison_poly(lhs: &Z3Expr, op: CompOp, rhs: &Z3Expr) -> Option<z3::ast::Bool> {
    match (lhs, rhs) {
        (Z3Expr::Int(l), Z3Expr::Int(r)) => Some(build_comparison_int(l, op, r)),
        (Z3Expr::Str(l), Z3Expr::Str(r)) => Some(build_comparison_str(l, op, r)),
        _ => None, // sort mismatch
    }
}

/// Build a Z3 boolean expression for an integer comparison.
fn build_comparison_int(lhs: &Z3Int, op: CompOp, rhs: &Z3Int) -> z3::ast::Bool {
    match op {
        CompOp::Eq => lhs.eq(rhs),
        CompOp::Neq => lhs.ne(rhs),
        CompOp::Lt => lhs.lt(rhs),
        CompOp::Gt => lhs.gt(rhs),
        CompOp::Le => lhs.le(rhs),
        CompOp::Ge => lhs.ge(rhs),
    }
}

/// Build a Z3 boolean expression for a string comparison.
///
/// All six comparison operators are supported:
/// - Eq/Neq: structural string equality
/// - Lt/Le/Gt/Ge: SMT-LIB2 lexicographic ordering (str.<, str.<=, str.>, str.>=)
fn build_comparison_str(lhs: &Z3Str, op: CompOp, rhs: &Z3Str) -> z3::ast::Bool {
    match op {
        CompOp::Eq => lhs.eq(rhs),
        CompOp::Neq => lhs.ne(rhs),
        CompOp::Lt => lhs.str_lt(rhs),
        CompOp::Le => lhs.str_le(rhs),
        CompOp::Gt => lhs.str_gt(rhs),
        CompOp::Ge => lhs.str_ge(rhs),
    }
}

//  Escalation predicate

/// Determine whether accumulated path constraints warrant SMT escalation.
///
/// Returns `true` when the constraints contain comparisons that the SMT
/// translator can lower: at least one `Value` operand, and both operands
/// are translatable (Int, Bool, Str constants or Value references).
///
/// BoolTest, NullCheck, TypeCheck, and Unknown conditions do not escalate.
pub fn should_escalate(constraints: &[PathConstraint]) -> bool {
    constraints.iter().any(|c| match &c.condition {
        ConditionExpr::Comparison { lhs, rhs, .. } => {
            let has_value = matches!(lhs, Operand::Value(_)) || matches!(rhs, Operand::Value(_));
            has_value && can_translate_operand(lhs) && can_translate_operand(rhs)
        }
        _ => false,
    })
}

/// Check whether an operand can be translated to Z3 (int, bool, or string).
fn can_translate_operand(op: &Operand) -> bool {
    match op {
        Operand::Value(_) => true,
        Operand::Const(ConstValue::Int(_) | ConstValue::Bool(_) | ConstValue::Str(_)) => true,
        Operand::Const(ConstValue::Null) | Operand::Unknown => false,
    }
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint::{CompOp, ConditionExpr, Operand, PathEnv};
    use crate::ssa::ir::{BlockId, SsaValue};

    /// Helper: build a Comparison PathConstraint.
    fn comparison_constraint(
        lhs: Operand,
        op: CompOp,
        rhs: Operand,
        polarity: bool,
    ) -> PathConstraint {
        PathConstraint {
            block: BlockId(0),
            condition: ConditionExpr::Comparison { lhs, op, rhs },
            polarity,
        }
    }

    fn val(n: u32) -> Operand {
        Operand::Value(SsaValue(n))
    }

    fn int_const(n: i64) -> Operand {
        Operand::Const(ConstValue::Int(n))
    }

    fn str_const(s: &str) -> Operand {
        Operand::Const(ConstValue::Str(s.into()))
    }

    // ── Escalation predicate ─────────────────────────────────────────────

    #[test]
    fn escalation_fires_on_value_vs_value() {
        let constraints = vec![comparison_constraint(val(0), CompOp::Gt, val(1), true)];
        assert!(should_escalate(&constraints));
    }

    #[test]
    fn escalation_fires_on_value_vs_int_const() {
        // Capability-based escalation also fires on Value vs Const.
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Gt,
            int_const(5),
            true,
        )];
        assert!(should_escalate(&constraints));
    }

    #[test]
    fn escalation_fires_on_value_vs_string_const() {
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Eq,
            str_const("hello"),
            true,
        )];
        assert!(should_escalate(&constraints));
    }

    #[test]
    fn escalation_skips_const_vs_const() {
        // No Value operand → no variable to reason about.
        let constraints = vec![comparison_constraint(
            int_const(3),
            CompOp::Eq,
            int_const(5),
            true,
        )];
        assert!(!should_escalate(&constraints));
    }

    #[test]
    fn escalation_skips_empty() {
        assert!(!should_escalate(&[]));
    }

    #[test]
    fn escalation_skips_non_comparison() {
        let constraints = vec![PathConstraint {
            block: BlockId(0),
            condition: ConditionExpr::BoolTest { var: SsaValue(0) },
            polarity: true,
        }];
        assert!(!should_escalate(&constraints));
    }

    #[test]
    fn escalation_skips_null_operand() {
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Eq,
            Operand::Const(ConstValue::Null),
            true,
        )];
        assert!(!should_escalate(&constraints));
    }

    // ── Simple integer contradiction ─────────────────────────────────────

    #[test]
    fn simple_contradiction() {
        // x > 10 AND x < 5 → Unsat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, int_const(10), true),
            comparison_constraint(val(0), CompOp::Lt, int_const(5), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Cross-variable contradiction (key SMT value prop) ────────────────

    #[test]
    fn cross_variable_contradiction() {
        // x > y AND y > x → Unsat
        // PathEnv cannot detect this, it tracks per-variable intervals.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, val(1), true),
            comparison_constraint(val(1), CompOp::Gt, val(0), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Arithmetic cross-variable ────────────────────────────────────────

    #[test]
    fn arithmetic_cross_variable() {
        // x < 3 AND y < 5 AND y > 3 AND x > y → Unsat
        // because y ∈ (3,5), x > y means x > 3, but x < 3.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Lt, int_const(3), true),
            comparison_constraint(val(1), CompOp::Lt, int_const(5), true),
            comparison_constraint(val(1), CompOp::Gt, int_const(3), true),
            comparison_constraint(val(0), CompOp::Gt, val(1), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Satisfiable path ─────────────────────────────────────────────────

    #[test]
    fn satisfiable_path() {
        // x > 0 AND x < 100 → Sat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, int_const(0), true),
            comparison_constraint(val(0), CompOp::Lt, int_const(100), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Sat);
    }

    // ── Budget exhaustion ────────────────────────────────────────────────

    #[test]
    fn budget_exhaustion() {
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Gt,
            int_const(0),
            true,
        )];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();

        // Exhaust budget.
        for _ in 0..MAX_SMT_QUERIES_PER_FINDING {
            let r = ctx.check_path_feasibility(&constraints, &sym, &env);
            assert_ne!(r, SmtResult::BudgetExhausted);
        }

        // Next call should return BudgetExhausted.
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::BudgetExhausted);
    }

    // ── PathEnv seeding (integer) ────────────────────────────────────────

    #[test]
    fn path_env_seeding_interval() {
        // Seed PathEnv with x in [10, 20], then assert x < 5 → Unsat.
        let mut env = PathEnv::empty();
        use crate::constraint::ValueFact;
        let mut fact = ValueFact::top();
        fact.lo = Some(10);
        fact.hi = Some(20);
        env.refine(SsaValue(0), &fact);

        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Lt,
            int_const(5),
            true,
        )];
        let mut ctx = SmtContext::new();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Sort safety: unknown sort variables are skipped ──────────────────

    #[test]
    fn skip_unknown_sort() {
        // BoolTest on a variable with no int evidence → skip.
        // The constraint is effectively ignored, so result should be Sat.
        let constraints = vec![PathConstraint {
            block: BlockId(0),
            condition: ConditionExpr::BoolTest { var: SsaValue(99) },
            polarity: true,
        }];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Sat);
    }

    // ── String equality ───────────────────────────────────────

    #[test]
    fn string_equality_asserted() {
        // x == "hello" → Sat (string constraint is now asserted, not skipped).
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Eq,
            str_const("hello"),
            true,
        )];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Sat);
    }

    #[test]
    fn string_equality_contradiction() {
        // x == "hello" AND x == "world" → Unsat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Eq, str_const("hello"), true),
            comparison_constraint(val(0), CompOp::Eq, str_const("world"), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    #[test]
    fn string_inequality_satisfiable() {
        // x != "hello" → Sat (x can be anything else)
        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Neq,
            str_const("hello"),
            true,
        )];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Sat);
    }

    #[test]
    fn string_eq_and_neq_contradiction() {
        // x == "hello" AND x != "hello" → Unsat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Eq, str_const("hello"), true),
            comparison_constraint(val(0), CompOp::Neq, str_const("hello"), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    #[test]
    fn string_cross_variable_contradiction() {
        // x == "hello" AND y == "world" AND x == y → Unsat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Eq, str_const("hello"), true),
            comparison_constraint(val(1), CompOp::Eq, str_const("world"), true),
            comparison_constraint(val(0), CompOp::Eq, val(1), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── PathEnv string seeding ────────────────────────────────

    #[test]
    fn path_env_string_seeding() {
        // Seed PathEnv with x = "safe", then assert x == "danger" → Unsat.
        let mut env = PathEnv::empty();
        use crate::constraint::ValueFact;
        let mut fact = ValueFact::top();
        fact.exact = Some(ConstValue::Str("safe".into()));
        env.refine(SsaValue(0), &fact);

        let constraints = vec![comparison_constraint(
            val(0),
            CompOp::Eq,
            str_const("danger"),
            true,
        )];
        let mut ctx = SmtContext::new();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Mixed int + string ───────────────────────────────────────────────

    #[test]
    fn mixed_int_string_no_conflict() {
        // x > 5 (int) AND y == "hello" (string) → Sat (independent)
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, int_const(5), true),
            comparison_constraint(val(1), CompOp::Eq, str_const("hello"), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Sat);
    }

    // ── Negated polarity ─────────────────────────────────────────────────

    #[test]
    fn negated_polarity() {
        // !(x > 10) means x <= 10, combined with x > 20 → Unsat.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, int_const(10), false), // x <= 10
            comparison_constraint(val(0), CompOp::Gt, int_const(20), true),  // x > 20
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    #[test]
    fn negated_string_equality() {
        // !(x == "hello") means x != "hello", combined with x == "hello" → Unsat.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Eq, str_const("hello"), false),
            comparison_constraint(val(0), CompOp::Eq, str_const("hello"), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Cross-variable with equality (integer) ──────────────────────────

    #[test]
    fn cross_variable_equality_contradiction() {
        // x == y AND x > 5 AND y < 3 → Unsat
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Eq, val(1), true),
            comparison_constraint(val(0), CompOp::Gt, int_const(5), true),
            comparison_constraint(val(1), CompOp::Lt, int_const(3), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert_eq!(result, SmtResult::Unsat);
    }

    // ── Lexicographic string ordering ─────────────────────────

    #[test]
    fn string_lexicographic_contradiction() {
        // x < "apple" AND x > "banana" → Unsat
        // (lexicographically "apple" < "banana", so nothing is < "apple" AND > "banana")
        // Bundled Z3 may not support str.< / str.<=, returning Unknown instead.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Lt, str_const("apple"), true),
            comparison_constraint(val(0), CompOp::Gt, str_const("banana"), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert!(
            result == SmtResult::Unsat || result == SmtResult::Unknown,
            "expected Unsat or Unknown, got {result:?}"
        );
    }

    #[test]
    fn string_lexicographic_satisfiable() {
        // x > "apple" AND x < "banana" → Sat (e.g., x = "avocado")
        // Bundled Z3 may not support str.< / str.<=, returning Unknown instead.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Gt, str_const("apple"), true),
            comparison_constraint(val(0), CompOp::Lt, str_const("banana"), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert!(
            result == SmtResult::Sat || result == SmtResult::Unknown,
            "expected Sat or Unknown, got {result:?}"
        );
    }

    #[test]
    fn string_lexicographic_le_ge() {
        // x <= "apple" AND x >= "banana" → Unsat
        // Bundled Z3 may not support str.< / str.<=, returning Unknown instead.
        let constraints = vec![
            comparison_constraint(val(0), CompOp::Le, str_const("apple"), true),
            comparison_constraint(val(0), CompOp::Ge, str_const("banana"), true),
        ];
        let mut ctx = SmtContext::new();
        let env = PathEnv::empty();
        let sym = SymbolicState::new();
        let result = ctx.check_path_feasibility(&constraints, &sym, &env);
        assert!(
            result == SmtResult::Unsat || result == SmtResult::Unknown,
            "expected Unsat or Unknown, got {result:?}"
        );
    }
}
