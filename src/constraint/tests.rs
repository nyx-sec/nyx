//! Comprehensive tests for the constraint solving module.

use super::domain::*;
use super::lower::*;
use super::solver::*;
use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::SsaValue;
use std::collections::HashMap;

// ── ValueFact meet tests ────────────────────────────────────────────────

#[test]
fn valuefact_meet_eq_eq_same() {
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    let mut b = ValueFact::top();
    b.exact = Some(ConstValue::Int(5));
    let m = a.meet(&b);
    assert_eq!(m.exact, Some(ConstValue::Int(5)));
    assert!(!m.is_bottom());
}

#[test]
fn valuefact_meet_eq_eq_diff() {
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    let mut b = ValueFact::top();
    b.exact = Some(ConstValue::Int(7));
    let m = a.meet(&b);
    assert!(m.is_bottom());
}

#[test]
fn valuefact_meet_eq_neq() {
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    let mut b = ValueFact::top();
    b.excluded.push(ConstValue::Int(5));
    let m = a.meet(&b);
    assert!(m.is_bottom());
}

#[test]
fn valuefact_meet_gt_lt_contradiction() {
    // x > 10 meet x < 5 → empty interval → bottom
    let mut a = ValueFact::top();
    a.lo = Some(10);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.hi = Some(5);
    b.hi_strict = true;
    let m = a.meet(&b);
    assert!(m.is_bottom(), "expected bottom for (10,+inf) ∩ (-inf,5)");
}

#[test]
fn valuefact_meet_gt_lt_compatible() {
    // x > 0 meet x < 100 → (0, 100) open interval
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.hi = Some(100);
    b.hi_strict = true;
    let m = a.meet(&b);
    assert!(!m.is_bottom());
    assert_eq!(m.lo, Some(0));
    assert!(m.lo_strict);
    assert_eq!(m.hi, Some(100));
    assert!(m.hi_strict);
}

#[test]
fn valuefact_meet_null_nonnull_is_bottom() {
    let mut a = ValueFact::top();
    a.null = Nullability::Null;
    let mut b = ValueFact::top();
    b.null = Nullability::NonNull;
    let m = a.meet(&b);
    assert!(m.is_bottom());
}

// ── ValueFact join tests ────────────────────────────────────────────────

#[test]
fn valuefact_join_intervals_preserves_weaker() {
    // [x > 0] join [x > 5] = [x > 0]
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.lo = Some(5);
    b.lo_strict = true;
    let j = a.join(&b);
    assert_eq!(j.lo, Some(0));
    assert!(j.lo_strict);
    assert_eq!(j.hi, None); // no upper bound
}

#[test]
fn valuefact_join_exact_to_interval() {
    // Eq(5) join Eq(7) = no exact, interval [5,7]
    let mut a = ValueFact::top();
    a.exact = Some(ConstValue::Int(5));
    a.lo = Some(5);
    a.hi = Some(5);
    let mut b = ValueFact::top();
    b.exact = Some(ConstValue::Int(7));
    b.lo = Some(7);
    b.hi = Some(7);
    let j = a.join(&b);
    assert_eq!(j.exact, None); // different constants
    assert_eq!(j.lo, Some(5));
    assert_eq!(j.hi, Some(7));
}

#[test]
fn valuefact_join_nonnull_and_unknown() {
    let mut a = ValueFact::top();
    a.null = Nullability::NonNull;
    let b = ValueFact::top(); // null = Unknown
    let j = a.join(&b);
    assert_eq!(j.null, Nullability::Unknown);
}

#[test]
fn valuefact_join_nonnull_and_nonnull() {
    let mut a = ValueFact::top();
    a.null = Nullability::NonNull;
    let mut b = ValueFact::top();
    b.null = Nullability::NonNull;
    let j = a.join(&b);
    assert_eq!(j.null, Nullability::NonNull);
}

// ── ValueFact widen tests ───────────────────────────────────────────────

#[test]
fn valuefact_widen_unstable_bound() {
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.lo = Some(5); // changed from 0 to 5
    b.lo_strict = true;
    let w = a.widen(&b);
    assert_eq!(w.lo, None); // dropped because unstable
}

#[test]
fn valuefact_widen_stable_bound() {
    let mut a = ValueFact::top();
    a.lo = Some(0);
    a.lo_strict = true;
    let mut b = ValueFact::top();
    b.lo = Some(0);
    b.lo_strict = true;
    let w = a.widen(&b);
    assert_eq!(w.lo, Some(0)); // stable, preserved
    assert!(w.lo_strict);
}

// ── Nullability tests ───────────────────────────────────────────────────

#[test]
fn nullability_meet_join_exhaustive() {
    use Nullability::*;
    // meet: refine
    assert_eq!(Unknown.meet(Null), Null);
    assert_eq!(Unknown.meet(NonNull), NonNull);
    assert_eq!(Null.meet(NonNull), Bottom);
    assert_eq!(Null.meet(Null), Null);
    assert_eq!(Bottom.meet(Unknown), Bottom);
    // join: merge
    assert_eq!(Null.join(NonNull), Unknown);
    assert_eq!(Null.join(Null), Null);
    assert_eq!(Unknown.join(Null), Unknown);
    assert_eq!(Bottom.join(Null), Null);
    assert_eq!(Bottom.join(Bottom), Bottom);
}

// ── BoolState tests ─────────────────────────────────────────────────────

#[test]
fn boolstate_meet_join_exhaustive() {
    use BoolState::*;
    assert_eq!(Unknown.meet(True), True);
    assert_eq!(True.meet(False), Bottom);
    assert_eq!(True.meet(True), True);
    assert_eq!(Bottom.meet(True), Bottom);
    assert_eq!(True.join(False), Unknown);
    assert_eq!(True.join(True), True);
    assert_eq!(Bottom.join(True), True);
}

// ── TypeSet tests ───────────────────────────────────────────────────────

#[test]
fn typeset_meet_is_intersection() {
    use crate::ssa::type_facts::TypeKind;
    let a = TypeSet::singleton(&TypeKind::String).join(TypeSet::singleton(&TypeKind::Int));
    let b = TypeSet::singleton(&TypeKind::Int).join(TypeSet::singleton(&TypeKind::Bool));
    let m = a.meet(b);
    assert!(m.contains(&TypeKind::Int));
    assert!(!m.contains(&TypeKind::String));
    assert!(!m.contains(&TypeKind::Bool));
}

#[test]
fn typeset_join_is_union() {
    use crate::ssa::type_facts::TypeKind;
    let a = TypeSet::singleton(&TypeKind::String);
    let b = TypeSet::singleton(&TypeKind::Int);
    let j = a.join(b);
    assert!(j.contains(&TypeKind::String));
    assert!(j.contains(&TypeKind::Int));
}

#[test]
fn typeset_complement() {
    use crate::ssa::type_facts::TypeKind;
    let s = TypeSet::singleton(&TypeKind::String);
    let c = s.complement();
    assert!(!c.contains(&TypeKind::String));
    assert!(c.contains(&TypeKind::Int));
    assert!(c.contains(&TypeKind::Bool));
    // complement of complement is original
    assert_eq!(c.complement(), s);
}

#[test]
fn typeset_top_bottom() {
    assert!(TypeSet::TOP.is_top());
    assert!(!TypeSet::TOP.is_bottom());
    assert!(TypeSet::BOTTOM.is_bottom());
    assert!(!TypeSet::BOTTOM.is_top());
}

// ── PathEnv tests ───────────────────────────────────────────────────────

#[test]
fn pathenv_refine_and_get() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let mut fact = ValueFact::top();
    fact.null = Nullability::NonNull;
    env.refine(v, &fact);
    let got = env.get(v);
    assert_eq!(got.null, Nullability::NonNull);
}

#[test]
fn pathenv_refine_contradiction_sets_unsat() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let mut f1 = ValueFact::top();
    f1.null = Nullability::Null;
    env.refine(v, &f1);
    assert!(!env.is_unsat());
    let mut f2 = ValueFact::top();
    f2.null = Nullability::NonNull;
    env.refine(v, &f2);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_join_common_facts_preserved() {
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    let mut f1 = ValueFact::top();
    f1.null = Nullability::NonNull;
    env1.refine(v, &f1);
    let mut env2 = PathEnv::empty();
    let mut f2 = ValueFact::top();
    f2.null = Nullability::NonNull;
    env2.refine(v, &f2);
    let joined = env1.join(&env2);
    let got = joined.get(v);
    assert_eq!(got.null, Nullability::NonNull);
}

#[test]
fn pathenv_join_one_side_absent_drops() {
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    let mut f1 = ValueFact::top();
    f1.null = Nullability::NonNull;
    env1.refine(v, &f1);
    let env2 = PathEnv::empty(); // no fact for v
    let joined = env1.join(&env2);
    let got = joined.get(v);
    // Intentional: absent = Top, Top.join(NonNull) = Top → dropped
    assert_eq!(got.null, Nullability::Unknown);
}

#[test]
fn pathenv_join_one_side_nonnull_other_untouched() {
    // Verify explicitly: one branch refines x to NonNull, other leaves x untouched
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    env1.refine(v, &{
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        f
    });
    let env2 = PathEnv::empty();
    let joined = env1.join(&env2);
    assert_eq!(joined.get(v).null, Nullability::Unknown); // drops to Unknown
}

#[test]
fn pathenv_join_one_side_range_other_untouched() {
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    env1.refine(v, &{
        let mut f = ValueFact::top();
        f.lo = Some(0);
        f.lo_strict = true;
        f
    });
    let env2 = PathEnv::empty();
    let joined = env1.join(&env2);
    assert_eq!(joined.get(v).lo, None); // dropped
}

#[test]
fn pathenv_join_one_side_type_other_untouched() {
    use crate::ssa::type_facts::TypeKind;
    let v = SsaValue(0);
    let mut env1 = PathEnv::empty();
    env1.refine(v, &{
        let mut f = ValueFact::top();
        f.types = TypeSet::singleton(&TypeKind::String);
        f
    });
    let env2 = PathEnv::empty();
    let joined = env1.join(&env2);
    assert!(joined.get(v).types.is_top()); // dropped to Top
}

#[test]
fn pathenv_bounded_size() {
    let mut env = PathEnv::empty();
    for i in 0..(MAX_PATH_ENV_ENTRIES + 10) {
        let v = SsaValue(i as u32);
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        env.refine(v, &f);
    }
    assert!(env.fact_count() <= MAX_PATH_ENV_ENTRIES);
    assert!(!env.is_unsat());
}

#[test]
fn pathenv_max_refine_per_block() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // Reset counter
    env.reset_refine_count();
    // Refine many times, should stop after MAX_REFINE_PER_BLOCK
    for _ in 0..(MAX_REFINE_PER_BLOCK + 50) {
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        env.refine(v, &f);
    }
    // Should not panic or set unsat from excessive refinement
    assert!(!env.is_unsat());
}

// ── UnionFind tests ─────────────────────────────────────────────────────

#[test]
fn uf_basic_union_find() {
    let mut uf = UnionFind::new();
    let a = SsaValue(0);
    let b = SsaValue(1);
    assert!(!uf.same_class(a, b));
    uf.union(a, b);
    assert!(uf.same_class(a, b));
    assert_eq!(uf.find(a), uf.find(b));
}

#[test]
fn uf_transitive() {
    let mut uf = UnionFind::new();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let c = SsaValue(2);
    uf.union(a, b);
    uf.union(b, c);
    assert!(uf.same_class(a, c));
}

#[test]
fn uf_equality_propagates_facts() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_equal(a, b);
    // Refine a with Eq(5) → should propagate to b
    let mut fact = ValueFact::top();
    fact.exact = Some(ConstValue::Int(5));
    fact.lo = Some(5);
    fact.hi = Some(5);
    env.refine(a, &fact);
    let got_b = env.get(b);
    assert_eq!(got_b.exact, Some(ConstValue::Int(5)));
}

#[test]
fn uf_disequality_contradiction() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_equal(a, b);
    env.assert_not_equal(a, b);
    assert!(env.is_unsat());
}

#[test]
fn uf_transitive_disequality() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let c = SsaValue(2);
    env.assert_equal(a, b);
    env.assert_equal(b, c);
    // Now a==b==c, then assert a!=c → contradiction
    env.assert_not_equal(a, c);
    assert!(env.is_unsat());
}

#[test]
fn uf_max_edges_bounded() {
    let mut uf = UnionFind::new();
    for i in 0..(MAX_EQUALITY_EDGES + 10) {
        uf.union(SsaValue(0), SsaValue(i as u32 + 1));
    }
    assert!(uf.edge_count() <= MAX_EQUALITY_EDGES);
}

// ── Lowering tests ──────────────────────────────────────────────────────

#[test]
fn compop_flip() {
    assert_eq!(CompOp::Lt.flip(), CompOp::Gt);
    assert_eq!(CompOp::Gt.flip(), CompOp::Lt);
    assert_eq!(CompOp::Le.flip(), CompOp::Ge);
    assert_eq!(CompOp::Ge.flip(), CompOp::Le);
    assert_eq!(CompOp::Eq.flip(), CompOp::Eq);
    assert_eq!(CompOp::Neq.flip(), CompOp::Neq);
}

#[test]
fn compop_negate() {
    assert_eq!(CompOp::Eq.negate(), CompOp::Neq);
    assert_eq!(CompOp::Neq.negate(), CompOp::Eq);
    assert_eq!(CompOp::Lt.negate(), CompOp::Ge);
    assert_eq!(CompOp::Ge.negate(), CompOp::Lt);
    assert_eq!(CompOp::Gt.negate(), CompOp::Le);
    assert_eq!(CompOp::Le.negate(), CompOp::Gt);
}

#[test]
fn compop_negate_round_trip() {
    for op in [
        CompOp::Eq,
        CompOp::Neq,
        CompOp::Lt,
        CompOp::Gt,
        CompOp::Le,
        CompOp::Ge,
    ] {
        assert_eq!(op.negate().negate(), op);
    }
}

#[test]
fn condition_expr_negate_comparison() {
    let expr = ConditionExpr::Comparison {
        lhs: Operand::Value(SsaValue(0)),
        op: CompOp::Gt,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    let neg = expr.negate();
    match neg {
        ConditionExpr::Comparison { op, .. } => assert_eq!(op, CompOp::Le),
        _ => panic!("expected Comparison"),
    }
}

#[test]
fn condition_expr_negate_null_check() {
    let expr = ConditionExpr::NullCheck {
        var: SsaValue(0),
        is_null: true,
    };
    let neg = expr.negate();
    match neg {
        ConditionExpr::NullCheck { is_null, .. } => assert!(!is_null),
        _ => panic!("expected NullCheck"),
    }
}

#[test]
fn condition_expr_negate_type_check() {
    let expr = ConditionExpr::TypeCheck {
        var: SsaValue(0),
        type_name: "number".into(),
        positive: true,
    };
    let neg = expr.negate();
    match neg {
        ConditionExpr::TypeCheck { positive, .. } => assert!(!positive),
        _ => panic!("expected TypeCheck"),
    }
}

#[test]
fn const_value_parse_literal() {
    assert_eq!(ConstValue::parse_literal("5"), Some(ConstValue::Int(5)));
    assert_eq!(ConstValue::parse_literal("-3"), Some(ConstValue::Int(-3)));
    assert_eq!(ConstValue::parse_literal("null"), Some(ConstValue::Null));
    assert_eq!(ConstValue::parse_literal("None"), Some(ConstValue::Null));
    assert_eq!(
        ConstValue::parse_literal("true"),
        Some(ConstValue::Bool(true))
    );
    assert_eq!(
        ConstValue::parse_literal("\"hello\""),
        Some(ConstValue::Str("hello".into()))
    );
    assert_eq!(
        ConstValue::parse_literal("'world'"),
        Some(ConstValue::Str("world".into()))
    );
    assert_eq!(ConstValue::parse_literal(""), None);
    assert_eq!(ConstValue::parse_literal("xyz"), None);
}

// ── Solver tests ────────────────────────────────────────────────────────

#[test]
fn refine_null_check_true_branch() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::NullCheck {
        var: v,
        is_null: true,
    };
    env = refine_env(&env, &cond, true);
    assert_eq!(env.get(v).null, Nullability::Null);
}

#[test]
fn refine_null_check_false_branch() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::NullCheck {
        var: v,
        is_null: true,
    };
    env = refine_env(&env, &cond, false); // negated: not null
    assert_eq!(env.get(v).null, Nullability::NonNull);
}

#[test]
fn refine_comparison_gt_then_lt_contradiction() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // x > 10
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Gt,
        rhs: Operand::Const(ConstValue::Int(10)),
    };
    env = refine_env(&env, &c1, true);
    assert!(!env.is_unsat());
    // x < 5 (contradicts x > 10)
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Lt,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    env = refine_env(&env, &c2, true);
    assert!(env.is_unsat());
}

#[test]
fn refine_comparison_eq_then_neq_contradiction() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    env = refine_env(&env, &c1, true);
    assert!(!env.is_unsat());
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Neq,
        rhs: Operand::Const(ConstValue::Int(5)),
    };
    env = refine_env(&env, &c2, true);
    assert!(env.is_unsat());
}

#[test]
fn refine_comparison_eq_string_then_different_string() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Str("safe".into())),
    };
    env = refine_env(&env, &c1, true);
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Str("dangerous".into())),
    };
    env = refine_env(&env, &c2, true);
    assert!(
        env.is_unsat(),
        "Eq('safe') ∧ Eq('dangerous') should be unsat"
    );
}

#[test]
fn refine_type_check_positive() {
    use crate::ssa::type_facts::TypeKind;
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::TypeCheck {
        var: v,
        type_name: "number".into(),
        positive: true,
    };
    env = refine_env(&env, &cond, true);
    let got = env.get(v);
    assert!(got.types.contains(&TypeKind::Int));
    assert!(!got.types.contains(&TypeKind::String));
    assert_eq!(got.null, Nullability::NonNull);
}

#[test]
fn refine_type_check_negative() {
    use crate::ssa::type_facts::TypeKind;
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::TypeCheck {
        var: v,
        type_name: "number".into(),
        positive: true,
    };
    env = refine_env(&env, &cond, false); // NOT number
    let got = env.get(v);
    assert!(!got.types.contains(&TypeKind::Int));
    assert!(got.types.contains(&TypeKind::String));
}

#[test]
fn refine_value_eq_value() {
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    // First: a is NonNull
    env.refine(a, &{
        let mut f = ValueFact::top();
        f.null = Nullability::NonNull;
        f
    });
    // Then: a == b → b should also become NonNull
    let cond = ConditionExpr::Comparison {
        lhs: Operand::Value(a),
        op: CompOp::Eq,
        rhs: Operand::Value(b),
    };
    env = refine_env(&env, &cond, true);
    assert_eq!(env.get(b).null, Nullability::NonNull);
}

#[test]
fn refine_unknown_is_noop() {
    let env = PathEnv::empty();
    let refined = refine_env(&env, &ConditionExpr::Unknown, true);
    assert!(!refined.is_unsat());
    assert_eq!(refined.fact_count(), 0);
}

#[test]
fn refine_booltest_conservative() {
    // BoolTest should NOT add NonNull for non-boolean-typed values
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    let cond = ConditionExpr::BoolTest {
        var: v,
        negated: false,
    };
    env = refine_env(&env, &cond, true);
    // Since v has no known type, BoolTest should be conservative
    assert_eq!(env.get(v).null, Nullability::Unknown);
}

#[test]
fn refine_booltest_boolean_typed() {
    use crate::ssa::type_facts::TypeKind;
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // First: mark v as boolean-typed
    env.refine(v, &{
        let mut f = ValueFact::top();
        f.types = TypeSet::singleton(&TypeKind::Bool);
        f
    });
    // Now BoolTest should refine to True + NonNull
    let cond = ConditionExpr::BoolTest {
        var: v,
        negated: false,
    };
    env = refine_env(&env, &cond, true);
    assert_eq!(env.get(v).bool_state, BoolState::True);
    assert_eq!(env.get(v).null, Nullability::NonNull);
}

/// Environment where `SsaValue(0)` is the boolean constant `value`.
fn env_with_bool_const(value: bool) -> PathEnv {
    let const_values: crate::ssa::const_prop::ConstValues =
        [(SsaValue(0), ConstLattice::Bool(value))]
            .into_iter()
            .collect();
    let mut env = PathEnv::empty();
    env.seed_from_optimization(
        &const_values,
        &crate::ssa::type_facts::TypeFactResult {
            facts: HashMap::new(),
        },
    );
    env
}

#[test]
fn refine_booltest_false_branch_of_false_flag_is_feasible() {
    // `debug := false; if debug { .. } else { sink }`: the else branch is
    // the one that runs, so it must not be refined as `debug == true`.
    let env = env_with_bool_const(false);
    let cond = ConditionExpr::BoolTest {
        var: SsaValue(0),
        negated: false,
    };
    assert!(refine_env(&env, &cond, true).is_unsat(), "then-branch");
    assert!(!refine_env(&env, &cond, false).is_unsat(), "else-branch");
    assert_eq!(
        refine_env(&env, &cond, false).get(SsaValue(0)).bool_state,
        BoolState::False
    );
}

#[test]
fn refine_negated_booltest_follows_the_bang() {
    // `if !flag`: the then-branch is where `flag` is false.
    let cond = ConditionExpr::BoolTest {
        var: SsaValue(0),
        negated: true,
    };
    let t = env_with_bool_const(true);
    assert!(refine_env(&t, &cond, true).is_unsat(), "!true then-branch");
    assert!(
        !refine_env(&t, &cond, false).is_unsat(),
        "!true else-branch"
    );
    let f = env_with_bool_const(false);
    assert!(
        !refine_env(&f, &cond, true).is_unsat(),
        "!false then-branch"
    );
    assert!(
        refine_env(&f, &cond, false).is_unsat(),
        "!false else-branch"
    );
}

#[test]
fn booltest_negate_round_trips() {
    let cond = ConditionExpr::BoolTest {
        var: SsaValue(3),
        negated: false,
    };
    assert_eq!(
        cond.negate(),
        ConditionExpr::BoolTest {
            var: SsaValue(3),
            negated: true,
        }
    );
    assert_eq!(cond.negate().negate(), cond);
}

#[test]
fn refine_falsy_booltest_on_maybe_null_bool_learns_nothing() {
    // A `Boolean`/`bool`-typed value that may be null is falsy when null,
    // so the falsy branch cannot conclude `false`.  The truthy branch can
    // conclude `true` and non-null.
    use crate::ssa::type_facts::TypeKind;
    let env = env_with_typed_value(TypeKind::Bool);
    let cond = ConditionExpr::BoolTest {
        var: SsaValue(0),
        negated: false,
    };
    let falsy = refine_env(&env, &cond, false);
    assert!(!falsy.is_unsat());
    assert_eq!(falsy.get(SsaValue(0)).bool_state, BoolState::Unknown);
    let truthy = refine_env(&env, &cond, true);
    assert_eq!(truthy.get(SsaValue(0)).bool_state, BoolState::True);
    assert_eq!(truthy.get(SsaValue(0)).null, Nullability::NonNull);
}

#[test]
fn lower_condition_negated_bare_var_sets_booltest_negated() {
    // `if !flag` reaches the lowering with `condition_negated` set; the
    // resulting BoolTest must carry the negation instead of dropping it.
    use crate::cfg::NodeInfo;
    let info = NodeInfo {
        condition_text: Some("flag".into()),
        condition_vars: vec!["flag".into()],
        condition_negated: true,
        ..Default::default()
    };
    let mut stacks = rustc_hash::FxHashMap::default();
    stacks.insert("flag".to_string(), vec![SsaValue(4)]);
    assert_eq!(
        lower_condition_with_stacks(&info, &stacks),
        ConditionExpr::BoolTest {
            var: SsaValue(4),
            negated: true,
        }
    );
}

#[test]
fn refine_comparison_feasible_range_not_pruned() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // x > 0
    let c1 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Gt,
        rhs: Operand::Const(ConstValue::Int(0)),
    };
    env = refine_env(&env, &c1, true);
    // x < 100 (compatible with x > 0)
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Lt,
        rhs: Operand::Const(ConstValue::Int(100)),
    };
    env = refine_env(&env, &c2, true);
    assert!(
        !env.is_unsat(),
        "feasible range (0, 100) should not be pruned"
    );
}

#[test]
fn refine_null_then_eq_string_contradiction() {
    let mut env = PathEnv::empty();
    let v = SsaValue(0);
    // x is null
    let c1 = ConditionExpr::NullCheck {
        var: v,
        is_null: true,
    };
    env = refine_env(&env, &c1, true);
    // x == "rm" (contradicts: null value can't be a string)
    let c2 = ConditionExpr::Comparison {
        lhs: Operand::Value(v),
        op: CompOp::Eq,
        rhs: Operand::Const(ConstValue::Str("rm".into())),
    };
    env = refine_env(&env, &c2, true);
    assert!(env.is_unsat(), "null ∧ Eq('rm') should be unsat");
}

// ── parse_type_name tests ───────────────────────────────────────────────

#[test]
fn parse_type_name_coverage() {
    use crate::ssa::type_facts::TypeKind;
    assert_eq!(parse_type_name("string"), Some(TypeKind::String));
    assert_eq!(parse_type_name("str"), Some(TypeKind::String));
    assert_eq!(parse_type_name("number"), Some(TypeKind::Int));
    assert_eq!(parse_type_name("int"), Some(TypeKind::Int));
    assert_eq!(parse_type_name("boolean"), Some(TypeKind::Bool));
    assert_eq!(parse_type_name("bool"), Some(TypeKind::Bool));
    assert_eq!(parse_type_name("object"), Some(TypeKind::Object));
    assert_eq!(parse_type_name("array"), Some(TypeKind::Array));
    assert_eq!(parse_type_name("null"), Some(TypeKind::Null));
    assert_eq!(parse_type_name("undefined"), Some(TypeKind::Null));
    assert_eq!(parse_type_name("blah"), None);
}

// ── PathEnv seed tests ──────────────────────────────────────────────────

#[test]
fn pathenv_seed_from_optimization() {
    use crate::ssa::type_facts::{TypeFact, TypeFactResult, TypeKind};
    let mut env = PathEnv::empty();
    let v0 = SsaValue(0);
    let v1 = SsaValue(1);
    let const_values: crate::ssa::const_prop::ConstValues =
        [(v0, ConstLattice::Int(42))].into_iter().collect();
    let mut type_facts = TypeFactResult {
        facts: HashMap::new(),
    };
    type_facts.facts.insert(
        v1,
        TypeFact {
            kind: TypeKind::String,
            nullable: false,
        },
    );
    env.seed_from_optimization(&const_values, &type_facts);
    let f0 = env.get(v0);
    assert_eq!(f0.exact, Some(ConstValue::Int(42)));
    assert_eq!(f0.null, Nullability::NonNull);
    // A type fact names the type but proves nothing about nullness, even
    // with `nullable: false`: the set keeps the `Null` bit and the value's
    // nullability stays unknown.
    let f1 = env.get(v1);
    assert!(f1.types.contains(&TypeKind::String));
    assert!(f1.types.contains(&TypeKind::Null));
    assert_eq!(f1.types.as_singleton(), Some(TypeKind::String));
    assert_eq!(f1.null, Nullability::Unknown);
}

/// Seed an environment with one non-nullable type fact on `SsaValue(0)`.
fn env_with_typed_value(kind: crate::ssa::type_facts::TypeKind) -> PathEnv {
    use crate::ssa::type_facts::{TypeFact, TypeFactResult};
    let mut type_facts = TypeFactResult {
        facts: HashMap::new(),
    };
    type_facts.facts.insert(
        SsaValue(0),
        TypeFact {
            kind,
            nullable: false,
        },
    );
    let mut env = PathEnv::empty();
    env.seed_from_optimization(&crate::ssa::const_prop::ConstValues::default(), &type_facts);
    env
}

#[test]
fn pathenv_seed_typed_value_keeps_both_nil_branches() {
    // gitea `cmd/serv.go`: `if _, err := os.Stat(p); err != nil` and
    // `if command == nil` where `var command *exec.Cmd`.  Both values are
    // known only by type; either branch of the nil check is reachable.
    use crate::ssa::type_facts::TypeKind;
    for kind in [TypeKind::Object, TypeKind::String, TypeKind::Int] {
        let env = env_with_typed_value(kind.clone());
        let check = ConditionExpr::NullCheck {
            var: SsaValue(0),
            is_null: true,
        };
        let is_nil = refine_env(&env, &check, true);
        let not_nil = refine_env(&env, &check, false);
        assert!(
            !is_nil.is_unsat(),
            "{kind:?}: `x == nil` must stay feasible"
        );
        assert!(
            !not_nil.is_unsat(),
            "{kind:?}: `x != nil` must stay feasible"
        );
        assert_eq!(is_nil.get(SsaValue(0)).null, Nullability::Null);
        assert_eq!(not_nil.get(SsaValue(0)).null, Nullability::NonNull);
    }
}

#[test]
fn pathenv_seed_typed_value_negated_type_check_allows_null() {
    // `!(s instanceof String)` holds when `s` is null, so it is feasible for a
    // value typed `String`; the positive check is feasible too.
    use crate::ssa::type_facts::TypeKind;
    let env = env_with_typed_value(TypeKind::String);
    let check = ConditionExpr::TypeCheck {
        var: SsaValue(0),
        type_name: "String".into(),
        positive: true,
    };
    assert!(!refine_env(&env, &check, true).is_unsat());
    let negated = refine_env(&env, &check, false);
    assert!(!negated.is_unsat());
    assert_eq!(
        negated.get(SsaValue(0)).types,
        TypeSet::singleton(&TypeKind::Null)
    );
}

#[test]
fn pathenv_seed_null_type_fact_contradicts_non_null_branch() {
    use crate::ssa::type_facts::TypeKind;
    let env = env_with_typed_value(TypeKind::Null);
    assert_eq!(env.get(SsaValue(0)).null, Nullability::Null);
    let check = ConditionExpr::NullCheck {
        var: SsaValue(0),
        is_null: true,
    };
    assert!(!refine_env(&env, &check, true).is_unsat());
    assert!(refine_env(&env, &check, false).is_unsat());
}

#[test]
fn pathenv_seed_skips_unknown_type_facts() {
    // An `Unknown` fact says nothing, so it must not take a slot in the
    // capped table (nor constrain the value).
    use crate::ssa::type_facts::TypeKind;
    let env = env_with_typed_value(TypeKind::Unknown);
    assert_eq!(env.fact_count(), 0);
    assert!(env.get(SsaValue(0)).is_top());
}

#[test]
fn typeset_singleton_queries_ignore_null_bit() {
    use crate::ssa::type_facts::TypeKind;
    let maybe_null_str = TypeSet::singleton(&TypeKind::String).with_null();
    assert!(maybe_null_str.is_singleton_of(&TypeKind::String));
    assert!(!maybe_null_str.is_singleton_of(&TypeKind::Null));
    assert_eq!(maybe_null_str.as_singleton(), Some(TypeKind::String));

    let null_only = TypeSet::singleton(&TypeKind::Null);
    assert!(null_only.is_singleton_of(&TypeKind::Null));
    assert_eq!(null_only.as_singleton(), Some(TypeKind::Null));

    let str_or_int = TypeSet::singleton(&TypeKind::String)
        .join(TypeSet::singleton(&TypeKind::Int))
        .with_null();
    assert_eq!(str_or_int.as_singleton(), None);
    assert!(!str_or_int.is_singleton_of(&TypeKind::String));
}

#[test]
fn pathenv_seed_unknown_type_does_not_contradict_const() {
    // A loop counter whose phi folds to a constant has an `Int` const fact
    // and an `Unknown` type fact.  `Unknown` carries no type information, so
    // seeding both must leave the environment satisfiable.
    use crate::ssa::type_facts::{TypeFact, TypeFactResult, TypeKind};
    let mut env = PathEnv::empty();
    let v0 = SsaValue(0);
    let const_values: crate::ssa::const_prop::ConstValues =
        [(v0, ConstLattice::Int(0))].into_iter().collect();
    let mut type_facts = TypeFactResult {
        facts: HashMap::new(),
    };
    type_facts.facts.insert(
        v0,
        TypeFact {
            kind: TypeKind::Unknown,
            nullable: false,
        },
    );
    env.seed_from_optimization(&const_values, &type_facts);
    assert!(!env.is_unsat());
    assert_eq!(env.get(v0).exact, Some(ConstValue::Int(0)));
}

#[test]
fn pathenv_seed_overflowing_type_facts_is_order_independent() {
    // More type facts than the environment can hold.  Which ones are kept
    // decides what the symex explorer can later prove unsatisfiable, so the
    // admitted set must not depend on the type-fact map's iteration order.
    // Every `HashMap::new()` draws fresh `RandomState` keys, so rebuilding
    // the map (in both insertion orders) exercises many iteration orders.
    use crate::ssa::type_facts::{TypeFact, TypeFactResult, TypeKind};
    let total = MAX_PATH_ENV_ENTRIES + 32;
    let const_values = crate::ssa::const_prop::ConstValues::default();
    let seed = |reverse: bool| {
        let mut type_facts = TypeFactResult {
            facts: HashMap::new(),
        };
        let mut ids: Vec<u32> = (0..total as u32).collect();
        if reverse {
            ids.reverse();
        }
        for id in ids {
            type_facts.facts.insert(
                SsaValue(id),
                TypeFact {
                    kind: TypeKind::String,
                    nullable: false,
                },
            );
        }
        let mut env = PathEnv::empty();
        env.seed_from_optimization(&const_values, &type_facts);
        env
    };

    let reference = seed(false);
    let kept: Vec<SsaValue> = reference.facts().iter().map(|(v, _)| *v).collect();
    let expected: Vec<SsaValue> = (0..MAX_PATH_ENV_ENTRIES as u32).map(SsaValue).collect();
    assert_eq!(kept, expected, "the lowest SsaValues fill the capped table");
    for round in 0..16 {
        assert_eq!(seed(round % 2 == 1), reference, "round {round}");
    }
}

// ── Relational constraint tests ────────────────────────────────────────

#[test]
fn pathenv_relational_lt_lt_contradiction() {
    // a < b then b < a → unsat (both strict)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_relational(a, RelOp::Lt, b);
    assert!(!env.is_unsat());
    env.assert_relational(b, RelOp::Lt, a);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_relational_lt_le_contradiction() {
    // a < b then b <= a → unsat (one strict suffices)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_relational(a, RelOp::Lt, b);
    assert!(!env.is_unsat());
    env.assert_relational(b, RelOp::Le, a);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_relational_le_lt_contradiction() {
    // a <= b then b < a → unsat (symmetric)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_relational(a, RelOp::Le, b);
    assert!(!env.is_unsat());
    env.assert_relational(b, RelOp::Lt, a);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_relational_le_le_not_contradiction() {
    // a <= b then b <= a → NOT unsat (a == b is satisfiable)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_relational(a, RelOp::Le, b);
    assert!(!env.is_unsat());
    env.assert_relational(b, RelOp::Le, a);
    assert!(!env.is_unsat());
}

#[test]
fn pathenv_relational_transitive_cycle() {
    // a < b, b < c, c < a → unsat (cycle with strict edge)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let c = SsaValue(2);
    env.assert_relational(a, RelOp::Lt, b);
    assert!(!env.is_unsat());
    env.assert_relational(b, RelOp::Lt, c);
    assert!(!env.is_unsat());
    env.assert_relational(c, RelOp::Lt, a);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_relational_transitive_all_le_cycle() {
    // a <= b, b <= c, c <= a → NOT unsat (all equal is satisfiable)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let c = SsaValue(2);
    env.assert_relational(a, RelOp::Le, b);
    env.assert_relational(b, RelOp::Le, c);
    env.assert_relational(c, RelOp::Le, a);
    assert!(!env.is_unsat());
}

#[test]
fn pathenv_relational_cross_interval_refine_strict() {
    // a < b with b ∈ [0, 10] → a.hi = 9 (strict: h-1)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let mut b_fact = ValueFact::top();
    b_fact.lo = Some(0);
    b_fact.hi = Some(10);
    env.refine(b, &b_fact);
    env.assert_relational(a, RelOp::Lt, b);
    let fa = env.get(a);
    assert_eq!(fa.hi, Some(9));
}

#[test]
fn pathenv_relational_cross_interval_refine_nonstrict() {
    // a <= b with b ∈ [0, 10] → a.hi = 10 (non-strict)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let mut b_fact = ValueFact::top();
    b_fact.lo = Some(0);
    b_fact.hi = Some(10);
    env.refine(b, &b_fact);
    env.assert_relational(a, RelOp::Le, b);
    let fa = env.get(a);
    assert_eq!(fa.hi, Some(10));
}

#[test]
fn pathenv_relational_cross_interval_refine_reverse() {
    // a < b with a ∈ [5, 20] → b.lo = 6 (strict: l+1)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    let mut a_fact = ValueFact::top();
    a_fact.lo = Some(5);
    a_fact.hi = Some(20);
    env.refine(a, &a_fact);
    env.assert_relational(a, RelOp::Lt, b);
    let fb = env.get(b);
    assert_eq!(fb.lo, Some(6));
}

#[test]
fn pathenv_relational_join_intersection() {
    // Only shared constraints survive join
    let a = SsaValue(0);
    let b = SsaValue(1);
    let c = SsaValue(2);

    let mut env1 = PathEnv::empty();
    env1.assert_relational(a, RelOp::Lt, b);
    env1.assert_relational(b, RelOp::Lt, c);

    let mut env2 = PathEnv::empty();
    env2.assert_relational(a, RelOp::Lt, b);
    // env2 does NOT have b < c

    let joined = env1.join(&env2);
    assert!(!joined.is_unsat());
    // The shared constraint a < b should survive;
    // b < c should be lost. We can verify by adding c < a
    // which would be contradictory with both a < b and b < c,
    // but only the first matters here.
    // (We can't directly inspect relational, but we can test behavior)
}

#[test]
fn pathenv_relational_max_bounded() {
    // Exceeding MAX_RELATIONAL doesn't panic
    let mut env = PathEnv::empty();
    for i in 0..MAX_RELATIONAL + 5 {
        let a = SsaValue(i as u32 * 2);
        let b = SsaValue(i as u32 * 2 + 1);
        env.assert_relational(a, RelOp::Lt, b);
        assert!(!env.is_unsat());
    }
}

#[test]
fn pathenv_relational_eq_then_strict_lt() {
    // assert_equal(a, b) then a < b → unsat
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_relational(a, RelOp::Lt, b);
    assert!(!env.is_unsat());
    env.assert_equal(a, b);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_relational_eq_then_le_ok() {
    // assert_equal(a, b) then a <= b is fine (Le compat with equality)
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    let b = SsaValue(1);
    env.assert_relational(a, RelOp::Le, b);
    assert!(!env.is_unsat());
    env.assert_equal(a, b);
    assert!(!env.is_unsat());
}

#[test]
fn solver_value_lt_value() {
    // End-to-end via refine_env with Comparison { Value(a), Lt, Value(b) }
    let a = SsaValue(0);
    let b = SsaValue(1);
    let env = PathEnv::empty();

    // True branch: a < b holds
    let cond = ConditionExpr::Comparison {
        lhs: Operand::Value(a),
        op: CompOp::Lt,
        rhs: Operand::Value(b),
    };
    let true_env = refine_env(&env, &cond, true);
    assert!(!true_env.is_unsat());

    // Now on true branch, assert b < a → should be unsat
    let cond2 = ConditionExpr::Comparison {
        lhs: Operand::Value(b),
        op: CompOp::Lt,
        rhs: Operand::Value(a),
    };
    let nested = refine_env(&true_env, &cond2, true);
    assert!(nested.is_unsat());
}

#[test]
fn solver_value_gt_value_contradiction() {
    // a > b on true branch, then b > a → unsat (via Gt → Lt flip)
    let a = SsaValue(0);
    let b = SsaValue(1);
    let env = PathEnv::empty();

    let cond1 = ConditionExpr::Comparison {
        lhs: Operand::Value(a),
        op: CompOp::Gt,
        rhs: Operand::Value(b),
    };
    let env1 = refine_env(&env, &cond1, true);
    assert!(!env1.is_unsat());

    let cond2 = ConditionExpr::Comparison {
        lhs: Operand::Value(b),
        op: CompOp::Gt,
        rhs: Operand::Value(a),
    };
    let env2 = refine_env(&env1, &cond2, true);
    assert!(env2.is_unsat());
}

#[test]
fn solver_value_le_ge_not_contradiction() {
    // a <= b then a >= b (i.e. b <= a) → NOT unsat (a == b)
    let a = SsaValue(0);
    let b = SsaValue(1);
    let env = PathEnv::empty();

    let cond1 = ConditionExpr::Comparison {
        lhs: Operand::Value(a),
        op: CompOp::Le,
        rhs: Operand::Value(b),
    };
    let env1 = refine_env(&env, &cond1, true);
    assert!(!env1.is_unsat());

    let cond2 = ConditionExpr::Comparison {
        lhs: Operand::Value(a),
        op: CompOp::Ge,
        rhs: Operand::Value(b),
    };
    let env2 = refine_env(&env1, &cond2, true);
    assert!(!env2.is_unsat());
}

#[test]
fn pathenv_relational_self_lt_unsat() {
    // a < a → unsat immediately
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    env.assert_relational(a, RelOp::Lt, a);
    assert!(env.is_unsat());
}

#[test]
fn pathenv_relational_self_le_ok() {
    // a <= a → trivially true, not unsat
    let mut env = PathEnv::empty();
    let a = SsaValue(0);
    env.assert_relational(a, RelOp::Le, a);
    assert!(!env.is_unsat());
}
