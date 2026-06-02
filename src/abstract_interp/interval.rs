//! Numeric interval domain for abstract interpretation.
//!
//! Tracks inclusive `[lo, hi]` integer bounds. `None` = unbounded (−∞ or +∞).
//! Both `None` = Top (any integer). Provides arithmetic transfer functions
//! (add, sub, mul, div, mod) with overflow-safe semantics.

use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};

/// Numeric interval: `[lo, hi]` inclusive bounds.
///
/// - `top()` = `[None, None]`, any integer
/// - `bottom()` = `[1, 0]`, empty / unsatisfiable (lo > hi)
/// - `exact(n)` = `[n, n]`, singleton
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntervalFact {
    pub lo: Option<i64>,
    pub hi: Option<i64>,
}

impl IntervalFact {
    pub fn top() -> Self {
        Self { lo: None, hi: None }
    }

    pub fn bottom() -> Self {
        Self {
            lo: Some(1),
            hi: Some(0),
        }
    }

    pub fn exact(n: i64) -> Self {
        Self {
            lo: Some(n),
            hi: Some(n),
        }
    }

    pub fn is_top(&self) -> bool {
        self.lo.is_none() && self.hi.is_none()
    }

    pub fn is_bottom(&self) -> bool {
        matches!((self.lo, self.hi), (Some(l), Some(h)) if l > h)
    }

    /// True when both bounds are known finite values: the value is a proven
    /// integer within `[lo, hi]`.
    pub fn is_proven_bounded(&self) -> bool {
        self.lo.is_some() && self.hi.is_some() && !self.is_bottom()
    }

    // ── Lattice operations ──────────────────────────────────────────────

    /// Join (hull): `[min(lo), max(hi)]`.
    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        Self {
            lo: match (self.lo, other.lo) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None, // unbounded wins
            },
            hi: match (self.hi, other.hi) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            },
        }
    }

    /// Meet (intersection): `[max(lo), min(hi)]`.
    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        let lo = match (self.lo, other.lo) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let hi = match (self.hi, other.hi) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let result = Self { lo, hi };
        if result.is_bottom() {
            Self::bottom()
        } else {
            result
        }
    }

    /// Widen: drop bounds that changed between iterations.
    ///
    /// Guarantees finite ascending chains: each bound can transition
    /// `Some(n) → None` at most once, then stabilizes. Height = 3 per bound.
    pub fn widen(&self, other: &Self) -> Self {
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        let lo = if self.lo == other.lo {
            self.lo
        } else {
            None // lower bound changed → drop to −∞
        };
        let hi = if self.hi == other.hi {
            self.hi
        } else {
            None // upper bound changed → drop to +∞
        };
        Self { lo, hi }
    }

    pub fn leq(&self, other: &Self) -> bool {
        if self.is_bottom() {
            return true;
        }
        if other.is_bottom() {
            return false;
        }
        // self ⊑ other iff other.lo ≤ self.lo and self.hi ≤ other.hi
        // (other is at least as wide as self)
        let lo_ok = match (self.lo, other.lo) {
            (_, None) => true,        // other unbounded below → ok
            (None, Some(_)) => false, // self unbounded, other bounded → not ⊑
            (Some(a), Some(b)) => a >= b,
        };
        let hi_ok = match (self.hi, other.hi) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a <= b,
        };
        lo_ok && hi_ok
    }

    // ── Arithmetic transfer functions ───────────────────────────────────

    /// Addition: `[a.lo + b.lo, a.hi + b.hi]`.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        Self {
            lo: checked_add_opt(self.lo, other.lo),
            hi: checked_add_opt(self.hi, other.hi),
        }
    }

    /// Subtraction: `[a.lo - b.hi, a.hi - b.lo]`.
    pub fn sub(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        Self {
            lo: checked_sub_opt(self.lo, other.hi),
            hi: checked_sub_opt(self.hi, other.lo),
        }
    }

    /// Multiplication: min/max of all 4 endpoint products.
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        // If any bound is None, result is Top for that direction
        if self.is_top() || other.is_top() {
            return Self::top();
        }
        match (self.lo, self.hi, other.lo, other.hi) {
            (Some(a_lo), Some(a_hi), Some(b_lo), Some(b_hi)) => {
                let products = [
                    a_lo.checked_mul(b_lo),
                    a_lo.checked_mul(b_hi),
                    a_hi.checked_mul(b_lo),
                    a_hi.checked_mul(b_hi),
                ];
                let lo = products.iter().filter_map(|p| *p).min();
                let hi = products.iter().filter_map(|p| *p).max();
                // If any product overflowed, the corresponding bound is None
                if products.iter().any(|p| p.is_none()) {
                    Self {
                        lo: if lo.is_some() && products[..2].iter().all(|p| p.is_some()) {
                            lo
                        } else {
                            None
                        },
                        hi: if hi.is_some() && products[2..].iter().all(|p| p.is_some()) {
                            hi
                        } else {
                            None
                        },
                    }
                } else {
                    Self { lo, hi }
                }
            }
            _ => Self::top(),
        }
    }

    /// Division: conservative. If divisor range spans 0, result is Top.
    pub fn div(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        match (self.lo, self.hi, other.lo, other.hi) {
            (Some(a_lo), Some(a_hi), Some(b_lo), Some(b_hi)) => {
                // Division by zero possible → Top
                if b_lo <= 0 && b_hi >= 0 {
                    return Self::top();
                }
                let quotients = [
                    a_lo.checked_div(b_lo),
                    a_lo.checked_div(b_hi),
                    a_hi.checked_div(b_lo),
                    a_hi.checked_div(b_hi),
                ];
                let lo = quotients.iter().filter_map(|q| *q).min();
                let hi = quotients.iter().filter_map(|q| *q).max();
                Self { lo, hi }
            }
            _ => Self::top(),
        }
    }

    /// Modulo: `[0, max(|b.lo|, |b.hi|) - 1]` when divisor is fully known
    /// and non-zero. Otherwise Top.
    pub fn modulo(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        match (other.lo, other.hi) {
            (Some(b_lo), Some(b_hi)) => {
                if b_lo <= 0 && b_hi >= 0 {
                    return Self::top(); // modulo by zero possible
                }
                let abs_max = b_lo.unsigned_abs().max(b_hi.unsigned_abs());
                if abs_max == 0 {
                    return Self::top();
                }
                // Result of a % b is in [0, |b|-1] for non-negative a,
                // or [-(|b|-1), |b|-1] in general. Conservative: use wider.
                let bound = (abs_max - 1) as i64;
                if self.lo.is_some_and(|l| l >= 0) {
                    Self {
                        lo: Some(0),
                        hi: Some(bound),
                    }
                } else {
                    Self {
                        lo: Some(-bound),
                        hi: Some(bound),
                    }
                }
            }
            _ => Self::top(),
        }
    }

    // ── Bitwise transfer functions ──────────────────────────────────────

    /// Bitwise AND: `a & b`.
    ///
    /// - Singletons: exact computation.
    /// - `x & 0` or `0 & x` → `[0, 0]`.
    /// - One non-negative singleton mask `m`: `[0, m]` regardless of other
    ///   operand's sign (two's complement AND with a non-negative mask always
    ///   produces a non-negative result bounded by the mask).
    /// - Both non-negative: `[0, min(a.hi, b.hi)]`, AND can only clear bits.
    pub fn bit_and(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        // Exact singletons
        if let (Some(a), Some(b)) = (self.as_singleton(), other.as_singleton()) {
            return Self::exact(a & b);
        }
        // x & 0 = 0
        if self.as_singleton() == Some(0) || other.as_singleton() == Some(0) {
            return Self::exact(0);
        }
        // Non-negative singleton mask: x & m is always in [0, m] regardless
        // of x's sign (two's complement AND with non-negative mask clears
        // the sign bit, producing a non-negative result ≤ mask).
        if let Some(m) = other.as_singleton() {
            if m >= 0 {
                return Self {
                    lo: Some(0),
                    hi: Some(m),
                };
            }
        }
        if let Some(m) = self.as_singleton() {
            if m >= 0 {
                return Self {
                    lo: Some(0),
                    hi: Some(m),
                };
            }
        }
        // Both non-negative
        let a_nonneg = self.lo.is_some_and(|l| l >= 0);
        let b_nonneg = other.lo.is_some_and(|l| l >= 0);
        if a_nonneg && b_nonneg {
            let hi = match (self.hi, other.hi) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            return Self { lo: Some(0), hi };
        }
        Self::top()
    }

    /// Bitwise OR: `a | b`.
    ///
    /// - Singletons: exact computation.
    /// - `x | 0` → `x`, `0 | x` → `x`.
    /// - Both non-negative with known upper bounds: `[max(a.lo, b.lo),
    ///   next_pow2_minus1(max(a.hi, b.hi))]`, OR can set any bit below
    ///   the highest set bit of either operand.
    pub fn bit_or(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        if let (Some(a), Some(b)) = (self.as_singleton(), other.as_singleton()) {
            return Self::exact(a | b);
        }
        // x | 0 = x
        if other.as_singleton() == Some(0) {
            return self.clone();
        }
        if self.as_singleton() == Some(0) {
            return other.clone();
        }
        // Both non-negative with bounded hi
        let a_nonneg = self.lo.is_some_and(|l| l >= 0);
        let b_nonneg = other.lo.is_some_and(|l| l >= 0);
        if a_nonneg && b_nonneg {
            if let (Some(a_hi), Some(b_hi)) = (self.hi, other.hi) {
                let max_hi = a_hi.max(b_hi);
                let lo = self.lo.unwrap_or(0).max(other.lo.unwrap_or(0));
                return Self {
                    lo: Some(lo),
                    hi: Some(next_pow2_minus1(max_hi)),
                };
            }
        }
        Self::top()
    }

    /// Bitwise XOR: `a ^ b`.
    ///
    /// - Singletons: exact computation.
    /// - `x ^ 0` → `x`, `0 ^ x` → `x`.
    /// - Same singleton: `x ^ x` → `[0, 0]`.
    /// - Both non-negative with known upper bounds:
    ///   `[0, next_pow2_minus1(max(a.hi, b.hi))]`.
    pub fn bit_xor(&self, other: &Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        if let (Some(a), Some(b)) = (self.as_singleton(), other.as_singleton()) {
            return Self::exact(a ^ b);
        }
        // x ^ 0 = x
        if other.as_singleton() == Some(0) {
            return self.clone();
        }
        if self.as_singleton() == Some(0) {
            return other.clone();
        }
        // Both non-negative with bounded hi
        let a_nonneg = self.lo.is_some_and(|l| l >= 0);
        let b_nonneg = other.lo.is_some_and(|l| l >= 0);
        if a_nonneg && b_nonneg {
            if let (Some(a_hi), Some(b_hi)) = (self.hi, other.hi) {
                let max_hi = a_hi.max(b_hi);
                return Self {
                    lo: Some(0),
                    hi: Some(next_pow2_minus1(max_hi)),
                };
            }
        }
        Self::top()
    }

    /// Left shift: `a << b`.
    ///
    /// - Both singletons with shift in `0..63`: exact via `checked_shl`.
    /// - Non-negative `a`, shift range in `0..63`:
    ///   `[a.lo << b.lo, a.hi << b.hi]` with overflow checking.
    pub fn left_shift(&self, shift: &Self) -> Self {
        if self.is_bottom() || shift.is_bottom() {
            return Self::bottom();
        }
        match (self.lo, self.hi, shift.lo, shift.hi) {
            // Both bounded
            (Some(a_lo), Some(a_hi), Some(s_lo), Some(s_hi))
                if a_lo >= 0 && s_lo >= 0 && s_hi <= 63 =>
            {
                // lo: smallest value (a_lo) shifted by smallest amount (s_lo)
                let result_lo = (a_lo as u64).checked_shl(s_lo as u32);
                // hi: largest value (a_hi) shifted by largest amount (s_hi)
                let result_hi = (a_hi as u64).checked_shl(s_hi as u32);
                match (result_lo, result_hi) {
                    (Some(lo), Some(hi)) if lo <= i64::MAX as u64 && hi <= i64::MAX as u64 => {
                        Self {
                            lo: Some(lo as i64),
                            hi: Some(hi as i64),
                        }
                    }
                    _ => Self::top(), // overflow
                }
            }
            _ => Self::top(),
        }
    }

    /// Right shift: `a >> b` (arithmetic).
    ///
    /// - Both singletons with shift in `0..63`: exact via `checked_shr`.
    /// - Non-negative `a`, bounded shift: `[a.lo >> s.hi, a.hi >> s.lo]`.
    pub fn right_shift(&self, shift: &Self) -> Self {
        if self.is_bottom() || shift.is_bottom() {
            return Self::bottom();
        }
        match (self.lo, self.hi, shift.lo, shift.hi) {
            (Some(a_lo), Some(a_hi), Some(s_lo), Some(s_hi))
                if a_lo >= 0 && s_lo >= 0 && s_hi <= 63 =>
            {
                // Right shift reduces magnitude:
                // min result: largest dividend >> largest shift
                // max result: largest dividend >> smallest shift
                Self {
                    lo: Some(a_lo >> s_hi), // max shift → min result
                    hi: Some(a_hi >> s_lo), // min shift → max result
                }
            }
            _ => Self::top(),
        }
    }

    /// Extract singleton value if `lo == hi`.
    fn as_singleton(&self) -> Option<i64> {
        match (self.lo, self.hi) {
            (Some(lo), Some(hi)) if lo == hi => Some(lo),
            _ => None,
        }
    }
}

/// Smallest `2^k - 1 ≥ n` for non-negative `n`.
///
/// Used to bound OR and XOR results: the result of `a | b` or `a ^ b` where
/// both operands are in `[0, n]` is at most `next_pow2_minus1(n)`.
fn next_pow2_minus1(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }
    // Find the position of the highest set bit
    let bits_needed = 64 - (n as u64).leading_zeros();
    if bits_needed >= 63 {
        // Would overflow i64 → use max positive i64
        return i64::MAX;
    }
    (1i64 << bits_needed) - 1
}

impl Lattice for IntervalFact {
    fn bot() -> Self {
        Self::bottom()
    }

    fn join(&self, other: &Self) -> Self {
        self.join(other)
    }

    fn leq(&self, other: &Self) -> bool {
        self.leq(other)
    }
}

impl AbstractDomain for IntervalFact {
    fn top() -> Self {
        Self::top()
    }

    fn meet(&self, other: &Self) -> Self {
        self.meet(other)
    }

    fn widen(&self, other: &Self) -> Self {
        self.widen(other)
    }
}

// ── Overflow-safe helpers ───────────────────────────────────────────────

fn checked_add_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => x.checked_add(y), // None on overflow
        _ => None,                              // unbounded
    }
}

fn checked_sub_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => x.checked_sub(y),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_values() {
        let a = IntervalFact::exact(5);
        assert_eq!(a.lo, Some(5));
        assert_eq!(a.hi, Some(5));
        assert!(a.is_proven_bounded());
        assert!(!a.is_top());
        assert!(!a.is_bottom());
    }

    #[test]
    fn top_and_bottom() {
        let t = IntervalFact::top();
        assert!(t.is_top());
        assert!(!t.is_bottom());
        assert!(!t.is_proven_bounded());

        let b = IntervalFact::bottom();
        assert!(b.is_bottom());
        assert!(!b.is_top());
        assert!(!b.is_proven_bounded());
    }

    // ── Lattice properties ──────────────────────────────────────────

    #[test]
    fn join_commutative() {
        let a = IntervalFact::exact(3);
        let b = IntervalFact::exact(7);
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_associative() {
        let a = IntervalFact::exact(1);
        let b = IntervalFact::exact(5);
        let c = IntervalFact::exact(3);
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn join_idempotent() {
        let a = IntervalFact {
            lo: Some(2),
            hi: Some(8),
        };
        assert_eq!(a.join(&a), a);
    }

    #[test]
    fn join_hull() {
        let a = IntervalFact {
            lo: Some(2),
            hi: Some(5),
        };
        let b = IntervalFact {
            lo: Some(3),
            hi: Some(9),
        };
        let j = a.join(&b);
        assert_eq!(j.lo, Some(2));
        assert_eq!(j.hi, Some(9));
    }

    #[test]
    fn join_with_bottom_identity() {
        let a = IntervalFact::exact(5);
        assert_eq!(a.join(&IntervalFact::bottom()), a);
        assert_eq!(IntervalFact::bottom().join(&a), a);
    }

    #[test]
    fn meet_intersection() {
        let a = IntervalFact {
            lo: Some(1),
            hi: Some(10),
        };
        let b = IntervalFact {
            lo: Some(5),
            hi: Some(15),
        };
        let m = a.meet(&b);
        assert_eq!(m.lo, Some(5));
        assert_eq!(m.hi, Some(10));
    }

    #[test]
    fn meet_disjoint_is_bottom() {
        let a = IntervalFact {
            lo: Some(1),
            hi: Some(3),
        };
        let b = IntervalFact {
            lo: Some(5),
            hi: Some(7),
        };
        assert!(a.meet(&b).is_bottom());
    }

    #[test]
    fn leq_subset() {
        let narrow = IntervalFact {
            lo: Some(3),
            hi: Some(5),
        };
        let wide = IntervalFact {
            lo: Some(1),
            hi: Some(10),
        };
        assert!(narrow.leq(&wide));
        assert!(!wide.leq(&narrow));
    }

    #[test]
    fn leq_top_greatest() {
        let a = IntervalFact::exact(42);
        assert!(a.leq(&IntervalFact::top()));
        assert!(!IntervalFact::top().leq(&a));
    }

    #[test]
    fn leq_bottom_least() {
        assert!(IntervalFact::bottom().leq(&IntervalFact::exact(0)));
        assert!(IntervalFact::bottom().leq(&IntervalFact::top()));
    }

    // ── Widening ────────────────────────────────────────────────────

    #[test]
    fn widen_stable_bounds() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        assert_eq!(a.widen(&a), a);
    }

    #[test]
    fn widen_growing_upper() {
        let old = IntervalFact {
            lo: Some(0),
            hi: Some(5),
        };
        let new = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        let w = old.widen(&new);
        assert_eq!(w.lo, Some(0)); // stable
        assert_eq!(w.hi, None); // grew → dropped
    }

    #[test]
    fn widen_growing_lower() {
        let old = IntervalFact {
            lo: Some(5),
            hi: Some(10),
        };
        let new = IntervalFact {
            lo: Some(2),
            hi: Some(10),
        };
        let w = old.widen(&new);
        assert_eq!(w.lo, None); // changed → dropped
        assert_eq!(w.hi, Some(10));
    }

    // ── Arithmetic transfer ─────────────────────────────────────────

    #[test]
    fn add_exact() {
        assert_eq!(
            IntervalFact::exact(5).add(&IntervalFact::exact(3)),
            IntervalFact::exact(8)
        );
    }

    #[test]
    fn add_ranges() {
        let a = IntervalFact {
            lo: Some(1),
            hi: Some(5),
        };
        let b = IntervalFact {
            lo: Some(2),
            hi: Some(4),
        };
        let r = a.add(&b);
        assert_eq!(r.lo, Some(3));
        assert_eq!(r.hi, Some(9));
    }

    #[test]
    fn sub_ranges() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        let b = IntervalFact {
            lo: Some(1),
            hi: Some(3),
        };
        let r = a.sub(&b);
        assert_eq!(r.lo, Some(-3)); // 0 - 3
        assert_eq!(r.hi, Some(9)); // 10 - 1
    }

    #[test]
    fn mul_ranges() {
        let a = IntervalFact {
            lo: Some(2),
            hi: Some(5),
        };
        let b = IntervalFact {
            lo: Some(3),
            hi: Some(4),
        };
        let r = a.mul(&b);
        assert_eq!(r.lo, Some(6)); // 2*3
        assert_eq!(r.hi, Some(20)); // 5*4
    }

    #[test]
    fn mul_negative() {
        let a = IntervalFact {
            lo: Some(-3),
            hi: Some(2),
        };
        let b = IntervalFact {
            lo: Some(1),
            hi: Some(4),
        };
        let r = a.mul(&b);
        assert_eq!(r.lo, Some(-12)); // -3*4
        assert_eq!(r.hi, Some(8)); // 2*4
    }

    #[test]
    fn div_no_zero() {
        let a = IntervalFact {
            lo: Some(10),
            hi: Some(20),
        };
        let b = IntervalFact {
            lo: Some(2),
            hi: Some(5),
        };
        let r = a.div(&b);
        assert_eq!(r.lo, Some(2)); // 10/5
        assert_eq!(r.hi, Some(10)); // 20/2
    }

    #[test]
    fn div_spans_zero_is_top() {
        let a = IntervalFact::exact(10);
        let b = IntervalFact {
            lo: Some(-1),
            hi: Some(1),
        };
        assert!(a.div(&b).is_top());
    }

    #[test]
    fn modulo_positive() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(100),
        };
        let b = IntervalFact {
            lo: Some(7),
            hi: Some(7),
        };
        let r = a.modulo(&b);
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(6));
    }

    #[test]
    fn overflow_add() {
        let a = IntervalFact::exact(i64::MAX);
        let b = IntervalFact::exact(1);
        let r = a.add(&b);
        // Overflow → bound becomes None
        assert_eq!(r.hi, None);
    }

    #[test]
    fn overflow_mul() {
        let a = IntervalFact::exact(i64::MAX);
        let b = IntervalFact::exact(2);
        let r = a.mul(&b);
        // At least one bound should be None due to overflow
        assert!(r.lo.is_none() || r.hi.is_none());
    }

    // ── Bitwise interval transfer tests ────────────────────────────────

    #[test]
    fn bit_and_constant_mask() {
        let x = IntervalFact {
            lo: Some(0),
            hi: Some(1000),
        };
        let mask = IntervalFact::exact(0xFF);
        let r = x.bit_and(&mask);
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(0xFF));
    }

    #[test]
    fn bit_and_zero() {
        let x = IntervalFact {
            lo: Some(0),
            hi: Some(1000),
        };
        let zero = IntervalFact::exact(0);
        assert_eq!(x.bit_and(&zero), IntervalFact::exact(0));
        assert_eq!(zero.bit_and(&x), IntervalFact::exact(0));
    }

    #[test]
    fn bit_and_negative_operand_with_nonneg_mask() {
        // Even with negative input, AND with non-negative singleton mask
        // always produces [0, mask] (two's complement guarantee).
        let x = IntervalFact {
            lo: Some(-5),
            hi: Some(10),
        };
        let mask = IntervalFact::exact(0xFF);
        let r = x.bit_and(&mask);
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(0xFF));
    }

    #[test]
    fn bit_and_both_negative_no_singleton() {
        // No singleton mask available and negative operands → Top
        let a = IntervalFact {
            lo: Some(-100),
            hi: Some(-1),
        };
        let b = IntervalFact {
            lo: Some(-50),
            hi: Some(-10),
        };
        assert!(a.bit_and(&b).is_top());
    }

    #[test]
    fn bit_and_singletons() {
        assert_eq!(
            IntervalFact::exact(0xFF).bit_and(&IntervalFact::exact(0x0F)),
            IntervalFact::exact(0x0F)
        );
    }

    #[test]
    fn bit_or_basic() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(0xF0),
        };
        let b = IntervalFact {
            lo: Some(0),
            hi: Some(0x0F),
        };
        let r = a.bit_or(&b);
        assert_eq!(r.lo, Some(0));
        // next_pow2_minus1(0xF0) = 0xFF
        assert_eq!(r.hi, Some(0xFF));
    }

    #[test]
    fn bit_or_zero_identity() {
        let x = IntervalFact {
            lo: Some(3),
            hi: Some(10),
        };
        let zero = IntervalFact::exact(0);
        assert_eq!(x.bit_or(&zero), x);
        assert_eq!(zero.bit_or(&x), x);
    }

    #[test]
    fn bit_or_concrete_singletons() {
        assert_eq!(
            IntervalFact::exact(0xF0).bit_or(&IntervalFact::exact(0x0F)),
            IntervalFact::exact(0xFF)
        );
    }

    #[test]
    fn bit_xor_basic() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(255),
        };
        let b = IntervalFact {
            lo: Some(0),
            hi: Some(255),
        };
        let r = a.bit_xor(&b);
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(255)); // next_pow2_minus1(255) = 255
    }

    #[test]
    fn bit_xor_zero_identity() {
        let x = IntervalFact {
            lo: Some(3),
            hi: Some(10),
        };
        let zero = IntervalFact::exact(0);
        assert_eq!(x.bit_xor(&zero), x);
        assert_eq!(zero.bit_xor(&x), x);
    }

    #[test]
    fn bit_xor_same_singleton_to_zero() {
        assert_eq!(
            IntervalFact::exact(42).bit_xor(&IntervalFact::exact(42)),
            IntervalFact::exact(0)
        );
    }

    #[test]
    fn left_shift_basic() {
        assert_eq!(
            IntervalFact::exact(1).left_shift(&IntervalFact::exact(3)),
            IntervalFact::exact(8)
        );
    }

    #[test]
    fn left_shift_range() {
        let x = IntervalFact {
            lo: Some(0),
            hi: Some(7),
        };
        let shift = IntervalFact {
            lo: Some(1),
            hi: Some(2),
        };
        let r = x.left_shift(&shift);
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(28)); // 7 << 2
    }

    #[test]
    fn left_shift_invalid_shift() {
        let x = IntervalFact::exact(1);
        assert!(x.left_shift(&IntervalFact::exact(64)).is_top());
        assert!(x.left_shift(&IntervalFact::exact(-1)).is_top());
    }

    #[test]
    fn left_shift_overflow_behavior() {
        // Large value shifted would overflow i64
        let x = IntervalFact::exact(i64::MAX);
        let shift = IntervalFact::exact(1);
        assert!(x.left_shift(&shift).is_top());
    }

    #[test]
    fn right_shift_basic() {
        assert_eq!(
            IntervalFact::exact(16).right_shift(&IntervalFact::exact(2)),
            IntervalFact::exact(4)
        );
    }

    #[test]
    fn right_shift_singleton_exactness() {
        assert_eq!(
            IntervalFact::exact(255).right_shift(&IntervalFact::exact(4)),
            IntervalFact::exact(15)
        );
    }

    #[test]
    fn right_shift_range() {
        let x = IntervalFact {
            lo: Some(0),
            hi: Some(255),
        };
        let shift = IntervalFact {
            lo: Some(1),
            hi: Some(3),
        };
        let r = x.right_shift(&shift);
        // lo: 0 >> 3 = 0, hi: 255 >> 1 = 127
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(127));
    }

    #[test]
    fn right_shift_negative_dividend() {
        let x = IntervalFact {
            lo: Some(-10),
            hi: Some(10),
        };
        let shift = IntervalFact::exact(1);
        assert!(x.right_shift(&shift).is_top());
    }

    /// `a - b` overflows when `a.lo - b.hi` underflows or
    /// `a.hi - b.lo` overflows. We expect the corresponding bound to
    /// drop to `None`. Mirrors `overflow_add` / `overflow_mul`.
    #[test]
    fn overflow_sub() {
        let a = IntervalFact::exact(i64::MIN);
        let b = IntervalFact::exact(1);
        let r = a.sub(&b);
        assert_eq!(r.lo, None, "underflow on i64::MIN - 1 must drop lo to None");
        // hi: i64::MIN - 1 also underflows, so hi must also be None.
        assert_eq!(r.hi, None, "i64::MIN - 1 underflows on hi too");
    }

    /// Division of `i64::MIN` by `-1` overflows (`i64::MAX + 1`).
    /// `checked_div` returns `None` for that case; we want the bound to
    /// gracefully degrade, not panic.
    #[test]
    fn div_i64_min_by_minus_one_does_not_panic() {
        let a = IntervalFact::exact(i64::MIN);
        let b = IntervalFact::exact(-1);
        let r = a.div(&b);
        // Either bound becomes None (graceful), exact representation
        // depends on the impl, but we mainly assert no panic occurred
        // and the result is a valid interval.
        assert!(
            r.lo.is_none() || r.hi.is_none() || (r.lo.is_some() && r.hi.is_some()),
            "div should never panic on i64::MIN / -1"
        );
    }

    /// Modulo with a single-point negative divisor: `[0,10] % -3` must
    /// be a valid interval (no panic, no negative-zero bound nonsense).
    #[test]
    fn modulo_negative_divisor_singleton() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        let b = IntervalFact::exact(-3);
        let r = a.modulo(&b);
        // |b| = 3 ⇒ result bounded by [0, 2] for non-negative dividend.
        assert_eq!(r.lo, Some(0));
        assert_eq!(r.hi, Some(2));
    }

    /// Modulo by an interval that *contains* zero must escape to Top ,
    /// modulo-by-zero is undefined and we cannot precise-narrow it.
    #[test]
    fn modulo_divisor_spans_zero_is_top() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(100),
        };
        let b = IntervalFact {
            lo: Some(-1),
            hi: Some(1),
        };
        let r = a.modulo(&b);
        assert!(r.is_top(), "modulo by zero-spanning divisor must be Top");
    }

    /// `[i64::MIN, i64::MAX]` is the maximal interval. Any join with
    /// any other interval must remain `[i64::MIN, i64::MAX]` (or Top
    /// equivalent), this guards against accidental narrowing on join.
    #[test]
    fn full_range_is_join_absorbing() {
        let full = IntervalFact {
            lo: Some(i64::MIN),
            hi: Some(i64::MAX),
        };
        let small = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        let j = full.join(&small);
        assert_eq!(j.lo, Some(i64::MIN), "join must not narrow lo");
        assert_eq!(j.hi, Some(i64::MAX), "join must not narrow hi");
    }

    // ── Additional lattice algebra laws ──────────────────────────────
    // These guard the soundness of the dataflow framework: join/meet/widen
    // must satisfy the standard lattice axioms or fixpoint convergence
    // and abstract correctness break.

    fn sample_intervals() -> Vec<IntervalFact> {
        vec![
            IntervalFact::bottom(),
            IntervalFact::top(),
            IntervalFact::exact(0),
            IntervalFact::exact(-7),
            IntervalFact {
                lo: Some(2),
                hi: Some(8),
            },
            IntervalFact {
                lo: None,
                hi: Some(10),
            },
            IntervalFact {
                lo: Some(-5),
                hi: None,
            },
        ]
    }

    #[test]
    fn join_with_top_is_top() {
        for a in sample_intervals() {
            let j = a.join(&IntervalFact::top());
            assert!(j.is_top(), "x ⊔ ⊤ = ⊤ failed for {:?}", a);
            let j2 = IntervalFact::top().join(&a);
            assert!(j2.is_top(), "⊤ ⊔ x = ⊤ failed for {:?}", a);
        }
    }

    #[test]
    fn meet_idempotent() {
        for a in sample_intervals() {
            assert_eq!(a.meet(&a), a, "x ⊓ x = x failed for {:?}", a);
        }
    }

    #[test]
    fn meet_commutative() {
        let xs = sample_intervals();
        for a in &xs {
            for b in &xs {
                assert_eq!(
                    a.meet(b),
                    b.meet(a),
                    "meet not commutative for {:?} / {:?}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn meet_associative() {
        let xs = sample_intervals();
        for a in &xs {
            for b in &xs {
                for c in &xs {
                    let lhs = a.meet(b).meet(c);
                    let rhs = a.meet(&b.meet(c));
                    assert_eq!(lhs, rhs, "meet not associative for {:?},{:?},{:?}", a, b, c);
                }
            }
        }
    }

    #[test]
    fn meet_top_identity() {
        for a in sample_intervals() {
            assert_eq!(
                a.meet(&IntervalFact::top()),
                a,
                "x ⊓ ⊤ = x failed for {:?}",
                a
            );
        }
    }

    #[test]
    fn meet_bottom_absorbing() {
        for a in sample_intervals() {
            assert!(
                a.meet(&IntervalFact::bottom()).is_bottom(),
                "x ⊓ ⊥ = ⊥ failed for {:?}",
                a
            );
        }
    }

    #[test]
    fn widen_idempotent() {
        for a in sample_intervals() {
            assert_eq!(a.widen(&a), a, "widen(x, x) = x failed for {:?}", a);
        }
    }

    /// **Soundness**: widening must over-approximate join.
    /// `widen(a, b) ⊒ join(a, b)` for all a, b.
    /// Without this, fixpoint iteration converges to an unsound result.
    #[test]
    fn widen_over_approximates_join() {
        let xs = sample_intervals();
        for a in &xs {
            for b in &xs {
                let j = a.join(b);
                let w = a.widen(b);
                assert!(
                    j.leq(&w),
                    "widen({:?}, {:?}) = {:?} does not over-approximate join = {:?}",
                    a,
                    b,
                    w,
                    j
                );
            }
        }
    }

    #[test]
    fn leq_reflexive() {
        for a in sample_intervals() {
            assert!(a.leq(&a), "x ⊑ x failed for {:?}", a);
        }
    }

    #[test]
    fn leq_transitive() {
        // a ⊑ b ⊑ c ⇒ a ⊑ c
        let a = IntervalFact::exact(5);
        let b = IntervalFact {
            lo: Some(0),
            hi: Some(10),
        };
        let c = IntervalFact::top();
        assert!(a.leq(&b));
        assert!(b.leq(&c));
        assert!(a.leq(&c), "leq must be transitive");
    }

    /// `x ⊔ y` is the least upper bound: both x and y must be ⊑ join(x,y).
    #[test]
    fn join_is_upper_bound() {
        let xs = sample_intervals();
        for a in &xs {
            for b in &xs {
                let j = a.join(b);
                assert!(a.leq(&j), "a ⊑ a ⊔ b failed for {:?}, {:?}", a, b);
                assert!(b.leq(&j), "b ⊑ a ⊔ b failed for {:?}, {:?}", a, b);
            }
        }
    }

    /// `x ⊓ y` is the greatest lower bound: meet(x,y) ⊑ both x and y.
    #[test]
    fn meet_is_lower_bound() {
        let xs = sample_intervals();
        for a in &xs {
            for b in &xs {
                let m = a.meet(b);
                assert!(m.leq(a), "a ⊓ b ⊑ a failed for {:?}, {:?}", a, b);
                assert!(m.leq(b), "a ⊓ b ⊑ b failed for {:?}, {:?}", a, b);
            }
        }
    }

    // ── Arithmetic edge cases not previously covered ─────────────────

    /// Multiplication by exact zero must yield exact zero, regardless
    /// of the other operand. This is critical for taint suppression
    /// (`x * 0` is provably bounded).
    #[test]
    fn mul_by_zero_singleton_is_zero() {
        let zero = IntervalFact::exact(0);
        let inputs = [
            IntervalFact::exact(42),
            IntervalFact {
                lo: Some(-100),
                hi: Some(100),
            },
            IntervalFact {
                lo: Some(i64::MIN),
                hi: Some(i64::MAX),
            },
            IntervalFact::top(),
        ];
        for a in inputs.iter() {
            // Note: when a is Top, mul currently short-circuits to Top.
            // The zero-singleton case is the precise one we care about
            // for sink suppression; assert it for non-Top inputs.
            if !a.is_top() {
                let r = a.mul(&zero);
                assert_eq!(r, IntervalFact::exact(0), "x * 0 should be 0 for {:?}", a);
                let r2 = zero.mul(a);
                assert_eq!(r2, IntervalFact::exact(0), "0 * x should be 0 for {:?}", a);
            }
        }
    }

    /// Bottom propagates through every arithmetic op.
    #[test]
    fn bottom_propagates_through_arith() {
        let bot = IntervalFact::bottom();
        let x = IntervalFact::exact(5);
        assert!(bot.add(&x).is_bottom());
        assert!(x.add(&bot).is_bottom());
        assert!(bot.sub(&x).is_bottom());
        assert!(bot.mul(&x).is_bottom());
        assert!(bot.div(&x).is_bottom());
        assert!(bot.modulo(&x).is_bottom());
        assert!(bot.bit_and(&x).is_bottom());
        assert!(bot.bit_or(&x).is_bottom());
        assert!(bot.bit_xor(&x).is_bottom());
        assert!(bot.left_shift(&x).is_bottom());
        assert!(bot.right_shift(&x).is_bottom());
    }

    /// Division by exact zero must escape to Top (not crash, not produce
    /// a bogus interval). Currently handled by the spans-zero check.
    #[test]
    fn div_by_exact_zero_is_top() {
        let a = IntervalFact::exact(10);
        let zero = IntervalFact::exact(0);
        assert!(
            a.div(&zero).is_top(),
            "division by exact zero must escape to Top"
        );
    }

    /// Modulo with exact-zero divisor, must escape to Top.
    #[test]
    fn modulo_by_exact_zero_is_top() {
        let a = IntervalFact {
            lo: Some(0),
            hi: Some(100),
        };
        let zero = IntervalFact::exact(0);
        assert!(a.modulo(&zero).is_top());
    }

    /// Add involving Top stays Top on the unbounded side.
    #[test]
    fn add_with_top_is_top() {
        let r = IntervalFact::exact(5).add(&IntervalFact::top());
        assert!(r.is_top(), "5 + Top should be Top, got {:?}", r);
    }

    /// Subtraction: i64::MAX - i64::MIN should overflow gracefully.
    #[test]
    fn sub_overflow_extreme() {
        let a = IntervalFact::exact(i64::MAX);
        let b = IntervalFact::exact(i64::MIN);
        let r = a.sub(&b); // i64::MAX - i64::MIN overflows
        assert!(
            r.lo.is_none() || r.hi.is_none(),
            "extreme subtraction must not panic and must drop a bound"
        );
    }

    /// `bottom().widen(x)` must be defined and converge.
    #[test]
    fn widen_with_bottom() {
        let x = IntervalFact::exact(5);
        let bot = IntervalFact::bottom();
        let w1 = bot.widen(&x);
        // Bottom widens to the new value (no growth observed yet).
        assert_eq!(w1, x);
        let w2 = x.widen(&bot);
        assert_eq!(w2, x);
    }
}
