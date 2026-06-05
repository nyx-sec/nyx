/// A bounded semi-lattice with bottom element and monotone join.
///
/// Implementations must satisfy:
/// - `join` is commutative, associative, and idempotent
/// - `bot()` is the identity for `join`
/// - `leq(a, b)` iff `join(a, b) == b`
pub trait Lattice: Clone + Eq + Sized {
    /// Bottom element (least information / unreachable).
    fn bot() -> Self;

    /// Least upper bound: merge two abstract values.
    fn join(&self, other: &Self) -> Self;

    /// Partial order: `self ⊑ other`.
    fn leq(&self, other: &Self) -> bool;
}

/// Full abstract domain with widening and top element.
///
/// Extends [`Lattice`] with operations required for abstract interpretation:
/// - `top()`: maximally imprecise element (no information)
/// - `meet()`: greatest lower bound (refine with new info)
/// - `widen()`: extrapolation operator ensuring termination
///
/// Implementations must satisfy:
/// - `top()` is the greatest element: `leq(x, top()) == true` for all x
/// - `meet(a, b) ⊑ a` and `meet(a, b) ⊑ b`
/// - `widen(a, b) ⊒ join(a, b)` (widening is at least as imprecise as join)
/// - Ascending chains under `widen` stabilize in finite steps
pub trait AbstractDomain: Lattice {
    /// Top element (no information / maximally imprecise).
    fn top() -> Self;

    /// Greatest lower bound: refine with new information.
    fn meet(&self, other: &Self) -> Self;

    /// Widening: extrapolate to ensure termination of ascending chains.
    fn widen(&self, other: &Self) -> Self;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial 3-element lattice for testing the trait contract.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Three(u8); // 0=bot, 1, 2=top-ish

    impl Lattice for Three {
        fn bot() -> Self {
            Three(0)
        }
        fn join(&self, other: &Self) -> Self {
            Three(self.0.max(other.0))
        }
        fn leq(&self, other: &Self) -> bool {
            self.0 <= other.0
        }
    }

    #[test]
    fn bot_identity() {
        let a = Three(1);
        assert_eq!(a.join(&Three::bot()), a);
        assert_eq!(Three::bot().join(&a), a);
    }

    #[test]
    fn join_commutative() {
        let a = Three(1);
        let b = Three(2);
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_associative() {
        let a = Three(0);
        let b = Three(1);
        let c = Three(2);
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn join_idempotent() {
        let a = Three(1);
        assert_eq!(a.join(&a), a);
    }

    #[test]
    fn leq_reflexive() {
        let a = Three(1);
        assert!(a.leq(&a));
    }

    #[test]
    fn leq_transitive() {
        let a = Three(0);
        let b = Three(1);
        let c = Three(2);
        assert!(a.leq(&b));
        assert!(b.leq(&c));
        assert!(a.leq(&c));
    }

    #[test]
    fn leq_consistent_with_join() {
        let a = Three(1);
        let b = Three(2);
        // a ⊑ b iff join(a, b) == b
        assert!(a.leq(&b));
        assert_eq!(a.join(&b), b);
    }
}
