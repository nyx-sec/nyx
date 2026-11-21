use crate::labels::{Cap, SourceKind};
use crate::taint::path_state::PredicateKind;
use petgraph::graph::NodeIndex;
use smallvec::SmallVec;

/// Per-variable taint information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarTaint {
    pub caps: Cap,
    /// Up to N origins that contributed taint (bounded).
    pub origins: SmallVec<[TaintOrigin; 2]>,
    /// Whether taint propagated through a function summary (cross-function).
    pub uses_summary: bool,
}

/// A single taint origin, the node and classification of where taint came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaintOrigin {
    pub node: NodeIndex,
    pub source_kind: SourceKind,
    /// Original source byte span, preserved when origin is remapped across
    /// body boundaries.  `None` for intra-body origins (span can be looked
    /// up from `cfg[node].span`).  `Some` for cross-body origins where
    /// `node` has been remapped to a body-local anchor.
    pub source_span: Option<(usize, usize)>,
}

/// Compact bitset for up to 64 variables (indexed by SymbolId ordinal).
///
/// # Capacity limit
///
/// `SmallBitSet` is a fixed-size 64-slot bitset backed by a single `u64`.
/// Inserting a `SymbolId` with ordinal ≥ 64 is a no-op, the bit is silently
/// dropped. This is a deliberate precision-over-completeness trade: the
/// bitset underpins predicate / validation tracking in the SSA taint engine,
/// and functions with more than 64 distinct predicate-relevant variables are
/// rare enough that the cost of a spill-out map is not worth the extra
/// allocations on the common path.
///
/// When an out-of-range id is dropped, a `tracing::debug!` event is emitted
/// under `target = "nyx::predicate_bitset"` so operators can detect the
/// degraded-precision case. Path-sensitivity for variables beyond id 63
/// degrades gracefully (no predicate bit recorded) rather than failing
/// loudly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallBitSet(u64);

impl SmallBitSet {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn insert(&mut self, id: crate::state::symbol::SymbolId) {
        let idx = id.0;
        if idx < 64 {
            self.0 |= 1u64 << idx;
        } else {
            tracing::debug!(
                target: "nyx::predicate_bitset",
                id = idx,
                "SmallBitSet: dropped id >= 64; path-sensitivity degrades for this variable"
            );
        }
    }

    pub fn contains(&self, id: crate::state::symbol::SymbolId) -> bool {
        let idx = id.0;
        if idx < 64 {
            self.0 & (1u64 << idx) != 0
        } else {
            false
        }
    }

    pub fn remove(&mut self, id: crate::state::symbol::SymbolId) {
        let idx = id.0;
        if idx < 64 {
            self.0 &= !(1u64 << idx);
        }
    }

    /// Union: self | other
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection: self & other
    pub fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether self is a subset of other.
    pub fn is_subset_of(self, other: Self) -> bool {
        self.0 & other.0 == self.0
    }

    /// Whether self is a superset of other.
    pub fn is_superset_of(self, other: Self) -> bool {
        other.is_subset_of(self)
    }

    /// Raw bits for serialization/debug display.
    pub fn bits(self) -> u64 {
        self.0
    }
}

/// Monotone predicate summary per variable.
///
/// Tracks which whitelisted predicate kinds are known true/false on ALL paths.
/// join = intersection of bits (must-hold semantics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PredicateSummary {
    /// Bitmask: bit 0=NullCheck, 1=EmptyCheck, 2=ErrorCheck,
    /// 3=LeadingSlashCheck, 4=ProtocolRelativeCheck
    pub known_true: u8,
    pub known_false: u8,
}

impl PredicateSummary {
    pub fn empty() -> Self {
        Self {
            known_true: 0,
            known_false: 0,
        }
    }

    /// Join = intersection (only predicates true on ALL paths).
    pub fn join(self, other: Self) -> Self {
        Self {
            known_true: self.known_true & other.known_true,
            known_false: self.known_false & other.known_false,
        }
    }

    /// Check for contradiction: same kind known both true and false.
    pub fn has_contradiction(self) -> bool {
        self.known_true & self.known_false != 0
    }

    pub fn is_empty(self) -> bool {
        self.known_true == 0 && self.known_false == 0
    }
}

/// [`PredicateKind::LeadingSlashCheck`] bit.
pub const PRED_BIT_LEADING_SLASH: u8 = 3;
/// [`PredicateKind::ProtocolRelativeCheck`] bit.
pub const PRED_BIT_PROTOCOL_RELATIVE: u8 = 4;
/// Bits that take part in function summaries and caller/callee path
/// compatibility.  The URL-shape bits only pair up within one body to
/// decide an OPEN_REDIRECT clear, and are masked out of everything
/// interprocedural.
pub const INTERPROC_PREDICATE_BITS: u8 = 0b0000_0111;

/// Map a whitelisted PredicateKind to its bit index (0-4).
/// Returns None for non-whitelisted kinds.
pub fn predicate_kind_bit(kind: PredicateKind) -> Option<u8> {
    match kind {
        PredicateKind::NullCheck => Some(0),
        PredicateKind::EmptyCheck => Some(1),
        PredicateKind::ErrorCheck => Some(2),
        PredicateKind::LeadingSlashCheck => Some(PRED_BIT_LEADING_SLASH),
        PredicateKind::ProtocolRelativeCheck => Some(PRED_BIT_PROTOCOL_RELATIVE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::symbol::SymbolId;

    // ── SmallBitSet tests ───────────────────────────────────────────────

    #[test]
    fn small_bitset_basic() {
        let mut bs = SmallBitSet::empty();
        assert!(bs.is_empty());

        bs.insert(SymbolId(0));
        assert!(bs.contains(SymbolId(0)));
        assert!(!bs.contains(SymbolId(1)));
        assert!(!bs.is_empty());
    }

    #[test]
    fn small_bitset_union_intersection() {
        let mut a = SmallBitSet::empty();
        a.insert(SymbolId(0));
        a.insert(SymbolId(2));

        let mut b = SmallBitSet::empty();
        b.insert(SymbolId(1));
        b.insert(SymbolId(2));

        let u = a.union(b);
        assert!(u.contains(SymbolId(0)));
        assert!(u.contains(SymbolId(1)));
        assert!(u.contains(SymbolId(2)));

        let i = a.intersection(b);
        assert!(!i.contains(SymbolId(0)));
        assert!(!i.contains(SymbolId(1)));
        assert!(i.contains(SymbolId(2)));
    }

    // ── PredicateSummary tests ──────────────────────────────────────────

    #[test]
    fn predicate_contradiction() {
        let s = PredicateSummary {
            known_true: 1,  // NullCheck true
            known_false: 1, // NullCheck false
        };
        assert!(s.has_contradiction());
    }

    #[test]
    fn predicate_no_contradiction() {
        let s = PredicateSummary {
            known_true: 1,  // NullCheck true
            known_false: 2, // EmptyCheck false (different kind)
        };
        assert!(!s.has_contradiction());
    }

    #[test]
    fn predicate_join_intersection() {
        let a = PredicateSummary {
            known_true: 0b011, // NullCheck + EmptyCheck
            known_false: 0,
        };
        let b = PredicateSummary {
            known_true: 0b010, // EmptyCheck only
            known_false: 0,
        };
        let joined = a.join(b);
        assert_eq!(joined.known_true, 0b010); // only EmptyCheck on both paths
    }
}
