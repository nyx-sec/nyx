//! Per-value abstract domain for path constraint solving.
//!
//! This module defines the core abstract elements used by the constraint solver:
//! - [`ConstValue`]: constants we can reason about (Int, Str, Bool, Null)
//! - [`TypeSet`]: bitset over [`TypeKind`] variants
//! - [`Nullability`] / [`BoolState`]: small lattices for null and boolean state
//! - [`ValueFact`]: per-SSA-value abstract element combining all of the above
//! - [`UnionFind`]: equality class tracking for SSA values
//! - [`PathEnv`]: constraint environment mapping SSA values to value facts

use crate::ssa::const_prop::ConstLattice;
use crate::ssa::ir::SsaValue;
use crate::ssa::type_facts::{TypeFactResult, TypeKind};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;

// ── Performance bounds ──────────────────────────────────────────────────

/// Maximum entries in the path environment.
pub const MAX_PATH_ENV_ENTRIES: usize = 64;
/// Maximum equality edges tracked in the union-find.
pub const MAX_EQUALITY_EDGES: usize = 32;
/// Maximum disequality pairs tracked.
pub const MAX_DISEQUALITY_EDGES: usize = 32;
/// Maximum refinement operations per block before stopping (conservative).
pub const MAX_REFINE_PER_BLOCK: usize = 128;
/// After this many meets on the same key, apply widening.
pub const WIDEN_THRESHOLD: u8 = 3;
/// Maximum relational constraints tracked (a < b, a <= b).
pub const MAX_RELATIONAL: usize = 16;
/// Maximum excluded constants per value (Neq set bound).
const MAX_NEQ: usize = 8;

// ── Relational operator ────────────────────────────────────────────────

/// Relational operator for value-vs-value constraints.
///
/// Only strict/non-strict less-than. Greater-than variants are normalized
/// by flipping operands at the solver level (CompOp::Gt → assert_relational(b, Lt, a)).
/// Equality is handled by [`UnionFind`]; disequality by the `disequalities` set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelOp {
    /// Strict less-than: `a < b`
    Lt,
    /// Non-strict less-than-or-equal: `a <= b`
    Le,
}

// ── ConstValue ──────────────────────────────────────────────────────────

/// A constant value that the constraint solver can reason about.
///
/// Cross-language normalization:
/// - JS `undefined` → `Null` (both are nullish)
/// - Python `None` → `Null`
/// - Go `nil` → `Null`
/// - Empty string / zero / false → distinct from `Null`
/// - Floats → not modeled in V1 (fall through to `None` in parse)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstValue {
    Int(i64),
    Str(String),
    Bool(bool),
    Null,
}

impl ConstValue {
    /// Convert from SSA constant propagation lattice.
    pub fn from_const_lattice(cl: &ConstLattice) -> Option<Self> {
        match cl {
            ConstLattice::Int(i) => Some(ConstValue::Int(*i)),
            ConstLattice::Str(s) => Some(ConstValue::Str(s.clone())),
            ConstLattice::Bool(b) => Some(ConstValue::Bool(*b)),
            ConstLattice::Null => Some(ConstValue::Null),
            ConstLattice::Top | ConstLattice::Varying => None,
        }
    }

    /// Parse a raw literal text into a ConstValue.
    pub fn parse_literal(text: &str) -> Option<Self> {
        let t = text.trim();
        if t.is_empty() {
            return None;
        }
        // Null variants
        if t == "null" || t == "nil" || t == "None" || t == "undefined" || t == "NULL" {
            return Some(ConstValue::Null);
        }
        // Boolean
        if t == "true" || t == "True" || t == "TRUE" {
            return Some(ConstValue::Bool(true));
        }
        if t == "false" || t == "False" || t == "FALSE" {
            return Some(ConstValue::Bool(false));
        }
        // Quoted string
        if t.len() >= 2
            && ((t.starts_with('"') && t.ends_with('"'))
                || (t.starts_with('\'') && t.ends_with('\''))
                || (t.starts_with('`') && t.ends_with('`')))
        {
            return Some(ConstValue::Str(t[1..t.len() - 1].to_string()));
        }
        // Integer (including negative)
        if let Ok(i) = t.parse::<i64>() {
            return Some(ConstValue::Int(i));
        }
        // Negative with space: "- 5", not supported, conservative
        None
    }
}

// ── TypeSet ─────────────────────────────────────────────────────────────

/// Bitset over [`TypeKind`] variants (19 bits used of u32).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TypeSet(u32);

impl TypeSet {
    /// All 19 type bits set, no type constraint (Top).
    pub const TOP: Self = Self(0x0007_FFFF);
    /// No type bits, unsatisfiable (Bottom).
    pub const BOTTOM: Self = Self(0);

    pub fn singleton(kind: &TypeKind) -> Self {
        Self(1u32 << type_kind_index(kind))
    }

    pub fn contains(&self, kind: &TypeKind) -> bool {
        self.0 & (1u32 << type_kind_index(kind)) != 0
    }

    /// Meet (intersection): refine type knowledge.
    pub fn meet(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Join (union): merge at CFG merge point.
    pub fn join(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn is_bottom(self) -> bool {
        self.0 == 0
    }

    pub fn is_top(self) -> bool {
        self == Self::TOP
    }

    /// Complement, all types NOT in this set.
    pub fn complement(self) -> Self {
        Self(!self.0 & Self::TOP.0)
    }

    /// Check if this set contains exactly one type matching the given kind.
    pub fn is_singleton_of(&self, kind: &TypeKind) -> bool {
        self.0 != 0 && self.0 == (1u32 << type_kind_index(kind))
    }

    /// Return the TypeKind if this is a singleton set (exactly one type).
    pub fn as_singleton(&self) -> Option<TypeKind> {
        if self.0 != 0 && self.0.count_ones() == 1 {
            type_kind_from_index(self.0.trailing_zeros())
        } else {
            None
        }
    }
}

fn type_kind_index(kind: &TypeKind) -> u32 {
    match kind {
        TypeKind::String => 0,
        TypeKind::Int => 1,
        TypeKind::Bool => 2,
        TypeKind::Object => 3,
        TypeKind::Array => 4,
        TypeKind::Null => 5,
        TypeKind::Unknown => 6,
        TypeKind::HttpResponse => 7,
        TypeKind::DatabaseConnection => 8,
        TypeKind::FileHandle => 9,
        TypeKind::Url => 10,
        TypeKind::HttpClient => 11,
        TypeKind::LocalCollection => 12,
        TypeKind::RequestBuilder => 13,
        TypeKind::JpaCriteriaQuery => 14,
        TypeKind::LdapClient => 15,
        TypeKind::XPathClient => 16,
        TypeKind::XmlParser => 17,
        TypeKind::Template => 18,
        // the analysis DTO types carry per-field structural info that the
        // bitset domain can't represent.  Collapse to Unknown so callers
        // still see "any type possible" rather than crashing on an
        // unhandled variant.  Same-file/cross-file Dto-aware paths read
        // the structured TypeKind directly, not via this index.
        TypeKind::Dto(_) => 6,
        // NullPrototypeObject is a JS-only sub-kind of Object used for
        // flow-sensitive prototype-pollution suppression.  The bitset
        // domain has no dedicated slot, share the Object index so
        // singleton recovery still maps to a meaningful TypeKind.
        TypeKind::NullPrototypeObject => 3,
        // FileSystemPromisesNs is a JS-only namespace receiver type used
        // by the Phase 05 fs/promises sink resolver. The bitset domain
        // has no dedicated slot; share the Object index so singleton
        // recovery still hands back a usable TypeKind.
        TypeKind::FileSystemPromisesNs => 3,
        // Phase 07 ORM receiver TypeKinds. They participate only in the
        // type-qualified callee resolver via their `label_prefix()`; the
        // bitset domain's flow-sensitive narrowing has no dedicated slot
        // for them, so collapse to Object (3). Singleton recovery from
        // the index will hand back `Object`, which is a benign upper
        // bound for the ORM receiver shapes.
        TypeKind::Sequelize
        | TypeKind::TypeOrmRepo
        | TypeKind::TypeOrmManager
        | TypeKind::MikroOrmEm => 3,
        // Phase 10 — `Request` is a Web-platform receiver type used
        // by the App Router entry-point seeding path; it shares the
        // Object slot for the same reason the ORM TypeKinds do.
        TypeKind::Request => 3,
    }
}

fn type_kind_from_index(idx: u32) -> Option<TypeKind> {
    match idx {
        0 => Some(TypeKind::String),
        1 => Some(TypeKind::Int),
        2 => Some(TypeKind::Bool),
        3 => Some(TypeKind::Object),
        4 => Some(TypeKind::Array),
        5 => Some(TypeKind::Null),
        6 => Some(TypeKind::Unknown),
        7 => Some(TypeKind::HttpResponse),
        8 => Some(TypeKind::DatabaseConnection),
        9 => Some(TypeKind::FileHandle),
        10 => Some(TypeKind::Url),
        11 => Some(TypeKind::HttpClient),
        12 => Some(TypeKind::LocalCollection),
        13 => Some(TypeKind::RequestBuilder),
        14 => Some(TypeKind::JpaCriteriaQuery),
        15 => Some(TypeKind::LdapClient),
        16 => Some(TypeKind::XPathClient),
        17 => Some(TypeKind::XmlParser),
        18 => Some(TypeKind::Template),
        _ => None,
    }
}

// ── Nullability ─────────────────────────────────────────────────────────

/// Nullability lattice for an SSA value.
///
/// ```text
///       Unknown  (Top)
///       /     \
///    Null    NonNull
///       \     /
///       Bottom
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Nullability {
    /// No information.
    Unknown,
    /// Definitely null.
    Null,
    /// Definitely not null.
    NonNull,
    /// Contradictory (bottom).
    Bottom,
}

impl Nullability {
    /// Meet (intersection / refine).
    pub fn meet(self, other: Self) -> Self {
        use Nullability::*;
        match (self, other) {
            (Bottom, _) | (_, Bottom) => Bottom,
            (Unknown, x) | (x, Unknown) => x,
            (Null, Null) => Null,
            (NonNull, NonNull) => NonNull,
            (Null, NonNull) | (NonNull, Null) => Bottom,
        }
    }

    /// Join (union / merge at CFG join).
    pub fn join(self, other: Self) -> Self {
        use Nullability::*;
        match (self, other) {
            (Bottom, x) | (x, Bottom) => x,
            (Unknown, _) | (_, Unknown) => Unknown,
            (Null, Null) => Null,
            (NonNull, NonNull) => NonNull,
            (Null, NonNull) | (NonNull, Null) => Unknown,
        }
    }

    /// Negate: Null ↔ NonNull.
    pub fn negate(self) -> Self {
        match self {
            Self::Null => Self::NonNull,
            Self::NonNull => Self::Null,
            other => other,
        }
    }
}

// ── BoolState ───────────────────────────────────────────────────────────

/// Boolean state lattice.
///
/// Same shape as [`Nullability`]. No `negate()`, negation is structural
/// on [`ConditionExpr`](super::lower::ConditionExpr).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BoolState {
    Unknown,
    True,
    False,
    Bottom,
}

impl BoolState {
    pub fn meet(self, other: Self) -> Self {
        use BoolState::*;
        match (self, other) {
            (Bottom, _) | (_, Bottom) => Bottom,
            (Unknown, x) | (x, Unknown) => x,
            (True, True) => True,
            (False, False) => False,
            (True, False) | (False, True) => Bottom,
        }
    }

    pub fn join(self, other: Self) -> Self {
        use BoolState::*;
        match (self, other) {
            (Bottom, x) | (x, Bottom) => x,
            (Unknown, _) | (_, Unknown) => Unknown,
            (True, True) => True,
            (False, False) => False,
            (True, False) | (False, True) => Unknown,
        }
    }
}

// ── ValueFact ───────────────────────────────────────────────────────────

/// Abstract fact about a single SSA value.
///
/// Combines interval, constant, type, null, and boolean constraints.
/// There is intentionally no generic `negate()` on ValueFact, negation
/// is structural on [`ConditionExpr`](super::lower::ConditionExpr) and
/// then applied as atomic refinements by the solver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueFact {
    /// Exact known constant (Eq constraint). `None` = unconstrained.
    pub exact: Option<ConstValue>,
    /// Excluded constant values (Neq constraints). Bounded by `MAX_NEQ`.
    pub excluded: SmallVec<[ConstValue; 4]>,
    /// Inclusive lower bound (`None` = −∞).
    pub lo: Option<i64>,
    /// Inclusive upper bound (`None` = +∞).
    pub hi: Option<i64>,
    /// Whether lower bound is strict (exclusive).
    pub lo_strict: bool,
    /// Whether upper bound is strict (exclusive).
    pub hi_strict: bool,
    /// Nullability state.
    pub null: Nullability,
    /// Boolean state.
    pub bool_state: BoolState,
    /// Possible runtime types (bitset).
    pub types: TypeSet,
}

impl ValueFact {
    /// Top: no constraints (maximally permissive).
    pub fn top() -> Self {
        Self {
            exact: None,
            excluded: SmallVec::new(),
            lo: None,
            hi: None,
            lo_strict: false,
            hi_strict: false,
            null: Nullability::Unknown,
            bool_state: BoolState::Unknown,
            types: TypeSet::TOP,
        }
    }

    /// Bottom: unsatisfiable.
    pub fn bottom() -> Self {
        Self {
            exact: None,
            excluded: SmallVec::new(),
            lo: None,
            hi: None,
            lo_strict: false,
            hi_strict: false,
            null: Nullability::Bottom,
            bool_state: BoolState::Bottom,
            types: TypeSet::BOTTOM,
        }
    }

    /// Check if this fact is unsatisfiable.
    pub fn is_bottom(&self) -> bool {
        self.types.is_bottom()
            || self.null == Nullability::Bottom
            || self.bool_state == BoolState::Bottom
            || self.interval_empty()
            || self.exact_excluded_contradiction()
    }

    /// Check if this fact is Top (no constraints).
    pub fn is_top(&self) -> bool {
        self.exact.is_none()
            && self.excluded.is_empty()
            && self.lo.is_none()
            && self.hi.is_none()
            && self.null == Nullability::Unknown
            && self.bool_state == BoolState::Unknown
            && self.types.is_top()
    }

    fn interval_empty(&self) -> bool {
        match (self.lo, self.hi) {
            (Some(lo), Some(hi)) => {
                if self.lo_strict || self.hi_strict {
                    lo >= hi
                } else {
                    lo > hi
                }
            }
            _ => false,
        }
    }

    fn exact_excluded_contradiction(&self) -> bool {
        if let Some(ref exact) = self.exact {
            self.excluded.contains(exact)
        } else {
            false
        }
    }

    /// Meet (refine / AND semantics): tighten with new information.
    pub fn meet(&self, other: &Self) -> Self {
        // Exact: both must agree, or take the one that's set
        let exact = match (&self.exact, &other.exact) {
            (Some(a), Some(b)) => {
                if a == b {
                    Some(a.clone())
                } else {
                    return Self::bottom();
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };

        // Excluded: union of both sets
        let mut excluded = self.excluded.clone();
        for v in &other.excluded {
            if excluded.len() >= MAX_NEQ {
                break;
            }
            if !excluded.contains(v) {
                excluded.push(v.clone());
            }
        }

        // Interval: tightest bounds
        let (lo, lo_strict) = tighten_lower(self.lo, self.lo_strict, other.lo, other.lo_strict);
        let (hi, hi_strict) = tighten_upper(self.hi, self.hi_strict, other.hi, other.hi_strict);

        let null = self.null.meet(other.null);
        let bool_state = self.bool_state.meet(other.bool_state);
        let types = self.types.meet(other.types);

        let result = Self {
            exact,
            excluded,
            lo,
            hi,
            lo_strict,
            hi_strict,
            null,
            bool_state,
            types,
        };

        // Final consistency check
        if result.is_bottom() {
            Self::bottom()
        } else {
            result
        }
    }

    /// Join (merge / OR semantics): conservative merge at CFG join.
    ///
    /// Preserves information true on BOTH paths. For example,
    /// `[x > 0].join([x > 5])` = `[x > 0]` (not Top).
    pub fn join(&self, other: &Self) -> Self {
        // Exact: only if both agree
        let exact = match (&self.exact, &other.exact) {
            (Some(a), Some(b)) if a == b => Some(a.clone()),
            _ => None,
        };

        // Excluded: intersection (only exclude what BOTH paths exclude)
        let excluded: SmallVec<[ConstValue; 4]> = self
            .excluded
            .iter()
            .filter(|v| other.excluded.contains(v))
            .cloned()
            .collect();

        // Interval: hull (weakest bounds)
        let (lo, lo_strict) = widen_lower(self.lo, self.lo_strict, other.lo, other.lo_strict);
        let (hi, hi_strict) = widen_upper(self.hi, self.hi_strict, other.hi, other.hi_strict);

        let null = self.null.join(other.null);
        let bool_state = self.bool_state.join(other.bool_state);
        let types = self.types.join(other.types);

        Self {
            exact,
            excluded,
            lo,
            hi,
            lo_strict,
            hi_strict,
            null,
            bool_state,
            types,
        }
    }

    /// Widen: accelerate convergence for loop-carried facts.
    ///
    /// Drops interval bounds that changed between iterations.
    /// Finite domains (null, bool, types) use normal join.
    pub fn widen(&self, other: &Self) -> Self {
        // If bounds changed, drop them
        let lo = if self.lo == other.lo && self.lo_strict == other.lo_strict {
            self.lo
        } else {
            None
        };
        let lo_strict = if lo.is_some() { self.lo_strict } else { false };

        let hi = if self.hi == other.hi && self.hi_strict == other.hi_strict {
            self.hi
        } else {
            None
        };
        let hi_strict = if hi.is_some() { self.hi_strict } else { false };

        // Exact: only if stable
        let exact = if self.exact == other.exact {
            self.exact.clone()
        } else {
            None
        };

        // Excluded: if set grew, clear (conservative)
        let excluded = if self.excluded.len() <= other.excluded.len()
            && self.excluded.iter().all(|v| other.excluded.contains(v))
        {
            other.excluded.clone()
        } else {
            SmallVec::new()
        };

        // Finite domains: normal join
        let null = self.null.join(other.null);
        let bool_state = self.bool_state.join(other.bool_state);
        let types = self.types.join(other.types);

        Self {
            exact,
            excluded,
            lo,
            hi,
            lo_strict,
            hi_strict,
            null,
            bool_state,
            types,
        }
    }
}

// ── Interval helpers ────────────────────────────────────────────────────

/// Tighten lower bound (take the higher / stricter one).
fn tighten_lower(
    a: Option<i64>,
    a_strict: bool,
    b: Option<i64>,
    b_strict: bool,
) -> (Option<i64>, bool) {
    match (a, b) {
        (None, None) => (None, false),
        (Some(v), None) => (Some(v), a_strict),
        (None, Some(v)) => (Some(v), b_strict),
        (Some(va), Some(vb)) => {
            if va > vb {
                (Some(va), a_strict)
            } else if vb > va {
                (Some(vb), b_strict)
            } else {
                // Same value: strict if either is strict
                (Some(va), a_strict || b_strict)
            }
        }
    }
}

/// Tighten upper bound (take the lower / stricter one).
fn tighten_upper(
    a: Option<i64>,
    a_strict: bool,
    b: Option<i64>,
    b_strict: bool,
) -> (Option<i64>, bool) {
    match (a, b) {
        (None, None) => (None, false),
        (Some(v), None) => (Some(v), a_strict),
        (None, Some(v)) => (Some(v), b_strict),
        (Some(va), Some(vb)) => {
            if va < vb {
                (Some(va), a_strict)
            } else if vb < va {
                (Some(vb), b_strict)
            } else {
                (Some(va), a_strict || b_strict)
            }
        }
    }
}

/// Widen lower bound (take the weaker / lower one) for join.
fn widen_lower(
    a: Option<i64>,
    a_strict: bool,
    b: Option<i64>,
    b_strict: bool,
) -> (Option<i64>, bool) {
    match (a, b) {
        (None, _) | (_, None) => (None, false),
        (Some(va), Some(vb)) => {
            if va < vb {
                (Some(va), a_strict)
            } else if vb < va {
                (Some(vb), b_strict)
            } else {
                // Same value: non-strict if either is non-strict (weaker)
                (Some(va), a_strict && b_strict)
            }
        }
    }
}

/// Widen upper bound (take the weaker / higher one) for join.
fn widen_upper(
    a: Option<i64>,
    a_strict: bool,
    b: Option<i64>,
    b_strict: bool,
) -> (Option<i64>, bool) {
    match (a, b) {
        (None, _) | (_, None) => (None, false),
        (Some(va), Some(vb)) => {
            if va > vb {
                (Some(va), a_strict)
            } else if vb > va {
                (Some(vb), b_strict)
            } else {
                (Some(va), a_strict && b_strict)
            }
        }
    }
}

// ── UnionFind ───────────────────────────────────────────────────────────

/// Small union-find for SSA value equality classes.
///
/// Supports transitive closure: `a == b` and `b == c` implies `a == c`.
/// Bounded by [`MAX_EQUALITY_EDGES`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnionFind {
    /// Parent map: SsaValue → parent SsaValue.
    /// Values not in the map are their own representative.
    parent: SmallVec<[(SsaValue, SsaValue); 8]>,
    /// Number of union operations performed.
    edges: usize,
}

impl UnionFind {
    pub fn new() -> Self {
        Self {
            parent: SmallVec::new(),
            edges: 0,
        }
    }

    /// Find the canonical representative for a value (with path compression).
    pub fn find(&mut self, x: SsaValue) -> SsaValue {
        // Look up parent
        let parent = self.parent.iter().find(|(k, _)| *k == x).map(|(_, v)| *v);
        match parent {
            None => x, // x is its own representative
            Some(p) if p == x => x,
            Some(p) => {
                let root = self.find(p);
                // Path compression
                if root != p
                    && let Some(entry) = self.parent.iter_mut().find(|(k, _)| *k == x)
                {
                    entry.1 = root;
                }
                root
            }
        }
    }

    /// Find without mutation (for read-only contexts).
    pub fn find_immutable(&self, x: SsaValue) -> SsaValue {
        let mut current = x;
        loop {
            let parent = self
                .parent
                .iter()
                .find(|(k, _)| *k == current)
                .map(|(_, v)| *v);
            match parent {
                None => return current,
                Some(p) if p == current => return current,
                Some(p) => current = p,
            }
        }
    }

    /// Union two values into the same equivalence class.
    /// Returns true if they were in different classes (new union).
    pub fn union(&mut self, a: SsaValue, b: SsaValue) -> bool {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return false; // already same class
        }
        if self.edges >= MAX_EQUALITY_EDGES {
            return false; // bounded
        }
        // Make the smaller representative the root (arbitrary but deterministic)
        let (root, child) = if ra.0 <= rb.0 { (ra, rb) } else { (rb, ra) };
        // Set child's parent to root
        match self.parent.iter_mut().find(|(k, _)| *k == child) {
            Some(entry) => entry.1 = root,
            None => self.parent.push((child, root)),
        }
        self.edges += 1;
        true
    }

    /// Check if two values are in the same equivalence class.
    pub fn same_class(&self, a: SsaValue, b: SsaValue) -> bool {
        self.find_immutable(a) == self.find_immutable(b)
    }

    /// Get all members of the equivalence class containing `v`.
    pub fn class_members(&self, v: SsaValue) -> SmallVec<[SsaValue; 4]> {
        let root = self.find_immutable(v);
        let mut members = SmallVec::new();
        members.push(root);
        for &(k, _) in &self.parent {
            if self.find_immutable(k) == root && !members.contains(&k) {
                members.push(k);
            }
        }
        members
    }

    /// Number of union operations performed.
    pub fn edge_count(&self) -> usize {
        self.edges
    }
}

impl Default for UnionFind {
    fn default() -> Self {
        Self::new()
    }
}

// ── PathEnv ─────────────────────────────────────────────────────────────

/// Constraint environment mapping SSA values to abstract value facts.
///
/// This is the main data structure carried through the taint analysis
/// worklist. It tracks per-value constraints, equality classes, and
/// disequality pairs, with incremental unsatisfiability detection.
///
/// ## Join behavior (intentional)
///
/// Keys present on only one side of a join are dropped. This is because
/// absent = Top, and Top.join(x) = Top. This is sound: if one branch
/// has no information about a value, the merge genuinely doesn't know.
/// Pre-branch constraints survive because they're inherited by both
/// successor states before branching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathEnv {
    /// Per-SsaValue facts, sorted by SsaValue for O(n) merge-join.
    facts: SmallVec<[(SsaValue, ValueFact); 8]>,
    /// Equality classes (union-find).
    pub(crate) uf: UnionFind,
    /// Known not-equal pairs (stored as canonical representative pairs,
    /// sorted for deterministic comparison).
    disequalities: SmallVec<[(SsaValue, SsaValue); 4]>,
    /// Relational constraints between SSA values (a < b, a <= b).
    /// Stored as `(lhs, op, rhs)` meaning `lhs op rhs`.
    /// Bounded by [`MAX_RELATIONAL`]; overflow drops the constraint (conservative).
    relational: SmallVec<[(SsaValue, RelOp, SsaValue); 8]>,
    /// Permanently unsatisfiable once set.
    unsat: bool,
    /// Per-key meet count for widening decisions.
    meet_counts: SmallVec<[(SsaValue, u8); 8]>,
    /// Refinement counter (bounded per block).
    refine_count: u32,
}

impl PathEnv {
    pub fn empty() -> Self {
        Self {
            facts: SmallVec::new(),
            uf: UnionFind::new(),
            disequalities: SmallVec::new(),
            relational: SmallVec::new(),
            unsat: false,
            meet_counts: SmallVec::new(),
            refine_count: 0,
        }
    }

    pub fn is_unsat(&self) -> bool {
        self.unsat
    }

    /// Get the fact for a value, defaulting to Top if absent.
    pub fn get(&self, v: SsaValue) -> ValueFact {
        let canonical = self.uf.find_immutable(v);
        self.facts
            .binary_search_by_key(&canonical, |(k, _)| *k)
            .ok()
            .map(|idx| self.facts[idx].1.clone())
            .unwrap_or_else(ValueFact::top)
    }

    /// Refine a value's fact via meet. Propagates to equality class.
    /// Sets unsat flag if result is bottom.
    pub fn refine(&mut self, v: SsaValue, fact: &ValueFact) {
        if self.unsat {
            return;
        }
        if self.refine_count >= MAX_REFINE_PER_BLOCK as u32 {
            return; // bounded
        }
        let canonical = self.uf.find_immutable(v);
        self.refine_single(canonical, fact);

        // Propagate to all members of the equality class
        let members = self.uf.class_members(canonical);
        for member in members {
            if member != canonical {
                self.refine_single(member, fact);
            }
        }
    }

    fn refine_single(&mut self, v: SsaValue, fact: &ValueFact) {
        if self.unsat {
            return;
        }
        // `refine` (the outer entry) short-circuits at MAX_REFINE_PER_BLOCK,
        // but `refine_single` is also invoked directly from `assume_eq`,
        // `assume_neq`, and a few internal sites.  Large generated inputs
        // (thousands of short statements on one line) can drive millions
        // of calls and overflow a plain u32 `refine_count`.  Saturate to
        // stay within bounds, the refinement pipeline is already
        // idempotent past the cap, so saturation is semantically a no-op.
        self.refine_count = self.refine_count.saturating_add(1);

        // Check size bound
        let pos = self.facts.binary_search_by_key(&v, |(k, _)| *k);
        if pos.is_err() && self.facts.len() >= MAX_PATH_ENV_ENTRIES {
            return; // bounded, don't grow
        }

        // Get meet count for widening
        let count = self.get_meet_count(v);
        let existing = match pos {
            Ok(idx) => &self.facts[idx].1,
            Err(_) => &ValueFact::top(), // will be replaced below
        };

        let new_fact = if count >= WIDEN_THRESHOLD {
            existing.widen(fact)
        } else {
            existing.meet(fact)
        };

        self.increment_meet_count(v);

        if new_fact.is_bottom() {
            self.unsat = true;
            return;
        }

        match pos {
            Ok(idx) => self.facts[idx].1 = new_fact,
            Err(idx) => self.facts.insert(idx, (v, new_fact)),
        }
    }

    fn get_meet_count(&self, v: SsaValue) -> u8 {
        self.meet_counts
            .binary_search_by_key(&v, |(k, _)| *k)
            .ok()
            .map(|idx| self.meet_counts[idx].1)
            .unwrap_or(0)
    }

    fn increment_meet_count(&mut self, v: SsaValue) {
        match self.meet_counts.binary_search_by_key(&v, |(k, _)| *k) {
            Ok(idx) => self.meet_counts[idx].1 = self.meet_counts[idx].1.saturating_add(1),
            Err(idx) => self.meet_counts.insert(idx, (v, 1)),
        }
    }

    /// Record that two values are equal. Merges their facts and checks
    /// for disequality contradiction.
    pub fn assert_equal(&mut self, a: SsaValue, b: SsaValue) {
        if self.unsat || a == b {
            return;
        }
        let ra = self.uf.find_immutable(a);
        let rb = self.uf.find_immutable(b);
        if ra == rb {
            return; // already known equal
        }

        // Check disequality contradiction
        let pair = (ra.min(rb), ra.max(rb));
        if self.disequalities.contains(&pair) {
            self.unsat = true;
            return;
        }

        // Check for strict relational contradiction: a == b but a < b or b < a
        for &(lhs, op, rhs) in &self.relational {
            if op == RelOp::Lt && ((lhs == ra && rhs == rb) || (lhs == rb && rhs == ra)) {
                self.unsat = true;
                return;
            }
        }

        // Merge equality classes
        let fa = self.get(ra);
        let fb = self.get(rb);
        let merged = fa.meet(&fb);
        if merged.is_bottom() {
            self.unsat = true;
            return;
        }

        self.uf.union(a, b);
        // Apply merged fact to the new canonical representative
        let new_rep = self.uf.find_immutable(a);
        self.refine_single(new_rep, &merged);
    }

    /// Record that two values are not equal. Checks for equality
    /// contradiction and propagates excluded constants.
    pub fn assert_not_equal(&mut self, a: SsaValue, b: SsaValue) {
        if self.unsat {
            return;
        }
        if a == b {
            self.unsat = true;
            return;
        }
        let ra = self.uf.find_immutable(a);
        let rb = self.uf.find_immutable(b);
        if ra == rb {
            // Already known equal, contradiction
            self.unsat = true;
            return;
        }

        let pair = (ra.min(rb), ra.max(rb));
        if self.disequalities.contains(&pair) {
            return; // already known
        }
        if self.disequalities.len() < MAX_DISEQUALITY_EDGES {
            // Insert sorted
            match self.disequalities.binary_search(&pair) {
                Ok(_) => {} // already present
                Err(idx) => self.disequalities.insert(idx, pair),
            }
        }

        // If one side has an exact value, add to other's excluded
        let fa = self.get(ra);
        let fb = self.get(rb);
        if let Some(ref cv) = fa.exact {
            let mut neq_fact = ValueFact::top();
            neq_fact.excluded.push(cv.clone());
            self.refine_single(rb, &neq_fact);
        }
        if let Some(ref cv) = fb.exact {
            let mut neq_fact = ValueFact::top();
            neq_fact.excluded.push(cv.clone());
            self.refine_single(ra, &neq_fact);
        }
    }

    /// Assert a relational constraint between two SSA values.
    ///
    /// `a op b` where `op` is `Lt` (a < b) or `Le` (a <= b).
    /// Detects direct contradictions and bounded transitive cycles,
    /// then propagates interval refinements between the two sides.
    pub fn assert_relational(&mut self, a: SsaValue, op: RelOp, b: SsaValue) {
        if self.unsat {
            return;
        }

        // Step 1: canonicalize via union-find
        let ra = self.uf.find_immutable(a);
        let rb = self.uf.find_immutable(b);

        // Self-comparison: x < x is impossible, x <= x is trivially true
        if ra == rb {
            if op == RelOp::Lt {
                self.unsat = true;
            }
            return;
        }

        // Step 2: check for direct contradiction against existing relationals.
        // Contradiction when new (ra op rb) conflicts with existing (rb op2 ra)
        // where at least one of op, op2 is strict (Lt).
        for &(lhs, existing_op, rhs) in &self.relational {
            if lhs == rb && rhs == ra {
                // Existing: rb existing_op ra. New: ra op rb.
                // Contradiction if either is strict.
                if op == RelOp::Lt || existing_op == RelOp::Lt {
                    self.unsat = true;
                    return;
                }
                // Both Le: a <= b and b <= a → satisfiable (a == b)
            }
        }

        // Step 3: bounded transitive cycle detection (conservative, depth 4).
        // Walk forward from rb following relational edges. If we reach ra,
        // we have a cycle. Unsat if any edge in the chain is strict.
        if self.check_relational_cycle(ra, rb, op) {
            self.unsat = true;
            return;
        }

        // Step 4: dedup check, if this exact constraint already exists, skip
        let already_present = self
            .relational
            .iter()
            .any(|&(l, o, r)| l == ra && o == op && r == rb);
        if already_present {
            // Still do interval refinement (may have new facts since last time)
        } else {
            // Insert if within bounds
            if self.relational.len() < MAX_RELATIONAL {
                self.relational.push((ra, op, rb));
            }
            // If at capacity, skip, conservative: losing a constraint only
            // loses pruning power, never introduces unsoundness.
        }

        // Step 5: cross-domain interval refinement.
        self.refine_relational_intervals(ra, op, rb);
    }

    /// Bounded transitive cycle detection.
    ///
    /// Starting from `start`, follow relational edges forward up to 4 hops.
    /// If we reach `target`, a cycle exists. Returns true if the cycle
    /// contains at least one strict (Lt) edge, making it contradictory.
    ///
    /// This is conservative, not complete: chains longer than 4 hops are
    /// missed. Missing a cycle means we fail to prune an infeasible path,
    /// not that we wrongly prune a feasible one.
    fn check_relational_cycle(
        &self,
        target: SsaValue,
        start: SsaValue,
        new_edge_op: RelOp,
    ) -> bool {
        const MAX_DEPTH: u8 = 4;
        // Track whether any edge in the chain is strict
        let mut has_strict = new_edge_op == RelOp::Lt;

        let mut current = start;
        for _ in 0..MAX_DEPTH {
            let mut found_next = false;
            for &(lhs, op, rhs) in &self.relational {
                if lhs == current {
                    if rhs == target {
                        // Cycle closed. Contradictory only if at least one strict edge.
                        if has_strict || op == RelOp::Lt {
                            return true;
                        }
                        // All Le: a <= b <= ... <= a means all equal, satisfiable
                        return false;
                    }
                    // Continue walking (take first outgoing edge)
                    if op == RelOp::Lt {
                        has_strict = true;
                    }
                    current = rhs;
                    found_next = true;
                    break;
                }
            }
            if !found_next {
                break;
            }
        }
        false
    }

    /// Propagate interval refinements from a relational constraint.
    ///
    /// For integer intervals: `a < b` with `b ∈ [_, h]` → `a.hi ≤ h-1` (strict).
    /// `a <= b` with `b ∈ [_, h]` → `a.hi ≤ h` (non-strict).
    fn refine_relational_intervals(&mut self, a: SsaValue, op: RelOp, b: SsaValue) {
        let fact_a = self.get(a);
        let fact_b = self.get(b);

        // Refine a's upper bound from b's upper bound
        if let Some(hi_b) = fact_b.hi {
            let new_hi = match op {
                RelOp::Lt => {
                    // a < b ∧ b ≤ hi_b → a ≤ hi_b - 1 (for integers)
                    if hi_b != i64::MIN {
                        Some(hi_b - 1)
                    } else {
                        None // underflow guard
                    }
                }
                RelOp::Le => {
                    // a <= b ∧ b ≤ hi_b → a ≤ hi_b
                    Some(hi_b)
                }
            };
            if let Some(h) = new_hi {
                let mut refine_fact = ValueFact::top();
                refine_fact.hi = Some(h);
                self.refine(a, &refine_fact);
            }
        }

        // Refine b's lower bound from a's lower bound
        if let Some(lo_a) = fact_a.lo {
            let new_lo = match op {
                RelOp::Lt => {
                    // a < b ∧ a ≥ lo_a → b ≥ lo_a + 1 (for integers)
                    if lo_a != i64::MAX {
                        Some(lo_a + 1)
                    } else {
                        None // overflow guard
                    }
                }
                RelOp::Le => {
                    // a <= b ∧ a ≥ lo_a → b ≥ lo_a
                    Some(lo_a)
                }
            };
            if let Some(l) = new_lo {
                let mut refine_fact = ValueFact::top();
                refine_fact.lo = Some(l);
                self.refine(b, &refine_fact);
            }
        }
    }

    /// Join two PathEnvs at a CFG merge point.
    ///
    /// Keys present on only one side are dropped (absent = Top,
    /// Top.join(x) = Top). This is intentional and documented.
    pub fn join(&self, other: &Self) -> Self {
        if self.unsat {
            return other.clone();
        }
        if other.unsat {
            return self.clone();
        }

        // Merge-join on sorted fact lists
        let mut facts = SmallVec::new();
        let (mut i, mut j) = (0, 0);
        while i < self.facts.len() && j < other.facts.len() {
            match self.facts[i].0.cmp(&other.facts[j].0) {
                std::cmp::Ordering::Less => {
                    // Only in self, drop (absent on other side = Top)
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    // Only in other, drop
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let joined = self.facts[i].1.join(&other.facts[j].1);
                    if !joined.is_top() {
                        facts.push((self.facts[i].0, joined));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        // Equalities: intersection
        let equalities_self = &self.uf;
        let equalities_other = &other.uf;

        // For intersection of union-finds, we keep pairs that both sides agree on.
        // Build a new UF by checking each pair in self against other.
        let mut uf = UnionFind::new();
        // Collect all values referenced in self's UF
        for &(k, _) in &equalities_self.parent {
            let rep_self = equalities_self.find_immutable(k);
            // Check if other also has them in the same class
            if equalities_other.same_class(k, rep_self) {
                uf.union(k, rep_self);
            }
        }

        // Disequalities: intersection
        let disequalities: SmallVec<[(SsaValue, SsaValue); 4]> = self
            .disequalities
            .iter()
            .filter(|pair| other.disequalities.contains(pair))
            .cloned()
            .collect();

        // Relationals: intersection (keep only constraints both sides agree on)
        let relational: SmallVec<[(SsaValue, RelOp, SsaValue); 8]> = self
            .relational
            .iter()
            .filter(|rel| other.relational.contains(rel))
            .cloned()
            .collect();

        PathEnv {
            facts,
            uf,
            disequalities,
            relational,
            unsat: false,
            meet_counts: SmallVec::new(), // reset after join
            refine_count: 0,
        }
    }

    /// Seed facts from constant propagation and type analysis results.
    pub fn seed_from_optimization(
        &mut self,
        const_values: &HashMap<SsaValue, ConstLattice>,
        type_facts: &TypeFactResult,
    ) {
        for (v, cl) in const_values {
            if let Some(cv) = ConstValue::from_const_lattice(cl) {
                let mut fact = ValueFact::top();
                fact.exact = Some(cv.clone());
                match &cv {
                    ConstValue::Int(i) => {
                        fact.lo = Some(*i);
                        fact.hi = Some(*i);
                        fact.types = TypeSet::singleton(&TypeKind::Int);
                        fact.null = Nullability::NonNull;
                    }
                    ConstValue::Bool(b) => {
                        fact.bool_state = if *b {
                            BoolState::True
                        } else {
                            BoolState::False
                        };
                        fact.types = TypeSet::singleton(&TypeKind::Bool);
                        fact.null = Nullability::NonNull;
                    }
                    ConstValue::Null => {
                        fact.null = Nullability::Null;
                        fact.types = TypeSet::singleton(&TypeKind::Null);
                    }
                    ConstValue::Str(_) => {
                        fact.types = TypeSet::singleton(&TypeKind::String);
                        fact.null = Nullability::NonNull;
                    }
                }
                self.refine_single(*v, &fact);
            }
        }
        for (v, tf) in &type_facts.facts {
            let mut fact = ValueFact::top();
            fact.types = TypeSet::singleton(&tf.kind);
            if !tf.nullable && tf.kind != TypeKind::Null {
                fact.null = Nullability::NonNull;
            }
            self.refine_single(*v, &fact);
        }
    }

    /// Reset refinement counter (call at the start of each block).
    pub fn reset_refine_count(&mut self) {
        self.refine_count = 0;
    }

    /// Number of facts currently tracked.
    pub fn fact_count(&self) -> usize {
        self.facts.len()
    }

    /// Iterate over all (SsaValue, ValueFact) pairs.
    pub fn facts(&self) -> &[(SsaValue, ValueFact)] {
        &self.facts
    }

    /// Iterate over all known disequality pairs.
    pub fn disequalities(&self) -> &[(SsaValue, SsaValue)] {
        &self.disequalities
    }

    /// Iterate over all relational constraints (lhs op rhs).
    pub fn relational(&self) -> &[(SsaValue, RelOp, SsaValue)] {
        &self.relational
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TypeSet::is_singleton_of ─────────────────────────────────────────

    #[test]
    fn is_singleton_of_matching() {
        let ts = TypeSet::singleton(&TypeKind::Int);
        assert!(ts.is_singleton_of(&TypeKind::Int));
    }

    #[test]
    fn is_singleton_of_non_matching() {
        let ts = TypeSet::singleton(&TypeKind::Int);
        assert!(!ts.is_singleton_of(&TypeKind::String));
    }

    #[test]
    fn is_singleton_of_multi_type() {
        let ts = TypeSet::singleton(&TypeKind::Int).join(TypeSet::singleton(&TypeKind::String));
        assert!(!ts.is_singleton_of(&TypeKind::Int));
        assert!(!ts.is_singleton_of(&TypeKind::String));
    }

    #[test]
    fn is_singleton_of_empty() {
        assert!(!TypeSet::BOTTOM.is_singleton_of(&TypeKind::Int));
    }

    // ── TypeSet::as_singleton ────────────────────────────────────────────

    #[test]
    fn as_singleton_returns_kind_for_singleton() {
        let ts = TypeSet::singleton(&TypeKind::HttpResponse);
        assert_eq!(ts.as_singleton(), Some(TypeKind::HttpResponse));
    }

    #[test]
    fn as_singleton_none_for_multi_type() {
        let ts = TypeSet::singleton(&TypeKind::Int).join(TypeSet::singleton(&TypeKind::Bool));
        assert_eq!(ts.as_singleton(), None);
    }

    #[test]
    fn as_singleton_none_for_empty() {
        assert_eq!(TypeSet::BOTTOM.as_singleton(), None);
    }

    // ── type_kind_from_index round-trip ──────────────────────────────────

    #[test]
    fn type_kind_index_round_trip() {
        let all_kinds = [
            TypeKind::String,
            TypeKind::Int,
            TypeKind::Bool,
            TypeKind::Object,
            TypeKind::Array,
            TypeKind::Null,
            TypeKind::Unknown,
            TypeKind::HttpResponse,
            TypeKind::DatabaseConnection,
            TypeKind::FileHandle,
            TypeKind::Url,
            TypeKind::HttpClient,
        ];
        for kind in &all_kinds {
            let idx = type_kind_index(kind);
            let recovered = type_kind_from_index(idx);
            assert_eq!(
                recovered.as_ref(),
                Some(kind),
                "round-trip failed for {:?} at index {}",
                kind,
                idx
            );
        }
    }

    // ── PathEnv join semantics ───────────────────────────────────────────

    #[test]
    fn join_both_narrow_same_type() {
        // Both paths narrow x to Int → joined has x as Int
        let v = SsaValue(0);

        let mut env1 = PathEnv::empty();
        let mut fact1 = ValueFact::top();
        fact1.types = TypeSet::singleton(&TypeKind::Int);
        env1.refine(v, &fact1);

        let mut env2 = PathEnv::empty();
        let mut fact2 = ValueFact::top();
        fact2.types = TypeSet::singleton(&TypeKind::Int);
        env2.refine(v, &fact2);

        let joined = env1.join(&env2);
        let result = joined.get(v);
        assert!(
            result.types.is_singleton_of(&TypeKind::Int),
            "expected singleton Int, got {:?}",
            result.types
        );
    }

    #[test]
    fn join_different_types_produces_union() {
        // One path narrows x to Int, other to String → joined has both
        let v = SsaValue(0);

        let mut env1 = PathEnv::empty();
        let mut fact1 = ValueFact::top();
        fact1.types = TypeSet::singleton(&TypeKind::Int);
        env1.refine(v, &fact1);

        let mut env2 = PathEnv::empty();
        let mut fact2 = ValueFact::top();
        fact2.types = TypeSet::singleton(&TypeKind::String);
        env2.refine(v, &fact2);

        let joined = env1.join(&env2);
        let result = joined.get(v);
        assert!(result.types.contains(&TypeKind::Int));
        assert!(result.types.contains(&TypeKind::String));
        // Should not be a singleton
        assert!(result.types.as_singleton().is_none());
    }

    #[test]
    fn join_one_side_missing_drops_entry() {
        // One path narrows x to Int, other has no entry for x →
        // joined drops x (absent = Top)
        let v = SsaValue(0);

        let mut env1 = PathEnv::empty();
        let mut fact1 = ValueFact::top();
        fact1.types = TypeSet::singleton(&TypeKind::Int);
        env1.refine(v, &fact1);

        let env2 = PathEnv::empty();

        let joined = env1.join(&env2);
        let result = joined.get(v);
        // Absent key → Top; get() returns ValueFact::top()
        assert!(
            result.is_top(),
            "expected Top for key absent on one side, got {:?}",
            result
        );
    }
}
