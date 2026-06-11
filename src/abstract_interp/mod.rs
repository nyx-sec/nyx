//! Abstract interpretation framework.
//!
//! Provides a product abstract domain ([`AbstractValue`]) composing independent
//! subdomains:
//! - [`IntervalFact`]: numeric interval `[lo, hi]` with arithmetic transfer
//! - [`StringFact`]: string prefix + suffix with concatenation transfer
//! - [`BitFact`]: known-zero/known-one bit masks for bitwise transfer
//!
//! Abstract values are stored per-SSA-value in [`AbstractState`], which is
//! carried through the taint analysis worklist in `SsaTaintState`. The framework
//! propagates abstract values forward through SSA operations, joins at CFG
//! merges, and widens at loop heads to ensure termination.
//!
//! ## Feature gate
//!
//! Enabled by default.  Disable via `analysis.engine.abstract_interpretation
//! = false` in `nyx.conf` or the `--no-abstract-interp` CLI flag.

pub mod bit_domain;
pub mod interval;
pub mod path_domain;
pub mod string_domain;

pub use bit_domain::BitFact;
pub use interval::IntervalFact;
pub use path_domain::{PathFact, Tri};
pub use string_domain::StringFact;

use crate::ssa::ir::SsaValue;
use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Feature gate: check if abstract interpretation is enabled.
///
/// Controlled by `analysis.engine.abstract_interpretation` in `nyx.conf`
/// (default `true`) or the `--abstract-interp / --no-abstract-interp` CLI
/// flag.  The legacy `NYX_ABSTRACT_INTERP` env var is consulted only when no
/// runtime has been installed (library use / legacy tests).
pub fn is_enabled() -> bool {
    crate::utils::analysis_options::current().abstract_interpretation
}

// ── AbstractValue ───────────────────────────────────────────────────────

/// Per-SSA-value abstract element: product of all subdomains.
///
/// Each subdomain is independent, join, meet, widen, and leq are applied
/// component-wise. Adding a new subdomain requires adding a field here
/// and updating the component-wise implementations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractValue {
    pub interval: IntervalFact,
    pub string: StringFact,
    pub bits: BitFact,
    #[serde(default, skip_serializing_if = "path_fact_is_top")]
    pub path: PathFact,
}

fn path_fact_is_top(p: &PathFact) -> bool {
    p.is_top()
}

impl AbstractValue {
    pub fn top() -> Self {
        Self {
            interval: IntervalFact::top(),
            string: StringFact::top(),
            bits: BitFact::top(),
            path: PathFact::top(),
        }
    }

    pub fn bottom() -> Self {
        Self {
            interval: IntervalFact::bottom(),
            string: StringFact::bottom(),
            bits: BitFact::bottom(),
            path: PathFact::bottom(),
        }
    }

    /// Construct a value with a specific [`PathFact`] and every other
    /// subdomain at Top.  Used by the Rust path-primitive transfer rules.
    pub fn with_path_fact(path: PathFact) -> Self {
        Self {
            interval: IntervalFact::top(),
            string: StringFact::top(),
            bits: BitFact::top(),
            path,
        }
    }

    pub fn is_top(&self) -> bool {
        self.interval.is_top() && self.string.is_top() && self.bits.is_top() && self.path.is_top()
    }

    pub fn is_bottom(&self) -> bool {
        self.interval.is_bottom()
            && self.string.is_bottom()
            && self.bits.is_bottom()
            && self.path.is_bottom()
    }

    pub fn join(&self, other: &Self) -> Self {
        Self {
            interval: self.interval.join(&other.interval),
            string: self.string.join(&other.string),
            bits: self.bits.join(&other.bits),
            path: self.path.join(&other.path),
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        Self {
            interval: self.interval.meet(&other.interval),
            string: self.string.meet(&other.string),
            bits: <BitFact as AbstractDomain>::meet(&self.bits, &other.bits),
            path: <PathFact as AbstractDomain>::meet(&self.path, &other.path),
        }
    }

    pub fn widen(&self, other: &Self) -> Self {
        Self {
            interval: self.interval.widen(&other.interval),
            string: self.string.widen(&other.string),
            bits: self.bits.widen(&other.bits),
            path: self.path.widen(&other.path),
        }
    }

    pub fn leq(&self, other: &Self) -> bool {
        self.interval.leq(&other.interval)
            && self.string.leq(&other.string)
            && self.bits.leq(&other.bits)
            && self.path.leq(&other.path)
    }
}

impl Lattice for AbstractValue {
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

impl AbstractDomain for AbstractValue {
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

// ── AbstractTransfer ────────────────────────────────────────────────────

/// Maximum length of a literal prefix tracked by [`StringTransfer::LiteralPrefix`].
///
/// Caps the on-disk summary size when a callee produces a long known prefix.
/// The interval domain already has a natural bound (two `i64`s); the string
/// side needs an explicit cap so a callee that returns a 10KB constant does
/// not balloon every cross-file summary that references it.
pub const MAX_LITERAL_PREFIX_LEN: usize = 64;

/// Per-parameter interval-to-return transform.
///
/// This is a **bounded** description of how a caller-known interval on one
/// parameter maps to the callee's return interval.  The forms are intentionally
/// restricted so the summary size stays constant regardless of callee body
/// complexity:
///
/// * [`IntervalTransfer::Top`], no interval knowledge crosses (default).
/// * [`IntervalTransfer::Identity`], return = param (pass-through).
/// * [`IntervalTransfer::Affine`], return = param * `mul` + `add` with
///   `i64` constants; overflow defaults to Top at apply time.
/// * [`IntervalTransfer::Clamped`], return is always in `[lo, hi]` regardless
///   of input.  Captures callee-intrinsic bounds (e.g. `saturating` ops).
///
/// No unbounded expression trees, no nesting.  A callee whose behaviour does
/// not fit one of these forms falls back to `Top`, we never try to encode
/// richer algebra in the summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum IntervalTransfer {
    #[default]
    Top,
    Identity,
    Affine {
        add: i64,
        mul: i64,
    },
    Clamped {
        lo: i64,
        hi: i64,
    },
}

impl IntervalTransfer {
    /// Apply the transform to a caller-known input interval.
    pub fn apply(&self, input: &IntervalFact) -> IntervalFact {
        match self {
            Self::Top => IntervalFact::top(),
            Self::Identity => input.clone(),
            Self::Affine { add, mul } => input
                .mul(&IntervalFact::exact(*mul))
                .add(&IntervalFact::exact(*add)),
            Self::Clamped { lo, hi } if lo <= hi => IntervalFact {
                lo: Some(*lo),
                hi: Some(*hi),
            },
            Self::Clamped { .. } => IntervalFact::top(),
        }
    }

    /// Join two transforms.  Used when multiple return paths produce
    /// differing transforms for the same parameter: the aggregate is the
    /// widest safe form.
    pub fn join(&self, other: &Self) -> Self {
        use IntervalTransfer::*;
        match (self, other) {
            (Top, _) | (_, Top) => Top,
            (a, b) if a == b => a.clone(),
            (Clamped { lo: a, hi: b }, Clamped { lo: c, hi: d }) => Clamped {
                lo: (*a).min(*c),
                hi: (*b).max(*d),
            },
            // Identity ⊔ anything else = Top (different flow shapes).
            _ => Top,
        }
    }
}

/// Per-parameter string-to-return transform.
///
/// Mirrors [`IntervalTransfer`] for the string subdomain.  Bounded by
/// [`MAX_LITERAL_PREFIX_LEN`] to keep summary size constant.
///
/// * [`StringTransfer::Unknown`], default.
/// * [`StringTransfer::Identity`], return = param.
/// * [`StringTransfer::LiteralPrefix`], return has this literal prefix
///   regardless of input (callee-intrinsic).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StringTransfer {
    #[default]
    Unknown,
    Identity,
    LiteralPrefix(String),
}

impl StringTransfer {
    /// Construct a `LiteralPrefix`, truncating to [`MAX_LITERAL_PREFIX_LEN`]
    /// and degrading to `Unknown` on empty input.
    pub fn literal_prefix(s: &str) -> Self {
        if s.is_empty() {
            return Self::Unknown;
        }
        if s.len() <= MAX_LITERAL_PREFIX_LEN {
            Self::LiteralPrefix(s.to_string())
        } else {
            // Truncate on a char boundary to stay valid UTF-8.
            let mut cut = MAX_LITERAL_PREFIX_LEN;
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }
            if cut == 0 {
                Self::Unknown
            } else {
                Self::LiteralPrefix(s[..cut].to_string())
            }
        }
    }

    /// Apply the transform to a caller-known input string fact.
    pub fn apply(&self, input: &StringFact) -> StringFact {
        match self {
            Self::Unknown => StringFact::top(),
            Self::Identity => input.clone(),
            Self::LiteralPrefix(p) => StringFact::from_prefix(p),
        }
    }

    /// Join two transforms.
    pub fn join(&self, other: &Self) -> Self {
        use StringTransfer::*;
        match (self, other) {
            (Unknown, _) | (_, Unknown) => Unknown,
            (a, b) if a == b => a.clone(),
            (LiteralPrefix(a), LiteralPrefix(b)) => {
                // Longest common prefix.
                let lcp: String = a
                    .chars()
                    .zip(b.chars())
                    .take_while(|(x, y)| x == y)
                    .map(|(x, _)| x)
                    .collect();
                if lcp.is_empty() {
                    Unknown
                } else {
                    Self::literal_prefix(&lcp)
                }
            }
            // Identity vs LiteralPrefix → Unknown (different flow shapes).
            _ => Unknown,
        }
    }
}

/// Per-parameter abstract-domain transfer channel.
///
/// Combines the per-subdomain transforms into one record attached to each
/// parameter in [`crate::summary::ssa_summary::SsaFuncSummary`].  Used at
/// cross-file call sites to synthesise a return abstract value from the
/// caller's knowledge of each argument, without having to re-run the callee.
///
/// Composition rule: `apply(input) = (interval.apply, string.apply,
/// bits=top)`.  The bit domain is always Top, we do not track cross-file
/// bit transfers.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AbstractTransfer {
    #[serde(default, skip_serializing_if = "is_interval_top")]
    pub interval: IntervalTransfer,
    #[serde(default, skip_serializing_if = "is_string_unknown")]
    pub string: StringTransfer,
}

fn is_interval_top(t: &IntervalTransfer) -> bool {
    matches!(t, IntervalTransfer::Top)
}

fn is_string_unknown(t: &StringTransfer) -> bool {
    matches!(t, StringTransfer::Unknown)
}

impl AbstractTransfer {
    /// Fully-imprecise transfer: no information crosses.  Used as the
    /// conservative default when a parameter's flow does not fit any of the
    /// bounded forms.
    pub fn top() -> Self {
        Self::default()
    }

    /// True when neither subdomain carries any information, equivalent to
    /// "omit this entry entirely".
    pub fn is_top(&self) -> bool {
        is_interval_top(&self.interval) && is_string_unknown(&self.string)
    }

    /// Apply the transform to a caller-known input abstract value.
    pub fn apply(&self, input: &AbstractValue) -> AbstractValue {
        AbstractValue {
            interval: self.interval.apply(&input.interval),
            string: self.string.apply(&input.string),
            bits: BitFact::top(),
            path: PathFact::top(),
        }
    }

    /// Join two transfers component-wise.
    pub fn join(&self, other: &Self) -> Self {
        Self {
            interval: self.interval.join(&other.interval),
            string: self.string.join(&other.string),
        }
    }
}

// ── AbstractState ───────────────────────────────────────────────────────

/// Maximum abstract values tracked per block (performance bound).
const MAX_ABSTRACT_VALUES: usize = 64;

/// Per-block abstract state: sorted map from SsaValue → AbstractValue.
///
/// Values not in the map are implicitly Top (no knowledge). Sorted by
/// SsaValue for O(n) merge-join, matching the pattern used by
/// `SsaTaintState.values`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbstractState {
    values: SmallVec<[(SsaValue, AbstractValue); 8]>,
}

impl AbstractState {
    pub fn empty() -> Self {
        Self {
            values: SmallVec::new(),
        }
    }

    /// Get abstract value for an SSA value. Returns Top if absent.
    pub fn get(&self, v: SsaValue) -> AbstractValue {
        self.values
            .binary_search_by_key(&v, |(id, _)| *id)
            .ok()
            .map(|idx| self.values[idx].1.clone())
            .unwrap_or_else(AbstractValue::top)
    }

    /// Set abstract value for an SSA value. Drops Top values to save space.
    pub fn set(&mut self, v: SsaValue, val: AbstractValue) {
        if val.is_top() {
            // Don't store Top, it's the default
            if let Ok(idx) = self.values.binary_search_by_key(&v, |(id, _)| *id) {
                self.values.remove(idx);
            }
            return;
        }
        match self.values.binary_search_by_key(&v, |(id, _)| *id) {
            Ok(idx) => self.values[idx].1 = val,
            Err(idx) => {
                if self.values.len() < MAX_ABSTRACT_VALUES {
                    self.values.insert(idx, (v, val));
                }
                // Over budget: silently drop (conservative, defaults to Top)
            }
        }
    }

    /// Merge-join two abstract states. Values present in both are joined;
    /// values present in only one side are dropped (absent = Top, join with
    /// Top = Top).
    pub fn join(&self, other: &Self) -> Self {
        let mut result = SmallVec::with_capacity(self.values.len().min(other.values.len()));
        let (mut i, mut j) = (0, 0);

        while i < self.values.len() && j < other.values.len() {
            match self.values[i].0.cmp(&other.values[j].0) {
                std::cmp::Ordering::Less => {
                    // Only in self → join with Top = Top → drop
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    // Only in other → drop
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let joined = self.values[i].1.join(&other.values[j].1);
                    if !joined.is_top() {
                        result.push((self.values[i].0, joined));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        Self { values: result }
    }

    /// Merge-widen: for values present in both states, apply widening.
    /// Values present in only one side are dropped (Top).
    pub fn widen(&self, other: &Self) -> Self {
        let mut result = SmallVec::with_capacity(self.values.len().min(other.values.len()));
        let (mut i, mut j) = (0, 0);

        while i < self.values.len() && j < other.values.len() {
            match self.values[i].0.cmp(&other.values[j].0) {
                std::cmp::Ordering::Less => {
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let widened = self.values[i].1.widen(&other.values[j].1);
                    if !widened.is_top() {
                        result.push((self.values[i].0, widened));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        Self { values: result }
    }

    /// Partial order: self ⊑ other.
    pub fn leq(&self, other: &Self) -> bool {
        // self ⊑ other iff for every SSA value v: self[v] ⊑ other[v], using the
        // convention that an absent entry is Top.
        //
        // Three cases by where v is stored:
        //   - in both:      check self[v] ⊑ other[v]  (loop over self below).
        //   - in self only: other[v] = Top, and self[v] ⊑ Top always holds — ok.
        //   - in other only: self[v] = Top; since stored entries are non-Top,
        //     Top ⋢ other[v], so self ⋢ other. This case was previously missed.
        for (v, val) in &self.values {
            let other_val = other.get(*v);
            if !val.leq(&other_val) {
                return false;
            }
        }
        // Any value present only in `other` means self[v] = Top ⋢ other[v]
        // (other's stored entries are non-Top), so self ⋢ other.
        for (v, _) in &other.values {
            if self.values.binary_search_by_key(v, |(id, _)| *id).is_err() {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_value_top_bottom() {
        assert!(AbstractValue::top().is_top());
        assert!(AbstractValue::bottom().is_bottom());
        assert!(!AbstractValue::top().is_bottom());
        assert!(!AbstractValue::bottom().is_top());
    }

    #[test]
    fn abstract_value_join_componentwise() {
        let a = AbstractValue {
            interval: IntervalFact::exact(1),
            string: StringFact::from_prefix("https://a.com/"),
            bits: BitFact::top(),
            path: PathFact::top(),
        };
        let b = AbstractValue {
            interval: IntervalFact::exact(5),
            string: StringFact::from_prefix("https://b.com/"),
            bits: BitFact::top(),
            path: PathFact::top(),
        };
        let j = a.join(&b);
        assert_eq!(j.interval.lo, Some(1));
        assert_eq!(j.interval.hi, Some(5));
        assert_eq!(j.string.prefix.as_deref(), Some("https://"));
    }

    #[test]
    fn abstract_value_widen_componentwise() {
        let old = AbstractValue {
            interval: IntervalFact {
                lo: Some(0),
                hi: Some(5),
            },
            string: StringFact::from_prefix("hello"),
            bits: BitFact::top(),
            path: PathFact::top(),
        };
        let new = AbstractValue {
            interval: IntervalFact {
                lo: Some(0),
                hi: Some(10),
            },
            string: StringFact::from_prefix("hello"),
            bits: BitFact::top(),
            path: PathFact::top(),
        };
        let w = old.widen(&new);
        assert_eq!(w.interval.lo, Some(0)); // stable
        assert_eq!(w.interval.hi, None); // grew → widened
        assert_eq!(w.string.prefix.as_deref(), Some("hello")); // stable
    }

    #[test]
    fn abstract_state_get_default_top() {
        let state = AbstractState::empty();
        assert!(state.get(SsaValue(42)).is_top());
    }

    #[test]
    fn abstract_state_set_get() {
        let mut state = AbstractState::empty();
        let val = AbstractValue {
            interval: IntervalFact::exact(10),
            string: StringFact::top(),
            bits: BitFact::top(),
            path: PathFact::top(),
        };
        state.set(SsaValue(1), val.clone());
        assert_eq!(state.get(SsaValue(1)), val);
    }

    #[test]
    fn abstract_state_set_top_removes() {
        let mut state = AbstractState::empty();
        state.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact::exact(5),
                string: StringFact::top(),
                bits: BitFact::top(),
                path: PathFact::top(),
            },
        );
        assert!(!state.get(SsaValue(1)).is_top());
        state.set(SsaValue(1), AbstractValue::top());
        assert!(state.get(SsaValue(1)).is_top());
        assert!(state.values.is_empty());
    }

    #[test]
    fn abstract_state_join() {
        let mut a = AbstractState::empty();
        a.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact::exact(3),
                string: StringFact::top(),
                bits: BitFact::top(),
                path: PathFact::top(),
            },
        );
        a.set(
            SsaValue(2),
            AbstractValue {
                interval: IntervalFact::exact(10),
                string: StringFact::top(),
                bits: BitFact::top(),
                path: PathFact::top(),
            },
        );

        let mut b = AbstractState::empty();
        b.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact::exact(7),
                string: StringFact::top(),
                bits: BitFact::top(),
                path: PathFact::top(),
            },
        );
        // SsaValue(2) not in b → join drops it (Top)

        let j = a.join(&b);
        // SsaValue(1): join [3,3] and [7,7] = [3,7]
        let v1 = j.get(SsaValue(1));
        assert_eq!(v1.interval.lo, Some(3));
        assert_eq!(v1.interval.hi, Some(7));
        // SsaValue(2): only in a → dropped to Top
        assert!(j.get(SsaValue(2)).is_top());
    }

    #[test]
    fn abstract_state_widen() {
        let mut old = AbstractState::empty();
        old.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact {
                    lo: Some(0),
                    hi: Some(5),
                },
                string: StringFact::top(),
                bits: BitFact::top(),
                path: PathFact::top(),
            },
        );

        let mut new = AbstractState::empty();
        new.set(
            SsaValue(1),
            AbstractValue {
                interval: IntervalFact {
                    lo: Some(0),
                    hi: Some(10),
                },
                string: StringFact::top(),
                bits: BitFact::top(),
                path: PathFact::top(),
            },
        );

        let w = old.widen(&new);
        let v1 = w.get(SsaValue(1));
        assert_eq!(v1.interval.lo, Some(0)); // stable
        assert_eq!(v1.interval.hi, None); // grew → widened
    }

    #[test]
    fn abstract_state_leq_respects_other_only_entries() {
        // self = empty (every value is implicitly Top).
        // other = { v1: [0,5] } (a non-Top, hence strictly-lower fact).
        // Since Top ⋢ [0,5], empty ⋢ other.
        let bounded = AbstractValue {
            interval: IntervalFact {
                lo: Some(0),
                hi: Some(5),
            },
            string: StringFact::top(),
            bits: BitFact::top(),
            path: PathFact::top(),
        };
        let empty = AbstractState::empty();
        let mut other = AbstractState::empty();
        other.set(SsaValue(1), bounded);

        // The bug under test: empty.leq(other) used to return true.
        assert!(
            !empty.leq(&other),
            "empty (Top everywhere) must not be ⊑ a state with a bounded entry"
        );
        // Sanity: the reverse direction holds (a bounded state ⊑ all-Top).
        assert!(other.leq(&empty), "a bounded state must be ⊑ all-Top");
        // Reflexivity still holds.
        assert!(other.leq(&other));
        assert!(empty.leq(&empty));
    }

    #[test]
    fn loop_carried_phi_join_and_widen() {
        // Simulate: x = 0; loop { x = phi(0, x+1) }
        // Iteration 1: join([0,0], [1,1]) = [0,1]
        let init = IntervalFact::exact(0);
        let inc1 = IntervalFact::exact(1);
        let phi1 = init.join(&inc1);
        assert_eq!(phi1.lo, Some(0));
        assert_eq!(phi1.hi, Some(1));

        // Iteration 2: join([0,1], [1,2]) = [0,2]
        let inc2 = IntervalFact {
            lo: Some(1),
            hi: Some(2),
        };
        let phi2 = phi1.join(&inc2);
        assert_eq!(phi2.lo, Some(0));
        assert_eq!(phi2.hi, Some(2));

        // Widen: [0,1] vs [0,2] → upper bound grew → [0, None]
        let widened = phi1.widen(&phi2);
        assert_eq!(widened.lo, Some(0));
        assert_eq!(widened.hi, None);

        // Iteration 3: join([0,None], [1,None]) = [0,None] (stable!)
        let inc3 = IntervalFact {
            lo: Some(1),
            hi: None,
        };
        let phi3 = widened.join(&inc3);
        assert_eq!(phi3.lo, Some(0));
        assert_eq!(phi3.hi, None);
        assert_eq!(phi3, widened); // converged
    }
}
