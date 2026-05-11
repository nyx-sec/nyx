//! String abstract domain for abstract interpretation.
//!
//! Tracks known prefix, suffix, and, when provably bounded, the finite set
//! of possible concrete string values. Used for SSRF suppression (URL prefix
//! proves host is locked), command-injection suppression (lookup result
//! bounded to a safe set of literals), and general string analysis.

use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};

/// Maximum tracked prefix length (bytes).
pub const MAX_PREFIX_LEN: usize = 256;
/// Maximum tracked suffix length (bytes).
pub const MAX_SUFFIX_LEN: usize = 128;
/// Maximum tracked finite-domain cardinality. Beyond this, `domain` widens
/// to `None` (Top on the domain sub-field).
pub const MAX_DOMAIN_SIZE: usize = 16;

/// Single-character shell metacharacters. A string containing any of these
/// cannot be passed as a single shell word without escaping, so bounded
/// sets containing them cannot suppress `Cap::SHELL_ESCAPE`.
const SHELL_METACHARS: &[char] = &[
    ';', '|', '&', '`', '$', '>', '<', '(', ')', '\n', '\r', '\0', '\\', '"', '\'', ' ', '\t',
];

/// Return `true` when `s` contains no shell metacharacter and is therefore
/// safe to pass as a single shell token.
pub fn is_shell_safe_literal(s: &str) -> bool {
    !s.chars().any(|c| SHELL_METACHARS.contains(&c))
}

/// String abstract domain: tracks known prefix, suffix, and finite domain.
///
/// Lattice ordering:
/// - `Bottom` ⊑ everything (unsatisfiable)
/// - Concrete facts ⊑ `Top` (no knowledge)
/// - `Some(prefix)` ⊑ `None` (no prefix known)
/// - `Some({a,b})` ⊑ `Some({a,b,c})` ⊑ `None` (subset → wider → Top)
///
/// Prefix, suffix, and domain are independent: a value can carry any subset
/// of the three.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringFact {
    /// Known prefix of the string. `None` = unknown.
    pub prefix: Option<String>,
    /// Known suffix of the string. `None` = unknown.
    pub suffix: Option<String>,
    /// Known finite set of possible concrete values. `None` = unknown set.
    /// `Some(vec)` with `vec.len() <= MAX_DOMAIN_SIZE` = value ∈ `vec`.
    /// Always sorted and deduped.
    pub domain: Option<Vec<String>>,
    /// True when this fact is Bottom (unsatisfiable).
    is_bottom: bool,
}

impl StringFact {
    /// Top: no knowledge about the string.
    pub fn top() -> Self {
        Self {
            prefix: None,
            suffix: None,
            domain: None,
            is_bottom: false,
        }
    }

    /// Bottom: unsatisfiable / empty set.
    pub fn bottom() -> Self {
        Self {
            prefix: None,
            suffix: None,
            domain: None,
            is_bottom: true,
        }
    }

    /// Exact known string value: prefix and suffix are the full string, and
    /// the finite domain is `{s}`.
    ///
    /// Empty prefix/suffix are normalised to `None` because "starts/ends with
    /// the empty string" carries no constraint, keeping `Some("")` would
    /// break join idempotence (`Some("")` ⊔ `Some("")` collapses to `None`).
    pub fn exact(s: &str) -> Self {
        let prefix = truncate_prefix(s);
        let suffix = truncate_suffix(s);
        Self {
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix)
            },
            suffix: if suffix.is_empty() {
                None
            } else {
                Some(suffix)
            },
            domain: Some(vec![s.to_string()]),
            is_bottom: false,
        }
    }

    /// Known prefix only. Empty `p` normalises to no-prefix-info (`None`).
    pub fn from_prefix(p: &str) -> Self {
        let prefix = truncate_prefix(p);
        Self {
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix)
            },
            suffix: None,
            domain: None,
            is_bottom: false,
        }
    }

    /// Known suffix only. Empty `s` normalises to no-suffix-info (`None`).
    pub fn from_suffix(s: &str) -> Self {
        let suffix = truncate_suffix(s);
        Self {
            prefix: None,
            suffix: if suffix.is_empty() {
                None
            } else {
                Some(suffix)
            },
            domain: None,
            is_bottom: false,
        }
    }

    /// Known finite set of possible concrete values.
    ///
    /// Inputs are sorted and deduped. If the cardinality exceeds
    /// [`MAX_DOMAIN_SIZE`] or the input is empty, the domain collapses to
    /// `None` (Top on this sub-field). The prefix/suffix sub-fields remain
    /// unset, callers can combine with [`Self::exact`] for single-element
    /// sets if tighter facts are desired.
    pub fn finite_set(values: Vec<String>) -> Self {
        let mut v = values;
        v.sort();
        v.dedup();
        let domain = if v.is_empty() || v.len() > MAX_DOMAIN_SIZE {
            None
        } else {
            Some(v)
        };
        Self {
            prefix: None,
            suffix: None,
            domain,
            is_bottom: false,
        }
    }

    pub fn is_top(&self) -> bool {
        !self.is_bottom && self.prefix.is_none() && self.suffix.is_none() && self.domain.is_none()
    }

    pub fn is_bottom(&self) -> bool {
        self.is_bottom
    }

    /// Returns `true` when the finite domain is known and every element is
    /// free of shell metacharacters. Used to suppress `Cap::SHELL_ESCAPE`
    /// when the payload is provably bounded to a safe set of words.
    pub fn is_finite_shell_safe(&self) -> bool {
        match &self.domain {
            Some(values) if !values.is_empty() => values.iter().all(|s| is_shell_safe_literal(s)),
            _ => false,
        }
    }

    // ── Lattice operations ──────────────────────────────────────────────

    /// Join: longest common prefix (LCP), longest common suffix (LCS), and
    /// set union of finite domains (clipped at [`MAX_DOMAIN_SIZE`]).
    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix = match (&self.prefix, &other.prefix) {
            (Some(a), Some(b)) => {
                let lcp = longest_common_prefix(a, b);
                if lcp.is_empty() { None } else { Some(lcp) }
            }
            _ => None,
        };
        let suffix = match (&self.suffix, &other.suffix) {
            (Some(a), Some(b)) => {
                let lcs = longest_common_suffix(a, b);
                if lcs.is_empty() { None } else { Some(lcs) }
            }
            _ => None,
        };
        let domain = match (&self.domain, &other.domain) {
            (Some(a), Some(b)) => {
                let mut merged: Vec<String> = Vec::with_capacity(a.len() + b.len());
                merged.extend_from_slice(a);
                merged.extend_from_slice(b);
                merged.sort();
                merged.dedup();
                if merged.len() > MAX_DOMAIN_SIZE {
                    None
                } else {
                    Some(merged)
                }
            }
            _ => None,
        };
        Self {
            prefix,
            suffix,
            domain,
            is_bottom: false,
        }
    }

    /// Meet: intersection of all three sub-fields (conservative).
    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom || other.is_bottom {
            return Self::bottom();
        }
        let prefix = match (&self.prefix, &other.prefix) {
            (Some(a), Some(b)) => {
                if a.starts_with(b.as_str()) {
                    Some(a.clone())
                } else if b.starts_with(a.as_str()) {
                    Some(b.clone())
                } else {
                    return Self::bottom();
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };
        let suffix = match (&self.suffix, &other.suffix) {
            (Some(a), Some(b)) => {
                if a.ends_with(b.as_str()) {
                    Some(a.clone())
                } else if b.ends_with(a.as_str()) {
                    Some(b.clone())
                } else {
                    return Self::bottom();
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };
        let domain = match (&self.domain, &other.domain) {
            (Some(a), Some(b)) => {
                let inter: Vec<String> = a
                    .iter()
                    .filter(|s| b.binary_search(s).is_ok())
                    .cloned()
                    .collect();
                if inter.is_empty() {
                    return Self::bottom();
                }
                Some(inter)
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };
        Self {
            prefix,
            suffix,
            domain,
            is_bottom: false,
        }
    }

    /// Widen: drop any sub-field that changed between iterations.
    pub fn widen(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix = if self.prefix == other.prefix {
            self.prefix.clone()
        } else {
            None
        };
        let suffix = if self.suffix == other.suffix {
            self.suffix.clone()
        } else {
            None
        };
        let domain = if self.domain == other.domain {
            self.domain.clone()
        } else {
            None
        };
        Self {
            prefix,
            suffix,
            domain,
            is_bottom: false,
        }
    }

    pub fn leq(&self, other: &Self) -> bool {
        if self.is_bottom {
            return true;
        }
        if other.is_bottom {
            return false;
        }
        let prefix_ok = match (&self.prefix, &other.prefix) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.starts_with(b.as_str()),
        };
        let suffix_ok = match (&self.suffix, &other.suffix) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.ends_with(b.as_str()),
        };
        let domain_ok = match (&self.domain, &other.domain) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.iter().all(|s| b.binary_search(s).is_ok()),
        };
        prefix_ok && suffix_ok && domain_ok
    }

    // ── Transfer functions ──────────────────────────────────────────────

    /// String concatenation: `self ++ other`.
    ///
    /// - Prefix of result = prefix of `self` (left operand)
    /// - Suffix of result = suffix of `other` (right operand)
    /// - Domain: cross-product is too explosive to track; collapse to `None`.
    pub fn concat(&self, other: &Self) -> Self {
        if self.is_bottom || other.is_bottom {
            return Self::bottom();
        }
        Self {
            prefix: self.prefix.clone(),
            suffix: other.suffix.clone(),
            domain: None,
            is_bottom: false,
        }
    }

    /// SSRF helper: build a fact for `new URL(path, base)` where `base` is a
    /// literal origin (`https://api.example.com`).  The result behaves as
    /// `base ++ path`, the locked-host prefix survives even when the path
    /// component carries arbitrary taint, and the fact's `prefix` is what
    /// `is_string_safe_for_ssrf` consults to suppress the SSRF sink.
    ///
    /// `path` carries any string knowledge for the path component (typically
    /// `StringFact::top()`).  When the base already ends in `/`, the helper
    /// keeps it as-is; otherwise appends a `/` so the prefix unambiguously
    /// includes the path separator (the SSRF check looks for
    /// `scheme://host/`).
    pub fn from_url_with_base(base: &str, path: &Self) -> Self {
        let mut anchor = base.to_string();
        if !anchor.ends_with('/') {
            anchor.push('/');
        }
        StringFact::exact(&anchor).concat(path)
    }
}

impl Lattice for StringFact {
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

impl AbstractDomain for StringFact {
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

// ── Helpers ─────────────────────────────────────────────────────────────

fn truncate_prefix(s: &str) -> String {
    if s.len() <= MAX_PREFIX_LEN {
        s.to_string()
    } else {
        // Find a char boundary at or before MAX_PREFIX_LEN
        let mut end = MAX_PREFIX_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

fn truncate_suffix(s: &str) -> String {
    if s.len() <= MAX_SUFFIX_LEN {
        s.to_string()
    } else {
        let start = s.len() - MAX_SUFFIX_LEN;
        let mut start = start;
        while start < s.len() && !s.is_char_boundary(start) {
            start += 1;
        }
        s[start..].to_string()
    }
}

/// Longest common prefix of two strings, char-aligned.
///
/// Iterates by `char` rather than `byte` so multi-byte UTF-8 code points are
/// either kept whole or dropped, a byte-wise comparison would slice into the
/// middle of a code point and produce mojibake (`x as char` on a UTF-8
/// continuation byte yields a garbage Latin-1 character).
pub fn longest_common_prefix(a: &str, b: &str) -> String {
    a.chars()
        .zip(b.chars())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x)
        .collect()
}

/// Longest common suffix of two strings, char-aligned.
pub fn longest_common_suffix(a: &str, b: &str) -> String {
    let mut lcs: Vec<char> = a
        .chars()
        .rev()
        .zip(b.chars().rev())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x)
        .collect();
    lcs.reverse();
    lcs.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_and_bottom() {
        assert!(StringFact::top().is_top());
        assert!(!StringFact::top().is_bottom());
        assert!(StringFact::bottom().is_bottom());
        assert!(!StringFact::bottom().is_top());
    }

    #[test]
    fn exact_sets_both() {
        let f = StringFact::exact("hello");
        assert_eq!(f.prefix.as_deref(), Some("hello"));
        assert_eq!(f.suffix.as_deref(), Some("hello"));
        assert_eq!(f.domain.as_deref(), Some(&["hello".to_string()][..]));
    }

    // ── LCP / LCS helpers ───────────────────────────────────────────

    #[test]
    fn lcp_basic() {
        assert_eq!(longest_common_prefix("abcdef", "abcxyz"), "abc");
        assert_eq!(longest_common_prefix("abc", "abc"), "abc");
        assert_eq!(longest_common_prefix("abc", "xyz"), "");
        assert_eq!(longest_common_prefix("", "abc"), "");
    }

    #[test]
    fn lcs_basic() {
        assert_eq!(longest_common_suffix("hello.json", "world.json"), ".json");
        assert_eq!(longest_common_suffix("abc", "xyz"), "");
        assert_eq!(longest_common_suffix("abc", "abc"), "abc");
    }

    // ── Join ────────────────────────────────────────────────────────

    #[test]
    fn join_same_prefix() {
        let a = StringFact::from_prefix("https://api.com/users/");
        let b = StringFact::from_prefix("https://api.com/items/");
        let j = a.join(&b);
        assert_eq!(j.prefix.as_deref(), Some("https://api.com/"));
    }

    #[test]
    fn join_no_common_prefix() {
        let a = StringFact::from_prefix("https://a.com/");
        let b = StringFact::from_prefix("http://b.com/");
        let j = a.join(&b);
        assert_eq!(j.prefix.as_deref(), Some("http")); // common: "http"
    }

    #[test]
    fn join_suffix() {
        let a = StringFact::from_suffix(".json");
        let b = StringFact::from_suffix(".json");
        assert_eq!(a.join(&b).suffix.as_deref(), Some(".json"));
    }

    #[test]
    fn join_different_suffix() {
        let a = StringFact::from_suffix(".json");
        let b = StringFact::from_suffix(".xml");
        assert_eq!(a.join(&b).suffix, None);
    }

    #[test]
    fn join_with_bottom() {
        let a = StringFact::from_prefix("hello");
        assert_eq!(a.join(&StringFact::bottom()), a);
        assert_eq!(StringFact::bottom().join(&a), a);
    }

    #[test]
    fn join_finite_sets_union() {
        let a = StringFact::finite_set(vec!["ls".into(), "cat".into()]);
        let b = StringFact::finite_set(vec!["true".into(), "ls".into()]);
        let j = a.join(&b);
        let d = j.domain.expect("union");
        assert_eq!(d, vec!["cat", "ls", "true"]);
    }

    #[test]
    fn join_finite_sets_overflow_to_top() {
        // 9 + 9 = 18 > MAX_DOMAIN_SIZE = 16 → domain collapses to None.
        let a = StringFact::finite_set((0..9).map(|n| format!("a{n}")).collect::<Vec<_>>());
        let b = StringFact::finite_set((0..9).map(|n| format!("b{n}")).collect::<Vec<_>>());
        let j = a.join(&b);
        assert!(j.domain.is_none());
    }

    #[test]
    fn join_unknown_domain_yields_top() {
        let a = StringFact::finite_set(vec!["x".into()]);
        let b = StringFact::from_prefix("x");
        assert!(a.join(&b).domain.is_none());
    }

    // ── Meet ────────────────────────────────────────────────────────

    #[test]
    fn meet_consistent_prefix() {
        let a = StringFact::from_prefix("https://");
        let b = StringFact::from_prefix("https://api.com/");
        let m = a.meet(&b);
        assert_eq!(m.prefix.as_deref(), Some("https://api.com/"));
    }

    #[test]
    fn meet_contradictory_prefix() {
        let a = StringFact::from_prefix("https://a.com/");
        let b = StringFact::from_prefix("https://b.com/");
        assert!(a.meet(&b).is_bottom());
    }

    #[test]
    fn meet_finite_sets_intersect() {
        let a = StringFact::finite_set(vec!["ls".into(), "cat".into(), "true".into()]);
        let b = StringFact::finite_set(vec!["ls".into(), "true".into()]);
        let m = a.meet(&b);
        assert_eq!(
            m.domain.as_deref(),
            Some(&["ls".to_string(), "true".to_string()][..])
        );
    }

    #[test]
    fn meet_finite_sets_empty_is_bottom() {
        let a = StringFact::finite_set(vec!["ls".into()]);
        let b = StringFact::finite_set(vec!["cat".into()]);
        assert!(a.meet(&b).is_bottom());
    }

    // ── Widen ───────────────────────────────────────────────────────

    #[test]
    fn widen_stable() {
        let a = StringFact::from_prefix("https://api.com/");
        assert_eq!(a.widen(&a), a);
    }

    #[test]
    fn widen_changed_prefix() {
        let old = StringFact::from_prefix("https://api.com/v1/");
        let new = StringFact::from_prefix("https://api.com/v2/");
        let w = old.widen(&new);
        assert_eq!(w.prefix, None); // changed → dropped
    }

    #[test]
    fn widen_changed_domain() {
        let old = StringFact::finite_set(vec!["ls".into()]);
        let new = StringFact::finite_set(vec!["ls".into(), "cat".into()]);
        assert!(old.widen(&new).domain.is_none());
    }

    // ── Concat ──────────────────────────────────────────────────────

    #[test]
    fn concat_exact() {
        let a = StringFact::exact("hello");
        let b = StringFact::exact(" world");
        let c = a.concat(&b);
        assert_eq!(c.prefix.as_deref(), Some("hello"));
        assert_eq!(c.suffix.as_deref(), Some(" world"));
        // domain drops because cross-product is not tracked
        assert!(c.domain.is_none());
    }

    #[test]
    fn concat_prefix_with_top() {
        let a = StringFact::from_prefix("https://api.com/");
        let b = StringFact::top();
        let c = a.concat(&b);
        assert_eq!(c.prefix.as_deref(), Some("https://api.com/"));
        assert_eq!(c.suffix, None);
    }

    #[test]
    fn concat_top_with_suffix() {
        let a = StringFact::top();
        let b = StringFact::from_suffix(".json");
        let c = a.concat(&b);
        assert_eq!(c.prefix, None);
        assert_eq!(c.suffix.as_deref(), Some(".json"));
    }

    // ── Leq ─────────────────────────────────────────────────────────

    #[test]
    fn leq_more_specific_prefix() {
        let specific = StringFact::from_prefix("https://api.com/users/");
        let general = StringFact::from_prefix("https://api.com/");
        assert!(specific.leq(&general));
        assert!(!general.leq(&specific));
    }

    #[test]
    fn leq_top_greatest() {
        let a = StringFact::from_prefix("hello");
        assert!(a.leq(&StringFact::top()));
        assert!(!StringFact::top().leq(&a));
    }

    #[test]
    fn leq_bottom_least() {
        assert!(StringFact::bottom().leq(&StringFact::top()));
        assert!(StringFact::bottom().leq(&StringFact::from_prefix("x")));
    }

    #[test]
    fn leq_finite_subset() {
        let sub = StringFact::finite_set(vec!["ls".into()]);
        let sup = StringFact::finite_set(vec!["ls".into(), "cat".into()]);
        assert!(sub.leq(&sup));
        assert!(!sup.leq(&sub));
    }

    // ── Finite-set / shell safety ───────────────────────────────────

    #[test]
    fn finite_set_sorts_and_dedups() {
        let f = StringFact::finite_set(vec!["b".into(), "a".into(), "a".into()]);
        assert_eq!(
            f.domain.as_deref(),
            Some(&["a".to_string(), "b".to_string()][..])
        );
    }

    #[test]
    fn finite_set_overflow_is_top() {
        let many: Vec<String> = (0..(MAX_DOMAIN_SIZE + 1))
            .map(|n| format!("v{n}"))
            .collect();
        let f = StringFact::finite_set(many);
        assert!(f.domain.is_none());
    }

    #[test]
    fn finite_set_empty_is_top() {
        let f = StringFact::finite_set(vec![]);
        assert!(f.domain.is_none());
        assert!(f.is_top());
    }

    #[test]
    fn shell_safe_detects_metachars() {
        assert!(is_shell_safe_literal("ls"));
        assert!(is_shell_safe_literal("cat"));
        assert!(is_shell_safe_literal("no-metachars"));
        assert!(!is_shell_safe_literal("rm;reboot"));
        assert!(!is_shell_safe_literal("echo $HOME"));
        assert!(!is_shell_safe_literal("a|b"));
        assert!(!is_shell_safe_literal("a b")); // whitespace splits shell words
    }

    #[test]
    fn is_finite_shell_safe_only_when_bounded() {
        assert!(!StringFact::top().is_finite_shell_safe());
        assert!(!StringFact::from_prefix("ls").is_finite_shell_safe());
        assert!(StringFact::finite_set(vec!["ls".into(), "cat".into()]).is_finite_shell_safe());
        assert!(
            !StringFact::finite_set(vec!["ls".into(), "rm;reboot".into()]).is_finite_shell_safe()
        );
    }

    /// `concat("", x)` and `concat(x, "")` must round-trip the
    /// non-empty operand's prefix/suffix. The current `concat` keeps
    /// LHS prefix and RHS suffix verbatim. After empty-string
    /// normalisation, `exact("")` carries no prefix/suffix info, so
    /// the LHS prefix is `None` (unknown) and only the RHS suffix
    /// survives.
    #[test]
    fn concat_empty_string_lhs_preserves_rhs_suffix() {
        let empty = StringFact::exact("");
        let rhs = StringFact::exact("x");
        let r = empty.concat(&rhs);
        assert_eq!(r.prefix, None);
        assert_eq!(r.suffix.as_deref(), Some("x"));
    }

    #[test]
    fn concat_empty_string_rhs_preserves_lhs_prefix() {
        let lhs = StringFact::exact("x");
        let empty = StringFact::exact("");
        let r = lhs.concat(&empty);
        assert_eq!(r.prefix.as_deref(), Some("x"));
        assert_eq!(r.suffix, None);
    }

    /// Bottom is concat-absorbing: concat with bottom in either
    /// position yields bottom (no flow can reach the call site).
    #[test]
    fn concat_with_bottom_is_bottom() {
        let bot = StringFact::bottom();
        let any = StringFact::exact("anything");
        assert!(bot.concat(&any).is_bottom());
        assert!(any.concat(&bot).is_bottom());
    }

    /// Joining two distinct URL prefixes must reduce to their LCP, not
    /// fall through to `None`. This is the property SSRF prefix-lock
    /// suppression depends on at phi nodes.
    #[test]
    fn join_distinct_urls_reduces_to_lcp() {
        let a = StringFact::from_prefix("https://api.example.com/");
        let b = StringFact::from_prefix("https://db.example.com/");
        let r = a.join(&b);
        // Common prefix is "https://", anything past that diverges.
        assert_eq!(
            r.prefix.as_deref(),
            Some("https://"),
            "join must compute LCP, not drop the prefix entirely"
        );
    }

    /// Meet of two prefix-locks with no overlap must collapse to
    /// bottom (it represents an unsatisfiable conjunction).
    #[test]
    fn meet_disjoint_prefixes_is_bottom() {
        let a = StringFact::from_prefix("/var/");
        let b = StringFact::from_prefix("/etc/");
        let r = a.meet(&b);
        assert!(
            r.is_bottom(),
            "meet of disjoint prefix-locks must be bottom"
        );
    }

    // ── Additional lattice algebra laws ──────────────────────────────

    fn sample_strings() -> Vec<StringFact> {
        vec![
            StringFact::bottom(),
            StringFact::top(),
            StringFact::exact(""),
            StringFact::exact("hello"),
            StringFact::from_prefix("https://"),
            StringFact::from_suffix(".com"),
            StringFact::finite_set(vec!["a".into(), "b".into()]),
        ]
    }

    /// `x ⊔ x = x`, join is idempotent across all sample shapes.
    #[test]
    fn join_idempotent_string() {
        for a in sample_strings() {
            assert_eq!(a.join(&a), a, "join not idempotent for {:?}", a);
        }
    }

    /// `x ⊔ y = y ⊔ x`, join is commutative.
    #[test]
    fn join_commutative_string() {
        let xs = sample_strings();
        for a in &xs {
            for b in &xs {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "join not commutative for {:?} / {:?}",
                    a,
                    b
                );
            }
        }
    }

    /// `x ⊓ x = x`, meet is idempotent.
    #[test]
    fn meet_idempotent_string() {
        for a in sample_strings() {
            assert_eq!(a.meet(&a), a, "meet not idempotent for {:?}", a);
        }
    }

    /// `x ⊓ y = y ⊓ x`, meet is commutative.
    #[test]
    fn meet_commutative_string() {
        let xs = sample_strings();
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

    /// `x ⊓ ⊤ = x` and `x ⊓ ⊥ = ⊥`.
    #[test]
    fn meet_identity_string() {
        for a in sample_strings() {
            assert_eq!(a.meet(&StringFact::top()), a, "x ⊓ ⊤ failed for {:?}", a);
            assert!(
                a.meet(&StringFact::bottom()).is_bottom(),
                "x ⊓ ⊥ failed for {:?}",
                a
            );
        }
    }

    /// `x ⊑ x`, leq is reflexive.
    #[test]
    fn leq_reflexive_string() {
        for a in sample_strings() {
            assert!(a.leq(&a), "x ⊑ x failed for {:?}", a);
        }
    }

    /// **Soundness**: `widen(a, b) ⊒ join(a, b)`, widening must
    /// over-approximate join, otherwise dataflow loses information.
    #[test]
    fn widen_over_approximates_join_string() {
        let xs = sample_strings();
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
    fn widen_idempotent_string() {
        for a in sample_strings() {
            assert_eq!(a.widen(&a), a, "widen(x, x) failed for {:?}", a);
        }
    }

    /// Join is upper bound: `a ⊑ a ⊔ b` and `b ⊑ a ⊔ b`.
    #[test]
    fn join_is_upper_bound_string() {
        let xs = sample_strings();
        for a in &xs {
            for b in &xs {
                let j = a.join(b);
                assert!(
                    a.leq(&j),
                    "a ⊑ a ⊔ b failed for {:?}, {:?} (join={:?})",
                    a,
                    b,
                    j
                );
                assert!(
                    b.leq(&j),
                    "b ⊑ a ⊔ b failed for {:?}, {:?} (join={:?})",
                    a,
                    b,
                    j
                );
            }
        }
    }

    /// Empty-string exact value must distinguish from Top, it is a
    /// singleton (`{""}`), not unconstrained. After the empty-prefix
    /// normalisation, prefix/suffix are `None` (carry no extra info)
    /// but the `domain` field still pins the value to exactly `""`.
    #[test]
    fn exact_empty_string_is_not_top() {
        let e = StringFact::exact("");
        assert!(!e.is_top(), "exact(\"\") must not be Top");
        assert!(!e.is_bottom(), "exact(\"\") must not be Bottom");
        assert_eq!(e.prefix, None, "empty prefix normalised to None");
        assert_eq!(e.suffix, None, "empty suffix normalised to None");
        assert_eq!(e.domain.as_deref(), Some(&[String::new()][..]));
    }

    /// LCP/LCS with multi-byte UTF-8 chars must not split a code point
    /// (would produce invalid UTF-8 strings or panic).
    #[test]
    fn lcp_lcs_unicode_safe() {
        // Both start with é (2-byte char in UTF-8).
        let a = StringFact::exact("éclair");
        let b = StringFact::exact("éclat");
        let j = a.join(&b);
        // LCP should be "écla" (still valid UTF-8). At minimum it must
        // be a valid Rust string and not panic.
        let prefix = j.prefix.as_deref().unwrap_or("");
        assert!(prefix.is_char_boundary(prefix.len()));
        assert!(prefix.starts_with('é'));

        // Suffix with multibyte: "café" vs "naïvé" share "é" suffix?
        // Simpler: both end with "好" (3-byte CJK).
        let a = StringFact::exact("你好");
        let b = StringFact::exact("您好");
        let j = a.join(&b);
        let suffix = j.suffix.as_deref().unwrap_or("");
        assert!(suffix.is_char_boundary(0) && suffix.is_char_boundary(suffix.len()));
        assert!(suffix.ends_with('好'));
    }

    /// Phase 08: a URL prefix-lock obtained from `new URL(path, base)`
    /// must survive concatenation with a tainted (Top-suffix) path
    /// component. The `is_string_safe_for_ssrf` check only consults the
    /// `prefix`, so the locked-host base must remain intact even when the
    /// path-side fact carries no knowledge.
    #[test]
    fn from_url_with_base_locks_prefix_under_tainted_suffix() {
        let base = "https://api.cal.com";
        let tainted_path = StringFact::top();
        let f = StringFact::from_url_with_base(base, &tainted_path);
        assert_eq!(
            f.prefix.as_deref(),
            Some("https://api.cal.com/"),
            "prefix lock must include the path separator"
        );
        // The path component contributes no suffix knowledge, the result
        // must mirror that without losing the prefix lock.
        assert!(
            f.suffix.is_none(),
            "suffix is unknown when path-side fact is Top"
        );
    }

    /// A concrete path component contributes its suffix knowledge to the
    /// concatenated URL fact while the base prefix stays locked.
    #[test]
    fn from_url_with_base_keeps_prefix_with_concrete_path_suffix() {
        let base = "https://api.cal.com/";
        let path = StringFact::from_suffix(".json");
        let f = StringFact::from_url_with_base(base, &path);
        assert_eq!(f.prefix.as_deref(), Some("https://api.cal.com/"));
        assert_eq!(f.suffix.as_deref(), Some(".json"));
    }

    /// Concat with empty-string `exact("")` should preserve the other
    /// side's prefix/suffix knowledge (empty is the identity).
    #[test]
    fn concat_with_empty_exact_preserves_other() {
        let s = StringFact::exact("hello");
        let e = StringFact::exact("");
        let r = s.concat(&e);
        // Concat should preserve prefix from `s`.
        assert_eq!(r.prefix.as_deref(), Some("hello"));
        let r2 = e.concat(&s);
        assert_eq!(r2.suffix.as_deref(), Some("hello"));
    }
}
