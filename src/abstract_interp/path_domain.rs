//! Path abstract domain for abstract interpretation.
//!
//! Tracks the abstract effect of path-sanitizer primitives on filesystem path
//! values along three independent axes:
//!
//! - `dotdot`: whether the path contains a `..` component
//! - `absolute`: whether the path is absolute (rooted at `/`, `\\`, `C:\\`, …)
//! - `normalized`: whether the path has been passed through a canonicalisation
//!   / structural filter step (e.g. `fs::canonicalize`, `Component::Normal`
//!   iterator filter)
//!
//! Plus a `prefix_lock` that records the known canonical root of the path
//! after a `starts_with(root_literal)` guard has been asserted on it.
//!
//! Each axis is a three-value lattice [`Tri::No`] / [`Tri::Yes`] / [`Tri::Maybe`]
//! where `Maybe` is Top (unknown) and `No` / `Yes` are the two definite
//! refinements.  A value is path-safe for a FILE_IO sink iff
//! `dotdot == No && absolute == No`, i.e. we have proof that *no* `..`
//! component and *no* absolute root can leak through.  `normalized == Yes`
//! alone is not sufficient (canonicalising an absolute input still produces
//! an absolute path); prefix_lock is used separately to certify containment
//! under a known root.
//!
//! This domain is Rust-first: the transfer rules wired from
//! `src/taint/ssa_transfer` recognise Rust's standard library path primitives
//! (`fs::canonicalize`, `Path::new`, `.starts_with`, `.components`, …).
//! Per-language extension slots live alongside those transfer rules; this
//! file defines only the lattice and its laws.

use crate::state::lattice::{AbstractDomain, Lattice};
use serde::{Deserialize, Serialize};

/// Maximum length (bytes) of a tracked prefix-lock root.  Bounds on-disk
/// summary size for callees that stamp a long canonical root onto every
/// return value.
pub const MAX_PREFIX_LOCK_LEN: usize = 128;

/// Three-value lattice: proven-absent, proven-present, or unknown.
///
/// Ordering (join-semilattice where [`Tri::Maybe`] is Top):
///
/// - `No ⊑ Maybe`, `Yes ⊑ Maybe`
/// - `No` and `Yes` are **incomparable** (both are strict refinements of
///   `Maybe`, but neither subsumes the other).
/// - `join(No, No) = No`, `join(Yes, Yes) = Yes`, otherwise `Maybe`.
/// - `meet(Maybe, x) = x`, `meet(No, No) = No`, `meet(Yes, Yes) = Yes`,
///   `meet(No, Yes)` is contradictory (represented by the enclosing
///   [`PathFact`]'s bottom flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tri {
    /// Proven absent (`..` component not present, path not absolute, etc.).
    No,
    /// Proven present.
    Yes,
    /// Unknown, no transfer or guard has proved the axis yet.
    Maybe,
}

impl Tri {
    pub fn top() -> Self {
        Tri::Maybe
    }

    pub fn is_top(&self) -> bool {
        matches!(self, Tri::Maybe)
    }

    /// Join: least upper bound.  Equal values are preserved; disagreements
    /// widen to [`Tri::Maybe`].
    pub fn join(&self, other: &Self) -> Self {
        match (*self, *other) {
            (a, b) if a == b => a,
            _ => Tri::Maybe,
        }
    }

    /// Meet: greatest lower bound.  `Maybe ⊓ x = x`; disagreement between
    /// `No` and `Yes` is contradictory and returns [`None`].  Callers convert
    /// the resulting [`Option`] into a `PathFact` bottom flag at the product
    /// level.
    pub fn meet_checked(&self, other: &Self) -> Option<Self> {
        match (*self, *other) {
            (Tri::Maybe, x) | (x, Tri::Maybe) => Some(x),
            (a, b) if a == b => Some(a),
            _ => None,
        }
    }

    /// Widen: drop to `Maybe` on any change.
    pub fn widen(&self, other: &Self) -> Self {
        if self == other { *self } else { Tri::Maybe }
    }

    /// Partial order: `self ⊑ other`.
    pub fn leq(&self, other: &Self) -> bool {
        match (*self, *other) {
            (_, Tri::Maybe) => true,
            (a, b) => a == b,
        }
    }
}

/// Path abstract fact.
///
/// Product of three [`Tri`] axes plus an optional canonical-prefix root.
/// The empty (`default()`) fact is Top on every axis: the abstract path
/// could be any filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathFact {
    /// Does the path contain a `..` component?
    pub dotdot: Tri,
    /// Is the path absolute (rooted at `/`, `\`, drive letter)?
    pub absolute: Tri,
    /// Has the path been passed through a canonicalisation / component filter?
    pub normalized: Tri,
    /// Canonical root the path was proved to start with.  `None` = unknown.
    pub prefix_lock: Option<String>,
    /// True when the fact is contradictory (e.g. two irreconcilable meets).
    /// Carried as a flag rather than a sentinel so the primary path stays
    /// allocation-free.
    is_bottom: bool,
}

impl Default for PathFact {
    fn default() -> Self {
        Self::top()
    }
}

impl PathFact {
    /// Top: no knowledge on any axis.
    pub fn top() -> Self {
        Self {
            dotdot: Tri::Maybe,
            absolute: Tri::Maybe,
            normalized: Tri::Maybe,
            prefix_lock: None,
            is_bottom: false,
        }
    }

    /// Bottom: unsatisfiable / empty set.
    pub fn bottom() -> Self {
        Self {
            dotdot: Tri::Maybe,
            absolute: Tri::Maybe,
            normalized: Tri::Maybe,
            prefix_lock: None,
            is_bottom: true,
        }
    }

    pub fn is_top(&self) -> bool {
        !self.is_bottom
            && self.dotdot == Tri::Maybe
            && self.absolute == Tri::Maybe
            && self.normalized == Tri::Maybe
            && self.prefix_lock.is_none()
    }

    pub fn is_bottom(&self) -> bool {
        self.is_bottom
    }

    /// Construct a fact after a sanitisation step that clears `..` components.
    pub fn with_dotdot_cleared(mut self) -> Self {
        self.dotdot = Tri::No;
        self
    }

    /// Construct a fact after a sanitisation step that clears absolute roots.
    pub fn with_absolute_cleared(mut self) -> Self {
        self.absolute = Tri::No;
        self
    }

    /// Construct a fact after a normalisation step (canonicalize / components
    /// filter).  Sets `normalized = Yes` and clears `..`.  Absolute axis is
    /// **not** touched by default: `canonicalize("/etc/passwd")` stays
    /// absolute, the plan's `canonicalize` transfer rule sets
    /// `absolute = Yes` separately.
    pub fn with_normalized(mut self) -> Self {
        self.normalized = Tri::Yes;
        self.dotdot = Tri::No;
        self
    }

    /// Attach a prefix-lock root (the argument of a proven `starts_with`
    /// guard).  Truncates to [`MAX_PREFIX_LOCK_LEN`] on a char boundary so
    /// on-disk summary size stays bounded.
    pub fn with_prefix_lock(mut self, root: &str) -> Self {
        if root.is_empty() {
            return self;
        }
        self.prefix_lock = Some(truncate_prefix_lock(root));
        self
    }

    /// True iff the fact proves both `dotdot = No` and `absolute = No`.
    ///
    /// This is the core sink-suppression predicate: a relative, `..`-free
    /// path can still escape into a parent via a symlink, but it cannot
    /// reach an attacker-controlled absolute location and cannot contain
    /// explicit parent-dir components, which together cover the
    /// documented rs-safe-0** FPs.
    pub fn is_path_safe(&self) -> bool {
        !self.is_bottom && self.dotdot == Tri::No && self.absolute == Tri::No
    }

    /// True iff the fact proves the path stays inside a trusted region
    /// for path-traversal purposes (the FILE_IO sink-suppression
    /// predicate).
    ///
    /// Accepts either of two structural invariants:
    ///
    /// * `dotdot = No && absolute = No` — the relative-and-`..`-free
    ///   shape recognised by `is_path_safe`.  Cannot escape to an
    ///   attacker-controlled absolute location.
    /// * `dotdot = No && prefix_lock.is_some()` — a canonicalised path
    ///   (typically `File.expand_path` / `realpath` / `fs::canonicalize`)
    ///   that has been verified-rooted by a `starts_with`-style guard
    ///   against some prefix.  The prefix may be opaque
    ///   ([`OPAQUE_PREFIX_LOCK`]); the structural guarantee is the same:
    ///   the path is provably inside the locked subtree.
    ///
    /// This relaxation closes the rswag CVE-2023-38337 patched-counterpart
    /// FP shape (`File.expand_path(File.join(root, p)) + start_with? root`)
    /// and the equivalent Python (`os.path.realpath + .startswith(root)`)
    /// and JS (`path.resolve + .startsWith(root)`) idioms, all of which
    /// produce absolute paths but are sound against `..` traversal.
    pub fn is_path_traversal_safe(&self) -> bool {
        if self.is_bottom || self.dotdot != Tri::No {
            return false;
        }
        self.absolute == Tri::No || self.prefix_lock.is_some()
    }

    /// True iff the fact has a prefix lock equal to or contained under
    /// `root`.  Used by sink-suppression to confirm that a path derived
    /// from a locked root is provably still under that root.
    pub fn prefix_locked_under(&self, root: &str) -> bool {
        match &self.prefix_lock {
            Some(p) => p.starts_with(root) || root.starts_with(p.as_str()),
            None => false,
        }
    }

    // ── Lattice operations ──────────────────────────────────────────────

    pub fn join(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix_lock = match (&self.prefix_lock, &other.prefix_lock) {
            (Some(a), Some(b)) => {
                // Longest common prefix; drop to None when LCP is empty.
                let lcp = longest_common_prefix(a, b);
                if lcp.is_empty() {
                    None
                } else {
                    Some(truncate_prefix_lock(&lcp))
                }
            }
            _ => None,
        };
        Self {
            dotdot: self.dotdot.join(&other.dotdot),
            absolute: self.absolute.join(&other.absolute),
            normalized: self.normalized.join(&other.normalized),
            prefix_lock,
            is_bottom: false,
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        if self.is_bottom || other.is_bottom {
            return Self::bottom();
        }
        let (dotdot, abs, norm) = match (
            self.dotdot.meet_checked(&other.dotdot),
            self.absolute.meet_checked(&other.absolute),
            self.normalized.meet_checked(&other.normalized),
        ) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return Self::bottom(),
        };
        let prefix_lock = match (&self.prefix_lock, &other.prefix_lock) {
            (Some(a), Some(b)) => {
                // Consistent when one is a prefix of the other; pick the
                // more specific (longer) root.  Otherwise contradictory.
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
        Self {
            dotdot,
            absolute: abs,
            normalized: norm,
            prefix_lock,
            is_bottom: false,
        }
    }

    pub fn widen(&self, other: &Self) -> Self {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        let prefix_lock = if self.prefix_lock == other.prefix_lock {
            self.prefix_lock.clone()
        } else {
            None
        };
        Self {
            dotdot: self.dotdot.widen(&other.dotdot),
            absolute: self.absolute.widen(&other.absolute),
            normalized: self.normalized.widen(&other.normalized),
            prefix_lock,
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
        let prefix_ok = match (&self.prefix_lock, &other.prefix_lock) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(a), Some(b)) => a.starts_with(b.as_str()),
        };
        prefix_ok
            && self.dotdot.leq(&other.dotdot)
            && self.absolute.leq(&other.absolute)
            && self.normalized.leq(&other.normalized)
    }
}

impl Lattice for PathFact {
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

impl AbstractDomain for PathFact {
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

// ── Rust path-primitive classifiers ─────────────────────────────────────
//
// Per-language extension slot: each new language that wants to participate in
// PathFact should add its own classifier module and dispatch from
// `src/taint/ssa_transfer/mod.rs` on `transfer.lang`.  Rust is wired here
// because the initial rs-safe-0** closure targets Rust idioms; Python's
// `os.path.normpath`, Java's `Path.normalize`, and Go's `filepath.Clean`
// would slot in alongside.

/// Classification of a branch-condition text against Rust path-rejection
/// idioms.  The *rejection* interpretation is: when the condition is TRUE
/// the enclosing branch rejects (returns, panics, throws); when FALSE the
/// narrowed axis can be proved safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRejection {
    /// `x.contains("..")`, false branch proves `dotdot = No` on the receiver.
    DotDot,
    /// `x.starts_with("/")` / `x.starts_with('\\')`, false branch proves
    /// `absolute = No` on the receiver.
    AbsoluteSlash,
    /// `x.is_absolute()` / `Path::new(x).is_absolute()`, false branch proves
    /// `absolute = No` on the argument/receiver.
    IsAbsolute,
    /// Not a path-rejection idiom.
    None,
}

/// Classification of a branch-condition text against Rust path *positive*
/// assertion idioms.  When the condition is TRUE on the enclosing branch,
/// the listed axis is refined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAssertion {
    /// `x.starts_with("<literal_root>")`, true branch attaches
    /// `prefix_lock = Some("<literal_root>")` to the receiver.
    PrefixLock(String),
    /// Not a path-assertion idiom.
    None,
}

/// Sentinel root attached to a [`PathFact::prefix_lock`] when the
/// `starts_with`-style guard's argument is non-literal (a method call,
/// field access, configured root from the application).  The structural
/// invariant — "verified rooted under SOME prefix" — is what the sink-
/// suppression layer needs; the *exact* prefix bytes are not.  Combined
/// with a `dotdot=No` proof from canonicalisation or `..`-rejection, an
/// opaque prefix-lock is sufficient to prove the path stays inside a
/// trusted region.
pub const OPAQUE_PREFIX_LOCK: &str = "__nyx_opaque_prefix__";

/// Recognise a Rust path-rejection branch idiom from the raw condition text.
///
/// Accepts both atomic conditions (`x.contains("..")`) and multi-clause
/// disjunctions (`x.contains("..") || x.starts_with('/') || ...`).  For
/// disjunctions the false branch implies **every** clause is false, so the
/// classifier returns the **first** recognised axis; callers should also
/// invoke [`classify_path_rejection_axes`] to pick up every axis covered
/// by an OR-chain.  Conservative: returns [`PathRejection::None`] when no
/// path-rejection clause is found.
pub fn classify_path_rejection(text: &str) -> PathRejection {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return PathRejection::None;
    }
    // Multi-clause OR: return the first recognised axis (callers should
    // use `classify_path_rejection_axes` for the full set).
    let axes = classify_path_rejection_axes(trimmed);
    if axes.is_empty() {
        return PathRejection::None;
    }
    axes[0]
}

/// Recognise every path-rejection axis covered by the condition, handling
/// disjunctions (`a || b || c`) by classifying each clause independently
/// and returning the union of recognised rejections.
///
/// The false branch of the whole condition implies all clauses are false,
/// so every recognised axis narrows on the false branch.
pub fn classify_path_rejection_axes(text: &str) -> smallvec::SmallVec<[PathRejection; 3]> {
    let mut out: smallvec::SmallVec<[PathRejection; 3]> = smallvec::SmallVec::new();
    for clause in split_top_level_or(text) {
        let clause = clause.trim();
        // Multi-axis special case: `!filepath.IsLocal(p)` (Go).
        // `filepath.IsLocal` returns true iff the path stays within the
        // current directory, no leading `/`, no `..` segments, no Windows
        // drive root.  Idiomatic Go path-traversal guard:
        //   `if !filepath.IsLocal(p) { return }`
        // The TRUE branch terminates; the FALSE branch (where IsLocal is
        // true) proves both `dotdot = No` and `absolute = No` on the
        // argument simultaneously.  Recognise it here so both axes flow
        // into the surviving branch's PathFact narrowing.
        if has_negated_filepath_is_local(clause) {
            for axis in [PathRejection::DotDot, PathRejection::IsAbsolute] {
                if !out.contains(&axis) {
                    out.push(axis);
                }
            }
            continue;
        }
        let cls = classify_path_rejection_atom(clause);
        if !matches!(cls, PathRejection::None) && !out.contains(&cls) {
            out.push(cls);
        }
    }
    out
}

/// True iff any top-level OR clause of `text` is the pre-negated
/// `!filepath.IsLocal(<expr>)` Go idiom — i.e. a clause whose `!` is
/// already consumed by [`classify_path_rejection_axes`] when reporting
/// the safe arm.  Callers use this to decide whether AST-level negation
/// (`condition_negated`) was already accounted for by the classifier
/// (returns `true`) or still needs to flip the safe-arm polarity for
/// polarity-blind atoms like `!path.contains("..")` (returns `false`).
pub(crate) fn cond_has_pre_negated_islocal_clause(text: &str) -> bool {
    for clause in split_top_level_or(text) {
        if has_negated_filepath_is_local(clause.trim()) {
            return true;
        }
    }
    false
}

/// Detect `!filepath.IsLocal(<expr>)`, Go's idiomatic path-traversal
/// guard.  Whitespace-tolerant: `! filepath.IsLocal(`, `!filepath . IsLocal(`,
/// etc.  Used by [`classify_path_rejection_axes`] to inject both
/// [`PathRejection::DotDot`] and [`PathRejection::IsAbsolute`] on the false
/// branch (which is the local-path branch by construction).
fn has_negated_filepath_is_local(clause: &str) -> bool {
    // Strip surrounding parens once to handle `(!filepath.IsLocal(p))`.
    let trimmed = clause.trim();
    let inner = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed)
        .trim();
    // Remove the leading `!` and any whitespace.
    let after_not = match inner.strip_prefix('!') {
        Some(rest) => rest.trim_start(),
        None => return false,
    };
    // Compress whitespace around `.` so `filepath . IsLocal(` matches.
    let compact: String = after_not.chars().filter(|c| !c.is_whitespace()).collect();
    compact.starts_with("filepath.IsLocal(")
}

fn classify_path_rejection_atom(clause: &str) -> PathRejection {
    // `.contains("..")` (Rust, Java) / `.includes("..")` (JS/TS) /
    // `.include?("..")` (Ruby) / `strings.Contains(s, "..")` (Go) /
    // `strstr(s, "..")` (C/C++), every form recognised by
    // `extract_contains_arg` returns `..` if the needle is the dotdot
    // segment.
    if let Some(needle) = extract_contains_arg(clause)
        && needle == ".."
    {
        return PathRejection::DotDot;
    }
    // Python `".." in s`, operator form.  Look for `".." in <something>`
    // anywhere in the clause text.  Conservative: requires the literal
    // `".." in ` substring (whitespace-tolerant).
    if has_python_dotdot_in(clause) {
        return PathRejection::DotDot;
    }
    // `.starts_with('/')` (Rust) / `.startsWith("/")` (JS/TS/Java) /
    // `.startswith("/")` (Python) / `.start_with?("/")` (Ruby) /
    // `strings.HasPrefix(s, "/")` (Go).
    if let Some(needle) = extract_starts_with_arg(clause)
        && (needle == "/" || needle == "\\")
    {
        return PathRejection::AbsoluteSlash;
    }
    // `.is_absolute()` (Rust) / `.isAbsolute()` (Java
    // `Paths.get(s).isAbsolute()`) / `os.path.isabs(s)` (Python) /
    // `filepath.IsAbs(s)` (Go).
    if clause.contains(".is_absolute()")
        || clause.contains(".isAbsolute()")
        || clause.contains("os.path.isabs(")
        || clause.contains("filepath.IsAbs(")
    {
        return PathRejection::IsAbsolute;
    }
    // C/C++ subscript form: `s[0] == '/'` or `s[0] == '\\'` (and reversed).
    // Idiomatic C/C++ absolute-path check since C has no `.startsWith` method.
    if has_first_char_absolute_check(clause) {
        return PathRejection::AbsoluteSlash;
    }
    PathRejection::None
}

/// Detect C/C++ `<var>[0] == '/'` or `<var>[0] == '\\'` subscript comparisons
/// (and the reversed `'/' == <var>[0]` form).  Recognises quoted char or
/// string-literal forms.  Conservative: needs both the `[0]` subscript and
/// a `'/'`/`'\\'` or `"/"`/`"\\"` literal within 32 chars of an `==` or `!=`
/// operator.  Idiomatic absolute-path check in C since C lacks
/// `.starts_with` methods.
fn has_first_char_absolute_check(clause: &str) -> bool {
    // We look for a subscript token `[0]` within the clause, then check that
    // an `==` or `!=` operator lies between the subscript and a `/`/`\` literal
    // on either side.
    let bytes = clause.as_bytes();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b'[' && bytes[i + 1] == b'0' && bytes[i + 2] == b']' {
            let lo = i.saturating_sub(32);
            let hi = (i + 3 + 32).min(bytes.len());
            let window = &bytes[lo..hi];
            let has_op = window.windows(2).any(|w| w == b"==" || w == b"!=");
            let has_lit = window.windows(3).any(|w| w == b"'/'")
                || window.windows(4).any(|w| w == b"'\\\\'")
                || window.windows(3).any(|w| w == b"\"/\"")
                || window.windows(4).any(|w| w == b"\"\\\\\"");
            if has_op && has_lit {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Detect Python's `".." in s` operator form.  The check is conservative:
/// it requires the literal substring `".." in ` (tolerating whitespace
/// between `".."` and `in`) anywhere in the clause text.
fn has_python_dotdot_in(clause: &str) -> bool {
    // Look for `".."` followed by `in` keyword.
    let bytes = clause.as_bytes();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i] == b'"' && bytes[i + 1] == b'.' && bytes[i + 2] == b'.' && bytes[i + 3] == b'"'
        {
            // Skip whitespace after the closing quote.
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j + 2 <= bytes.len() && &bytes[j..j + 2] == b"in" {
                // Require word boundary after `in`.
                let after = bytes.get(j + 2).copied();
                if after
                    .map(|c| !c.is_ascii_alphanumeric() && c != b'_')
                    .unwrap_or(true)
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Split a condition text on top-level `||` operators, ignoring those
/// inside string literals or nested parentheses.  Also recognises Python's
/// keyword form ` or ` (whitespace-bounded) at top level so OR-chain
/// rejection idioms are decomposed identically across languages.
fn split_top_level_or(text: &str) -> smallvec::SmallVec<[&str; 4]> {
    let mut out: smallvec::SmallVec<[&str; 4]> = smallvec::SmallVec::new();
    let bytes = text.as_bytes();
    let mut depth: i32 = 0;
    let mut in_quote: Option<u8> = None;
    let mut last = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => {
                in_quote = Some(b);
                i += 1;
                continue;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
                continue;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                i += 1;
                continue;
            }
            b'|' if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b'|' => {
                out.push(&text[last..i]);
                last = i + 2;
                i += 2;
                continue;
            }
            // Python `or` keyword at top level.  Require word boundaries on
            // both sides: a preceding ASCII whitespace, and a following ASCII
            // whitespace.  Avoids splitting inside identifiers like
            // `record_or_default`.
            b'o' | b'O'
                if depth == 0
                    && i + 2 < bytes.len()
                    && (bytes[i + 1] == b'r' || bytes[i + 1] == b'R')
                    && bytes[i + 2].is_ascii_whitespace()
                    && (i == 0 || bytes[i - 1].is_ascii_whitespace()) =>
            {
                // i is start of `or`.  Trim trailing whitespace from the
                // previous clause: out.push slice [last..i] but caller
                // .trim()s anyway, so pushing the raw range is fine.
                out.push(&text[last..i]);
                last = i + 2;
                i += 2;
                continue;
            }
            _ => {
                i += 1;
            }
        }
    }
    out.push(&text[last..]);
    out
}

/// Recognise a path-positive-assertion branch idiom (language-agnostic).
///
/// Returns:
///
/// * `PrefixLock(<literal>)` when the condition is a `starts_with`-style
///   call with a literal prefix of length ≥ 2.  Sibling single-character
///   prefixes (`"/"`, `"\\"`) are absolute-axis rejections, not locks.
/// * `PrefixLock(`[`OPAQUE_PREFIX_LOCK`]`)` when the call has a
///   non-empty, *non-literal* argument (method call, field access, local
///   variable).  The opaque marker certifies the structural invariant
///   "verified rooted under some prefix" without committing to bytes,
///   which is exactly what FILE_IO sink-suppression needs to combine with
///   a `dotdot=No` proof — the upstream code path
///   `File.expand_path(...) + start_with?(<config_root>)` is the
///   motivating example.
/// * `None` otherwise.
pub fn classify_path_assertion(text: &str) -> PathAssertion {
    let trimmed = text.trim();
    match extract_starts_with_arg(trimmed) {
        Some(needle) if needle.len() >= 2 => PathAssertion::PrefixLock(needle),
        // Single-char literal (`"/"`, `"\\"`) is an absolute-axis
        // rejection idiom handled by `classify_path_rejection_axes`, not
        // a positive prefix-lock — fall through to None.
        Some(_) => PathAssertion::None,
        // No literal recovered: check for a non-literal argument
        // (method call, field access, configured root) and attach the
        // opaque marker so the structural "verified rooted under SOME
        // prefix" invariant is recorded for downstream sink suppression.
        None if has_starts_with_call_with_nonempty_arg(trimmed) => {
            PathAssertion::PrefixLock(OPAQUE_PREFIX_LOCK.to_string())
        }
        None => PathAssertion::None,
    }
}

/// Recognise a *structural* one-argument enum-variant constructor.
///
/// Returns `true` when `callee` matches Rust's grammar for a variant
/// constructor call: the leaf (last path segment after `::` / `.`)
/// starts with an uppercase ASCII letter, and the callee has no method
/// receiver portion past a single terminal identifier.  Callers combine
/// this with a structural "single-argument call, no receiver" gate; the
/// classification is deliberately name-agnostic and does not hard-code
/// `Some` / `Ok` / `Err` / `Box::new` / …, so user-defined enum variants
/// participate on the same footing as stdlib ones.
///
/// The heuristic is intentionally conservative:
///   * Must be non-empty.
///   * The leaf segment must begin with an ASCII uppercase letter
///     (Rust's variant / struct / type grammar).
///   * The leaf segment must be ASCII alphanumeric / underscore, no
///     method call noise (parentheses, argument lists) survives here
///     because callees arrive in their normalised scoped-identifier
///     form.
///
/// Callers that use this as a PathFact passthrough must still verify
/// the call has exactly one argument (or one argument past a receiver-
/// less structural gate); the leaf check alone does not constrain
/// arity.
pub fn is_structural_variant_ctor(callee: &str) -> bool {
    let trimmed = callee.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Accept either form by inspecting both the leaf and (for scoped
    // callees) the penultimate segment.  A bare identifier whose leaf is
    // upper-camel-case names an enum variant or tuple struct (`Some`,
    // `Ok`, `MyResult`).  A scoped identifier whose *penultimate*
    // segment is upper-camel-case names an associated constructor on
    // that type, `Box::new`, `Cell::from`, `PathBuf::with_capacity`,
    // etc.  The latter is the lower-leaf-case shape we want to admit
    // alongside the bare-variant shape.
    let segments: smallvec::SmallVec<[&str; 4]> =
        trimmed.split("::").filter(|s| !s.is_empty()).collect();
    let is_upper_ident = |s: &str| -> bool {
        match s.chars().next() {
            Some(c) if c.is_ascii_uppercase() => {
                s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }
            _ => false,
        }
    };
    if segments.is_empty() {
        return false;
    }
    if segments.len() == 1 {
        return is_upper_ident(segments[0]);
    }
    // Scoped: accept either upper-camel-case leaf (`Module::Variant`)
    // or upper-camel-case penultimate (`Type::associated_fn`).
    let leaf = segments[segments.len() - 1];
    let parent = segments[segments.len() - 2];
    is_upper_ident(leaf) || is_upper_ident(parent)
}

/// Recognise a Rust path-producing primitive call by canonical callee name,
/// and return its PathFact effect on the result.  `input_fact` is the
/// PathFact of the receiver/first argument (the value being sanitised);
/// it is used as the baseline to which the call's effect is applied.
///
/// Returned [`None`] means the callee is not a recognised path primitive ,
/// the caller should leave the result at its pre-existing PathFact (Top).
///
/// Backwards-compatible wrapper around [`classify_path_primitive_rust`].
/// New callers should prefer [`classify_path_primitive_for_lang`] which
/// dispatches on the source language.
pub fn classify_path_primitive(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    classify_path_primitive_rust(callee, input_fact)
}

/// Per-language path-primitive dispatcher.
///
/// Routes to the language-specific classifier, Rust, Python, JS/TS, Go,
/// Java, Ruby, PHP, or C/C++.  Returns [`None`] for languages without a
/// classifier (or callees the language's classifier doesn't recognise).
pub fn classify_path_primitive_for_lang(
    lang: crate::symbol::Lang,
    callee: &str,
    input_fact: &PathFact,
) -> Option<PathFact> {
    use crate::symbol::Lang;
    match lang {
        Lang::Rust => classify_path_primitive_rust(callee, input_fact),
        Lang::Python => classify_path_primitive_python(callee, input_fact),
        Lang::JavaScript | Lang::TypeScript => classify_path_primitive_js(callee, input_fact),
        Lang::Go => classify_path_primitive_go(callee, input_fact),
        Lang::Java => classify_path_primitive_java(callee, input_fact),
        Lang::Ruby => classify_path_primitive_ruby(callee, input_fact),
        Lang::Php => classify_path_primitive_php(callee, input_fact),
        Lang::C | Lang::Cpp => classify_path_primitive_c_cpp(callee, input_fact),
    }
}

/// Per-language structural-variant-constructor predicate.
///
/// Rust uses ASCII-uppercase variant naming; other languages with
/// destructuring null/Optional idioms (Python `Optional[T]`, JS `null`,
/// Go `(T, error)`, Java `Optional<T>`, Ruby `nil`, PHP `?T`,
/// C++ `std::optional<T>`) don't share Rust's convention, so this
/// predicate is conservatively true only for Rust today.  Per-language
/// extensions can opt in later.
pub fn is_structural_variant_ctor_for_lang(lang: crate::symbol::Lang, callee: &str) -> bool {
    match lang {
        crate::symbol::Lang::Rust => is_structural_variant_ctor(callee),
        // Other languages: no grammatical variant-ctor convention to
        // recognise structurally.  `Some(s)` / `Ok(s)` are Rust-specific;
        // Java's `Optional.of(s)` is a method call, not a constructor; JS
        // returns `s` directly with `null` as the failure sentinel.
        _ => false,
    }
}

/// Per-language predicate for "this callee is a zero-arg fresh-allocation
/// constructor", used by the variant-rejection-path classifier so that
/// `String::new()` (Rust) / `''` (Python/JS/Java/...) is recognised as a
/// no-attacker-content fresh value with cleared `dotdot`/`absolute` axes.
///
/// Rust uses the `Type::method` scoped form recognised by
/// [`crate::ssa::type_facts::peel_identity_suffix`].  Other languages do
/// not (yet) have an equivalent grammar-driven recogniser; the rejection
/// arm in their fixtures returns either an empty string literal (handled
/// by `SsaOp::Const` seeding) or `None`/`null`/`nil` (handled by the
/// non-data-return skip).
pub fn is_zero_arg_allocator_for_lang(lang: crate::symbol::Lang, _callee: &str) -> bool {
    // Currently a no-op for non-Rust languages: rejection-arm constructors
    // are absorbed via `SsaOp::Const` seeding (e.g. `""` literal) or the
    // [`is_non_data_return`] sentinel skip (`None`/`null`/`nil`).  This
    // function exists as the per-language extension point.
    let _ = lang;
    false
}

/// Rust path-primitive classifier, `fs::canonicalize`, `Path::new`,
/// `PathBuf::from`, identity-string conversions.
pub fn classify_path_primitive_rust(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    // Accept both path-qualified (`std::fs::canonicalize`, `fs::canonicalize`)
    // and bare-leaf (`canonicalize`, produced from `p.canonicalize()` method
    // calls after normalisation) forms.
    let leaf = rightmost_segment(callee);
    match leaf {
        // `fs::canonicalize(p)` / `p.canonicalize()`:
        //   normalized = Yes, dotdot = No, absolute = Yes.  The result is
        //   an absolute, fully-resolved path; combined with a prefix-lock
        //   via `.starts_with(root)`, this is the standard Rust
        //   path-containment idiom.
        "canonicalize" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        // `Path::new(s)` / `PathBuf::from(s)`:
        //   pass-through of the input's PathFact so downstream `starts_with`
        //   checks against a Path/PathBuf value still see the underlying
        //   string's narrowed axes.  No axis is forced, wrapping does not
        //   sanitize on its own.
        "new" | "from" => {
            if callee_contains_segment(callee, "Path") || callee_contains_segment(callee, "PathBuf")
            {
                Some(input_fact.clone())
            } else {
                None
            }
        }
        // Identity conversions on strings/paths.  Each one re-binds the
        // same logical value, the converted String / PathBuf / OsString
        // still describes the exact same filesystem path, so the PathFact
        // flows through unchanged.  Without this, a sanitised `s: &str`
        // would lose its narrowed axes the moment the helper returns
        // `s.to_string()` / `s.to_owned()` / `String::from(s)`.
        "to_string" | "to_owned" | "clone" | "into" | "as_ref" | "as_str" | "as_path" => {
            Some(input_fact.clone())
        }
        _ => None,
    }
}

/// Python path-primitive classifier, `os.path.normpath`, `os.path.realpath`,
/// `pathlib.Path.resolve`, `os.path.abspath`.
///
/// Pattern conventions: tree-sitter-python emits dotted attribute access as
/// `obj.attr.method` after [`crate::callgraph`] normalisation.  Method calls
/// on Path objects appear as `Path.resolve` / `<bare>.resolve`; free-function
/// calls appear as `os.path.normpath` / `posixpath.normpath` / similar.
pub fn classify_path_primitive_python(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    let leaf = rightmost_segment(callee);
    match leaf {
        // `os.path.normpath(s)` / `posixpath.normpath(s)` / `ntpath.normpath`:
        //   Resolves `..` segments syntactically.  dotdot = No.
        //   Does not make absolute.
        "normpath" => {
            let mut f = input_fact.clone();
            f.dotdot = Tri::No;
            f.normalized = Tri::Yes;
            Some(f)
        }
        // `os.path.realpath(s)` / `pathlib.Path.resolve()`:
        //   Resolves symlinks AND `..` AND yields an absolute path.
        //   normalized = Yes, dotdot = No, absolute = Yes.
        "realpath" | "resolve" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        // `os.path.abspath(s)`:
        //   Returns an absolute version of the input.  absolute = Yes.
        //   Does NOT clear `..` (abspath joins with cwd; trailing `..` survives).
        "abspath" => {
            let mut f = input_fact.clone();
            f.absolute = Tri::Yes;
            Some(f)
        }
        // Identity conversions: `str(p)` / `Path(s)` / `os.fspath(s)` re-bind
        // the same logical path.
        "fspath" | "PurePath" | "PurePosixPath" | "PureWindowsPath" => Some(input_fact.clone()),
        _ => None,
    }
}

/// JavaScript / TypeScript path-primitive classifier, Node's `path` module:
/// `path.normalize`, `path.resolve`, `path.join`.
pub fn classify_path_primitive_js(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    let leaf = rightmost_segment(callee);
    match leaf {
        // `path.normalize(p)`:
        //   Resolves `..` syntactically.  dotdot = No.
        "normalize" => {
            let mut f = input_fact.clone();
            f.dotdot = Tri::No;
            f.normalized = Tri::Yes;
            Some(f)
        }
        // `path.resolve(p)`:
        //   Resolves to an absolute path, collapsing `..`.
        //   normalized = Yes, dotdot = No, absolute = Yes.
        "resolve" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        _ => None,
    }
}

/// Go path-primitive classifier, `path/filepath` package:
/// `filepath.Clean`, `filepath.Abs`.
pub fn classify_path_primitive_go(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    let leaf = rightmost_segment(callee);
    match leaf {
        // `filepath.Clean(p)`:
        //   Lexical normalisation that resolves `..`.  dotdot = No.
        "Clean" => {
            let mut f = input_fact.clone();
            f.dotdot = Tri::No;
            f.normalized = Tri::Yes;
            Some(f)
        }
        // `filepath.Abs(p)`:
        //   Returns an absolute path (also calls Clean).
        //   normalized = Yes, dotdot = No, absolute = Yes.
        "Abs" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        _ => None,
    }
}

/// Java path-primitive classifier, `java.nio.file.Path.normalize` /
/// `Paths.get(s).normalize().toAbsolutePath()`.
pub fn classify_path_primitive_java(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    let leaf = rightmost_segment(callee);
    match leaf {
        // `Path.normalize()`:
        //   Lexical normalisation that resolves `..`.
        "normalize" => {
            let mut f = input_fact.clone();
            f.dotdot = Tri::No;
            f.normalized = Tri::Yes;
            Some(f)
        }
        // `Path.toAbsolutePath()`:
        //   Returns an absolute path.
        "toAbsolutePath" => {
            let mut f = input_fact.clone();
            f.absolute = Tri::Yes;
            Some(f)
        }
        // `Path.toRealPath()`:
        //   Resolves symlinks and `..`, returns absolute path.
        "toRealPath" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        _ => None,
    }
}

/// Ruby path-primitive classifier, `File.expand_path` / `Pathname#cleanpath`.
pub fn classify_path_primitive_ruby(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    let leaf = rightmost_segment(callee);
    match leaf {
        // `File.expand_path(s)`:
        //   Returns an absolute path with `..` collapsed.
        "expand_path" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        // `Pathname#cleanpath`:
        //   Lexical normalisation that resolves `..`.
        "cleanpath" => {
            let mut f = input_fact.clone();
            f.dotdot = Tri::No;
            f.normalized = Tri::Yes;
            Some(f)
        }
        _ => None,
    }
}

/// PHP path-primitive classifier, `realpath`, `basename`.
pub fn classify_path_primitive_php(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    let leaf = rightmost_segment(callee);
    match leaf {
        // `realpath($s)`:
        //   Resolves symlinks and `..`, returns absolute path.  Returns
        //   `false` if the file doesn't exist, but on the success path
        //   (which is what reaches a sink), it produces a clean absolute path.
        "realpath" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        // `basename($s)`:
        //   Strips directory components, guaranteed to contain no `..`
        //   (basename of `..` is `..`, but basename of any traversal-
        //   prefixed path is just the leaf).  Conservative: clear dotdot.
        "basename" => {
            let mut f = input_fact.clone();
            f.dotdot = Tri::No;
            f.absolute = Tri::No;
            Some(f)
        }
        _ => None,
    }
}

/// C / C++ path-primitive classifier, POSIX `realpath`,
/// `std::filesystem::canonical`.
pub fn classify_path_primitive_c_cpp(callee: &str, input_fact: &PathFact) -> Option<PathFact> {
    let leaf = rightmost_segment(callee);
    match leaf {
        // POSIX `realpath(in, out)` / C++ `std::filesystem::canonical(p)`:
        //   Resolves to absolute canonical path.
        "realpath" | "canonical" => {
            let mut f = input_fact.clone();
            f.normalized = Tri::Yes;
            f.dotdot = Tri::No;
            f.absolute = Tri::Yes;
            Some(f)
        }
        _ => None,
    }
}

// ── Text helpers (kept in sync with path_state.rs's parsing style) ─────

fn rightmost_segment(s: &str) -> &str {
    let after_colons = s.rsplit("::").next().unwrap_or(s);
    after_colons.rsplit('.').next().unwrap_or(after_colons)
}

fn callee_contains_segment(callee: &str, seg: &str) -> bool {
    callee.split([':', '.']).any(|s| s == seg)
}

/// Extract the string argument passed to a "contains-like" call.  Matches
/// the canonical method-call shapes across languages:
///   * Rust / Java / JS String: `r.contains("..")`
///   * JS / TS array: `r.includes("..")`
///   * Ruby: `r.include?("..")`
///   * Go: `strings.Contains(r, "..")`
///   * C / C++: `strstr(r, "..")` / `strchr(r, '/')`
fn extract_contains_arg(text: &str) -> Option<String> {
    // Tier 1: method-call form `.contains(`, `.includes(`, `.include?(`.
    for method in [".contains(", ".includes(", ".include?("] {
        if let Some(idx) = text.find(method)
            && let Some(s) = extract_first_string_literal(&text[idx + method.len()..])
        {
            return Some(s);
        }
    }
    // Tier 2: free-function form with the receiver as first arg.  We can't
    // recover the receiver from the text (the lowering already records it
    // in `condition_vars`); we just need the literal needle to classify.
    for prefix in [
        "strings.Contains(",
        "strings.HasPrefix(",
        "strings.Index(",
        "strstr(",
    ] {
        if let Some(idx) = text.find(prefix) {
            // Skip past the first argument (receiver), the literal needle
            // is the second arg, separated by a comma.  Find the comma at
            // top level inside this call.
            let inner = &text[idx + prefix.len()..];
            if let Some(comma_idx) = top_level_comma(inner) {
                let after_comma = &inner[comma_idx + 1..];
                if let Some(s) = extract_first_string_literal(after_comma) {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Extract the string argument passed to a "starts-with-like" call.
///   * Rust: `r.starts_with('/')`
///   * Ruby: `r.start_with?("/")`
///   * JS / TS / Java: `r.startsWith("/")`
///   * Python: `r.startswith("/")`
///   * Go: `strings.HasPrefix(r, "/")`
fn extract_starts_with_arg(text: &str) -> Option<String> {
    for method in [
        ".starts_with(",
        ".start_with?(",
        ".startsWith(",
        ".startswith(",
    ] {
        if let Some(idx) = text.find(method)
            && let Some(s) = extract_first_string_literal(&text[idx + method.len()..])
        {
            return Some(s);
        }
    }
    // Go free-function form `strings.HasPrefix(r, "/")`, second arg.
    if let Some(idx) = text.find("strings.HasPrefix(") {
        let inner = &text[idx + "strings.HasPrefix(".len()..];
        if let Some(comma_idx) = top_level_comma(inner) {
            let after_comma = &inner[comma_idx + 1..];
            if let Some(s) = extract_first_string_literal(after_comma) {
                return Some(s);
            }
        }
    }
    None
}

/// Detect a `starts_with`-style call with a non-empty argument, where the
/// argument is *not* recovered as a string literal by
/// [`extract_starts_with_arg`] (so it's a method call, field access, local
/// variable, etc.).  Used by [`classify_path_assertion`] to attach an
/// opaque prefix-lock when the application validates with a configured
/// root rather than an inline string literal.
///
/// Whitespace-tolerant.  Conservative: returns `false` for any shape where
/// the argument cannot be confirmed non-empty.
fn has_starts_with_call_with_nonempty_arg(text: &str) -> bool {
    // Method-call forms with parens.  The argument-presence check is
    // simple: after the opening `(`, the first non-whitespace byte must
    // not be `)` (empty arg list).
    for method in [
        ".starts_with(",
        ".start_with?(",
        ".startsWith(",
        ".startswith(",
    ] {
        if let Some(idx) = text.find(method) {
            let after = &text[idx + method.len()..];
            if first_non_ws_byte(after).is_some_and(|b| b != b')') {
                return true;
            }
        }
    }
    // Ruby paren-less call: `r.start_with? <expr>`.  Tree-sitter still
    // serialises the source text verbatim, so a space (or tab) follows
    // the `?`.  Require a non-empty, non-clause-terminator token after.
    if let Some(idx) = text.find(".start_with?") {
        let rest = &text[idx + ".start_with?".len()..];
        // Skip the `(` form (already covered above) and any whitespace.
        let after = rest.trim_start();
        if !after.is_empty() {
            let first = after.as_bytes()[0];
            // `(` belongs to the parenthesised form; clause terminators
            // (`&&` / `||` / `)` / `]` / `;` / `,`) mean the call has no
            // arguments at this position.
            if !matches!(first, b'(' | b'&' | b'|' | b')' | b']' | b';' | b',') {
                return true;
            }
        }
    }
    // Go free-function form `strings.HasPrefix(<recv>, <prefix>)`.  The
    // second argument must exist and be non-empty.
    if let Some(idx) = text.find("strings.HasPrefix(") {
        let inner = &text[idx + "strings.HasPrefix(".len()..];
        if let Some(comma_idx) = top_level_comma(inner) {
            let after_comma = inner[comma_idx + 1..].trim_start();
            if !after_comma.is_empty() && !after_comma.starts_with(')') {
                return true;
            }
        }
    }
    false
}

/// Return the first non-whitespace byte of `text`, or `None` if the slice
/// is empty or all-whitespace.
fn first_non_ws_byte(text: &str) -> Option<u8> {
    text.bytes().find(|b| !b.is_ascii_whitespace())
}

/// Find the index of the first top-level `,` in a slice (depth 0, ignoring
/// commas inside nested parentheses, brackets, braces, or string literals).
/// Returns `None` if no top-level comma is present.
fn top_level_comma(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth: i32 = 0;
    let mut in_quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => {
                in_quote = Some(b);
                i += 1;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                i += 1;
            }
            b',' if depth == 0 => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Parse a `"..."` / `'...'` literal at the start of a slice (after an
/// opening `(`).  Returns the inner text, handling the common Rust escapes
/// `\\`, `\"`, `\'`, `\n`, `\t`.  `None` when the slice does not start
/// with a string literal.
fn extract_first_string_literal(after_open: &str) -> Option<String> {
    let bytes = after_open.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    i += 1;
    let mut out = Vec::new();
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                c => out.push(c),
            }
            i += 2;
            continue;
        }
        if b == quote {
            return String::from_utf8(out).ok();
        }
        out.push(b);
        i += 1;
    }
    None
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn truncate_prefix_lock(s: &str) -> String {
    if s.len() <= MAX_PREFIX_LOCK_LEN {
        s.to_string()
    } else {
        let mut end = MAX_PREFIX_LOCK_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// Longest common prefix, char-aligned so multi-byte UTF-8 sequences are
/// kept whole. The earlier byte-iteration form re-encoded continuation
/// bytes as Latin-1 chars and produced mojibake; the same fix lives at
/// `crate::abstract_interp::string_domain::longest_common_prefix`.
fn longest_common_prefix(a: &str, b: &str) -> String {
    a.chars()
        .zip(b.chars())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LCP helper ──────────────────────────────────────────────────────

    #[test]
    fn lcp_basic() {
        assert_eq!(longest_common_prefix("abcdef", "abcxyz"), "abc");
        assert_eq!(longest_common_prefix("abc", "abc"), "abc");
        assert_eq!(longest_common_prefix("", "abc"), "");
    }

    #[test]
    fn lcp_keeps_utf8_codepoints_whole() {
        // Without char-alignment, byte iteration would emit the
        // continuation byte 0xA9 as a separate char and corrupt the
        // prefix.  Both the 2-byte and 3-byte UTF-8 cases must survive.
        assert_eq!(longest_common_prefix("héllo", "héllo!"), "héllo");
        assert_eq!(longest_common_prefix("名前.json", "名前.txt"), "名前.");
    }

    // ── Tri lattice laws ────────────────────────────────────────────────

    #[test]
    fn tri_join_idempotent() {
        for v in [Tri::No, Tri::Yes, Tri::Maybe] {
            assert_eq!(v.join(&v), v);
        }
    }

    #[test]
    fn tri_join_commutative() {
        let pairs = [
            (Tri::No, Tri::Yes),
            (Tri::No, Tri::Maybe),
            (Tri::Yes, Tri::Maybe),
        ];
        for (a, b) in pairs {
            assert_eq!(a.join(&b), b.join(&a));
        }
    }

    #[test]
    fn tri_join_disagreement_is_top() {
        assert_eq!(Tri::No.join(&Tri::Yes), Tri::Maybe);
    }

    #[test]
    fn tri_join_with_top_is_top() {
        assert_eq!(Tri::No.join(&Tri::Maybe), Tri::Maybe);
        assert_eq!(Tri::Yes.join(&Tri::Maybe), Tri::Maybe);
    }

    #[test]
    fn tri_meet_top_is_identity() {
        assert_eq!(Tri::No.meet_checked(&Tri::Maybe), Some(Tri::No));
        assert_eq!(Tri::Maybe.meet_checked(&Tri::Yes), Some(Tri::Yes));
    }

    #[test]
    fn tri_meet_contradiction_is_none() {
        assert_eq!(Tri::No.meet_checked(&Tri::Yes), None);
        assert_eq!(Tri::Yes.meet_checked(&Tri::No), None);
    }

    #[test]
    fn tri_meet_agree() {
        assert_eq!(Tri::No.meet_checked(&Tri::No), Some(Tri::No));
        assert_eq!(Tri::Yes.meet_checked(&Tri::Yes), Some(Tri::Yes));
    }

    #[test]
    fn tri_widen_drops_on_change() {
        assert_eq!(Tri::No.widen(&Tri::Yes), Tri::Maybe);
        assert_eq!(Tri::No.widen(&Tri::No), Tri::No);
    }

    #[test]
    fn tri_leq_top_greatest() {
        assert!(Tri::No.leq(&Tri::Maybe));
        assert!(Tri::Yes.leq(&Tri::Maybe));
        assert!(!Tri::Maybe.leq(&Tri::No));
    }

    // ── PathFact basics ─────────────────────────────────────────────────

    #[test]
    fn default_is_top() {
        let f = PathFact::default();
        assert!(f.is_top());
        assert!(!f.is_bottom());
        assert!(!f.is_path_safe());
    }

    #[test]
    fn bottom_detection() {
        let b = PathFact::bottom();
        assert!(b.is_bottom());
        assert!(!b.is_top());
        assert!(!b.is_path_safe());
    }

    #[test]
    fn is_path_safe_requires_both_axes() {
        let mut f = PathFact::default().with_dotdot_cleared();
        assert!(!f.is_path_safe(), "dotdot=No alone is insufficient");
        f = f.with_absolute_cleared();
        assert!(f.is_path_safe());
    }

    #[test]
    fn is_path_safe_truth_table() {
        let cases = [
            (Tri::No, Tri::No, true),
            (Tri::No, Tri::Yes, false),
            (Tri::No, Tri::Maybe, false),
            (Tri::Yes, Tri::No, false),
            (Tri::Maybe, Tri::No, false),
            (Tri::Maybe, Tri::Maybe, false),
        ];
        for (dd, abs, expected) in cases {
            let f = PathFact {
                dotdot: dd,
                absolute: abs,
                normalized: Tri::Maybe,
                prefix_lock: None,
                is_bottom: false,
            };
            assert_eq!(
                f.is_path_safe(),
                expected,
                "is_path_safe({:?}, {:?}) should be {expected}",
                dd,
                abs
            );
        }
    }

    #[test]
    fn with_normalized_clears_dotdot() {
        let f = PathFact::default().with_normalized();
        assert_eq!(f.dotdot, Tri::No);
        assert_eq!(f.normalized, Tri::Yes);
        assert_eq!(f.absolute, Tri::Maybe);
    }

    #[test]
    fn with_prefix_lock_ignores_empty() {
        let f = PathFact::default().with_prefix_lock("");
        assert!(f.prefix_lock.is_none());
    }

    #[test]
    fn with_prefix_lock_truncates() {
        let huge = "/".to_string() + &"a".repeat(MAX_PREFIX_LOCK_LEN * 2);
        let f = PathFact::default().with_prefix_lock(&huge);
        assert!(
            f.prefix_lock.as_deref().unwrap().len() <= MAX_PREFIX_LOCK_LEN,
            "prefix_lock must be bounded"
        );
    }

    #[test]
    fn c_or_chain_rejection_full() {
        // Exact text shape that lowering produces for c-safe-014 / c-safe-016.
        let axes = classify_path_rejection_axes(
            "strstr(s, \"..\") != NULL || s[0] == '/' || s[0] == '\\\\'",
        );
        assert!(
            axes.contains(&PathRejection::DotDot),
            "expected DotDot in {:?}",
            axes
        );
        assert!(
            axes.contains(&PathRejection::AbsoluteSlash),
            "expected AbsoluteSlash in {:?}",
            axes
        );
    }

    #[test]
    fn classify_subscript_first_char_absolute() {
        // C/C++ idiom: `s[0] == '/'`
        assert_eq!(
            classify_path_rejection_atom("s[0] == '/'"),
            PathRejection::AbsoluteSlash
        );
        // `s[0] == '\\'` (backslash)
        assert_eq!(
            classify_path_rejection_atom("s[0] == '\\\\'"),
            PathRejection::AbsoluteSlash
        );
        // Reversed comparison `'/' == s[0]`
        assert_eq!(
            classify_path_rejection_atom("'/' == in[0]"),
            PathRejection::AbsoluteSlash
        );
        // `!=` operator inside a negated check (`s[0] != '/'`) also matches the
        // literal-nearby pattern; classification callers gate on clause polarity.
        assert_eq!(
            classify_path_rejection_atom("s[0] != '\\\\'"),
            PathRejection::AbsoluteSlash
        );
        // Negative: no literal near subscript
        assert_eq!(
            classify_path_rejection_atom("s[0] == c"),
            PathRejection::None
        );
        // Negative: subscript but no equality op
        assert_eq!(classify_path_rejection_atom("s[0]"), PathRejection::None);
        // Regression: multibyte char inside the 32-byte search window must not
        // panic on a non-char-boundary slice (fuzz crash repro).
        let s = format!("{}s[0] == '/'", "—".repeat(20));
        assert_eq!(
            classify_path_rejection_atom(&s),
            PathRejection::AbsoluteSlash
        );
        let s2 = format!("s[0] == '/'{}", "—".repeat(20));
        assert_eq!(
            classify_path_rejection_atom(&s2),
            PathRejection::AbsoluteSlash
        );
    }

    #[test]
    fn prefix_locked_under_works() {
        let f = PathFact::default().with_prefix_lock("/var/app/uploads/");
        assert!(f.prefix_locked_under("/var/app/"));
        assert!(f.prefix_locked_under("/var/app/uploads/"));
        assert!(!f.prefix_locked_under("/etc/"));
        assert!(!PathFact::default().prefix_locked_under("/var/app/"));
    }

    // ── Lattice laws ────────────────────────────────────────────────────

    #[test]
    fn join_idempotent() {
        let f = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        assert_eq!(f.join(&f), f);
    }

    #[test]
    fn join_commutative() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default().with_absolute_cleared();
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_associative() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default().with_absolute_cleared();
        let c = PathFact::default().with_normalized();
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn join_with_bottom_identity() {
        let a = PathFact::default().with_dotdot_cleared();
        assert_eq!(a.join(&PathFact::bottom()), a);
        assert_eq!(PathFact::bottom().join(&a), a);
    }

    #[test]
    fn join_disagreement_yields_maybe() {
        let a = PathFact::default().with_dotdot_cleared(); // dotdot=No
        let b = PathFact {
            dotdot: Tri::Yes,
            ..Default::default()
        };
        let j = a.join(&b);
        assert_eq!(j.dotdot, Tri::Maybe);
    }

    #[test]
    fn join_prefix_locks_lcp() {
        let a = PathFact::default().with_prefix_lock("/var/app/uploads/");
        let b = PathFact::default().with_prefix_lock("/var/app/static/");
        let j = a.join(&b);
        assert_eq!(j.prefix_lock.as_deref(), Some("/var/app/"));
    }

    #[test]
    fn join_prefix_locks_disjoint_drops() {
        let a = PathFact::default().with_prefix_lock("/var/app/");
        let b = PathFact::default().with_prefix_lock("/etc/");
        let j = a.join(&b);
        // LCP of "/var/app/" and "/etc/" is "/"; still a non-empty lock.
        assert_eq!(j.prefix_lock.as_deref(), Some("/"));
        let c = PathFact::default().with_prefix_lock("home/");
        let d = PathFact::default().with_prefix_lock("etc/");
        assert!(c.join(&d).prefix_lock.is_none());
    }

    #[test]
    fn meet_top_is_identity() {
        let a = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        assert_eq!(a.meet(&PathFact::top()), a);
        assert_eq!(PathFact::top().meet(&a), a);
    }

    #[test]
    fn meet_refines() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default().with_absolute_cleared();
        let m = a.meet(&b);
        assert_eq!(m.dotdot, Tri::No);
        assert_eq!(m.absolute, Tri::No);
        assert!(m.is_path_safe());
    }

    #[test]
    fn meet_contradiction_is_bottom() {
        let a = PathFact::default().with_dotdot_cleared(); // dotdot=No
        let b = PathFact {
            dotdot: Tri::Yes,
            ..Default::default()
        };
        assert!(a.meet(&b).is_bottom());
    }

    #[test]
    fn meet_prefix_locks_picks_longer() {
        let a = PathFact::default().with_prefix_lock("/var/app/");
        let b = PathFact::default().with_prefix_lock("/var/app/uploads/");
        let m = a.meet(&b);
        assert_eq!(m.prefix_lock.as_deref(), Some("/var/app/uploads/"));
    }

    #[test]
    fn meet_prefix_locks_disjoint_is_bottom() {
        let a = PathFact::default().with_prefix_lock("/var/app/");
        let b = PathFact::default().with_prefix_lock("/etc/");
        assert!(a.meet(&b).is_bottom());
    }

    // ── Widening ────────────────────────────────────────────────────────

    #[test]
    fn widen_stable() {
        let a = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        assert_eq!(a.widen(&a), a);
    }

    #[test]
    fn widen_drops_on_change() {
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact {
            dotdot: Tri::Yes,
            ..Default::default()
        };
        let w = a.widen(&b);
        assert_eq!(w.dotdot, Tri::Maybe);
    }

    #[test]
    fn widen_chain_terminates() {
        // Finite-ascent guarantee: any sequence of widens must stabilise
        // within a small fixed number of steps (each axis has height 2).
        let mut cur = PathFact::default().with_dotdot_cleared();
        let target = PathFact {
            dotdot: Tri::Yes,
            absolute: Tri::Yes,
            normalized: Tri::Yes,
            prefix_lock: None,
            is_bottom: false,
        };
        for _ in 0..8 {
            cur = cur.widen(&target);
        }
        // After widening with a disagreeing target, we drop to Top on that axis.
        assert_eq!(cur.dotdot, Tri::Maybe);
        assert_eq!(cur, cur.widen(&target), "must have stabilised");
    }

    #[test]
    fn widen_prefix_drops_on_change() {
        let a = PathFact::default().with_prefix_lock("/var/app/v1/");
        let b = PathFact::default().with_prefix_lock("/var/app/v2/");
        assert!(a.widen(&b).prefix_lock.is_none());
    }

    // ── Leq ─────────────────────────────────────────────────────────────

    #[test]
    fn leq_top_greatest() {
        let a = PathFact::default().with_dotdot_cleared();
        assert!(a.leq(&PathFact::top()));
        assert!(!PathFact::top().leq(&a));
    }

    #[test]
    fn leq_bottom_least() {
        assert!(PathFact::bottom().leq(&PathFact::default()));
        assert!(!PathFact::default().leq(&PathFact::bottom()));
    }

    #[test]
    fn leq_refinement() {
        let refined = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        let coarse = PathFact::default().with_dotdot_cleared();
        assert!(refined.leq(&coarse));
        assert!(!coarse.leq(&refined));
    }

    // ── Rust classifier tests ───────────────────────────────────────────

    #[test]
    fn rejection_contains_dotdot() {
        assert_eq!(
            classify_path_rejection("user.contains(\"..\")"),
            PathRejection::DotDot
        );
    }

    #[test]
    fn rejection_axes_disjunction_covers_all_clauses() {
        let axes = classify_path_rejection_axes(
            "s.contains(\"..\") || s.starts_with('/') || s.starts_with('\\\\')",
        );
        assert!(
            axes.contains(&PathRejection::DotDot),
            "expected DotDot in {axes:?}"
        );
        assert!(
            axes.contains(&PathRejection::AbsoluteSlash),
            "expected AbsoluteSlash in {axes:?}"
        );
    }

    #[test]
    fn rejection_axes_deduplicates() {
        let axes = classify_path_rejection_axes("a.starts_with('/') || b.starts_with(\"\\\\\")");
        // Two absolute-slash clauses collapse to a single axis.
        assert_eq!(
            axes.iter()
                .filter(|a| matches!(a, PathRejection::AbsoluteSlash))
                .count(),
            1
        );
    }

    #[test]
    fn rejection_contains_other_needle_is_none() {
        assert_eq!(
            classify_path_rejection("name.contains(\";\")"),
            PathRejection::None
        );
    }

    #[test]
    fn rejection_starts_with_slash() {
        assert_eq!(
            classify_path_rejection("p.starts_with('/')"),
            PathRejection::AbsoluteSlash
        );
        assert_eq!(
            classify_path_rejection("p.starts_with(\"/\")"),
            PathRejection::AbsoluteSlash
        );
    }

    #[test]
    fn rejection_starts_with_backslash() {
        assert_eq!(
            classify_path_rejection("p.starts_with(\"\\\\\")"),
            PathRejection::AbsoluteSlash
        );
    }

    #[test]
    fn rejection_is_absolute() {
        assert_eq!(
            classify_path_rejection("Path::new(s).is_absolute()"),
            PathRejection::IsAbsolute
        );
        assert_eq!(
            classify_path_rejection("p.is_absolute()"),
            PathRejection::IsAbsolute
        );
    }

    #[test]
    fn assertion_prefix_lock() {
        match classify_path_assertion("p.starts_with(\"/var/app/\")") {
            PathAssertion::PrefixLock(r) => assert_eq!(r, "/var/app/"),
            other => panic!("expected PrefixLock, got {other:?}"),
        }
    }

    #[test]
    fn assertion_single_char_not_lock() {
        assert_eq!(
            classify_path_assertion("p.starts_with('/')"),
            PathAssertion::None
        );
    }

    #[test]
    fn assertion_opaque_prefix_lock_method_call_arg() {
        // rswag CVE-2023-38337 patched shape: `start_with?` with a
        // configured-root method call as argument.  The exact bytes are
        // unknown to the analyser, but the structural invariant "rooted
        // under SOME prefix" is captured via the opaque marker.
        assert_eq!(
            classify_path_assertion("filename.start_with? @config.resolve_swagger_root(env)"),
            PathAssertion::PrefixLock(OPAQUE_PREFIX_LOCK.to_string())
        );
    }

    #[test]
    fn assertion_opaque_prefix_lock_paren_method_call() {
        // Same shape, parenthesised: `r.start_with?(some_root)`.
        assert_eq!(
            classify_path_assertion("filename.start_with?(@config.root)"),
            PathAssertion::PrefixLock(OPAQUE_PREFIX_LOCK.to_string())
        );
    }

    #[test]
    fn assertion_opaque_prefix_lock_python_startswith() {
        // Python: `os.path.realpath(p).startswith(safe_root)` where
        // `safe_root` is a local variable, not a literal.
        assert_eq!(
            classify_path_assertion("p.startswith(safe_root)"),
            PathAssertion::PrefixLock(OPAQUE_PREFIX_LOCK.to_string())
        );
    }

    #[test]
    fn assertion_opaque_prefix_lock_js_starts_with() {
        assert_eq!(
            classify_path_assertion("resolved.startsWith(uploadsDir)"),
            PathAssertion::PrefixLock(OPAQUE_PREFIX_LOCK.to_string())
        );
    }

    #[test]
    fn assertion_opaque_prefix_lock_go_hasprefix() {
        assert_eq!(
            classify_path_assertion("strings.HasPrefix(p, safeRoot)"),
            PathAssertion::PrefixLock(OPAQUE_PREFIX_LOCK.to_string())
        );
    }

    #[test]
    fn assertion_no_lock_on_empty_arg() {
        // `r.starts_with()` (degenerate) should not produce a lock.
        assert_eq!(
            classify_path_assertion("r.starts_with()"),
            PathAssertion::None
        );
    }

    #[test]
    fn is_path_traversal_safe_relative_dotdot_free() {
        let f = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        assert!(f.is_path_traversal_safe());
    }

    #[test]
    fn is_path_traversal_safe_canonicalised_with_prefix_lock() {
        // `File.expand_path + start_with?(root)` shape: dotdot=No,
        // absolute=Yes, prefix_lock=Some.  The relaxed predicate should
        // accept this even though the strict `is_path_safe` rejects it.
        let f = PathFact::default()
            .with_dotdot_cleared()
            .with_prefix_lock("__nyx_opaque_prefix__");
        assert!(!f.is_path_safe(), "absolute axis still Maybe blocks strict");
        // Setting absolute=Yes via expand_path-style transfer:
        let mut f2 = f.clone();
        f2.absolute = Tri::Yes;
        assert!(!f2.is_path_safe(), "absolute=Yes blocks strict predicate");
        assert!(
            f2.is_path_traversal_safe(),
            "prefix_lock + dotdot=No is sufficient under relaxed predicate"
        );
    }

    #[test]
    fn is_path_traversal_safe_rejects_dotdot_maybe() {
        let f = PathFact::default().with_prefix_lock("/var/app/");
        // dotdot still Maybe — relaxed predicate must still reject.
        assert!(!f.is_path_traversal_safe());
    }

    #[test]
    fn is_path_traversal_safe_rejects_absolute_without_lock() {
        let mut f = PathFact::default().with_dotdot_cleared();
        f.absolute = Tri::Yes;
        // No prefix_lock — relaxed predicate must reject.
        assert!(!f.is_path_traversal_safe());
    }

    #[test]
    fn is_path_traversal_safe_rejects_bottom() {
        assert!(!PathFact::bottom().is_path_traversal_safe());
    }

    #[test]
    fn primitive_canonicalize_normalises() {
        let f = classify_path_primitive("fs::canonicalize", &PathFact::top()).unwrap();
        assert_eq!(f.dotdot, Tri::No);
        assert_eq!(f.normalized, Tri::Yes);
        assert_eq!(f.absolute, Tri::Yes);
    }

    #[test]
    fn primitive_method_canonicalize_normalises() {
        let f = classify_path_primitive("canonicalize", &PathFact::top()).unwrap();
        assert_eq!(f.normalized, Tri::Yes);
    }

    #[test]
    fn primitive_path_new_passthrough() {
        let input = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        let f = classify_path_primitive("Path::new", &input).unwrap();
        assert_eq!(f, input, "Path::new passes PathFact through unchanged");
    }

    #[test]
    fn primitive_pathbuf_from_passthrough() {
        let input = PathFact::default().with_dotdot_cleared();
        let f = classify_path_primitive("PathBuf::from", &input).unwrap();
        assert_eq!(f, input);
    }

    #[test]
    fn primitive_unknown_returns_none() {
        assert!(classify_path_primitive("unknown_fn", &PathFact::top()).is_none());
        assert!(classify_path_primitive("vec::new", &PathFact::top()).is_none());
    }

    // ── Structural variant-ctor classifier ─────────────────────────────

    #[test]
    fn variant_ctor_recognises_upper_camel_leaf() {
        assert!(is_structural_variant_ctor("Some"));
        assert!(is_structural_variant_ctor("Ok"));
        assert!(is_structural_variant_ctor("Err"));
        assert!(is_structural_variant_ctor("Box::new"));
        assert!(is_structural_variant_ctor("std::option::Option::Some"));
        // User-defined upper-camel-case variant name participates the
        // same way, name list is not part of the contract.
        assert!(is_structural_variant_ctor("MyResult::Ok"));
        assert!(is_structural_variant_ctor("Wrapper"));
    }

    #[test]
    fn variant_ctor_rejects_lowercase_leaf() {
        assert!(!is_structural_variant_ctor("foo"));
        assert!(!is_structural_variant_ctor("bar::baz"));
        assert!(!is_structural_variant_ctor("std::env::var"));
        assert!(!is_structural_variant_ctor("to_string"));
    }

    #[test]
    fn variant_ctor_rejects_empty_or_garbled() {
        assert!(!is_structural_variant_ctor(""));
        assert!(!is_structural_variant_ctor("::"));
        assert!(!is_structural_variant_ctor("123"));
    }

    // ── PathFactReturnEntry merge / dedup ───────────────────────────────

    #[test]
    fn merge_path_fact_dedups_by_predicate_hash() {
        use crate::summary::ssa_summary::{PathFactReturnEntry, merge_path_fact_return_paths};
        use smallvec::SmallVec;
        let mut acc: SmallVec<[PathFactReturnEntry; 2]> = SmallVec::new();
        let f1 = PathFact::top().with_dotdot_cleared();
        let f2 = PathFact::top().with_absolute_cleared();
        merge_path_fact_return_paths(
            &mut acc,
            &[PathFactReturnEntry {
                predicate_hash: 42,
                known_true: 0,
                known_false: 0,
                path_fact: f1.clone(),
                variant_inner_fact: None,
            }],
        );
        merge_path_fact_return_paths(
            &mut acc,
            &[PathFactReturnEntry {
                predicate_hash: 42,
                known_true: 0,
                known_false: 0,
                path_fact: f2.clone(),
                variant_inner_fact: None,
            }],
        );
        assert_eq!(acc.len(), 1, "same predicate hash collapses to one entry");
        let joined = f1.join(&f2);
        assert_eq!(
            acc[0].path_fact, joined,
            "facts join on predicate-hash collision"
        );
    }

    #[test]
    fn merge_path_fact_distinct_hashes_kept_separate() {
        use crate::summary::ssa_summary::{PathFactReturnEntry, merge_path_fact_return_paths};
        use smallvec::SmallVec;
        let mut acc: SmallVec<[PathFactReturnEntry; 2]> = SmallVec::new();
        merge_path_fact_return_paths(
            &mut acc,
            &[
                PathFactReturnEntry {
                    predicate_hash: 1,
                    known_true: 0,
                    known_false: 0,
                    path_fact: PathFact::top().with_dotdot_cleared(),
                    variant_inner_fact: None,
                },
                PathFactReturnEntry {
                    predicate_hash: 2,
                    known_true: 0,
                    known_false: 0,
                    path_fact: PathFact::top(),
                    variant_inner_fact: Some(PathFact::top().with_absolute_cleared()),
                },
            ],
        );
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn merge_path_fact_overflow_caps_at_bound() {
        use crate::summary::ssa_summary::{
            MAX_PATH_FACT_RETURN_ENTRIES, PathFactReturnEntry, merge_path_fact_return_paths,
        };
        use smallvec::SmallVec;
        let mut acc: SmallVec<[PathFactReturnEntry; 2]> = SmallVec::new();
        // Push twice as many distinct predicate hashes as the cap so
        // overflow collapse fires repeatedly.  Each collapse compacts
        // the accumulator back to a single Top-predicate entry; the
        // next insert lands fresh on top.  The invariant we care
        // about is bounded growth: the final length must not exceed
        // `MAX_PATH_FACT_RETURN_ENTRIES`.
        for i in 0..(MAX_PATH_FACT_RETURN_ENTRIES * 2) {
            merge_path_fact_return_paths(
                &mut acc,
                &[PathFactReturnEntry {
                    predicate_hash: i as u64 + 100,
                    known_true: 0,
                    known_false: 0,
                    path_fact: PathFact::top().with_dotdot_cleared(),
                    variant_inner_fact: None,
                }],
            );
        }
        assert!(
            acc.len() <= MAX_PATH_FACT_RETURN_ENTRIES,
            "overflow growth stays bounded: got {}",
            acc.len()
        );
        // Whichever of the post-collapse entries survives, at least
        // one carries the unguarded (predicate_hash == 0) collapse
        // sentinel from a previous overflow.
        assert!(
            acc.iter().any(|e| e.predicate_hash == 0),
            "collapse sentinel must persist"
        );
    }

    #[test]
    fn leq_consistent_with_join() {
        // a ⊑ b iff join(a, b) == b (within the domain's join-semilattice).
        let a = PathFact::default().with_dotdot_cleared();
        let b = PathFact::default()
            .with_dotdot_cleared()
            .with_absolute_cleared();
        // b ⊑ a because b is strictly more informative.
        assert!(b.leq(&a));
        assert_eq!(b.join(&a), a);
    }
}
