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

/// True when a URL whose constant prefix is `prefix` cannot leave the
/// origin the prefix names, whatever follows it:
///
/// * `scheme://host/...`: a non-empty host closed by a path separator;
/// * `/x...` with `x` neither `/` nor `\`: a same-origin absolute path.
///   A bare `/`, `//...` and `/\...` are not locked, since browsers and most
///   HTTP clients read `//host` and `/\host` as protocol-relative.
///
/// Shared by the SSRF and open-redirect prefix suppressions.
pub fn prefix_locks_origin(prefix: &str) -> bool {
    if let Some(rest) = prefix.strip_prefix('/') {
        return rest.chars().next().is_some_and(|c| c != '/' && c != '\\');
    }
    if let Some(after_scheme) = prefix.find("://") {
        let host_and_rest = &prefix[after_scheme + 3..];
        if let Some(slash_pos) = host_and_rest.find('/') {
            return slash_pos > 0;
        }
    }
    false
}

/// True for callees that open their argument as a filesystem path unless it
/// carries a URL scheme (PHP's stream functions, and Ruby's `open` /
/// `URI.open`, which fall back to `Kernel#open`; all are also SSRF sinks).
/// A leading `/` there names a local file, not a path on the current origin.
pub fn opens_local_paths(callee: &str) -> bool {
    let leaf = callee.rsplit(['\\', ':', '.']).next().unwrap_or(callee);
    match leaf.to_ascii_lowercase().as_str() {
        "file_get_contents" | "fopen" | "readfile" | "file" => true,
        // Only Ruby's `open`, `Kernel.open`, `URI.open` and
        // `OpenURI.open_uri`. Other receivers (`window.open`) navigate
        // instead of reading a file.
        "open" | "open_uri" => {
            let receiver = callee[..callee.len() - leaf.len()].trim_end_matches(['.', ':']);
            matches!(
                receiver.to_ascii_lowercase().as_str(),
                "" | "kernel" | "uri" | "openuri"
            )
        }
        _ => false,
    }
}

/// [`prefix_locks_origin`] for a URL sink called as `callee`: a same-origin
/// `/path` prefix pins nothing when the callee reads local paths, so only a
/// `scheme://host/` prefix counts there.
pub fn prefix_locks_origin_for(callee: Option<&str>, prefix: &str) -> bool {
    if prefix.starts_with('/') && callee.is_some_and(opens_local_paths) {
        return false;
    }
    prefix_locks_origin(prefix)
}

/// [`prefix_locks_origin_for`] for a whole fact: besides a locking prefix, a
/// bare `/` prefix locks the origin when the character after it can be
/// neither `/` nor `\`, so `"/" + strings.Trim(p, "/\\")` stays on the
/// current origin (`/` followed by anything else is a same-origin path).
/// The characters a URL parser drops (`url_parser_skips`) must be excluded
/// as well, or `"/" + "\t/evil.com"` would read as `//evil.com`.
pub fn fact_locks_origin_for(callee: Option<&str>, fact: &StringFact) -> bool {
    let Some(prefix) = fact.prefix.as_deref() else {
        return false;
    };
    if prefix_locks_origin_for(callee, prefix) {
        return true;
    }
    if prefix != "/" || callee.is_some_and(opens_local_paths) {
        return false;
    }
    // The parser drops tab, CR, LF, other C0 controls and space before it
    // looks at the second character, so each of them must be excluded too.
    let after = fact.excl_at(1);
    after.contains('/') && after.contains('\\') && (0u8..=0x20).all(|b| after.contains(b as char))
}

/// Characters a URL parser strips or folds before it decides whether a
/// reference starts with `//` or `\\`: leading C0 controls and spaces, and
/// the tab/newline/carriage-return characters that WHATWG parsing removes
/// anywhere in the input.
fn url_parser_skips(c: char) -> bool {
    c.is_ascii_control() || c == ' '
}

/// True when a relative reference that is known to start with `prefix` (and
/// continue with unknown text) resolves against a base without changing its
/// scheme or host.
///
/// Reference resolution is not concatenation: `new URL(ref, base)`,
/// `urljoin(base, ref)` and friends replace the whole base when `ref` is an
/// absolute URL (`https://evil/`), and replace the host when it is
/// protocol-relative (`//evil/`, and `/\evil/` for special schemes).  Only
/// these prefixes keep the base origin whatever follows them:
///
/// * `/x...` with `x` neither `/` nor `\` nor a character the parser drops;
/// * `?...` and `#...` (query-only and fragment-only references);
/// * `seg/...`, `seg?...` or `seg#...` where `seg` is non-empty and holds no
///   `:`.  Without a terminating `/`, `?` or `#` the unknown text that
///   follows could complete a scheme (`"a"` + `"://evil"`), so a bare
///   `users` prefix does not count.
pub fn prefix_is_host_preserving_reference(prefix: &str) -> bool {
    reference_is_host_preserving(prefix, false)
}

/// Like [`prefix_is_host_preserving_reference`] for a fully known reference
/// string: nothing follows it, so a relative path needs no terminator.
pub fn exact_is_host_preserving_reference(reference: &str) -> bool {
    reference_is_host_preserving(reference, true)
}

fn reference_is_host_preserving(text: &str, complete: bool) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return complete;
    };
    if url_parser_skips(first) {
        return false;
    }
    match first {
        '/' => match chars.next() {
            Some(second) => second != '/' && second != '\\' && !url_parser_skips(second),
            None => complete,
        },
        '\\' => false,
        '?' | '#' => true,
        _ => {
            let seg_end = text.find(['/', '?', '#']);
            match seg_end {
                Some(end) => !text[..end].contains(':') && !text[..end].contains('\\'),
                None => complete && !text.contains(':') && !text.contains('\\'),
            }
        }
    }
}

/// `scheme://authority` of an absolute base URL, without a trailing slash.
/// `None` when `base` has no scheme or an empty host.
fn url_origin(base: &str) -> Option<&str> {
    let after_scheme = base.find("://")? + 3;
    let rest = &base[after_scheme..];
    let host_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if host_len == 0 {
        return None;
    }
    Some(&base[..after_scheme + host_len])
}

/// A set of ASCII characters.  Non-ASCII characters are never members, so a
/// set used as an exclusion ("the string holds none of these") only ever
/// claims things about ASCII text, which keeps it sound for any input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AsciiSet(u128);

impl AsciiSet {
    pub const EMPTY: Self = Self(0);
    pub const ALL: Self = Self(u128::MAX);

    /// The ASCII characters of `s`.
    pub fn of_str(s: &str) -> Self {
        let mut bits = 0u128;
        for b in s.bytes().filter(u8::is_ascii) {
            bits |= 1u128 << b;
        }
        Self(bits)
    }

    pub fn contains(self, c: char) -> bool {
        c.is_ascii() && self.0 & (1u128 << c as u32) != 0
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Every ASCII character except `byte` (any non-ASCII byte excludes none).
    fn all_but(byte: u8) -> Self {
        if byte.is_ascii() {
            Self(!(1u128 << byte))
        } else {
            Self::ALL
        }
    }

    /// The members of `self` that are not in `other`.
    pub fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl Serialize for AsciiSet {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // Two words: JSON numbers do not round-trip a full 128 bits.
        ((self.0 >> 64) as u64, self.0 as u64).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for AsciiSet {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let (hi, lo) = <(u64, u64)>::deserialize(de)?;
        Ok(Self(((hi as u128) << 64) | lo as u128))
    }
}

/// The value of a Go string literal given as the text the CFG records for it:
/// the source text between the quotes, with `is_raw` set for a backtick
/// literal (whose text is already its value).  An interpreted literal's
/// escapes are read for the single-character forms and for byte escapes below
/// 0x80; any other escape returns `None` rather than guess.
pub fn go_literal_value(text: &str, is_raw: bool) -> Option<String> {
    if is_raw {
        return Some(text.to_string());
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            'x' => {
                let hi = chars.next()?.to_digit(16)?;
                let lo = chars.next()?.to_digit(16)?;
                let byte = hi * 16 + lo;
                // A byte above 0x7f is not a character of its own in UTF-8.
                if byte > 0x7f {
                    return None;
                }
                byte as u8 as char
            }
            '\\' => '\\',
            '"' => '"',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'a' => '\x07',
            'b' => '\x08',
            'f' => '\x0c',
            'v' => '\x0b',
            _ => return None,
        });
    }
    Some(out)
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
    /// ASCII characters the string does not contain anywhere (after every
    /// backslash of `s` is replaced by a slash, no backslash is left).
    #[serde(default)]
    pub absent: AsciiSet,
    /// ASCII characters that cannot be the character at byte offset
    /// `prefix.len()` (offset 0 when there is no prefix), when the string is
    /// long enough to have one.  `"/" + strings.Trim(p, "/\\")` has prefix
    /// `/` and excludes `/` and `\` there, which is what keeps the result from
    /// reading as `//host` or `/\host`.
    #[serde(default)]
    pub next_excl: AsciiSet,
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
            absent: AsciiSet::EMPTY,
            next_excl: AsciiSet::EMPTY,
            is_bottom: false,
        }
    }

    /// Bottom: unsatisfiable / empty set.
    pub fn bottom() -> Self {
        Self {
            prefix: None,
            suffix: None,
            domain: None,
            absent: AsciiSet::EMPTY,
            next_excl: AsciiSet::EMPTY,
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
            // Every character the text lacks is absent, and nothing follows
            // it: the exclusion at the end offset holds vacuously.
            absent: AsciiSet::ALL.minus(AsciiSet::of_str(s)),
            next_excl: if s.len() <= MAX_PREFIX_LEN {
                AsciiSet::ALL
            } else {
                AsciiSet::EMPTY
            },
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
            absent: AsciiSet::EMPTY,
            next_excl: AsciiSet::EMPTY,
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
            absent: AsciiSet::EMPTY,
            next_excl: AsciiSet::EMPTY,
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
            absent: AsciiSet::EMPTY,
            next_excl: AsciiSet::EMPTY,
            is_bottom: false,
        }
    }

    pub fn is_top(&self) -> bool {
        !self.is_bottom
            && self.prefix.is_none()
            && self.suffix.is_none()
            && self.domain.is_none()
            && self.absent.is_empty()
            && self.next_excl.is_empty()
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
        let at = prefix.as_deref().map_or(0, str::len);
        Self {
            next_excl: self.excl_at(at).intersect(other.excl_at(at)),
            absent: self.absent.intersect(other.absent),
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
        let at = prefix.as_deref().map_or(0, str::len);
        Self {
            next_excl: self.excl_at(at).union(other.excl_at(at)),
            absent: self.absent.union(other.absent),
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
        let same_exclusions = self.absent == other.absent && self.next_excl == other.next_excl;
        Self {
            prefix,
            suffix,
            domain,
            absent: if same_exclusions {
                self.absent
            } else {
                AsciiSet::EMPTY
            },
            next_excl: if same_exclusions {
                self.next_excl
            } else {
                AsciiSet::EMPTY
            },
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
        let other_at = other.prefix.as_deref().map_or(0, str::len);
        let excl_ok = other.absent.is_subset_of(self.absent)
            && other.next_excl.is_subset_of(self.excl_at(other_at));
        prefix_ok && suffix_ok && domain_ok && excl_ok
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
        let at = self.prefix.as_deref().map_or(0, str::len);
        if let Some(lead) = self.exact_text() {
            // `lead + other`: the prefix grows by `other`'s own, and the
            // character after it is `other`'s.
            let tail = other.prefix.as_deref().unwrap_or("");
            let joined = format!("{lead}{tail}");
            let (prefix, next_excl) = if joined.len() <= MAX_PREFIX_LEN {
                (joined, other.excl_at(tail.len()))
            } else {
                (truncate_prefix(&joined), AsciiSet::EMPTY)
            };
            return Self {
                prefix: if prefix.is_empty() {
                    None
                } else {
                    Some(prefix)
                },
                suffix: other.suffix.clone(),
                domain: None,
                absent: self.absent.intersect(other.absent),
                next_excl,
                is_bottom: false,
            };
        }
        // The character just past `self`'s prefix is `self`'s own when `self`
        // is known to have one, and `other`'s first when `self` may end at
        // the prefix.
        let next_excl = if self.has_char_at_prefix_end() {
            self.excl_at(at)
        } else {
            self.excl_at(at).intersect(other.excl_at(0))
        };
        Self {
            prefix: self.prefix.clone(),
            suffix: other.suffix.clone(),
            domain: None,
            absent: self.absent.intersect(other.absent),
            next_excl,
            is_bottom: false,
        }
    }

    /// The whole text when this fact pins exactly one string that the prefix
    /// holds in full.
    fn exact_text(&self) -> Option<&str> {
        match (&self.domain, &self.prefix) {
            (Some(values), Some(prefix)) if values.len() == 1 && values[0] == *prefix => {
                Some(prefix)
            }
            (Some(values), None) if values.len() == 1 && values[0].is_empty() => Some(""),
            _ => None,
        }
    }

    /// True when every string this fact describes is longer than its known
    /// prefix, so [`Self::next_excl`] always has a character to apply to.
    /// A string that ends in a known suffix the prefix does not itself end in
    /// cannot stop at the prefix.
    fn has_char_at_prefix_end(&self) -> bool {
        if self.exact_text().is_some() {
            return false;
        }
        let prefix = self.prefix.as_deref().unwrap_or("");
        match (&self.domain, &self.suffix) {
            (Some(values), _) if values.iter().all(|v| v.len() > prefix.len()) => true,
            (_, Some(suffix)) => !prefix.ends_with(suffix.as_str()),
            _ => false,
        }
    }

    /// ASCII characters that cannot be the character at byte offset `pos`.
    /// Inside the known prefix every character but the prefix's own is
    /// excluded; at its end, [`Self::next_excl`]; the characters that occur
    /// nowhere are excluded at every offset.
    pub fn excl_at(&self, pos: usize) -> AsciiSet {
        let plen = self.prefix.as_deref().map_or(0, str::len);
        let here = match &self.prefix {
            Some(p) if pos < plen => AsciiSet::all_but(p.as_bytes()[pos]),
            _ if pos == plen => self.next_excl,
            _ => AsciiSet::EMPTY,
        };
        here.union(self.absent)
    }

    /// True when the fact claims any excluded character.
    pub fn has_exclusions(&self) -> bool {
        self.absent != AsciiSet::EMPTY || self.next_excl != AsciiSet::EMPTY
    }

    /// The same fact without its character-exclusion claims.
    pub fn without_exclusions(&self) -> Self {
        Self {
            absent: AsciiSet::EMPTY,
            next_excl: AsciiSet::EMPTY,
            ..self.clone()
        }
    }

    /// `strings.Trim` / `TrimLeft` / `TrimRight` with a literal cutset.  The
    /// result is a substring of `self`, so what `self` never contains it never
    /// contains; trimming from the left leaves a first character outside the
    /// cutset.  Trimming only from the right keeps `self`'s own first
    /// character.
    pub fn trimmed(&self, cutset: AsciiSet, from_left: bool, from_right: bool) -> Self {
        if self.is_bottom {
            return Self::bottom();
        }
        let first = if from_left {
            cutset
        } else if from_right {
            self.excl_at(0)
        } else {
            AsciiSet::EMPTY
        };
        Self {
            prefix: None,
            suffix: None,
            domain: None,
            absent: self.absent,
            next_excl: first.union(self.absent),
            is_bottom: false,
        }
    }

    /// `strings.ReplaceAll(self, old, new)` for a single-character `old` and a
    /// literal `new` (given as its character set): when `new` does not
    /// contain `old`, the result contains no `old` at all.  Every other
    /// character of `new` may now appear anywhere.
    pub fn with_char_replaced(&self, old: char, new_chars: AsciiSet) -> Self {
        if self.is_bottom {
            return Self::bottom();
        }
        let mut absent = self.absent.minus(new_chars);
        if !new_chars.contains(old) {
            absent = absent.union(AsciiSet::of_str(old.encode_utf8(&mut [0; 4])));
        }
        Self {
            prefix: None,
            suffix: None,
            domain: None,
            absent,
            next_excl: absent,
            is_bottom: false,
        }
    }

    /// SSRF helper: the fact for a URL built by *resolving* `path` against a
    /// literal absolute `base` (`new URL(path, base)`, `urljoin(base, path)`,
    /// `URI.join(base, path)`, `new URL(context, spec)`).
    ///
    /// Resolution is not concatenation: an absolute or protocol-relative
    /// `path` replaces the base's host, so the origin stays pinned only when
    /// `path` is provably a host-preserving relative reference (see
    /// [`prefix_is_host_preserving_reference`]).  Otherwise the result is
    /// Top and the sink keeps its SSRF finding.  When the origin is pinned
    /// the known prefix is `scheme://host/`; the base's own path is not
    /// claimed because `..` segments in `path` can climb out of it.
    pub fn from_url_with_base(base: &str, path: &Self) -> Self {
        let Some(origin) = url_origin(base) else {
            return Self::top();
        };
        let preserved = match &path.domain {
            Some(values) => values.iter().all(|v| exact_is_host_preserving_reference(v)),
            None => path
                .prefix
                .as_deref()
                .is_some_and(prefix_is_host_preserving_reference),
        };
        if !preserved || path.is_bottom {
            return Self::top();
        }
        Self::from_prefix(&format!("{origin}/"))
    }

    /// SSRF helper: the fact for a URL built by *appending* path elements to a
    /// literal `base` (Go `url.JoinPath(base, elem...)`).  Elements are joined
    /// and cleaned as path segments, so no element can change the host and the
    /// origin stays pinned whatever the elements hold.  `base` keeps the path
    /// separator the SSRF check looks for (`scheme://host/`).
    pub fn from_url_joined_path(base: &str, elements: &Self) -> Self {
        let mut anchor = base.to_string();
        if !anchor.ends_with('/') {
            anchor.push('/');
        }
        StringFact::exact(&anchor).concat(elements)
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
        // A known left operand is followed by the right operand's own prefix.
        assert_eq!(c.prefix.as_deref(), Some("hello world"));
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
    /// non-empty operand's prefix/suffix. A known left operand is followed
    /// by the right operand's own prefix, and the right operand's suffix is
    /// the result's.  `exact("")` is the identity on both sides.
    #[test]
    fn concat_empty_string_lhs_preserves_rhs_suffix() {
        let empty = StringFact::exact("");
        let rhs = StringFact::exact("x");
        let r = empty.concat(&rhs);
        assert_eq!(r.prefix.as_deref(), Some("x"));
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

    /// Resolving a reference against a base pins the origin only when the
    /// reference is provably relative to it.  A path of unknown content can be
    /// `https://evil/` or `//evil/`, either of which replaces the host.
    #[test]
    fn from_url_with_base_does_not_lock_unknown_path() {
        let base = "https://api.cal.com";
        assert!(StringFact::from_url_with_base(base, &StringFact::top()).is_top());
        assert!(StringFact::from_url_with_base(base, &StringFact::from_suffix(".json")).is_top());
    }

    #[test]
    fn from_url_with_base_locks_host_preserving_prefix() {
        let base = "https://api.cal.com/v1/";
        for prefix in ["/users/", "v2/", "?q=", "#frag", "a/b"] {
            let f = StringFact::from_url_with_base(base, &StringFact::from_prefix(prefix));
            assert_eq!(
                f.prefix.as_deref(),
                Some("https://api.cal.com/"),
                "prefix {prefix:?} keeps the origin"
            );
        }
        // Fully known references need no terminator.
        let f = StringFact::from_url_with_base(base, &StringFact::exact("users"));
        assert_eq!(f.prefix.as_deref(), Some("https://api.cal.com/"));
        let f = StringFact::from_url_with_base(base, &StringFact::exact(""));
        assert_eq!(f.prefix.as_deref(), Some("https://api.cal.com/"));
    }

    #[test]
    fn from_url_with_base_rejects_origin_replacing_prefix() {
        let base = "https://api.cal.com/";
        for prefix in [
            "//evil.com/",
            "/\\evil.com",
            "/",
            "\\evil.com",
            "https://evil.com/",
            "evil:",
            // No terminator yet: unknown text can complete a scheme.
            "users",
            "a",
            " //evil.com",
            "/\tx",
        ] {
            let f = StringFact::from_url_with_base(base, &StringFact::from_prefix(prefix));
            assert!(f.is_top(), "prefix {prefix:?} can leave the origin");
        }
        for exact in ["//evil.com", "https://evil.com", "mailto:x@y", "/"] {
            let f = StringFact::from_url_with_base(base, &StringFact::exact(exact));
            // A lone "/" is the only host-preserving one of these.
            assert_eq!(!f.is_top(), exact == "/", "exact {exact:?}");
        }
    }

    #[test]
    fn from_url_with_base_needs_an_absolute_base() {
        let path = StringFact::from_prefix("/users/");
        assert!(StringFact::from_url_with_base("/internal", &path).is_top());
        assert!(StringFact::from_url_with_base("api.example.com", &path).is_top());
        assert!(StringFact::from_url_with_base("https://", &path).is_top());
    }

    /// Go `JoinPath` appends elements as path segments, so the base prefix
    /// survives any element, including a tainted one.
    #[test]
    fn from_url_joined_path_locks_under_tainted_elements() {
        let f = StringFact::from_url_joined_path("https://api.cal.com", &StringFact::top());
        assert_eq!(f.prefix.as_deref(), Some("https://api.cal.com/"));
        assert!(f.suffix.is_none());
        let f = StringFact::from_url_joined_path(
            "https://api.cal.com/",
            &StringFact::from_suffix(".json"),
        );
        assert_eq!(f.prefix.as_deref(), Some("https://api.cal.com/"));
        assert_eq!(f.suffix.as_deref(), Some(".json"));
    }

    /// A `/path` prefix names a path on the current origin for a URL client,
    /// but a local file for a callee that opens paths (PHP stream functions).
    #[test]
    fn site_relative_prefix_does_not_lock_local_path_readers() {
        for callee in [
            "file_get_contents",
            "fopen",
            "\\file_get_contents",
            "URI.open",
            "URI::open",
            "Kernel.open",
            "open",
            "OpenURI.open_uri",
        ] {
            assert!(
                !prefix_locks_origin_for(Some(callee), "/var/data/"),
                "{callee}"
            );
            assert!(
                prefix_locks_origin_for(Some(callee), "https://api.example.com/"),
                "{callee}"
            );
        }
        assert!(prefix_locks_origin_for(Some("axios.get"), "/api/"));
        // A browser navigation sink named `open` stays same-origin locked.
        assert!(prefix_locks_origin_for(Some("window.open"), "/reports/"));
        assert!(prefix_locks_origin_for(Some("File.open"), "/reports/"));
        assert!(prefix_locks_origin_for(None, "/api/"));
        assert!(!prefix_locks_origin_for(None, "//evil.com/"));
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

    // ── Character exclusions ────────────────────────────────────────

    fn cutset(s: &str) -> AsciiSet {
        AsciiSet::of_str(s)
    }

    /// `extra` plus every character a URL parser drops (C0 controls, space).
    fn with_controls(extra: &str) -> String {
        let mut s = String::from(extra);
        s.extend((0u8..=0x20).map(|b| b as char));
        s
    }

    /// `"/" + strings.Trim(p, cutset)`.
    fn slash_then_trim(input: &StringFact, set: &str) -> StringFact {
        StringFact::exact("/").concat(&input.trimmed(cutset(set), true, true))
    }

    #[test]
    fn slash_plus_trim_locks_origin_only_when_both_separators_are_trimmed() {
        let p = StringFact::top();
        assert!(fact_locks_origin_for(
            None,
            &slash_then_trim(&p, &with_controls("/\\"))
        ));
        assert!(!fact_locks_origin_for(None, &slash_then_trim(&p, "/")));
        assert!(!fact_locks_origin_for(None, &slash_then_trim(&p, "\\")));
        assert!(!fact_locks_origin_for(None, &slash_then_trim(&p, "x")));
        // No trim at all: the bare prefix alone is not a lock.
        assert!(!fact_locks_origin_for(
            None,
            &StringFact::exact("/").concat(&p)
        ));
    }

    #[test]
    fn url_parser_dropped_characters_keep_the_origin_open() {
        // `"/" + Trim(p, "/\\")` can be `"/\t/evil.com"`, which a browser reads
        // as `//evil.com`.
        let p = StringFact::top();
        assert!(!fact_locks_origin_for(None, &slash_then_trim(&p, "/\\")));
        for skipped in ["\t", "\r", "\n", "\x01", " "] {
            let missing_one: String = with_controls("/\\").replace(skipped, "");
            assert!(
                !fact_locks_origin_for(None, &slash_then_trim(&p, &missing_one)),
                "{skipped:?}"
            );
        }
        // Backslash rewrite then Trim of '/' leaves a tab possible as well.
        let no_backslash = StringFact::top().with_char_replaced('\\', cutset("/"));
        assert!(!fact_locks_origin_for(
            None,
            &slash_then_trim(&no_backslash, "/")
        ));
    }

    #[test]
    fn aliased_variable_loses_exclusions_only() {
        let f = slash_then_trim(&StringFact::top(), &with_controls("/\\"));
        assert!(f.has_exclusions());
        let stripped = f.without_exclusions();
        assert!(!stripped.has_exclusions());
        assert_eq!(stripped.prefix.as_deref(), Some("/"));
        assert!(!fact_locks_origin_for(None, &stripped));
    }

    #[test]
    fn replaced_backslash_then_trimmed_slash_locks_origin() {
        let no_backslash = StringFact::top().with_char_replaced('\\', cutset("/"));
        assert!(no_backslash.absent.contains('\\'));
        assert!(fact_locks_origin_for(
            None,
            &slash_then_trim(&no_backslash, &with_controls("/"))
        ));
        // Replacing with text that holds a backslash proves nothing.
        let still = StringFact::top().with_char_replaced('\\', cutset("\\/"));
        assert!(!fact_locks_origin_for(
            None,
            &slash_then_trim(&still, &with_controls("/"))
        ));
        // Replacing `/` instead leaves a possible backslash at the front.
        let other = StringFact::top().with_char_replaced('/', cutset("-"));
        assert!(!fact_locks_origin_for(
            None,
            &slash_then_trim(&other, &with_controls("/"))
        ));
    }

    #[test]
    fn trim_right_only_keeps_the_first_character_open() {
        let right = StringFact::top().trimmed(cutset(&with_controls("/\\")), false, true);
        assert!(!fact_locks_origin_for(
            None,
            &StringFact::exact("/").concat(&right)
        ));
    }

    #[test]
    fn exclusion_survives_a_literal_suffix_but_not_an_unknown_tail() {
        let head = slash_then_trim(&StringFact::top(), &with_controls("/\\"));
        // `head + "?" + q` (Sprintf("%s?%s", head, q)).
        let with_query = head
            .concat(&StringFact::exact("?"))
            .concat(&StringFact::top());
        assert!(fact_locks_origin_for(None, &with_query));
        // The trimmed part may be empty, so a literal after it is what
        // follows `/` then; one that starts with `/` is not a lock.
        let bad = slash_then_trim(&StringFact::top(), &with_controls("/\\"))
            .concat(&StringFact::exact("/x"));
        assert!(!fact_locks_origin_for(None, &bad));
    }

    #[test]
    fn join_keeps_only_exclusions_both_sides_share() {
        let both = slash_then_trim(&StringFact::top(), &with_controls("/\\"));
        let forward = slash_then_trim(&StringFact::top(), &with_controls("/"));
        assert!(fact_locks_origin_for(None, &both.join(&both)));
        assert!(!fact_locks_origin_for(None, &both.join(&forward)));
        // A join with a known-safe literal head keeps the lock.
        let literal = StringFact::from_prefix("/dash");
        assert!(fact_locks_origin_for(None, &both.join(&literal)));
    }

    #[test]
    fn exclusions_do_not_lock_a_local_path_reader() {
        let head = slash_then_trim(&StringFact::top(), &with_controls("/\\"));
        assert!(!fact_locks_origin_for(Some("file_get_contents"), &head));
    }

    #[test]
    fn exact_concat_extends_the_prefix() {
        let r = StringFact::exact("/api/").concat(&StringFact::from_prefix("v1/"));
        assert_eq!(r.prefix.as_deref(), Some("/api/v1/"));
        let lead = StringFact::exact("");
        assert_eq!(
            lead.concat(&StringFact::from_prefix("abc"))
                .prefix
                .as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn exclusion_fields_keep_lattice_laws() {
        let a = slash_then_trim(&StringFact::top(), &with_controls("/\\"));
        let b = StringFact::exact("/x");
        assert_eq!(a.join(&a), a);
        assert!(a.leq(&a.join(&b)));
        assert!(b.leq(&a.join(&b)));
        let exact = StringFact::exact("/");
        assert_eq!(exact.join(&exact), exact);
        assert!(exact.leq(&a));
        assert!(!StringFact::from_prefix("/").leq(&a));
        // Widening drops a changed exclusion rather than keeping a stale one.
        let w = a.widen(&StringFact::from_prefix("/"));
        assert!(!fact_locks_origin_for(None, &w));
    }

    #[test]
    fn exclusion_sets_round_trip_through_json() {
        let f = StringFact::top()
            .with_char_replaced('\\', cutset("/"))
            .trimmed(cutset("/"), true, true);
        let json = serde_json::to_string(&f).unwrap();
        let back: StringFact = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
        // Older blobs without the fields still load.
        let old: StringFact =
            serde_json::from_str(r#"{"prefix":"/","suffix":null,"domain":null,"is_bottom":false}"#)
                .unwrap();
        assert_eq!(old, StringFact::from_prefix("/"));
    }

    #[test]
    fn go_literal_values_read_interpreted_and_raw_text() {
        assert_eq!(go_literal_value("/\\\\", false).as_deref(), Some("/\\"));
        assert_eq!(go_literal_value("\\n", false).as_deref(), Some("\n"));
        assert_eq!(go_literal_value("\\x41", false).as_deref(), Some("A"));
        assert_eq!(go_literal_value("\\xff", false), None);
        assert_eq!(go_literal_value("\\\\", true).as_deref(), Some("\\\\"));
        assert_eq!(go_literal_value("a\\", false), None);
    }
}
