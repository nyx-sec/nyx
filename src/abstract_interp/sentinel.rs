//! Text-level recognition of a predicate atom compared against a sentinel
//! literal (`f(x) === false`, `A.indexOf(x) === -1`, `M[x] === undefined`).
//!
//! Shared by the taint predicate classifier and the path-fact classifiers so
//! a comparison against a sentinel decides which edge an atom holds on in
//! exactly one place.

/// Check if a string is a simple identifier (letters, digits, underscores, dots).
pub(crate) fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

/// How a trailing comparison against a sentinel literal changes the polarity
/// of the predicate atom it wraps.  See [`sentinel_comparison_polarity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentinelPolarity {
    /// No single top-level comparison against a sentinel literal.
    NoComparison,
    /// The comparison keeps the atom's polarity (`f(x) === true`,
    /// `A.indexOf(x) !== -1`, `M[x] !== undefined`).
    Same,
    /// The comparison inverts it (`f(x) === false`, `f(x) is not True`,
    /// `A.indexOf(x) === -1`, `M[x] === undefined`).
    Flip,
    /// A sentinel whose meaning is ambiguous for this atom
    /// (`M[x] === false` cannot tell a missing key from a `false` value,
    /// `A.indexOf(x) === 0`).  Callers should validate neither branch.
    Opaque,
}

/// Classify a branch condition of the form `<atom> <op> <sentinel>` (or the
/// Yoda form `<sentinel> <op> <atom>`), where the atom is the predicate the
/// rest of the classifier recognises: a call (`isValid(x)`,
/// `ALLOWED.includes(x)`, `in_array($x, $a)`), an `indexOf` result, a map
/// lookup (`ALLOWED[x]`), or a bare identifier.
///
/// `path_state::classify_condition` classifies such text by the inner atom, so without
/// this the TRUE edge of `ALLOWED.includes(cmd) === false` would be treated
/// as the validated one.  A whole-condition `!( ... )` / `not ...` is
/// peeled first because the CFG already reports it as `condition_negated`;
/// a `!` bound to the atom alone (`!isValid(x) === true`) is folded in here.
///
/// Sentinels are `true`, `false`, `undefined`, `-1` and `0`, matched case
/// insensitively (Python `True` / `False`).  `null` / `None` / `nil` are left
/// to the null-check classifier.  Conditions with a top-level `&&` / `||`,
/// or with more than one comparison, return
/// [`SentinelPolarity::NoComparison`].
pub fn sentinel_comparison_polarity(text: &str) -> SentinelPolarity {
    use super::path_domain::{strip_leading_not, strip_outer_parens};

    let mut t = strip_outer_parens(text.trim());
    if let Some(rest) = strip_leading_not(t) {
        let rest = rest.trim_start();
        let python_not = !t.trim_start().starts_with('!');
        let inner = strip_outer_parens(rest);
        if python_not || inner.len() < rest.len() {
            t = inner;
        }
    }

    let Some((lhs, op, rhs)) = split_single_comparison(t) else {
        return SentinelPolarity::NoComparison;
    };
    let (atom, sentinel, op) = match (sentinel_literal(rhs), sentinel_literal(lhs)) {
        (Some(s), None) => (lhs, s, op),
        (None, Some(s)) => (rhs, s, mirror_comparison(op)),
        _ => return SentinelPolarity::NoComparison,
    };

    // Every `!` bound to the atom flips it once (`!!f(x) === true`).
    let mut atom = atom;
    let mut local_not = false;
    while let Some(rest) = atom.strip_prefix('!') {
        if rest.starts_with('=') {
            break;
        }
        atom = rest.trim_start();
        local_not = !local_not;
    }

    let eq = matches!(op, "==" | "===" | "is");
    let ne = matches!(op, "!=" | "!==" | "is not");
    let lower_atom = atom.to_ascii_lowercase();

    let base = if lower_atom.contains(".indexof(") {
        match (op, sentinel) {
            ("==" | "===", "-1") | ("<", "0") | ("<=", "-1") => SentinelPolarity::Flip,
            ("!=" | "!==", "-1") | (">=", "0") | (">", "-1") => SentinelPolarity::Same,
            _ => SentinelPolarity::Opaque,
        }
    } else if is_index_lookup_atom(atom) {
        match sentinel {
            "undefined" if eq => SentinelPolarity::Flip,
            "undefined" if ne => SentinelPolarity::Same,
            "true" if eq => SentinelPolarity::Same,
            "true" if ne => SentinelPolarity::Flip,
            _ => SentinelPolarity::Opaque,
        }
    } else if atom.contains('(') || is_identifier(atom) {
        // Boolean predicate result: a call or a variable holding one.
        // Numeric sentinels on a call (`strpos($x, "/") === 0`) belong to
        // other idioms and are left alone.
        match sentinel {
            "true" if eq => SentinelPolarity::Same,
            "true" if ne => SentinelPolarity::Flip,
            "false" if eq => SentinelPolarity::Flip,
            "false" if ne => SentinelPolarity::Same,
            "undefined" if atom.contains('(') => SentinelPolarity::Opaque,
            _ => SentinelPolarity::NoComparison,
        }
    } else {
        SentinelPolarity::NoComparison
    };

    match (base, local_not) {
        (SentinelPolarity::Flip, true) => SentinelPolarity::Same,
        (SentinelPolarity::Same, true) => SentinelPolarity::Flip,
        (other, _) => other,
    }
}

/// Normalise a sentinel operand: `true` / `false` / `undefined` / `-1` /
/// `0`, case-insensitive.  Returns `None` for anything else.
fn sentinel_literal(operand: &str) -> Option<&'static str> {
    let compact: String = operand.chars().filter(|c| !c.is_whitespace()).collect();
    match compact.to_ascii_lowercase().as_str() {
        "true" => Some("true"),
        "false" => Some("false"),
        "undefined" => Some("undefined"),
        "-1" => Some("-1"),
        "0" => Some("0"),
        _ => None,
    }
}

/// Swap the operand order of a comparison operator (`a < b` == `b > a`).
fn mirror_comparison(op: &'static str) -> &'static str {
    match op {
        "<" => ">",
        ">" => "<",
        "<=" => ">=",
        ">=" => "<=",
        other => other,
    }
}

/// `IDENT[IDENT]`, the map-lookup atom also accepted by
/// [`is_index_membership_check`].
fn is_index_lookup_atom(atom: &str) -> bool {
    let Some(open) = atom.find('[') else {
        return false;
    };
    let Some(inner) = atom[open + 1..].strip_suffix(']') else {
        return false;
    };
    is_identifier(atom[..open].trim()) && is_identifier(inner.trim())
}

/// Split `text` into `(lhs, op, rhs)` when it holds exactly one comparison
/// operator outside parens, brackets and string literals, and no top-level
/// `&&` / `||` / `and` / `or`.  `->` and `=>` are not comparisons.
pub(crate) fn split_single_comparison(text: &str) -> Option<(&str, &'static str, &str)> {
    let bytes = text.as_bytes();
    let mut depth: i32 = 0;
    let mut in_quote: Option<u8> = None;
    let mut found: Option<(usize, usize, &'static str)> = None;
    let mut i = 0usize;
    let word_at = |i: usize, w: &[u8]| -> bool {
        i > 0
            && bytes[i - 1] == b' '
            && bytes.len() > i + w.len()
            && bytes[i..i + w.len()].eq_ignore_ascii_case(w)
            && bytes[i + w.len()] == b' '
    };
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if depth == 0 {
            if word_at(i, b"and") || word_at(i, b"or") {
                return None;
            }
            let two = bytes.get(i..i + 2);
            if two == Some(b"&&") || two == Some(b"||") {
                return None;
            }
        }
        let op: Option<(&'static str, usize)> = match b {
            b'"' | b'\'' | b'`' => {
                in_quote = Some(b);
                None
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                None
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                None
            }
            _ if depth != 0 => None,
            b'=' | b'!' if bytes.get(i + 1) == Some(&b'=') => {
                let strict = bytes.get(i + 2) == Some(&b'=');
                match (b, strict) {
                    (b'=', true) => Some(("===", 3)),
                    (b'=', false) => Some(("==", 2)),
                    (_, true) => Some(("!==", 3)),
                    (_, false) => Some(("!=", 2)),
                }
            }
            b'<' | b'>' => {
                let prev = if i > 0 { bytes[i - 1] } else { b' ' };
                if b == b'>' && (prev == b'-' || prev == b'=') {
                    None
                } else if bytes.get(i + 1) == Some(&b'=') {
                    Some((if b == b'<' { "<=" } else { ">=" }, 2))
                } else if bytes.get(i + 1) == Some(&b) {
                    // `<<` / `>>` shifts are not comparisons; skip both bytes.
                    i += 1;
                    None
                } else {
                    Some((if b == b'<' { "<" } else { ">" }, 1))
                }
            }
            b'i' | b'I' if depth == 0 && word_at(i, b"is") => {
                if word_at(i + 3, b"not") {
                    Some(("is not", 6))
                } else {
                    Some(("is", 2))
                }
            }
            _ => None,
        };
        if let Some((op, len)) = op {
            if found.is_some() {
                return None;
            }
            found = Some((i, len, op));
            i += len;
            continue;
        }
        i += 1;
    }
    let (pos, len, op) = found?;
    let lhs = text[..pos].trim();
    let rhs = text[pos + len..].trim();
    if lhs.is_empty() || rhs.is_empty() {
        return None;
    }
    Some((lhs, op, rhs))
}
