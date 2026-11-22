//! Predicate tracking for path-sensitive taint.
//!
//! Classifies if-conditions (`PredicateKind` / `classify_condition`) and narrows
//! validation to specific targets, so branch outcomes can validate or contradict
//! tainted values during the SSA taint solve.

pub use crate::abstract_interp::sentinel::{SentinelPolarity, sentinel_comparison_polarity};
use crate::abstract_interp::sentinel::{is_identifier, split_single_comparison};

// ─── PredicateKind ───────────────────────────────────────────────────────────

/// Classification of what an if-condition tests.
///
/// Determined by heuristic analysis of the raw condition text.
/// Classification is conservative: prefer [`Unknown`](PredicateKind::Unknown)
/// over a wrong guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateKind {
    /// `x.is_none()`, `x == null`, `x == nil`, `x is None`
    NullCheck,
    /// `x.is_empty()`, `x.len() == 0`, `x == ""`
    EmptyCheck,
    /// `x.is_err()`, `x.is_ok()`, `err != nil`
    ErrorCheck,
    /// Call to a validation/guard function: `validate(x)`, `is_safe(x)`
    ValidationCall,
    /// Call to a sanitizer function: `sanitize(x)`, `escape(x)`
    SanitizerCall,
    /// Allowlist/membership check: `.includes(x)`, `x in ALLOWED`, `in_array(x, ...)`
    AllowlistCheck,
    /// Type-check guard: `typeof x`, `isinstance(x, int)`, `is_numeric(x)`
    TypeCheck,
    /// Negative-validation of shell metacharacters:
    /// `x.contains(";")`, `x.match(/[;|&]/)`, `";" in x`, etc.
    ///
    /// The **true branch is the REJECT path** (early return / panic / throw)
    /// and the **false branch is the validated path**.  Use inverted polarity
    /// when applying branch predicates.
    ShellMetaValidated,
    /// Inline relative-URL validation held in one undecomposed condition:
    /// `x.startsWith("/") && !x.startsWith("//")`.  The TRUE branch
    /// constrains `x` to a same-origin path (leading `/`, no `//host`).
    /// Cap-aware: clears [`crate::labels::Cap::OPEN_REDIRECT`] only on the
    /// validated branch so non-redirect sinks downstream still fire on the
    /// residual taint.  The usual split form (one branch per clause) is
    /// tracked by [`LeadingSlashCheck`](Self::LeadingSlashCheck) and
    /// [`ProtocolRelativeCheck`](Self::ProtocolRelativeCheck) instead.
    RelativeUrlValidated,
    /// One half of the inline relative-URL check: `x.startsWith("/")`,
    /// `x.starts_with("/")`, `x.startswith("/")`, `strpos($x, "/") === 0`,
    /// `x[0] === '/'`.  On its own it proves nothing about the host:
    /// `//evil.com` and `/\evil.com` start with `/` and browsers resolve both
    /// as protocol-relative.  The branch sets a predicate bit, and
    /// OPEN_REDIRECT is cleared only once
    /// [`ProtocolRelativeCheck`](Self::ProtocolRelativeCheck) has also been
    /// seen false on the same path.
    LeadingSlashCheck,
    /// `x.startsWith("//")` / `x.startsWith("/\\")` / `x[1] === '/'`.  The
    /// TRUE branch is the protocol-relative (reject) case; the FALSE branch
    /// proves the value has no authority prefix.  Pairs with
    /// [`LeadingSlashCheck`](Self::LeadingSlashCheck).
    ProtocolRelativeCheck,
    /// Inline URL-parse + host-allowlist validation:
    /// `new URL(x).host === ALLOWED` (JS/TS),
    /// `urlparse(x).netloc == ALLOWED` (Python),
    /// `urlparse(x).hostname in ALLOWED_HOSTS` (Python).
    /// The TRUE branch constrains the parsed URL's host to a developer-chosen
    /// allowlist value, the canonical multi-statement open-redirect sanitiser
    /// for absolute URLs.  Cap-aware: clears
    /// [`crate::labels::Cap::OPEN_REDIRECT`] only on the validated branch so
    /// non-redirect sinks downstream still fire on residual taint.
    HostAllowlistValidated,
    /// C path-prefix confinement: `strncmp(x, prefix, strlen(prefix))` /
    /// `strncmp(x, prefix, N)` (also `strncasecmp`).  `strncmp` returns 0 when
    /// `x` begins with `prefix`, so the idiomatic guard
    /// `if (strncmp(x, prefix, strlen(prefix))) reject;` rejects paths that do
    /// **not** start with the fixed prefix — a directory-confinement check.
    /// Inverted polarity like [`ShellMetaValidated`](Self::ShellMetaValidated):
    /// the TRUE (non-zero) branch is the reject path, the FALSE (starts-with)
    /// branch is confined.  Cap-aware: clears
    /// [`crate::labels::Cap::FILE_IO`] only on the confined branch so
    /// non-file sinks downstream still fire on residual taint.  Surfaced by
    /// CVE-2020-5221 (uftpd), whose fix moved the check from the unresolved
    /// `dir` onto the `realpath()`-resolved `rpath`.
    PathPrefixConfined,
    /// A boolean predicate whose name states that a URL is safe to redirect
    /// to (`safe_for_redirect(x)`, `is_safe_redirect_url(x)`).  The TRUE
    /// branch is the validated path.  Cap-aware: clears
    /// [`crate::labels::Cap::OPEN_REDIRECT`] only, so a `*_url` guard never
    /// vouches for SQL, shell or file sinks.  Only recognised as a plain
    /// call that is a conjunct of the condition, since a disjunction does
    /// not hold the predicate on its true edge.
    RedirectValidator,
    /// A boolean predicate whose name states that a host or address is
    /// internal or blocked (`IsHostnameInternal(host)`, `is_private_ip(ip)`).
    /// Inverted polarity: the TRUE branch is the reject path and the FALSE
    /// branch is the validated one.  Cap-aware: clears
    /// [`crate::labels::Cap::SSRF`] only.  Only recognised as a plain call
    /// that is a disjunct of the condition, since a conjunction does not
    /// hold the predicate false on its false edge.
    HostDenylistRejected,
    /// Bounded-length rejection: `x.len() > N` / `x.length < N` with N >= 2.
    ///
    /// Commonly paired with `ShellMetaValidated` in OR-chain rejection
    /// idioms (`if x.len() > MAX || x.contains(";") { reject }`).  Counts as
    /// a dominator guard for `cfg-unguarded-sink` purposes, but intentionally
    /// does **not** mark variables as validated, the rejection direction is
    /// ambiguous from the condition alone (a `.len() > 5 { sink(x) }`
    /// gate is a precondition, not a rejection).
    BoundedLength,
    /// Comparison operators: `x == 5`, `x > threshold`
    Comparison,
    /// Generic boolean test, cannot classify further.
    Unknown,
}

/// Single-character shell metacharacters that a rejection check commonly
/// guards against before constructing a shell command.
///
/// Presence of any of these in user input is sufficient to enable shell
/// injection, so rejecting input that contains them is a real sanitizer.
/// `"foo"` or other non-metachar needles don't qualify, a rejection of
/// those is business logic, not security.
const SHELL_METACHARS: &[&str] = &[";", "|", "&", "`", "$", ">", "<", "\n", "\r", "\0"];

/// Check whether `text` matches a shell-metachar rejection idiom.
///
/// Recognizes:
/// - Rust / Java / Go: `x.contains("<METACHAR>")`
/// - JS / TS:          `x.includes("<METACHAR>")`
/// - Python:           `"<METACHAR>" in x`
/// - Ruby:             `x.include?("<METACHAR>")`
/// - Regex form:       `x.match(/[;|&]/)` / `re.search(r"[;|&]", x)` with a
///   character class containing only metacharacters.
///
/// Returns `false` if the needle is a non-metachar literal or cannot be
/// extracted, falls through to broader classification.
fn is_shell_metachar_rejection(text: &str) -> bool {
    if is_dash_prefix_rejection(text) {
        return true;
    }

    // Method-call form: `.contains(…)` / `.includes(…)` / `.include?(…)`
    for method in [".contains(", ".includes(", ".include?("] {
        if let Some(idx) = text.find(method) {
            let args_start = idx + method.len();
            if let Some(needle) = extract_first_string_arg(&text[args_start..]) {
                if SHELL_METACHARS.contains(&needle.as_str()) {
                    return true;
                }
            }
        }
    }
    // Python membership form: `"<METACHAR>" in x` (but not `x in ALLOWED`)
    if let Some(needle) = extract_python_in_needle(text) {
        if SHELL_METACHARS.contains(&needle.as_str()) {
            return true;
        }
    }
    // Regex character-class form: `.match(/[;|&]/)` / `re.search(r"[…]", …)`
    is_metachar_regex_class(text)
}

/// Detect the C/C++ argv-injection guard used before exec-family calls:
/// `host[0] == '-'` means the true branch rejects an argv element that would
/// be interpreted as an option by ssh/git/etc., while the false branch is
/// safe for shell/argv execution.
fn is_dash_prefix_rejection(text: &str) -> bool {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("[0]=='-'")
        || compact.contains("[0]==\"-\"")
        || compact.contains("'-'==")
        || compact.contains("\"-\"==")
}

/// Extract the first string literal argument from a slice starting just after
/// an opening `(` in a call expression.  Returns the raw inner text of the
/// literal (without surrounding quotes).
///
/// Handles `"..."`, `'...'`, and simple escapes `\"`, `\'`, `\\`.
fn extract_first_string_arg(after_open: &str) -> Option<String> {
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
                b'0' => out.push(b'\0'),
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

/// For Python `"<METACHAR>" in x` (needle on the left side of ` in `), return
/// the needle.  Returns `None` for `x in ALLOWED` (identifier on the left) ,
/// that is an allowlist check, not a rejection.
fn extract_python_in_needle(text: &str) -> Option<String> {
    let pos = text.find(" in ")?;
    let left = text[..pos].trim().trim_start_matches('(').trim();
    // Strip leading `!` / `not` for rejection contexts
    let left = left.strip_prefix('!').unwrap_or(left).trim();
    let left = left.strip_prefix("not ").unwrap_or(left).trim();
    let bytes = left.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    if bytes.last() != Some(&quote) || bytes.len() < 2 {
        return None;
    }
    let inner = &left[1..left.len() - 1];
    Some(inner.to_string())
}

/// Detect regex character classes that contain only shell metacharacters:
/// `[;|&]`, `[;&`$]`, etc.  Missing: escape-class metacharacters inside the
/// class (e.g. `[\n]`), conservative, returns false there.
fn is_metachar_regex_class(text: &str) -> bool {
    // Find `[` followed by content and `]`, anywhere in the text.
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        if let Some(close) = after.find(']') {
            let inner = &after[..close];
            if !inner.is_empty()
                && inner
                    .chars()
                    .all(|c| SHELL_METACHARS.iter().any(|m| m.starts_with(c)))
            {
                return true;
            }
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    false
}

/// Check whether `text` is an inline relative-URL validation: a leading-
/// slash check on a string variable.  Recognised shapes:
///
/// * `<X>.startsWith("/")` — JS/TS/Java/Kotlin
/// * `<X>.starts_with("/")` — Rust
/// * `<X>.startswith("/")` — Python
/// * `strpos($X, "/") === 0` / `mb_strpos(...)` — PHP
/// * `<X>[0] === "/"` / `<X>[0] == '/'` — JS/TS direct index
///
/// Negation prefixes (`!`, `not`) are NOT stripped, the caller's
/// classification path handles those uniformly via the predicate
/// polarity inversion machinery.
/// Recognise a C prefix-containment guard and return the confined subject.
///
/// Matches `strncmp(subject, prefix, strlen(prefix))` / `strncmp(subject,
/// prefix, <numeric>)` (and the `strncasecmp` variant), the canonical C
/// idiom for "does `subject` begin with `prefix`".  The length argument must
/// tie the comparison to the prefix (`strlen(prefix)` or a numeric literal),
/// which is what distinguishes a genuine prefix check from an arbitrary
/// `strncmp(a, b, n)` byte comparison.  `subject` must be a bare identifier so
/// the caller can name-clear its taint.  Best-effort text analysis; scans for
/// the call anywhere in the (possibly compound) condition text.
///
/// Returns `None` when the shape does not match, keeping the classifier out of
/// this branch for unrelated `strncmp` uses.
fn path_prefix_confinement_subject(text: &str) -> Option<String> {
    for fname in ["strncmp(", "strncasecmp("] {
        let Some(pos) = text.find(fname) else {
            continue;
        };
        let args_part = &text[pos + fname.len()..];
        let args = split_top_level_args(args_part);
        if args.len() < 3 {
            continue;
        }
        let subject = args[0].trim();
        let prefix = args[1].trim();
        let length = args[2].trim();

        // The length must anchor the comparison to the prefix: `strlen(prefix)`
        // (the uftpd form), or a bare numeric constant.  Reject `sizeof(x)` and
        // arbitrary expressions so a plain `strncmp(a, b, n)` does not confine.
        let expected_strlen = format!("strlen({prefix})");
        let len_anchored = length == expected_strlen
            || (!length.is_empty() && length.bytes().all(|b| b.is_ascii_digit()));
        if !len_anchored {
            continue;
        }

        if is_identifier(subject) {
            return Some(subject.to_string());
        }
    }
    None
}

/// Split the top-level comma-separated arguments of a call, starting from the
/// substring immediately after its open paren.  Stops at the matching close
/// paren, respects nested paren/bracket/brace depth, and skips quoted strings.
fn split_top_level_args(args_part: &str) -> Vec<&str> {
    let bytes = args_part.as_bytes();
    let mut out = Vec::new();
    let mut depth: usize = 1;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    out.push(args_part[start..i].trim());
                    return out;
                }
            }
            b',' if depth == 1 => {
                out.push(args_part[start..i].trim());
                start = i + 1;
            }
            b'"' | b'\'' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        break;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Every leading-prefix test in `text`, as `(needle, negated)`:
/// `.startsWith(N)` / `.starts_with(N)` / `.startswith(N)` (all occurrences),
/// `strpos($x, N) === 0` / `mb_strpos`, and the subscript forms
/// `x[0] === '/'` (needle `/`) and `x[1] === '/'` (needle `//`).  `negated`
/// is set when the test is directly preceded by `!` / `not`, which is how a
/// clause of a conjunction says "does not start with".
fn leading_prefix_tests(text: &str) -> smallvec::SmallVec<[(String, bool); 2]> {
    let lower = text.to_ascii_lowercase();
    let mut out: smallvec::SmallVec<[(String, bool); 2]> = smallvec::SmallVec::new();
    for method in [".startswith(", ".starts_with("] {
        for (idx, _) in lower.match_indices(method) {
            let args_start = idx + method.len();
            if let Some(needle) = extract_first_string_arg(&lower[args_start..]) {
                out.push((needle, prefix_test_negated(&lower[..idx])));
            }
        }
    }
    // PHP `strpos($x, "/") === 0` / `mb_strpos($x, "/") === 0`: leading-
    // prefix detection via offset-zero substring match.  Both equality
    // forms (`===`, `==`) accepted; the `0` literal is the load-bearing
    // bit.  Bare `strpos(...)` (truthy check) is not recognised.
    for prefix in ["strpos(", "mb_strpos("] {
        for (start, _) in lower.match_indices(prefix) {
            if prefix == "strpos(" && lower[..start].ends_with("mb_") {
                continue;
            }
            let after = &lower[start + prefix.len()..];
            let Some(needle) = call_arg(after, 1) else {
                continue;
            };
            let needle = needle.trim_matches(|c: char| c == '"' || c == '\'');
            let Some(close) = matching_call_close(after) else {
                continue;
            };
            let tail = after[close + 1..].trim_start();
            if let Some(rest) = tail.strip_prefix("===").or_else(|| tail.strip_prefix("=="))
                && rest.trim_start().starts_with('0')
                && !rest.trim_start()[1..].starts_with(|c: char| c.is_ascii_digit())
            {
                let negated = prefix_test_negated(&lower[..start]);
                out.push((needle.replace("\\\\", "\\"), negated));
            }
        }
    }
    // Direct subscript form: `<X>[0] === '/'` / `<X>[1] == "/"`, with or
    // without spaces around the operator.
    for (index, needle) in [("[0]", "/"), ("[1]", "//")] {
        for op in ["===", "=="] {
            for probe in [format!("{index} {op}"), format!("{index}{op}")] {
                for (idx, _) in lower.match_indices(probe.as_str()) {
                    let after = lower[idx + probe.len()..].trim_start();
                    if after.starts_with("'/'") || after.starts_with("\"/\"") {
                        out.push((needle.to_string(), prefix_test_negated(&lower[..idx])));
                    }
                }
            }
        }
    }
    out
}

/// Byte index of the `)` closing a call whose argument list starts at
/// `args_part`.
fn matching_call_close(args_part: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (i, b) in args_part.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// True when the prefix test whose receiver ends `before` is negated on its
/// own (`!x.startsWith(..)`, `not x.startswith(..)`): the clause of the
/// enclosing condition it belongs to starts with a negation.
fn prefix_test_negated(before: &str) -> bool {
    let clause = before
        .rsplit(['&', '|', '(', ','])
        .next()
        .unwrap_or(before)
        .trim_start();
    let clause = clause
        .rsplit(" and ")
        .next()
        .unwrap_or(clause)
        .rsplit(" or ")
        .next()
        .unwrap_or(clause)
        .trim_start();
    clause.starts_with('!') || clause.starts_with("not ")
}

/// `//` and `/\` both make a browser treat the rest as a host.
fn is_protocol_relative_needle(needle: &str) -> bool {
    matches!(needle, "//" | "/\\")
}

/// `x.startsWith("/")` and friends as a single test (see
/// [`PredicateKind::LeadingSlashCheck`]).
fn is_leading_slash_check(text: &str) -> bool {
    leading_prefix_tests(text).iter().any(|(n, _)| n == "/")
}

/// `x.startsWith("//")` / `x.startsWith("/\\")` / `x[1] === '/'`, where every
/// prefix test in the text is a protocol-relative one.
fn is_protocol_relative_check(text: &str) -> bool {
    let tests = leading_prefix_tests(text);
    !tests.is_empty() && tests.iter().all(|(n, _)| is_protocol_relative_needle(n))
}

/// A condition with a top-level boolean connective, which the CFG would
/// normally have split into one branch per clause.
fn has_boolean_connective(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("&&")
        || lower.contains("||")
        || lower.contains(" and ")
        || lower.contains(" or ")
}

/// The whole relative-URL check in one conjunction:
/// `x.startsWith("/") && !x.startsWith("//")` (optionally also rejecting
/// `/\`).  The TRUE edge holds both facts.
fn is_relative_url_conjunction(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("||") || lower.contains(" or ") {
        return false;
    }
    if !(lower.contains("&&") || lower.contains(" and ")) {
        return false;
    }
    let tests = leading_prefix_tests(text);
    tests.iter().any(|(n, neg)| n == "/" && !neg) && tests.iter().any(|(n, neg)| n == "//" && *neg)
}

/// Check whether `text` is an inline URL-parse + host-allowlist validation.
///
/// Recognises the canonical multi-statement open-redirect sanitiser shapes:
///
/// * `new URL(<X>).host === ALLOWED` / `new URL(<X>).hostname === ALLOWED`
///   / `new URL(<X>).origin === ALLOWED` (JS/TS) — accepts `==` and `===`.
/// * `urlparse(<X>).netloc == ALLOWED` / `urlparse(<X>).hostname == ALLOWED`
///   (Python `urllib.parse.urlparse` and the `urlparse.urlparse` legacy alias)
///   — accepts `==`.
/// * `urllib.parse.urlparse(<X>).netloc == ALLOWED` (qualified Python form).
/// * `<parsed>.host_str() == ALLOWED` (Rust `url::Url::host_str()`).
/// * `<parsed>.Host == ALLOWED` / `<parsed>.Hostname() == ALLOWED`
///   (Go `*url.URL` — case-sensitive capital `H`).
///
/// The Rust/Go forms intentionally do not look for the parse call in the
/// condition text — those parse on a separate line (`let parsed = Url::parse(x)?`,
/// `parsed, err := url.Parse(x)`) and the validated branch then references
/// `parsed` directly as the redirect target.  Distinctive accessor names
/// (`.host_str()`, capital-`H` `.Host`/`.Hostname()`) gate the match so a bare
/// `u.host == X` (lowercase, ambiguous) still falls through to `Comparison`.
///
/// The right-hand side may be a string literal or a bare identifier
/// (`ALLOWED_HOST` / `cfg.allowed_origin`) — what matters is that the
/// validation pins the parsed host to one fixed value, locking off the
/// scheme/authority that would otherwise let the redirect leave the trusted
/// origin.  The membership form
/// `ALLOWED_HOSTS.includes(new URL(<X>).host)` / `urlparse(<X>).host in ALLOWED`
/// is intentionally NOT recognised here, those fall through to
/// `AllowlistCheck` whose generic validated-must mechanic already clears
/// every cap for the matched receiver / member token.
///
/// Negation prefixes are not stripped, the caller's polarity-inversion
/// machinery handles `!`-wrapped forms uniformly.
fn is_host_allowlist_check(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // Need an equality operator so we know the host is being pinned to a
    // specific allowed value (not e.g. assigned, indexed, or used as a key).
    if !(lower.contains("==") || lower.contains("!=")) {
        return false;
    }
    let has_parse_call = lower.contains("new url(")
        || lower.contains("urlparse(")
        || lower.contains("url.parse(")
        || lower.contains("urllib.parse.urlparse(");
    if has_parse_call {
        // Need a host-style accessor on the parse result.
        return lower.contains(".host")
            || lower.contains(".hostname")
            || lower.contains(".netloc")
            || lower.contains(".origin");
    }
    // Multi-statement form: parse happened on a prior line.  Match
    // distinctive Rust/Go accessor names so we don't misclassify a
    // generic `obj.host == X` field comparison.
    //
    //   Rust: `parsed.host_str() == Some("x")`
    //   Go:   `parsed.Host == "x"` / `parsed.Hostname() == "x"`
    //
    // `.host_str()` is Rust-specific (lowercase-stable identifier).
    // `.Host`/`.Hostname()` use case-sensitive capital `H` to avoid
    // matching lowercase `u.host` (which `host_allowlist_requires_parse_call`
    // explicitly excludes).
    if lower.contains(".host_str(") {
        return true;
    }
    if has_capital_host_accessor(text) {
        return true;
    }
    false
}

/// Test whether `text` contains a Go-style capital-`H` URL host accessor:
/// `.Host` (followed by whitespace or `==`/`!=`) or `.Hostname(`.
fn has_capital_host_accessor(text: &str) -> bool {
    if text.contains(".Hostname(") {
        return true;
    }
    let mut rest = text;
    while let Some(pos) = rest.find(".Host") {
        let after = &rest[pos + ".Host".len()..];
        // Reject `.Hostname` (handled above) and any continuation that
        // would make `.Host` part of a longer identifier (`.Hostess` etc.).
        let next = after.chars().next();
        let is_terminator = match next {
            None => true,
            Some(c) => !c.is_ascii_alphanumeric() && c != '_',
        };
        if is_terminator {
            // Require an equality op somewhere after the accessor so it's
            // a comparison, not e.g. an assignment target.
            let trimmed = after.trim_start();
            if trimmed.starts_with("==") || trimmed.starts_with("!=") {
                return true;
            }
        }
        rest = after;
    }
    false
}

/// Extract the parse-call argument from a host-allowlist condition.
///
/// Inline form (single-statement parse + check, JS/TS/Python):
/// recognises `new URL(<X>)`, `urlparse(<X>)`, `URL.parse(<X>)`,
/// `urllib.parse.urlparse(<X>)`.  Returns `Some("X")` when the argument is a
/// bare identifier (with optional `&` or PHP `$` sigil stripped).
///
/// Multi-statement form (Rust/Go): recognises the receiver of `.host_str()`,
/// case-sensitive `.Host`/`.Hostname()` and returns the receiver identifier
/// (the parsed-URL var), which is what downstream code redirects on.
///
/// Returns `None` for nested expressions / multi-arg calls so branch
/// narrowing doesn't widen to a non-existent var.  Mirrors the conservative
/// target shape used by [`extract_validation_target`].
fn extract_host_allowlist_target(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    for probe in [
        "new url(",
        "urllib.parse.urlparse(",
        "urlparse(",
        "url.parse(",
    ] {
        if let Some(idx) = lower.find(probe) {
            let args_start = idx + probe.len();
            if args_start <= text.len() {
                if let Some(first_arg) = first_call_arg(&text[args_start..]) {
                    let first_arg = first_arg.strip_prefix('&').unwrap_or(first_arg).trim();
                    let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
                    if !first_arg.is_empty() && is_identifier(first_arg) {
                        return Some(first_arg.to_string());
                    }
                }
            }
        }
    }
    // Multi-statement form: receiver of the host accessor is the
    // parsed-URL var.  Walk the original text (case-sensitive for Go).
    extract_host_accessor_receiver(text)
}

/// Walk `text` for `<receiver>.host_str(` (Rust), `<receiver>.Host` followed
/// by `==`/`!=` (Go), or `<receiver>.Hostname(` (Go).  Returns `Some(receiver)`
/// when the receiver is a bare identifier (optionally with a `&` deref-prefix
/// stripped, e.g. Rust `&parsed.host_str()`); `None` otherwise.
fn extract_host_accessor_receiver(text: &str) -> Option<String> {
    let probes: &[(&str, bool)] = &[
        (".host_str(", false), // Rust, case-stable
        (".Hostname(", false), // Go
        (".Host", true),       // Go, requires `==`/`!=` after
    ];
    for (probe, requires_eq) in probes {
        if let Some(idx) = text.find(probe) {
            if *requires_eq {
                let after = &text[idx + probe.len()..];
                // Reject `.Hostname` (handled by its own probe) and any
                // longer-identifier continuation.
                if let Some(c) = after.chars().next()
                    && (c.is_ascii_alphanumeric() || c == '_')
                {
                    continue;
                }
                let trimmed = after.trim_start();
                if !(trimmed.starts_with("==") || trimmed.starts_with("!=")) {
                    continue;
                }
            }
            let before = &text[..idx];
            // Receiver = trailing identifier of `before`, optionally
            // preceded by `&` (Rust deref).  `parsed.foo.host_str()`
            // would yield `foo`, which is not a parse var, so we
            // conservatively reject any receiver with a `.` or `::`.
            let recv = trailing_identifier(before)?;
            if recv.contains('.') || recv.contains(':') {
                return None;
            }
            return Some(recv);
        }
    }
    None
}

/// Walk back from the end of `s` and return the trailing identifier token.
///
/// `&parsed` → `Some("parsed")`, `foo.bar` → `Some("bar")`,
/// `()` → `None`.  Used by [`extract_host_accessor_receiver`] to pull the
/// parsed-URL var out of `parsed.host_str() == ...`.
fn trailing_identifier(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end > 0 {
        let c = bytes[end - 1];
        if c.is_ascii_alphanumeric() || c == b'_' {
            end -= 1;
        } else {
            break;
        }
    }
    if end == bytes.len() {
        return None;
    }
    let ident = &s[end..];
    if ident.is_empty() || ident.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    Some(ident.to_string())
}

/// Check whether `text` looks like a bounded-length rejection:
/// `x.len() > N`, `x.len() < N`, `x.length >= N`, etc. where `N` is an
/// integer literal >= 2.  Excludes `> 0` / `>= 1` / `< 1`, those are
/// non-empty checks, which are not length-bound validations.
fn is_bounded_length_check(lower: &str) -> bool {
    const PROBES: &[&str] = &[
        ".len()", ".length", // JS/TS/Java `.length` property (no parens)
    ];
    for probe in PROBES {
        let mut rest = lower;
        while let Some(pos) = rest.find(probe) {
            let after = &rest[pos + probe.len()..];
            // Skip the optional `()` that `.length` never has but `.len` does.
            let after = after.trim_start();
            let after = after.strip_prefix("()").unwrap_or(after);
            let after = after.trim_start();
            for op in [">=", "<=", ">", "<"] {
                if let Some(tail) = after.strip_prefix(op) {
                    let tail = tail.trim_start();
                    if let Some(n) = parse_leading_uint(tail) {
                        if n >= 2 {
                            return true;
                        }
                    }
                    break;
                }
            }
            rest = &rest[pos + probe.len()..];
        }
    }
    false
}

/// Normalise an identifier to its snake-case lowercase form so that
/// camelCase / PascalCase / SCREAMING variants line up against snake-cased
/// prefix lists (`is_safe`, `is_authorized`, `is_authenticated`).
///
/// Underscore is inserted at every case boundary:
/// - lowercase/digit → uppercase     (`isSafe` → `is_safe`)
/// - uppercase → uppercase-then-lowercase  (`HTTPClient` → `http_client`)
///
/// Inputs already in snake_case round-trip unchanged: `is_safe` → `is_safe`.
/// Used by `classify_condition` so a sanitiser predicate authored in any
/// of the dominant identifier conventions classifies the same.
pub(crate) fn to_snake_lower(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(chars.len() + 4);
    for i in 0..chars.len() {
        let c = chars[i];
        if c.is_ascii_uppercase() {
            if i > 0 {
                let prev = chars[i - 1];
                let next = chars.get(i + 1).copied();
                let between_camel = prev.is_ascii_lowercase() || prev.is_ascii_digit();
                let acronym_end =
                    prev.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase());
                if (between_camel || acronym_end) && !out.ends_with('_') {
                    out.push('_');
                }
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// Negative-polarity validation predicate: a call whose callee name asserts
/// the input is *bad* (`isInvalidUrl`, `is_invalid`, `isNotValid`,
/// `not_valid`), so the **truthy** branch is the reject/early-return path and
/// the **false** branch is the validated path.
///
/// [`classify_condition`] routes these to [`PredicateKind::ValidationCall`]
/// via the broad `bare.contains("valid")` match (every `…invalid…` name
/// contains the substring `valid`).  ValidationCall applies non-inverted
/// polarity (truthy ⇒ validated), which lands the validation on the *reject*
/// branch — exactly backwards.  Callers flip `effective_negated` when this
/// returns true, reusing the same polarity-inversion path as `not in` /
/// `!==`.  Motivated by CVE-2024-39954 (Apache EventMesh): the patched
/// `if (isInvalidUrl(targetUrl)) { return false; }` guard validates
/// `targetUrl` on the surviving (false) branch.
///
/// Language-agnostic: matches on the bare callee name after stripping
/// receiver / namespace qualifiers and any leading `!` / `not`.
pub fn is_negative_polarity_validation_callee(text: &str) -> bool {
    if !text.contains('(') {
        return false;
    }
    let trimmed = text.trim_start_matches(['(', '!', ' ', '\t']);
    let trimmed = trimmed.strip_prefix("not ").unwrap_or(trimmed).trim();
    let callee_part = trimmed.split('(').next().unwrap_or("");
    let bare = callee_part
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(callee_part)
        .trim();
    let snake = to_snake_lower(bare);
    // The callee classified as ValidationCall because it contains `valid`.
    // The negative sense is precisely the `…invalid…` / `…not_valid…` form.
    snake.contains("invalid") || snake.contains("not_valid") || snake.contains("notvalid")
}

/// Parse a leading non-negative integer literal (decimal only).
fn parse_leading_uint(s: &str) -> Option<u64> {
    let mut n: u64 = 0;
    let mut any = false;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            n = n.checked_mul(10)?.checked_add(d as u64)?;
            any = true;
        } else {
            break;
        }
    }
    any.then_some(n)
}

/// Detect a substring-REJECTION idiom dressed up as a membership method:
/// `x.includes("..")`, `x.contains("<script>")`, `x.indexOf("..")`, etc., where
/// the needle is a **string literal**.
///
/// Genuine allowlist membership has the form `ALLOWED.includes(value)`, the
/// argument is the variable under test and the TRUE branch proves membership.
/// When the argument is a string literal, the receiver is the value under test
/// and the call asks "does this user string contain a dangerous substring?",
/// the TRUE branch is the dangerous/reject path, not a validated path.
///
/// Returning `true` keeps such conditions out of [`PredicateKind::AllowlistCheck`]
/// (which marks every condition var validated on the TRUE branch with the wrong
/// polarity). The shell-metachar form is handled earlier by
/// [`is_shell_metachar_rejection`]; this covers the broader literal-needle case
/// (`..`, `<script>`, etc.) that the shell-metachar carve-out deliberately
/// excludes. Conservative: only fires when the first argument parses as a
/// string literal, so `ALLOWED.includes(value)` (identifier arg) is untouched.
///
/// Two spellings put the needle somewhere other than the first method
/// argument and are matched separately: the Python operator form
/// `"<lit>" in x` and the Go free functions `strings.Contains(x, "<lit>")` /
/// `bytes.Contains(x, "<lit>")`.
fn is_literal_needle_membership(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for method in [
        ".includes(",
        ".include?(",
        ".contains(",
        ".indexof(",
        ".has(",
    ] {
        if let Some(idx) = lower.find(method) {
            let args_start = idx + method.len();
            // Index into the original (case-preserving) text so quoted needle
            // characters stay accurate; the byte offset matches because the
            // method tokens are ASCII.
            if extract_first_string_arg(&text[args_start..]).is_some() {
                return true;
            }
        }
    }
    if extract_python_in_needle(text).is_some() {
        return true;
    }
    // `"<lit>" not in x` asks the same question with the opposite polarity;
    // it is still a test on `x`, not an allowlist that validates it.
    if let Some(pos) = text.find(" not in ") {
        let left = text[..pos].trim().trim_start_matches('(').trim();
        if extract_first_string_arg(left).is_some_and(|lit| lit.len() + 2 == left.len()) {
            return true;
        }
    }
    for func in ["strings.contains(", "bytes.contains("] {
        if let Some(idx) = lower.find(func) {
            let args = split_top_level_args(&text[idx + func.len()..]);
            if args.len() == 2 && extract_first_string_arg(args[1]).is_some() {
                return true;
            }
        }
    }
    false
}

/// Detect the *negated* `search` / `find` membership idiom whose TRUE branch is
/// the NOT-found (reject) path:
///
/// * `s.find(x) == -1` (Python `str.find` / C++ `std::string::find` use
///   `npos`/`-1` for absent; `< 0` covers the common int form)
/// * `s.search(x) < 0` (JS string search)
///
/// These search a string, not a collection, so even the positive form proves
/// little; the negated form is dropped to [`PredicateKind::Unknown`] so
/// neither branch is validated.  `ALLOWED.indexOf(x) === -1` is a genuine
/// collection membership test and is not claimed here: it classifies as
/// [`PredicateKind::AllowlistCheck`] and [`sentinel_comparison_polarity`]
/// puts the validation on the found branch.
fn is_negated_indexof_membership(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let has_index_search = lower.contains(".search(") || lower.contains(".find(");
    if !has_index_search {
        return false;
    }
    // Strip whitespace so spacing variants (`=== -1`, `===-1`, `< 0`) collapse
    // to a single canonical form.
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    // Positive (found) forms keep the AllowlistCheck classification.
    if compact.contains("!==-1")
        || compact.contains("!=-1")
        || compact.contains(">=0")
        || compact.contains(">-1")
    {
        return false;
    }
    compact.contains("===-1")
        || compact.contains("==-1")
        || compact.contains("<0")
        || compact.contains("<=-1")
}

/// Value-first membership predicate free functions: `f(value, collection)`
/// whose TRUE branch proves `value ∈ collection`.  Names are matched case- and
/// underscore-insensitively (see [`membership_fn_leaf_normalised`]) so the PHP
/// `in_array`, Go `InArray` / `stringInSlice`, and JS lodash `inArray`
/// spellings all resolve to the same membership concept.  The existing
/// `in_array(` / ` in ` / `.contains(` recognisers cover the underscore, `in`
/// operator, and method spellings; this closes the camelCase free-function
/// spelling.  Motivated by CVE-2026-21859 (Mailpit `tools.InArray(uri, links)`
/// SSRF allowlist).
const VALUE_FIRST_MEMBERSHIP_FNS: &[&str] = &["inarray", "stringinslice", "stringinlist"];

/// If `text` is a bare call to a free function (`InArray(x, list)`,
/// `!in_array($x, $y)`, `tools.InArray(x, list)`, `not stringInSlice(x, l)`),
/// return the function's leaf name lowercased with underscores stripped.
/// Returns `None` for method calls with a value receiver, operators, indexing,
/// or non-call text, so only simple membership free functions are considered.
fn membership_fn_leaf_normalised(text: &str) -> Option<String> {
    let t = text.trim().trim_start_matches(['(', '!', ' ', '\t']);
    let t = t.strip_prefix("not ").unwrap_or(t).trim();
    let open = t.find('(')?;
    let callee = t[..open].trim();
    // Callee must be a plain identifier or a dotted / scoped path
    // (`tools.InArray`, `pkg::in_array`) — reject anything with spaces,
    // operators, or brackets so this never fires on comparisons or receiver
    // method chains that happen to contain a paren.
    if callee.is_empty()
        || !callee
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':')
    {
        return None;
    }
    let leaf = callee.rsplit(['.', ':']).next().unwrap_or(callee);
    if leaf.is_empty() || !leaf.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(leaf.to_ascii_lowercase().replace('_', ""))
}

/// True when `text` is a call to a recognised value-first membership free
/// function (see [`VALUE_FIRST_MEMBERSHIP_FNS`]).
fn is_value_first_membership_fn(text: &str) -> bool {
    membership_fn_leaf_normalised(text)
        .is_some_and(|leaf| VALUE_FIRST_MEMBERSHIP_FNS.contains(&leaf.as_str()))
}

/// PHP `ctype_*` checks whose accepted alphabet excludes shell, SQL and
/// path metacharacters.  `ctype_punct` / `ctype_print` / `ctype_graph`
/// accept `;`, `'`, `/` and friends, so they are not validators.
const SAFE_CTYPE_FNS: &[&str] = &[
    "ctype_digit(",
    "ctype_alnum(",
    "ctype_alpha(",
    "ctype_xdigit(",
    "ctype_upper(",
    "ctype_lower(",
];

/// `typeof` results that pin a JS value to something that cannot carry a
/// string payload: a non-string scalar, or a function (request data, JSON
/// and query strings never produce one).
const SAFE_TYPEOF_RESULTS: &[&str] = &["number", "bigint", "boolean", "function"];

/// Python classes (last dotted segment, lowercased) whose instances render
/// as plain numbers / booleans / UUIDs.
const SCALAR_PY_CLASSES: &[&str] = &[
    "int", "float", "bool", "complex", "decimal", "uuid", "number", "integral", "real", "rational",
    "fraction",
];

/// Java / JS classes (last dotted segment, lowercased) for `instanceof`.
/// `Character` is left out: a single quote is enough to break SQL.
const SCALAR_INSTANCEOF_CLASSES: &[&str] = &[
    "number",
    "integer",
    "long",
    "short",
    "byte",
    "double",
    "float",
    "boolean",
    "biginteger",
    "bigdecimal",
    "uuid",
    "atomicinteger",
    "atomiclong",
];

/// Ruby classes (last `::` segment, lowercased) for `is_a?` / `kind_of?`.
const SCALAR_RUBY_CLASSES: &[&str] = &[
    "integer",
    "numeric",
    "float",
    "fixnum",
    "bignum",
    "rational",
    "bigdecimal",
    "complex",
    "trueclass",
    "falseclass",
];

/// True when every runtime type test in `lower` (already lowercased) pins
/// the value to one of the types listed above.  A condition mixing such a
/// test with any other type test, or a type test whose type cannot be
/// read, does not qualify.
fn type_check_proves_scalar(lower: &str) -> bool {
    let mut saw_test = false;

    if lower.contains("is_string(") {
        return false;
    }

    if lower.contains("typeof ") {
        // Every quoted literal in the condition must be a safe `typeof`
        // result; this also covers the reversed `'number' === typeof x`.
        let literals = quoted_literals(lower);
        if literals.is_empty() || !literals.iter().all(|lit| SAFE_TYPEOF_RESULTS.contains(lit)) {
            return false;
        }
        saw_test = true;
    }

    for (idx, _) in lower.match_indices("isinstance(") {
        let args = split_top_level_args(&lower[idx + "isinstance(".len()..]);
        let Some(classes) = args.get(1) else {
            return false;
        };
        let classes = classes.trim().trim_start_matches('(').trim_end_matches(')');
        let all_scalar = classes
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .all(|c| SCALAR_PY_CLASSES.contains(&c.rsplit('.').next().unwrap_or(c)));
        if classes.trim().is_empty() || !all_scalar {
            return false;
        }
        saw_test = true;
    }

    for (idx, _) in lower.match_indices(" instanceof ") {
        let after = lower[idx + " instanceof ".len()..].trim_start();
        let class: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        let leaf = class.rsplit('.').next().unwrap_or("");
        if !SCALAR_INSTANCEOF_CLASSES.contains(&leaf) {
            return false;
        }
        saw_test = true;
    }

    for method in [".is_a?(", ".kind_of?("] {
        for (idx, _) in lower.match_indices(method) {
            let Some(class) = first_call_arg(&lower[idx + method.len()..]) else {
                return false;
            };
            let leaf = class.rsplit("::").next().unwrap_or(class).trim();
            if !SCALAR_RUBY_CLASSES.contains(&leaf) {
                return false;
            }
            saw_test = true;
        }
    }

    saw_test
}

/// For a JS/TS regex-literal allowlist test, `/^[0-9]+$/.test(x)` (with an
/// optional leading `!` / wrapping parens), return the tested argument `x`.
///
/// The literal must be anchored at both ends and its body must restrict the
/// alphabet: no `.` wildcard outside a class, no negated class `[^...]` and
/// no `\S` / `\W` / `\D`.  `/^.*$/` or an unanchored `/[0-9]/` proves nothing
/// about the rest of the value.  The receiver-name rule in
/// [`classify_condition`] (`SAFE_REGEX.test(x)`) covers named patterns;
/// this covers inline literals, whose body is visible.
fn anchored_regex_literal_test_arg(text: &str) -> Option<String> {
    let t = text.trim().trim_start_matches(['(', '!', ' ', '\t']);
    let bytes = t.as_bytes();
    if bytes.first() != Some(&b'/') {
        return None;
    }
    // Find the closing `/` of the literal: skip escapes and `/` inside a
    // character class.
    let mut i = 1usize;
    let mut in_class = false;
    let close = loop {
        let b = *bytes.get(i)?;
        match b {
            b'\\' => i += 1,
            b'[' => in_class = true,
            b']' => in_class = false,
            b'/' if !in_class => break i,
            _ => {}
        }
        i += 1;
    };
    let body = &t[1..close];
    let after = &t[close + 1..];
    let rest = after.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    // The `m` flag lets `^` and `$` match at every line break, so a payload
    // can ride on a second line of a value that passes the test.
    if after[..after.len() - rest.len()].contains('m') {
        return None;
    }
    let args = rest.strip_prefix(".test(")?;
    let anchored = body.len() >= 2
        && body.starts_with('^')
        && body.ends_with('$')
        && !body[..body.len() - 1].ends_with('\\');
    if !anchored || !regex_body_restricts_alphabet(body) {
        return None;
    }
    let arg = first_call_arg(args)?.trim();
    is_identifier(arg).then(|| arg.to_string())
}

/// True when a regex body has no construct that matches an open-ended
/// alphabet (see [`anchored_regex_literal_test_arg`]).
fn regex_body_restricts_alphabet(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut i = 0usize;
    let mut in_class = false;
    let mut group_depth = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if matches!(bytes.get(i + 1), Some(b'S' | b'W' | b'D')) {
                    return false;
                }
                i += 2;
                continue;
            }
            b'[' if !in_class => {
                if bytes.get(i + 1) == Some(&b'^') {
                    return false;
                }
                in_class = true;
            }
            b']' => in_class = false,
            b'.' if !in_class => return false,
            b'(' if !in_class => group_depth += 1,
            b')' if !in_class => group_depth = group_depth.saturating_sub(1),
            // `^a|b$` anchors each branch on one side only.
            b'|' if !in_class && group_depth == 0 => return false,
            _ => {}
        }
        i += 1;
    }
    true
}

/// Contents of every `'...'`, `"..."` and `` `...` `` literal in `text`.
fn quoted_literals(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'"' || q == b'\'' || q == b'`' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != q {
                if bytes[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            out.push(&text[start..j]);
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Classify a raw condition text into a [`PredicateKind`].
///
/// # Rules
///
/// - Empty/None text → [`Unknown`](PredicateKind::Unknown).
/// - `ValidationCall` / `SanitizerCall` require a `(` in the text **and** a
///   matching callee token. This avoids misclassifying comparisons like
///   `x_valid == true`.
/// - Prefers [`Unknown`](PredicateKind::Unknown) over false positives.
pub fn classify_condition(text: &str) -> PredicateKind {
    if text.is_empty() {
        return PredicateKind::Unknown;
    }

    let lower = text.to_ascii_lowercase();

    // ── Error checks (before null checks: `err != nil` is an error check,
    //    not a null check, even though it contains `!= nil`) ──────────────
    if lower.contains("is_err")
        || lower.contains("is_ok")
        || lower.contains("err != nil")
        || lower.contains("err == nil")
        || lower.contains("error != nil")
        || lower.contains("error == nil")
    {
        return PredicateKind::ErrorCheck;
    }

    // ── Null checks ──────────────────────────────────────────────────────
    if lower.contains("is_none")
        || lower.contains("is_some")
        || lower.contains("== none")
        || lower.contains("!= none")
        || lower.contains("is none")
        || lower.contains("is not none")
        || lower.contains("== null")
        || lower.contains("!= null")
        || lower.contains("=== null")
        || lower.contains("!== null")
        || lower.contains("== nil")
        || lower.contains("!= nil")
    {
        return PredicateKind::NullCheck;
    }

    // ── Empty checks ─────────────────────────────────────────────────────
    if lower.contains("is_empty")
        || lower.contains(".len() == 0")
        || lower.contains(".len() != 0")
        || lower.contains(".length == 0")
        || lower.contains(".length === 0")
        || lower.contains(".length != 0")
        || lower.contains(".length !== 0")
        || lower.contains("== \"\"")
        || lower.contains("== ''")
    {
        return PredicateKind::EmptyCheck;
    }

    // ── Shell-metachar negative validation ───────────────────────────────
    //
    // Matched BEFORE AllowlistCheck so that `x.contains(";")` is recognized
    // as a rejection idiom rather than a membership test.  Checked on the
    // raw (non-lowercased) text so metacharacter comparisons stay
    // case-accurate, `;` / `|` / `&` have no case.
    if is_shell_metachar_rejection(text) {
        return PredicateKind::ShellMetaValidated;
    }

    // ── Inline relative-URL validation ──────────────────────────────────
    //
    // `x.startsWith("/")` (JS/TS/Java/Kotlin), `x.starts_with("/")` (Rust),
    // `x.startswith("/")` (Python), `strpos($x, "/") === 0` (PHP), and the
    // protocol-relative rejection `x.startsWith("//")`.  A leading slash
    // alone does not keep a redirect on-site (`//evil.com`), so the two
    // tests are separate kinds whose facts meet on the path; only a
    // single-text conjunction of both is the full check.  A compound text
    // in any other shape is left to the generic classifier.
    if is_relative_url_conjunction(text) {
        return PredicateKind::RelativeUrlValidated;
    }
    if !has_boolean_connective(text) {
        if is_protocol_relative_check(text) {
            return PredicateKind::ProtocolRelativeCheck;
        }
        if is_leading_slash_check(text) {
            return PredicateKind::LeadingSlashCheck;
        }
    }

    // ── Host-allowlist URL-parse validation ─────────────────────────────
    //
    // `new URL(x).host === ALLOWED` (JS/TS), `urlparse(x).netloc == ALLOWED`
    // (Python), etc.  Matched BEFORE AllowlistCheck so the membership form
    // `ALLOWED.includes(new URL(x).host)` doesn't fall through here, and
    // BEFORE the generic Comparison branch so the equality operator
    // doesn't classify generically.
    if is_host_allowlist_check(text) {
        return PredicateKind::HostAllowlistValidated;
    }

    // ── C path-prefix confinement ───────────────────────────────────────
    //
    // `strncmp(x, prefix, strlen(prefix))` guarding a reject branch confines
    // `x` to a fixed directory prefix (uftpd CVE-2020-5221).  Matched here so
    // the bare `strncmp(...)` call isn't captured by any later comparison /
    // membership branch.
    if path_prefix_confinement_subject(text).is_some() {
        return PredicateKind::PathPrefixConfined;
    }

    // ── Substring-REJECTION with a literal needle (not an allowlist) ─────
    //
    // `x.includes("..")` / `x.contains("<script>")` / `x.indexOf("..")` test
    // the *receiver* against a fixed literal — a rejection idiom whose TRUE
    // branch is the dangerous path.  Classifying these as `AllowlistCheck`
    // (below) would mark the receiver validated on the TRUE branch with the
    // wrong polarity, silencing a genuine finding.  Drop to `Unknown` so
    // neither branch is over-validated and the sink finding survives.
    // (The shell-metachar form was already caught earlier; this covers the
    // broader literal-needle case.)
    if is_literal_needle_membership(text) {
        return PredicateKind::Unknown;
    }

    // ── Negated indexOf/find membership (inverted polarity) ──────────────
    //
    // `ALLOWED.indexOf(x) === -1` / `< 0` means NOT-in-list, so the TRUE
    // branch is the reject path.  Classifying as `AllowlistCheck` (below)
    // would mark `x` validated on the TRUE branch with the wrong polarity —
    // suppressing a genuine finding on `if (!FOUND) sink(x)` and producing an
    // FP on the correctly-guarded `if (!FOUND) return; sink(x)` shape.  The
    // polarity-inversion machinery does not cover indexOf result comparisons,
    // so drop to `Unknown` and let neither branch over-validate.  The positive
    // `!== -1` / `>= 0` form is excluded by `is_negated_indexof_membership`
    // and still classifies as `AllowlistCheck` with correct polarity.
    if is_negated_indexof_membership(text) {
        return PredicateKind::Unknown;
    }

    // ── Allowlist / membership checks ────────────────────────────────────
    if lower.contains(".includes(")
        || lower.contains(".include?(")
        || lower.contains(".contains(")
        || lower.contains(".indexof(")
        || lower.contains(".has(")
        || lower.contains("in_array(")
        || lower.contains(" in ")
        || is_index_membership_check(text)
        || is_value_first_membership_fn(text)
    {
        return PredicateKind::AllowlistCheck;
    }

    // ── Java/Kotlin Pattern.matcher().matches() chain (before TypeCheck) ─
    //
    // Recognise `<re>.matcher(value).matches()` as a regex allowlist
    // validator, not a TypeCheck.  The receiver of `.matcher(` must
    // contain `regex` or `pattern` so we don't widen to arbitrary
    // `obj.matcher(x).matches()` calls.  Surfaced by GHSA-h8cj-hpmg-636v
    // (Appsmith FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()).
    // Matched here (before the generic `.matches(` TypeCheck branch
    // below) so the chain doesn't silently fall into TypeCheck.
    if let Some(matcher_pos) = lower.find(".matcher(")
        && lower[matcher_pos..].contains(".matches(")
    {
        let receiver = &lower[..matcher_pos];
        if receiver.contains("regex") || receiver.contains("pattern") {
            return PredicateKind::ValidationCall;
        }
    }

    // ── Type-check guards ──────────────────────────────────────────────
    //
    // Value-shape checks that pin the value to a digit / alnum alphabet.
    if lower.contains(".matches(")
        || lower.contains("is_numeric(")
        || lower.contains("is_int(")
        || lower.contains("is_float(")
        || SAFE_CTYPE_FNS.iter().any(|f| lower.contains(f))
        // Rust character-class validation: `.chars().all(|c| c.is_ascii_*())`
        // and similar per-character validations.  Presence of `is_ascii_`
        // inside an `.all(…)` / `.iter().all(…)` call is a strong validation
        // signal equivalent to a TypeCheck.
        || (lower.contains(".all(") && lower.contains("is_ascii_"))
        || (lower.contains(".all(") && lower.contains("is_alphanumeric"))
        || (lower.contains(".all(") && lower.contains("is_numeric("))
    {
        return PredicateKind::TypeCheck;
    }
    // Runtime type tests validate only when the tested type cannot carry
    // an injection payload (a non-string scalar, or a JS function).  `typeof x === 'string'` /
    // `isinstance(x, str)` / `x instanceof String` / `is_string($x)` /
    // `x.is_a?(String)` describe the type every payload already has; in
    // Express they mostly reject `qs` arrays.  Those return Unknown here
    // (not Comparison) so neither branch is validated.
    if lower.contains("typeof ")
        || lower.contains("isinstance(")
        || lower.contains(" instanceof ")
        || lower.contains("is_string(")
        || lower.contains(".is_a?(")
        || lower.contains(".kind_of?(")
    {
        return if type_check_proves_scalar(&lower) {
            PredicateKind::TypeCheck
        } else {
            PredicateKind::Unknown
        };
    }

    // ── Bounded-length rejection ─────────────────────────────────────────
    //
    // `.len() > N` / `.length < N` with N >= 2.  Pairs with
    // ShellMetaValidated in OR-chain rejection patterns.  Kept as its own
    // kind (not TypeCheck) because the rejection direction is ambiguous: a
    // `.len() > 5 { sink(x) }` gate is a precondition, not a rejection, so
    // marking condition vars as validated on the true branch would silence
    // legitimate findings.  `cfg-unguarded-sink` still treats this as a
    // dominator guard (structural intent), just without SSA-level validation.
    if is_bounded_length_check(&lower) {
        return PredicateKind::BoundedLength;
    }

    // ── Call-based kinds (require `(` to be present) ─────────────────────
    if lower.contains('(') {
        // Inline anchored regex literal: `/^[0-9]+$/.test(x)`.  Checked on
        // the case-preserved text (`\S` and `\s` differ) and before the
        // callee split below, which stops at the first `(` and would cut
        // a regex containing a group.
        if anchored_regex_literal_test_arg(text).is_some() {
            return PredicateKind::ValidationCall;
        }
        // Strip leading wrappers (parens, `!`, whitespace) before locating
        // the callee token.  Without this, idiomatic forms like
        // `(!validate(x))` (TypeScript / JS) or `not validate(x)` (Python)
        // produce an empty `callee_part` and the classifier misses
        // ValidationCall, defeating downstream validated-must propagation.
        let trimmed = lower.trim_start_matches(['(', '!', ' ', '\t']);
        // Strip a leading `not ` keyword (Python boolean not) plus surrounding
        // whitespace.  Without this, `not validate_no_dotdot(raw)` skips
        // ValidationCall classification and validation never propagates.
        let trimmed = trimmed.strip_prefix("not ").unwrap_or(trimmed).trim();
        // Extract a rough callee token: everything before the first `(`
        // that looks like an identifier (letters, digits, underscores, dots).
        let callee_part = trimmed.split('(').next().unwrap_or("");
        // Take the last segment (after `.` or `::`) as the bare name.
        let bare = callee_part
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(callee_part)
            .trim();

        // Derive a snake-cased form from the **original** text so that
        // camelCase identifiers (`isSafeRemoteUrl`, `isAuthorized`,
        // `isValidUUID`) classify against the snake-cased prefix list
        // (`is_safe`, `is_authorized`, `is_authenticated`) the same as
        // `is_safe_remote_url` would.  Required to recognise CVE-2026-33486
        // (roadiz/documents `isSafeRemoteUrl` SSRF sanitiser) as a
        // ValidationCall on the patched fixture.  Mirrors the trim/strip
        // pipeline above on case-preserved text so the snake form lines up
        // with `bare`.
        let orig_trimmed = text.trim_start_matches(['(', '!', ' ', '\t']);
        let orig_trimmed = orig_trimmed
            .strip_prefix("not ")
            .unwrap_or(orig_trimmed)
            .trim();
        let orig_callee_part = orig_trimmed.split('(').next().unwrap_or("");
        let orig_bare = orig_callee_part
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(orig_callee_part)
            .trim();
        let bare_snake = to_snake_lower(orig_bare);

        // Validation
        if bare.contains("valid")
            || bare.contains("check")
            || bare.contains("verify")
            || bare_snake.starts_with("is_safe")
            || bare_snake.starts_with("is_authorized")
            || bare_snake.starts_with("is_authenticated")
        {
            return PredicateKind::ValidationCall;
        }

        // Cap-scoped predicates named for what they establish.
        if let Some((kind, _)) = scoped_predicate_call(text) {
            return kind;
        }

        // Regex / pattern allowlist `<X>.test(value)` / `<X>.match(value)` calls
        // where the receiver name carries a regex or pattern marker.  The
        // standard JS / TS / Python / Java / Ruby / Go regex APIs all expose a
        // boolean test method; the success arm (true) means `value` matches the
        // pattern.  Conservative on receiver names so non-regex methods like
        // `obj.test(x)` (test runner), `db.test(...)` (test column) etc. don't
        // get pulled in.  Motivated by Payload CVE-2026-25544
        // (`if (!SAFE_STRING_REGEX.test(value)) throw …;`).
        if (bare == "test" || bare == "match" || bare == "matches")
            && let Some(dot_pos) = callee_part.rfind('.')
        {
            let receiver = &callee_part[..dot_pos];
            let receiver_lower = receiver.to_ascii_lowercase();
            if receiver_lower.contains("regex") || receiver_lower.contains("pattern") {
                return PredicateKind::ValidationCall;
            }
        }

        // Java idiom `<PATTERN>.matcher(value).matches()` — the regex
        // allowlist on Java/Kotlin is a two-step chain (`Pattern.matcher`
        // returns a `Matcher`, `.matches()` is the boolean predicate).
        // The bare callee here is `matches` (no args), so the
        // single-call recogniser above doesn't fire.  Lock on the
        // chain shape and require the receiver of `.matcher(` to carry
        // a regex / pattern marker so we don't widen to `.matcher(` on
        // arbitrary types.  Surfaced by GHSA-h8cj-hpmg-636v
        // (Appsmith FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()).
        if bare == "matches"
            && let Some(matcher_pos) = lower.find(".matcher(")
        {
            let receiver = &lower[..matcher_pos];
            if receiver.contains("regex") || receiver.contains("pattern") {
                return PredicateKind::ValidationCall;
            }
        }

        // Sanitizer
        if bare.contains("sanitiz") || bare.contains("escape") || bare.contains("encode") {
            return PredicateKind::SanitizerCall;
        }
    }

    // ── Comparison operators ─────────────────────────────────────────────
    if lower.contains("==")
        || lower.contains("!=")
        || lower.contains(">=")
        || lower.contains("<=")
        || lower.contains(" > ")
        || lower.contains(" < ")
    {
        return PredicateKind::Comparison;
    }

    PredicateKind::Unknown
}

/// Whether a null, error or empty check is written in its negated form.
///
/// The predicate bits for these kinds record a fact about the value: bit set
/// in `known_true` means the value is null / holds an error / is empty.  The
/// condition text can state either side (`x == null` or `x != null`,
/// `err != nil` or `err == nil`), so the branch that makes the fact true
/// depends on the operator.  Returns `Some(true)` for the negated form
/// (`x != null`, `err == nil`, `.length != 0`), `Some(false)` for the plain
/// form, and `None` when the text holds both forms (`a != null && b == null`),
/// where no single bit describes the condition, or for kinds that carry no
/// predicate bit.  The leading-slash and protocol-relative URL checks have a
/// single spelling, so they return `Some(false)`.
///
/// The negated markers are matched first and blanked out, because the `==`
/// inside `!==` would otherwise read as the plain form.
pub fn predicate_bit_negative_form(kind: PredicateKind, text: &str) -> Option<bool> {
    let (negated, plain): (&[&str], &[&str]) = match kind {
        PredicateKind::NullCheck => (
            &[
                "!== null",
                "!= null",
                "!= nil",
                "!= none",
                "is not none",
                "is_some",
            ],
            &[
                "=== null", "== null", "== nil", "== none", "is none", "is_none",
            ],
        ),
        PredicateKind::ErrorCheck => (
            &["err == nil", "error == nil", "is_ok"],
            &["err != nil", "error != nil", "is_err"],
        ),
        PredicateKind::EmptyCheck => (
            &[
                ".len() != 0",
                ".length !== 0",
                ".length != 0",
                "!== \"\"",
                "!= \"\"",
                "!== ''",
                "!= ''",
            ],
            &[
                "is_empty",
                ".len() == 0",
                ".length === 0",
                ".length == 0",
                "== \"\"",
                "== ''",
            ],
        ),
        // One spelling only: the branch polarity alone states the fact.
        PredicateKind::LeadingSlashCheck | PredicateKind::ProtocolRelativeCheck => {
            return Some(false);
        }
        _ => return None,
    };
    let mut rest = text.to_ascii_lowercase();
    let mut has_negated = false;
    for marker in negated {
        if rest.contains(marker) {
            has_negated = true;
            rest = rest.replace(marker, " ");
        }
    }
    let has_plain = plain.iter().any(|m| rest.contains(m));
    match (has_negated, has_plain) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    }
}

/// Recognise a canonical open-redirect URL-safety validator callee by name.
///
/// These are the ecosystem-standard boolean guards that pin a redirect target
/// to the current host / a relative URL before it is used: Django's
/// `url_has_allowed_host_and_scheme` (and its legacy `is_safe_url` alias),
/// Flask / Flask-AppBuilder's `is_safe_redirect_url`, and app-local helpers
/// named `*safe*redirect*` / `*safe*url*` / `*valid*redirect*`.  Their bodies
/// are frequently library-internal (Django's live in `django.utils.http`), so
/// name recognition is the only available signal.  Conservative: the name must
/// carry an explicit redirect/URL-safety token, so a generic `is_valid_email`
/// does not match.
pub(crate) fn is_open_redirect_validator_name(name: &str) -> bool {
    let leaf = name.rsplit(['.', ':']).next().unwrap_or(name);
    let l = leaf.to_ascii_lowercase();
    l == "url_has_allowed_host_and_scheme"
        || l == "is_safe_url"
        || l == "url_is_safe"
        || (l.contains("safe") && l.contains("redirect"))
        || (l.contains("safe") && l.contains("url"))
        || (l.contains("valid") && l.contains("redirect"))
}

/// Leading verbs of functions that return a value rather than a boolean, so
/// a `safe`/`url` token in the rest of the name does not make them guards.
const VALUE_PRODUCING_PREFIXES: [&str; 14] = [
    "get_",
    "make_",
    "build_",
    "create_",
    "generate_",
    "sanitize_",
    "sanitise_",
    "clean_",
    "escape_",
    "fix_",
    "normalize_",
    "normalise_",
    "resolve_",
    "parse_",
];

/// A boolean predicate whose name states that a redirect target is safe
/// (`safe_for_redirect`, `is_safe_redirect_url`,
/// `url_has_allowed_host_and_scheme`).  Narrower than
/// [`is_open_redirect_validator_name`], which also admits helpers that return
/// the confined URL.
pub(crate) fn is_redirect_safety_predicate_name(leaf: &str) -> bool {
    let snake = to_snake_lower(leaf);
    if VALUE_PRODUCING_PREFIXES
        .iter()
        .any(|p| snake.starts_with(p))
        || snake.contains("unsafe")
        || snake.contains("not_safe")
        || !is_open_redirect_validator_name(&snake)
    {
        return false;
    }
    // A bare `safe_url(x)` / `url_safe_quote(x)` is as likely to return an
    // escaped or confined value (truthy for any input) as to answer a
    // question.  Accept the known boolean names, or a name that carries a
    // predicate verb or states the redirect target is safe.
    matches!(
        snake.as_str(),
        "url_has_allowed_host_and_scheme" | "is_safe_url" | "url_is_safe"
    ) || BOOLEAN_PREFIXES.iter().any(|p| snake.starts_with(p))
        || snake.contains("safe_for_redirect")
        || snake.ends_with("_is_safe")
}

/// Leading verbs that mark a function as answering a yes/no question.
const BOOLEAN_PREFIXES: [&str; 8] = [
    "is_",
    "has_",
    "check_",
    "validate_",
    "verify_",
    "can_",
    "should_",
    "allow",
];

/// Subject nouns of a host / address denylist predicate.
const DENYLIST_SUBJECTS: [&str; 12] = [
    "host", "hostname", "ip", "addr", "address", "url", "uri", "domain", "remote", "target",
    "endpoint", "server",
];

/// Property words of a host / address denylist predicate.
const DENYLIST_PROPERTIES: [&str; 11] = [
    "internal",
    "private",
    "loopback",
    "local",
    "reserved",
    "blocked",
    "blacklisted",
    "denied",
    "disallowed",
    "forbidden",
    "unsafe",
];

/// A boolean predicate whose name states that a host or address is internal
/// or blocked: `is_` followed only by subject and property words, at least
/// one of each (`IsHostnameInternal`, `is_private_ip`, `isInternalURL`).
/// `is_local_file`, `isInternalUser` and `is_blocked_user` do not match: a
/// word outside both sets means the predicate is about something else.
fn is_host_denylist_predicate_name(leaf: &str) -> bool {
    let snake = to_snake_lower(leaf);
    let Some(rest) = snake.strip_prefix("is_") else {
        return false;
    };
    let mut has_subject = false;
    let mut has_property = false;
    for word in rest.split('_') {
        if DENYLIST_SUBJECTS.contains(&word) {
            has_subject = true;
        } else if DENYLIST_PROPERTIES.contains(&word) {
            has_property = true;
        } else if word != "link" {
            return false;
        }
    }
    has_subject && has_property
}

/// If `clause` is exactly a call `name(args)` (no leading `!` / `not`, nothing
/// after the closing paren) whose leaf name passes `name_ok`, return the
/// clause when its first argument is a bare identifier.
fn plain_predicate_call(clause: &str, name_ok: fn(&str) -> bool) -> Option<String> {
    let clause = crate::abstract_interp::path_domain::strip_outer_parens(clause.trim());
    if !clause.ends_with(')') {
        return None;
    }
    let open = clause.find('(')?;
    let callee = clause[..open].trim();
    if callee.is_empty()
        || !callee
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | ':' | '$'))
    {
        return None;
    }
    let leaf = callee.rsplit(['.', ':']).next().unwrap_or(callee);
    if !name_ok(leaf) {
        return None;
    }
    // The parenthesis opened after the callee must be the one the clause ends
    // with, so `f(a) || g(b)` is not read as one call.
    let mut depth = 0i32;
    for (i, b) in clause.bytes().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 && i + 1 != clause.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    let first = first_call_arg(&clause[open + 1..])?;
    let first = first.strip_prefix('&').unwrap_or(first).trim();
    // Keyword form `url=next` names the argument after `=`.
    let first = match first.split_once('=') {
        Some((kw, value)) if is_identifier(kw.trim()) && !value.starts_with('=') => value.trim(),
        _ => first,
    };
    let first = first.strip_prefix('$').unwrap_or(first);
    (is_identifier(first) && !first.contains('.')).then(|| first.to_string())
}

/// Recognise a scope-limited predicate call in `text`, returning its kind and
/// the identifier it tests.
///
/// The call must stand alone as a clause on the edge that carries its
/// meaning: a redirect-safety predicate as a conjunct (true edge), a host
/// denylist predicate as a disjunct (false edge).  The one wrapper allowed
/// around a lone call is the leading negation the CFG reports as
/// `condition_negated`.
fn scoped_predicate_call(text: &str) -> Option<(PredicateKind, String)> {
    use crate::abstract_interp::path_domain::{
        split_top_level_and, split_top_level_or, strip_leading_not, strip_outer_parens,
    };
    let mut t = strip_outer_parens(text.trim());
    if !has_boolean_connective(t) {
        while let Some(rest) = strip_leading_not(t) {
            t = strip_outer_parens(rest.trim_start());
        }
    } else if let Some(rest) = strip_leading_not(t)
        && rest.trim_start().starts_with('(')
        && strip_outer_parens(rest.trim_start()).len() < rest.trim_start().len()
    {
        // `!(a || f(x))`: the whole-condition negation is the caller's.
        t = strip_outer_parens(rest.trim_start());
    }
    let disjuncts = split_top_level_or(t);
    if disjuncts.len() == 1 {
        for clause in split_top_level_and(t) {
            if let Some(arg) = plain_predicate_call(clause, is_redirect_safety_predicate_name) {
                return Some((PredicateKind::RedirectValidator, arg));
            }
        }
    }
    if !crate::abstract_interp::path_domain::has_top_level_and(t) {
        for clause in disjuncts {
            // One argument only: with several, which one is the host is a guess.
            if count_call_args(strip_outer_parens(clause.trim())) == Some(1)
                && let Some(arg) = plain_predicate_call(clause, is_host_denylist_predicate_name)
            {
                return Some((PredicateKind::HostDenylistRejected, arg));
            }
        }
    }
    None
}

/// Classify a condition AND extract the specific validated variable target.
///
/// For `ValidationCall`/`SanitizerCall`, tries to extract the first argument
/// or method receiver as the validated variable:
/// - `validate(x, ...)` → target = `"x"`
/// - `x.validate(...)` → target = `"x"`
///
/// When target extraction fails on a multi-argument call (e.g.,
/// `validate(expr, limit)` where `expr` is not a plain identifier), the
/// validator's effect is opaque: we can't tell which argument is being
/// checked. Returning the original kind with `None` target would cause
/// upstream code to over-validate (mark every `condition_var` as validated).
/// Instead, we fall back to `PredicateKind::Unknown`, safer to assume the
/// validator did nothing than to assume it validated every variable in the
/// condition. Single-argument calls retain `(kind, None)` so downstream code
/// can still use the predicate-summary bit tracking.
pub fn classify_condition_with_target(text: &str) -> (PredicateKind, Option<String>) {
    let kind = classify_condition(text);

    match kind {
        PredicateKind::ValidationCall | PredicateKind::SanitizerCall => {
            // A dotted target (`a.field`, `req.body.x`) is a member expression.
            // `condition_vars` only ever contains bare identifier tokens
            // (collect_idents pushes single identifiers), so a dotted target
            // can never match and the consumer falls back to validating EVERY
            // condition var, the exact over-validation the multi-arg Unknown
            // guard was written to prevent.  Treat dotted extraction the same
            // as a failed extraction so multi-arg validators degrade to
            // Unknown instead of silently validating unrelated arguments.
            match extract_validation_target(text) {
                Some(target) if !target.contains('.') => (kind, Some(target)),
                _ if count_call_args(text).map(|n| n > 1).unwrap_or(false) => {
                    (PredicateKind::Unknown, None)
                }
                _ => (kind, None),
            }
        }
        PredicateKind::AllowlistCheck => {
            let target = extract_allowlist_target(text);
            (kind, target)
        }
        PredicateKind::TypeCheck => {
            let target = extract_type_check_target(text);
            (kind, target)
        }
        PredicateKind::ShellMetaValidated => {
            // The receiver of `.contains(…)` / `.includes(…)` is the value
            // being validated.  Reuses the validation extractor which already
            // handles `x.method(arg)` → `"x"`.
            let target = extract_validation_target(text);
            (kind, target)
        }
        PredicateKind::RelativeUrlValidated
        | PredicateKind::LeadingSlashCheck
        | PredicateKind::ProtocolRelativeCheck => {
            // Receiver of `.startsWith("/")` / `.startswith("/")` /
            // `.starts_with("/")`, or first arg of `strpos($x, "/")`.
            // Same machinery as ShellMetaValidated.
            let target = extract_validation_target(text);
            (kind, target)
        }
        PredicateKind::HostAllowlistValidated => {
            // Argument of the parse call: `new URL(x).host` → `x`,
            // `urlparse(x).netloc` → `x`.
            let target = extract_host_allowlist_target(text);
            (kind, target)
        }
        PredicateKind::RedirectValidator | PredicateKind::HostDenylistRejected => {
            let target = scoped_predicate_call(text).map(|(_, arg)| arg);
            (kind, target)
        }
        PredicateKind::PathPrefixConfined => {
            // Subject (arg 0) of `strncmp(x, prefix, strlen(prefix))`.  Scoping
            // the FILE_IO clear to just the subject is what distinguishes the
            // uftpd fix (`strncmp(rpath, …)`, confines the returned value) from
            // the bug (`strncmp(dir, …)`, confines an unrelated local).
            let target = path_prefix_confinement_subject(text);
            (kind, target)
        }
        PredicateKind::Comparison => {
            // `x === '/login'`, `x == 5`, `null != obj`, when exactly one
            // side is a literal, extract the identifier side as the target.
            // This only narrows which condition vars the branch touches;
            // the equal-edge validation itself comes from
            // [`equality_literal_guard`].
            let target = extract_comparison_target(text);
            (kind, target)
        }
        _ => (kind, None),
    }
}

/// Extract the identifier side of an equality/inequality comparison where
/// exactly one side is a scalar literal.
///
/// Examples:
/// - `x === '/login'` → `Some("x")`
/// - `x !== 5` → `Some("x")`
/// - `null != obj` → `Some("obj")`
/// - `x === y` → `None` (neither side is a literal)
/// - `'a' == 'b'` → `None` (both sides are literals)
/// - `obj.field == 3` → `Some("obj.field")` ([`is_identifier`] accepts
///   dots; the consumer only uses it when it names a condition var)
///
/// Best-effort text analysis, kept conservative to avoid false validation.
fn extract_comparison_target(text: &str) -> Option<String> {
    let trimmed = text.trim();

    // Find the operator token.  Check longer forms first so `===` doesn't
    // match as `==` with a trailing `=`.
    for op in &["===", "!==", "==", "!="] {
        if let Some(pos) = trimmed.find(op) {
            let left = trimmed[..pos].trim();
            let right = trimmed[pos + op.len()..].trim();
            let left_is_ident = is_identifier(left);
            let right_is_ident = is_identifier(right);
            let left_is_lit = is_comparison_literal(left);
            let right_is_lit = is_comparison_literal(right);
            return match (left_is_ident, right_is_ident, left_is_lit, right_is_lit) {
                (true, _, false, true) => Some(left.to_string()),
                (_, true, true, false) => Some(right.to_string()),
                _ => None,
            };
        }
    }
    None
}

/// Test whether `s` is a scalar literal for comparison-target extraction.
/// Accepts string literals (single/double/backtick quoted), numeric literals,
/// and the null/undefined/nil/true/false tokens.
fn is_comparison_literal(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }

    // String literal: delimited by matching quotes.
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'' || first == b'`') && first == last {
            return true;
        }
    }

    // Keyword literal tokens.
    if matches!(s, "null" | "undefined" | "nil" | "None" | "true" | "false") {
        return true;
    }

    is_numeric_literal(s)
}

/// A comparison of a parsed URL's authority against another value:
/// `u.host === X`, `u.hostname != X`, `u.origin == X`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlHostCompare {
    /// The identifier holding the parsed URL (`u`).
    pub subject: String,
    /// True for `==` / `===`, false for `!=` / `!==`.
    pub is_eq: bool,
    /// Text of the other operand.
    pub rhs: String,
}

/// True when the `(` at the start of `text` closes at its last byte.
fn outer_parens_wrap(text: &str) -> bool {
    let mut depth = 0i32;
    for (i, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i == text.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// Recognise `<ident>.host|hostname|origin <op> <expr>` as a whole condition.
///
/// Text only: the caller must confirm `subject` really holds a parsed URL
/// (`const u = new URL(..)`), because `.host` on any other object is just a
/// field comparison.  Compound conditions, a leading `!` or `(`, and a
/// left-hand side that is not a plain `ident.accessor` return `None`.
pub fn url_host_compare(text: &str) -> Option<UrlHostCompare> {
    let mut text = text.trim();
    // `if (a.host === b)` may reach us with the parentheses still on.
    while text.starts_with('(') && text.ends_with(')') && outer_parens_wrap(text) {
        text = text[1..text.len() - 1].trim();
    }
    if text.contains("&&") || text.contains("||") || text.contains('?') {
        return None;
    }
    let (pos, op) = ["!==", "===", "!=", "=="]
        .iter()
        .filter_map(|op| text.find(op).map(|i| (i, *op)))
        .min_by_key(|(i, op)| (*i, std::cmp::Reverse(op.len())))?;
    let lhs = text[..pos].trim();
    let rhs = text[pos + op.len()..].trim();
    if rhs.is_empty() {
        return None;
    }
    let (subject, accessor) = lhs.split_once('.')?;
    if !matches!(accessor, "host" | "hostname" | "origin") {
        return None;
    }
    let mut chars = subject.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    Some(UrlHostCompare {
        subject: subject.to_string(),
        is_eq: op.starts_with('=') || op == "==",
        rhs: rhs.to_string(),
    })
}

/// A single equality test of a bare variable against a constant literal:
/// `dir === 'asc'`, `order != "desc"`, `$n === 5`, `'asc' == dir`.
///
/// Returns `(variable, op_is_eq)`.  On the edge where the values are equal
/// the variable holds the literal, so an `a == 'x' || a == 'y'` chain (which
/// the CFG splits into one branch per clause) is an inline allowlist.
///
/// Conservative on purpose:
/// * the variable must be a plain identifier (an optional PHP `$` is
///   stripped), not a member path like `x.length`;
/// * the literal must be a plain string (no `${..}` / `#{..}` / PHP `"$x"`
///   interpolation) or a number; `null` / `true` / `false` and friends are
///   other idioms;
/// * PHP loose `==` against a number is rejected, since before PHP 8
///   `"1 OR 1=1" == 1` holds;
/// * a whole-condition `!` / `not` returns `None` rather than guessing.
pub fn equality_literal_guard(text: &str) -> Option<(String, bool)> {
    use crate::abstract_interp::path_domain::{strip_leading_not, strip_outer_parens};

    let t = strip_outer_parens(text.trim());
    if strip_leading_not(t).is_some() {
        return None;
    }
    let (lhs, op, rhs) = split_single_comparison(t)?;
    let op_is_eq = match op {
        "==" | "===" => true,
        "!=" | "!==" => false,
        _ => return None,
    };
    let strict = op.len() == 3;
    let (ident, literal) = match (equality_literal(lhs), equality_literal(rhs)) {
        (None, Some(lit)) => (lhs.trim(), lit),
        (Some(lit), None) => (rhs.trim(), lit),
        _ => return None,
    };
    let (ident, php_var) = match ident.strip_prefix('$') {
        Some(rest) => (rest, true),
        None => (ident, false),
    };
    if !is_identifier(ident) && !is_const_index_read(ident) || ident.contains('.') {
        return None;
    }
    if php_var && !strict && literal == EqLiteral::Number {
        return None;
    }
    Some((ident.to_string(), op_is_eq))
}

/// `ident[<decimal literal>]`, the spelling Go lowering uses for a
/// constant-index element read (see [`crate::cfg::NodeInfo::elem_reads`]).
/// Only a condition that lists the same spelling among its variables can
/// narrow on it, which the Go CFG does and no other language does.
fn is_const_index_read(s: &str) -> bool {
    let Some((base, rest)) = s.split_once('[') else {
        return false;
    };
    let Some(digits) = rest.strip_suffix(']') else {
        return false;
    };
    is_identifier(base)
        && !base.contains('.')
        && !digits.is_empty()
        && digits.bytes().all(|c| c.is_ascii_digit())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EqLiteral {
    String,
    Number,
}

/// A constant string or numeric literal operand of an equality test.
fn equality_literal(operand: &str) -> Option<EqLiteral> {
    let s = operand.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let q = bytes[0];
        if matches!(q, b'"' | b'\'' | b'`') && bytes[bytes.len() - 1] == q {
            let inner = &s[1..s.len() - 1];
            if inner.contains(q as char) || inner.contains("${") || inner.contains("#{") {
                return None;
            }
            // PHP / shell style `"$name"` interpolation.
            let dollar_var = q == b'"'
                && inner
                    .split('$')
                    .skip(1)
                    .any(|rest| rest.starts_with(|c: char| c.is_alphabetic() || c == '_'));
            if dollar_var {
                return None;
            }
            return Some(EqLiteral::String);
        }
    }
    is_numeric_literal(s).then_some(EqLiteral::Number)
}

/// Optional sign, then digits with optional `.` / `_` separators.
fn is_numeric_literal(s: &str) -> bool {
    let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
    digits.starts_with(|c: char| c.is_ascii_digit())
        && digits
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '_')
}

/// Count positional arguments in a call-shaped condition text.
///
/// Returns `None` when the text does not look like a call (no `(`). Returns
/// `Some(0)` for a call with empty argument list. Respects paren/bracket/brace
/// nesting so `f(g(a, b), c)` counts as 2 top-level args.
///
/// Best-effort, operates on source text, not an AST. Used by
/// `classify_condition_with_target` to distinguish single-arg vs multi-arg
/// validator calls when target extraction fails.
fn count_call_args(text: &str) -> Option<usize> {
    let trimmed = text.trim();
    let trimmed = trimmed.strip_prefix('!').unwrap_or(trimmed).trim();
    let paren_pos = trimmed.find('(')?;
    let args_part = &trimmed[paren_pos + 1..];
    let args_inner = args_part
        .trim_end()
        .strip_suffix(')')
        .unwrap_or(args_part)
        .trim();
    if args_inner.is_empty() {
        return Some(0);
    }
    let mut count = 1usize;
    let mut depth: i32 = 0;
    for ch in args_inner.chars() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    Some(count)
}

/// Extract the first top-level argument from `args_part`, the substring
/// immediately following the open paren of a call expression.  Walks
/// paren/bracket/brace depth and skips quoted strings so nested calls and
/// punctuation inside string literals do not confuse the scan.  Returns
/// the trimmed argument substring up to the first top-level `,` or
/// matching `)`, or `None` when no balanced close paren is found.
///
/// Robust against trailing wrapper parens such as
/// `(!ALLOWED.includes(cmd))` where naïve `strip_suffix(')')` would leave
/// `cmd)` and lose the argument.
fn first_call_arg(args_part: &str) -> Option<&str> {
    call_arg(args_part, 0)
}

/// The `n`th top-level argument of the call whose argument list starts at
/// `args_part` (just after the opening paren).  Same scan as
/// [`first_call_arg`].
fn call_arg(args_part: &str, n: usize) -> Option<&str> {
    let bytes = args_part.as_bytes();
    let mut depth: usize = 1;
    let mut end: Option<usize> = None;
    let mut commas: smallvec::SmallVec<[usize; 4]> = smallvec::SmallVec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            b',' if depth == 1 => commas.push(i),
            b'"' | b'\'' => {
                let quote = b;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        break;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let end = end?;
    let from = if n == 0 { 0 } else { *commas.get(n - 1)? + 1 };
    let to = commas.get(n).copied().unwrap_or(end);
    Some(args_part[from..to].trim())
}

/// Extract the validated variable from a condition text.
///
/// Handles two patterns:
/// - Function call: `validate(x, ...)` → `"x"`
/// - Method call: `x.validate(...)` → `"x"`
fn extract_validation_target(text: &str) -> Option<String> {
    if let Some(arg) = anchored_regex_literal_test_arg(text) {
        return Some(arg);
    }
    let trimmed = text.trim();

    // Strip leading wrappers (parens, `!`, `not `) so idiomatic forms like
    // `(!validate(x))` (TS/JS) and `not validate(x)` (Python) are reachable.
    let trimmed = trimmed.trim_start_matches(['(', '!', ' ', '\t']);
    let trimmed = trimmed.strip_prefix("not ").unwrap_or(trimmed).trim();

    // Java/Kotlin chain `<re>.matcher(value).matches()`: the validated
    // target is the inner `.matcher()` argument, not the bare `.matches()`
    // receiver.  Locked on the same regex/pattern receiver gate as the
    // classifier (GHSA-h8cj-hpmg-636v).
    if trimmed.to_ascii_lowercase().contains(".matches(")
        && let Some(matcher_pos) = trimmed.find(".matcher(")
    {
        let receiver_lower = trimmed[..matcher_pos].to_ascii_lowercase();
        if receiver_lower.contains("regex") || receiver_lower.contains("pattern") {
            let args_start = matcher_pos + ".matcher(".len();
            if let Some(first_arg) = first_call_arg(&trimmed[args_start..]) {
                let first_arg = first_arg.strip_prefix('&').unwrap_or(first_arg).trim();
                if !first_arg.is_empty() && is_identifier(first_arg) {
                    return Some(first_arg.to_string());
                }
            }
        }
    }

    // Find the first `(` which separates callee from args
    let paren_pos = trimmed.find('(')?;
    let callee_part = &trimmed[..paren_pos];
    let args_part = &trimmed[paren_pos + 1..];

    // Check for method call pattern: `x.method(...)` or `x.method_name(...)`
    if let Some(dot_pos) = callee_part.rfind('.') {
        let receiver = callee_part[..dot_pos].trim();
        let method = callee_part[dot_pos + 1..].trim().to_ascii_lowercase();
        // Regex-allowlist `<re>.test(value)` / `<re>.match(value)` / `<re>.matches(value)`:
        // the validated target is the call's first argument, not the regex
        // receiver.  Without this special case, branch narrowing would mark
        // the regex itself as validated and leave the user input alone.
        if matches!(method.as_str(), "test" | "match" | "matches")
            && let Some(first_arg) = first_call_arg(args_part)
        {
            let first_arg = first_arg.strip_prefix('&').unwrap_or(first_arg).trim();
            if !first_arg.is_empty() && is_identifier(first_arg) {
                return Some(first_arg.to_string());
            }
        }
        if !receiver.is_empty() && is_identifier(receiver) {
            return Some(receiver.to_string());
        }
    }

    // Function call pattern: `func(x, ...)`, extract first argument with
    // balanced-paren scan so trailing wrapper parens (`(validate(x))`) do
    // not corrupt the argument substring.
    let first_arg = first_call_arg(args_part)?;

    // Strip reference operators (e.g. `&x` → `x`) and PHP variable sigil
    // (`$url` → `url`) so the extracted target lines up with the var-name
    // form used in branch-narrowing.  Mirrors the `$` strip already done by
    // `extract_allowlist_target` for `in_array($cmd, $allowed)`.
    let first_arg = first_arg.strip_prefix('&').unwrap_or(first_arg).trim();
    let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);

    if !first_arg.is_empty() && is_identifier(first_arg) {
        Some(first_arg.to_string())
    } else {
        None
    }
}

/// Extract the target variable from an allowlist/membership check.
///
/// Handles:
/// - `.includes(cmd)` → `cmd` (first argument)
/// - `in_array($cmd, $allowed)` → `cmd` (first arg, strip `$`)
/// - `cmd not in ALLOWED` / `cmd in ALLOWED` → `cmd` (left of ` in `)
/// - `allowed[cmd]` → `cmd` (inside brackets)
fn extract_allowlist_target(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();

    // Method call pattern: something.includes(arg) / .contains(arg) / .has(arg) / .indexof(arg)
    for method in &[
        ".includes(",
        ".include?(",
        ".contains(",
        ".indexof(",
        ".has(",
    ] {
        if let Some(pos) = lower.find(method) {
            let args_start = pos + method.len();
            let args_part = &trimmed[args_start..];
            // Go's generic `slices.Contains(list, v)` (and the samber/lo and
            // go-funk equivalents) is a package function: the collection is
            // argument 0 and the value under test argument 1.
            let pkg_second = (*method == ".contains(" && is_go_collection_pkg(&lower[..pos]))
                .then(|| call_arg(args_part, 1))
                .flatten();
            let value_arg = pkg_second.or_else(|| first_call_arg(args_part));
            if let Some(arg) = value_arg {
                let arg = strip_borrow_and_view(arg);
                let arg = arg.strip_prefix('$').unwrap_or(arg);
                if !arg.is_empty() && is_identifier(arg) {
                    return Some(arg.to_string());
                }
            }
        }
    }

    // in_array($cmd, $allowed) → cmd
    if let Some(pos) = lower.find("in_array(") {
        let args_start = pos + "in_array(".len();
        let args_part = &trimmed[args_start..];
        if let Some(first_arg) = first_call_arg(args_part) {
            let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
            if !first_arg.is_empty() && is_identifier(first_arg) {
                return Some(first_arg.to_string());
            }
        }
    }

    // Value-first membership free function: `InArray(value, coll)` /
    // `stringInSlice(value, list)` — the value under test is the first arg.
    // Matches the camelCase / package-qualified spellings the `in_array(`
    // branch above misses (CVE-2026-21859 Mailpit `tools.InArray(uri, links)`).
    if is_value_first_membership_fn(trimmed) {
        let t = trimmed.trim_start_matches(['(', '!', ' ', '\t']);
        let t = t.strip_prefix("not ").unwrap_or(t).trim();
        if let Some(open) = t.find('(') {
            let args_part = &t[open + 1..];
            if let Some(first_arg) = first_call_arg(args_part) {
                let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
                if !first_arg.is_empty() && is_identifier(first_arg) {
                    return Some(first_arg.to_string());
                }
            }
        }
    }

    // Python `in` operator: `cmd in ALLOWED` / `cmd not in ALLOWED`
    if lower.contains(" in ") {
        // Find the leftmost ` in `, everything before it is the target expression
        // Handle `not in` by looking for ` not in ` first
        let target_part = if let Some(pos) = lower.find(" not in ") {
            &trimmed[..pos]
        } else {
            let pos = lower.find(" in ")?;
            &trimmed[..pos]
        };
        let target = target_part.trim();
        let target = target.strip_prefix('!').unwrap_or(target).trim();
        let target = target.strip_prefix('$').unwrap_or(target);
        if !target.is_empty() && is_identifier(target) {
            return Some(target.to_string());
        }
    }

    // Go map lookup: `allowed[cmd]`
    if let Some(open) = trimmed.find('[') {
        if let Some(close) = trimmed.find(']') {
            if close > open + 1 {
                let inner = trimmed[open + 1..close].trim();
                let inner = inner.strip_prefix('$').unwrap_or(inner);
                if !inner.is_empty() && is_identifier(inner) {
                    return Some(inner.to_string());
                }
            }
        }
    }

    None
}

/// True when `before` (the text up to a `.contains(` call) ends in a bare Go
/// collection-helper package name rather than a receiver value.
fn is_go_collection_pkg(before: &str) -> bool {
    let start = before
        .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
        .map_or(0, |i| i + 1);
    matches!(&before[start..], "slices" | "lo" | "funk")
}

/// Peel borrows and identity views off a membership argument so the value
/// under test lines up with its variable name: Rust `&x`, `&mut x`, `*x`,
/// `&x.as_str()`, `x.as_ref()`, `x.to_string()`.  Conversions that change
/// the value (`trim`, `to_lowercase`) are left alone, so the argument is no
/// longer a bare identifier and no target is extracted.
fn strip_borrow_and_view(arg: &str) -> &str {
    let mut a = arg.trim();
    loop {
        let before = a;
        a = a.strip_prefix("&mut ").unwrap_or(a).trim_start();
        a = a.trim_start_matches(['&', '*']).trim_start();
        for view in [
            ".as_str()",
            ".as_ref()",
            ".to_string()",
            ".as_slice()",
            ".as_bytes()",
        ] {
            if let Some(rest) = a.strip_suffix(view) {
                a = rest.trim_end();
            }
        }
        if a == before {
            return a;
        }
    }
}

/// Detect map-membership style indexing such as `allowed[cmd]` without
/// treating ordinary array indexing/comparisons (`buf[len - 1] == '\n'`) as
/// allowlist validation.
fn is_index_membership_check(text: &str) -> bool {
    let mut trimmed = text.trim();
    while let Some(inner) = trimmed
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
    {
        trimmed = inner.trim();
    }
    trimmed = trimmed.strip_prefix('!').unwrap_or(trimmed).trim();
    if trimmed.contains('(') {
        return false;
    }
    let Some(open) = trimmed.find('[') else {
        return false;
    };
    let Some(close_rel) = trimmed[open + 1..].find(']') else {
        return false;
    };
    let close = open + 1 + close_rel;
    let base = trimmed[..open].trim();
    let inner = trimmed[open + 1..close].trim();
    let after = trimmed[close + 1..].trim();
    is_identifier(base)
        && is_identifier(inner)
        && (after.is_empty()
            || after.starts_with("==")
            || after.starts_with("!=")
            || after.starts_with("===")
            || after.starts_with("!=="))
}

/// Extract the target variable from a type-check guard.
///
/// Handles:
/// - `typeof input !== 'number'` → `input` (word after `typeof`)
/// - `isinstance(user_id, int)` → `user_id` (first arg)
/// - `input.matches("\\d+")` → `input` (receiver)
/// - `is_numeric($id)` → `id` (first arg, strip `$`)
fn extract_type_check_target(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();

    // typeof: `typeof input !== 'number'`
    if let Some(pos) = lower.find("typeof ") {
        let after = &trimmed[pos + "typeof ".len()..];
        // The target is the next identifier-like word
        let target: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !target.is_empty() {
            return Some(target);
        }
    }

    // isinstance(user_id, int) → user_id
    if let Some(pos) = lower.find("isinstance(") {
        let args_start = pos + "isinstance(".len();
        let args_part = &trimmed[args_start..];
        let inner = args_part.strip_suffix(')').unwrap_or(args_part);
        let first_arg = inner.split(',').next()?.trim();
        let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
        if !first_arg.is_empty() && is_identifier(first_arg) {
            return Some(first_arg.to_string());
        }
    }

    // Java/TS instanceof: "x instanceof String" → "x"
    if let Some(pos) = lower.find(" instanceof ") {
        let var_part = trimmed[..pos].trim();
        if !var_part.is_empty() && is_identifier(var_part) {
            return Some(var_part.to_string());
        }
    }

    // .matches("...") → receiver
    if let Some(pos) = lower.find(".matches(") {
        let receiver = trimmed[..pos].trim();
        let receiver = receiver.strip_prefix('!').unwrap_or(receiver).trim();
        if !receiver.is_empty() && is_identifier(receiver) {
            return Some(receiver.to_string());
        }
    }

    // PHP type checks: is_numeric($id), is_int($x), is_string($x), is_float($x)
    for func in &["is_numeric(", "is_int(", "is_string(", "is_float("] {
        if let Some(pos) = lower.find(func) {
            let args_start = pos + func.len();
            let args_part = &trimmed[args_start..];
            let inner = args_part.strip_suffix(')').unwrap_or(args_part);
            let first_arg = inner.split(',').next()?.trim();
            let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
            if !first_arg.is_empty() && is_identifier(first_arg) {
                return Some(first_arg.to_string());
            }
        }
    }

    // Ruby type checks: user_id.is_a?(Integer), x.kind_of?(String) → receiver
    for method in &[".is_a?(", ".kind_of?("] {
        if let Some(pos) = lower.find(method) {
            let receiver = trimmed[..pos].trim();
            let receiver = receiver.strip_prefix('!').unwrap_or(receiver).trim();
            if !receiver.is_empty() && is_identifier(receiver) {
                return Some(receiver.to_string());
            }
        }
    }

    // ctype_ functions: ctype_digit($x)
    if let Some(pos) = lower.find("ctype_") {
        // Find the `(` after ctype_xxx
        if let Some(paren_pos) = trimmed[pos..].find('(') {
            let args_start = pos + paren_pos + 1;
            let args_part = &trimmed[args_start..];
            let inner = args_part.strip_suffix(')').unwrap_or(args_part);
            let first_arg = inner.split(',').next()?.trim();
            let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
            if !first_arg.is_empty() && is_identifier(first_arg) {
                return Some(first_arg.to_string());
            }
        }
    }

    None
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_condition ────────────────────────────────────────────────

    #[test]
    fn classify_empty_is_unknown() {
        assert_eq!(classify_condition(""), PredicateKind::Unknown);
    }

    #[test]
    fn classify_null_checks() {
        assert_eq!(classify_condition("x.is_none()"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x == null"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x != nil"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x is None"), PredicateKind::NullCheck);
        assert_eq!(classify_condition("x === null"), PredicateKind::NullCheck);
    }

    #[test]
    fn classify_error_checks() {
        assert_eq!(classify_condition("x.is_err()"), PredicateKind::ErrorCheck);
        assert_eq!(classify_condition("err != nil"), PredicateKind::ErrorCheck);
        assert_eq!(classify_condition("x.is_ok()"), PredicateKind::ErrorCheck);
    }

    #[test]
    fn classify_empty_checks() {
        assert_eq!(
            classify_condition("x.is_empty()"),
            PredicateKind::EmptyCheck
        );
        assert_eq!(
            classify_condition("x.len() == 0"),
            PredicateKind::EmptyCheck
        );
        assert_eq!(
            classify_condition("x.length === 0"),
            PredicateKind::EmptyCheck
        );
    }

    #[test]
    fn predicate_bit_negative_form_reads_the_operator() {
        use PredicateKind::*;
        let neg = |k, t| predicate_bit_negative_form(k, t);
        // Null checks: the `==` inside `!==` / `!=` must not read as equality.
        assert_eq!(neg(NullCheck, "x === null"), Some(false));
        assert_eq!(neg(NullCheck, "x == null"), Some(false));
        assert_eq!(neg(NullCheck, "x !== null"), Some(true));
        assert_eq!(neg(NullCheck, "x != nil"), Some(true));
        assert_eq!(neg(NullCheck, "cfg is None"), Some(false));
        assert_eq!(neg(NullCheck, "cfg is not None"), Some(true));
        assert_eq!(neg(NullCheck, "y.is_none()"), Some(false));
        assert_eq!(neg(NullCheck, "y.is_some()"), Some(true));
        // Error checks: the plain form is "an error is present".
        assert_eq!(neg(ErrorCheck, "err != nil"), Some(false));
        assert_eq!(neg(ErrorCheck, "err == nil"), Some(true));
        assert_eq!(neg(ErrorCheck, "r.is_err()"), Some(false));
        assert_eq!(neg(ErrorCheck, "r.is_ok()"), Some(true));
        // Empty checks.
        assert_eq!(neg(EmptyCheck, "xs.length === 0"), Some(false));
        assert_eq!(neg(EmptyCheck, "xs.length !== 0"), Some(true));
        assert_eq!(neg(EmptyCheck, "s !== \"\""), Some(true));
        assert_eq!(neg(EmptyCheck, "v.is_empty()"), Some(false));
        // Both forms in one condition: no single bit applies.
        assert_eq!(neg(NullCheck, "a != null && b == null"), None);
        assert_eq!(neg(ErrorCheck, "err != nil || error == nil"), None);
        // Other kinds carry no predicate bit.
        assert_eq!(neg(ValidationCall, "validate(x)"), None);
    }

    #[test]
    fn classify_validation_call() {
        assert_eq!(
            classify_condition("validate(x)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("is_safe(input)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("check_auth(req)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("input.verify(sig)"),
            PredicateKind::ValidationCall
        );
    }

    #[test]
    fn classify_camelcase_safety_validators_are_validation_call() {
        // Real-CVE shape: roadiz/documents `isSafeRemoteUrl($url)` (CVE-2026-33486).
        // Without snake-case normalisation, the bare `issaferemoteurl` would
        // not match the `is_safe` prefix and the predicate would silently
        // fall into `Comparison`/`Unknown`, leaving `$url` un-validated past
        // the early-return.
        assert_eq!(
            classify_condition("self::isSafeRemoteUrl($url)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("isAuthorized(user)"),
            PredicateKind::ValidationCall
        );
        assert_eq!(
            classify_condition("isAuthenticated(req)"),
            PredicateKind::ValidationCall
        );
        // Acronym handling: `isValidUUID` → `is_valid_uuid` → contains "valid".
        assert_eq!(
            classify_condition("isValidUUID(id)"),
            PredicateKind::ValidationCall
        );
        // Snake-case round-trips unchanged.
        assert_eq!(
            classify_condition("is_safe_remote_url(x)"),
            PredicateKind::ValidationCall
        );
    }

    #[test]
    fn extract_validation_target_strips_php_dollar_sigil() {
        // PHP `$url` strips the sigil so the extracted target lines up with
        // the var-name form used in branch narrowing.  Required for
        // CVE-2026-33486 patched fixture to silence on `fopen($url, 'r')`.
        assert_eq!(
            extract_validation_target("self::isSafeRemoteUrl($url)"),
            Some("url".to_string())
        );
        assert_eq!(
            extract_validation_target("validate($input)"),
            Some("input".to_string())
        );
    }

    #[test]
    fn to_snake_lower_handles_common_variants() {
        assert_eq!(to_snake_lower("isSafeRemoteUrl"), "is_safe_remote_url");
        assert_eq!(to_snake_lower("isValidUUID"), "is_valid_uuid");
        assert_eq!(to_snake_lower("HTTPClient"), "http_client");
        assert_eq!(to_snake_lower("IsSafe"), "is_safe");
        assert_eq!(to_snake_lower("is_safe"), "is_safe");
        assert_eq!(to_snake_lower("validate"), "validate");
        assert_eq!(to_snake_lower(""), "");
    }

    #[test]
    fn classify_validation_requires_paren() {
        // `x_valid == true` should NOT be ValidationCall, no `(` call syntax.
        assert_eq!(
            classify_condition("x_valid == true"),
            PredicateKind::Comparison
        );
        assert_eq!(
            classify_condition("is_valid && ready"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn classify_sanitizer_call() {
        assert_eq!(
            classify_condition("sanitize(x)"),
            PredicateKind::SanitizerCall
        );
        assert_eq!(
            classify_condition("html_escape(s)"),
            PredicateKind::SanitizerCall
        );
        assert_eq!(
            classify_condition("url_encode(path)"),
            PredicateKind::SanitizerCall
        );
    }

    #[test]
    fn classify_comparison() {
        assert_eq!(classify_condition("x == 5"), PredicateKind::Comparison);
        assert_eq!(classify_condition("x != y"), PredicateKind::Comparison);
        assert_eq!(classify_condition("a >= b"), PredicateKind::Comparison);
    }

    #[test]
    fn classify_unknown_fallback() {
        assert_eq!(classify_condition("flag"), PredicateKind::Unknown);
        assert_eq!(classify_condition("a && b"), PredicateKind::Unknown);
    }

    // ── classify_condition_with_target ──────────────────────────────────

    #[test]
    fn target_function_call_first_arg() {
        let (kind, target) = classify_condition_with_target("validate(x, config)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_method_call_receiver() {
        let (kind, target) = classify_condition_with_target("x.isValid()");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_sanitizer_first_arg() {
        let (kind, target) = classify_condition_with_target("sanitize(input)");
        assert_eq!(kind, PredicateKind::SanitizerCall);
        assert_eq!(target.as_deref(), Some("input"));
    }

    #[test]
    fn target_negated_validation() {
        let (kind, target) = classify_condition_with_target("!validate(&x)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("x"));
    }

    /// Regex `<X>.test(value)` should classify as ValidationCall and the
    /// validated target should be the call argument, not the regex
    /// receiver.  Pinned because the receiver-as-target heuristic is the
    /// default for method calls.  Motivated by Payload CVE-2026-25544
    /// (`if (!SAFE_STRING_REGEX.test(value)) throw …;`).
    #[test]
    fn target_regex_test_first_arg() {
        let (kind, target) = classify_condition_with_target("!SAFE_STRING_REGEX.test(value)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("value"));
    }

    #[test]
    fn target_regex_test_pattern_receiver() {
        let (kind, target) = classify_condition_with_target("ALLOWED_PATTERN.test(s)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("s"));
    }

    /// Receiver name without a regex/pattern marker should NOT be pulled
    /// in as a validator: `obj.test(x)` is a test runner, not a regex.
    #[test]
    fn target_test_non_regex_receiver_is_not_validation() {
        let kind = classify_condition("obj.test(value)");
        assert_eq!(kind, PredicateKind::Unknown);
    }

    #[test]
    fn target_comparison_extracts_identifier_side() {
        let (kind, target) = classify_condition_with_target("x == 5");
        assert_eq!(kind, PredicateKind::Comparison);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_comparison_strict_equality_with_string() {
        let (kind, target) = classify_condition_with_target("x === '/login'");
        assert_eq!(kind, PredicateKind::Comparison);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn target_comparison_literal_on_left() {
        let (kind, target) = classify_condition_with_target("null != obj");
        assert_eq!(kind, PredicateKind::Comparison);
        assert_eq!(target.as_deref(), Some("obj"));
    }

    #[test]
    fn target_comparison_both_identifiers_returns_none() {
        let (kind, target) = classify_condition_with_target("x === y");
        assert_eq!(kind, PredicateKind::Comparison);
        assert_eq!(target, None);
    }

    #[test]
    fn target_comparison_both_literals_returns_none() {
        let (kind, target) = classify_condition_with_target("'a' == 'b'");
        assert_eq!(kind, PredicateKind::Comparison);
        assert_eq!(target, None);
    }

    #[test]
    fn target_check_auth_first_arg() {
        let (kind, target) = classify_condition_with_target("check_auth(req)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("req"));
    }

    #[test]
    fn target_method_with_args() {
        let (kind, target) = classify_condition_with_target("input.verify(sig)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("input"));
    }

    #[test]
    fn target_multi_arg_fallback_opaque_expr_is_unknown() {
        // `validate(x + 1, y)`, first arg is an expression, not an identifier.
        // Target extraction fails. Multi-arg call, so fall back to Unknown
        // rather than letting upstream validate every condition var.
        let (kind, target) = classify_condition_with_target("validate(x + 1, y)");
        assert_eq!(kind, PredicateKind::Unknown);
        assert_eq!(target, None);
    }

    #[test]
    fn target_single_arg_fallback_preserves_kind() {
        // Single-arg call with unextractable target: keep the original kind so
        // the predicate-summary bit can still be set. No over-validation risk
        // because there is only one var in scope.
        let (kind, target) = classify_condition_with_target("validate(x + 1)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target, None);
    }

    #[test]
    fn target_multi_arg_dotted_first_arg_is_unknown() {
        // `validate(a.field, limit)` extracts the dotted target `a.field`,
        // which can never match a bare-identifier condition var, so the
        // consumer would fall back to validating EVERY condition var
        // (including `limit`, which the validator never inspected).  A dotted
        // multi-arg target must degrade to Unknown, exactly like a failed
        // extraction, so no unrelated argument is wrongly validated.
        let (kind, target) = classify_condition_with_target("validate(a.field, limit)");
        assert_eq!(kind, PredicateKind::Unknown);
        assert_eq!(target, None);
    }

    #[test]
    fn target_multi_arg_dotted_receiver_is_unknown() {
        // `req.session.verify(sig, opts)` resolves to the dotted receiver
        // `req.session`; same non-matching-target hazard on a multi-arg call.
        let (kind, target) = classify_condition_with_target("req.session.verify(sig, opts)");
        assert_eq!(kind, PredicateKind::Unknown);
        assert_eq!(target, None);
    }

    #[test]
    fn target_single_arg_dotted_preserves_kind_no_dotted_target() {
        // Single-arg dotted-receiver validator: over-validation of all
        // condition vars is pre-existing/intentional for single-arg calls, but
        // the returned target must NOT be a dotted member expression (which
        // can never match condition_vars).  Preserve the kind with None.
        let (kind, target) = classify_condition_with_target("req.session.verify(sig)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target, None);
    }

    #[test]
    fn target_bare_identifier_still_extracted() {
        // Regression guard: a bare-identifier multi-arg target still narrows.
        let (kind, target) = classify_condition_with_target("validate(x, limit)");
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn count_call_args_basic() {
        assert_eq!(super::count_call_args("f(a, b, c)"), Some(3));
        assert_eq!(super::count_call_args("f(a)"), Some(1));
        assert_eq!(super::count_call_args("f()"), Some(0));
        assert_eq!(super::count_call_args("f(g(x, y), z)"), Some(2));
        assert_eq!(super::count_call_args("not_a_call"), None);
    }

    // ── AllowlistCheck classification ─────────────────────────────────

    #[test]
    fn classify_allowlist_includes() {
        assert_eq!(
            classify_condition("ALLOWED.includes(cmd)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_in_array() {
        assert_eq!(
            classify_condition("in_array($cmd, $allowed)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_python_not_in() {
        assert_eq!(
            classify_condition("cmd not in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_python_in() {
        assert_eq!(
            classify_condition("cmd in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_map_lookup() {
        assert_eq!(
            classify_condition("allowed[cmd]"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("!allowed[cmd]"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("(!allowed[cmd])"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_contains() {
        assert_eq!(
            classify_condition("whitelist.contains(value)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_allowlist_has() {
        assert_eq!(
            classify_condition("allowedSet.has(key)"),
            PredicateKind::AllowlistCheck
        );
    }

    // ── Literal-needle substring rejection is NOT an allowlist ─────────
    //
    // `x.includes("..")` / `x.contains("<script>")` test the receiver
    // against a literal needle (a rejection idiom whose TRUE branch is the
    // dangerous path), so they must NOT classify as AllowlistCheck (which
    // would mark `x` validated on the TRUE branch with inverted polarity and
    // silence the finding).  They drop to Unknown so neither branch is
    // over-validated.
    #[test]
    fn classify_literal_needle_dotdot_not_allowlist() {
        assert_eq!(
            classify_condition("p.includes(\"..\")"),
            PredicateKind::Unknown
        );
        assert_eq!(
            classify_condition("p.contains(\"..\")"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn classify_literal_needle_html_not_allowlist() {
        assert_eq!(
            classify_condition("input.includes(\"<script>\")"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn classify_literal_needle_indexof_not_allowlist() {
        assert_eq!(
            classify_condition("path.indexOf(\"..\")"),
            PredicateKind::Unknown
        );
    }

    // ── Negated indexOf membership has inverted polarity ──────────────
    //
    // `ALLOWED.indexOf(x) === -1` / `< 0` means NOT-in-list, so the TRUE
    // branch is the reject path.  Must NOT classify as AllowlistCheck (which
    // would mark `x` validated on the TRUE branch with inverted polarity,
    // silencing a real reject-then-sink finding and producing an FP on the
    // correctly-guarded `=== -1; return; sink` shape).  Drop to Unknown.
    #[test]
    fn classify_negated_indexof_eq_minus_one_is_flipped_allowlist() {
        // Membership is still the atom; the `=== -1` comparison puts it on
        // the FALSE edge (see `sentinel_comparison_polarity`).
        for text in ["ALLOWED.indexOf(cmd) === -1", "ALLOWED.indexOf(cmd) == -1"] {
            assert_eq!(
                classify_condition_with_target(text),
                (PredicateKind::AllowlistCheck, Some("cmd".to_string())),
                "{text}"
            );
            assert_eq!(
                sentinel_comparison_polarity(text),
                SentinelPolarity::Flip,
                "{text}"
            );
        }
    }

    #[test]
    fn classify_negated_indexof_lt_zero_is_flipped_allowlist() {
        assert_eq!(
            classify_condition("allowed.indexOf(x) < 0"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            sentinel_comparison_polarity("allowed.indexOf(x) < 0"),
            SentinelPolarity::Flip
        );
    }

    #[test]
    fn classify_negated_string_find_stays_unknown() {
        // String search, not collection membership.
        assert_eq!(
            classify_condition("s.find(x) == -1"),
            PredicateKind::Unknown
        );
        assert_eq!(
            classify_condition("s.search(x) < 0"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn classify_positive_indexof_membership_stays_allowlist() {
        // `!== -1` / `>= 0` mean found ⇒ in list ⇒ TRUE branch is validated.
        // The existing AllowlistCheck polarity is correct here, so these must
        // remain AllowlistCheck (NOT dropped to Unknown).
        assert_eq!(
            classify_condition("ALLOWED.indexOf(cmd) !== -1"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("ALLOWED.indexOf(cmd) >= 0"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_genuine_allowlist_identifier_arg_unchanged() {
        // Identifier argument (the value under test) is a real membership
        // check and must remain AllowlistCheck.
        assert_eq!(
            classify_condition("ALLOWED.includes(cmd)"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("whitelist.contains(value)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_literal_needle_shell_metachar_still_inverted() {
        // A shell-metachar literal needle is caught by the earlier
        // shell-metachar branch (inverted-polarity SHELL_ESCAPE clear) and
        // must NOT be swallowed by the literal-needle carve-out.
        assert_eq!(
            classify_condition("cmd.includes(\";\")"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn extract_allowlist_target_negated_paren_wrapper() {
        // Tree-sitter records the if-condition as `(!ALLOWED.includes(cmd))`,
        // including the surrounding parens.  Naïve `strip_suffix(')')` left
        // `cmd)` and `is_identifier` rejected the trailing `)`, dropping the
        // structural guard for `cfg-unguarded-sink` suppression.  The
        // balanced-paren scan must return `Some("cmd")`.
        let (kind, target) = classify_condition_with_target("(!ALLOWED.includes(cmd))");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn extract_allowlist_target_java_contains_paren_wrapper() {
        let (kind, target) = classify_condition_with_target("(!ALLOWED.contains(cmd))");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn extract_allowlist_target_in_array_paren_wrapper() {
        let (kind, target) = classify_condition_with_target("(!in_array($cmd, $allowed))");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn classify_value_first_membership_camelcase_in_array() {
        // CVE-2026-21859: Mailpit's SSRF fix guards with `tools.InArray(uri,
        // links)`.  The camelCase spelling lowercases to `inarray(` which the
        // PHP-style `in_array(` (underscore) recogniser misses; the value-first
        // membership-fn recogniser must classify it as an AllowlistCheck and
        // extract the value under test (`uri`, arg 0).
        let (kind, target) = classify_condition_with_target("!InArray(uri, links)");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("uri"));
    }

    #[test]
    fn classify_value_first_membership_package_qualified_and_go_idioms() {
        // Package-qualified callee (`tools.InArray`) resolves on the leaf name.
        let (k1, t1) = classify_condition_with_target("!tools.InArray(uri, links)");
        assert_eq!(k1, PredicateKind::AllowlistCheck);
        assert_eq!(t1.as_deref(), Some("uri"));
        // Common Go membership idiom `stringInSlice(value, list)`.
        let (k2, t2) = classify_condition_with_target("!stringInSlice(host, allowed)");
        assert_eq!(k2, PredicateKind::AllowlistCheck);
        assert_eq!(t2.as_deref(), Some("host"));
    }

    #[test]
    fn relative_url_checks_split_into_two_facts() {
        use PredicateKind::*;
        let cases = [
            ("next.startsWith('/')", LeadingSlashCheck),
            ("!next.startsWith('/')", LeadingSlashCheck),
            ("x.starts_with(\"/\")", LeadingSlashCheck),
            ("not nxt.startswith(\"/\")", LeadingSlashCheck),
            ("strpos($x, '/') === 0", LeadingSlashCheck),
            ("u[0] === '/'", LeadingSlashCheck),
            ("next.startsWith('//')", ProtocolRelativeCheck),
            ("next.startsWith('/\\\\')", ProtocolRelativeCheck),
            ("u[1] === '/'", ProtocolRelativeCheck),
            ("strpos($x, '//') === 0", ProtocolRelativeCheck),
            // the whole check in one undecomposed conjunction
            (
                "x.startsWith('/') && !x.startsWith('//')",
                RelativeUrlValidated,
            ),
            (
                "!(x.startsWith('/') && !x.startsWith('//'))",
                RelativeUrlValidated,
            ),
            (
                "nxt.startswith('/') and not nxt.startswith('//')",
                RelativeUrlValidated,
            ),
        ];
        for (text, want) in cases {
            assert_eq!(classify_condition(text), want, "{text}");
        }
        // Compound texts that are not the full check are not a URL fact.
        for text in [
            "!(x.startsWith('/') || x.startsWith('//'))",
            "x.startsWith('/') && x.length < 100",
            "!x.startsWith('/') || x.startsWith('//')",
        ] {
            let k = classify_condition(text);
            assert!(
                !matches!(
                    k,
                    LeadingSlashCheck | ProtocolRelativeCheck | RelativeUrlValidated
                ),
                "{text}: {k:?}"
            );
        }
        // Targets resolve to the receiver.
        assert_eq!(
            classify_condition_with_target("!next.startsWith('//')")
                .1
                .as_deref(),
            Some("next")
        );
    }

    #[test]
    fn membership_target_go_package_contains_and_rust_borrows() {
        // Go `slices.Contains(list, v)`: the value is the second argument.
        for text in [
            "!slices.Contains(allowed, x)",
            "slices.Contains(allowed, x)",
            "!lo.Contains(allowed, x)",
        ] {
            let (k, t) = classify_condition_with_target(text);
            assert_eq!(k, PredicateKind::AllowlistCheck, "{text}");
            assert_eq!(t.as_deref(), Some("x"), "{text}");
        }
        // A method on a receiver keeps its first argument.
        let (_, t) = classify_condition_with_target("allowed.contains(x)");
        assert_eq!(t.as_deref(), Some("x"));
        let (_, t) = classify_condition_with_target("myslices.Contains(x)");
        assert_eq!(t.as_deref(), Some("x"));
        // Rust borrows and identity views resolve to the variable.
        for text in [
            "!ALLOWED.contains(&x)",
            "!ALLOWED.contains(&x.as_str())",
            "ALLOWED.contains(&mut x)",
            "ALLOWED.contains(*x)",
            "ALLOWED.contains(x.as_ref())",
        ] {
            let (k, t) = classify_condition_with_target(text);
            assert_eq!(k, PredicateKind::AllowlistCheck, "{text}");
            assert_eq!(t.as_deref(), Some("x"), "{text}");
        }
        // A value-changing conversion is not the variable itself.
        let (_, t) = classify_condition_with_target("ALLOWED.contains(&x.trim())");
        assert_eq!(t, None);
    }

    #[test]
    fn value_first_membership_does_not_capture_unrelated_calls() {
        // `.contains(` is handled by the dedicated method branch, not the
        // value-first free-function recogniser (its leaf isn't in the set).
        assert!(!is_value_first_membership_fn("arr.contains(x)"));
        // An unrelated free function must not classify as membership.
        assert!(!is_value_first_membership_fn("compute(a, b)"));
        // A plain comparison is not a membership call.
        assert!(!is_value_first_membership_fn("x == y"));
        // Indexing is not a free-function call.
        assert!(!is_value_first_membership_fn("allowed[cmd]"));
    }

    // ── TypeCheck classification ──────────────────────────────────────

    #[test]
    fn classify_type_check_typeof() {
        assert_eq!(
            classify_condition("typeof input !== 'number'"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_isinstance() {
        assert_eq!(
            classify_condition("isinstance(user_id, int)"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_matches() {
        assert_eq!(
            classify_condition("input.matches(\"\\\\d+\")"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_is_numeric() {
        assert_eq!(
            classify_condition("is_numeric($id)"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn classify_type_check_is_int() {
        assert_eq!(classify_condition("is_int($x)"), PredicateKind::TypeCheck);
    }

    #[test]
    fn classify_type_check_ctype() {
        assert_eq!(
            classify_condition("ctype_digit($x)"),
            PredicateKind::TypeCheck
        );
    }

    // ── Allowlist target extraction ───────────────────────────────────

    #[test]
    fn target_allowlist_includes() {
        let (kind, target) = classify_condition_with_target("ALLOWED.includes(cmd)");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_in_array() {
        let (kind, target) = classify_condition_with_target("in_array($cmd, $allowed)");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_python_in() {
        let (kind, target) = classify_condition_with_target("cmd in ALLOWED");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_python_not_in() {
        let (kind, target) = classify_condition_with_target("cmd not in ALLOWED");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    #[test]
    fn target_allowlist_map_lookup() {
        let (kind, target) = classify_condition_with_target("allowed[cmd]");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));

        let (kind, target) = classify_condition_with_target("!allowed[cmd]");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    // ── TypeCheck target extraction ───────────────────────────────────

    #[test]
    fn target_type_check_typeof() {
        let (kind, target) = classify_condition_with_target("typeof input !== 'number'");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("input"));
    }

    #[test]
    fn target_type_check_isinstance() {
        let (kind, target) = classify_condition_with_target("isinstance(user_id, int)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("user_id"));
    }

    #[test]
    fn target_type_check_matches() {
        let (kind, target) = classify_condition_with_target("input.matches(\"\\\\d+\")");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("input"));
    }

    #[test]
    fn target_type_check_is_numeric() {
        let (kind, target) = classify_condition_with_target("is_numeric($id)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("id"));
    }

    #[test]
    fn target_type_check_ctype() {
        let (kind, target) = classify_condition_with_target("ctype_digit($x)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("x"));
    }

    #[test]
    fn classify_type_check_is_a() {
        assert_eq!(
            classify_condition("user_id.is_a?(Integer)"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn target_type_check_is_a() {
        let (kind, target) = classify_condition_with_target("user_id.is_a?(Integer)");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("user_id"));
    }

    #[test]
    fn classify_allowlist_include_question() {
        assert_eq!(
            classify_condition("ALLOWED.include?(cmd)"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn target_allowlist_include_question() {
        let (kind, target) = classify_condition_with_target("ALLOWED.include?(cmd)");
        assert_eq!(kind, PredicateKind::AllowlistCheck);
        assert_eq!(target.as_deref(), Some("cmd"));
    }

    // ── instanceof classification and target ─────────────────────────────

    #[test]
    fn classify_instanceof_is_type_check() {
        assert_eq!(
            classify_condition("x instanceof Integer"),
            PredicateKind::TypeCheck
        );
        // A String instance is exactly what an injection payload is, so the
        // check validates nothing.
        assert_eq!(
            classify_condition("x instanceof String"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn target_instanceof_x_string() {
        let (kind, target) = classify_condition_with_target("x instanceof String");
        assert_eq!(kind, PredicateKind::Unknown);
        assert_eq!(target, None);
    }

    #[test]
    fn target_instanceof_obj_integer() {
        let (kind, target) = classify_condition_with_target("obj instanceof Integer");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("obj"));
    }

    // ── ShellMetaValidated classification ─────────────────────────────────

    #[test]
    fn classify_shell_metachar_contains_rust() {
        assert_eq!(
            classify_condition("input.contains(\";\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("cmd.contains(\"|\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("s.contains(\"&\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("s.contains(\"`\")"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("s.contains(\"$\")"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_includes_js() {
        assert_eq!(
            classify_condition("input.includes(';')"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("cmd.includes(\"|\")"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_include_question_ruby() {
        assert_eq!(
            classify_condition("cmd.include?(\";\")"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_python_in() {
        assert_eq!(
            classify_condition("\";\" in cmd"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("'|' in cmd"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_shell_metachar_regex_class() {
        assert_eq!(
            classify_condition("cmd.match(/[;|&]/)"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("re.search(\"[;|&]\", cmd)"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_dash_prefix_rejection_for_argv_injection() {
        assert_eq!(
            classify_condition("ssh_host[0] == '-'"),
            PredicateKind::ShellMetaValidated
        );
        assert_eq!(
            classify_condition("\"-\" == argv0[0]"),
            PredicateKind::ShellMetaValidated
        );
    }

    #[test]
    fn classify_non_metachar_contains_is_unknown_not_allowlist() {
        // `x.contains("foo")` must NOT be credited as a shell-metachar
        // rejection, AND must NOT be classified as `AllowlistCheck`: the
        // argument is a string literal, so this is a substring presence/
        // rejection test on the receiver, not membership of the receiver in a
        // collection.  Classifying it as AllowlistCheck would mark the
        // receiver validated on the TRUE branch with inverted polarity and
        // silence a genuine finding (e.g. `if (path.contains("..")) sink(path)`).
        // The classifier degrades to Unknown so neither branch is
        // over-validated.  (guards.rs already excluded these from structural
        // `Cap::all()` dominator guards via the missing allowlist target, so
        // cfg-unguarded-sink suppression is unaffected by this change.)
        assert_eq!(
            classify_condition("input.contains(\"foo\")"),
            PredicateKind::Unknown
        );
        assert_eq!(
            classify_condition("path.contains(\"..\")"),
            PredicateKind::Unknown
        );
        assert_eq!(
            classify_condition("name.contains(\"admin\")"),
            PredicateKind::Unknown
        );
    }

    #[test]
    fn classify_allowlist_membership_unaffected() {
        // `x in ALLOWED` (identifier on left) remains AllowlistCheck.
        // Only a quoted metachar on the LEFT of ` in ` triggers ShellMeta.
        assert_eq!(
            classify_condition("cmd in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("cmd not in ALLOWED"),
            PredicateKind::AllowlistCheck
        );
    }

    #[test]
    fn classify_indexed_char_comparison_as_comparison() {
        assert_eq!(
            classify_condition("len && url_buf[len - 1] == '\\n'"),
            PredicateKind::Comparison
        );
    }

    #[test]
    fn target_shell_metachar_receiver() {
        let (kind, target) = classify_condition_with_target("input.contains(\";\")");
        assert_eq!(kind, PredicateKind::ShellMetaValidated);
        assert_eq!(target.as_deref(), Some("input"));
    }

    // ── Bounded-length TypeCheck ──────────────────────────────────────────

    #[test]
    fn classify_bounded_length_rust_len() {
        assert_eq!(
            classify_condition("input.len() > 100"),
            PredicateKind::BoundedLength
        );
        assert_eq!(
            classify_condition("s.len() >= 256"),
            PredicateKind::BoundedLength
        );
        assert_eq!(
            classify_condition("s.len() < 4096"),
            PredicateKind::BoundedLength
        );
    }

    #[test]
    fn classify_bounded_length_js_length() {
        assert_eq!(
            classify_condition("input.length > 100"),
            PredicateKind::BoundedLength
        );
    }

    #[test]
    fn classify_non_empty_len_stays_comparison() {
        // `.len() > 0` is a non-empty check, NOT a bounded-length validation.
        // Must fall through to Comparison.
        assert_eq!(
            classify_condition("input.len() > 0"),
            PredicateKind::Comparison
        );
        assert_eq!(
            classify_condition("s.len() >= 1"),
            PredicateKind::Comparison
        );
    }

    // ── Helper sanity ─────────────────────────────────────────────────────

    #[test]
    fn shell_metachar_rejection_detects_common_chars() {
        for m in &[";", "|", "&", "`", "$", ">", "<"] {
            let text = format!("x.contains(\"{m}\")");
            assert!(
                is_shell_metachar_rejection(&text),
                "should detect metachar {m:?} in {text:?}"
            );
        }
    }

    #[test]
    fn shell_metachar_rejection_rejects_non_metachar() {
        assert!(!is_shell_metachar_rejection("x.contains(\"foo\")"));
        assert!(!is_shell_metachar_rejection("x.contains(\"admin\")"));
        assert!(!is_shell_metachar_rejection("x.contains(\"..\")"));
    }

    #[test]
    fn shell_metachar_rejection_handles_escapes() {
        assert!(is_shell_metachar_rejection("x.contains(\"\\n\")"));
    }

    #[test]
    fn bounded_length_rejects_zero_and_one() {
        assert!(!is_bounded_length_check("x.len() > 0"));
        assert!(!is_bounded_length_check("x.len() >= 1"));
        assert!(!is_bounded_length_check("x.len() < 1"));
    }

    #[test]
    fn bounded_length_accepts_small_bounds() {
        assert!(is_bounded_length_check("x.len() > 2"));
        assert!(is_bounded_length_check("x.len() <= 256"));
    }

    // ── UrlHostCompare ────────────────────────────────────────────────────

    #[test]
    fn url_host_compare_parses_eq_and_neq() {
        let c = url_host_compare("url.host === this.ctx.host").unwrap();
        assert_eq!(c.subject, "url");
        assert!(c.is_eq);
        assert_eq!(c.rhs, "this.ctx.host");
        let c = url_host_compare("apiUrl.host !== new URL(apiEndPoint).host").unwrap();
        assert_eq!(c.subject, "apiUrl");
        assert!(!c.is_eq);
        assert_eq!(c.rhs, "new URL(apiEndPoint).host");
        let c = url_host_compare("(target.origin == base.origin)").unwrap();
        assert_eq!(c.subject, "target");
        assert!(c.is_eq);
    }

    #[test]
    fn url_host_compare_rejects_other_shapes() {
        assert!(url_host_compare("a.port === 80").is_none());
        assert!(url_host_compare("a.b.host === x").is_none());
        assert!(url_host_compare("a.host === x && ok").is_none());
        assert!(url_host_compare("a.host === x || ok").is_none());
        assert!(url_host_compare("!a.host").is_none());
        assert!(url_host_compare("a.host ===").is_none());
        assert!(url_host_compare("(a).host === x").is_none());
    }

    // ── HostAllowlistValidated ────────────────────────────────────────────

    #[test]
    fn classify_host_allowlist_js_strict_eq() {
        assert_eq!(
            classify_condition("new URL(target).host === ALLOWED_HOST"),
            PredicateKind::HostAllowlistValidated
        );
        assert_eq!(
            classify_condition("new URL(target).hostname === \"trusted.example.com\""),
            PredicateKind::HostAllowlistValidated
        );
        assert_eq!(
            classify_condition("new URL(target).origin === ALLOWED_ORIGIN"),
            PredicateKind::HostAllowlistValidated
        );
    }

    #[test]
    fn classify_host_allowlist_python_urlparse() {
        assert_eq!(
            classify_condition("urlparse(target).netloc == ALLOWED_HOST"),
            PredicateKind::HostAllowlistValidated
        );
        assert_eq!(
            classify_condition("urllib.parse.urlparse(target).hostname == \"trusted.example.com\""),
            PredicateKind::HostAllowlistValidated
        );
    }

    #[test]
    fn target_host_allowlist_extracts_parse_arg_js() {
        let (kind, target) =
            classify_condition_with_target("new URL(target).host === ALLOWED_HOST");
        assert_eq!(kind, PredicateKind::HostAllowlistValidated);
        assert_eq!(target.as_deref(), Some("target"));
    }

    #[test]
    fn target_host_allowlist_extracts_parse_arg_python() {
        let (kind, target) =
            classify_condition_with_target("urlparse(target).netloc == ALLOWED_HOST");
        assert_eq!(kind, PredicateKind::HostAllowlistValidated);
        assert_eq!(target.as_deref(), Some("target"));
    }

    #[test]
    fn host_allowlist_requires_parse_call() {
        // Bare `.host == X` without a parse call is not host-allowlist.
        let kind = classify_condition("u.host == ALLOWED_HOST");
        assert_ne!(kind, PredicateKind::HostAllowlistValidated);
    }

    #[test]
    fn host_allowlist_requires_equality_op() {
        // `new URL(x)` without an equality op is not host-allowlist.
        let kind = classify_condition("new URL(target).host");
        assert_ne!(kind, PredicateKind::HostAllowlistValidated);
    }

    // ── Multi-statement form: Rust `.host_str()` ──────────────────────────

    #[test]
    fn classify_host_allowlist_rust_host_str() {
        assert_eq!(
            classify_condition("parsed.host_str() == Some(\"trusted.example.com\")"),
            PredicateKind::HostAllowlistValidated
        );
    }

    #[test]
    fn target_host_allowlist_rust_host_str_extracts_receiver() {
        let (kind, target) =
            classify_condition_with_target("parsed.host_str() == Some(\"trusted.example.com\")");
        assert_eq!(kind, PredicateKind::HostAllowlistValidated);
        assert_eq!(target.as_deref(), Some("parsed"));
    }

    #[test]
    fn target_host_allowlist_rust_host_str_strips_amp_deref() {
        // `&parsed.host_str()` is not idiomatic but we still pull out the
        // receiver via the trailing-identifier walk.
        let (kind, target) =
            classify_condition_with_target("&parsed.host_str() == Some(\"trusted.com\")");
        assert_eq!(kind, PredicateKind::HostAllowlistValidated);
        assert_eq!(target.as_deref(), Some("parsed"));
    }

    // ── Multi-statement form: Go `.Host` / `.Hostname()` ──────────────────

    #[test]
    fn classify_host_allowlist_go_capital_host() {
        assert_eq!(
            classify_condition("parsed.Host == \"trusted.example.com\""),
            PredicateKind::HostAllowlistValidated
        );
    }

    #[test]
    fn classify_host_allowlist_go_hostname_method() {
        assert_eq!(
            classify_condition("parsed.Hostname() == \"trusted.example.com\""),
            PredicateKind::HostAllowlistValidated
        );
    }

    #[test]
    fn target_host_allowlist_go_extracts_receiver() {
        let (kind, target) =
            classify_condition_with_target("parsed.Host == \"trusted.example.com\"");
        assert_eq!(kind, PredicateKind::HostAllowlistValidated);
        assert_eq!(target.as_deref(), Some("parsed"));
    }

    #[test]
    fn target_host_allowlist_go_hostname_extracts_receiver() {
        let (kind, target) =
            classify_condition_with_target("parsed.Hostname() == \"trusted.example.com\"");
        assert_eq!(kind, PredicateKind::HostAllowlistValidated);
        assert_eq!(target.as_deref(), Some("parsed"));
    }

    #[test]
    fn host_allowlist_rejects_lowercase_host_field() {
        // `.host` (lowercase) without a parse call must NOT match — that
        // shape is too generic (could be any struct field named `host`).
        let kind = classify_condition("u.host == ALLOWED_HOST");
        assert_ne!(kind, PredicateKind::HostAllowlistValidated);
    }

    #[test]
    fn host_allowlist_rejects_capital_host_without_eq() {
        // `parsed.Host` used as a side-effect call argument, not a guard.
        let kind = classify_condition("log(parsed.Host)");
        assert_ne!(kind, PredicateKind::HostAllowlistValidated);
    }

    #[test]
    fn host_allowlist_rejects_capital_host_substring_in_identifier() {
        // `.Hostess` is NOT `.Host` — must not match.
        let kind = classify_condition("party.Hostess == \"alice\"");
        assert_ne!(kind, PredicateKind::HostAllowlistValidated);
    }
}

#[cfg(test)]
mod ghsa_h8cj_hpmg_636v_tests {
    use super::*;
    #[test]
    fn java_pattern_matcher_chain_classifies_as_validation() {
        let kind =
            classify_condition("FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()");
        assert_eq!(
            kind,
            PredicateKind::ValidationCall,
            "matcher().matches() chain on PATTERN-named receiver should be ValidationCall"
        );
    }
    #[test]
    fn java_pattern_matcher_chain_target_is_matcher_arg() {
        let (kind, target) = classify_condition_with_target(
            "FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()",
        );
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("tableName"));
    }
    #[test]
    fn java_negated_pattern_matcher_chain_target_is_matcher_arg() {
        let (kind, target) = classify_condition_with_target(
            "!FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()",
        );
        assert_eq!(kind, PredicateKind::ValidationCall);
        assert_eq!(target.as_deref(), Some("tableName"));
    }
    #[test]
    fn java_pattern_matcher_chain_non_pattern_receiver_is_not_validation() {
        // Precision guard: only fires when receiver name has regex/pattern marker.
        let kind = classify_condition("obj.matcher(x).matches()");
        assert!(
            kind != PredicateKind::ValidationCall,
            "no regex marker should not trigger validation"
        );
    }

    #[test]
    fn negative_polarity_validation_callee_recognised() {
        // CVE-2024-39954: `isInvalidUrl(targetUrl)` classifies as ValidationCall
        // (it contains the substring `valid`) but its truthy branch is the
        // reject path, so polarity must be flipped.
        assert!(is_negative_polarity_validation_callee(
            "isInvalidUrl(targetUrl)"
        ));
        assert!(is_negative_polarity_validation_callee("is_invalid(url)"));
        assert!(is_negative_polarity_validation_callee("isNotValid(x)"));
        assert!(is_negative_polarity_validation_callee(
            "checker.isInvalidHost(h)"
        ));
        assert!(is_negative_polarity_validation_callee("!isInvalidUrl(u)"));
    }

    #[test]
    fn positive_validation_callees_are_not_negative_polarity() {
        // Precision guard: ordinary positive validators must NOT be flipped.
        assert!(!is_negative_polarity_validation_callee(
            "isValidUrl(targetUrl)"
        ));
        assert!(!is_negative_polarity_validation_callee("validate(x)"));
        assert!(!is_negative_polarity_validation_callee("isSafe(x)"));
        assert!(!is_negative_polarity_validation_callee(
            "URL_VALIDATOR.isValid(url)"
        ));
        // No call → not a validation callee at all.
        assert!(!is_negative_polarity_validation_callee("x == null"));
    }

    // ── C path-prefix confinement (uftpd CVE-2020-5221) ──────────────────

    #[test]
    fn strncmp_prefix_check_is_path_prefix_confined() {
        // `strncmp(x, prefix, strlen(prefix))` → PathPrefixConfined, subject x.
        let (kind, target) = classify_condition_with_target("strncmp(rpath, home, strlen(home))");
        assert_eq!(kind, PredicateKind::PathPrefixConfined);
        assert_eq!(target.as_deref(), Some("rpath"));

        // strncasecmp variant + numeric length constant.
        assert_eq!(
            classify_condition("strncasecmp(p, \"/srv\", 4)"),
            PredicateKind::PathPrefixConfined
        );

        // The subject scoping is what distinguishes the uftpd bug from the fix:
        // the bug checks `dir` (an unrelated local) while returning `rpath`.
        let (_, bug_target) = classify_condition_with_target("strncmp(dir, home, strlen(home))");
        assert_eq!(bug_target.as_deref(), Some("dir"));
    }

    #[test]
    fn strncmp_without_prefix_length_is_not_confinement() {
        // A plain byte comparison whose length is not tied to the prefix must
        // NOT be treated as a prefix confinement (would over-suppress).
        assert_ne!(
            classify_condition("strncmp(a, b, n)"),
            PredicateKind::PathPrefixConfined
        );
        // `strlen` of a *different* operand does not anchor the prefix.
        assert_ne!(
            classify_condition("strncmp(a, b, strlen(c))"),
            PredicateKind::PathPrefixConfined
        );
        // A non-identifier subject (member/index expression) is not extracted.
        assert_eq!(
            classify_condition_with_target("strncmp(buf[0], home, strlen(home))").1,
            None
        );
    }

    // ── Runtime type tests: only scalar types validate ───────────────────

    #[test]
    fn type_tests_validate_only_scalar_types() {
        let scalar = [
            "typeof x !== 'number'",
            "'number' === typeof x",
            "typeof flag === \"boolean\"",
            "typeof cb === 'function'",
            "isinstance(x, (int, float))",
            "not isinstance(u, uuid.UUID)",
            "x instanceof Integer",
            "x instanceof java.lang.Long",
            "x.is_a?(Integer)",
            "!x.kind_of?(Numeric)",
            "is_numeric($x)",
            "ctype_digit($x)",
        ];
        for text in scalar {
            assert_eq!(classify_condition(text), PredicateKind::TypeCheck, "{text}");
        }
        let non_scalar = [
            "typeof x !== 'string'",
            "typeof x === 'object'",
            "typeof x === 'number' || typeof x === 'string'",
            "isinstance(x, str)",
            "isinstance(x, (int, str))",
            "x instanceof String",
            "is_string($x)",
            "!is_string($cmd)",
            "x.is_a?(String)",
            "x.kind_of?(Hash)",
        ];
        for text in non_scalar {
            assert_eq!(classify_condition(text), PredicateKind::Unknown, "{text}");
        }
        // `ctype_punct` / `ctype_print` accept metacharacters.
        assert_ne!(
            classify_condition("ctype_punct($x)"),
            PredicateKind::TypeCheck
        );
        assert_ne!(
            classify_condition("ctype_print($x)"),
            PredicateKind::TypeCheck
        );
    }

    // ── Literal-needle tests are not allowlists ──────────────────────────

    #[test]
    fn literal_needle_operator_and_go_forms_are_not_allowlists() {
        for text in [
            "\"..\" in name",
            "'x' in host",
            "\"admin\" not in name",
            "strings.Contains(name, \"..\")",
            "bytes.Contains(body, \"<script\")",
        ] {
            assert_eq!(classify_condition(text), PredicateKind::Unknown, "{text}");
        }
        // Genuine membership keeps its classification.
        assert_eq!(
            classify_condition_with_target("cmd in ALLOWED"),
            (PredicateKind::AllowlistCheck, Some("cmd".to_string()))
        );
        assert_eq!(
            classify_condition_with_target("cmd not in ALLOWED"),
            (PredicateKind::AllowlistCheck, Some("cmd".to_string()))
        );
    }

    // ── Inline anchored regex literal validators ─────────────────────────

    #[test]
    fn anchored_regex_literal_test_is_validation_call() {
        for (text, target) in [
            ("!/^[0-9]+$/.test(id)", "id"),
            ("/^[a-z_]+$/i.test(name)", "name"),
            ("(!/^(ls|pwd)$/.test(cmd))", "cmd"),
            ("/^\\d{1,6}$/.test(n)", "n"),
        ] {
            assert_eq!(
                classify_condition_with_target(text),
                (PredicateKind::ValidationCall, Some(target.to_string())),
                "{text}"
            );
        }
        for text in [
            "/[0-9]/.test(id)",
            "/^[0-9]+/.test(id)",
            "/^.*$/.test(id)",
            "/^[^;]+$/.test(id)",
            "/^\\S+$/.test(id)",
            // `m` anchors per line; a top-level `|` splits the anchors.
            "/^[0-9]+$/m.test(id)",
            "/^[0-9]+|[a-z]+$/.test(id)",
        ] {
            assert_ne!(
                classify_condition(text),
                PredicateKind::ValidationCall,
                "{text}"
            );
        }
    }

    // ── Sentinel comparison polarity ─────────────────────────────────────

    #[test]
    fn equality_literal_guard_table() {
        let some = |v: &str, eq: bool| Some((v.to_string(), eq));
        // (text, expected)
        let cases: &[(&str, Option<(String, bool)>)] = &[
            ("(dir === 'asc')", some("dir", true)),
            ("dir !== 'asc'", some("dir", false)),
            ("order != \"desc\"", some("order", false)),
            ("'asc' == dir", some("dir", true)),
            ("$dir !== 'asc'", some("dir", false)),
            ("$n === 5", some("n", true)),
            ("x == 5", some("x", true)),
            // PHP loose `==` against a number: "1 OR 1=1" == 1 before PHP 8
            ("$n == 5", None),
            ("x.length === 5", None),
            ("x === `${y}`", None),
            ("x == \"#{y}\"", None),
            ("$x == \"a$y\"", None),
            ("x === true", None),
            ("x == null", None),
            ("x === y", None),
            ("!(x === 'a')", None),
            ("x === 'a' || y === 'b'", None),
            ("x >= 5", None),
            ("x is 'a'", None),
            // Constant-index element reads keep their `base[idx]` spelling.
            ("parts[1] != \"asc\"", some("parts[1]", false)),
            ("\"asc\" == parts[10]", some("parts[10]", true)),
            ("parts[i] == \"asc\"", None),
            ("parts[] == \"asc\"", None),
            ("a.b[0] == \"asc\"", None),
        ];
        for (text, want) in cases {
            assert_eq!(&equality_literal_guard(text), want, "{text}");
        }
    }

    #[test]
    fn sentinel_comparison_polarity_table() {
        use SentinelPolarity::*;
        let cases = [
            ("(ALLOWED.includes(cmd) === false)", Flip),
            ("(isValidName(cmd) === false)", Flip),
            ("is_valid_name(name) == False", Flip),
            ("is_valid_name(name) is False", Flip),
            ("is_valid(x) is not True", Flip),
            ("(false === in_array($cmd, $allowed, true))", Flip),
            ("(ALLOWED[cmd] === undefined)", Flip),
            ("(ALLOWED[cmd] !== true)", Flip),
            ("(ALLOWED.indexOf(cmd) === -1)", Flip),
            ("ALLOWED.indexOf(cmd) < 0", Flip),
            ("-1 === ALLOWED.indexOf(cmd)", Flip),
            ("(!isValidName(cmd) === true)", Flip),
            ("!(isValidName(cmd) === false)", Flip),
            ("not is_valid(x) == False", Flip),
            ("ok === false", Flip),
            ("ALLOWED.includes(cmd) !== false", Same),
            ("(ALLOWED[cmd] !== undefined)", Same),
            ("ALLOWED.indexOf(cmd) >= 0", Same),
            ("ALLOWED.indexOf(cmd) > -1", Same),
            ("(!isValidName(cmd) === false)", Same),
            ("isinstance(x, int) == True", Same),
            ("(ALLOWED[cmd] === false)", Opaque),
            ("ALLOWED.indexOf(cmd) === 0", Opaque),
            ("typeof x !== 'string'", NoComparison),
            ("isValid(x === false)", NoComparison),
            ("a && isValid(x) === false", NoComparison),
            ("isValid(x) === false || other", NoComparison),
            ("ALLOWED.includes(cmd)", NoComparison),
            ("strpos($x, '/') === 0", NoComparison),
            ("$obj->isValid() === false", Flip),
            ("count === 0", NoComparison),
            ("x == null", NoComparison),
        ];
        for (text, want) in cases {
            assert_eq!(sentinel_comparison_polarity(text), want, "{text}");
        }
    }
    // ── RedirectValidator / HostDenylistRejected ─────────────────────────

    #[test]
    fn redirect_safety_predicate_is_a_scoped_kind() {
        for (text, arg) in [
            ("safe_for_redirect(redirect_url)", "redirect_url"),
            (
                "redirect_url and safe_for_redirect(redirect_url)",
                "redirect_url",
            ),
            ("next && safeForRedirect(next)", "next"),
            ("not safe_for_redirect(u)", "u"),
        ] {
            let (kind, target) = classify_condition_with_target(text);
            assert_eq!(kind, PredicateKind::RedirectValidator, "{text}");
            assert_eq!(target.as_deref(), Some(arg), "{text}");
        }
        // Names that do not state redirect safety, helpers that return a
        // value, and a predicate that is only one arm of a disjunction.
        for text in [
            "is_valid_email(x)",
            "get_safe_redirect_url(x)",
            "make_safe_url(x)",
            "x or safe_for_redirect(x)",
            "safe_for_redirect(x) || other",
            "safe_for_redirect(a.b)",
            "is_unsafe_redirect(x)",
            "safe_url(x)",
            "url_safe_quote(x)",
        ] {
            assert_ne!(
                classify_condition(text),
                PredicateKind::RedirectValidator,
                "{text}"
            );
        }
    }

    #[test]
    fn host_denylist_predicate_is_a_scoped_kind() {
        for (text, arg) in [
            ("IsHostnameInternal(host)", "host"),
            ("(IsHostnameInternal(host))", "host"),
            ("!IsHostnameInternal(host)", "host"),
            ("is_private_ip(ip)", "ip"),
            ("isInternalURL(u)", "u"),
            ("blocked || IsHostnameInternal(host)", "host"),
            ("utils.IsHostnameInternal(host)", "host"),
        ] {
            let (kind, target) = classify_condition_with_target(text);
            assert_eq!(kind, PredicateKind::HostDenylistRejected, "{text}");
            assert_eq!(target.as_deref(), Some(arg), "{text}");
        }
        for text in [
            "is_local_file(path)",
            "isInternalUser(u)",
            "is_blocked_user(u)",
            "IsHostnameInternal(a, b)",
            "ok && IsHostnameInternal(host)",
            "IsHostnameInternal(host) && ok",
            "isPrivate(x)",
            "IsHostnameInternal(a.b)",
        ] {
            assert_ne!(
                classify_condition(text),
                PredicateKind::HostDenylistRejected,
                "{text}"
            );
        }
    }
}
