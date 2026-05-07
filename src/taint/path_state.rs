#![allow(clippy::collapsible_if)]

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
    /// Inline relative-URL validation: `x.startsWith("/")` / `x.starts_with("/")`
    /// / `x.startswith("/")` / `strpos(x, "/") === 0`.  The TRUE branch
    /// constrains `x` to a relative path (no scheme, no `//host`), which is
    /// the standard inline form of an open-redirect sanitiser when the
    /// developer didn't extract a named helper.  Cap-aware: clears
    /// [`crate::labels::Cap::OPEN_REDIRECT`] only on the validated branch
    /// so non-redirect sinks downstream still fire on the residual taint.
    /// Mirrors [`ShellMetaValidated`](Self::ShellMetaValidated) but with
    /// non-inverted polarity (true branch is the validated path).
    RelativeUrlValidated,
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
    if is_metachar_regex_class(text) {
        return true;
    }
    false
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
    let left = text[..pos].trim();
    // Strip leading `!` / `not` for rejection contexts
    let left = left.strip_prefix('!').unwrap_or(left).trim();
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
fn is_leading_slash_check(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // Method-call form: `.startswith("/")` covers JS/TS/Java (`startsWith`
    // lower-cases to `startswith`), Python (`startswith`), Rust
    // (`starts_with` → `starts_with` after lower).  Keep the variants
    // explicit so we don't miss the underscore form.
    for method in [".startswith(", ".starts_with("] {
        if let Some(idx) = lower.find(method) {
            let args_start = idx + method.len();
            if let Some(needle) = extract_first_string_arg(&lower[args_start..]) {
                if needle == "/" {
                    return true;
                }
            }
        }
    }
    // PHP `strpos($x, "/") === 0` / `mb_strpos($x, "/") === 0` — leading-
    // slash detection via offset-zero substring match.  Both equality
    // forms (`===`, `==`) accepted; the `0` literal is the load-bearing
    // bit.  Conservative: requires the closing `=== 0` form; bare
    // `strpos(...)` (truthy check) is not recognised.
    for prefix in ["strpos(", "mb_strpos("] {
        if let Some(start) = lower.find(prefix) {
            let after = &lower[start + prefix.len()..];
            // Find the closing paren of the strpos call.
            let mut depth = 1usize;
            let bytes = after.as_bytes();
            let mut close = None;
            let mut i = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            let Some(close) = close else { continue };
            let args = &after[..close];
            // Need at least one comma so we have two args.
            let mut depth = 0i32;
            let mut comma = None;
            for (j, ch) in args.char_indices() {
                match ch {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    ',' if depth == 0 => {
                        comma = Some(j);
                        break;
                    }
                    _ => {}
                }
            }
            let Some(comma) = comma else { continue };
            let second = args[comma + 1..].trim();
            // Strip optional surrounding parens / quotes.
            let needle = second.trim_matches(|c: char| c == '"' || c == '\'');
            if needle != "/" {
                continue;
            }
            // Tail after the strpos `)` should compare against 0 with
            // `===` / `==`.  Allow whitespace.
            let tail = after[close + 1..].trim_start();
            if let Some(rest) = tail
                .strip_prefix("===")
                .or_else(|| tail.strip_prefix("=="))
            {
                if rest.trim() == "0" {
                    return true;
                }
            }
        }
    }
    // Direct subscript form: `<X>[0] === '/'` / `<X>[0] == "/"`.
    // Conservative: the literal `[0]` immediately followed by an
    // equality op and a single-char `/` literal.
    for op in ["===", "=="] {
        let probe = format!("[0] {}", op);
        if let Some(idx) = lower.find(&probe) {
            let after = lower[idx + probe.len()..].trim_start();
            if after.starts_with("'/'") || after.starts_with("\"/\"") {
                return true;
            }
        }
        // Without spaces around the operator: `[0]==='/'`.
        let probe_tight = format!("[0]{}", op);
        if let Some(idx) = lower.find(&probe_tight) {
            let after = lower[idx + probe_tight.len()..].trim_start();
            if after.starts_with("'/'") || after.starts_with("\"/\"") {
                return true;
            }
        }
    }
    false
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
/// Conservative: requires both the parse-call AND the `.host`-style accessor
/// AND the equality operator in the same condition text.  Negation prefixes
/// are not stripped, the caller's polarity-inversion machinery handles
/// `!`-wrapped forms uniformly.
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
    if !has_parse_call {
        return false;
    }
    // Need a host-style accessor on the parse result.
    lower.contains(".host") || lower.contains(".hostname") || lower.contains(".netloc") || lower.contains(".origin")
}

/// Extract the parse-call argument from a host-allowlist condition.
///
/// Recognises `new URL(<X>)`, `urlparse(<X>)`, `URL.parse(<X>)`,
/// `urllib.parse.urlparse(<X>)`.  Returns `Some("X")` when the argument is a
/// bare identifier (with optional `&` or PHP `$` sigil stripped); returns
/// `None` for nested expressions / multi-arg calls so branch narrowing
/// doesn't widen to a non-existent var.  Mirrors the conservative target
/// shape used by [`extract_validation_target`].
fn extract_host_allowlist_target(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    for probe in ["new url(", "urllib.parse.urlparse(", "urlparse(", "url.parse("] {
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
    None
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
    // `x.startswith("/")` (Python), `strpos($x, "/") === 0` (PHP).
    // The TRUE branch constrains `x` to a leading-slash relative path —
    // the canonical inline open-redirect sanitiser.  Matched BEFORE
    // AllowlistCheck (which would otherwise capture `.starts_with(`).
    if is_leading_slash_check(text) {
        return PredicateKind::RelativeUrlValidated;
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

    // ── Allowlist / membership checks ────────────────────────────────────
    if lower.contains(".includes(")
        || lower.contains(".include?(")
        || lower.contains(".contains(")
        || lower.contains(".indexof(")
        || lower.contains(".has(")
        || lower.contains("in_array(")
        || lower.contains(" in ")
        || (lower.contains('[') && !lower.contains('('))
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
    if lower.contains("typeof ")
        || lower.contains("isinstance(")
        || lower.contains(" instanceof ")
        || lower.contains(".matches(")
        || lower.contains("is_numeric(")
        || lower.contains("is_int(")
        || lower.contains("is_string(")
        || lower.contains("is_float(")
        || lower.contains("ctype_")
        || lower.contains(".is_a?(")
        || lower.contains(".kind_of?(")
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
            if let Some(target) = extract_validation_target(text) {
                (kind, Some(target))
            } else if count_call_args(text).map(|n| n > 1).unwrap_or(false) {
                (PredicateKind::Unknown, None)
            } else {
                (kind, None)
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
        PredicateKind::RelativeUrlValidated => {
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
        PredicateKind::Comparison => {
            // `x === '/login'`, `x == 5`, `null != obj`, when exactly one
            // side is a literal, extract the identifier side as the target.
            // Downstream `apply_branch_predicates` uses this to mark the
            // variable as `validated_may` on the true (equal) branch.
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
/// - `obj.field == 3` → `None` (not a bare identifier)
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

    // Numeric literal: optional sign + digits, optional decimal point.
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    let rest_start = if first == '-' || first == '+' {
        match chars.next() {
            Some(c) => c,
            None => return false,
        }
    } else {
        first
    };
    if !rest_start.is_ascii_digit() {
        return false;
    }
    s.chars()
        .skip(if first == '-' || first == '+' { 1 } else { 0 })
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
    let bytes = args_part.as_bytes();
    let mut depth: usize = 1;
    let mut end: Option<usize> = None;
    let mut first_comma: Option<usize> = None;
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
            b',' if depth == 1 && first_comma.is_none() => first_comma = Some(i),
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
    let cut = first_comma.unwrap_or(end);
    Some(args_part[..cut].trim())
}

/// Extract the validated variable from a condition text.
///
/// Handles two patterns:
/// - Function call: `validate(x, ...)` → `"x"`
/// - Method call: `x.validate(...)` → `"x"`
fn extract_validation_target(text: &str) -> Option<String> {
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
            if let Some(first_arg) = first_call_arg(args_part) {
                let first_arg = first_arg.strip_prefix('$').unwrap_or(first_arg);
                if !first_arg.is_empty() && is_identifier(first_arg) {
                    return Some(first_arg.to_string());
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

    // Python `in` operator: `cmd in ALLOWED` / `cmd not in ALLOWED`
    if lower.contains(" in ") {
        // Find the leftmost ` in `, everything before it is the target expression
        // Handle `not in` by looking for ` not in ` first
        let target_part = if let Some(pos) = lower.find(" not in ") {
            &trimmed[..pos]
        } else if let Some(pos) = lower.find(" in ") {
            &trimmed[..pos]
        } else {
            return None;
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

/// Check if a string is a simple identifier (letters, digits, underscores, dots).
fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && !s.starts_with(|c: char| c.is_ascii_digit())
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
            classify_condition("x instanceof String"),
            PredicateKind::TypeCheck
        );
    }

    #[test]
    fn target_instanceof_x_string() {
        let (kind, target) = classify_condition_with_target("x instanceof String");
        assert_eq!(kind, PredicateKind::TypeCheck);
        assert_eq!(target.as_deref(), Some("x"));
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
    fn classify_non_metachar_contains_stays_allowlist() {
        // `x.contains("foo")` must NOT be credited as a shell-metachar
        // rejection.  It falls back to the existing AllowlistCheck behavior.
        assert_eq!(
            classify_condition("input.contains(\"foo\")"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("path.contains(\"..\")"),
            PredicateKind::AllowlistCheck
        );
        assert_eq!(
            classify_condition("name.contains(\"admin\")"),
            PredicateKind::AllowlistCheck
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
}
