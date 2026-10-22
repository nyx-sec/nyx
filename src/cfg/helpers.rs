use super::anon_fn_name;
use super::conditions::unwrap_parens;
use crate::labels::{DataLabel, Kind, classify, lookup};
use smallvec::SmallVec;
use std::cell::Cell;
use tree_sitter::Node;

//                      Utility helpers

// ── Pre-validated source fast path ──────────────────────────────────────────
//
// Node text extraction (`text_of` + the handful of `from_utf8(&code[range])`
// sites) is one of the hottest CFG-build primitives — `core::str::from_utf8`
// (i.e. `run_utf8_validation`) was ~1.6% of active CPU on mattermost/server/
// channels/app (samply, 2026-07-14), driven by re-validating a fresh byte range
// on *every* one of the millions of `text_of` calls. Each call re-scans its
// node's bytes for UTF-8 validity even though the enclosing source file was
// already whole-file valid UTF-8.
//
// Fix (algorithmic, `O(range_len)` → `O(1)` per call): validate the whole file
// **once** when it is parsed ([`ValidSourceGuard::new`] in `ParsedSource::
// try_new`) and record its byte span in a thread-local. Any later `slice_str`
// on that exact slice then reinterprets the already-validated bytes as `&str`
// for free and takes an `O(1)` char-boundary slice (`str::get`) instead of an
// `O(range_len)` validation scan. Bit-identical: `str::get` returns `None` for
// a non-char-boundary / out-of-range slice exactly where `from_utf8` returns
// `Err` today, and yields identical `&str` content otherwise. Files that are
// not whole-file valid UTF-8 register nothing → every `slice_str` on them falls
// back to the original checked `from_utf8`, so behaviour is unchanged there too.

thread_local! {
    /// Byte span (`ptr`, `len`) of the source file currently being analysed on
    /// this thread, recorded **only** when the file validated as whole-file
    /// UTF-8. `None` when no validated source is active (or the active file is
    /// not valid UTF-8). A live [`ValidSourceGuard`] keeps the referenced bytes
    /// alive for as long as the entry is set.
    static VALID_SOURCE: Cell<Option<(*const u8, usize)>> = const { Cell::new(None) };
}

/// Escape hatch / benchmark A-B toggle: `NYX_DISABLE_SRC_STR_CACHE=1` forces
/// every [`slice_str`] onto the checked `from_utf8` fallback, so the pre-
/// validated fast path can be measured against the baseline in a single binary.
fn src_str_cache_disabled() -> bool {
    use std::sync::OnceLock;
    static DISABLED: OnceLock<bool> = OnceLock::new();
    *DISABLED.get_or_init(|| std::env::var("NYX_DISABLE_SRC_STR_CACHE").is_ok())
}

/// RAII guard registering `bytes` as this thread's validated source for the
/// guard's lifetime. Validates the whole file once (the single `O(file_len)`
/// scan that replaces the per-node scans) and, if valid, records its span in
/// [`VALID_SOURCE`]. The previous registration is saved and restored on drop so
/// nested parses (a parse-within-parse on one thread) compose correctly. Stored
/// inside `ParsedSource`, so the registered span stays alive exactly as long as
/// the borrowed file bytes it points at, and is cleared before those bytes can
/// be freed.
pub(crate) struct ValidSourceGuard {
    prev: Option<(*const u8, usize)>,
}

impl ValidSourceGuard {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let entry = if std::str::from_utf8(bytes).is_ok() {
            Some((bytes.as_ptr(), bytes.len()))
        } else {
            None
        };
        let prev = VALID_SOURCE.with(|c| c.replace(entry));
        ValidSourceGuard { prev }
    }
}

impl Drop for ValidSourceGuard {
    fn drop(&mut self) {
        VALID_SOURCE.with(|c| c.set(self.prev));
    }
}

/// Decode `code[start..end]` as `&str`.
///
/// When `code` is exactly the file registered by a live [`ValidSourceGuard`],
/// this reinterprets the pre-validated bytes as `&str` for free and takes an
/// `O(1)` char-boundary slice; otherwise it falls back to the original checked
/// `O(range_len)` `from_utf8`. Both paths return `None` for an out-of-range or
/// non-char-boundary slice, so the result is bit-identical.
#[inline]
pub(crate) fn slice_str(code: &[u8], start: usize, end: usize) -> Option<&str> {
    if !src_str_cache_disabled()
        && VALID_SOURCE.with(|c| c.get()) == Some((code.as_ptr(), code.len()))
    {
        // SAFETY: the active `ValidSourceGuard` validated this exact live slice
        // (same ptr + len) as whole-file UTF-8, so viewing it as `&str` is
        // sound. `str::get` still bounds- and char-boundary-checks the range in
        // O(1) instead of the O(range_len) `from_utf8` validation scan.
        let s = unsafe { std::str::from_utf8_unchecked(code) };
        match s.get(start..end) {
            Some(sub) => Some(sub),
            // `str::get` diverges from the checked `from_utf8(&bytes[start..end])`
            // path only for an empty range landing mid-codepoint: `get` -> None,
            // but `from_utf8(b"")` -> Some(""). Node byte ranges are always
            // codepoint boundaries so this never arises for real callers, but
            // mirror the checked result to stay bit-identical for any range.
            None if start == end && end <= code.len() => Some(""),
            None => None,
        }
    } else {
        code.get(start..end)
            .and_then(|b| std::str::from_utf8(b).ok())
    }
}

/// Return the text of a node.
#[inline]
pub(crate) fn text_of<'a>(n: Node<'a>, code: &'a [u8]) -> Option<String> {
    slice_str(code, n.start_byte(), n.end_byte()).map(|s| s.to_string())
}

/// Borrowed sibling of [`text_of`]: return `code[n.start_byte()..n.end_byte()]`
/// as `&str` **without allocating**, via the pre-validated-source fast path.
///
/// Bit-identical to `n.utf8_text(code).ok()` and to
/// `std::str::from_utf8(&code[n.byte_range()]).ok()` — the same byte range, the
/// same `Some`/`None` verdict (`None` only when that range is not valid UTF-8,
/// which under a live [`ValidSourceGuard`] can only happen in a non-UTF-8 file
/// where the guard registers nothing and this falls back to checked `from_utf8`
/// anyway). Prefer this over `Node::utf8_text` / `from_utf8(&code[range])` on
/// the per-file scan path so the `O(range_len)` UTF-8 re-validation collapses to
/// an `O(1)` `str::get` once the file is registered by the guard.
#[inline]
pub(crate) fn node_str<'c>(n: Node<'_>, code: &'c [u8]) -> Option<&'c str> {
    // The result borrows `code` only (the byte offsets are plain `usize`), so the
    // node's tree lifetime is intentionally independent of the returned `&str` —
    // mirroring the old `from_utf8(&code[n.byte_range()])` borrow shape.
    slice_str(code, n.start_byte(), n.end_byte())
}

/// Walk through chained calls / member accesses to find the root receiver.
///
/// For `Runtime.getRuntime().exec(cmd)`, the receiver of `exec` is the call
/// `Runtime.getRuntime()`.  This function drills through that to return
/// `"Runtime"`, the outermost non-call object.  This lets labels like
/// `"Runtime.exec"` match correctly.
pub(crate) fn root_receiver_text(n: Node, lang: &str, code: &[u8]) -> Option<String> {
    match lookup(lang, n.kind()) {
        // The receiver is itself a call, drill into ITS receiver.
        // e.g. for `Runtime.getRuntime()`, the object is `Runtime`.
        Kind::CallFn | Kind::CallMethod => {
            let inner = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("receiver"))
                .or_else(|| n.child_by_field_name("function"));
            match inner {
                Some(child) => root_receiver_text(child, lang, code),
                None => text_of(n, code),
            }
        }
        // PHP `variable_name` text carries a leading `$` (`$smarty`, `$twig`).
        // Strip it so chain text built downstream (`{recv}.{method}`) presents
        // a `.`-only delimiter sequence — required by the suffix-matcher
        // boundary rule, which only accepts `.`/`:` as chain separators.
        // Without this strip, gate matchers like `Smarty.fetch` /
        // `Environment.createTemplate` never fire on idiomatic
        // `$smarty->fetch(...)` / `$twig->createTemplate(...)` shapes.
        _ if lang == "php" && n.kind() == "variable_name" => {
            text_of(n, code).map(|s| s.trim_start_matches('$').to_string())
        }
        _ => text_of(n, code),
    }
}

/// Walk a member-expression / attribute chain down to its root identifier.
///
/// Unlike [`root_receiver_text`], which returns the raw text of a nested
/// attribute (yielding `"request.args.get"` for the attribute node covering
/// `request.args.get`), this drills through `object`/`value` fields until it
/// hits a terminal identifier and returns just that leaf.
///
/// Used when JS/Python `obj.method(x)` is classified as `Kind::CallFn` with a
/// dotted function child: we want the leftmost segment (`request` in
/// `request.args.get("q")`) as the structured receiver for type-qualified
/// resolution.  Returns `None` when the chain does not resolve to a plain
/// identifier (e.g. call expressions, subscripts, `this`/`self`, etc.).
pub(crate) fn root_member_receiver(n: Node, code: &[u8]) -> Option<String> {
    let mut cur = n;
    // Bounded walk, tree-sitter can nest deeply but we only need a handful
    // of hops for real code.
    for _ in 0..16 {
        match cur.kind() {
            "identifier" | "variable_name" | "this" | "self" => {
                return text_of(cur, code);
            }
            "member_expression" | "attribute" => {
                cur = cur.child_by_field_name("object")?;
            }
            // Rust `x.y` is `field_expression` with a `value` field.
            "field_expression" => {
                cur = cur.child_by_field_name("value")?;
            }
            // Drill through nested calls / method chains to find the base
            // identifier.  E.g. `Connection::open(p).unwrap().execute(...)` ,
            // the receiver of `.execute` is the `.unwrap()` call whose
            // object is `Connection::open(p)`; we want the leftmost plain
            // identifier the chain resolves to (for SSA var_stacks lookup).
            "call_expression" => {
                cur = cur.child_by_field_name("function")?;
            }
            "method_call_expression" => {
                cur = cur
                    .child_by_field_name("object")
                    .or_else(|| cur.child_by_field_name("receiver"))?;
            }
            _ => return None,
        }
    }
    None
}

/// Callee text for a call's `function` node.  For JS/TS this applies
/// [`js_canonical_callee`] first; every other case is the node's source
/// text.
pub(crate) fn call_fn_callee_text(func: Node, lang: &str, code: &[u8]) -> Option<String> {
    if matches!(lang, "javascript" | "typescript" | "tsx")
        && let Some(canonical) = js_canonical_callee(func, code)
    {
        return Some(canonical);
    }
    text_of(func, code)
}

/// Canonical callee text for a JS/TS member call whose raw source text hides
/// the API being called from the label rules: `require('child_process').exec`
/// becomes `child_process.exec` (and `require('node:fs').readFileSync` becomes
/// `fs.readFileSync`).  Only bare identifier-shaped module names are
/// rewritten, never relative paths.  `None` when the shape does not apply.
pub(crate) fn js_canonical_callee(func: Node, code: &[u8]) -> Option<String> {
    let func = unwrap_parens(func);
    if func.kind() != "member_expression" {
        return None;
    }
    let property = func.child_by_field_name("property")?;
    if property.kind() != "property_identifier" {
        return None;
    }
    let method = text_of(property, code)?;
    let object = unwrap_parens(func.child_by_field_name("object")?);
    if object.kind() != "call_expression" {
        return None;
    }
    js_required_module_name(object, code).map(|module| format!("{module}.{method}"))
}

/// Module name of a `require('<name>')` call, with any `node:` scheme
/// stripped.  `None` unless the single argument is a string literal naming
/// a bare identifier-shaped module (`child_process`, `fs`, `vm`).
fn js_required_module_name(call: Node, code: &[u8]) -> Option<String> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "identifier" || text_of(callee, code).as_deref() != Some("require") {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut named = args.named_children(&mut cursor);
    let arg = named.next()?;
    if named.next().is_some() || arg.kind() != "string" {
        return None;
    }
    let raw = text_of(arg, code)?;
    let spec = raw.trim_matches(|c| c == '\'' || c == '"');
    let name = spec.strip_prefix("node:").unwrap_or(spec);
    let mut chars = name.chars();
    let first = chars.next()?;
    if (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Some(name.to_string())
    } else {
        None
    }
}

/// Check if a callee represents an RAII-managed factory whose resources are
/// automatically cleaned up by language semantics (Rust ownership/Drop, C++
/// smart pointers).  Returns `true` to set `managed_resource` on the acquire
/// node, suppressing false `state-resource-leak` findings.
pub(crate) fn is_raii_factory(lang: &str, callee: &str) -> bool {
    fn matches_any(callee: &str, patterns: &[&str]) -> bool {
        let cl = callee.to_ascii_lowercase();
        // Strip C++ template arguments: make_unique<int> → make_unique
        let base = cl.split('<').next().unwrap_or(&cl);
        patterns.iter().any(|p| base == *p || base.ends_with(p))
    }

    match lang {
        "cpp" => {
            static CPP_RAII_FACTORIES: &[&str] = &[
                "make_unique",
                "make_shared",
                "std::make_unique",
                "std::make_shared",
            ];
            matches_any(callee, CPP_RAII_FACTORIES)
        }
        "rust" => {
            static RUST_RAII_CONSTRUCTORS: &[&str] = &[
                "file::open",
                "file::create",
                "box::new",
                "bufwriter::new",
                "bufreader::new",
                "tcplistener::bind",
                "tcpstream::connect",
                "udpsocket::bind",
                "mutex::new",
                "rwlock::new",
                "fs::file::open",
                "fs::file::create",
                "std::fs::file::open",
                "std::fs::file::create",
            ];
            matches_any(callee, RUST_RAII_CONSTRUCTORS)
        }
        _ => false,
    }
}

/// Fallback for constructor expressions whose grammar lacks field names.
/// For example, PHP `object_creation_expression` has positional children
/// `new name arguments` where `name` is a node kind (not a field).
/// Returns the first child whose kind is `"name"` or `"type_identifier"`.
pub(crate) fn find_constructor_type_child(n: Node) -> Option<Node> {
    let mut cursor = n.walk();
    n.children(&mut cursor)
        .find(|c| matches!(c.kind(), "name" | "type_identifier" | "qualified_name"))
}

/// Return the callee identifier and byte span for the first call / method /
/// macro inside `n`.  Searches recursively through all descendants.
///
/// The span is the byte range of the call expression itself, so a caller that
/// overrides `text` with the returned identifier can also record a
/// `callee_span` pointing at the inner call (narrower than the enclosing
/// statement) for accurate source-location reporting.
pub(crate) fn first_call_ident_with_span<'a>(
    n: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Option<(String, (usize, usize))> {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
                let span = (c.start_byte(), c.end_byte());
                // C++ new/delete: normalize callee before returning.
                if lang == "cpp" && c.kind() == "new_expression" {
                    return Some(("new".to_string(), span));
                }
                if lang == "cpp" && c.kind() == "delete_expression" {
                    return Some(("delete".to_string(), span));
                }
                // Ruby backtick subshell: no `function` field, normalise to
                // the synthetic callee so assignment-wrapped subshells classify.
                if lang == "ruby" && c.kind() == "subshell" {
                    return Some(("subshell".to_string(), span));
                }
                let ident = match lookup(lang, c.kind()) {
                    Kind::CallFn => c
                        .child_by_field_name("function")
                        .or_else(|| c.child_by_field_name("method"))
                        .or_else(|| c.child_by_field_name("name"))
                        .or_else(|| c.child_by_field_name("type"))
                        .or_else(|| c.child_by_field_name("constructor"))
                        // Fallback for constructors whose grammar lacks field names
                        // (e.g. PHP `object_creation_expression` has positional children).
                        .or_else(|| find_constructor_type_child(c))
                        .and_then(|f| {
                            let unwrapped = unwrap_parens(f);
                            if lookup(lang, unwrapped.kind()) == Kind::Function {
                                Some(anon_fn_name(unwrapped.start_byte()))
                            } else {
                                call_fn_callee_text(f, lang, code)
                            }
                        }),
                    Kind::CallMethod => {
                        let func = c
                            .child_by_field_name("method")
                            .or_else(|| c.child_by_field_name("name"))
                            .and_then(|f| text_of(f, code));
                        let recv = c
                            .child_by_field_name("object")
                            .or_else(|| c.child_by_field_name("receiver"))
                            .or_else(|| c.child_by_field_name("scope"))
                            .and_then(|f| root_receiver_text(f, lang, code));
                        match (recv, func) {
                            (Some(r), Some(f)) => Some(format!("{r}.{f}")),
                            (_, Some(f)) => Some(f),
                            _ => None,
                        }
                    }
                    Kind::CallMacro => c
                        .child_by_field_name("macro")
                        .and_then(|f| text_of(f, code)),
                    _ => None,
                };
                return ident.map(|s| (s, span));
            }
            Kind::Function => {
                // Do not descend into nested function/lambda bodies ,
                // they are separate scopes and should not contribute
                // callee identifiers to the parent expression.
                continue;
            }
            _ => {
                // Recurse into children (handles nested declarators)
                if let Some(found) = first_call_ident_with_span(c, lang, code) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Convenience wrapper around [`first_call_ident_with_span`] that discards
/// the byte-span when only the callee identifier is needed (e.g. for
/// Python-side label lookup that does not participate in span-narrowed
/// location reporting).
pub(crate) fn first_call_ident<'a>(n: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    first_call_ident_with_span(n, lang, code).map(|(s, _)| s)
}

/// Search recursively for any nested call whose identifier classifies as a label.
/// Used for cases like `str(eval(expr))` where `str` doesn't match but `eval` does.
///
/// Returns `(callee_text, label, span)` where `span` is the byte range of the
/// inner call node itself, used to populate `CallMeta.callee_span` so that
/// display sites can report the actual call location rather than the enclosing
/// statement's span.
pub(crate) fn find_classifiable_inner_call<'a>(
    n: Node<'a>,
    lang: &str,
    code: &'a [u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<(String, DataLabel, Node<'a>)> {
    find_inner_call_impl(n, lang, code, extra, false)
}

/// Like [`find_classifiable_inner_call`], but ONLY returns a nested call that
/// classifies as a `Sink`, recursing PAST nested calls that classify as a
/// Source / Sanitizer.  Used when the outer call already carries a non-Sink
/// label (Sanitizer / Source) and a dangerous inner sink would otherwise be
/// shadowed — e.g. `JSON.parse(await fsp.readFile(tainted))` (the FILE_IO
/// path-traversal sink hidden under the `JSON.parse` sanitizer in vite
/// CVE-2026-39365).  An outer sanitizer neutralises the *result* it returns,
/// never the inner sink's path / query / command argument, so the inner sink
/// must still be surfaced.
pub(crate) fn find_inner_sink_call<'a>(
    n: Node<'a>,
    lang: &str,
    code: &'a [u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<(String, DataLabel, Node<'a>)> {
    find_inner_call_impl(n, lang, code, extra, true)
}

/// Shared walker for [`find_classifiable_inner_call`] /
/// [`find_inner_sink_call`].  When `require_sink` is set, a non-`Sink`
/// classification does not terminate the search: the walk continues into the
/// call's arguments so a deeper sink is still found.
fn find_inner_call_impl<'a>(
    n: Node<'a>,
    lang: &str,
    code: &'a [u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
    require_sink: bool,
) -> Option<(String, DataLabel, Node<'a>)> {
    let accept = |lbl: &DataLabel| !require_sink || matches!(lbl, DataLabel::Sink(_));
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        // Do not descend into Kind::Function nodes, they will be extracted
        // as separate BodyCfg entries and should not contribute inner callees
        // to the parent expression.
        if lookup(lang, c.kind()) == Kind::Function {
            continue;
        }
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => {
                // For CallMethod we also remember the bare receiver
                // identifier so we can try a type-qualified rewrite
                // when the literal classify misses.
                let mut method_receiver: Option<String> = None;
                let mut method_name: Option<String> = None;
                let ident = match lookup(lang, c.kind()) {
                    Kind::CallFn => c
                        .child_by_field_name("function")
                        .or_else(|| c.child_by_field_name("method"))
                        .or_else(|| c.child_by_field_name("name"))
                        .or_else(|| c.child_by_field_name("type"))
                        .and_then(|f| call_fn_callee_text(f, lang, code)),
                    Kind::CallMethod => {
                        let func = c
                            .child_by_field_name("method")
                            .or_else(|| c.child_by_field_name("name"))
                            .and_then(|f| text_of(f, code));
                        let recv = c
                            .child_by_field_name("object")
                            .or_else(|| c.child_by_field_name("receiver"))
                            .or_else(|| c.child_by_field_name("scope"))
                            .and_then(|f| root_receiver_text(f, lang, code));
                        method_receiver = recv.clone();
                        method_name = func.clone();
                        match (recv, func) {
                            (Some(r), Some(f)) => Some(format!("{r}.{f}")),
                            (_, Some(f)) => Some(f),
                            _ => None,
                        }
                    }
                    Kind::CallMacro => c
                        .child_by_field_name("macro")
                        .and_then(|f| text_of(f, code)),
                    _ => None,
                };
                if let Some(ref id) = ident
                    && let Some(lbl) = classify(lang, id, extra)
                    && accept(&lbl)
                {
                    return Some((id.clone(), lbl, c));
                }
                // Receiver-type rewrite fallback: when the literal
                // `recv.method` text didn't classify, AND we're inside
                // a chained call (parent `n` is itself a call), look
                // up `recv`'s locally-bound type and retry with the
                // type prefix.  E.g. for
                // `sess.createNativeQuery(sql).getResultList()`, the
                // inner `sess.createNativeQuery` rewrites to
                // `HibernateSession.createNativeQuery` (rule fires).
                //
                // Gated on `n` being a Call-kind so the rewrite only
                // fires on chain-hop inner calls.  When `n` is an
                // expression-statement / variable-declarator / etc.
                // the candidate `c` IS the outermost call of the
                // statement, and the SSA-time
                // `resolve_type_qualified_labels` path handles it
                // with multi-label semantics that single-label
                // `classify` here would erase.
                let parent_is_call = matches!(
                    lookup(lang, n.kind()),
                    Kind::CallFn | Kind::CallMethod | Kind::CallMacro
                );
                if parent_is_call
                    && let (Some(recv), Some(method)) = (method_receiver, method_name)
                    && let Some(prefix) = crate::cfg::local_receiver_type_prefix(c, &recv, lang)
                {
                    let alt = format!("{prefix}.{method}");
                    if let Some(lbl) = classify(lang, &alt, extra)
                        && accept(&lbl)
                    {
                        return Some((alt, lbl, c));
                    }
                }
                // Recurse into arguments of this call
                if let Some(found) = find_inner_call_impl(c, lang, code, extra, require_sink) {
                    return Some(found);
                }
            }
            _ => {
                if let Some(found) = find_inner_call_impl(c, lang, code, extra, require_sink) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Walk `n`'s descendants for a nested call whose callee classifies — via the
/// *import-gated* registry with `ctx` (so the `fs/promises` import alias is
/// resolved) — as a `Sink`, recursing past calls that do not.  Mirror of
/// [`find_inner_sink_call`] for the gated post-pass: the CFG-time `classify`
/// in `push_node` cannot see the per-file import view, so an import-gated sink
/// (`fsp.readFile`) shadowed under a non-sink outer call
/// (`JSON.parse(await fsp.readFile(tainted))`, vite CVE-2026-39365) is invisible
/// until the import view is built.  Returns `(callee_text, match, span)`,
/// where the match carries the rule's sink label and payload positions.
pub(crate) fn find_inner_gated_sink_call<'a>(
    n: Node<'a>,
    lang: &str,
    code: &'a [u8],
    ctx: &crate::labels::ClassificationContext<'_>,
) -> Option<(String, crate::labels::GatedLabelMatch, (usize, usize))> {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        if lookup(lang, c.kind()) == Kind::Function {
            continue;
        }
        if matches!(
            lookup(lang, c.kind()),
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro
        ) {
            let ident = match lookup(lang, c.kind()) {
                Kind::CallMethod => {
                    let func = c
                        .child_by_field_name("method")
                        .or_else(|| c.child_by_field_name("name"))
                        .and_then(|f| text_of(f, code));
                    let recv = c
                        .child_by_field_name("object")
                        .or_else(|| c.child_by_field_name("receiver"))
                        .or_else(|| c.child_by_field_name("scope"))
                        .and_then(|f| root_receiver_text(f, lang, code));
                    match (recv, func) {
                        (Some(r), Some(f)) => Some(format!("{r}.{f}")),
                        (_, Some(f)) => Some(f),
                        _ => None,
                    }
                }
                _ => c
                    .child_by_field_name("function")
                    .or_else(|| c.child_by_field_name("method"))
                    .or_else(|| c.child_by_field_name("name"))
                    .and_then(|f| call_fn_callee_text(f, lang, code)),
            };
            if let Some(id) = ident {
                if let Some(m) = crate::labels::classify_gated_matches(lang, &id, Some(ctx))
                    .iter()
                    .find(|m| matches!(m.label, DataLabel::Sink(_)))
                    .copied()
                {
                    return Some((id, m, (c.start_byte(), c.end_byte())));
                }
            }
        }
        if let Some(found) = find_inner_gated_sink_call(c, lang, code, ctx) {
            return Some(found);
        }
    }
    None
}

/// Build the dot-joined text of a member_expression / attribute / selector_expression.
/// E.g. for `process.env.CMD` this returns `"process.env.CMD"`.
/// Field paths are capped at 3 segments (2 dots) to bound state size.
pub(crate) fn member_expr_text(n: Node, code: &[u8]) -> Option<String> {
    let path = member_expr_text_inner(n, code)?;
    // Depth limit: keep at most 3 segments (2 dots)
    let mut dots = 0;
    for (i, c) in path.char_indices() {
        if c == '.' {
            dots += 1;
        }
        if dots >= 3 {
            return Some(path[..i].to_string());
        }
    }
    Some(path)
}

pub(crate) fn member_expr_text_inner(n: Node, code: &[u8]) -> Option<String> {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" => {
            // Tree-sitter exposes the receiver under `object` (JS/TS, Python),
            // `value` (Rust field_expression, handled in the matching arm
            // above), or `operand` (Go selector_expression).  Without the
            // `operand` fallback, Go member access like `r.Body` collapsed to
            // just the trailing field (`Body`), so source rules keyed on the
            // dotted form (e.g. Go's `r.Body`) would never match.
            let obj = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("value"))
                .or_else(|| n.child_by_field_name("operand"))
                .and_then(|o| member_expr_text_inner(o, code))
                .or_else(|| {
                    n.child_by_field_name("object")
                        .or_else(|| n.child_by_field_name("value"))
                        .or_else(|| n.child_by_field_name("operand"))
                        .and_then(|o| text_of(o, code))
                });
            let prop = n
                .child_by_field_name("property")
                .or_else(|| n.child_by_field_name("attribute"))
                .or_else(|| n.child_by_field_name("field"))
                .and_then(|p| text_of(p, code));
            match (obj, prop) {
                (Some(o), Some(p)) => Some(format!("{o}.{p}")),
                (_, Some(p)) => Some(p),
                (Some(o), _) => Some(o),
                _ => text_of(n, code),
            }
        }
        _ => text_of(n, code),
    }
}

/// Recursively search `n` for a member expression whose text classifies as a label.
pub(crate) fn first_member_label(
    n: Node,
    lang: &str,
    code: &[u8],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<DataLabel> {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" => {
            if let Some(full) = member_expr_text(n, code) {
                // Try the full text first, then progressively strip the last segment
                // to match rules like "process.env" from "process.env.CMD".
                //
                // The strip-and-retry only ever yields a sound label for Sources:
                // `process.env.CMD` → strip → `process.env` makes sense because
                // the receiver itself IS the source.  Sinks and Sanitizers, by
                // contrast, name the *operation* — `connection.query`, `eval`,
                // `exec` — and stripping a trailing segment to match them is
                // not semantically valid (e.g. `exec.start` should never be
                // treated as a SHELL_ESCAPE sink because of bare `exec`).  We
                // accept any label on a full-text match (the behaviour callers
                // already depend on for Source/Sink labels alike), but only
                // accept Source labels after segment stripping.
                let mut candidate = full.as_str();
                let mut first = true;
                loop {
                    if let Some(lbl) = classify(lang, candidate, extra_labels) {
                        if first || matches!(lbl, DataLabel::Source(_)) {
                            return Some(lbl);
                        }
                    }
                    first = false;
                    match candidate.rsplit_once('.') {
                        Some((prefix, _)) => candidate = prefix,
                        None => break,
                    }
                }
            }
        }
        // PHP/Python/Ruby subscript access: `$_GET['cmd']`, `os.environ['KEY']`, `params[:cmd]`
        // Try to classify the object (before the `[`) as a source.
        //
        // Source-only on the receiver: a subscript reads a value from the
        // receiver, so a Sink label found on the receiver text (e.g.
        // `response.headers['content-type']`, where `response.headers`
        // matches the JS HEADER_INJECTION sink rule) describes the
        // *target* of a hypothetical write, not this read.  Promoting it
        // would fire phantom sinks at every `body =
        // response.headers["X"]`-shape line.  Sinks/Sanitizers reachable
        // via callable positions (function-arg, method-receiver) still
        // flow through the outer recursive walk below.
        "subscript_expression" | "subscript" | "element_reference" => {
            if let Some(obj) = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("value"))
                .or_else(|| n.child(0))
            {
                if let Some(txt) = text_of(obj, code)
                    && let Some(lbl @ DataLabel::Source(_)) = classify(lang, &txt, extra_labels)
                {
                    return Some(lbl);
                }
                // Recurse into the object for nested member accesses, but
                // keep the same Source-only restriction as above by passing
                // through the dedicated source-only walker.
                if let Some(lbl @ DataLabel::Source(_)) =
                    first_member_label(obj, lang, code, extra_labels)
                {
                    return Some(lbl);
                }
            }
            // Suppress further descent into this subscript node, the outer
            // child-walk loop would otherwise enter the receiver via the
            // member_expression arm and reattach a value-extraction Sink.
            return None;
        }
        _ => {}
    }
    let mut cursor = n.walk();
    for child in n.children(&mut cursor) {
        if let Some(lbl) = first_member_label(child, lang, code, extra_labels) {
            return Some(lbl);
        }
    }
    None
}

/// Locate the inner sink CALL node whose `Sink` label [`first_member_label`]
/// hoisted onto an outer wrapper node from inside a callback-argument function
/// literal.
///
/// This is the dual of [`first_member_label`] for the callback-descent case:
/// where `first_member_label` returns only the `DataLabel`, this returns the
/// enclosing `call_expression` so its own payload-arg positions + argument
/// string literals can be recorded as [`super::HoistedSink`] provenance on the
/// wrapper.  Motivated by the outline Sequelize-migration idiom
/// `queryInterface.sequelize.transaction(async (t) => {
/// queryInterface.sequelize.query(`…const DDL…`, { transaction: t }) })`, whose
/// `.transaction` wrapper inherits the inner `sequelize.query` `Sink` and then
/// fires a phantom `cfg-unguarded-sink` because the wrapper's own argument is
/// the callback, not the constant SQL.
///
/// Descent only reports a sink call that lives **inside** a function-literal
/// boundary (`Kind::Function`): a sink found in `n`'s own non-callback subtree
/// returns `None`, so the ordinary member-source-on-wrapper hoist is
/// unaffected.  Returns the FIRST such inner sink call in source order, so the
/// provenance matches the first `Sink` label `first_member_label` would return.
pub(crate) fn first_callback_sink_call<'a>(
    n: Node<'a>,
    lang: &str,
    code: &[u8],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<Node<'a>> {
    fn walk<'a>(
        n: Node<'a>,
        lang: &str,
        code: &[u8],
        extra: Option<&[crate::labels::RuntimeLabelRule]>,
        inside_fn: bool,
    ) -> Option<Node<'a>> {
        // Once inside a callback body, a call whose callee (function-field
        // member expression) classifies as a `Sink` is the hoisted inner sink.
        if inside_fn
            && let Some(callee) = n
                .child_by_field_name("function")
                .or_else(|| n.child_by_field_name("method"))
                .or_else(|| n.child_by_field_name("name"))
            && let Some(callee_text) =
                member_expr_text(callee, code).or_else(|| text_of(callee, code))
            && matches!(
                classify(lang, &callee_text, extra),
                Some(DataLabel::Sink(_))
            )
        {
            return Some(n);
        }
        let now_inside = inside_fn || lookup(lang, n.kind()) == Kind::Function;
        // Never descend a call's callee/receiver side.  On a chained call
        // (`http.get(target, cb).on('error', cb2)`) the receiver — including
        // its own callback argument — hangs off the `function` field, so
        // descending it would return a sink belonging to the RECEIVER call and
        // hand the caller provenance for a call it does not own.  Argument
        // positions are the only place a callback this node passes can live.
        let callee_side = n
            .child_by_field_name("function")
            .or_else(|| n.child_by_field_name("method"))
            .or_else(|| n.child_by_field_name("name"))
            .map(|c| c.id());
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if Some(child.id()) == callee_side {
                continue;
            }
            if let Some(found) = walk(child, lang, code, extra, now_inside) {
                return Some(found);
            }
        }
        None
    }
    walk(n, lang, code, extra_labels, false)
}

/// Return the text of the first member expression found in `n`.
pub(crate) fn first_member_text(n: Node, code: &[u8]) -> Option<String> {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" => member_expr_text(n, code),
        "subscript_expression" | "subscript" | "element_reference" => n
            .child_by_field_name("object")
            .or_else(|| n.child_by_field_name("value"))
            .or_else(|| n.child(0))
            .and_then(|obj| text_of(obj, code)),
        _ => {
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                if let Some(t) = first_member_text(child, code) {
                    return Some(t);
                }
            }
            None
        }
    }
}

/// Check whether any descendant of `n` is a call expression.
/// Collect function-expression nodes nested inside a call's arguments.
///
/// This finds anonymous functions / arrow functions / closures that are
/// passed as arguments to a call and should be analysed as separate
/// function scopes.  Only direct function-argument children are collected
/// (not functions nested inside other functions, those get handled when
/// the outer function is recursed into).
pub(crate) fn collect_nested_function_nodes<'a>(n: Node<'a>, lang: &str) -> Vec<Node<'a>> {
    let mut funcs = Vec::new();
    collect_nested_functions_rec(n, lang, &mut funcs, false);
    funcs
}

pub(crate) fn collect_nested_functions_rec<'a>(
    n: Node<'a>,
    lang: &str,
    out: &mut Vec<Node<'a>>,
    inside_function: bool,
) {
    let kind = lookup(lang, n.kind());
    // Only treat as a function if it's a real function node (has children),
    // not a keyword token like `function` in JS which shares the same kind name.
    if kind == Kind::Function && n.child_count() > 0 {
        if inside_function {
            // Don't recurse into nested functions of nested functions
            return;
        }
        out.push(n);
        return;
    }
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        collect_nested_functions_rec(c, lang, out, inside_function);
    }
}

/// Derive a binding name for an anonymous function literal from its syntactic
/// context. Returns `None` when no unambiguous binding exists (e.g. function
/// passed directly as a call argument, nested in a destructuring pattern, or
/// stored into a subscript expression).
///
/// Supported shapes (across JS/TS, Python, Ruby, Go, PHP, Rust):
///  * `var|let|const h = <fn>`         → `"h"`
///  * `h := <fn>`                      → `"h"` (Go short-var)
///  * `h = <fn>`                       → `"h"` (reassignment)
///  * `obj.prop = <fn>` / `obj::prop`  → `"prop"` (bind via rightmost member)
///
/// Parenthesised wrappers (`var h = (function(){})`) are transparently
/// skipped. The disambig start-byte on the generated FuncKey prevents
/// shadowed same-name bindings from colliding.
pub(crate) fn derive_anon_fn_name_from_context<'a>(
    func_node: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Option<String> {
    // Walk up past parenthesized wrappers so `var h = (fn)` works.
    let mut cur = func_node.parent()?;
    while cur.kind() == "parenthesized_expression" {
        cur = cur.parent()?;
    }
    let parent = cur;

    let lhs_ident_text = |lhs: Node<'a>| -> Option<String> {
        let lhs = unwrap_parens(lhs);
        match lhs.kind() {
            "identifier" | "variable_name" | "simple_identifier" => text_of(lhs, code),
            // `obj.prop = <fn>` → "prop" (JS/TS/Python/PHP/Ruby/Go)
            "member_expression"
            | "attribute"
            | "field_expression"
            | "selector_expression"
            | "scoped_identifier" => lhs
                .child_by_field_name("property")
                .or_else(|| lhs.child_by_field_name("field"))
                .or_else(|| lhs.child_by_field_name("name"))
                .and_then(|n| text_of(n, code)),
            _ => None,
        }
    };

    match parent.kind() {
        // JS/TS: `var h = fn`, Java/Rust: `let h = fn`, C++: `auto h = fn`,
        // PHP: `$h = fn` also lands here when the parent is `variable_declarator`.
        "variable_declarator" | "init_declarator" | "let_declaration" => parent
            .child_by_field_name("name")
            .or_else(|| parent.child_by_field_name("pattern"))
            .and_then(|n| match n.kind() {
                "identifier" | "variable_name" | "simple_identifier" => text_of(n, code),
                _ => None, // destructuring / tuple patterns are ambiguous
            }),

        // JS/TS: `h = fn`, `obj.prop = fn`
        // Ruby `assignment` / C `assignment_expression`
        "assignment_expression" | "assignment" => {
            parent.child_by_field_name("left").and_then(lhs_ident_text)
        }

        // Go: `h := fn` (short_var_declaration). The left child is an
        // expression_list with one identifier.
        "short_var_declaration" => {
            let left = parent.child_by_field_name("left")?;
            let mut cur = left.walk();
            left.children(&mut cur).find_map(|c| {
                (c.kind() == "identifier")
                    .then(|| text_of(c, code))
                    .flatten()
            })
        }

        // Go: `var h = fn` → var_spec with names field.
        "var_spec" | "const_spec" => {
            let names = parent.child_by_field_name("name")?;
            let mut cur = names.walk();
            names.children(&mut cur).find_map(|c| {
                (c.kind() == "identifier")
                    .then(|| text_of(c, code))
                    .flatten()
            })
        }

        // Python: `h = lambda: ...` parents as `assignment`, handled above.
        // Python `default_parameter` assigning `def foo(x=lambda: 0)`, ambiguous, skip.
        _ => {
            // Some grammars wrap the RHS in an `expression`, `expression_list`,
            // or similar node between the binding site and the function literal.
            // Do one more hop to catch these without blowing past meaningful
            // scopes (e.g. enclosing function body / block).
            let grand = parent.parent()?;
            match grand.kind() {
                "variable_declarator" | "init_declarator" => grand
                    .child_by_field_name("name")
                    .and_then(|n| match n.kind() {
                        "identifier" | "variable_name" | "simple_identifier" => text_of(n, code),
                        _ => None,
                    }),
                "assignment_expression" | "assignment" => {
                    grand.child_by_field_name("left").and_then(lhs_ident_text)
                }
                // Go: `run := func(){...}` → func_literal's parent is
                // `expression_list`, grandparent is `short_var_declaration`.
                "short_var_declaration" => {
                    let left = grand.child_by_field_name("left")?;
                    let mut cur = left.walk();
                    left.children(&mut cur).find_map(|c| {
                        (c.kind() == "identifier")
                            .then(|| text_of(c, code))
                            .flatten()
                    })
                }
                // Go: `var run = func(){...}` wraps through var_spec via
                // expression_list in older grammar versions.
                "var_spec" | "const_spec" => {
                    let names = grand.child_by_field_name("name")?;
                    let mut cur = names.walk();
                    names.children(&mut cur).find_map(|c| {
                        (c.kind() == "identifier")
                            .then(|| text_of(c, code))
                            .flatten()
                    })
                }
                _ => None,
            }
        }
    }
    .and_then(|name| {
        // Guard against degenerate names that would collide with label rules
        // or produce unstable summary keys. Lang-specific leaf only.
        if name.is_empty()
            || name.contains(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        {
            None
        } else {
            // Silence unused-binding warning if lang matching never fires.
            let _ = lang;
            Some(name)
        }
    })
}

pub(crate) fn has_call_descendant(n: Node, lang: &str) -> bool {
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        match lookup(lang, c.kind()) {
            Kind::CallFn | Kind::CallMethod | Kind::CallMacro => return true,
            _ => {
                if has_call_descendant(c, lang) {
                    return true;
                }
            }
        }
    }
    false
}

/// Recursively collect identifiers AND full dotted member-expression paths.
///
/// For `member_expression` / `attribute` / `selector_expression` / `field_expression`
/// nodes the full dotted path (via `member_expr_text`) is pushed into `paths`,
/// and the individual leaf identifiers are pushed into `idents` as a fallback.
/// Plain identifiers go only into `idents`.
pub(crate) fn collect_idents_with_paths(
    n: Node,
    code: &[u8],
    idents: &mut Vec<String>,
    paths: &mut Vec<String>,
) {
    match n.kind() {
        "member_expression" | "attribute" | "selector_expression" | "field_expression" => {
            if let Some(path) = member_expr_text(n, code) {
                paths.push(path);
            }
            collect_idents(n, code, idents);
        }
        "identifier"
        | "field_identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern" => {
            if let Some(txt) = text_of(n, code) {
                idents.push(txt);
            }
        }
        "variable_name" => {
            if let Some(txt) = text_of(n, code) {
                idents.push(txt.trim_start_matches('$').to_string());
            }
        }
        _ => {
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                collect_idents_with_paths(ch, code, idents, paths);
            }
        }
    }
}

/// Walk an array/tuple destructure pattern in source order and return
/// each simple-identifier binding paired with its position index.
///
/// Recognises:
///   * JS/TS `array_pattern` — `const [a, b] = ...`, `const [, b] = ...`,
///     `const [a, ,] = ...`. Skip slots (commas with no binding between)
///     advance the position counter without emitting a binding.
///   * Rust `tuple_pattern` — `let (a, _, b) = ...`. `_pattern` (wildcard)
///     advances the position counter without emitting a binding.
///   * Python `pattern_list` / `tuple_pattern` — `a, b = ...` and
///     `(a, b) = ...`. Python `_` is a normal identifier binding (not a
///     wildcard), so every `identifier` child emits a (name, position)
///     entry.
///   * Ruby `left_assignment_list` — `a, b = ...`. Bare comma-list LHS
///     produced by `assignment` whose RHS is an array literal, a call
///     return, or another tuple-yielding expression. Ruby `_` is a normal
///     identifier (matches Python convention; `_` may still be referenced
///     later in scope). Splat (`*rest` parsed as `rest_assignment`) and
///     parenthesised nested destructure (`destructured_left_assignment`)
///     hit the bail branch and fall back to scalar union.
///
/// Returns an empty `SmallVec` when the pattern is not one of the above
/// kinds OR contains complex sub-patterns (`assignment_pattern` for
/// `[a = 1, b]`, `rest_pattern` for `[a, ...rest]`, Python
/// `list_splat_pattern` for `a, *rest = ...`, Ruby `rest_assignment` for
/// `a, *rest = ...`, nested `array_pattern`, `object_pattern`,
/// `destructured_left_assignment`). Callers treat the empty return as
/// "no position-aware rewrite available; fall back to scalar union".
pub(crate) fn collect_array_pattern_bindings_indexed(
    pat: Node,
    code: &[u8],
) -> SmallVec<[(String, usize); 4]> {
    let mut out: SmallVec<[(String, usize); 4]> = SmallVec::new();
    let kind = pat.kind();
    if !matches!(
        kind,
        "array_pattern" | "tuple_pattern" | "pattern_list" | "left_assignment_list"
    ) {
        return out;
    }
    let mut cursor = pat.walk();
    let mut pos: usize = 0;
    for child in pat.children(&mut cursor) {
        match child.kind() {
            "[" | "]" | "(" | ")" => {}
            "," => {
                pos += 1;
            }
            "identifier" | "shorthand_property_identifier_pattern" => {
                if let Some(txt) = text_of(child, code) {
                    out.push((txt, pos));
                }
            }
            // Rust wildcard `_` in tuple_pattern. Advances position counter
            // without binding; no emit. Tree-sitter-rust models the
            // wildcard as a leaf node whose `kind()` is literally "_".
            "_" => {}
            _ => {
                // Complex sub-pattern. Bail by clearing — caller treats
                // empty as "no position-aware rewrite", preserving the
                // pre-existing scalar-union behavior for these shapes.
                out.clear();
                return out;
            }
        }
    }
    out
}

/// Walk an array-literal-shape RHS node and return one slot per source-order
/// element. Each slot is one of:
///   * `RhsArraySlot::Ident(name)` — bare identifier element.
///   * `RhsArraySlot::Literal` — syntactic literal (string, number, bool,
///     null/nil).
///   * `RhsArraySlot::Complex(uses)` — call / binary / subscript / member
///     access / nested array literal / etc. `uses` carries the inner
///     identifier names (member-access paths first, bare idents second)
///     harvested from the slot's subtree via `collect_idents_with_paths`.
///
/// Recognised RHS kinds:
///   * JS/TS / Ruby `array` — `[a, b]`
///   * Python `list` — `[a, b]`
///   * Python `tuple` — `(a, b)`
///   * Python `expression_list` — bare comma form `a, b`
///   * Rust `tuple_expression` — `(a, b)`
///
/// Bails (returns empty) when the RHS is not one of these kinds OR contains
/// a slot whose shape would shift index alignment (spread, list splat).
/// Callers treat empty as "no per-element rewrite available; fall back to
/// scalar union".
pub(crate) fn collect_rhs_array_literal_elements(
    rhs: Node,
    lang: &str,
    code: &[u8],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> SmallVec<[crate::cfg::RhsArraySlot; 4]> {
    use crate::cfg::RhsArraySlot;
    use crate::labels::{Cap, DataLabel};

    // Per-slot source classification: when a slot's own subtree carries a
    // Source-labeled member-expression / subscript, capture the Cap so the
    // SSA destructure rewrite emits Source for THIS slot specifically and
    // lets sibling Complex slots stay slot-scoped Assign. Falls back to
    // Cap::empty() when no per-slot source is recognised; the lowering
    // path then consults the outer-node Source flag for conservative
    // preservation of legacy behavior on shapes whose source pattern
    // doesn't text-classify (e.g. a subscript on a tainted local).
    let slot_source_cap = |slot: Node| -> Cap {
        match first_member_label(slot, lang, code, extra_labels) {
            Some(DataLabel::Source(c)) => c,
            _ => Cap::empty(),
        }
    };

    let mut out: SmallVec<[RhsArraySlot; 4]> = SmallVec::new();
    let kind = rhs.kind();
    if !matches!(
        kind,
        "array" | "array_literal" | "list" | "tuple" | "tuple_expression" | "expression_list"
    ) {
        return out;
    }
    let mut cursor = rhs.walk();
    for child in rhs.named_children(&mut cursor) {
        let ck = child.kind();
        match ck {
            "identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "field_identifier"
            | "property_identifier" => match text_of(child, code) {
                Some(txt) => out.push(RhsArraySlot::Ident(txt)),
                None => {
                    out.clear();
                    return out;
                }
            },
            "variable_name" => match text_of(child, code) {
                Some(txt) => out.push(RhsArraySlot::Ident(txt.trim_start_matches('$').to_string())),
                None => {
                    out.clear();
                    return out;
                }
            },
            // Syntactic literal slots: no ident, no taint contribution.
            // Names follow tree-sitter's per-grammar literal kinds across
            // the supported languages.
            "string"
            | "string_literal"
            | "raw_string_literal"
            | "interpreted_string_literal"
            | "concatenated_string"
            | "integer"
            | "integer_literal"
            | "float"
            | "float_literal"
            | "number"
            | "numeric_literal"
            | "true"
            | "false"
            | "boolean_literal"
            | "boolean"
            | "null"
            | "null_literal"
            | "nil"
            | "none"
            | "None"
            | "undefined" => {
                out.push(RhsArraySlot::Literal);
            }
            // Spread / list-splat shift index alignment unpredictably
            // (`[...arr, b]` may expand to N elements at index 0). Bail
            // so callers fall back to scalar union.
            "spread_element" | "list_splat" | "list_splat_pattern" | "splat_argument"
            | "unary_splat" | "splat_expression" => {
                out.clear();
                return out;
            }
            // Interpolated strings carry inner identifier uses. Treat as
            // Complex so the slot picks up the contributions from
            // `${user.id}` etc.
            "template_string" | "string_interpolation" | "interpolation" | "encapsed_string" => {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(child, code, &mut idents, &mut paths);
                let mut uses: SmallVec<[String; 4]> = SmallVec::new();
                for p in paths {
                    uses.push(p);
                }
                for ident in idents {
                    if !uses.iter().any(|u| u == &ident) {
                        uses.push(ident);
                    }
                }
                let source_cap = slot_source_cap(child);
                out.push(RhsArraySlot::Complex { uses, source_cap });
            }
            // Everything else (call, member access, binary, subscript,
            // unary, ternary, nested array literal, etc.) is a "complex"
            // slot. Harvest inner ident uses so the SSA lowering can paint
            // the binding with this slot's contributions only — not the
            // union of every ident on the RHS.
            _ => {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(child, code, &mut idents, &mut paths);
                let mut uses: SmallVec<[String; 4]> = SmallVec::new();
                for p in paths {
                    uses.push(p);
                }
                for ident in idents {
                    if !uses.iter().any(|u| u == &ident) {
                        uses.push(ident);
                    }
                }
                let source_cap = slot_source_cap(child);
                out.push(RhsArraySlot::Complex { uses, source_cap });
            }
        }
    }
    out
}

/// Recursively collect every identifier that occurs inside `n`.
///
/// Recognises `identifier` (most languages), `variable_name` (PHP),
/// `field_identifier` (Go), `property_identifier` (JS/TS), and
/// `shorthand_property_identifier` / `shorthand_property_identifier_pattern`
/// (JS/TS object-literal shorthand uses and destructuring binding patterns).
pub(crate) fn collect_idents(n: Node, code: &[u8], out: &mut Vec<String>) {
    match n.kind() {
        "identifier"
        | "field_identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern"
        // PHP `name`: leaf node carrying the bare identifier text for
        // function/method names and similar grammar slots.  Without this
        // arm `function_definition` → `name` extraction returns empty
        // for PHP, demoting every named function to `<anon#N>` and
        // breaking cross-function summary lookup at the call site.
        | "name" => {
            if let Some(txt) = text_of(n, code) {
                out.push(txt);
            }
        }
        // PHP: $x is `variable_name` → `$` + `name`. Use the whole text minus `$`.
        "variable_name" => {
            if let Some(txt) = text_of(n, code) {
                out.push(txt.trim_start_matches('$').to_string());
            }
        }
        _ => {
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                collect_idents(ch, code, out);
            }
        }
    }
}

/// AST kind names for subscript / index expressions
/// across the languages whose container-element flow we model.
///
/// JS/TS and C/C++ use `subscript_expression`; Python uses `subscript`;
/// Go uses `index_expression`. Other languages either lower indexing
/// through method calls (Rust slice indexing) or are out of scope for
/// the initial W5 rollout (Java/Ruby/PHP).
#[inline]
pub(crate) fn is_subscript_kind(kind: &str) -> bool {
    matches!(
        kind,
        "subscript_expression" | "subscript" | "index_expression"
    )
}

/// when the LHS of an assignment statement is a
/// subscript / index expression (or a single-element wrapper around
/// one), return that node.  Returns `None` for multi-target Go
/// `expression_list`s, identifier LHSs, member-expression LHSs, etc.
pub(crate) fn subscript_lhs_node<'a>(lhs: Node<'a>, lang: &str) -> Option<Node<'a>> {
    if is_subscript_kind(lhs.kind()) {
        return Some(lhs);
    }
    // Go: `assignment_statement.left` is an `expression_list`; for
    // single-target subscript writes (`m[k] = v`) it has exactly one
    // named child which is `index_expression`.
    if lang == "go" && lhs.kind() == "expression_list" {
        let mut cursor = lhs.walk();
        let named: Vec<Node> = lhs.named_children(&mut cursor).collect();
        if named.len() == 1 && is_subscript_kind(named[0].kind()) {
            return Some(named[0]);
        }
    }
    None
}

/// extract `(array_text, index_text)` from a
/// subscript / index AST node.
///
/// Returns `None` when the array operand is not a plain identifier, we
/// only synthesise `__index_get__` / `__index_set__` calls when the
/// receiver resolves cleanly to a SSA-renamed local, since the W2/W4
/// container hooks need a stable receiver var_name to drive
/// `pt(receiver)`.
pub(crate) fn subscript_components<'a>(n: Node<'a>, code: &'a [u8]) -> Option<(String, String)> {
    if !is_subscript_kind(n.kind()) {
        return None;
    }
    let arr = n
        .child_by_field_name("object")
        .or_else(|| n.child_by_field_name("operand"))
        .or_else(|| n.child_by_field_name("value"))
        .or_else(|| n.child(0))?;
    let idx = n
        .child_by_field_name("index")
        .or_else(|| n.child_by_field_name("subscript"))
        .or_else(|| {
            // Fallback: take the second named child after the array.
            let mut cur = n.walk();
            n.named_children(&mut cur).nth(1)
        })?;
    let arr_kind = arr.kind();
    // Only proceed when the array is a plain identifier, otherwise
    // we can't bind a stable receiver name for the synth Call.
    if !matches!(
        arr_kind,
        "identifier" | "variable_name" | "simple_identifier"
    ) {
        return None;
    }
    let arr_text = text_of(arr, code)?;
    // PHP-style `$x` strip not needed here; the supported languages
    // don't use it for local array identifiers.
    let idx_text = text_of(idx, code)?;
    Some((arr_text, idx_text))
}

#[cfg(test)]
mod source_str_tests {
    use super::{VALID_SOURCE, ValidSourceGuard, node_str, slice_str};

    /// `node_str` must decode every node's byte range identically to the checked
    /// `from_utf8(&code[node.byte_range()]).ok()` it replaced at the scan-path
    /// call sites (ast query pass, entry-point detection, import resolution),
    /// with the pre-validated-source fast path active. Walks a real parsed tree
    /// so the guard covers the actual `Node::start_byte()/end_byte()` offsets.
    #[test]
    fn node_str_matches_checked_over_parsed_tree() {
        // `\xc3\xa9` is the UTF-8 encoding of `é`; written as an escape because
        // a raw non-ASCII char is not permitted in a `b"..."` byte-string
        // literal.  The decoded bytes are identical, so the multi-byte-char
        // decode path is still exercised.
        let code =
            b"package main\nfunc handler(w http.ResponseWriter) { fmt.Println(\"h\xc3\xa9llo\") }\n";
        let _g = ValidSourceGuard::new(code.as_slice());
        assert_eq!(
            VALID_SOURCE.with(|c| c.get()),
            Some((code.as_ptr(), code.len())),
            "fast path must be active for this exact slice",
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("load go grammar");
        let tree = parser.parse(code.as_slice(), None).expect("parse");

        fn walk(n: tree_sitter::Node, code: &[u8]) {
            let got = node_str(n, code).map(str::to_string);
            let want = code
                .get(n.start_byte()..n.end_byte())
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(str::to_string);
            assert_eq!(got, want, "node_str diverged at {:?}", n.byte_range());
            let mut c = n.walk();
            for child in n.children(&mut c) {
                walk(child, code);
            }
        }
        walk(tree.root_node(), code.as_slice());
    }

    /// Reference decode: exactly what `text_of`/the direct sites did before the
    /// pre-validated fast path — an unconditional checked `from_utf8` of the
    /// byte range. Every `slice_str` result must equal this on every range.
    fn checked(code: &[u8], start: usize, end: usize) -> Option<String> {
        code.get(start..end)
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| s.to_string())
    }

    fn slice_owned(code: &[u8], start: usize, end: usize) -> Option<String> {
        slice_str(code, start, end).map(|s| s.to_string())
    }

    #[test]
    fn fast_path_bit_identical_to_checked_ascii() {
        let code = b"let handle = File::open(path).unwrap();";
        let _g = ValidSourceGuard::new(code);
        // Guard registered this exact slice -> fast path is active.
        assert_eq!(
            VALID_SOURCE.with(|c| c.get()),
            Some((code.as_ptr(), code.len()))
        );
        for start in 0..=code.len() {
            for end in start..=code.len() {
                assert_eq!(
                    slice_owned(code, start, end),
                    checked(code, start, end),
                    "mismatch at {start}..{end}"
                );
            }
        }
    }

    #[test]
    fn fast_path_multibyte_boundaries_match_checked() {
        // Mixed multibyte: `é` (2 bytes), `€` (3 bytes), `𝄞` (4 bytes).
        let s = "aé b€ c𝄞 d";
        let code = s.as_bytes();
        let _g = ValidSourceGuard::new(code);
        for start in 0..=code.len() {
            for end in start..=code.len() {
                // Non-char-boundary ranges must yield None in BOTH paths.
                assert_eq!(
                    slice_owned(code, start, end),
                    checked(code, start, end),
                    "mismatch at {start}..{end}"
                );
            }
        }
    }

    #[test]
    fn no_guard_uses_checked_path_and_matches() {
        // With no active guard, VALID_SOURCE is None -> checked fallback.
        let code = b"session.query(sql)";
        VALID_SOURCE.with(|c| c.set(None));
        assert_ne!(
            VALID_SOURCE.with(|c| c.get()),
            Some((code.as_ptr(), code.len()))
        );
        for start in 0..=code.len() {
            for end in start..=code.len() {
                assert_eq!(slice_owned(code, start, end), checked(code, start, end));
            }
        }
    }

    #[test]
    fn guard_registers_only_valid_utf8() {
        let good = b"valid ascii";
        {
            let _g = ValidSourceGuard::new(good);
            assert_eq!(
                VALID_SOURCE.with(|c| c.get()),
                Some((good.as_ptr(), good.len()))
            );
        }
        // Dropped -> restored to None.
        assert_eq!(VALID_SOURCE.with(|c| c.get()), None);

        // Invalid UTF-8 registers nothing (None) -> slice_str stays on the
        // checked path, which returns None for the invalid range.
        let bad = [b'o', b'k', 0xFF, 0xFE];
        let _g = ValidSourceGuard::new(&bad);
        assert_eq!(VALID_SOURCE.with(|c| c.get()), None);
        assert_eq!(slice_str(&bad, 0, 4), None); // 0xFF 0xFE not valid UTF-8
        assert_eq!(slice_str(&bad, 0, 2), Some("ok")); // valid prefix still decodes
    }

    #[test]
    fn nested_guards_save_and_restore() {
        let outer = b"outer source file";
        let inner = b"inner nested snippet";
        let g_outer = ValidSourceGuard::new(outer);
        assert_eq!(
            VALID_SOURCE.with(|c| c.get()),
            Some((outer.as_ptr(), outer.len()))
        );
        {
            let _g_inner = ValidSourceGuard::new(inner);
            assert_eq!(
                VALID_SOURCE.with(|c| c.get()),
                Some((inner.as_ptr(), inner.len()))
            );
        }
        // Inner dropped -> outer registration restored (composes for
        // parse-within-parse on one thread).
        assert_eq!(
            VALID_SOURCE.with(|c| c.get()),
            Some((outer.as_ptr(), outer.len()))
        );
        drop(g_outer);
        assert_eq!(VALID_SOURCE.with(|c| c.get()), None);
    }
}

#[cfg(test)]
mod callback_sink_tests {
    use super::{first_callback_sink_call, member_expr_text};
    use tree_sitter::{Node, Parser};

    fn callee_of(call: Node, code: &[u8]) -> Option<String> {
        call.child_by_field_name("function")
            .and_then(|f| member_expr_text(f, code))
    }

    /// The inner `sequelize.query` sink nested in the `.transaction` callback
    /// body is located (through the arrow-function boundary), and its enclosing
    /// call node is returned.
    #[test]
    fn finds_inner_sink_call_in_transaction_callback() {
        let code = br#"function up(q) {
  return q.sequelize.transaction(async (t) => {
    return q.sequelize.query(`DROP VIEW x`, { transaction: t });
  });
}"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&code[..], None).unwrap();
        // Root program → find the transaction call_expression.
        fn find_transaction<'a>(n: Node<'a>, code: &[u8]) -> Option<Node<'a>> {
            if n.kind() == "call_expression"
                && callee_of(n, code).as_deref() == Some("q.sequelize.transaction")
            {
                return Some(n);
            }
            let mut c = n.walk();
            for ch in n.children(&mut c) {
                if let Some(f) = find_transaction(ch, code) {
                    return Some(f);
                }
            }
            None
        }
        let tx = find_transaction(tree.root_node(), &code[..]).expect("transaction call");
        let inner = first_callback_sink_call(tx, "javascript", &code[..], None)
            .expect("inner sink call inside the callback");
        assert_eq!(
            callee_of(inner, &code[..]).as_deref(),
            Some("q.sequelize.query")
        );
    }

    /// A member-source passed as a plain (non-callback) argument is not a
    /// callback-nested sink → `None` (the ordinary hoist path is unaffected).
    #[test]
    fn ignores_non_callback_member_arg() {
        let code = b"function h(req) { storeInto(req.query.input, items); }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&code[..], None).unwrap();
        assert!(
            first_callback_sink_call(tree.root_node(), "javascript", &code[..], None).is_none()
        );
    }
}
