use super::anon_fn_name;
use super::conditions::unwrap_parens;
use crate::labels::{DataLabel, Kind, classify, lookup};
use tree_sitter::Node;

// -------------------------------------------------------------------------
//                      Utility helpers
// -------------------------------------------------------------------------

/// Return the text of a node.
#[inline]
pub(crate) fn text_of<'a>(n: Node<'a>, code: &'a [u8]) -> Option<String> {
    std::str::from_utf8(&code[n.start_byte()..n.end_byte()])
        .ok()
        .map(|s| s.to_string())
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
                                text_of(f, code)
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
                            (_, Some(f)) => Some(f.to_string()),
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
) -> Option<(String, DataLabel, (usize, usize))> {
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
                let ident = match lookup(lang, c.kind()) {
                    Kind::CallFn => c
                        .child_by_field_name("function")
                        .or_else(|| c.child_by_field_name("method"))
                        .or_else(|| c.child_by_field_name("name"))
                        .or_else(|| c.child_by_field_name("type"))
                        .and_then(|f| text_of(f, code)),
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
                if let Some(ref id) = ident
                    && let Some(lbl) = classify(lang, id, extra)
                {
                    return Some((id.clone(), lbl, (c.start_byte(), c.end_byte())));
                }
                // Recurse into arguments of this call
                if let Some(found) = find_classifiable_inner_call(c, lang, code, extra) {
                    return Some(found);
                }
            }
            _ => {
                if let Some(found) = find_classifiable_inner_call(c, lang, code, extra) {
                    return Some(found);
                }
            }
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
        "subscript_expression" | "subscript" | "element_reference" => {
            if let Some(obj) = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("value"))
                .or_else(|| n.child(0))
            {
                if let Some(txt) = text_of(obj, code)
                    && let Some(lbl) = classify(lang, &txt, extra_labels)
                {
                    return Some(lbl);
                }
                // Recurse into the object for nested member accesses
                if let Some(lbl) = first_member_label(obj, lang, code, extra_labels) {
                    return Some(lbl);
                }
            }
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
            // Also collect individual idents as fallback
            collect_idents(n, code, idents);
        }
        "identifier"
        | "field_identifier"
        | "property_identifier"
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

/// Recursively collect every identifier that occurs inside `n`.
///
/// Recognises `identifier` (most languages), `variable_name` (PHP),
/// `field_identifier` (Go), `property_identifier` (JS/TS), and
/// `shorthand_property_identifier_pattern` (JS/TS destructuring).
pub(crate) fn collect_idents(n: Node, code: &[u8], out: &mut Vec<String>) {
    match n.kind() {
        "identifier"
        | "field_identifier"
        | "property_identifier"
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
/// JS/TS use `subscript_expression`; Python uses `subscript`; Go uses
/// `index_expression`.  Other languages either lower indexing through
/// method calls (Rust slice indexing) or are out of scope for the
/// initial W5 rollout (Java/Ruby/PHP/C/C++).
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
    // PHP-style `$x` strip not needed here, Go/JS/Python don't use it.
    let idx_text = text_of(idx, code)?;
    Some((arr_text, idx_text))
}
