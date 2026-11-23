//! Literal and constant-expression extraction from tree-sitter AST nodes.
//!
//! Parses integer and string literals, folds constant binary ops, and derives
//! template/string prefixes and quote stripping for CFG construction and
//! const propagation.

use super::conditions::unwrap_parens;
use super::helpers::{
    collect_array_pattern_bindings_indexed, collect_assign_targets,
    collect_rhs_array_literal_elements, find_condition_subtree, for_each_parts,
};
use super::{
    RmwAssign, anon_fn_name, collect_idents, collect_idents_with_paths,
    find_constructor_type_child, first_call_ident, rmw_assignment, rmw_target_define,
    rmw_target_reads, root_receiver_text, text_of,
};
use crate::cfg::fast_kind::{FastKind, lookup_node};
use crate::labels::{Cap, DataLabel, Kind, lookup};
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// PHP expressions that wrap a call without hiding it: `!unlink($p)`,
/// `@unlink($p)` and `(unlink($p))`. They are searched through like `await`,
/// so `$ok = !unlink($p)` still exposes its call. Casts are left opaque: a
/// numeric cast of a call is handled as a number (see `yields_number`).
fn is_php_value_wrapper(lang: &str, n: Node) -> bool {
    lang == "php"
        && matches!(
            n.fkind(),
            "unary_op_expression" | "parenthesized_expression" | "error_suppression_expression"
        )
}

/// Find the inner CallFn/CallMethod/CallMacro node within an AST node.
/// For direct call nodes, returns the node itself. For wrappers, searches
/// up to two levels of children, transparently descending through
/// `await_expression` / `yield_expression` (`Kind::AwaitForward`) wrappers
/// so `const x = await foo(y)` reaches the inner `call_expression` at
/// effective depth 3 (`lexical_declaration > variable_declarator >
/// await_expression > call_expression`).
pub(super) fn find_call_node<'a>(n: Node<'a>, lang: &str) -> Option<Node<'a>> {
    match lookup_node(lang, n) {
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => Some(n),
        Kind::AwaitForward => {
            // Transparent wrapper: descend into the awaited expression.
            let mut cursor = n.walk();
            for c in n.children(&mut cursor) {
                if let Some(found) = find_call_node(c, lang) {
                    return Some(found);
                }
            }
            None
        }
        _ => {
            let mut cursor = n.walk();
            for c in n.children(&mut cursor) {
                match lookup_node(lang, c) {
                    Kind::CallFn | Kind::CallMethod | Kind::CallMacro => return Some(c),
                    // Skip past await/yield wrappers without consuming a
                    // recursion level — the wrapper itself is transparent.
                    Kind::AwaitForward => {
                        if let Some(found) = find_call_node(c, lang) {
                            return Some(found);
                        }
                    }
                    _ if is_php_value_wrapper(lang, c) => {
                        if let Some(found) = find_call_node(c, lang) {
                            return Some(found);
                        }
                    }
                    _ => {}
                }
            }
            // Recurse one more level (handles `expression_statement > variable_declarator > call`)
            let mut cursor2 = n.walk();
            for c in n.children(&mut cursor2) {
                // The loop above already ran the full search on wrapper
                // children, which covers every grandchild check below.
                // Searching their grandchildren again re-enters each nested
                // wrapper twice per level, so a PHP `~~~...~$x` chain cost
                // grew exponentially with its depth.
                if lookup_node(lang, c) == Kind::AwaitForward || is_php_value_wrapper(lang, c) {
                    continue;
                }
                let mut cursor3 = c.walk();
                for gc in c.children(&mut cursor3) {
                    match lookup_node(lang, gc) {
                        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => return Some(gc),
                        Kind::AwaitForward => {
                            if let Some(found) = find_call_node(gc, lang) {
                                return Some(found);
                            }
                        }
                        _ if is_php_value_wrapper(lang, gc) => {
                            if let Some(found) = find_call_node(gc, lang) {
                                return Some(found);
                            }
                        }
                        // `$ok = unlink($f) or die('x')` parses as
                        // `(assignment) or (call)`: the assignment's call is
                        // the one the callee name came from.
                        _ if lang == "php"
                            && gc.fkind() == "assignment_expression"
                            && c.fkind() == "binary_expression" =>
                        {
                            if let Some(found) = find_call_node(gc, lang) {
                                return Some(found);
                            }
                        }
                        _ => {}
                    }
                }
            }
            None
        }
    }
}

/// Extract `(field_name, ident_name)` pairs from specified fields of an
/// object-literal argument.
///
/// Returns:
/// * `Some(pairs)` if the positional argument at `index` IS an object literal
///   (JS `object`, TS `object`, Python `dictionary`). Each pair is
///   `(field_name, ident_name)` where `field_name` is the matched key from
///   `fields` and `ident_name` is an identifier lifted from that pair's
///   value expression. When no destination-field pairs are present, returns
///   `Some(vec![])`, the sink is effectively silenced because no destination
///   identifier exists.
/// * `None` if the arg is absent, is not an object literal (plain string
///   / ident / expression), or has splat/spread children that break static
///   per-field reasoning. Callers fall back to the whole-arg positional
///   filter in this case.
pub(super) fn extract_destination_field_pairs(
    call_node: Node,
    arg_index: usize,
    fields: &[&str],
    code: &[u8],
) -> Option<Vec<(String, String)>> {
    let values = destination_field_values(call_node, arg_index, fields, code)?;
    let mut out: Vec<(String, String)> = Vec::new();
    for (key, val_node) in values {
        let mut idents: Vec<String> = Vec::new();
        let mut paths: Vec<String> = Vec::new();
        collect_idents_with_paths(val_node, code, &mut idents, &mut paths);
        if idents.is_empty() && paths.is_empty() {
            // Shorthand `{ url }`: the node is the binding itself.
            if let Some(name) = text_of(val_node, code)
                && matches!(
                    val_node.fkind(),
                    "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
                )
            {
                idents.push(name);
            }
        }
        for name in paths.into_iter().chain(idents) {
            if !out.iter().any(|(_, v)| v == &name) {
                out.push((key.clone(), name));
            }
        }
    }
    Some(out)
}

/// The first destination field of the object-literal argument at
/// `arg_index` that reads a member Source (`{ text: 'SELECT ' +
/// req.query.id }`).  Such a Source is lowered to the synthetic
/// `__nyx_src_*` binding of the whole argument (see
/// `cfg::pre_emit_arg_source_nodes`), which the destination filter must
/// keep.
pub(super) fn destination_field_reading_source(
    call_node: Node,
    arg_index: usize,
    fields: &[&str],
    lang: &str,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> Option<String> {
    destination_field_values(call_node, arg_index, fields, code)?
        .into_iter()
        .find(|(_, v)| {
            matches!(
                super::helpers::first_member_label(*v, lang, code, extra),
                Some(crate::labels::DataLabel::Source(_))
            )
        })
        .map(|(key, _)| key)
}

/// `(field_name, value node)` for every field of the object-literal argument
/// at `arg_index` whose key is listed in `fields`.  A shorthand property
/// (`{ url }`) yields the shorthand node itself.  `None` under the same
/// conditions as [`extract_destination_field_pairs`].
fn destination_field_values<'a>(
    call_node: Node<'a>,
    arg_index: usize,
    fields: &[&str],
    code: &[u8],
) -> Option<Vec<(String, Node<'a>)>> {
    if fields.is_empty() {
        return None;
    }
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let arg = args.named_children(&mut cursor).nth(arg_index)?;

    // Only object / dict literal forms carry per-field destination semantics.
    // For anything else (identifier, member expression, string, call), return
    // None so the caller treats the whole arg as destination.
    if !matches!(arg.fkind(), "object" | "dictionary") {
        return None;
    }

    let mut out: Vec<(String, Node<'a>)> = Vec::new();
    let mut c = arg.walk();
    for child in arg.named_children(&mut c) {
        match child.fkind() {
            // `spread_element` (JS/TS) / `dictionary_splat` (Python): we can't
            // statically attribute spread contents to specific fields, so
            // bail out, caller falls back to the whole-arg filter, matching
            // the conservative posture used by arg_uses for splats.
            "spread_element" | "dictionary_splat" => {
                return None;
            }
            // Shorthand property `{ url }` binds the `url` field to a binding
            // also named `url`. Treat as destination iff the name matches.
            "shorthand_property_identifier" | "shorthand_property_identifier_pattern" => {
                let Some(name) = text_of(child, code) else {
                    continue;
                };
                if fields.iter().any(|&f| f == name) {
                    out.push((name, child));
                }
            }
            "pair" => {
                let Some(key_node) = child.child_by_field_name("key") else {
                    continue;
                };
                let key_text = match key_node.fkind() {
                    // Strip quotes from string-literal keys so `"url"` and `url`
                    // both match the configured field list.
                    "string" | "string_literal" => text_of(key_node, code).map(|raw| {
                        if raw.len() >= 2 {
                            raw[1..raw.len() - 1].to_string()
                        } else {
                            raw
                        }
                    }),
                    // Computed keys: resolve only when the inner expression
                    // is a pure string literal (`['url']`).  Dynamic forms
                    // (`[someVar]`, `[`url-${i}`]`, ``[`url`]`` with
                    // interpolation) stay conservative-skip.
                    "computed_property_name" => {
                        let mut inner_cursor = key_node.walk();
                        let inner = key_node.named_children(&mut inner_cursor).find(|c| {
                            !matches!(c.fkind(), "comment" | "block_comment" | "line_comment")
                        });
                        match inner.map(|n| (n.fkind(), n)) {
                            Some(("string" | "string_literal", n)) => text_of(n, code).map(|raw| {
                                if raw.len() >= 2 {
                                    raw[1..raw.len() - 1].to_string()
                                } else {
                                    raw
                                }
                            }),
                            // Template strings only when no interpolation
                            // (no `template_substitution` children).
                            Some(("template_string", n))
                                if {
                                    let mut tc = n.walk();
                                    !n.named_children(&mut tc)
                                        .any(|c| c.fkind() == "template_substitution")
                                } =>
                            {
                                text_of(n, code).map(|raw| {
                                    if raw.len() >= 2 {
                                        raw[1..raw.len() - 1].to_string()
                                    } else {
                                        raw
                                    }
                                })
                            }
                            _ => continue,
                        }
                    }
                    _ => text_of(key_node, code),
                };
                let Some(key) = key_text else {
                    continue;
                };
                if !fields.iter().any(|&f| f == key) {
                    continue;
                }
                let Some(val_node) = child.child_by_field_name("value") else {
                    continue;
                };
                out.push((key, val_node));
            }
            _ => {}
        }
    }
    Some(out)
}

/// Extract `(field_name, ident_name)` pairs from `keyword_argument` /
/// `named_argument` children of a call whose keyword name matches one of
/// `fields`.  Used for languages where destination-bearing fields are passed
/// as direct kwargs rather than wrapped in a dict literal, e.g. Python
/// `requests.post(url, data=tainted, json=safe)` where `data` and `json` are
/// `keyword_argument` siblings of the positional URL.
///
/// Also covers Ruby, where tree-sitter-ruby emits `pair` nodes (with
/// `key`/`value` fields) directly under `argument_list` for the
/// `Faraday.new(url: x)` / `Net::HTTP.start(host, port, proxy_addr: prx)`
/// kwarg shape.  The `key` is typically a `hash_key_symbol` whose text is the
/// bare identifier (`url`); `simple_symbol` (`:url`) and string keys are
/// normalised by stripping a leading `:` or wrapping quotes.
///
/// Returns the union of matching kwargs, preserving the kwarg name in the
/// `field` slot so callers can still attribute findings per-field.  Empty
/// when no matching kwargs exist or the call has no `arguments` field.
pub(super) fn extract_destination_kwarg_pairs(
    call_node: Node,
    fields: &[&str],
    code: &[u8],
) -> Vec<(String, String)> {
    if fields.is_empty() {
        return Vec::new();
    }
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let kind = child.fkind();
        let (name_node, value_node) = if kind == "keyword_argument" || kind == "named_argument" {
            let named_count = child.named_child_count();
            (
                child
                    .child_by_field_name("name")
                    .or_else(|| child.named_child(0)),
                child
                    .child_by_field_name("value")
                    .or_else(|| child.named_child(named_count.saturating_sub(1) as u32)),
            )
        } else if kind == "pair" {
            // Ruby `pair` node sits directly under `argument_list` for
            // kwarg-style call args (`f(url: x)`).  `key`/`value` fields
            // are populated; key text is `hash_key_symbol` ("url"),
            // `simple_symbol` (":url"), or a string literal.
            (
                child.child_by_field_name("key"),
                child.child_by_field_name("value"),
            )
        } else {
            continue;
        };
        let (Some(nn), Some(vn)) = (name_node, value_node) else {
            continue;
        };
        let Some(name_raw) = text_of(nn, code) else {
            continue;
        };
        let name = name_raw
            .trim_start_matches(':')
            .trim_matches(['"', '\''])
            .to_string();
        if !fields.iter().any(|&f| f == name) {
            continue;
        }
        let mut idents = Vec::new();
        let mut paths = Vec::new();
        collect_idents_with_paths(vn, code, &mut idents, &mut paths);
        for ident in paths.into_iter().chain(idents) {
            if !out.iter().any(|(_, v)| v == &ident) {
                out.push((name.clone(), ident));
            }
        }
    }
    out
}

/// Extract the string-literal content at argument position `index` (0-based).
/// Returns `None` if the argument is not a string literal or the index is out of range.
/// True when `call_node` is `Object.create(null)` (or its parenthesised /
/// awaited / type-cast wrappers).  Strict literal-`null` first-arg match,
/// no aliasing through intermediate variables.  Caller restricts to JS/TS.
pub(super) fn is_object_create_null_call(call_node: Node, code: &[u8]) -> bool {
    if !matches!(call_node.fkind(), "call_expression") {
        return false;
    }
    let callee = call_node
        .child_by_field_name("function")
        .and_then(|f| text_of(f, code))
        .unwrap_or_default();
    if callee != "Object.create" {
        return false;
    }
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let named: Vec<Node> = args.named_children(&mut cursor).collect();
    if named.len() != 1 {
        return false;
    }
    let mut arg = named[0];
    // Unwrap parens / await / TS type-assertions.
    for _ in 0..4 {
        match arg.fkind() {
            "parenthesized_expression" => {
                if let Some(inner) = arg.named_child(0) {
                    arg = inner;
                    continue;
                }
            }
            "await_expression" => {
                if let Some(inner) = arg.child_by_field_name("argument") {
                    arg = inner;
                    continue;
                }
            }
            "as_expression" | "type_assertion" => {
                if let Some(inner) = arg.named_child(0) {
                    arg = inner;
                    continue;
                }
            }
            _ => break,
        }
    }
    arg.fkind() == "null" || text_of(arg, code).as_deref() == Some("null")
}

pub(super) fn extract_const_string_arg(
    call_node: Node,
    index: usize,
    code: &[u8],
) -> Option<String> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut arg = args.named_children(&mut cursor).nth(index)?;
    // PHP / Go wrap each positional argument in an `argument` node; unwrap so
    // the kind-match below sees the inner literal.
    if arg.fkind() == "argument" && arg.named_child_count() == 1 {
        if let Some(inner) = arg.named_child(0) {
            arg = inner;
        }
    }
    match arg.fkind() {
        // `string` / `string_literal` cover JS/TS, Python, Java, PHP, C/C++, Ruby, Rust;
        // `interpreted_string_literal` / `raw_string_literal` cover Go's
        // tree-sitter grammar (double-quoted vs. backtick-quoted forms).
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal" => {
            let raw = text_of(arg, code)?;
            if raw.len() >= 2 {
                Some(raw[1..raw.len() - 1].to_string())
            } else {
                None
            }
        }
        // Boolean literals — JS/TS `true`/`false` are their own node kinds; some
        // grammars wrap them as identifiers carrying the keyword text.  Returned
        // verbatim so `dangerous_values` matching can detect deep-flag forms
        // like `extend(true, target, src)`.
        "true" | "false" => Some(arg.fkind().to_string()),
        // PHP double-quoted strings parse as `encapsed_string` whose body is
        // a sequence of `string_content` / `escape_sequence` / interpolation
        // nodes.  Treat the string as constant only when every child is a
        // pure-literal segment (no `variable_name` / `subscript_expression`
        // interpolations); the returned value is the concatenation of the
        // literal segments verbatim.
        "encapsed_string" => {
            let mut c = arg.walk();
            let mut buf = String::new();
            for ch in arg.named_children(&mut c) {
                match ch.fkind() {
                    "string_content" => {
                        if let Some(s) = text_of(ch, code) {
                            buf.push_str(&s);
                        }
                    }
                    "escape_sequence" => {
                        if let Some(s) = text_of(ch, code) {
                            buf.push_str(&s);
                        }
                    }
                    _ => return None,
                }
            }
            Some(buf)
        }
        "template_string" => {
            // Only treat as constant if no interpolation (no template_substitution children)
            let mut c = arg.walk();
            if arg
                .named_children(&mut c)
                .any(|ch| ch.fkind() == "template_substitution")
            {
                return None; // dynamic
            }
            let raw = text_of(arg, code)?;
            if raw.len() >= 2 {
                Some(raw[1..raw.len() - 1].to_string())
            } else {
                None
            }
        }
        // Concat-style binary expression with a leading string literal, e.g.
        // PHP `"Location: " . $url`, JS/TS `"Location: " + url`.  Returns the
        // left-most literal so prefix-driven gates (`dangerous_prefixes`) can
        // activate on partially-dynamic concatenations; falls through to
        // `None` when the leading segment is not a string literal so
        // exact-`dangerous_values` matching keeps its strict semantics.
        "binary_expression" => {
            let left = arg.child_by_field_name("left")?;
            match left.fkind() {
                "string"
                | "string_literal"
                | "interpreted_string_literal"
                | "raw_string_literal" => {
                    let raw = text_of(left, code)?;
                    if raw.len() >= 2 {
                        Some(raw[1..raw.len() - 1].to_string())
                    } else {
                        None
                    }
                }
                "encapsed_string" => {
                    let mut c = left.walk();
                    let mut buf = String::new();
                    for ch in left.named_children(&mut c) {
                        match ch.fkind() {
                            "string_content" | "escape_sequence" => {
                                if let Some(s) = text_of(ch, code) {
                                    buf.push_str(&s);
                                }
                            }
                            _ => return None,
                        }
                    }
                    Some(buf)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Extract a macro-constant or `define`d identifier name at argument position
/// `index` (0-based).  Used for languages where activation values are
/// preprocessor symbols rather than string literals — currently C, C++, and
/// PHP define-constants like `CURLOPT_POSTFIELDS` whose syntactic form is an
/// `identifier` / `name` node, not a `string`.
///
/// Returns `None` for any non-identifier shape so dynamic-activation
/// semantics still apply when the activation arg is a runtime value
/// (variable, expression, function call).
pub(super) fn extract_const_macro_arg(
    call_node: Node,
    index: usize,
    code: &[u8],
) -> Option<String> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut arg = args.named_children(&mut cursor).nth(index)?;
    if arg.fkind() == "argument" && arg.named_child_count() == 1 {
        if let Some(inner) = arg.named_child(0) {
            arg = inner;
        }
    }
    match arg.fkind() {
        // C/C++ identifier / PHP `name` node for define-style constants.
        // Scoped C++ identifiers (`Curl::OPT_POSTFIELDS`) and PHP namespaced
        // names also surface here so the dangerous_values match catches them.
        "identifier" | "name" | "qualified_name" | "scoped_identifier" => text_of(arg, code),
        // Ruby bare constant (`NOENT`) — leaf form.
        "constant" => text_of(arg, code),
        // Ruby scope-qualified constant (`Nokogiri::XML::ParseOptions::NOENT`).
        // Return only the rightmost `name` segment so the gate's
        // `dangerous_values` list can stay identifier-bare instead of
        // enumerating every possible namespacing.  Falls back to the full
        // text if the `name` field is missing for any reason.
        "scope_resolution" => arg
            .child_by_field_name("name")
            .and_then(|n| text_of(n, code))
            .or_else(|| text_of(arg, code)),
        // Integer literals at the activation arg position.  PHP / C / C++
        // commonly use plain `0` to opt into the safe-default option set
        // (e.g. `simplexml_load_string($xml, "SimpleXMLElement", 0)`).  The
        // gate's `dangerous_values` list is identifier-only, so returning
        // the literal text lets the comparison fail against `LIBXML_NOENT`
        // and suppresses the conservative-fire branch.
        "integer" | "integer_literal" | "number_literal" | "decimal_integer_literal" => {
            text_of(arg, code)
        }
        _ => None,
    }
}

/// Whether `call_node` has a positional argument at `index`.
///
/// Used by the gated-sink activation logic (via
/// [`crate::labels::classify_gated_sink_with_presence`]) to distinguish a
/// **missing** activation argument from a **present-but-dynamic** one.  A
/// `ValueMatch` gate whose activation arg is *absent* must not fire
/// conservatively: the guarded flag / option was never passed, so the call
/// takes the library's default (safe) behaviour.  For example PHP
/// `simplexml_load_string($xml)` / `$dom->loadXML($xml)` with no `$options`
/// literal is XXE-safe (libxml >= 2.9 default), so it should suppress; whereas
/// `loadXML($xml, $dynamicFlags)` (present but dynamic) still fires because the
/// runtime flags could enable entity expansion.
///
/// Mirrors the argument walk in [`extract_const_string_arg`] /
/// [`extract_const_macro_arg`] (`child_by_field_name("arguments")`) so
/// presence stays consistent with the const-extraction those closures do; the
/// `argument_list` fallback errs toward "present" (never a spurious suppress)
/// for any grammar that names the container differently.
pub(super) fn call_has_arg_at(call_node: Node, index: usize) -> bool {
    let Some(args) = call_node
        .child_by_field_name("arguments")
        .or_else(|| call_node.child_by_field_name("argument_list"))
    else {
        return false;
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor).nth(index).is_some()
}

/// Extract the value of a keyword argument from a call node (e.g. Python `shell=True`).
/// Walks argument children looking for `keyword_argument` nodes, matches the keyword
/// name, and extracts the value node text for literals.
pub(super) fn extract_const_keyword_arg(
    call_node: Node,
    keyword_name: &str,
    code: &[u8],
) -> Option<String> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.fkind() == "keyword_argument" || child.fkind() == "named_argument" {
            // keyword_argument has a "name" field and a "value" field in Python tree-sitter
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let Some(name_text) = text_of(name_node, code) else {
                continue;
            };
            if name_text != keyword_name {
                continue;
            }
            let value_node = child.child_by_field_name("value")?;
            if keyword_name == "shell" && !python_literal_is_falsy(value_node, code) {
                // Any truthy value starts a shell (`shell=1`, `shell="yes"`),
                // so only a falsy literal counts as a known value.
                return python_truthy_literal_is_true(value_node, code).then(|| "True".to_string());
            }
            // Only return a literal, identifiers / calls / complex exprs are
            // "dynamic" and must be reported as `None` so the gate can
            // distinguish literal-safe from dynamic.
            return match value_node.fkind() {
                "true" | "false" | "none" | "integer" | "float" | "string" | "string_literal"
                | "identifier" => text_of(value_node, code),
                _ => None,
            }
            .filter(|_| {
                // identifiers are only "literal" when they're the Python
                // booleans True/False/None (tree-sitter-python classifies
                // these as identifiers in older grammar versions).
                match value_node.fkind() {
                    "identifier" => text_of(value_node, code)
                        .as_deref()
                        .is_some_and(|s| matches!(s, "True" | "False" | "None")),
                    _ => true,
                }
            });
        }
    }
    if keyword_name == "shell" {
        // Not given by name: the ninth positional argument of the `subprocess`
        // family, when present.
        return python_positional_shell(call_node, code).flatten();
    }
    None
}

/// Position of `shell` in the positional arguments of `Popen` (and of `run`,
/// `call` and `check_*`, which forward their positionals to it).
const PY_POPEN_SHELL_POSITION: usize = 8;

/// Whether a Python call passes `shell` other than by name, as the ninth
/// positional argument or through a `*args` spread that could hold it.
/// `Some(None)` means present with an unknown value, `Some(Some("True"))` a
/// literal truthy value, and `None` that it is not passed this way.
fn python_positional_shell(call_node: Node, code: &[u8]) -> Option<Option<String>> {
    // Only a Python call: its callee is a `function` field.
    call_node.child_by_field_name("function")?;
    let args = call_node.child_by_field_name("arguments")?;
    if args.fkind() != "argument_list" {
        return None;
    }
    let mut cursor = args.walk();
    let mut pos = 0usize;
    for child in args.named_children(&mut cursor) {
        match child.fkind() {
            "keyword_argument" | "dictionary_splat" | "comment" => {}
            "list_splat" => return Some(None),
            _ => {
                if pos == PY_POPEN_SHELL_POSITION {
                    if python_literal_is_falsy(child, code) {
                        return None;
                    }
                    return Some(
                        python_truthy_literal_is_true(child, code).then(|| "True".to_string()),
                    );
                }
                pos += 1;
            }
        }
    }
    None
}

/// A Python literal that is false in a boolean context.
fn python_literal_is_falsy(node: Node, code: &[u8]) -> bool {
    match node.fkind() {
        "false" | "none" => true,
        "integer" | "float" => text_of(node, code).is_some_and(|t| {
            t.chars()
                .all(|c| matches!(c, '0' | '.' | '_' | 'x' | 'X' | 'b' | 'B' | 'o' | 'O'))
        }),
        "string" => text_of(node, code).is_some_and(|t| {
            let body = t.trim_start_matches(|c: char| c.is_ascii_alphabetic());
            body.len() == 2
        }),
        "identifier" => text_of(node, code).is_some_and(|t| matches!(t.as_str(), "False" | "None")),
        _ => false,
    }
}

/// A truthy value is the literal `True` only when spelled so; any other
/// literal is truthy too but reported as unknown, which the gate also fires on.
fn python_truthy_literal_is_true(node: Node, code: &[u8]) -> bool {
    node.fkind() == "true" || text_of(node, code).is_some_and(|t| t == "True")
}

/// Return `true` if the call node has a keyword/named argument whose name
/// matches `keyword_name` (regardless of whether the value is a literal).
/// Used by gated-sink classification to distinguish an absent kwarg (language
/// default) from a present-but-dynamic kwarg (conservative).
pub(super) fn has_keyword_arg(call_node: Node, keyword_name: &str, code: &[u8]) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.fkind() != "keyword_argument" && child.fkind() != "named_argument" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if text_of(name_node, code).as_deref() == Some(keyword_name) {
            return true;
        }
    }
    // A `**opts` spread may carry `shell`, and so may the ninth positional
    // argument; neither is visible, so the keyword counts as passed with an
    // unknown value.
    keyword_name == "shell"
        && (args
            .named_children(&mut args.walk())
            .any(|c| c.fkind() == "dictionary_splat" && splat_may_carry_shell(c, code))
            || python_positional_shell(call_node, code).is_some())
}

/// Whether a `**value` spread may contain a `shell` key.  A literal dict or a
/// `dict(...)` call whose keys are all visible and none is `shell` cannot; any
/// other value (a variable, a call, a nested spread) might.
fn splat_may_carry_shell(splat: Node, code: &[u8]) -> bool {
    let Some(inner) = splat.named_child(0) else {
        return true;
    };
    let inner = unwrap_parens(inner);
    let mut cursor = inner.walk();
    match inner.fkind() {
        "dictionary" => inner.named_children(&mut cursor).any(|pair| {
            if pair.fkind() != "pair" {
                return true;
            }
            match pair.child_by_field_name("key") {
                Some(key) if key.fkind() == "string" => {
                    const_string_value(key, code).is_none_or(|k| k == "shell")
                }
                _ => true,
            }
        }),
        "call" => {
            let is_dict = inner
                .child_by_field_name("function")
                .and_then(|f| text_of(f, code))
                .is_some_and(|t| t == "dict");
            let Some(args) = inner.child_by_field_name("arguments") else {
                return true;
            };
            !is_dict
                || args.named_children(&mut args.walk()).any(|a| {
                    a.fkind() != "keyword_argument"
                        || a.child_by_field_name("name")
                            .and_then(|n| text_of(n, code))
                            .is_none_or(|n| n == "shell")
                })
        }
        _ => true,
    }
}

/// Extract the literal value of a property `prop_name` from the object
/// literal at positional argument `arg_index`.  Returns `None` if the
/// arg is absent, is not an object literal, the prop key isn't found,
/// or the prop value isn't a literal (so callers can distinguish
/// "present but dynamic" from "absent" only via [`has_object_arg_property`]).
///
/// Used by JS/TS-style "options object as kwargs" gates — e.g.
/// `_.template(tpl, { evaluate: false })` — where the safe-flag lives
/// in an inline object literal rather than as a dedicated kwarg node
/// (which JS does not have).  Strict-additive: returns `None` for any
/// non-JS-object shape, including bare identifiers passed as the
/// options arg, so the gate falls back to the conservative dynamic
/// branch.
pub(super) fn extract_object_arg_property(
    call_node: Node,
    arg_index: usize,
    prop_name: &str,
    code: &[u8],
) -> Option<String> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let arg = args.named_children(&mut cursor).nth(arg_index)?;
    let arg = unwrap_parens(arg);
    if !matches!(arg.fkind(), "object" | "dictionary") {
        return None;
    }
    let mut c = arg.walk();
    for child in arg.named_children(&mut c) {
        if child.fkind() != "pair" {
            continue;
        }
        let Some(key_node) = child.child_by_field_name("key") else {
            continue;
        };
        let key_text = match key_node.fkind() {
            "string" | "string_literal" => text_of(key_node, code).map(|raw| {
                if raw.len() >= 2 {
                    raw[1..raw.len() - 1].to_string()
                } else {
                    raw
                }
            }),
            "computed_property_name" => continue,
            _ => text_of(key_node, code),
        };
        if key_text.as_deref() != Some(prop_name) {
            continue;
        }
        let val_node = child.child_by_field_name("value")?;
        let val_node = unwrap_parens(val_node);
        return match val_node.fkind() {
            "true" | "false" | "null" | "undefined" | "number" | "string" | "string_literal" => {
                text_of(val_node, code)
            }
            // JS booleans true/false are their own node kinds (above), but
            // some grammar versions wrap them as identifier literals; surface
            // `undefined` similarly.
            "identifier" => text_of(val_node, code)
                .filter(|s| matches!(s.as_str(), "true" | "false" | "null" | "undefined")),
            _ => None,
        };
    }
    None
}

/// True when the object literal at positional argument `arg_index` sets
/// `prop_name` and holds no spread element, so no spread can override it.
/// Used where an options object pins a value the callee enforces
/// (`res.sendFile(p, { root })`).
pub(super) fn object_arg_sets_property_without_spread(
    call_node: Node,
    arg_index: usize,
    prop_name: &str,
    code: &[u8],
) -> bool {
    if !has_object_arg_property(call_node, arg_index, prop_name, code) {
        return false;
    }
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(arg) = args.named_children(&mut cursor).nth(arg_index) else {
        return false;
    };
    let arg = unwrap_parens(arg);
    let mut c = arg.walk();
    !arg.named_children(&mut c)
        .any(|child| child.fkind() == "spread_element")
}

/// Return `true` if the call node's positional arg at `arg_index` is an
/// object literal containing a property named `prop_name` (whether the
/// value is a literal or a dynamic expression).  Used alongside
/// [`extract_object_arg_property`] so gated-sink classification can
/// distinguish "options key absent" (language default) from "options
/// key present with dynamic value" (conservative dangerous).
pub(super) fn has_object_arg_property(
    call_node: Node,
    arg_index: usize,
    prop_name: &str,
    code: &[u8],
) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(arg) = args.named_children(&mut cursor).nth(arg_index) else {
        return false;
    };
    let arg = unwrap_parens(arg);
    if !matches!(arg.fkind(), "object" | "dictionary") {
        return false;
    }
    let mut c = arg.walk();
    for child in arg.named_children(&mut c) {
        match child.fkind() {
            "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
                if text_of(child, code).as_deref() == Some(prop_name) =>
            {
                return true;
            }
            "pair" => {
                if let Some(key_node) = child.child_by_field_name("key") {
                    let key_text = match key_node.fkind() {
                        "string" | "string_literal" => text_of(key_node, code).map(|raw| {
                            if raw.len() >= 2 {
                                raw[1..raw.len() - 1].to_string()
                            } else {
                                raw
                            }
                        }),
                        "computed_property_name" => continue,
                        _ => text_of(key_node, code),
                    };
                    if key_text.as_deref() == Some(prop_name) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Inspect the first positional argument of a call node and return its
/// tree-sitter `kind()` plus a flag indicating whether any descendant is an
/// `interpolation` node.  Skips parenthesisation (`(arg0)` is treated as
/// `arg0`).  Returns `None` when the call has no arguments.
///
/// Used by per-language shape-aware sink suppression, for example, Ruby
/// ActiveRecord query methods (`where`, `order`, `pluck`, …) are intrinsically
/// parameterised when arg 0 is a hash/symbol/array/non-interpolated string,
/// regardless of taint reaching that argument.
pub(super) fn arg0_kind_and_interpolation(call_node: Node) -> Option<(String, bool)> {
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let arg0 = args.named_children(&mut cursor).next()?;
    let arg0 = unwrap_ts_value_wrappers(unwrap_parens(arg0));
    let kind = arg0.fkind().to_string();
    let has_interp = subtree_has_interpolation(arg0);
    Some((kind, has_interp))
}

/// Strip TypeScript value-transparent wrappers (`x as T`, `x satisfies T`,
/// `x!`) so the underlying value node's kind is observed.  A cast does not
/// change the runtime value, only its static type, so `db.query(key as UID)`
/// carries the same model-UID reference (`key`, an `identifier`) as
/// `db.query(key)`.  Recurses to handle nested casts.
fn unwrap_ts_value_wrappers(node: Node) -> Node {
    match node.fkind() {
        "as_expression" | "satisfies_expression" | "non_null_expression" => {
            if let Some(inner) = node.named_child(0) {
                return unwrap_ts_value_wrappers(unwrap_parens(inner));
            }
            node
        }
        _ => node,
    }
}

/// Arg-0 shapes that denote a model-UID *reference* for the ORM-accessor chain
/// `<recv>.query(UID).<orm_method>(...)` (e.g. Strapi
/// `strapi.db.query(uid).findMany({...})`,
/// `strapi.db.query(RELEASE_MODEL_UID).findOne({...})`).
///
/// A Strapi / TypeORM model UID handed to `db.query(...)` is a string literal,
/// a const / variable identifier (`uid`, `RELEASE_MODEL_UID`), or a member
/// access (`models.Release`, `this.uid`) — it is *never* a runtime-computed
/// SQL string (`"SELECT " + x` → `binary_expression`, a call, etc.).  What
/// proves the chain is a parameterised ORM accessor is the trailing ORM method
/// (`findMany` / `findOne` / `update` / …), not the literalness of the UID;
/// requiring a string *literal* at arg 0 misses the dominant real-repo shapes
/// where the UID is passed by variable or module constant.  Interpolated
/// templates are still rejected by the `!has_interp` gate at the call site, so
/// a raw `db.query(`SELECT ${x}`)` never reaches here.
pub(super) fn js_orm_query_arg0_is_uid_ref(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_fragment"
            | "template_string"
            | "identifier"
            | "shorthand_property_identifier"
            | "property_identifier"
            | "member_expression"
    )
}

/// Walk a Java method-chain receiver looking for an inner `method_invocation`
/// whose method name matches one of `target_methods` (e.g. `createQuery`,
/// `prepareStatement`).  Returns the kind of that inner call's arg 0, used
/// to verify the SQL-bearing call up-chain was given a string literal rather
/// than a concatenation / method call.
///
/// Conservative: returns `None` when no matching call is found in the chain.
/// Stops drilling into args of an unrelated call, so the chain walk is
/// strictly down the receiver spine.
pub(super) fn java_chain_arg0_kind_for_method(
    expr: Node,
    target_methods: &[&str],
    code: &[u8],
) -> Option<String> {
    let n = unwrap_parens(expr);
    if n.fkind() == "method_invocation"
        && let Some(name_node) = n.child_by_field_name("name")
        && let Some(name) = text_of(name_node, code)
        && target_methods.iter().any(|m| *m == name)
    {
        let args = n.child_by_field_name("arguments")?;
        let mut cursor = args.walk();
        let arg0 = args.named_children(&mut cursor).next()?;
        let arg0 = unwrap_parens(arg0);
        return Some(arg0.fkind().to_string());
    }
    // Drill down the receiver spine.  Java grammar uses `object` for the
    // receiver of a `method_invocation`.
    if n.fkind() == "method_invocation"
        && let Some(recv) = n.child_by_field_name("object")
        && let Some(found) = java_chain_arg0_kind_for_method(recv, target_methods, code)
    {
        return Some(found);
    }
    None
}

/// Decide whether every ActiveRecord query call in a Ruby statement has a
/// parameter-safe argument shape, so the statement may carry a synthesised
/// `Sanitizer(SQL_QUERY)`.
///
/// The CFG node for a Ruby statement stands for the whole expression:
/// `Status.where.not(a: 1).joins(:b).merge(Account.where("n = '#{q}'"))`
/// is one node, and the label machinery may have picked any call in it as the
/// sink.  The synthesised sanitizer clears the whole node, so the proof must
/// cover the whole statement rather than one call:
///
/// * at least one AR query method (`where`, `order`, `group`, `having`,
///   `joins`, `pluck`) call must be present;
/// * every such call must have a safe arg 0 (hash, symbol, array, or a string
///   without interpolation) or no arguments at all (`where` followed by
///   `.not(hash)`; the `not` call is checked like `where`);
/// * no other SQL-labelled call (`find_by_sql`, `execute`, ...) may appear,
///   since the sanitizer would mask it.
///
/// Nested function literals (`do` blocks, lambdas) are separate CFG bodies and
/// are not walked.
pub(super) fn ruby_statement_ar_queries_safe(
    scope: Node,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> bool {
    const AR_QUERY_METHODS: &[&str] = &["where", "order", "group", "having", "joins", "pluck"];
    const AR_FRAGMENT_METHODS: &[&str] = &[
        "update_all",
        "delete_all",
        "destroy_all",
        "reorder",
        "rewhere",
        "select",
        "from",
        "lock",
        "calculate",
        "sum",
        "average",
        "minimum",
        "maximum",
        "count",
        "find_by",
        "exists?",
        "left_joins",
        "left_outer_joins",
    ];
    let mut seen_ar = false;
    let mut stack = vec![scope];
    while let Some(n) = stack.pop() {
        if n.fkind() == "call" {
            let method = n
                .child_by_field_name("method")
                .and_then(|m| text_of(m, code));
            let is_not_on_where = method.as_deref() == Some("not")
                && n.child_by_field_name("receiver")
                    .map(unwrap_parens)
                    .and_then(|r| {
                        (r.fkind() == "call")
                            .then(|| r.child_by_field_name("method"))
                            .flatten()
                    })
                    .and_then(|m| text_of(m, code))
                    .as_deref()
                    == Some("where");
            let ar_method = method
                .as_deref()
                .filter(|m| AR_QUERY_METHODS.contains(m))
                .or(is_not_on_where.then_some("not"));
            if let Some(m) = ar_method {
                seen_ar = true;
                if let Some((kind, has_interp)) = arg0_kind_and_interpolation(n) {
                    let lookup_name = if m == "not" { "where" } else { m };
                    if !crate::labels::ruby::ar_query_safe_shape(lookup_name, &kind, has_interp)
                        && !ruby_arg0_is_inert_value(n, code)
                    {
                        return false;
                    }
                }
            } else if let Some(m) = method {
                // Relation methods that take a SQL fragment but are not in
                // the proven set: `where(a: 1).update_all(params[:set])`.
                // Their calls do not classify as sinks (the receiver
                // segment is the inner `where`), so check the argument
                // shape directly.
                if AR_FRAGMENT_METHODS.contains(&m.as_str())
                    && let Some((kind, has_interp)) = arg0_kind_and_interpolation(n)
                    && !crate::labels::ruby::ar_query_safe_shape("where", &kind, has_interp)
                    && !ruby_arg0_is_inert_value(n, code)
                {
                    return false;
                }
                // Name the call by its own method and the nearest receiver
                // segment only.  `call_ident_of` would fold the whole
                // receiver chain in, so `where(a: 1).delete_all` would read
                // as the AR call it wraps and trip this check.
                let seg = n
                    .child_by_field_name("receiver")
                    .map(unwrap_parens)
                    .and_then(|r| {
                        if r.fkind() == "call" {
                            r.child_by_field_name("method")
                                .and_then(|x| text_of(x, code))
                        } else {
                            text_of(r, code)
                        }
                    });
                // An AR query segment (`where(a: 1).reorder(nil)`) is already
                // judged by its own arg 0 above; folding it into the id would
                // make `where.reorder` match the `where` sink rule.
                let id = match seg {
                    Some(r) if !AR_QUERY_METHODS.contains(&r.as_str()) => format!("{r}.{m}"),
                    _ => m,
                };
                if crate::labels::classify_all("ruby", &id, extra)
                    .iter()
                    .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(Cap::SQL_QUERY)))
                {
                    return false;
                }
            }
        }
        let mut cursor = n.walk();
        for c in n.named_children(&mut cursor) {
            if lookup("ruby", c.fkind()) != Kind::Function {
                stack.push(c);
            }
        }
    }
    seen_ar
}

/// Arg 0 of a Ruby call is a value that cannot carry a SQL fragment: a
/// `nil`/boolean/numeric literal (`reorder(nil)`, `select(1)`) or an Arel
/// expression built from `arel_table` / `Arel` (`reorder(T.arel_table[:n].asc)`),
/// which Active Record renders and quotes itself.
fn ruby_arg0_is_inert_value(call: Node, code: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(arg0) = args.named_children(&mut cursor).next() else {
        return false;
    };
    let arg0 = unwrap_parens(arg0);
    if matches!(arg0.fkind(), "nil" | "true" | "false" | "integer" | "float") {
        return true;
    }
    if matches!(arg0.fkind(), "string" | "binary") && ruby_sql_text_is_static(arg0, code) {
        return true;
    }
    if subtree_has_interpolation(arg0) || !matches!(arg0.fkind(), "call" | "element_reference") {
        return false;
    }
    // Walk the receiver chain looking for `arel_table` or an `Arel` root.
    let mut cur = arg0;
    loop {
        match cur.fkind() {
            "call" => {
                if cur
                    .child_by_field_name("method")
                    .and_then(|m| text_of(m, code))
                    .as_deref()
                    == Some("arel_table")
                {
                    return true;
                }
                match cur.child_by_field_name("receiver") {
                    Some(r) => cur = unwrap_parens(r),
                    None => return false,
                }
            }
            "element_reference" => match cur.child_by_field_name("object") {
                Some(r) => cur = unwrap_parens(r),
                None => return false,
            },
            "scope_resolution" | "constant" => {
                return text_of(cur, code).is_some_and(|t| t == "Arel" || t.starts_with("Arel::"));
            }
            _ => return false,
        }
    }
}

/// A `+` concatenation of string literals whose interpolations are all
/// `Const.table_name` / `Const.quoted_table_name` reads: SQL text built from
/// model metadata, with no request value in it.
fn ruby_sql_text_is_static(n: Node, code: &[u8]) -> bool {
    match n.fkind() {
        "string" => {
            let mut cursor = n.walk();
            n.named_children(&mut cursor).all(|c| match c.fkind() {
                "string_content" | "escape_sequence" => true,
                "interpolation" => {
                    let mut ic = c.walk();
                    let mut inner = c.named_children(&mut ic);
                    match (inner.next(), inner.next()) {
                        (Some(e), None) => ruby_is_table_name_read(e, code),
                        _ => false,
                    }
                }
                _ => false,
            })
        }
        "binary" => {
            n.child_by_field_name("operator")
                .is_some_and(|o| o.fkind() == "+")
                && n.child_by_field_name("left")
                    .zip(n.child_by_field_name("right"))
                    .is_some_and(|(l, r)| {
                        ruby_sql_text_is_static(unwrap_parens(l), code)
                            && ruby_sql_text_is_static(unwrap_parens(r), code)
                    })
        }
        _ => false,
    }
}

fn ruby_is_table_name_read(e: Node, code: &[u8]) -> bool {
    e.fkind() == "call"
        && e.child_by_field_name("arguments").is_none()
        && e.child_by_field_name("method")
            .and_then(|m| text_of(m, code))
            .is_some_and(|m| matches!(m.as_str(), "table_name" | "quoted_table_name"))
        && e.child_by_field_name("receiver")
            .is_some_and(|r| matches!(r.fkind(), "constant" | "scope_resolution"))
}

fn subtree_has_interpolation(n: Node) -> bool {
    if n.fkind() == "interpolation" || n.fkind() == "string_interpolation" {
        return true;
    }
    let mut cursor = n.walk();
    n.named_children(&mut cursor).any(subtree_has_interpolation)
}

/// Walk a JS/TS method-chain receiver-side to find an inner `call_expression`
/// whose member-property name matches one of `target_methods` (e.g. `query`,
/// `execute`).  Returns the `(kind, has_interp)` of that inner call's arg 0.
///
/// Used to recognise ORM-accessor chains where a labelled SQL sink sits on
/// the receiver side of a parameterised execute method:
/// `strapi.db.query('admin::api-token').findOne({...})`.  The outer call
/// (`findOne`) is the CFG node; the inner labelled `db.query` call carries
/// the literal model UID that proves the chain is parameterised.
///
/// Conservative: returns `None` when no matching inner call is found, so
/// callers fall through to the no-suppression path.
pub(super) fn js_chain_arg0_kind_for_method(
    expr: Node,
    target_methods: &[&str],
    code: &[u8],
) -> Option<(String, bool)> {
    let n = unwrap_parens(expr);
    // tree-sitter-typescript / -javascript: call_expression with fields
    // `function` (member_expression / identifier) and `arguments`.
    if n.fkind() == "call_expression" {
        // Check this call's callee: if its property name (or full text) ends
        // with one of `target_methods`, this is the inner labelled call.
        if let Some(function) = n.child_by_field_name("function") {
            // Property of a member_expression; falls back to the function
            // text itself for bare-identifier calls.
            let prop_text = function
                .child_by_field_name("property")
                .and_then(|p| text_of(p, code));
            let full_text = text_of(function, code);
            let leaf_text = full_text
                .as_ref()
                .map(|s| s.rsplit('.').next().unwrap_or(s).to_string());
            let matched = target_methods.iter().any(|m| {
                prop_text.as_deref() == Some(*m)
                    || leaf_text.as_deref() == Some(*m)
                    || full_text.as_deref() == Some(*m)
                    || full_text
                        .as_deref()
                        .is_some_and(|s| s.ends_with(&format!(".{m}")))
            });
            if matched {
                return arg0_kind_and_interpolation(n);
            }
            // Drill down the receiver spine: function.object is the prior
            // call in the chain.
            if let Some(object) = function.child_by_field_name("object")
                && let Some(found) = js_chain_arg0_kind_for_method(object, target_methods, code)
            {
                return Some(found);
            }
        }
    }
    None
}

/// Walk the receiver chain of a JS/TS call to count *non-execute* method
/// calls between the outer call and an inner labelled call to
/// `target_inner` (e.g. `query`, `execute`).  Returns the immediate outer
/// chain method name (e.g. `findOne`) when an inner-call to `target_inner`
/// exists somewhere on the receiver spine, otherwise `None`.
///
/// Used alongside [`js_chain_arg0_kind_for_method`] to verify the chain
/// shape `<inner>.query(LITERAL).<orm_method>(...)`, bare
/// `connection.query("SELECT ...")` returns `None` because there is no
/// outer chain method.
pub(super) fn js_chain_outer_method_for_inner<'a>(
    outer: Node<'a>,
    target_inner: &[&str],
    code: &'a [u8],
) -> Option<String> {
    let n = unwrap_parens(outer);
    if n.fkind() != "call_expression" {
        return None;
    }
    let function = n.child_by_field_name("function")?;
    let object = function.child_by_field_name("object")?;
    // If `object` itself is a call_expression whose property matches
    // `target_inner`, the immediate outer is `function.property`.
    if object.fkind() == "call_expression" {
        let inner_function = object.child_by_field_name("function");
        if let Some(inner_function) = inner_function {
            let prop_text = inner_function
                .child_by_field_name("property")
                .and_then(|p| text_of(p, code));
            let full_text = text_of(inner_function, code);
            let leaf_text = full_text
                .as_ref()
                .map(|s| s.rsplit('.').next().unwrap_or(s).to_string());
            let inner_matched = target_inner.iter().any(|m| {
                prop_text.as_deref() == Some(*m)
                    || leaf_text.as_deref() == Some(*m)
                    || full_text.as_deref() == Some(*m)
                    || full_text
                        .as_deref()
                        .is_some_and(|s| s.ends_with(&format!(".{m}")))
            });
            if inner_matched {
                return function
                    .child_by_field_name("property")
                    .and_then(|p| text_of(p, code));
            }
        }
        // Recurse: outer chain may have more depth (`a.b().c().d()` ,
        // d is outermost, c is next, target may be at b or further in).
        return js_chain_outer_method_for_inner(object, target_inner, code);
    }
    None
}

/// Bounded pre-order DFS over a node subtree for the ORM-accessor call
/// `<recv>.query(UID).<orm_method>(...)`, i.e. the outer call whose receiver
/// spine contains an inner `query` / `execute` call (matched by
/// [`js_chain_outer_method_for_inner`] against `target_inner`).
///
/// More robust than a fixed-depth `find_call_node_deep`, which loses the chain
/// when a wrapper (`(await ...)`, `... > 0`, `... as T`) pushes it past the
/// depth budget, or when a non-ORM outer call (`Promise.all([...])`) is found
/// first and shadows the ORM call nested in its arguments.  Pre-order returns
/// the outermost matching call (`findMany`) before descending into its inner
/// `query(...)` receiver, so the immediate outer ORM method is what surfaces.
/// `budget` bounds the walk so a large statement subtree cannot blow up.
pub(super) fn find_orm_query_chain_call<'a>(
    n: Node<'a>,
    target_inner: &[&str],
    code: &'a [u8],
    budget: &mut u32,
) -> Option<Node<'a>> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    if n.fkind() == "call_expression"
        && js_chain_outer_method_for_inner(n, target_inner, code).is_some()
    {
        return Some(n);
    }
    let mut cursor = n.walk();
    for c in n.children(&mut cursor) {
        if let Some(found) = find_orm_query_chain_call(c, target_inner, code, budget) {
            return Some(found);
        }
    }
    None
}

/// Gated-sink matches for the call `call` whose callee text is `callee`,
/// reading the activation arguments (constants, keywords, presence) from the
/// call itself.  Shared by the chain rebinding and hoisted-sink paths so a
/// gate keyed on `shell=True` is judged against the call that carries it.
pub(super) fn classify_gates_at_call(
    lang: &str,
    callee: &str,
    call: Node,
    code: &[u8],
) -> SmallVec<[crate::labels::GateMatch; 2]> {
    crate::labels::classify_gated_sink_with_presence(
        lang,
        callee,
        |idx| {
            extract_const_string_arg(call, idx, code).or_else(|| {
                if matches!(lang, "c" | "cpp" | "c++" | "php" | "ruby" | "rb") {
                    extract_const_macro_arg(call, idx, code)
                } else {
                    None
                }
            })
        },
        |kw| {
            extract_const_keyword_arg(call, kw, code).or_else(|| {
                if matches!(lang, "javascript" | "typescript") {
                    extract_object_arg_property(call, 1, kw, code)
                } else {
                    None
                }
            })
        },
        |kw| {
            has_keyword_arg(call, kw, code)
                || (matches!(lang, "javascript" | "typescript")
                    && has_object_arg_property(call, 1, kw, code))
        },
        |idx| call_has_arg_at(call, idx),
    )
}

/// Whether `callee` is a gated sink at the chain level `call`: either a gate
/// that fires without inspecting arguments, or one whose activation
/// arguments on `call` itself select it.
pub(super) fn chain_level_is_gated(lang: &str, callee: &str, call: Node, code: &[u8]) -> bool {
    !crate::labels::classify_gated_sink(lang, callee, |_| None, |_| None, |_| false).is_empty()
        || !classify_gates_at_call(lang, callee, call, code).is_empty()
}

/// For a chained method call (`a.b().c().d()`), walk down the receiver
/// chain (`function.object`) and return the innermost call_expression
/// alongside its callee text (e.g. `"http.get"`).
///
/// Returns `None` when:
/// * `outer` is not itself a CallFn / CallMethod node, or
/// * its `function`/`method` field is not a member-style expression whose
///   `object` field is itself a call (i.e. there is no chained receiver).
///
/// Motivated by CVE-2025-64430 (Parse Server SSRF via
/// `http.get(uri, cb).on('error', e => ...)`).  Without this, the outer
/// `.on(...)` call swallows classification of the inner gated sink.
pub(super) fn find_chained_inner_call<'a>(
    outer: Node<'a>,
    lang: &str,
    code: &[u8],
) -> Option<(Node<'a>, String)> {
    if !matches!(lookup_node(lang, outer), Kind::CallFn | Kind::CallMethod) {
        return None;
    }
    let function = outer
        .child_by_field_name("function")
        .or_else(|| outer.child_by_field_name("method"))?;
    // Direct double-call form (`f()(x)`): the outer call's `function`
    // field IS itself a call_expression, with no intermediate
    // member-chain.  Treat the inner call as the chain's innermost.
    // Without this, lodash-style template-render chains like
    // `_.template(t)(data)` evade the chained-inner rebinding because
    // the outer's function field is a `call_expression`, not the
    // `member_expression` shape the original branch below expects.
    if matches!(lookup_node(lang, function), Kind::CallFn | Kind::CallMethod) {
        // Recurse: the inner call may itself be chained.
        if let Some(inner) = find_chained_inner_call(function, lang, code) {
            return Some(inner);
        }
        let inner_func = function
            .child_by_field_name("function")
            .or_else(|| function.child_by_field_name("method"))
            .or_else(|| function.child_by_field_name("name"))?;
        let raw = text_of(inner_func, code)?;
        let inner_text: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        return Some((function, inner_text));
    }
    // The function/method field for a chained call is a member_expression
    // (JS/TS), attribute (Python), or field_expression (Rust); its
    // receiver is the `object` field (JS/TS/Python) or `value` field
    // (Rust).  Only proceed when that receiver is itself a call.
    let object = function
        .child_by_field_name("object")
        .or_else(|| function.child_by_field_name("value"))?;
    if !matches!(lookup_node(lang, object), Kind::CallFn | Kind::CallMethod) {
        return None;
    }
    // Decide whether `object` is itself a chained method call (its
    // function/method field is a member-style expression). When yes,
    // recurse one more level so deeper chains resolve to their innermost
    // method (e.g. `axios.get(u).then(h).catch(h)` → `axios.get`).
    // When no — the receiver is a plain function/constructor call like
    // Rust's `HttpResponse::Found()` — descending one more level would
    // strand us on the non-method leaf whose text would not match any
    // gate matcher. Stop here and return the current `outer` level,
    // which IS the innermost method call.
    let object_function = object
        .child_by_field_name("function")
        .or_else(|| object.child_by_field_name("method"));
    let object_is_chained_method = object_function
        .map(|f| {
            matches!(
                f.fkind(),
                "member_expression"
                    | "attribute"
                    | "field_expression"
                    | "scoped_identifier"
                    | "scope_resolution"
            ) && f
                .child_by_field_name("object")
                .or_else(|| f.child_by_field_name("value"))
                .is_some()
        })
        .unwrap_or(false);
    if object_is_chained_method {
        // Recurse: the inner call may itself be chained.
        if let Some(inner) = find_chained_inner_call(object, lang, code) {
            return Some(inner);
        }
        // `object` is the innermost call_expression in the chain.  Extract
        // its callee identifier the same way `first_call_ident_with_span`
        // does for a CallFn (member_expression text → "http.get").
        let inner_func = object
            .child_by_field_name("function")
            .or_else(|| object.child_by_field_name("method"))
            .or_else(|| object.child_by_field_name("name"))?;
        // Multi-line dotted member expressions (`http\n  .get`) include
        // formatting whitespace in the source-text slice. The labels map
        // keys are literal `"http.get"` etc., strip whitespace so the
        // chained-call inner-gate rebinding fires for both single-line and
        // multi-line chain styles. Also strips `\r` for CRLF sources.
        // Motivated by upstream Parse Server CVE-2025-64430 which uses the
        // multi-line `http\n  .get(uri, ...)\n  .on(...)` form.
        let raw = text_of(inner_func, code)?;
        let inner_text: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        return Some((object, inner_text));
    }
    // Receiver is a non-chained call (Rust constructor `Foo::new()` /
    // `HttpResponse::Found()`, JS bare `f()`).  Outer level IS the
    // innermost method call — return its own function text so gate
    // matching sees the method name.
    let raw = text_of(function, code)?;
    let inner_text: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    Some((outer, inner_text))
}

/// Walk the receiver chain of `outer` (the outer call plus every chained
/// receiver call), from outermost inward, and return the FIRST call whose
/// callee text classifies as a gated sink for `lang`.
///
/// Unlike [`find_chained_inner_call`] — which descends to the
/// structurally-innermost method regardless of what it classifies as —
/// this selects by GATE MATCH, so a gated sink that sits in the MIDDLE of a
/// builder chain is found rather than skipped.
///
/// Motivated by RUSTSEC-2022-0072 (hyper-staticfile open redirect): the
/// redirect Location header is set via
/// `HttpResponseBuilder::new().status(..).header(LOCATION, target).body(..)`,
/// where the gated `header` sink is neither the outermost call (`.body`) nor
/// the structurally-innermost (`.status`).  `find_chained_inner_call`
/// returned `.status`, so the existing rebind dispatch saw no gate and the
/// open-redirect flow was lost.  classify_gated_sink suffix-matches the last
/// dotted segment, so the full member text (e.g. `…status().header`) still
/// resolves to the `header` gate.
pub(super) fn find_chained_gated_sink_call<'a>(
    outer: Node<'a>,
    lang: &str,
    code: &[u8],
) -> Option<(Node<'a>, String)> {
    let mut cur = outer;
    loop {
        if !matches!(lookup_node(lang, cur), Kind::CallFn | Kind::CallMethod) {
            return None;
        }
        let mut function = cur
            .child_by_field_name("function")
            .or_else(|| cur.child_by_field_name("method"))?;
        // Rust turbofish (`sqlx::query_as::<_, User>(..)`): the callee is a
        // `generic_function` wrapping the real path.
        if function.fkind() == "generic_function"
            && let Some(inner) = function.child_by_field_name("function")
        {
            function = inner;
        }
        // Only treat THIS chain level as a candidate sink when its callee is a
        // real member/method access (has an own method-name segment). For an
        // immediately-invoked-call form `f(..)(..)` (e.g. lodash
        // `_.template(t)(data)`), `function` is itself a call_expression with
        // no member segment; the whole-chain text would spuriously normalise
        // to the inner gate, so we must NOT claim the outer application call
        // here — skip it and let the `find_chained_inner_call` fallback bind
        // the real inner call.
        //
        // A Python call through a bare imported name (`Popen(..)` after
        // `from subprocess import Popen`) has an identifier callee, which is
        // the whole callee of this level.
        let has_own_method = function.child_by_field_name("property").is_some()
            || function.child_by_field_name("field").is_some()
            || function.child_by_field_name("attribute").is_some()
            || function.child_by_field_name("name").is_some()
            || (matches!(lang, "python" | "py") && function.fkind() == "identifier");
        // Callee text of THIS chain level: the call's `function`/`method`
        // field text, whitespace-stripped (mirrors `find_chained_inner_call`
        // so the gate's suffix matchers hit on both single- and multi-line
        // chains).
        if has_own_method
            && let Some(raw) = super::helpers::call_fn_callee_text(function, lang, code)
        {
            let callee: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
            if chain_level_is_gated(lang, &callee, cur, code) {
                return Some((cur, callee));
            }
        }
        // Descend to the receiver call, if any.
        let object = function
            .child_by_field_name("object")
            .or_else(|| function.child_by_field_name("value"))
            .or_else(|| function.child_by_field_name("operand"));
        match object {
            Some(o) if matches!(lookup_node(lang, o), Kind::CallFn | Kind::CallMethod) => {
                cur = o;
            }
            _ => return None,
        }
    }
}

/// Recursively walk the receiver chain of `outer` (a CallFn / CallMethod
/// node) and yield each *named argument* of every inner call along the
/// way.  Outer's own arguments are NOT included, the caller already
/// handles those via the standard `pre_emit_arg_source_nodes` pass over
/// `outer.arguments`.
///
/// For `json.NewDecoder(r.Body).Decode(emoji)`:
///   outer  = `.Decode(emoji)`          , caller iterates `emoji`
///   inner  = `json.NewDecoder(r.Body)` , yielded arg: `r.Body`
///
/// We only pull from each inner call's `arguments` field, never from its
/// `function`/`method`/receiver expressions.  That distinction matters
/// because chained source-receivers like `r.URL.Query()` expose a
/// member-text path that classifies as a Source, but it's the OUTER
/// chain text (`r.URL.Query.Get`) that already classifies, so emitting
/// a synth source for the inner-call's own callee would double-count.
///
/// Used by Go (where chain shapes like `json.NewDecoder(r.Body).Decode`
/// hide source-labeled args inside parens between dots, leaving the
/// outer callee text un-classifiable).  The helper itself is
/// language-neutral, but callers should gate per-language until each
/// language's regression coverage catches up.
pub(super) fn walk_chain_inner_call_args<'a>(outer: Node<'a>, lang: &str, out: &mut Vec<Node<'a>>) {
    if !matches!(lookup_node(lang, outer), Kind::CallFn | Kind::CallMethod) {
        return;
    }
    let function = outer
        .child_by_field_name("function")
        .or_else(|| outer.child_by_field_name("method"));
    let Some(function) = function else { return };
    let object = function
        .child_by_field_name("object")
        .or_else(|| function.child_by_field_name("operand"))
        .or_else(|| function.child_by_field_name("value"));
    let Some(inner) = object else { return };
    if !matches!(lookup_node(lang, inner), Kind::CallFn | Kind::CallMethod) {
        return;
    }
    if let Some(args) = inner.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            out.push(arg);
        }
    }
    walk_chain_inner_call_args(inner, lang, out);
}

/// Recursively find a call-expression node within an AST subtree (up to
/// 4 levels deep).  Unlike `find_call_node` which only checks 2 levels,
/// this handles `await`-wrapped calls inside declarations.
///
/// The walk stops at nested blocks and function literals: a call inside a
/// loop / `if` body or a callback is its own CFG node, so it must not stand
/// in for the enclosing statement (a `for` header picking up the gated sink
/// of a `res.setHeader(..)` call in its body).
pub(super) fn find_call_node_deep<'a>(n: Node<'a>, lang: &str, depth: u8) -> Option<Node<'a>> {
    if depth == 0 {
        return None;
    }
    match lookup_node(lang, n) {
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => Some(n),
        _ => {
            let mut cursor = n.walk();
            for c in n.children(&mut cursor) {
                if matches!(lookup_node(lang, c), Kind::Block | Kind::Function) {
                    continue;
                }
                if let Some(found) = find_call_node_deep(c, lang, depth - 1) {
                    return Some(found);
                }
            }
            None
        }
    }
}

/// How a call's first argument relates to the parameterized-query shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParamQueryShape {
    /// Not a `query-with-placeholders, params` call.
    NotParameterized,
    /// Arg 0 is constant query text with placeholders and a params argument
    /// follows.  The driver binds the params, so the sink is safe.
    ConstantQuery,
    /// Same shape, but the query text itself is interpolated
    /// (`f"... ORDER BY {sort} LIMIT ?"`, `"... #{q} ... = ?"`,
    /// `` `... ${t} ... $1` ``).  Binding the params does nothing for the
    /// interpolated part, so arg 0 is still a live injection point while the
    /// bind values are not.
    InterpolatedQuery,
}

/// Classify a call as a parameterized SQL query.
///
/// The call must have at least 2 arguments (query + params), and arg 0 must
/// be a string literal (a template string, an f-string or a Ruby `"#{..}"`
/// string counts) containing SQL placeholder patterns: `$1`..`$N`, `?`,
/// `%s`, or `:identifier`.  Placeholder characters that sit inside an
/// interpolation do not count.
///
/// If arg 0 is a variable, a concatenation or any other expression the result
/// is `NotParameterized`.
pub(super) fn parameterized_query_shape(call_node: Node, code: &[u8]) -> ParamQueryShape {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return ParamQueryShape::NotParameterized;
    };
    let mut cursor = args.walk();
    let named: Vec<_> = args.named_children(&mut cursor).collect();
    // Need at least 2 arguments: query string + params
    if named.len() < 2 {
        return ParamQueryShape::NotParameterized;
    }
    let first_arg = named[0];
    let dynamic = match first_arg.fkind() {
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal" => {
            has_string_interpolation(first_arg)
        }
        "template_string" => {
            let mut c = first_arg.walk();
            first_arg
                .named_children(&mut c)
                .any(|ch| ch.fkind() == "template_substitution")
        }
        // Python implicit concatenation: "SELECT" "..." f"{x}" is one node
        // whose parts are plain or f-strings.
        "concatenated_string" => {
            let mut c = first_arg.walk();
            first_arg
                .named_children(&mut c)
                .any(has_string_interpolation)
        }
        _ => return ParamQueryShape::NotParameterized, // not a literal
    };
    let Some(qt) = text_of(first_arg, code) else {
        return ParamQueryShape::NotParameterized;
    };
    let qt = if dynamic {
        mask_interpolations(first_arg, &qt)
    } else {
        qt
    };
    if !has_sql_placeholders(&qt) {
        return ParamQueryShape::NotParameterized;
    }
    if dynamic {
        ParamQueryShape::InterpolatedQuery
    } else {
        ParamQueryShape::ConstantQuery
    }
}

/// Blank out the source text of every interpolation inside `node`, so a `?`
/// or `:name` that belongs to an embedded expression (`{a if b else c}`,
/// `${x ? y : z}`) is not mistaken for a SQL placeholder.  `text` is the
/// text of `node` itself; offsets are relative to its start byte.
fn mask_interpolations(node: Node, text: &str) -> String {
    fn walk(n: Node, base: usize, out: &mut Vec<(usize, usize)>) {
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            if ch.fkind().contains("interpolation") || ch.fkind() == "template_substitution" {
                out.push((ch.start_byte() - base, ch.end_byte() - base));
            } else {
                walk(ch, base, out);
            }
        }
    }
    let mut spans = Vec::new();
    walk(node, node.start_byte(), &mut spans);
    let mut bytes = text.as_bytes().to_vec();
    for (s, e) in spans {
        if let Some(slice) = bytes.get_mut(s..e.min(text.len())) {
            slice.fill(b' ');
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| text.to_string())
}

/// Check whether a string contains SQL parameterized-query placeholders.
///
/// Recognised patterns:
/// - `$1`, `$2`, …, `$N` (PostgreSQL positional)
/// - `?` (MySQL / SQLite positional)
/// - `%s` (Python DB-API / psycopg2)
/// - `:identifier` (Oracle / named parameters), requires the colon to be
///   preceded by a space or `=` (to avoid matching JS ternary / object
///   literals).
pub(super) fn has_sql_placeholders(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        match bytes[i] {
            b'$' if i + 1 < len && bytes[i + 1].is_ascii_digit() && bytes[i + 1] != b'0' => {
                // $N where N is 1..9 (at minimum)
                return true;
            }
            b'?' => return true,
            b'%' if i + 1 < len && bytes[i + 1] == b's' => {
                return true;
            }
            b':' if i > 0
                && (bytes[i - 1] == b' '
                    || bytes[i - 1] == b'='
                    || bytes[i - 1] == b'('
                    || bytes[i - 1] == b',')
                && i + 1 < len
                && bytes[i + 1].is_ascii_alphabetic() =>
            {
                // :identifier, must be preceded by whitespace/= to avoid
                // false positives on object literals or ternary operators.
                return true;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Returns true when a tree-sitter node is a syntactic literal value.
///
/// Intentionally conservative: if in doubt, returns false. It is better
/// to miss a suppression opportunity than to suppress a real tainted flow.
///
/// NOTE: Literal-kind classification also exists in `ast.rs::is_literal_node`.
/// The two must stay aligned across languages. TODO: consider extracting a
/// shared literal-kind helper if a third call site appears.
#[allow(clippy::only_used_in_recursion)]
pub(super) fn is_syntactic_literal(node: Node, code: &[u8]) -> bool {
    match node.fkind() {
        // Scalar strings, but reject if they contain interpolation
        // (e.g. Ruby `"hello #{name}"`, Python f-strings).
        "string"
        | "string_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "string_content"
        | "string_fragment" => !has_string_interpolation(node),

        // Numbers.  Java's grammar uses radix-tagged kinds
        // (`decimal_integer_literal`, `hex_integer_literal`, …) rather than a
        // bare `integer`, so `int num = 86;` would otherwise miss this arm and
        // lower to `Const(None)` (Varying) instead of `Const("86")`.
        "integer"
        | "integer_literal"
        | "int_literal"
        | "float"
        | "float_literal"
        | "number"
        | "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal"
        | "decimal_floating_point_literal"
        | "hex_floating_point_literal" => true,

        // Booleans / null / nil / none
        "true" | "false" | "null" | "nil" | "none" | "null_literal" | "boolean"
        | "boolean_literal" => true,

        // PHP encapsed_string: safe only if no variable interpolation
        "encapsed_string" => !has_interpolation_cfg(node),

        // Wrapper: PHP/Go wrap each arg in an `argument` node, unwrap
        "argument" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_syntactic_literal(c, code))
        }

        // Unary minus on a number literal: `-42`
        "unary_expression" | "unary_op" => {
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|c| is_syntactic_literal(c, code))
        }

        // String concatenation of literals: `"a" + "b"` or `"a" . "b"`
        "binary_expression" | "concatenated_string" => {
            let count = node.named_child_count();
            count >= 2
                && (0..count).all(|i| {
                    node.named_child(i as u32)
                        .is_some_and(|c| is_syntactic_literal(c, code))
                })
        }

        // JS/TS template string: only if no interpolation substitution
        "template_string" => {
            let mut c = node.walk();
            !node
                .named_children(&mut c)
                .any(|ch| ch.fkind() == "template_substitution")
        }

        // Containers: all elements must be syntactic literals
        "list"
        | "array"
        | "array_expression"
        | "array_creation_expression"
        | "tuple"
        | "tuple_expression" => {
            let mut c = node.walk();
            node.named_children(&mut c)
                .all(|ch| is_syntactic_literal(ch, code))
        }

        // Container entries: `{"key": "value"}` style pairs
        "pair" => {
            let mut c = node.walk();
            node.named_children(&mut c)
                .all(|ch| is_syntactic_literal(ch, code))
        }

        _ => false,
    }
}

/// Check if a string node contains interpolation children
/// (e.g. Ruby `"hello #{name}"` has `interpolation` children,
/// Python f-strings may have `interpolation` children).
pub(super) fn has_string_interpolation(node: Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.fkind().contains("interpolation") {
            return true;
        }
    }
    false
}

/// Check if an encapsed_string node contains interpolation (PHP).
pub(super) fn has_interpolation_cfg(node: Node) -> bool {
    for i in 0..node.child_count() as u32 {
        if let Some(child) = node.child(i) {
            let kind = child.fkind();
            if kind == "variable_name"
                || kind == "simple_variable"
                || kind.contains("interpolation")
            {
                return true;
            }
        }
    }
    false
}

/// Extract the raw literal text from the RHS of a declaration/assignment AST node.
///
/// Walks the same value/right child paths as `def_use` and returns the text
/// if the RHS is a syntactic literal. Used to populate `NodeInfo::const_text`.
pub(super) fn extract_literal_rhs(ast: Node, lang: &str, code: &[u8]) -> Option<String> {
    // Direct value/right field (Rust let, Go short_var, etc.)
    let val_node = ast
        .child_by_field_name("value")
        .or_else(|| ast.child_by_field_name("right"));

    if let Some(val) = val_node {
        if is_syntactic_literal(val, code) {
            return text_of(val, code);
        }
    }

    // Nested declarator pattern (JS let/const → variable_declarator, etc.)
    if matches!(lookup_node(lang, ast), Kind::CallWrapper | Kind::Assignment) {
        let mut cursor = ast.walk();
        for child in ast.children(&mut cursor) {
            let child_val = child.child_by_field_name("value").or_else(|| {
                if matches!(lookup_node(lang, child), Kind::Assignment) {
                    child.child_by_field_name("right")
                } else {
                    None
                }
            });
            // Go `const x = "lit"`: the value is a one-element expression
            // list.  Only `const` is unwrapped; `x := "lit"` and `var x =
            // "lit"` keep their existing, non-constant lowering.
            let child_val = child_val.map(|v| {
                if child.fkind() == "const_spec" && v.fkind() == "expression_list" {
                    v.named_child(0)
                        .filter(|_| v.named_child_count() == 1)
                        .unwrap_or(v)
                } else {
                    v
                }
            });
            if let Some(val) = child_val {
                if is_syntactic_literal(val, code) {
                    return text_of(val, code);
                }
            }
        }
    }

    // Return statement with a literal argument (`return []`, `return {}`).
    // Lets SSA's const-return path ([`crate::ssa::lower`] line ~1066) emit
    // `SsaOp::Const(Some(text))` instead of `Const(None)` so downstream
    // container-literal detection (heap points-to, fresh-alloc summary)
    // can recognise the fresh allocation.
    if matches!(lookup_node(lang, ast), Kind::Return) {
        let mut cursor = ast.walk();
        for child in ast.named_children(&mut cursor) {
            // Go wraps the returned values in an `expression_list`; a single
            // literal in it (`return ""`) is the whole return value, a tuple
            // (`return "", err`) is not.
            let value = if child.fkind() == "expression_list" && child.named_child_count() == 1 {
                child.named_child(0).unwrap_or(child)
            } else {
                child
            };
            if is_syntactic_literal(value, code) {
                return text_of(value, code);
            }
        }
    }

    None
}

/// Returns true when every argument in the call's argument list is a
/// syntactic literal (per `is_syntactic_literal`).  Returns false for a call
/// with no arguments, or when the argument list cannot be found.
///
/// For method chains like `a("x").b(y).c("z")`, the outermost call node
/// represents the entire chain. This function walks nested call expressions
/// to verify ALL argument lists in the chain contain only literals.  Inner
/// chain calls may take no arguments (`Runtime.getRuntime().exec("ls")`).
pub(super) fn has_only_literal_args(call_node: Node, code: &[u8]) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let mut any_arg = false;
    for ch in args.named_children(&mut cursor) {
        any_arg = true;
        if !is_syntactic_literal(ch, code) {
            return false;
        }
    }
    // Zero-arg calls are not "all literal", taint can still flow via a
    // non-literal receiver (e.g. `tainted.readObject()`), and the sink-
    // suppression gate (`info.all_args_literal`) must not skip these.
    if !any_arg {
        return false;
    }
    // Walk nested call expressions in the callee chain.
    check_inner_call_args(call_node, code)
}

/// Recursively check nested call expressions in a method chain for
/// non-literal arguments.
pub(super) fn check_inner_call_args(node: Node, code: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.fkind();
        // Skip argument lists, those are checked by the caller.
        if kind == "arguments" || kind == "argument_list" || kind == "actual_parameters" {
            continue;
        }
        // If this child is itself a call expression, check its arguments.
        if child.child_by_field_name("arguments").is_some() {
            if !inner_call_args_literal(child, code) {
                return false;
            }
        } else {
            // Recurse through non-call structural nodes (field_expression, etc.)
            if !check_inner_call_args(child, code) {
                return false;
            }
        }
    }
    true
}

/// An inner call of a method chain whose arguments, if any, are all
/// syntactic literals, as are those of the calls further down its chain.
/// Unlike the outermost call, a zero-argument inner call qualifies: the
/// receiver-sink guard in [`has_only_literal_args`] is about the call that
/// is the sink, not the calls that build its receiver.
fn inner_call_args_literal(call: Node, code: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    if !args
        .named_children(&mut cursor)
        .all(|ch| is_syntactic_literal(ch, code))
    {
        return false;
    }
    check_inner_call_args(call, code)
}

/// Extract identifiers captured by Rust format-string named-argument syntax
/// (`format!("…{name}…")`, stable since 1.58) from a `macro_invocation`
/// node.  Returns the identifier names referenced by `{name}` /
/// `{name:fmt-spec}` patterns inside the first `string_literal` child of
/// the macro's `token_tree`.
///
/// Without this lifting, `let q = format!("...{x}...")` carries no `x` in
/// its `uses` because `x` lives in the format string's bytes rather than
/// as a separate AST argument node, so taint stops at the macro
/// boundary.  Mirrors the Python f-string interpolation lifting in
/// `patterns/python.rs`.
///
/// Conservative recognition: only fires for known format-style macros
/// (`format`, `print`/`println`, `eprint`/`eprintln`, `write`/`writeln`,
/// `panic`, `format_args`, `assert`/`debug_assert`, the common `log`
/// crate severity macros).  Empty for any non-Rust call node, any other
/// macro, or a token_tree whose first string is not present.
pub(super) fn extract_rust_format_macro_named_idents(call_node: Node, code: &[u8]) -> Vec<String> {
    if call_node.fkind() != "macro_invocation" {
        return Vec::new();
    }
    let Some(macro_node) = call_node.child_by_field_name("macro") else {
        return Vec::new();
    };
    let Some(macro_text) = text_of(macro_node, code) else {
        return Vec::new();
    };
    let leaf = macro_text
        .rsplit("::")
        .next()
        .unwrap_or(macro_text.as_str());
    if !is_rust_format_style_macro(leaf) {
        return Vec::new();
    }
    let tt = match call_node.child_by_field_name("token_tree") {
        Some(t) => t,
        None => {
            let mut cursor = call_node.walk();
            match call_node
                .children(&mut cursor)
                .find(|c| c.fkind() == "token_tree")
            {
                Some(t) => t,
                None => return Vec::new(),
            }
        }
    };
    let mut cursor = tt.walk();
    let fmt_lit = match tt
        .children(&mut cursor)
        .find(|c| matches!(c.fkind(), "string_literal" | "raw_string_literal"))
    {
        Some(n) => n,
        None => return Vec::new(),
    };
    let raw = match text_of(fmt_lit, code) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let content = strip_literal_quotes(&raw, fmt_lit, code).unwrap_or_else(|| raw.clone());
    parse_rust_format_named_idents(&content)
}

/// Walk `n` and any descendants, accumulating named-format-arg idents from
/// every Rust `macro_invocation` reachable through structural expression
/// children (calls, fields, await, references, blocks, ...).  Lets the
/// def-use collectors lift `format!("...{x}...")` named args through one
/// or two levels of expression wrapping (e.g.
/// `let q = format!("{x}").to_owned();` or RHS chained method calls).
pub(super) fn extract_rust_format_macro_named_idents_in(n: Node, code: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    collect_format_macro_idents_recursive(n, code, &mut out, 0);
    out
}

fn collect_format_macro_idents_recursive(n: Node, code: &[u8], out: &mut Vec<String>, depth: u32) {
    if depth > 6 {
        return;
    }
    if n.fkind() == "macro_invocation" {
        for ident in extract_rust_format_macro_named_idents(n, code) {
            out.push(ident);
        }
    }
    let mut cursor = n.walk();
    for child in n.children(&mut cursor) {
        collect_format_macro_idents_recursive(child, code, out, depth + 1);
    }
}

pub(super) fn is_rust_format_style_macro(name: &str) -> bool {
    matches!(
        name,
        "format"
            | "print"
            | "println"
            | "eprint"
            | "eprintln"
            | "write"
            | "writeln"
            | "panic"
            | "format_args"
            | "assert"
            | "debug_assert"
            | "todo"
            | "unimplemented"
            | "unreachable"
            | "info"
            | "warn"
            | "error"
            | "debug"
            | "trace"
    )
}

fn parse_rust_format_named_idents(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                i += 2;
                continue;
            }
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'}' && bytes[j] != b':' {
                j += 1;
            }
            let ident_bytes = &bytes[start..j];
            if is_valid_rust_format_ident(ident_bytes) {
                if let Ok(name) = std::str::from_utf8(ident_bytes) {
                    out.push(name.to_string());
                }
            }
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            i = j + 1;
        } else if b == b'}' && i + 1 < bytes.len() && bytes[i + 1] == b'}' {
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn is_valid_rust_format_ident(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let first = b[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    if b.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// Extract per-argument identifiers from a call node's argument list.
/// Returns one `Vec<String>` per argument (in parameter-position order).
/// Returns empty if argument list can't be found or contains spread/keyword args.
pub(super) fn extract_arg_uses(call_node: Node, code: &[u8]) -> Vec<Vec<String>> {
    // Ruby `subshell` (backticks) has no `arguments` field, its children are
    // string fragments and `interpolation` nodes. Lift each interpolation's
    // identifiers into a positional arg so taint flows from `#{var}` into the
    // synthetic "subshell" sink.
    if call_node.fkind() == "subshell" {
        let mut result = Vec::new();
        let mut cursor = call_node.walk();
        for child in call_node.named_children(&mut cursor) {
            if child.fkind() == "interpolation" {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(child, code, &mut idents, &mut paths);
                let mut combined = paths;
                combined.extend(idents);
                if !combined.is_empty() {
                    result.push(combined);
                }
            }
        }
        return result;
    }

    // Rust `tokio::join!` / `futures::join!` (and their `try_*` variants).
    // tree-sitter-rust models macro args as a `token_tree` rather than an
    // `arguments` field, so a vanilla extraction returns nothing.  Walk the
    // top-level token_tree splitting on `,` separators, lifting identifiers
    // out of each chunk so the existing PromiseCombinator transfer can union
    // arg-side taint into the resulting tuple value.
    if call_node.fkind() == "macro_invocation"
        && let Some(arg_uses) = extract_rust_macro_join_arg_uses(call_node, code)
    {
        return arg_uses;
    }

    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let kind = child.fkind();
        // Named / keyword arguments are tracked separately in `CallMeta.kwargs`
        // and do not participate in positional indexing, skip them here so
        // `arg_uses` remains strictly positional.  Splats (spread/dict splat)
        // still invalidate positional mapping; bail out in that case.
        if kind == "spread_element"
            || kind == "dictionary_splat"
            || kind == "list_splat"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
        {
            return Vec::new();
        }
        if kind == "keyword_argument" || kind == "named_argument" || kind == "block_argument" {
            continue;
        }
        let mut idents = Vec::new();
        let mut paths = Vec::new();
        collect_idents_with_paths(child, code, &mut idents, &mut paths);
        // Dotted paths first, then individual idents as fallback
        let mut combined = paths;
        combined.extend(idents);
        result.push(combined);
    }
    result
}

/// Ruby keyword arguments written at the call site (`f(a, dir: x)`), as
/// `(name, position)` pairs where `position` indexes the call's positional
/// argument list as [`extract_arg_uses`] numbers it.  Ruby passes keywords as
/// a trailing `pair` in the argument list, so each one occupies a positional
/// slot there.  Braced hash literals (`f({dir: x})`) are not keywords and are
/// not listed.  Empty when a splat makes positions unreliable.
pub(super) fn extract_ruby_kw_arg_positions(call_node: Node, code: &[u8]) -> Vec<(String, usize)> {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for (pos, child) in args_node.named_children(&mut cursor).enumerate() {
        match child.fkind() {
            "splat_argument" | "hash_splat_argument" => return Vec::new(),
            "pair" => {
                let Some(key) = child.child_by_field_name("key") else {
                    continue;
                };
                let name = match key.fkind() {
                    "hash_key_symbol" => text_of(key, code),
                    "simple_symbol" => {
                        text_of(key, code).map(|t| t.trim_start_matches(':').to_string())
                    }
                    _ => None,
                };
                if let Some(name) = name {
                    out.push((name, pos));
                }
            }
            _ => {}
        }
    }
    out
}

/// `tokio::join!` / `futures::join!` (and their `try_*` variants) bundle
/// concurrently-awaited futures into a tuple result.  tree-sitter-rust
/// represents the args as a `token_tree` whose children alternate between
/// expressions and `,` separators (`token_tree` itself nests on every
/// parenthesised group, e.g. the `(x)` inside `fetch(x)`).  Walk the
/// top-level token_tree, segment by `,` leaves, and lift identifiers out
/// of each chunk so the SSA Call op carries one positional arg per future.
///
/// Returns `Some(arg_uses)` only when the macro is one of the recognised
/// join macros, so `extract_arg_uses` can fall through to its normal
/// `arguments`-field path for every other macro shape (`format!`,
/// `println!`, custom DSL macros) where arg lifting could disturb existing
/// label / SSA flow.
pub(super) fn extract_rust_macro_join_arg_uses(
    call_node: Node,
    code: &[u8],
) -> Option<Vec<Vec<String>>> {
    let macro_node = call_node.child_by_field_name("macro")?;
    let macro_text = text_of(macro_node, code)?;
    if !is_rust_join_macro(&macro_text) {
        return None;
    }
    let tt = match call_node.child_by_field_name("token_tree") {
        Some(t) => t,
        None => {
            let mut cursor = call_node.walk();
            call_node
                .children(&mut cursor)
                .find(|c| c.fkind() == "token_tree")?
        }
    };
    let mut chunks: Vec<Vec<Node>> = vec![Vec::new()];
    let mut cursor = tt.walk();
    for child in tt.children(&mut cursor) {
        // Skip the surrounding `(`/`)` punctuation.
        if !child.is_named() {
            let kind = child.fkind();
            if kind == "," {
                chunks.push(Vec::new());
                continue;
            }
            if kind == "(" || kind == ")" {
                continue;
            }
        }
        chunks.last_mut().unwrap().push(child);
    }
    let mut result = Vec::new();
    for chunk in chunks {
        if chunk.is_empty() {
            continue;
        }
        let mut idents = Vec::new();
        let mut paths = Vec::new();
        for n in chunk {
            collect_idents_with_paths(n, code, &mut idents, &mut paths);
        }
        let mut combined = paths;
        combined.extend(idents);
        result.push(combined);
    }
    Some(result)
}

fn is_rust_join_macro(macro_text: &str) -> bool {
    matches!(
        macro_text,
        "tokio::join"
            | "tokio::try_join"
            | "futures::join"
            | "futures::try_join"
            | "join"
            | "try_join"
    )
}

/// Extract keyword / named argument bindings for a call node.
///
/// Returns `Vec<(name, uses)>` where `uses` are the identifier references
/// from the keyword's value expression, in the same shape used by
/// `arg_uses` entries.  Empty for calls with no named arguments, or for
/// languages whose grammar does not produce `keyword_argument` / `named_argument`
/// children (C, Java, Go, …).
pub(super) fn extract_kwargs(call_node: Node, code: &[u8]) -> Vec<(String, Vec<String>)> {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let kind = child.fkind();
        // JS/TS object-literal positional arg: `f(x, { a: true, b: 'str' })`.
        // The pairs inside the object are not tree-sitter
        // `keyword_argument` nodes (those are Python/Ruby), but
        // downstream consumers (xml_config's
        // `lookup_kwargs(inst.cfg_node)` JS branch checking
        // `processEntities`) expect these fields in the kwargs vector.
        // Lift each `pair` (and `shorthand_property_identifier`) into
        // the kwargs list using the property name as kwarg name and the
        // raw text of the value expression as the single value.
        // Boolean / numeric / string / identifier values all surface as
        // their textual form, which is what xml_config's kwarg-value
        // matchers (e.g. `v == "true"`) compare against.
        if kind == "object" {
            let mut oc = child.walk();
            for pair in child.named_children(&mut oc) {
                let pk = pair.fkind();
                if pk == "pair" {
                    let Some(kn) = pair.child_by_field_name("key") else {
                        continue;
                    };
                    let Some(vn) = pair.child_by_field_name("value") else {
                        continue;
                    };
                    let Some(raw_name) = text_of(kn, code) else {
                        continue;
                    };
                    let name = raw_name
                        .trim_start_matches(['"', '\''])
                        .trim_end_matches(['"', '\''])
                        .to_string();
                    if let Some(val_text) = text_of(vn, code) {
                        out.push((name, vec![val_text.to_string()]));
                    }
                } else if pk == "shorthand_property_identifier" {
                    if let Some(name) = text_of(pair, code) {
                        out.push((name.to_string(), vec![name.to_string()]));
                    }
                }
            }
            continue;
        }
        if kind != "keyword_argument" && kind != "named_argument" {
            continue;
        }
        // Python `keyword_argument` uses `name`/`value`; Ruby `named_argument`
        // uses `name`/`value` as well (with `:` syntax in source).  Fall back
        // to the first/last named children if fields are absent.
        let named_count = child.named_child_count();
        let name_node = child
            .child_by_field_name("name")
            .or_else(|| child.named_child(0));
        let value_node = child
            .child_by_field_name("value")
            .or_else(|| child.named_child(named_count.saturating_sub(1) as u32));
        let (Some(nn), Some(vn)) = (name_node, value_node) else {
            continue;
        };
        let Some(name) = text_of(nn, code) else {
            continue;
        };
        let mut idents = Vec::new();
        let mut paths = Vec::new();
        collect_idents_with_paths(vn, code, &mut idents, &mut paths);
        let mut combined = paths;
        combined.extend(idents);
        // Boolean / numeric literal kwarg values (Python `True`/`False`,
        // Ruby `true`/`false`/integer/float, JS `true`/`false`/number)
        // do not surface through `collect_idents_with_paths` — the value
        // node's kind is `true`/`false`/`integer`/`float`/`number`, not
        // an identifier kind.  Capture the raw text so consumers like
        // `xml_config::classify_call` (which checks
        // `values.iter().any(|v| v == "True" || v == "true")` for the
        // lxml `resolve_entities=True` opt-in) can match.
        if combined.is_empty() {
            if matches!(
                vn.fkind(),
                "true"
                    | "false"
                    | "integer"
                    | "float"
                    | "number"
                    | "string"
                    | "string_literal"
                    | "true_constant"
                    | "false_constant"
            ) {
                if let Some(txt) = text_of(vn, code) {
                    combined.push(txt.trim_matches(['"', '\'']).to_string());
                }
            }
        }
        out.push((name, combined));
    }
    out
}

/// Caps a literal `search -> replacement` replace is known to strip.
///
/// Policy is deliberately narrow: an arbitrary `.replace("foo", "bar")` is
/// never promoted to a sanitizer, and neither is removing a single injection
/// metacharacter.
///   * `..`, `/`, `\\` in the search: path traversal (`Cap::FILE_IO`)
///   * HTML and SQL: only complete escapes, per
///     [`crate::symex::strings::replace_neutralises`]
///   * shell: never, no single literal covers the metacharacter class
pub(super) fn caps_stripped_by_literal_replace(search: &str, replacement: &str) -> Cap {
    let mut caps = crate::symex::strings::replace_neutralises(search, replacement);
    if search.contains("..") || search.contains('/') || search.contains('\\') {
        caps |= Cap::FILE_IO;
    }
    caps
}

/// True when a replacement literal carries a character that some injection
/// class cares about.  A hop whose replacement does is able to reintroduce
/// what a later hop strips, so the chain detectors abandon all credit.
fn literal_carries_metachars(lit: &str) -> bool {
    lit.contains("..")
        || lit.contains(['/', '\\', '<', '>', ';', '|', '&', '$', '`', '\'', '"'])
        || lit.contains("--")
}

/// Maximum number of `.replace(LIT, LIT)` hops we'll walk on a single chain.
const MAX_REPLACE_CHAIN_HOPS: usize = 16;

/// Recognise a Rust `param.replace(LIT, LIT)[.replace(LIT, LIT)]*` chain whose
/// receiver bottoms out at a plain identifier, and infer which caps the chain
/// provably strips.
///
/// In tree-sitter-rust a method call is encoded as a `call_expression` whose
/// `function` field is a `field_expression` (`receiver.method`). Chained method
/// calls therefore nest `call_expression` nodes recursively through the
/// `field_expression.value` slot.  The detector walks that nest, requiring
/// every hop to be a pure literal-to-literal `replace` / `replacen` call and
/// the innermost receiver to be a bare identifier.  Returns the union of caps
/// stripped across the chain when at least one literal contains a recognised
/// dangerous pattern, or `None` when the pattern doesn't apply (so the caller
/// falls back to normal unresolved-call propagation).
pub(super) fn detect_rust_replace_chain_sanitizer(call_ast: Node, code: &[u8]) -> Option<Cap> {
    fn is_rust_str_literal(k: &str) -> bool {
        matches!(k, "string_literal" | "raw_string_literal")
    }

    fn extract_rust_str_content<'a>(n: Node<'a>, code: &'a [u8]) -> Option<String> {
        // A `string_literal` node in tree-sitter-rust has a `string_content`
        // child that holds the unquoted bytes.  Fall back to whole-node text
        // with outer-character trimming only as a last resort.
        let mut cur = n.walk();
        for c in n.named_children(&mut cur) {
            if c.fkind() == "string_content" {
                return text_of(c, code);
            }
        }
        let raw = text_of(n, code)?;
        if raw.len() >= 2 {
            Some(
                raw.trim_start_matches('r')
                    .trim_start_matches('#')
                    .trim_end_matches('#')
                    .trim_matches('"')
                    .to_string(),
            )
        } else {
            None
        }
    }

    let mut current = call_ast;
    let mut earned = Cap::empty();

    for _ in 0..MAX_REPLACE_CHAIN_HOPS {
        if current.fkind() != "call_expression" {
            // Chain base: must be a plain identifier (parameter / local) to
            // qualify.  A base that's another expression (field access,
            // nested non-method call, …) breaks the sanitizer invariant.
            if current.fkind() == "identifier" && !earned.is_empty() {
                return Some(earned);
            }
            return None;
        }

        // Must be a method-style call: function is a field_expression whose
        // `field` names a `replace`-like method.
        let func = current.child_by_field_name("function")?;
        if func.fkind() != "field_expression" {
            return None;
        }
        let method_ident = func.child_by_field_name("field")?;
        let method_name = text_of(method_ident, code)?;
        if method_name != "replace" && method_name != "replacen" {
            return None;
        }
        // `replacen` stops after n matches, so it strips nothing for sure.
        // It still counts as a hop: its replacement can put a metacharacter
        // back, and the walk has to reach the receiver beneath it.
        let is_global = method_name == "replace";

        let args_node = current.child_by_field_name("arguments")?;
        let mut cursor = args_node.walk();
        let positional: Vec<Node<'_>> = args_node
            .named_children(&mut cursor)
            .filter(|c| {
                !matches!(
                    c.fkind(),
                    "keyword_argument"
                        | "named_argument"
                        | "spread_element"
                        | "list_splat"
                        | "dictionary_splat"
                        | "splat_argument"
                        | "hash_splat_argument"
                )
            })
            .collect();
        let (arg0, arg1) = match positional.as_slice() {
            [a, b, ..] => (*a, *b),
            _ => return None,
        };
        if !is_rust_str_literal(arg0.fkind()) || !is_rust_str_literal(arg1.fkind()) {
            return None;
        }
        let search = extract_rust_str_content(arg0, code)?;
        let replacement = extract_rust_str_content(arg1, code)?;

        // If the replacement itself contains a dangerous sequence, this hop
        // can reintroduce the pattern that a later hop tries to strip.  Be
        // conservative: abandon all credit.
        if literal_carries_metachars(&replacement) {
            return None;
        }
        if is_global {
            earned |= caps_stripped_by_literal_replace(&search, &replacement);
        }

        // Walk to receiver via field_expression.value.
        current = func.child_by_field_name("value")?;
    }

    None
}

/// Recognise a Go `strings.Replace(s, OLD, NEW, n)` /
/// `strings.ReplaceAll(s, OLD, NEW)` call that provably strips one of the
/// known-dangerous metacharacter classes from its first argument.
///
/// Returns the union of caps stripped, or `None` when the pattern doesn't
/// apply (so the caller falls back to normal unresolved-call propagation).
///
/// Mirrors [`detect_rust_replace_chain_sanitizer`] but for the single-call
/// (non-method-chain) Go shape.  The caller wires the resulting cap into
/// the call's [`crate::labels::DataLabel::Sanitizer`] label, which the
/// taint engine consumes via the standard sanitizer pathway, taint flows
/// in on `s`, the matching cap is stripped from the result.
pub(super) fn detect_go_replace_call_sanitizer(call_ast: Node, code: &[u8]) -> Option<Cap> {
    if call_ast.fkind() != "call_expression" {
        return None;
    }
    // The call's `function` field is a `selector_expression`, `operand`
    // is the package ident (`strings`), `field` is the method ident.
    let func = call_ast.child_by_field_name("function")?;
    if func.fkind() != "selector_expression" {
        return None;
    }
    let operand = func.child_by_field_name("operand")?;
    if text_of(operand, code).as_deref() != Some("strings") {
        return None;
    }
    let field = func.child_by_field_name("field")?;
    let method_name = text_of(field, code)?;
    if method_name != "Replace" && method_name != "ReplaceAll" {
        return None;
    }
    // `strings.Replace(s, old, new, n)` only replaces the first n matches.
    // Only n == -1 is a full replace.
    if method_name == "Replace" {
        let args = call_ast.child_by_field_name("arguments")?;
        let mut cursor = args.walk();
        let n_arg = args.named_children(&mut cursor).nth(3)?;
        if text_of(n_arg, code)?.trim() != "-1" {
            return None;
        }
    }
    // Args layout: (s, old, new[, n]).  Need positional args 1 (old) and
    // 2 (new) to be string literals.
    let old_lit = extract_const_string_arg(call_ast, 1, code)?;
    let new_lit = extract_const_string_arg(call_ast, 2, code)?;

    // If the replacement itself reintroduces a dangerous sequence, don't
    // credit the strip, matches the Rust chain detector's policy.
    if literal_carries_metachars(&new_lit) {
        return None;
    }
    let caps = caps_stripped_by_literal_replace(&old_lit, &new_lit);
    if caps.is_empty() { None } else { Some(caps) }
}

/// Like `first_call_ident`, but also checks if `n` itself is a call node.
/// `first_call_ident` only searches children, so when `n` IS the call
/// expression (e.g. the argument `sanitize(cmd)`), this function catches it.
pub(super) fn call_ident_of<'a>(n: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    // C++ new/delete: normalize callee before field extraction.
    if lang == "cpp" && n.fkind() == "new_expression" {
        return Some("new".to_string());
    }
    if lang == "cpp" && n.fkind() == "delete_expression" {
        return Some("delete".to_string());
    }
    match lookup_node(lang, n) {
        Kind::Function => {
            // Function/closure expression passed as argument, return the same
            // synthetic anon name used by build_sub so callback_bindings and
            // source_to_callback can match it to the extracted BodyCfg.
            n.child_by_field_name("name")
                .and_then(|nm| text_of(nm, code))
                .or_else(|| Some(anon_fn_name(n.start_byte())))
        }
        Kind::CallFn => n
            .child_by_field_name("function")
            .or_else(|| n.child_by_field_name("method"))
            .or_else(|| n.child_by_field_name("name"))
            .or_else(|| n.child_by_field_name("type"))
            .or_else(|| find_constructor_type_child(n))
            .and_then(|f| {
                let unwrapped = unwrap_parens(f);
                if lookup_node(lang, unwrapped) == Kind::Function {
                    Some(anon_fn_name(unwrapped.start_byte()))
                } else {
                    text_of(f, code)
                }
            }),
        Kind::CallMethod => {
            let func = n
                .child_by_field_name("method")
                .or_else(|| n.child_by_field_name("name"))
                .and_then(|f| text_of(f, code));
            let recv_node = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("receiver"))
                .or_else(|| n.child_by_field_name("scope"));
            let recv = recv_node.and_then(|f| root_receiver_text(f, lang, code));
            match (recv, func) {
                (Some(r), Some(f)) => Some(format!("{r}.{f}")),
                (_, Some(f)) => Some(f),
                _ => None,
            }
        }
        Kind::CallMacro => n
            .child_by_field_name("macro")
            .and_then(|f| text_of(f, code)),
        _ => first_call_ident(n, lang, code),
    }
}

/// For each argument of `call_node`, return `Some(s)` when the argument is a
/// syntactic string literal (unquoted contents) and `None` otherwise.  The
/// returned vector is parallel to [`extract_arg_uses`] / [`extract_arg_callees`].
///
/// Bails on splats so that a variadic call (`f(*args)`, `f(...xs)`) produces
/// an empty vector, positional indices past the splat are meaningless and
/// downstream passes already treat an empty vector as "no info".
pub(super) fn extract_arg_string_literals(call_node: Node, code: &[u8]) -> Vec<Option<String>> {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let kind = child.fkind();
        // Splat → positional indexing breaks; bail.
        if kind == "spread_element"
            || kind == "dictionary_splat"
            || kind == "list_splat"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
        {
            return Vec::new();
        }
        // Named / keyword arguments are tracked separately in `kwargs` and
        // don't participate in positional indexing, skip them here so this
        // vector stays aligned with `arg_uses`.
        if kind == "keyword_argument" || kind == "named_argument" || kind == "block_argument" {
            continue;
        }
        // PHP wraps each call argument in an `argument` node whose first
        // named child is the actual expression.  Unwrap one level so the
        // string-literal arm below sees the literal directly rather than
        // the wrapper kind, otherwise PHP `f("https://…")` records
        // `None` for arg 0 and downstream prefix-aware suppressions miss.
        let target = if kind == "argument" {
            child.named_child(0).unwrap_or(child)
        } else {
            child
        };
        let target_kind = target.fkind();
        let literal = match target_kind {
            "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            // PHP's double-quoted form (single-quoted maps to `string`).
            // Only safe to lift when there is no `encapsed_string` /
            // `embedded_expression` interpolation child, checked below.
            | "encapsed_string" => {
                let raw = text_of(target, code);
                raw.and_then(|s| strip_literal_quotes(&s, target, code))
            }
            // JS/TS backtick template literal.  A constant string only when it
            // has no `${…}` interpolation (no `template_substitution` child) —
            // an interpolation-free template is byte-for-byte a string literal
            // (`\`SELECT * FROM t\``).  Capturing it lets positional-arg-aware
            // suppressions (SQL-string const check, URL prefix lock) treat the
            // extremely common `sequelize.query(\`…const DDL…\`, { transaction })`
            // migration idiom as the constant it is.  A template WITH
            // interpolation stays `None` (its dynamic parts may carry taint).
            "template_string" => {
                let mut tw = target.walk();
                let has_interp = target
                    .named_children(&mut tw)
                    .any(|c| c.fkind() == "template_substitution");
                if has_interp {
                    None
                } else {
                    text_of(target, code).map(|s| s.trim_matches('`').to_string())
                }
            }
            // Boolean / null / numeric literal tokens — capture verbatim so
            // downstream pattern-aware analysis (e.g. the XXE config-fact
            // pass that needs to read the boolean polarity arg of
            // `setFeature(NAME, true)`) can recover the literal text without
            // re-walking the AST.  Existing string-only consumers (URL
            // prefix matching, etc.) are unaffected: a "true" / "false"
            // token never satisfies their matching predicates.
            "true"
            | "false"
            | "null"
            | "null_literal"
            | "nil"
            | "nil_literal"
            | "none"
            | "boolean_literal"
            | "true_literal"
            | "false_literal"
            | "decimal_integer_literal"
            | "integer_literal"
            | "integer"
            | "number"
            | "number_literal"
            | "decimal_literal" => text_of(target, code),
            _ => None,
        };
        result.push(literal);
    }
    result
}

/// Constant leading text of each positional argument of `call_node`, parallel
/// to [`extract_arg_string_literals`] and `arg_uses`.  `Some(prefix)` when the
/// argument is a string being built from a literal head (`"https://h/" + id`,
/// a template literal, an f-string, a format call) and `None` for plain
/// literals (those are in `arg_string_literals`) and everything else.
pub(super) fn extract_arg_string_prefixes(
    call_node: Node,
    lang: &str,
    code: &[u8],
) -> Vec<Option<String>> {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    // Every prefix starts at a string literal: a quote, a PHP heredoc (`<<<`),
    // a Ruby `%q()` literal, or a Rust macro whose format string is a `const`.
    // Most calls have none of these bytes in their arguments, so they skip the
    // per-argument walk.
    if !code[args_node.byte_range()]
        .iter()
        .any(|b| matches!(b, b'"' | b'\'' | b'`' | b'%' | b'<' | b'!'))
    {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let kind = child.fkind();
        if kind == "spread_element"
            || kind == "dictionary_splat"
            || kind == "list_splat"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
        {
            return Vec::new();
        }
        if kind == "keyword_argument" || kind == "named_argument" || kind == "block_argument" {
            continue;
        }
        result.push(super::arg_prefix_of_expression(child, lang, code));
    }
    if result.iter().all(Option::is_none) {
        return Vec::new();
    }
    result
}

/// Positional arguments of `call_node` that are exactly a name, as the bit
/// mask stored in `CallMeta::arg_bare_names`.  Indexed like
/// [`extract_arg_uses`]: keyword arguments are skipped and a splat clears the
/// whole mask, since positions after it are unknown.
pub(super) fn extract_arg_bare_name_mask(call_node: Node) -> u64 {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return 0;
    };
    let mut mask = 0u64;
    let mut pos = 0usize;
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let kind = child.fkind();
        if matches!(
            kind,
            "spread_element"
                | "dictionary_splat"
                | "list_splat"
                | "splat_argument"
                | "hash_splat_argument"
        ) {
            return 0;
        }
        if kind == "keyword_argument" || kind == "named_argument" || kind == "block_argument" {
            continue;
        }
        if pos < 64 && is_bare_name(child) {
            mask |= 1 << pos;
        }
        pos += 1;
    }
    mask
}

/// The operand of a C / C++ pointer cast `(T *)x`: a pointer cast keeps the
/// value, so `free((char *)p)` still passes `p` whole.
fn c_pointer_cast_operand(node: Node) -> Option<Node> {
    if node.fkind() != "cast_expression" {
        return None;
    }
    let ty = node.child_by_field_name("type")?;
    if ty.fkind() != "type_descriptor" {
        return None;
    }
    let mut w = ty.walk();
    let is_ptr = ty
        .children(&mut w)
        .any(|c| c.fkind() == "abstract_pointer_declarator");
    if is_ptr {
        node.child_by_field_name("value")
    } else {
        None
    }
}

/// True when `node` is an identifier or a member path made only of
/// identifiers, after peeling parentheses and PHP's `argument` wrapper.
fn is_bare_name(node: Node) -> bool {
    let mut cur = node;
    loop {
        if matches!(cur.fkind(), "argument" | "parenthesized_expression") {
            match cur.named_child(0) {
                Some(inner) if cur.named_child_count() == 1 => cur = inner,
                _ => return false,
            }
        } else if let Some(inner) = c_pointer_cast_operand(cur) {
            cur = inner;
        } else {
            break;
        }
    }
    match cur.fkind() {
        "identifier" | "variable_name" | "constant" => true,
        "member_expression"
        | "selector_expression"
        | "attribute"
        | "field_access"
        | "field_expression"
        | "member_access_expression" => {
            let mut w = cur.walk();
            cur.named_children(&mut w).all(|c| {
                matches!(
                    c.fkind(),
                    "property_identifier" | "field_identifier" | "identifier" | "name"
                ) || is_bare_name(c)
            })
        }
        _ => false,
    }
}

/// Strip surrounding quotes from a syntactic string literal, resolving the
/// `string_content` child for Rust-style two-level string nodes.  Returns the
/// raw inner text (no escape-sequence processing), sufficient for whitelist
/// matching against shell-metachar sets.
pub(super) fn strip_literal_quotes(raw: &str, node: Node, code: &[u8]) -> Option<String> {
    // Rust/tree-sitter-rust: `string_literal` wraps a `string_content` child.
    // Prefer the content text so the caller doesn't have to deal with quote
    // pairing for raw strings (`r"..."`, `r#"..."#`, etc.).
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.fkind() == "string_content" {
            return text_of(child, code);
        }
    }
    if raw.len() >= 2 {
        let bytes = raw.as_bytes();
        let first = bytes[0];
        let last = bytes[raw.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return Some(raw[1..raw.len() - 1].to_string());
        }
        // Go raw string: the text between the backticks is the value, with
        // no escapes.  See `extract_arg_raw_string_mask`.
        if first == b'`' && last == b'`' && node.fkind() == "raw_string_literal" {
            return Some(raw[1..raw.len() - 1].to_string());
        }
    }
    None
}

/// Positional arguments of `call_node` that are Go raw string literals, as the
/// bit mask stored in `CallMeta::arg_raw_string_mask`.  A raw literal's
/// recorded text is its value, while an interpreted literal's is the source
/// text with its escapes unread, so a reader of
/// [`extract_arg_string_literals`] needs the mask to tell a raw pair of
/// backslashes from an interpreted escaped backslash (one character).
/// Indexed like [`extract_arg_uses`].
pub(super) fn extract_arg_raw_string_mask(call_node: Node) -> u64 {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return 0;
    };
    let mut mask = 0u64;
    let mut cursor = args_node.walk();
    for (pos, child) in args_node.named_children(&mut cursor).enumerate() {
        if child.fkind() == "variadic_argument" {
            return 0;
        }
        if pos < 64 && child.fkind() == "raw_string_literal" {
            mask |= 1 << pos;
        }
    }
    mask
}

/// For each argument of `call_node`, find the callee name if that argument
/// is itself a call expression (e.g. `sanitize(x)` in `os.system(sanitize(x))`).
/// Returns a `Vec<Option<String>>` parallel to `extract_arg_uses` output.
pub(super) fn extract_arg_callees(call_node: Node, lang: &str, code: &[u8]) -> Vec<Option<String>> {
    // Ruby backticks: one entry per interpolation, parallel to the
    // `subshell` branch of `extract_arg_uses`, so a `#{x.shellescape}`
    // interpolation resolves to its sanitizer callee.
    if call_node.fkind() == "subshell" {
        let mut result = Vec::new();
        let mut cursor = call_node.walk();
        for child in call_node.named_children(&mut cursor) {
            if child.fkind() != "interpolation" {
                continue;
            }
            let mut idents = Vec::new();
            let mut paths = Vec::new();
            collect_idents_with_paths(child, code, &mut idents, &mut paths);
            if idents.is_empty() && paths.is_empty() {
                continue;
            }
            let mut inner = child.walk();
            let callee = child
                .named_children(&mut inner)
                .next()
                .and_then(|e| call_ident_of(e, lang, code));
            result.push(callee);
        }
        return result;
    }
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        // Bail on spread/splat like extract_arg_uses does
        let kind = child.fkind();
        if kind == "block_argument" {
            continue;
        }
        if kind == "spread_element"
            || kind == "dictionary_splat"
            || kind == "list_splat"
            || kind == "keyword_argument"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
            || kind == "named_argument"
        {
            return Vec::new();
        }
        result.push(
            call_ident_of(child, lang, code).or_else(|| ruby_implicit_call_arg(child, lang, code)),
        );
    }
    result
}

thread_local! {
    /// Ruby scope start byte -> every name bound anywhere inside that scope
    /// (see [`ruby_scope_bindings`]).  Per file: cleared by
    /// [`clear_ruby_scope_bindings`] when a file's CFG build starts and ends.
    static RUBY_SCOPE_BINDINGS: RefCell<HashMap<usize, HashSet<String>>> =
        RefCell::new(HashMap::new());
}

/// Drop the per-file Ruby binding cache.
pub(super) fn clear_ruby_scope_bindings() {
    RUBY_SCOPE_BINDINGS.with(|c| c.borrow_mut().clear());
}

/// A bare `identifier` call argument in Ruby is a zero-argument method call
/// (`redirect_to redirect_url`) unless the enclosing scope binds the name as
/// a local, formal, block parameter, `for` / `rescue` variable or pattern
/// capture.  Returns the method name so the argument resolves through the
/// same callee summaries as the parenthesised `redirect_url()` form.
///
/// Names that carry a label of their own (`params`, `session`, `request`)
/// are left to the existing label handling.  The binding check is by name
/// over the whole scope, so a name bound anywhere in it stays a variable:
/// this can only miss a call, never turn a local into one.
pub(super) fn ruby_implicit_call_arg(arg: Node, lang: &str, code: &[u8]) -> Option<String> {
    if lang != "ruby" || arg.fkind() != "identifier" {
        return None;
    }
    let name = text_of(arg, code)?;
    let mut scope = arg.parent()?;
    while !matches!(
        scope.fkind(),
        "method" | "singleton_method" | "class" | "module" | "singleton_class" | "program"
    ) {
        scope = scope.parent()?;
    }
    if ruby_scope_bindings(scope, code, |b| b.contains(&name)) {
        return None;
    }
    if !crate::labels::classify_all("ruby", &name, None).is_empty() {
        return None;
    }
    Some(name)
}

/// Run `query` over the names bound inside the Ruby `scope` node, computing
/// and caching them on first use.
fn ruby_scope_bindings(
    scope: Node,
    code: &[u8],
    query: impl FnOnce(&HashSet<String>) -> bool,
) -> bool {
    RUBY_SCOPE_BINDINGS.with(|cache| {
        let mut cache = cache.borrow_mut();
        let set = cache.entry(scope.start_byte()).or_insert_with(|| {
            let mut out = HashSet::new();
            collect_ruby_bindings(scope, code, &mut out);
            out
        });
        query(set)
    })
}

fn collect_ruby_bindings(n: Node, code: &[u8], out: &mut HashSet<String>) {
    fn add_idents(n: Node, code: &[u8], out: &mut HashSet<String>) {
        if n.fkind() == "identifier"
            && let Some(t) = text_of(n, code)
        {
            out.insert(t);
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            add_idents(ch, code, out);
        }
    }
    let kind = n.fkind();
    match kind {
        "assignment" | "operator_assignment" => {
            if let Some(left) = n.child_by_field_name("left") {
                add_idents(left, code, out);
            }
        }
        "left_assignment_list"
        | "destructured_left_assignment"
        | "rest_assignment"
        | "method_parameters"
        | "block_parameters"
        | "lambda_parameters"
        | "destructured_parameter"
        | "exception_variable" => add_idents(n, code, out),
        "for" => {
            if let Some(pattern) = n.child_by_field_name("pattern") {
                add_idents(pattern, code, out);
            }
        }
        _ if kind.ends_with("_pattern") || kind == "in_clause" => add_idents(n, code, out),
        _ => {}
    }
    let mut c = n.walk();
    for ch in n.children(&mut c) {
        collect_ruby_bindings(ch, code, out);
    }
}

/// `(defines, uses)` of a read-modify-write assignment (`x += y`, `x ||= y`,
/// `i++`).  The target is both the define and a use, and its reads come first
/// in `uses` so SSA lowering sees `x' = op(x, y)` with the old value as the
/// left operand.  A plain `x = y` takes the other `def_use` paths and never
/// lists its target as a use.
fn rmw_def_use(rmw: &RmwAssign, code: &[u8]) -> (Option<String>, Vec<String>) {
    let defs = rmw_target_define(rmw.target, code);
    let mut uses = rmw_target_reads(rmw.target, code);
    if let Some(rhs) = rmw.value {
        let mut idents = Vec::new();
        let mut paths = Vec::new();
        collect_idents_with_paths(rhs, code, &mut idents, &mut paths);
        uses.extend(paths);
        uses.extend(idents);
        uses.extend(extract_rust_format_macro_named_idents_in(rhs, code));
    }
    (defs, uses)
}

/// Primary define and extra defines of a Java / PHP assignment LHS (see
/// [`collect_assign_targets`]).
fn assign_targets(lhs: Node, code: &[u8]) -> (Option<String>, Vec<String>) {
    let mut targets = Vec::new();
    collect_assign_targets(lhs, code, &mut targets);
    let mut it = targets.into_iter();
    (it.next(), it.collect())
}

/// Return `(defines, uses, extra_defines, array_pattern_indices,
/// rhs_array_elements)` for the AST fragment `ast`.
///
/// `extra_defines` captures additional bindings from destructuring patterns
/// beyond the primary define. `array_pattern_indices`, when non-empty, gives
/// the source-order position of each binding in `iter::once(defines).chain(
/// extra_defines)` for `array_pattern` / `tuple_pattern` LHS shapes. Empty
/// for non-array destructures and for non-skip array patterns where callers
/// can derive sequential 0..N indices implicitly.
///
/// `rhs_array_elements`, when non-empty, gives source-order RHS slots for
/// destructure-from-array-literal shapes (`const [a, b] = [safe, tainted]`,
/// `let (a, b) = (safe, tainted)`, Python `a, b = safe, tainted`). Each slot
/// is `Some(ident)` for a bare-ident element or `None` for a syntactic
/// literal. Empty when RHS isn't an array-literal shape or any element is
/// too complex; callers fall back to scalar union in that case.
#[allow(clippy::type_complexity)]
pub(super) fn def_use(
    ast: Node,
    lang: &str,
    code: &[u8],
    extra_labels: Option<&[crate::labels::RuntimeLabelRule]>,
) -> (
    Option<String>,
    Vec<String>,
    Vec<String>,
    SmallVec<[usize; 4]>,
    SmallVec<[crate::cfg::RhsArraySlot; 4]>,
) {
    // Java / PHP member and subscript LHS are split into whole targets
    // (`o.cmd`, `this.fh`, `arr`) instead of being flattened into their
    // component identifiers, which made `o.cmd = x` also redefine a local
    // `cmd` and `$this->fh = ..` define `this`.  Other languages keep their
    // existing split.
    let java_or_php = matches!(lang, "java" | "php");
    match lookup_node(lang, ast) {
        // Declaration wrappers (let, var, short_var_declaration, etc.)
        Kind::CallWrapper => {
            let mut defs = None;
            let mut extra_defs = Vec::new();
            let mut uses = Vec::new();
            let mut pattern_indices: SmallVec<[usize; 4]> = SmallVec::new();
            let mut rhs_array_elements: SmallVec<[crate::cfg::RhsArraySlot; 4]> = SmallVec::new();

            // Try direct field names first (Rust `let_declaration`, Go `short_var_declaration`)
            let def_node = ast
                .child_by_field_name("pattern")
                .or_else(|| ast.child_by_field_name("name"))
                .or_else(|| ast.child_by_field_name("left"))
                // Python `with_item`: value is `as_pattern` whose `alias` holds the target
                .or_else(|| {
                    ast.child_by_field_name("value")
                        .and_then(|v| v.child_by_field_name("alias"))
                });

            let val_node = ast
                .child_by_field_name("value")
                .or_else(|| ast.child_by_field_name("right"));

            if def_node.is_some() || val_node.is_some() {
                if let Some(pat) = def_node {
                    let bindings = collect_array_pattern_bindings_indexed(pat, code);
                    if !bindings.is_empty() {
                        let mut iter = bindings.into_iter();
                        if let Some((first_name, first_idx)) = iter.next() {
                            defs = Some(first_name);
                            pattern_indices.push(first_idx);
                        }
                        for (name, idx) in iter {
                            extra_defs.push(name);
                            pattern_indices.push(idx);
                        }
                    } else if java_or_php {
                        let (d, extra) = assign_targets(pat, code);
                        defs = d;
                        extra_defs.extend(extra);
                    } else {
                        let mut idents = Vec::new();
                        let mut paths = Vec::new();
                        collect_idents_with_paths(pat, code, &mut idents, &mut paths);
                        let first = paths.pop().or_else(|| idents.first().cloned());
                        // Remaining idents are extra defines (for destructuring)
                        for ident in &idents {
                            if first.as_ref() != Some(ident) {
                                extra_defs.push(ident.clone());
                            }
                        }
                        defs = first;
                    }
                }
                if let Some(val) = val_node {
                    let mut idents = Vec::new();
                    let mut paths = Vec::new();
                    collect_idents_with_paths(val, code, &mut idents, &mut paths);
                    uses.extend(paths);
                    uses.extend(idents);
                    // Rust format-string named-arg capture: `let q =
                    // format!("...{x}...")` reads `x`, but `x` lives in
                    // the format-string bytes, not as a separate AST
                    // argument node, so collect_idents misses it.
                    uses.extend(extract_rust_format_macro_named_idents_in(val, code));
                    // When the LHS is a recognised destructure pattern AND
                    // the RHS is a bare array-literal shape (no call), record
                    // per-element idents so the SSA destructure rewrite can
                    // map each binding to its specific RHS slot.
                    if !pattern_indices.is_empty() {
                        rhs_array_elements =
                            collect_rhs_array_literal_elements(val, lang, code, extra_labels);
                    }
                }
            } else {
                // Try nested declarator pattern (JS/TS `lexical_declaration` → `variable_declarator`,
                // Java `local_variable_declaration` → `variable_declarator`,
                // C/C++ `declaration` → `init_declarator`,
                // Python/Ruby `expression_statement` → `assignment`)
                let mut cursor = ast.walk();
                for child in ast.children(&mut cursor) {
                    // Only use left/right fields for actual assignment nodes, binary
                    // expressions also have left/right but are not definitions.
                    let is_assign = matches!(lookup_node(lang, child), Kind::Assignment);
                    // `x += y;` / `x++;` wrapped in an expression statement.
                    if is_assign
                        && defs.is_none()
                        && let Some(rmw) = rmw_assignment(child)
                    {
                        let (d, u) = rmw_def_use(&rmw, code);
                        defs = d;
                        uses.extend(u);
                        continue;
                    }
                    let child_name = child
                        .child_by_field_name("name")
                        .or_else(|| child.child_by_field_name("declarator"))
                        .or_else(|| {
                            if is_assign {
                                child.child_by_field_name("left")
                            } else {
                                None
                            }
                        });
                    let child_value = child.child_by_field_name("value").or_else(|| {
                        if is_assign {
                            child.child_by_field_name("right")
                        } else {
                            None
                        }
                    });

                    // Only treat this child as a declarator if it has BOTH a name
                    // and a value (or at least a value). This prevents method_invocation
                    // nodes (which have a `name` field) from being misinterpreted.
                    if child_value.is_some() {
                        if let Some(name_node) = child_name
                            && defs.is_none()
                        {
                            let bindings = collect_array_pattern_bindings_indexed(name_node, code);
                            if !bindings.is_empty() {
                                let mut iter = bindings.into_iter();
                                if let Some((first_name, first_idx)) = iter.next() {
                                    defs = Some(first_name);
                                    pattern_indices.push(first_idx);
                                }
                                for (name, idx) in iter {
                                    extra_defs.push(name);
                                    pattern_indices.push(idx);
                                }
                            } else if java_or_php {
                                let (d, extra) = assign_targets(name_node, code);
                                defs = d;
                                extra_defs.extend(extra);
                            } else {
                                let mut idents = Vec::new();
                                let mut paths = Vec::new();
                                collect_idents_with_paths(name_node, code, &mut idents, &mut paths);
                                let first = paths.pop().or_else(|| idents.first().cloned());
                                for ident in &idents {
                                    if first.as_ref() != Some(ident) {
                                        extra_defs.push(ident.clone());
                                    }
                                }
                                defs = first;
                            }
                        }
                        if let Some(val_node) = child_value {
                            let mut idents = Vec::new();
                            let mut paths = Vec::new();
                            collect_idents_with_paths(val_node, code, &mut idents, &mut paths);
                            uses.extend(paths);
                            uses.extend(idents);
                            uses.extend(extract_rust_format_macro_named_idents_in(val_node, code));
                            if !pattern_indices.is_empty() && rhs_array_elements.is_empty() {
                                rhs_array_elements = collect_rhs_array_literal_elements(
                                    val_node,
                                    lang,
                                    code,
                                    extra_labels,
                                );
                            }
                        }
                    }
                }

                // Fallback: if still nothing found, collect all idents as uses.
                // This handles expression_statement wrappers.
                if defs.is_none() && uses.is_empty() {
                    let mut idents = Vec::new();
                    let mut paths = Vec::new();
                    collect_idents_with_paths(ast, code, &mut idents, &mut paths);
                    uses.extend(paths);
                    uses.extend(idents);
                    uses.extend(extract_rust_format_macro_named_idents_in(ast, code));
                }
            }
            (defs, uses, extra_defs, pattern_indices, rhs_array_elements)
        }

        // Plain assignment `x = y` or destructuring assignment such as
        // Python `a, b = await asyncio.gather(...)` whose LHS surfaces as
        // a `pattern_list` / `tuple_pattern`. When the LHS is a
        // destructure pattern that the indexed helper recognises, the
        // primary binding lands in `defs`, the rest land in `extra_defs`,
        // and `pattern_indices` carries source-order positions so the
        // SSA lowering's destructure-promise rewrite can paint each
        // binding from the matching combinator argument.
        Kind::Assignment => {
            if let Some(rmw) = rmw_assignment(ast) {
                let (defs, uses) = rmw_def_use(&rmw, code);
                return (defs, uses, Vec::new(), SmallVec::new(), SmallVec::new());
            }
            let mut defs = None;
            let mut extra_defs = Vec::new();
            let mut pattern_indices: SmallVec<[usize; 4]> = SmallVec::new();
            let mut rhs_array_elements: SmallVec<[crate::cfg::RhsArraySlot; 4]> = SmallVec::new();
            let mut uses = Vec::new();
            if let Some(lhs) = ast.child_by_field_name("left") {
                let bindings = collect_array_pattern_bindings_indexed(lhs, code);
                if !bindings.is_empty() {
                    let mut iter = bindings.into_iter();
                    if let Some((first_name, first_idx)) = iter.next() {
                        defs = Some(first_name);
                        pattern_indices.push(first_idx);
                    }
                    for (name, idx) in iter {
                        extra_defs.push(name);
                        pattern_indices.push(idx);
                    }
                } else if java_or_php {
                    let (d, extra) = assign_targets(lhs, code);
                    defs = d;
                    extra_defs.extend(extra);
                } else {
                    let mut idents = Vec::new();
                    let mut paths = Vec::new();
                    collect_idents_with_paths(lhs, code, &mut idents, &mut paths);
                    if let Some(path) = paths.pop() {
                        // Member-expression LHS (`obj.field = ...`): the dotted
                        // path is the sole define; the bare idents it decomposed
                        // into are receiver components, not defines.
                        defs = Some(path);
                    } else if !idents.is_empty() {
                        // Bare multi-target assignment `a, b = rhs` whose LHS is a
                        // plain identifier list — Go's `expression_list` (e.g.
                        // `handle, err = os.Open(p)`). The FIRST identifier is the
                        // primary define and the rest are `extra_defs`, mirroring
                        // the `:=` / CallWrapper arm. Picking the LAST ident
                        // (`idents.pop()`) bound the resource-lifecycle handle to
                        // Go's trailing `err` return — an error value is never a
                        // closeable resource, so every `handle, err = open()`
                        // reported a false `resource-leak` on `err` — and dropped
                        // the real handle (and any taint on it) from the def set
                        // entirely (`val, ok = os.LookupEnv(); sink(val)` lost the
                        // flow to `val`).
                        defs = Some(idents[0].clone());
                        for ident in &idents[1..] {
                            extra_defs.push(ident.clone());
                        }
                    }
                }
            }
            if let Some(rhs) = ast.child_by_field_name("right") {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(rhs, code, &mut idents, &mut paths);
                uses.extend(paths);
                uses.extend(idents);
                uses.extend(extract_rust_format_macro_named_idents_in(rhs, code));
                // When the LHS is a recognised destructure pattern AND the
                // RHS is a bare array-literal shape, record per-element
                // idents so the SSA destructure rewrite can map each
                // binding to its specific RHS slot.
                if !pattern_indices.is_empty() {
                    rhs_array_elements =
                        collect_rhs_array_literal_elements(rhs, lang, code, extra_labels);
                }
            }
            (defs, uses, extra_defs, pattern_indices, rhs_array_elements)
        }

        // if‑let / while‑let, the `let_condition` binds a variable from
        // the value expression.  E.g. `if let Ok(cmd) = env::var("CMD")`
        // defines `cmd` and uses `env`, `var`, `CMD`.
        Kind::If | Kind::While => {
            let cond = find_condition_subtree(ast, lang);
            if let Some(c) = cond
                && c.fkind() == "let_condition"
            {
                let mut defs = None;
                let mut uses = Vec::new();

                if let Some(pat) = c.child_by_field_name("pattern") {
                    let mut tmp = Vec::<String>::new();
                    collect_idents(pat, code, &mut tmp);
                    // The first plain identifier in the pattern is the binding.
                    // Skip type identifiers (e.g. "Ok" in Ok(cmd)), take the
                    // last ident which is the inner binding name.
                    defs = tmp.into_iter().last();
                }
                if let Some(val) = c.child_by_field_name("value") {
                    collect_idents(val, code, &mut uses);
                }
                return (defs, uses, vec![], SmallVec::new(), SmallVec::new());
            }

            // C / C++ `if ((x = getenv("V")) == NULL)` and
            // `while ((c = getc(f)) != EOF)`: the condition assigns, so the
            // header defines the target like the assignment statement would.
            if matches!(lang, "c" | "cpp")
                && let Some(c) = cond
                && let Some(assign) = condition_assignment(c)
            {
                // The target is overwritten, so only the assignment's own
                // reads flow into it: a stale taint on `x` must not survive
                // `if ((x = safe) == NULL)`.
                return def_use(assign, lang, code, extra_labels);
            }

            // The header reads its condition only: the branches and the loop
            // body are lowered as nodes of their own.
            (
                None,
                header_uses(cond, code),
                vec![],
                SmallVec::new(),
                SmallVec::new(),
            )
        }

        Kind::InfiniteLoop => (None, vec![], vec![], SmallVec::new(), SmallVec::new()),

        // for-in / for-of / Python `for x in iter:` ─────────────────────────
        //
        // A for-each loop defines its binding from the iterable
        // (`for_each_parts` maps every grammar's field layout, including Go's
        // `range_clause`, Java `enhanced_for_statement` and PHP `foreach`).
        // Without the define, taint entering the iterable never reaches the
        // body's references to the binding (`for (const [a, b] of obj) {
        // sink(a) }`, OWASP's `for (Cookie c : req.getCookies())`,
        // CVE-2026-41422 daptin's Go `range c.QueryArray("col")`).
        //
        // A C-style three-clause loop has neither part.  Its header reads the
        // init / condition / update clauses but never the body: Go's
        // `for_clause` and Java's `init` are not lowered as nodes of their
        // own, so their identifiers stay on the header.
        Kind::For => {
            let (left, right) = for_each_parts(ast, lang);
            if left.is_none() && right.is_none() {
                let body = ast.child_by_field_name("body");
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                let mut cursor = ast.walk();
                for child in ast.named_children(&mut cursor) {
                    if Some(child) == body || lookup_node(lang, child) == Kind::Block {
                        continue;
                    }
                    collect_idents_with_paths(child, code, &mut idents, &mut paths);
                }
                let mut uses = paths;
                uses.extend(idents);
                return (None, uses, vec![], SmallVec::new(), SmallVec::new());
            }

            let mut defs: Option<String> = None;
            let mut extra_defs: Vec<String> = Vec::new();
            let mut uses: Vec<String> = Vec::new();

            if let Some(pat) = left {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(pat, code, &mut idents, &mut paths);
                let first = paths.pop().or_else(|| idents.first().cloned());
                for ident in &idents {
                    if first.as_ref() != Some(ident) {
                        extra_defs.push(ident.clone());
                    }
                }
                defs = first;
            }
            if let Some(val) = right {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(val, code, &mut idents, &mut paths);
                uses.extend(paths);
                uses.extend(idents);
            }
            (defs, uses, extra_defs, SmallVec::new(), SmallVec::new())
        }

        // Python `elif` / PHP `elseif` guard nodes (their grammar kind maps
        // to `Kind::Block`): the guard reads its condition, not its body.
        _ if matches!(ast.fkind(), "elif_clause" | "else_if_clause") => (
            None,
            header_uses(ast.child_by_field_name("condition"), code),
            vec![],
            SmallVec::new(),
            SmallVec::new(),
        ),

        // everything else – no definition, but may read vars
        _ => {
            // A short-circuit operand of a C / C++ condition that assigns:
            // `(x = getenv("V")) == NULL` inside `a && (x = f()) != NULL`.
            if matches!(lang, "c" | "cpp")
                && matches!(
                    ast.fkind(),
                    "binary_expression" | "parenthesized_expression" | "unary_expression"
                )
                && let Some(assign) = condition_assignment(ast)
            {
                return def_use(assign, lang, code, extra_labels);
            }
            let mut idents = Vec::new();
            let mut paths = Vec::new();
            collect_idents_with_paths(ast, code, &mut idents, &mut paths);
            let mut uses = paths;
            uses.extend(idents);
            (None, uses, vec![], SmallVec::new(), SmallVec::new())
        }
    }
}

/// The plain assignment a C / C++ condition evaluates for its value:
/// `(x = f())`, `(x = f()) == NULL`, `NULL != (x = f())`, `!(x = f())`.
/// Compound assignments (`x += y`) are not matched.
pub(super) fn condition_assignment(cond: Node) -> Option<Node> {
    fn unwrap(mut n: Node) -> Node {
        while n.fkind() == "parenthesized_expression" {
            match n.named_child(0) {
                Some(c) => n = c,
                None => break,
            }
        }
        n
    }
    let n = unwrap(cond);
    match n.fkind() {
        "assignment_expression" => {
            let op = n.child_by_field_name("operator")?;
            (op.fkind() == "=").then_some(n)
        }
        "binary_expression" => {
            let op = n.child_by_field_name("operator")?.fkind();
            if !matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=") {
                return None;
            }
            [
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ]
            .into_iter()
            .flatten()
            .map(unwrap)
            .find_map(|o| {
                let op = o.child_by_field_name("operator")?;
                (o.fkind() == "assignment_expression" && op.fkind() == "=").then_some(o)
            })
        }
        "unary_expression" => {
            let op = n.child_by_field_name("operator")?;
            if op.fkind() != "!" {
                return None;
            }
            condition_assignment(n.child_by_field_name("argument")?)
        }
        _ => None,
    }
}

/// The call on the right-hand side of the assignment a C / C++ condition
/// evaluates, looking through parentheses and casts.
pub(super) fn condition_assigned_call<'a>(cond: Node<'a>, lang: &str) -> Option<Node<'a>> {
    let mut rhs = condition_assignment(cond)?.child_by_field_name("right")?;
    for _ in 0..8 {
        match rhs.fkind() {
            "parenthesized_expression" => rhs = rhs.named_child(0)?,
            "cast_expression" => rhs = rhs.child_by_field_name("value")?,
            _ => break,
        }
    }
    match lookup_node(lang, rhs) {
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => Some(rhs),
        _ => find_call_node(rhs, lang),
    }
}

/// Uses of a branch or loop header: the dotted paths and identifiers of its
/// condition, none when it has no condition.
fn header_uses(cond: Option<Node>, code: &[u8]) -> Vec<String> {
    let Some(cond) = cond else {
        return Vec::new();
    };
    let mut idents = Vec::new();
    let mut paths = Vec::new();
    collect_idents_with_paths(cond, code, &mut idents, &mut paths);
    paths.extend(idents);
    paths
}

/// The calls whose results a method chain passes through, innermost last:
/// for `Popen([...]).wait()` called on `.wait()`, the `Popen([...])` call.
/// Empty when `outer` is not a call on a call.
pub(super) fn chain_receiver_calls<'a>(outer: Node<'a>, lang: &str) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut cur = outer;
    while matches!(lookup_node(lang, cur), Kind::CallFn | Kind::CallMethod) {
        let Some(function) = cur
            .child_by_field_name("function")
            .or_else(|| cur.child_by_field_name("method"))
        else {
            break;
        };
        let Some(object) = function
            .child_by_field_name("object")
            .or_else(|| function.child_by_field_name("value"))
            .or_else(|| function.child_by_field_name("operand"))
        else {
            break;
        };
        if !matches!(lookup_node(lang, object), Kind::CallFn | Kind::CallMethod) {
            break;
        }
        out.push(object);
        cur = object;
    }
    out
}

/// One match from [`extract_shell_array_payload_idents`].
///
/// `arg_position` is the positional argument index of the call where the
/// shell-array literal was found.  `payload_idents` is the union of
/// identifiers (and dotted paths) lifted from the array's payload elements
/// (positions 2+ for POSIX `sh -c <cmd>` form; positions 2+ for `cmd /c <cmd>`
/// likewise).  Empty `payload_idents` means the payload is a constant string,
/// which the caller should treat as benign (no SHELL_ESCAPE finding possible).
#[derive(Debug, Clone)]
pub(super) struct ShellArrayMatch {
    pub arg_position: usize,
    pub payload_idents: Vec<String>,
}

/// Detect inline shell-execution array literals at a call site.
///
/// Recognises the pattern `[<shell>, "-c", <payload>]` (POSIX shells) and
/// `[<cmd-shell>, "/c"|"/C", <payload>]` (Windows `cmd.exe`) appearing as
/// either:
///   * a direct positional argument of `call_node`, or
///   * the value of any field within an object-literal positional argument
///     (covers `container.exec({Cmd: ["bash", "-c", x]})` form).
///
/// Returns one [`ShellArrayMatch`] per detected shell-array.  Empty when the
/// call has no shell-array literals.
///
/// The shell-name list is intentionally narrow (POSIX shells + Windows
/// `cmd.exe`/`powershell`) to avoid false positives on benign array literals
/// like `["ls", "-la"]` or `["git", "rev-parse", "HEAD"]`, where element 0 is
/// not a shell.  Element 1 must be a literal `-c` (POSIX) or `/c`/`/C` (cmd);
/// otherwise the array is not in shell-exec form regardless of element 0.
///
/// The split form `(<shell>, [<flag>, <payload>...])`, where the shell is
/// its own string argument and the next argument is the argv array
/// (`spawn('sh', ['-c', cmd])`, `execFile('/bin/bash', ['-c', cmd])`), is the
/// same shell invocation spelled through an argv-taking API and matches too;
/// its `arg_position` is the argv array's index.
///
/// Identifiers from elements at positions 2+ are lifted via
/// [`collect_idents_with_paths`] so template-literal interpolations
/// (`` `echo ${x}` ``), member-expressions (`obj.field`), and bare idents are
/// all captured.  Dedup is preserved across array elements so a single ident
/// referenced in multiple payload positions appears once.
pub(super) fn extract_shell_array_payload_idents(
    call_node: Node,
    code: &[u8],
) -> Vec<ShellArrayMatch> {
    let mut out = Vec::new();
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return out;
    };
    // `Popen(...)` (Python): the program is the first element of its argv.
    let is_popen = call_node.fkind() == "call"
        && call_node
            .child_by_field_name("function")
            .and_then(|f| text_of(f, code))
            .is_some_and(|t| t == "Popen" || t.ends_with(".Popen"));
    // Shell named by the previous positional argument, for the split form.
    let mut prev_shell: Option<String> = None;
    let mut cursor = args_node.walk();
    for (idx, child) in args_node.named_children(&mut cursor).enumerate() {
        let shell_here = const_string_value(child, code).filter(|s| is_known_shell(s));
        if let Some(shell) = prev_shell.take()
            && let Some(idents) = shell_argv_payload_idents_of(&shell, child, code)
        {
            out.push(ShellArrayMatch {
                arg_position: idx,
                payload_idents: idents,
            });
            continue;
        }
        prev_shell = shell_here;
        let kind = child.fkind();
        // Splats break positional indexing; bail conservatively on the whole call.
        if kind == "spread_element"
            || kind == "list_splat"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
        {
            return Vec::new();
        }
        // `**opts` adds keywords only; it does not shift positions.
        if kind == "dictionary_splat" {
            continue;
        }
        if kind == "keyword_argument" || kind == "named_argument" {
            // Python `Popen(args=[...])` is the first positional argument
            // spelled by name.
            if kind == "keyword_argument"
                && child
                    .child_by_field_name("name")
                    .and_then(|n| text_of(n, code))
                    .as_deref()
                    == Some("args")
                && let Some(value) = child.child_by_field_name("value")
            {
                push_argv_matches(value, 0, is_popen, code, &mut out);
            }
            continue;
        }

        if is_popen && idx == 0 {
            push_argv_matches(child, idx, true, code, &mut out);
            continue;
        }

        // Direct array-literal arg.
        if let Some(idents) = shell_array_payload_idents_of(child, code) {
            out.push(ShellArrayMatch {
                arg_position: idx,
                payload_idents: idents,
            });
            continue;
        }

        // Object-literal arg whose field value is a shell-array literal.
        // Covers `container.exec({Cmd: [...]})` form.  Field name is not
        // restricted to `Cmd` / `cmd`: the shell-shape itself is the gate,
        // and the payload extraction is per-array.
        if matches!(kind, "object" | "dictionary") {
            let mut cc = child.walk();
            for pair in child.named_children(&mut cc) {
                if pair.fkind() != "pair" {
                    continue;
                }
                let Some(val_node) = pair.child_by_field_name("value") else {
                    continue;
                };
                let val_node = unwrap_parens(val_node);
                if let Some(idents) = shell_array_payload_idents_of(val_node, code) {
                    out.push(ShellArrayMatch {
                        arg_position: idx,
                        payload_idents: idents,
                    });
                }
            }
        }
    }
    out
}

/// Record the shell-exec matches of one `Popen` argv argument: a literal
/// `[<shell>, "-c", payload]` runs `payload` as code, and an argv whose
/// program (element 0) is not a string literal runs whatever that value names.
fn push_argv_matches(
    node: Node,
    position: usize,
    is_popen: bool,
    code: &[u8],
    out: &mut Vec<ShellArrayMatch>,
) {
    if let Some(idents) = shell_array_payload_idents_of(node, code) {
        out.push(ShellArrayMatch {
            arg_position: position,
            payload_idents: idents,
        });
        return;
    }
    if !is_popen {
        return;
    }
    let node = unwrap_parens(node);
    if !matches!(node.fkind(), "list" | "tuple") {
        return;
    }
    let mut cursor = node.walk();
    let Some(program) = node.named_children(&mut cursor).next() else {
        return;
    };
    if const_string_value(program, code).is_some() {
        return;
    }
    let mut idents = Vec::new();
    let mut paths = Vec::new();
    collect_idents_with_paths(program, code, &mut idents, &mut paths);
    paths.extend(idents);
    let mut seen = std::collections::HashSet::new();
    paths.retain(|s| seen.insert(s.clone()));
    if !paths.is_empty() {
        out.push(ShellArrayMatch {
            arg_position: position,
            payload_idents: paths,
        });
    }
}

/// If `node` is an array literal of shape `[<shell>, "-c", *]` (POSIX shells)
/// or `[<cmd-shell>, "/c", *]` (Windows cmd.exe), return the identifiers
/// referenced in the payload elements (positions 2+).  Otherwise return
/// `None`.  Returning `Some(vec![])` means the payload is a constant string
/// — caller should still skip emitting a sink (no taint can reach a literal).
fn shell_array_payload_idents_of(node: Node, code: &[u8]) -> Option<Vec<String>> {
    let node = unwrap_parens(node);
    if !matches!(node.fkind(), "array" | "list" | "tuple") {
        return None;
    }
    // Walk named children to skip commas and other trivia.
    let mut cursor = node.walk();
    let elems: Vec<Node> = node.named_children(&mut cursor).collect();
    if elems.len() < 3 {
        return None;
    }
    // The program: a literal shell or interpreter, reached through any
    // wrapper (`env bash -c x`, `sudo -u root sh -c x`, `timeout 5 sh -c x`).
    let mut prog_idx = 0;
    let mut program = const_string_value(elems[0], code)?;
    if crate::labels::is_wrapper_command(&program) {
        let mut found = None;
        for (j, e) in elems.iter().enumerate().skip(1) {
            let word = const_string_value(*e, code)?;
            if crate::labels::is_command_runner_program(&word)
                && !crate::labels::is_wrapper_command(&word)
            {
                found = Some((j, word));
                break;
            }
        }
        (prog_idx, program) = found?;
    } else if !crate::labels::is_command_runner_program(&program) {
        return None;
    }
    // The switch that runs the next word as code, possibly after other
    // literal options (`bash -x -c`, `cmd /s /c`).
    let mut flag_idx = None;
    for (j, e) in elems.iter().enumerate().skip(prog_idx + 1) {
        let word = const_string_value(*e, code)?;
        if crate::labels::is_code_flag(&program, &word) {
            flag_idx = Some(j);
            break;
        }
        let is_option = word.starts_with("--")
            || ((word.starts_with('-') || word.starts_with('/')) && word.len() <= 3);
        if !is_option {
            return None;
        }
    }
    shell_payload_idents(&elems[flag_idx? + 1..], code)
}

/// Number of positional arguments a JS/TS call passes, counted the way
/// [`extract_arg_uses`] indexes them, or `None` when a spread argument
/// (`f(...args)`) hides the real arity.
pub(super) fn js_positional_arity(call_node: Node) -> Option<usize> {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return Some(0);
    };
    let mut cursor = args.walk();
    let mut arity = 0;
    for arg in args.named_children(&mut cursor) {
        if arg.fkind() == "spread_element" {
            return None;
        }
        arity += 1;
    }
    Some(arity)
}

/// Positional argument count of a Python call, or `None` when a `*args` /
/// `**kwargs` splat can supply arguments the call text does not show.
/// Keyword arguments do not count.
pub(super) fn python_positional_arity(call_node: Node) -> Option<usize> {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return Some(0);
    };
    if args.fkind() != "argument_list" {
        return None;
    }
    let mut cursor = args.walk();
    let mut arity = 0;
    for arg in args.named_children(&mut cursor) {
        match arg.fkind() {
            "list_splat" | "dictionary_splat" => return None,
            "keyword_argument" | "comment" => {}
            _ => arity += 1,
        }
    }
    Some(arity)
}

/// True when the positional argument at `index` of a JS/TS call is a
/// string by construction, the shape a string-evaluating timer
/// (`setTimeout(code, ms)`) compiles:
///
/// * a string or template literal, or a `+` concatenation;
/// * a member read that classifies as a taint Source (`req.query.code`,
///   `location.hash`);
/// * a call to a string-producing method or global
///   ([`JS_STRING_METHODS`], [`JS_STRING_FUNCTIONS`]), as in
///   `location.hash.substring(1)`;
/// * a local name whose nearest declaration initialises it with one of the
///   above.
///
/// Everything else (a function reference, a parameter, an arbitrary call
/// result) is not evidence of a string: timers almost always receive a
/// callback.
pub(super) fn js_arg_is_string_valued(
    call_node: Node,
    index: usize,
    lang: &str,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(arg) = args.named_children(&mut cursor).nth(index) else {
        return false;
    };
    js_expr_is_string_valued(arg, lang, code, extra, 3)
}

/// Tags whose `${}` substitutions are sent as bind parameters: Prisma's
/// `$queryRaw` / `$executeRaw` and the `sql` tag of drizzle, `Prisma.sql`,
/// `@vercel/postgres`, `postgres` and slonik.
const PARAMETERIZED_SQL_TAGS: &[&str] = &["$queryRaw", "$executeRaw", "sql", "SQL"];

/// Helpers that splice their argument into a parameterized SQL template as
/// raw text (`Prisma.raw(x)`, `sql.raw(x)`, `raw(x)`, `sql.unsafe(x)`).
const RAW_SQL_SPLICE_HELPERS: &[&str] = &["raw", "unsafe"];

/// Module specifiers whose `sql` / `Prisma` / `raw` exports build parameterized
/// SQL. A tag or helper counts only when its root name comes from one of
/// these, directly or through a client built from one
/// (`const sql = postgres(url)`): a user-defined `sql` tag that concatenates
/// its substitutions is not parameterized.
fn is_sql_template_library(spec: &str) -> bool {
    const LIBS: &[&str] = &[
        "drizzle-orm",
        "@prisma/client",
        "@vercel/postgres",
        "@neondatabase/serverless",
        "postgres",
        "slonik",
        "kysely",
        "sql-template-strings",
        "@databases/",
    ];
    LIBS.iter().any(|l| {
        spec == *l
            || (l.ends_with('/') && spec.starts_with(l))
            || spec.strip_prefix(l).is_some_and(|r| r.starts_with('/'))
    })
}

/// True when the name `name` used under `node` is bound by an import from a
/// parameterized-SQL library, or by a top-level `const name = f(..)` where
/// `f` is such an import.
fn js_name_is_sql_library_binding(node: Node, name: &str, code: &[u8]) -> bool {
    if crate::ssa::type_facts::file_import_path(name)
        .as_deref()
        .is_some_and(is_sql_template_library)
    {
        return true;
    }
    js_top_level_statements(node)
        .into_iter()
        .flat_map(|stmt| {
            let mut c = stmt.walk();
            stmt.named_children(&mut c).collect::<Vec<_>>()
        })
        .filter(|d| d.fkind() == "variable_declarator")
        .any(|d| {
            d.child_by_field_name("name")
                .and_then(|n| text_of(n, code))
                .is_some_and(|n| n == name)
                && d.child_by_field_name("value").is_some_and(|v| {
                    let v = unwrap_parens(v);
                    v.fkind() == "call_expression"
                        && v.child_by_field_name("function")
                            .map(unwrap_parens)
                            .and_then(|f| text_of(f, code))
                            .is_some_and(|f| {
                                let root_name = f.split('.').next().unwrap_or(&f);
                                crate::ssa::type_facts::file_import_path(root_name)
                                    .as_deref()
                                    .is_some_and(is_sql_template_library)
                            })
                })
        })
}

/// Top-level statements of the file that holds `node`, with an
/// `export const ..` / `export function ..` read as its declaration.
fn js_top_level_statements(node: Node) -> Vec<Node> {
    let mut root = node;
    while let Some(p) = root.parent() {
        root = p;
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .map(|stmt| {
            if stmt.fkind() == "export_statement" {
                stmt.child_by_field_name("declaration").unwrap_or(stmt)
            } else {
                stmt
            }
        })
        .collect()
}

/// True when `name` is a function the file defines itself at top level:
/// `function sql(..) {..}` or `const sql = (..) => ..`.
fn js_name_is_local_function(node: Node, name: &str, code: &[u8]) -> bool {
    js_top_level_statements(node)
        .into_iter()
        .any(|stmt| match stmt.fkind() {
            "function_declaration" | "generator_function_declaration" => stmt
                .child_by_field_name("name")
                .and_then(|n| text_of(n, code))
                .is_some_and(|n| n == name),
            "lexical_declaration" | "variable_declaration" => {
                let mut c = stmt.walk();
                stmt.named_children(&mut c).any(|d| {
                    d.fkind() == "variable_declarator"
                        && d.child_by_field_name("name")
                            .and_then(|n| text_of(n, code))
                            .is_some_and(|n| n == name)
                        && d.child_by_field_name("value")
                            .map(unwrap_parens)
                            .is_some_and(|v| {
                                matches!(
                                    v.fkind(),
                                    "arrow_function" | "function_expression" | "function"
                                )
                            })
                })
            }
            _ => false,
        })
}

/// Roots of a parameterized SQL template API (`sql\`..\``, `sql.raw(..)`,
/// `Prisma.sql`, `Prisma.raw(..)`).
const SQL_TEMPLATE_ROOTS: &[&str] = &["sql", "SQL", "Prisma"];

/// True when the `sql` / `SQL` / `Prisma` root of a SQL template is not the
/// file's own function. An import (from a SQL library, or from a project
/// module that re-exports one) and a client value (`const sql = postgres(url)`)
/// are trusted to bind their substitutions; a tag the file defines as a
/// function may concatenate them.
fn js_sql_template_root_is_library(node: Node, name: &str, code: &[u8]) -> bool {
    !js_name_is_local_function(node, name, code)
}

/// True when the callee text `callee` of a call under `node` is a raw-text
/// splice of a SQL library: `Prisma.raw`, `sql.raw`, `sql.unsafe`, or a bare
/// `raw` / `unsafe` imported from one.
fn is_sql_raw_splice_callee(node: Node, callee: &str, code: &[u8]) -> bool {
    let callee: String = callee.chars().filter(|c| !c.is_whitespace()).collect();
    let mut parts = callee.split('.');
    let (Some(first), second, None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let leaf = second.unwrap_or(first);
    if !RAW_SQL_SPLICE_HELPERS.contains(&leaf) {
        return false;
    }
    if second.is_some() && SQL_TEMPLATE_ROOTS.contains(&first) {
        return js_sql_template_root_is_library(node, first, code);
    }
    js_name_is_sql_library_binding(node, first, code)
}

/// Raw-text splices of a JS/TS tagged SQL template, or `None` when `call` is
/// not a tagged template with a parameterizing tag
/// ([`PARAMETERIZED_SQL_TAGS`]).  A call with parentheses
/// (`prisma.$queryRaw(text)`) is not a tagged template and returns `None`.
///
/// The first vector lists the positional indices (as
/// [`extract_arg_uses`] numbers the template's children) of substitutions
/// that contain a raw splice; the second the identifiers inside those
/// splices' arguments.  Both are empty when every substitution is bound as a
/// parameter.
pub(super) fn js_sql_template_raw_splices(
    call: Node,
    code: &[u8],
) -> Option<(Vec<usize>, Vec<String>)> {
    if call.fkind() != "call_expression" {
        return None;
    }
    let template = call.child_by_field_name("arguments")?;
    if template.fkind() != "template_string" {
        return None;
    }
    let tag: String = text_of(call.child_by_field_name("function")?, code)?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let leaf = tag.rsplit('.').next().unwrap_or(&tag);
    if !PARAMETERIZED_SQL_TAGS.contains(&leaf) {
        return None;
    }
    // Prisma's `$queryRaw` / `$executeRaw` are method names of its client.
    // `sql` / `SQL` are ordinary identifiers, so a tag the file defines as
    // its own function is not trusted: it may concatenate.
    if !leaf.starts_with('$') {
        let root_name = tag.split('.').next().unwrap_or(&tag);
        if !js_sql_template_root_is_library(call, root_name, code) {
            return None;
        }
    }
    let mut positions = Vec::new();
    let mut idents = Vec::new();
    let mut cursor = template.walk();
    for (pos, child) in template.named_children(&mut cursor).enumerate() {
        if child.fkind() != "template_substitution" {
            continue;
        }
        let mut found = false;
        collect_raw_sql_splice_idents(child, code, &mut idents, &mut found);
        if found {
            positions.push(pos);
        }
    }
    Some((positions, idents))
}

fn collect_raw_sql_splice_idents(n: Node, code: &[u8], out: &mut Vec<String>, found: &mut bool) {
    if n.fkind() == "call_expression"
        && let Some(func) = n.child_by_field_name("function")
        && let Some(text) = text_of(func, code)
        && is_sql_raw_splice_callee(n, &text, code)
        && let Some(args) = n.child_by_field_name("arguments")
    {
        *found = true;
        let mut idents = Vec::new();
        let mut paths = Vec::new();
        collect_idents_with_paths(args, code, &mut idents, &mut paths);
        for name in paths.into_iter().chain(idents) {
            if !out.contains(&name) {
                out.push(name);
            }
        }
        return;
    }
    let mut cursor = n.walk();
    for child in n.named_children(&mut cursor) {
        collect_raw_sql_splice_idents(child, code, out, found);
    }
}

/// True when the positional argument at `index` of a query-builder call
/// `method` is a value the builder turns into parameterized SQL itself.
///
/// Condition methods (`where`, `andWhere`, `orWhere`, `having` and their
/// variants) take an object of bound values, a callback, or a
/// `new Brackets(..)` / `new NotBrackets(..)` group. The other methods
/// (`orderBy`, `groupBy`, `select`, ...) put object keys into the SQL text as
/// column names, so an object counts only when every key is a static name;
/// a computed key or a spread leaves the column attacker-controlled. A
/// callback or any other `new` expression is not structured for them.
pub(super) fn js_arg_is_structured_condition(
    call_node: Node,
    index: usize,
    method: &str,
    code: &[u8],
) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(arg) = args
        .named_children(&mut cursor)
        .nth(index)
        .map(unwrap_parens)
    else {
        return false;
    };
    let is_condition_method = matches!(
        method,
        "where" | "andWhere" | "orWhere" | "having" | "andHaving" | "orHaving"
    );
    match arg.fkind() {
        "object" if is_condition_method => true,
        // TypeORM writes the values too (`orderBy({ 'u.name': dir })` puts
        // `dir` after the column), so they must be static as well.
        "object" => js_object_is_static(arg),
        "arrow_function" | "function_expression" | "function" => is_condition_method,
        "new_expression" => {
            is_condition_method
                && arg
                    .child_by_field_name("constructor")
                    .and_then(|f| text_of(f, code))
                    .is_some_and(|t| {
                        matches!(t.rsplit('.').next(), Some("Brackets" | "NotBrackets"))
                    })
        }
        _ => false,
    }
}

/// True when an object literal has only static keys and static values: string,
/// number or substitution-free template literals, or nested objects of the
/// same (`{ 'u.name': 'ASC' }`, `{ id: { order: 'DESC', nulls: 'NULLS LAST' } }`).
fn js_object_is_static(obj: Node) -> bool {
    let mut c = obj.walk();
    obj.named_children(&mut c).all(|pair| match pair.fkind() {
        "pair" => {
            pair.child_by_field_name("key")
                .is_some_and(|k| matches!(k.fkind(), "property_identifier" | "string" | "number"))
                && pair
                    .child_by_field_name("value")
                    .map(unwrap_parens)
                    .is_some_and(|v| match v.fkind() {
                        "string" | "number" => true,
                        "template_string" => {
                            let mut tc = v.walk();
                            v.named_children(&mut tc)
                                .all(|ch| ch.fkind() != "template_substitution")
                        }
                        "object" => js_object_is_static(v),
                        _ => false,
                    })
        }
        "comment" => true,
        _ => false,
    })
}

/// True when the positional argument at `index` of a JS/TS call names an
/// object's prototype: `Foo.prototype`, `x.__proto__`, `x['__proto__']`, or
/// `Object.getPrototypeOf(x)` / `Reflect.getPrototypeOf(x)`.  Properties
/// written into such a target are inherited by every object built from it,
/// which is what a shallow `Object.assign` needs to pollute a prototype.
pub(super) fn js_arg_is_prototype_object(call_node: Node, index: usize, code: &[u8]) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(arg) = args.named_children(&mut cursor).nth(index) else {
        return false;
    };
    let arg = unwrap_parens(arg);
    match arg.fkind() {
        "member_expression" => arg
            .child_by_field_name("property")
            .and_then(|p| text_of(p, code))
            .is_some_and(|p| p == "prototype" || p == "__proto__"),
        "subscript_expression" => arg
            .child_by_field_name("index")
            .and_then(|i| const_string_value(i, code))
            .is_some_and(|k| k == "prototype" || k == "__proto__"),
        "call_expression" => arg
            .child_by_field_name("function")
            .and_then(|f| text_of(f, code))
            .is_some_and(|f| {
                matches!(
                    f.as_str(),
                    "Object.getPrototypeOf" | "Reflect.getPrototypeOf"
                )
            }),
        _ => false,
    }
}

/// String-returning `String.prototype` / `Array.prototype.join` methods.
const JS_STRING_METHODS: &[&str] = &[
    "substring",
    "substr",
    "slice",
    "replace",
    "replaceAll",
    "trim",
    "trimStart",
    "trimEnd",
    "toString",
    "toLowerCase",
    "toUpperCase",
    "concat",
    "join",
    "padStart",
    "padEnd",
    "repeat",
    "normalize",
];

/// String-returning global functions.
const JS_STRING_FUNCTIONS: &[&str] = &[
    "String",
    "decodeURIComponent",
    "decodeURI",
    "unescape",
    "atob",
];

fn js_expr_is_string_valued(
    expr: Node,
    lang: &str,
    code: &[u8],
    extra: Option<&[crate::labels::RuntimeLabelRule]>,
    depth: u8,
) -> bool {
    let expr = unwrap_parens(expr);
    match expr.fkind() {
        "string" | "template_string" => true,
        "binary_expression" => expr
            .child_by_field_name("operator")
            .and_then(|o| text_of(o, code))
            .is_some_and(|o| o == "+"),
        "member_expression" | "subscript_expression" => matches!(
            super::helpers::first_member_label(expr, lang, code, extra),
            Some(crate::labels::DataLabel::Source(_))
        ),
        "call_expression" => {
            let Some(func) = expr.child_by_field_name("function") else {
                return false;
            };
            match func.fkind() {
                "member_expression" => func
                    .child_by_field_name("property")
                    .and_then(|p| text_of(p, code))
                    .is_some_and(|p| JS_STRING_METHODS.contains(&p.as_str())),
                "identifier" => {
                    text_of(func, code).is_some_and(|f| JS_STRING_FUNCTIONS.contains(&f.as_str()))
                }
                _ => false,
            }
        }
        "identifier" if depth > 0 => text_of(expr, code)
            .and_then(|name| js_local_initializer(expr, &name, code))
            .is_some_and(|init| js_expr_is_string_valued(init, lang, code, extra, depth - 1)),
        _ => false,
    }
}

/// Initialiser of the nearest `const` / `let` / `var` declaration of `name`
/// in a block enclosing `from`.  `None` when a parameter of an enclosing
/// function binds `name` first, or when no initialised declaration is found.
fn js_local_initializer<'a>(from: Node<'a>, name: &str, code: &[u8]) -> Option<Node<'a>> {
    let mut scope = from.parent();
    while let Some(s) = scope {
        if matches!(
            s.fkind(),
            "function_expression"
                | "function"
                | "function_declaration"
                | "generator_function"
                | "generator_function_declaration"
                | "arrow_function"
                | "method_definition"
        ) && js_function_has_param(s, name, code)
        {
            return None;
        }
        if matches!(s.fkind(), "statement_block" | "program") {
            let mut cursor = s.walk();
            for stmt in s.named_children(&mut cursor) {
                if !matches!(stmt.fkind(), "lexical_declaration" | "variable_declaration") {
                    continue;
                }
                let mut dc = stmt.walk();
                for decl in stmt.named_children(&mut dc) {
                    if decl.fkind() == "variable_declarator"
                        && decl
                            .child_by_field_name("name")
                            .and_then(|n| text_of(n, code))
                            .is_some_and(|n| n == name)
                    {
                        return decl.child_by_field_name("value");
                    }
                }
            }
        }
        scope = s.parent();
    }
    None
}

/// True when the function node `func` declares a parameter named `name`.
fn js_function_has_param(func: Node, name: &str, code: &[u8]) -> bool {
    // `x => ...` keeps its lone parameter in the `parameter` field.
    if let Some(p) = func.child_by_field_name("parameter") {
        return text_of(p, code).is_some_and(|t| t == name);
    }
    let Some(params) = func.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = params.walk();
    params.named_children(&mut cursor).any(|p| {
        // TS wraps each parameter (`required_parameter` / `optional_parameter`)
        // with the binding under `pattern`; JS default values wrap it in an
        // `assignment_pattern` under `left`.
        let binding = p
            .child_by_field_name("pattern")
            .or_else(|| p.child_by_field_name("left"))
            .unwrap_or(p);
        binding.fkind() == "identifier" && text_of(binding, code).is_some_and(|t| t == name)
    })
}

/// Positional args of an argv-taking `child_process` call (`spawn`,
/// `execFile`, ...) that become shell payloads because an inline options
/// object enables `shell`.  Node then joins the binary and the argv array
/// into one `/bin/sh -c` string, so the argv array is injectable the same
/// way `exec`'s command string is.
///
/// Empty when no object-literal argument after arg 0 has a `shell` key, or
/// when its value is a falsy literal (`false`, `null`, `undefined`, `0`,
/// `''`).  A dynamic value counts as enabled.  Arg 0 is not reported (it is
/// already a payload), and neither are the options object itself nor a
/// function argument (the completion callback).
pub(super) fn js_shell_option_argv_positions(call_node: Node, code: &[u8]) -> Vec<usize> {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    let positional: Vec<Node> = args.named_children(&mut cursor).collect();
    let shell_enabled = positional
        .iter()
        .skip(1)
        .any(|a| js_object_enables_shell(unwrap_parens(*a), code));
    if !shell_enabled {
        return Vec::new();
    }
    positional
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, a)| {
            !matches!(
                unwrap_parens(**a).fkind(),
                "object" | "function_expression" | "arrow_function" | "function"
            )
        })
        .map(|(i, _)| i)
        .collect()
}

/// True when `obj` is an object literal whose `shell` property is present
/// and not a falsy literal.
fn js_object_enables_shell(obj: Node, code: &[u8]) -> bool {
    if obj.fkind() != "object" {
        return false;
    }
    let mut cursor = obj.walk();
    for child in obj.named_children(&mut cursor) {
        match child.fkind() {
            // `{ shell }`: value is whatever the local binding holds.
            "shorthand_property_identifier" if text_of(child, code).as_deref() == Some("shell") => {
                return true;
            }
            "pair" => {
                let Some(key) = child.child_by_field_name("key") else {
                    continue;
                };
                let key_text = match key.fkind() {
                    "string" => const_string_value(key, code),
                    "property_identifier" => text_of(key, code),
                    _ => None,
                };
                if key_text.as_deref() != Some("shell") {
                    continue;
                }
                let Some(value) = child.child_by_field_name("value") else {
                    return true;
                };
                let value = unwrap_parens(value);
                return match value.fkind() {
                    "false" | "null" | "undefined" => false,
                    "number" => text_of(value, code).as_deref() != Some("0"),
                    "string" | "template_string" => {
                        const_string_value(value, code).is_none_or(|s| !s.is_empty())
                    }
                    "identifier" => text_of(value, code).as_deref() != Some("undefined"),
                    _ => true,
                };
            }
            _ => {}
        }
    }
    false
}

/// Split-form counterpart of [`shell_array_payload_idents_of`]: `shell` came
/// from the previous positional argument and `node` must be an argv array
/// literal `[<flag>, *]` whose first element is that shell's command flag.
/// Returns the identifiers in the elements after the flag.
fn shell_argv_payload_idents_of(shell: &str, node: Node, code: &[u8]) -> Option<Vec<String>> {
    let node = unwrap_parens(node);
    if !matches!(node.fkind(), "array" | "list") {
        return None;
    }
    let mut cursor = node.walk();
    let elems: Vec<Node> = node.named_children(&mut cursor).collect();
    if elems.len() < 2 {
        return None;
    }
    let flag = const_string_value(elems[0], code)?;
    if !is_shell_command_flag(shell, &flag) {
        return None;
    }
    shell_payload_idents(&elems[1..], code)
}

/// Identifiers and dotted paths referenced by the shell-command elements of
/// a shell-array literal.  `None` when every element is a constant.
fn shell_payload_idents(payload: &[Node], code: &[u8]) -> Option<Vec<String>> {
    // Lift identifiers from the payload elements.  Constants contribute
    // nothing.  An empty result means the entire payload is statically
    // benign.
    let mut idents: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    for elem in payload {
        collect_idents_with_paths(*elem, code, &mut idents, &mut paths);
    }
    let mut combined = paths;
    combined.extend(idents);
    // Dedup (preserve first-seen order).
    let mut seen = std::collections::HashSet::new();
    combined.retain(|s| seen.insert(s.clone()));
    if combined.is_empty() {
        // Static payload — no taint can reach it. Return None so the caller
        // does not emit a useless sink filter.
        return None;
    }
    Some(combined)
}

/// Extract a constant string value from `node`, handling JS/TS `string` /
/// `template_string` (no interpolation) forms.  Returns `None` for dynamic
/// values, identifiers, or expressions.
fn const_string_value(node: Node, code: &[u8]) -> Option<String> {
    let node = unwrap_parens(node);
    match node.fkind() {
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal" => {
            let raw = text_of(node, code)?;
            // A Python string may carry a prefix (`r"x"`, `b'x'`) and an
            // f-string holds `{...}` fields; only a fixed literal has a
            // constant value.
            let mut c = node.walk();
            if node
                .named_children(&mut c)
                .any(|ch| ch.fkind() == "interpolation")
            {
                return None;
            }
            let body = raw.trim_start_matches(|ch: char| ch.is_ascii_alphabetic());
            if body.len() >= 2 {
                Some(body[1..body.len() - 1].to_string())
            } else {
                None
            }
        }
        "template_string" => {
            let mut c = node.walk();
            if node
                .named_children(&mut c)
                .any(|ch| ch.fkind() == "template_substitution")
            {
                return None;
            }
            let raw = text_of(node, code)?;
            if raw.len() >= 2 {
                Some(raw[1..raw.len() - 1].to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Known shell executable names that activate the shell-array detector.
/// Scoped narrowly to POSIX shells + Windows command interpreters, listing
/// only canonical names so benign arrays like `["ls", ...]`, `["git", ...]`,
/// or `["python", ...]` do not match.
fn is_known_shell(name: &str) -> bool {
    // Strip directory prefix for matching: `/bin/bash` → `bash`.
    let leaf = name.rsplit('/').next().unwrap_or(name);
    matches!(
        leaf,
        "bash"
            | "sh"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "ash"
            | "tcsh"
            | "csh"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    )
}

/// True when `flag` is the "execute the following string as a shell command"
/// switch for the given `shell`.  POSIX shells use `-c`; cmd.exe accepts
/// `/c` / `/C`; PowerShell uses `-Command` (also `-c` as alias) and
/// `-EncodedCommand`.
fn is_shell_command_flag(shell: &str, flag: &str) -> bool {
    let leaf = shell.rsplit('/').next().unwrap_or(shell);
    let is_cmd = matches!(leaf, "cmd" | "cmd.exe");
    let is_powershell = matches!(leaf, "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe");
    if is_cmd {
        return matches!(flag, "/c" | "/C" | "/k" | "/K");
    }
    if is_powershell {
        return matches!(
            flag,
            "-c" | "-Command" | "-command" | "-EncodedCommand" | "-encodedcommand"
        );
    }
    // POSIX shells, including clustered short options such as `-lc` and `-ic`.
    crate::labels::is_code_flag(shell, flag)
}

/// Whether a Go call's first argument is a `context.Context`.
///
/// Go database APIs that take a context put it before the SQL text
/// (`db.Exec(ctx, query, args...)`), so a gate that names arg 0 as the
/// payload has to move to arg 1 for these calls.  Recognised without type
/// information: a call that produces a context (`context.Background()`,
/// `context.TODO()`, `context.With*(..)`, `x.Context()`), and an identifier
/// that the enclosing function declares as a parameter of type
/// `context.Context` or binds from such a call with `:=`.  Anything else,
/// including a plain string, is not a context.
pub(super) fn go_leading_arg_is_context(call: Node, code: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(arg0) = args.named_children(&mut cursor).next() else {
        return false;
    };
    let arg0 = unwrap_parens(arg0);
    match arg0.fkind() {
        "call_expression" => go_call_yields_context(arg0, code),
        "identifier" => {
            let Some(name) = text_of(arg0, code) else {
                return false;
            };
            go_ident_is_context(arg0, &name, code)
        }
        _ => false,
    }
}

fn go_call_yields_context(call: Node, code: &[u8]) -> bool {
    let Some(f) = call.child_by_field_name("function") else {
        return false;
    };
    let Some(text) = text_of(f, code) else {
        return false;
    };
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if let Some(leaf) = text.strip_prefix("context.") {
        return matches!(leaf, "Background" | "TODO") || leaf.starts_with("With");
    }
    // `r.Context()`, `t.Context()`: a method named Context taking no arguments.
    text.ends_with(".Context")
        && call
            .child_by_field_name("arguments")
            .is_some_and(|a| a.named_child_count() == 0)
}

fn go_is_context_type(ty: Node, code: &[u8]) -> bool {
    text_of(ty, code).is_some_and(|t| t == "context.Context")
}

fn go_ident_is_context(use_node: Node, name: &str, code: &[u8]) -> bool {
    // Nearest enclosing function; its parameters and `:=` bindings decide.
    let mut cur = use_node.parent();
    while let Some(n) = cur {
        if matches!(
            n.fkind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            if let Some(params) = n.child_by_field_name("parameters") {
                let mut pc = params.walk();
                for p in params.named_children(&mut pc) {
                    if p.fkind() != "parameter_declaration" {
                        continue;
                    }
                    let Some(ty) = p.child_by_field_name("type") else {
                        continue;
                    };
                    if !go_is_context_type(ty, code) {
                        continue;
                    }
                    let mut nc = p.walk();
                    if p.children_by_field_name("name", &mut nc)
                        .any(|id| text_of(id, code).is_some_and(|t| t == name))
                    {
                        return true;
                    }
                }
            }
            if let Some(body) = n.child_by_field_name("body") {
                return go_body_binds_context(body, use_node.start_byte(), name, code);
            }
            return false;
        }
        cur = n.parent();
    }
    false
}

/// `name := <context-producing call>` before `before` in `body`, without
/// descending into nested function literals.
fn go_body_binds_context(body: Node, before: usize, name: &str, code: &[u8]) -> bool {
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if n.start_byte() >= before {
            continue;
        }
        if n.fkind() == "short_var_declaration"
            && let (Some(l), Some(r)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
        {
            let mut lc = l.walk();
            let mut rc = r.walk();
            let lhs: Vec<Node> = l.named_children(&mut lc).collect();
            let rhs: Vec<Node> = r.named_children(&mut rc).collect();
            if let Some(i) = lhs
                .iter()
                .position(|x| text_of(*x, code).is_some_and(|t| t == name))
                && let Some(call) = rhs.get(i.min(rhs.len().saturating_sub(1)))
                && call.fkind() == "call_expression"
                && go_call_yields_context(*call, code)
            {
                return true;
            }
        }
        if n.fkind() == "func_literal" {
            continue;
        }
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            stack.push(ch);
        }
    }
    false
}

/// Whether the right-hand side bound by `ast` is an array / list / tuple
/// literal made only of string (without interpolation) and number literals.
pub(super) fn literal_scalar_collection_rhs(ast: Node, lang: &str, code: &[u8]) -> bool {
    fn collection_of_scalars(val: Node, code: &[u8]) -> bool {
        if !matches!(val.fkind(), "array" | "list" | "tuple") {
            return false;
        }
        let mut c = val.walk();
        val.named_children(&mut c).all(|e| {
            matches!(e.fkind(), "comment")
                || (is_syntactic_literal(e, code)
                    && !matches!(
                        e.fkind(),
                        "true"
                            | "false"
                            | "null"
                            | "nil"
                            | "none"
                            | "null_literal"
                            | "boolean"
                            | "boolean_literal"
                    ))
        })
    }
    let direct = ast
        .child_by_field_name("value")
        .or_else(|| ast.child_by_field_name("right"));
    if let Some(v) = direct {
        return collection_of_scalars(v, code);
    }
    if !matches!(lookup_node(lang, ast), Kind::CallWrapper | Kind::Assignment) {
        return false;
    }
    let mut cursor = ast.walk();
    ast.children(&mut cursor).any(|child| {
        child
            .child_by_field_name("value")
            .or_else(|| {
                matches!(lookup_node(lang, child), Kind::Assignment)
                    .then(|| child.child_by_field_name("right"))
                    .flatten()
            })
            .is_some_and(|v| collection_of_scalars(v, code))
    })
}

#[cfg(test)]
mod orm_uid_ref_tests {
    use super::{
        find_orm_query_chain_call, js_chain_outer_method_for_inner, js_orm_query_arg0_is_uid_ref,
    };

    fn parse_ts(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    const QT: &[&str] = &["query", "execute"];

    /// The robust DFS locates the `<recv>.query(UID).<orm_method>(...)` call
    /// through wrappers that defeat a fixed-depth lookup: `(await ...)` const
    /// bindings, `(await ...) > 0` binary expressions, and `Promise.all([...])`
    /// array arguments.  For each, the surfaced outer method must be the ORM
    /// accessor, not the wrapping call.
    #[test]
    fn dfs_finds_orm_chain_through_wrappers() {
        for (src, want) in [
            (
                &b"async function f(u:string){ const r = (await x.db.query(u).findMany({})); return r; }"[..],
                "findMany",
            ),
            (
                &b"async function f(a:unknown){ return (await x.db.query('admin::user').count({where:a})) > 0; }"[..],
                "count",
            ),
            (
                &b"async function f(m:string){ return Promise.all([x.db.query(m).findOne({})]); }"[..],
                "findOne",
            ),
        ] {
            let tree = parse_ts(src);
            let bytes = src;
            let mut budget = 96u32;
            let call = find_orm_query_chain_call(tree.root_node(), QT, bytes, &mut budget)
                .unwrap_or_else(|| panic!("DFS should find ORM call in: {}", String::from_utf8_lossy(src)));
            assert_eq!(
                js_chain_outer_method_for_inner(call, QT, bytes).as_deref(),
                Some(want),
                "outer method for: {}",
                String::from_utf8_lossy(src),
            );
        }
    }

    /// A `key as UID.Schema` type-cast argument is transparent: the observed
    /// inner-query arg-0 kind is the underlying `identifier`, not
    /// `as_expression`, so the UID-reference gate accepts it.
    #[test]
    fn as_cast_arg0_unwraps_to_identifier() {
        let src = &b"function f(k:string){ return x.db.query(k as any).count({}); }"[..];
        let tree = parse_ts(src);
        let call = find_orm_query_chain_call(tree.root_node(), QT, src, &mut 96u32)
            .expect("DFS finds the count call");
        let (kind, has_interp) =
            super::js_chain_arg0_kind_for_method(call, QT, src).expect("inner query arg0");
        assert_eq!(kind, "identifier", "as-cast should unwrap to identifier");
        assert!(!has_interp);
        assert!(js_orm_query_arg0_is_uid_ref(&kind));
    }

    /// Model-UID references accepted by the `db.query(UID).<orm_method>(...)`
    /// ORM-chain recogniser: string literals AND by-reference forms (variable /
    /// const identifier, member access).  Pins the real-repo shapes
    /// `db.query(uid)` / `db.query(RELEASE_MODEL_UID)` / `db.query(models.x)`.
    #[test]
    fn accepts_literal_and_reference_uid_shapes() {
        for k in [
            "string",
            "string_fragment",
            "template_string",
            "identifier",
            "shorthand_property_identifier",
            "property_identifier",
            "member_expression",
        ] {
            assert!(js_orm_query_arg0_is_uid_ref(k), "should accept {k}");
        }
    }

    /// Computed / concatenated arg-0 shapes are NOT model-UID references: a
    /// `binary_expression` (`"SELECT " + x`) or a nested call could carry raw
    /// SQL, so the sanitizer synthesis must refuse them even when an ORM method
    /// is chained.  Guards against re-broadening the allowlist.
    #[test]
    fn rejects_computed_arg_shapes() {
        for k in [
            "binary_expression",
            "call_expression",
            "await_expression",
            "ternary_expression",
            "subscript_expression",
        ] {
            assert!(!js_orm_query_arg0_is_uid_ref(k), "should reject {k}");
        }
    }
}
