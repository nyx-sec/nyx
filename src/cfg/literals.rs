use super::conditions::unwrap_parens;
use super::{
    anon_fn_name, collect_idents, collect_idents_with_paths, find_constructor_type_child,
    first_call_ident, root_receiver_text, text_of,
};
use crate::labels::{Cap, Kind, lookup};
use tree_sitter::Node;

/// Find the inner CallFn/CallMethod/CallMacro node within an AST node.
/// For direct call nodes, returns the node itself. For wrappers, searches
/// up to two levels of children, transparently descending through
/// `await_expression` / `yield_expression` (`Kind::AwaitForward`) wrappers
/// so `const x = await foo(y)` reaches the inner `call_expression` at
/// effective depth 3 (`lexical_declaration > variable_declarator >
/// await_expression > call_expression`).
pub(super) fn find_call_node<'a>(n: Node<'a>, lang: &str) -> Option<Node<'a>> {
    match lookup(lang, n.kind()) {
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
                match lookup(lang, c.kind()) {
                    Kind::CallFn | Kind::CallMethod | Kind::CallMacro => return Some(c),
                    // Skip past await/yield wrappers without consuming a
                    // recursion level — the wrapper itself is transparent.
                    Kind::AwaitForward => {
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
                let mut cursor3 = c.walk();
                for gc in c.children(&mut cursor3) {
                    match lookup(lang, gc.kind()) {
                        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => return Some(gc),
                        Kind::AwaitForward => {
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
    if fields.is_empty() {
        return None;
    }
    let args = call_node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let arg = args.named_children(&mut cursor).nth(arg_index)?;

    // Only object / dict literal forms carry per-field destination semantics.
    // For anything else (identifier, member expression, string, call), return
    // None so the caller treats the whole arg as destination.
    if !matches!(arg.kind(), "object" | "dictionary") {
        return None;
    }

    let mut out: Vec<(String, String)> = Vec::new();
    let mut c = arg.walk();
    for child in arg.named_children(&mut c) {
        match child.kind() {
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
                if fields.iter().any(|&f| f == name) && !out.iter().any(|(_, v)| v == &name) {
                    out.push((name.clone(), name));
                }
            }
            "pair" => {
                let Some(key_node) = child.child_by_field_name("key") else {
                    continue;
                };
                let key_text = match key_node.kind() {
                    // Strip quotes from string-literal keys so `"url"` and `url`
                    // both match the configured field list.
                    "string" | "string_literal" => text_of(key_node, code).map(|raw| {
                        if raw.len() >= 2 {
                            raw[1..raw.len() - 1].to_string()
                        } else {
                            raw
                        }
                    }),
                    // Computed keys like `[someVar]` can't be statically
                    // resolved, skip (conservative: not a destination field).
                    "computed_property_name" => continue,
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
                let mut idents: Vec<String> = Vec::new();
                let mut paths: Vec<String> = Vec::new();
                collect_idents_with_paths(val_node, code, &mut idents, &mut paths);
                for name in paths.into_iter().chain(idents) {
                    if !out.iter().any(|(_, v)| v == &name) {
                        out.push((key.clone(), name));
                    }
                }
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
        let kind = child.kind();
        if kind != "keyword_argument" && kind != "named_argument" {
            continue;
        }
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
    if !matches!(call_node.kind(), "call_expression") {
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
        match arg.kind() {
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
    arg.kind() == "null" || text_of(arg, code).as_deref() == Some("null")
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
    if arg.kind() == "argument" && arg.named_child_count() == 1 {
        if let Some(inner) = arg.named_child(0) {
            arg = inner;
        }
    }
    match arg.kind() {
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
        "true" | "false" => Some(arg.kind().to_string()),
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
                match ch.kind() {
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
                .any(|ch| ch.kind() == "template_substitution")
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
            match left.kind() {
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
                        match ch.kind() {
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
    if arg.kind() == "argument" && arg.named_child_count() == 1 {
        if let Some(inner) = arg.named_child(0) {
            arg = inner;
        }
    }
    match arg.kind() {
        // C/C++ identifier / PHP `name` node for define-style constants.
        // Scoped C++ identifiers (`Curl::OPT_POSTFIELDS`) and PHP namespaced
        // names also surface here so the dangerous_values match catches them.
        "identifier" | "name" | "qualified_name" | "scoped_identifier" => {
            text_of(arg, code).map(|s| s.to_string())
        }
        // Ruby bare constant (`NOENT`) — leaf form.
        "constant" => text_of(arg, code).map(|s| s.to_string()),
        // Ruby scope-qualified constant (`Nokogiri::XML::ParseOptions::NOENT`).
        // Return only the rightmost `name` segment so the gate's
        // `dangerous_values` list can stay identifier-bare instead of
        // enumerating every possible namespacing.  Falls back to the full
        // text if the `name` field is missing for any reason.
        "scope_resolution" => arg
            .child_by_field_name("name")
            .and_then(|n| text_of(n, code))
            .map(|s| s.to_string())
            .or_else(|| text_of(arg, code).map(|s| s.to_string())),
        // Integer literals at the activation arg position.  PHP / C / C++
        // commonly use plain `0` to opt into the safe-default option set
        // (e.g. `simplexml_load_string($xml, "SimpleXMLElement", 0)`).  The
        // gate's `dangerous_values` list is identifier-only, so returning
        // the literal text lets the comparison fail against `LIBXML_NOENT`
        // and suppresses the conservative-fire branch.
        "integer" | "integer_literal" | "number_literal" | "decimal_integer_literal" => {
            text_of(arg, code).map(|s| s.to_string())
        }
        _ => None,
    }
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
        if child.kind() == "keyword_argument" || child.kind() == "named_argument" {
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
            // Only return a literal, identifiers / calls / complex exprs are
            // "dynamic" and must be reported as `None` so the gate can
            // distinguish literal-safe from dynamic.
            return match value_node.kind() {
                "true" | "false" | "none" | "integer" | "float" | "string" | "string_literal"
                | "identifier" => text_of(value_node, code).map(|s| s.to_string()),
                _ => None,
            }
            .filter(|_| {
                // identifiers are only "literal" when they're the Python
                // booleans True/False/None (tree-sitter-python classifies
                // these as identifiers in older grammar versions).
                match value_node.kind() {
                    "identifier" => text_of(value_node, code)
                        .as_deref()
                        .is_some_and(|s| matches!(s, "True" | "False" | "None")),
                    _ => true,
                }
            });
        }
    }
    None
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
        if child.kind() != "keyword_argument" && child.kind() != "named_argument" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if text_of(name_node, code).as_deref() == Some(keyword_name) {
            return true;
        }
    }
    false
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
    if !matches!(arg.kind(), "object" | "dictionary") {
        return None;
    }
    let mut c = arg.walk();
    for child in arg.named_children(&mut c) {
        if child.kind() != "pair" {
            continue;
        }
        let Some(key_node) = child.child_by_field_name("key") else {
            continue;
        };
        let key_text = match key_node.kind() {
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
        return match val_node.kind() {
            "true" | "false" | "null" | "undefined" | "number" | "string" | "string_literal" => {
                text_of(val_node, code).map(|s| s.to_string())
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
    if !matches!(arg.kind(), "object" | "dictionary") {
        return false;
    }
    let mut c = arg.walk();
    for child in arg.named_children(&mut c) {
        match child.kind() {
            "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
                if text_of(child, code).as_deref() == Some(prop_name) =>
            {
                return true;
            }
            "pair" => {
                if let Some(key_node) = child.child_by_field_name("key") {
                    let key_text = match key_node.kind() {
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
    let arg0 = unwrap_parens(arg0);
    let kind = arg0.kind().to_string();
    let has_interp = subtree_has_interpolation(arg0);
    Some((kind, has_interp))
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
    if n.kind() == "method_invocation"
        && let Some(name_node) = n.child_by_field_name("name")
        && let Some(name) = text_of(name_node, code)
        && target_methods.iter().any(|m| *m == name)
    {
        let args = n.child_by_field_name("arguments")?;
        let mut cursor = args.walk();
        let arg0 = args.named_children(&mut cursor).next()?;
        let arg0 = unwrap_parens(arg0);
        return Some(arg0.kind().to_string());
    }
    // Drill down the receiver spine.  Java grammar uses `object` for the
    // receiver of a `method_invocation`.
    if n.kind() == "method_invocation"
        && let Some(recv) = n.child_by_field_name("object")
        && let Some(found) = java_chain_arg0_kind_for_method(recv, target_methods, code)
    {
        return Some(found);
    }
    None
}

/// Walk a Ruby method-chain receiver-side looking for the inner call whose
/// method identifier matches one of `target_methods`, then return that
/// inner call's [`arg0_kind_and_interpolation`].  Used when the CFG node
/// represents a chained expression like `Model.where(...).preload(...).to_a`
///, the outermost call (`to_a`) has no arguments, so the shape suppressor
/// must reach down the chain to inspect `where`'s arg 0.
///
/// Conservative: returns `None` if the chain doesn't contain a matching
/// method, so callers fall through to the no-suppression path.
pub(super) fn ruby_chain_arg0_for_method(
    expr: Node,
    target_methods: &[&str],
    code: &[u8],
) -> Option<(String, bool)> {
    let n = unwrap_parens(expr);
    if n.kind() == "call"
        && let Some(method) = n.child_by_field_name("method")
        && let Some(name) = text_of(method, code)
        && target_methods.iter().any(|m| *m == name)
    {
        return arg0_kind_and_interpolation(n);
    }
    // Recurse into the receiver chain (`call.receiver` → next call up).
    if n.kind() == "call"
        && let Some(recv) = n
            .child_by_field_name("receiver")
            .or_else(|| n.child_by_field_name("object"))
        && let Some(found) = ruby_chain_arg0_for_method(recv, target_methods, code)
    {
        return Some(found);
    }
    // Also descend into named children to handle wrapping (assignment RHS,
    // begin-end blocks, parenthesised expressions, etc.).
    let mut cursor = n.walk();
    for c in n.named_children(&mut cursor) {
        if let Some(found) = ruby_chain_arg0_for_method(c, target_methods, code) {
            return Some(found);
        }
    }
    None
}

fn subtree_has_interpolation(n: Node) -> bool {
    if n.kind() == "interpolation" || n.kind() == "string_interpolation" {
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
    if n.kind() == "call_expression" {
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
    if n.kind() != "call_expression" {
        return None;
    }
    let function = n.child_by_field_name("function")?;
    let object = function.child_by_field_name("object")?;
    // If `object` itself is a call_expression whose property matches
    // `target_inner`, the immediate outer is `function.property`.
    if object.kind() == "call_expression" {
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
                    .and_then(|p| text_of(p, code).map(|s| s.to_string()));
            }
        }
        // Recurse: outer chain may have more depth (`a.b().c().d()` ,
        // d is outermost, c is next, target may be at b or further in).
        return js_chain_outer_method_for_inner(object, target_inner, code);
    }
    None
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
    if !matches!(lookup(lang, outer.kind()), Kind::CallFn | Kind::CallMethod) {
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
    if matches!(
        lookup(lang, function.kind()),
        Kind::CallFn | Kind::CallMethod
    ) {
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
    if !matches!(lookup(lang, object.kind()), Kind::CallFn | Kind::CallMethod) {
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
                f.kind(),
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
    if !matches!(lookup(lang, outer.kind()), Kind::CallFn | Kind::CallMethod) {
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
    if !matches!(lookup(lang, inner.kind()), Kind::CallFn | Kind::CallMethod) {
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
pub(super) fn find_call_node_deep<'a>(n: Node<'a>, lang: &str, depth: u8) -> Option<Node<'a>> {
    if depth == 0 {
        return None;
    }
    match lookup(lang, n.kind()) {
        Kind::CallFn | Kind::CallMethod | Kind::CallMacro => Some(n),
        _ => {
            let mut cursor = n.walk();
            for c in n.children(&mut cursor) {
                if let Some(found) = find_call_node_deep(c, lang, depth - 1) {
                    return Some(found);
                }
            }
            None
        }
    }
}

/// Detect whether a call node is a parameterized SQL query.
///
/// Returns `true` when:
/// 1. The first argument (arg 0) is a string literal (including template
///    strings without interpolation) containing SQL placeholder patterns:
///    `$1`..`$N`, `?`, `%s`, or `:identifier`.
/// 2. The call has at least 2 arguments (the second being the params
///    array/tuple).
///
/// This is intentionally conservative: if arg 0 is dynamic (variable,
/// concatenation, template with interpolation), returns `false`.
pub(super) fn is_parameterized_query_call(call_node: Node, code: &[u8]) -> bool {
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let named: Vec<_> = args.named_children(&mut cursor).collect();
    // Need at least 2 arguments: query string + params
    if named.len() < 2 {
        return false;
    }
    let first_arg = named[0];
    // Extract the raw text of arg 0, must be a string literal or
    // template string without interpolation.
    let query_text = match first_arg.kind() {
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal" => {
            text_of(first_arg, code)
        }
        "template_string" => {
            // Only constant templates (no interpolation)
            let mut c = first_arg.walk();
            if first_arg
                .named_children(&mut c)
                .any(|ch| ch.kind() == "template_substitution")
            {
                return false; // dynamic, not safe
            }
            text_of(first_arg, code)
        }
        // Python concatenated strings: "SELECT" "..." are implicit concat
        "concatenated_string" => {
            // If it's a concatenated_string, get the full text
            text_of(first_arg, code)
        }
        _ => return false, // not a literal
    };
    let Some(qt) = query_text else {
        return false;
    };
    has_sql_placeholders(&qt)
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
    match node.kind() {
        // Scalar strings, but reject if they contain interpolation
        // (e.g. Ruby `"hello #{name}"`, Python f-strings).
        "string"
        | "string_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "string_content"
        | "string_fragment" => !has_string_interpolation(node),

        // Numbers
        "integer" | "integer_literal" | "int_literal" | "float" | "float_literal" | "number" => {
            true
        }

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
                .any(|ch| ch.kind() == "template_substitution")
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
        if child.kind().contains("interpolation") {
            return true;
        }
    }
    false
}

/// Check if an encapsed_string node contains interpolation (PHP).
pub(super) fn has_interpolation_cfg(node: Node) -> bool {
    for i in 0..node.child_count() as u32 {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
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
    use crate::labels::lookup;

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
    if matches!(
        lookup(lang, ast.kind()),
        Kind::CallWrapper | Kind::Assignment
    ) {
        let mut cursor = ast.walk();
        for child in ast.children(&mut cursor) {
            let child_val = child.child_by_field_name("value").or_else(|| {
                if matches!(lookup(lang, child.kind()), Kind::Assignment) {
                    child.child_by_field_name("right")
                } else {
                    None
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
    if matches!(lookup(lang, ast.kind()), Kind::Return) {
        let mut cursor = ast.walk();
        for child in ast.named_children(&mut cursor) {
            if is_syntactic_literal(child, code) {
                return text_of(child, code);
            }
        }
    }

    None
}

/// Returns true when every argument in the call's argument list is a
/// syntactic literal (per `is_syntactic_literal`). Returns true for calls
/// with zero arguments (no argument-carried taint vector). Returns false
/// when the argument list cannot be found.
///
/// For method chains like `a("x").b(y).c()`, the outermost call node
/// represents the entire chain. This function walks nested call expressions
/// to verify ALL argument lists in the chain contain only literals.
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
        let kind = child.kind();
        // Skip argument lists, those are checked by the caller.
        if kind == "arguments" || kind == "argument_list" || kind == "actual_parameters" {
            continue;
        }
        // If this child is itself a call expression, check its arguments.
        if child.child_by_field_name("arguments").is_some() {
            if !has_only_literal_args(child, code) {
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
    if call_node.kind() != "macro_invocation" {
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
                .find(|c| c.kind() == "token_tree")
            {
                Some(t) => t,
                None => return Vec::new(),
            }
        }
    };
    let mut cursor = tt.walk();
    let fmt_lit = match tt
        .children(&mut cursor)
        .find(|c| matches!(c.kind(), "string_literal" | "raw_string_literal"))
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
    if n.kind() == "macro_invocation" {
        for ident in extract_rust_format_macro_named_idents(n, code) {
            out.push(ident);
        }
    }
    let mut cursor = n.walk();
    for child in n.children(&mut cursor) {
        collect_format_macro_idents_recursive(child, code, out, depth + 1);
    }
}

fn is_rust_format_style_macro(name: &str) -> bool {
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
    if call_node.kind() == "subshell" {
        let mut result = Vec::new();
        let mut cursor = call_node.walk();
        for child in call_node.named_children(&mut cursor) {
            if child.kind() == "interpolation" {
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

    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let kind = child.kind();
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
        if kind == "keyword_argument" || kind == "named_argument" {
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
        let kind = child.kind();
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
                let pk = pair.kind();
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
                vn.kind(),
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

/// Caps that a search literal is known to strip, provided the replacement
/// itself does not reintroduce any dangerous sequence.
///
/// Policy is deliberately narrow and conservative: only literals that contain
/// *known-dangerous* payloads earn a strip credit, so an arbitrary
/// `.replace("foo", "bar")` is never promoted to a sanitizer.
///   * `..`, `/`, `\\`         → path-traversal     → `Cap::FILE_IO`
///   * `<`, `>`                → HTML metachars     → `Cap::HTML_ESCAPE`
///   * `;`, `|`, `&`, `$`, `\`` → shell metachars   → `Cap::SHELL_ESCAPE`
///   * `'`, `"`, `--`          → SQL metachars      → `Cap::SQL_QUERY`
pub(super) fn caps_stripped_by_literal_pattern(search: &str) -> Cap {
    let mut caps = Cap::empty();
    if search.contains("..") || search.contains('/') || search.contains('\\') {
        caps |= Cap::FILE_IO;
    }
    if search.contains('<') || search.contains('>') {
        caps |= Cap::HTML_ESCAPE;
    }
    if search.contains(';')
        || search.contains('|')
        || search.contains('&')
        || search.contains('$')
        || search.contains('`')
    {
        caps |= Cap::SHELL_ESCAPE;
    }
    if search.contains('\'') || search.contains('"') || search.contains("--") {
        caps |= Cap::SQL_QUERY;
    }
    caps
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
            if c.kind() == "string_content" {
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
        if current.kind() != "call_expression" {
            // Chain base: must be a plain identifier (parameter / local) to
            // qualify.  A base that's another expression (field access,
            // nested non-method call, …) breaks the sanitizer invariant.
            if current.kind() == "identifier" && !earned.is_empty() {
                return Some(earned);
            }
            return None;
        }

        // Must be a method-style call: function is a field_expression whose
        // `field` names a `replace`-like method.
        let func = current.child_by_field_name("function")?;
        if func.kind() != "field_expression" {
            return None;
        }
        let method_ident = func.child_by_field_name("field")?;
        let method_name = text_of(method_ident, code)?;
        if method_name != "replace" && method_name != "replacen" {
            return None;
        }

        let args_node = current.child_by_field_name("arguments")?;
        let mut cursor = args_node.walk();
        let positional: Vec<Node<'_>> = args_node
            .named_children(&mut cursor)
            .filter(|c| {
                !matches!(
                    c.kind(),
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
        if !is_rust_str_literal(arg0.kind()) || !is_rust_str_literal(arg1.kind()) {
            return None;
        }
        let search = extract_rust_str_content(arg0, code)?;
        let replacement = extract_rust_str_content(arg1, code)?;

        // If the replacement itself contains a dangerous sequence, this hop
        // can reintroduce the pattern that a later hop tries to strip.  Be
        // conservative: abandon all credit.
        if !caps_stripped_by_literal_pattern(&replacement).is_empty() {
            return None;
        }
        earned |= caps_stripped_by_literal_pattern(&search);

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
    if call_ast.kind() != "call_expression" {
        return None;
    }
    // The call's `function` field is a `selector_expression`, `operand`
    // is the package ident (`strings`), `field` is the method ident.
    let func = call_ast.child_by_field_name("function")?;
    if func.kind() != "selector_expression" {
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
    // Args layout: (s, old, new[, n]).  Need positional args 1 (old) and
    // 2 (new) to be string literals.
    let old_lit = extract_const_string_arg(call_ast, 1, code)?;
    let new_lit = extract_const_string_arg(call_ast, 2, code)?;

    // If the replacement itself reintroduces a dangerous sequence, don't
    // credit the strip, matches the Rust chain detector's policy.
    if !caps_stripped_by_literal_pattern(&new_lit).is_empty() {
        return None;
    }
    let caps = caps_stripped_by_literal_pattern(&old_lit);
    if caps.is_empty() { None } else { Some(caps) }
}

/// Like `first_call_ident`, but also checks if `n` itself is a call node.
/// `first_call_ident` only searches children, so when `n` IS the call
/// expression (e.g. the argument `sanitize(cmd)`), this function catches it.
pub(super) fn call_ident_of<'a>(n: Node<'a>, lang: &str, code: &'a [u8]) -> Option<String> {
    // C++ new/delete: normalize callee before field extraction.
    if lang == "cpp" && n.kind() == "new_expression" {
        return Some("new".to_string());
    }
    if lang == "cpp" && n.kind() == "delete_expression" {
        return Some("delete".to_string());
    }
    match lookup(lang, n.kind()) {
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
                if lookup(lang, unwrapped.kind()) == Kind::Function {
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
            let recv = n
                .child_by_field_name("object")
                .or_else(|| n.child_by_field_name("receiver"))
                .or_else(|| n.child_by_field_name("scope"))
                .and_then(|f| root_receiver_text(f, lang, code));
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
        let kind = child.kind();
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
        if kind == "keyword_argument" || kind == "named_argument" {
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
        let target_kind = target.kind();
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
            | "decimal_literal" => text_of(target, code).map(|s| s.to_string()),
            _ => None,
        };
        result.push(literal);
    }
    result
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
        if child.kind() == "string_content" {
            return text_of(child, code).map(|s| s.to_string());
        }
    }
    if raw.len() >= 2 {
        let bytes = raw.as_bytes();
        let first = bytes[0];
        let last = bytes[raw.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return Some(raw[1..raw.len() - 1].to_string());
        }
    }
    None
}

/// For each argument of `call_node`, find the callee name if that argument
/// is itself a call expression (e.g. `sanitize(x)` in `os.system(sanitize(x))`).
/// Returns a `Vec<Option<String>>` parallel to `extract_arg_uses` output.
pub(super) fn extract_arg_callees(call_node: Node, lang: &str, code: &[u8]) -> Vec<Option<String>> {
    let Some(args_node) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        // Bail on spread/splat like extract_arg_uses does
        let kind = child.kind();
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
        result.push(call_ident_of(child, lang, code));
    }
    result
}

/// Return `(defines, uses)` for the AST fragment `ast`.
/// Returns (defines, uses, extra_defines) where extra_defines captures additional
/// bindings from destructuring patterns beyond the primary define.
pub(super) fn def_use(
    ast: Node,
    lang: &str,
    code: &[u8],
) -> (Option<String>, Vec<String>, Vec<String>) {
    match lookup(lang, ast.kind()) {
        // Declaration wrappers (let, var, short_var_declaration, etc.)
        Kind::CallWrapper => {
            let mut defs = None;
            let mut extra_defs = Vec::new();
            let mut uses = Vec::new();

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
                    let is_assign = matches!(lookup(lang, child.kind()), Kind::Assignment);
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
                        if let Some(val_node) = child_value {
                            let mut idents = Vec::new();
                            let mut paths = Vec::new();
                            collect_idents_with_paths(val_node, code, &mut idents, &mut paths);
                            uses.extend(paths);
                            uses.extend(idents);
                            uses.extend(extract_rust_format_macro_named_idents_in(val_node, code));
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
            (defs, uses, extra_defs)
        }

        // Plain assignment `x = y`
        Kind::Assignment => {
            let mut defs = None;
            let mut uses = Vec::new();
            if let Some(lhs) = ast.child_by_field_name("left") {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(lhs, code, &mut idents, &mut paths);
                // Prefer dotted path (member expression) over last ident
                defs = paths.pop().or_else(|| idents.pop());
            }
            if let Some(rhs) = ast.child_by_field_name("right") {
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(rhs, code, &mut idents, &mut paths);
                uses.extend(paths);
                uses.extend(idents);
                uses.extend(extract_rust_format_macro_named_idents_in(rhs, code));
            }
            (defs, uses, vec![])
        }

        // if‑let / while‑let, the `let_condition` binds a variable from
        // the value expression.  E.g. `if let Ok(cmd) = env::var("CMD")`
        // defines `cmd` and uses `env`, `var`, `CMD`.
        Kind::If | Kind::While => {
            let cond = ast.child_by_field_name("condition");
            if let Some(c) = cond
                && c.kind() == "let_condition"
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
                return (defs, uses, vec![]);
            }

            let mut idents = Vec::new();
            let mut paths = Vec::new();
            collect_idents_with_paths(ast, code, &mut idents, &mut paths);
            let mut uses = paths;
            uses.extend(idents);
            (None, uses, vec![])
        }

        // for-in / for-of / Python `for x in iter:` ─────────────────────────
        //
        // Tree-sitter classifies these as `Kind::For` with a `left`/`right`
        // field pair (binding pattern + iterable).  Without an explicit
        // arm here, the default branch collects every ident as a `use` and
        // never registers the iteration binding as a `define`, so taint
        // entering the iterable does not propagate into the body's
        // references to the binding (`for (const [a, b] of obj) { sink(a) }`
        // would lose the flow at `a`).
        //
        // C-style `for_statement` has no `left`/`right` fields (it uses
        // `initializer`/`condition`/`increment`), so this path falls through
        // to the default-collecting behaviour for those, preserving today's
        // semantics.
        //
        // Go's `for ident := range iter` shape places the binding pattern
        // and iterable on a `range_clause` child of the `for_statement`
        // rather than as direct fields.  Without the range_clause lookup
        // below, taint from the iterable never reaches the loop binding
        // (CVE-2026-41422 daptin: `c.QueryArray("col")` loop var `project`
        // flows into `goqu.L(project)` SQL_QUERY sink).
        Kind::For => {
            let mut left = ast.child_by_field_name("left");
            let mut right = ast.child_by_field_name("right");
            if left.is_none() && right.is_none() {
                let mut cursor = ast.walk();
                for child in ast.children(&mut cursor) {
                    if child.kind() == "range_clause" {
                        left = child.child_by_field_name("left");
                        right = child.child_by_field_name("right");
                        break;
                    }
                }
            }
            if left.is_none() && right.is_none() {
                // C-style for, defer to default ident collection.
                let mut idents = Vec::new();
                let mut paths = Vec::new();
                collect_idents_with_paths(ast, code, &mut idents, &mut paths);
                let mut uses = paths;
                uses.extend(idents);
                return (None, uses, vec![]);
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
            (defs, uses, extra_defs)
        }

        // everything else – no definition, but may read vars
        _ => {
            let mut idents = Vec::new();
            let mut paths = Vec::new();
            collect_idents_with_paths(ast, code, &mut idents, &mut paths);
            let mut uses = paths;
            uses.extend(idents);
            (None, uses, vec![])
        }
    }
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
    let mut cursor = args_node.walk();
    for (idx, child) in args_node.named_children(&mut cursor).enumerate() {
        let kind = child.kind();
        // Splats break positional indexing; bail conservatively on the whole call.
        if kind == "spread_element"
            || kind == "dictionary_splat"
            || kind == "list_splat"
            || kind == "splat_argument"
            || kind == "hash_splat_argument"
        {
            return Vec::new();
        }
        if kind == "keyword_argument" || kind == "named_argument" {
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
                if pair.kind() != "pair" {
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

/// If `node` is an array literal of shape `[<shell>, "-c", *]` (POSIX shells)
/// or `[<cmd-shell>, "/c", *]` (Windows cmd.exe), return the identifiers
/// referenced in the payload elements (positions 2+).  Otherwise return
/// `None`.  Returning `Some(vec![])` means the payload is a constant string
/// — caller should still skip emitting a sink (no taint can reach a literal).
fn shell_array_payload_idents_of(node: Node, code: &[u8]) -> Option<Vec<String>> {
    let node = unwrap_parens(node);
    if node.kind() != "array" {
        return None;
    }
    // Walk named children to skip commas and other trivia.
    let mut cursor = node.walk();
    let elems: Vec<Node> = node.named_children(&mut cursor).collect();
    if elems.len() < 3 {
        return None;
    }
    let shell = const_string_value(elems[0], code)?;
    if !is_known_shell(&shell) {
        return None;
    }
    let flag = const_string_value(elems[1], code)?;
    if !is_shell_command_flag(&shell, &flag) {
        return None;
    }
    // Lift identifiers from the payload elements (positions 2+).  Constants
    // contribute nothing.  An empty result means the entire payload is
    // statically benign.
    let mut idents: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    for elem in &elems[2..] {
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
    match node.kind() {
        "string" | "string_literal" | "interpreted_string_literal" | "raw_string_literal" => {
            let raw = text_of(node, code)?;
            if raw.len() >= 2 {
                Some(raw[1..raw.len() - 1].to_string())
            } else {
                None
            }
        }
        "template_string" => {
            let mut c = node.walk();
            if node
                .named_children(&mut c)
                .any(|ch| ch.kind() == "template_substitution")
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
    // POSIX shells.
    flag == "-c"
}
