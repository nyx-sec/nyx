use super::text_of;
use tree_sitter::Node;

/// Extract the leading identifier from a tree-sitter expression/call node.
///
/// Used by decorator extraction to reduce `login_required`, `permission_required(...)`,
/// `flask_login.login_required`, `hasRole('ADMIN')` to their first identifier
/// name, the matcher target.
fn leading_ident_text(node: Node<'_>, code: &[u8]) -> Option<String> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier"
            | "type_identifier"
            | "property_identifier"
            | "scoped_identifier"
            | "name"
            | "constant"
            | "simple_identifier" => {
                return text_of(cur, code);
            }
            _ => {}
        }
        // Peel wrappers: call → function, member/attribute → object or last segment
        if let Some(fn_field) = cur.child_by_field_name("function") {
            cur = fn_field;
            continue;
        }
        if let Some(name_field) = cur.child_by_field_name("name") {
            cur = name_field;
            continue;
        }
        if let Some(obj_field) = cur.child_by_field_name("object") {
            // For `flask_login.login_required`, we want the RIGHT side.
            if let Some(prop) = cur.child_by_field_name("property") {
                cur = prop;
                continue;
            }
            cur = obj_field;
            continue;
        }
        // Fallback: first non-trivia child.
        let mut walker = cur.walk();
        let next = cur
            .children(&mut walker)
            .find(|c| !matches!(c.kind(), "@" | "(" | ")" | "," | " " | "\n"));
        match next {
            Some(n) if n.id() != cur.id() => cur = n,
            _ => return text_of(cur, code),
        }
    }
}

/// Strip trailing `!` / `?` / `()` and leading `:` / `@`, then lowercase.
fn normalize_decorator_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let trimmed = trimmed.trim_start_matches(':').trim_start_matches('@');
    // If a call syntax leaked through (e.g. `UseGuards(AuthGuard)`), keep only
    // the head, callers that want the arg handle it separately.
    let head = trimmed
        .split(['(', ' ', '\t', '\n'])
        .next()
        .unwrap_or(trimmed);
    let head = head.trim_end_matches('!').trim_end_matches('?');
    // Keep only the last path segment so `module.name` / `a::b::c` become `c`.
    let head = head.rsplit(['.', ':']).next().unwrap_or(head);
    head.to_ascii_lowercase()
}

/// Collect decorator-argument identifiers for call-style decorators like
/// NestJS `@UseGuards(AuthGuard, JwtGuard)` or Java `@PreAuthorize("hasRole('USER')")`.
///
/// For Java annotations with string-literal arguments, also splits out bare
/// identifiers from inside the string so that `hasRole('ADMIN')` contributes
/// `hasrole` and `admin` as additional matcher candidates.
fn decorator_arg_names(decorator_ast: Node<'_>, code: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let args = decorator_ast.child_by_field_name("arguments").or_else(|| {
        let mut w = decorator_ast.walk();
        decorator_ast
            .children(&mut w)
            .find(|c| matches!(c.kind(), "argument_list" | "arguments"))
    });
    let Some(args) = args else {
        return out;
    };
    let mut walker = args.walk();
    for arg in args.children(&mut walker) {
        match arg.kind() {
            "(" | ")" | "," => continue,
            "string" | "string_literal" | "interpreted_string_literal" => {
                if let Some(s) = text_of(arg, code) {
                    for token in s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                        if !token.is_empty() {
                            out.push(token.to_ascii_lowercase());
                        }
                    }
                }
            }
            _ => {
                if let Some(name) = leading_ident_text(arg, code) {
                    out.push(name.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

/// Walk tree-sitter decorator/annotation/attribute children of a function AST
/// node and return normalized names for auth-rule matching.
///
/// Grammar-specific notes:
/// - **Python**: function is wrapped by `decorated_definition` whose siblings
///   are `decorator` nodes containing an `identifier` or `call` expression.
/// - **JS/TS**: decorators attach to `method_definition` children or appear
///   as siblings inside `class_body`; stage-3 decorators use `decorator` nodes.
///   `@UseGuards(AuthGuard)`, we include the call args too.
/// - **Java**: annotations live in the `modifiers` child of `method_declaration`;
///   kinds are `marker_annotation` / `annotation`.
/// - **Rust**: `function_item` has `attribute_item` siblings (outer `#[..]`).
/// - **PHP**: `method_declaration` has an `attribute_list` child with `attribute`
///   grandchildren (`#[IsGranted(..)]`).
/// - **C++**: `function_definition` preceded or prefixed by `attribute_declaration`
///   / `attribute` (`[[authenticated]]`).
/// - **Ruby**: not a per-function decorator. `before_action :authenticate_user!`
///   at class body scope applies to every method in the class. `only:` /
///   `except:` hash args scope the filter to the listed action names; the
///   filter is only recorded for the current method when the scope matches.
///   Conditional filters (`if:` / `unless:`) are not honored, those require
///   predicate evaluation and are deferred.
pub(super) fn extract_auth_decorators<'a>(
    func_node: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |raw: &str| {
        let norm = normalize_decorator_name(raw);
        if !norm.is_empty() && !out.contains(&norm) {
            out.push(norm);
        }
    };

    match lang {
        "python" => {
            if let Some(parent) = func_node.parent() {
                if parent.kind() == "decorated_definition" {
                    let mut w = parent.walk();
                    for ch in parent.children(&mut w) {
                        if ch.kind() != "decorator" {
                            continue;
                        }
                        // `decorator` → '@' + expression child.
                        let mut dw = ch.walk();
                        let expr = ch.children(&mut dw).find(|c| c.kind() != "@");
                        let Some(expr) = expr else { continue };
                        if let Some(name) = leading_ident_text(expr, code) {
                            push(&name);
                        }
                        // Arguments (e.g. `permission_required('view_user')`).
                        for arg in decorator_arg_names(expr, code) {
                            push(&arg);
                        }
                    }
                }
            }
        }
        "javascript" | "typescript" => {
            // Decorators may live as children of method_definition or as
            // preceding siblings inside a class_body.
            let mut seen = Vec::new();
            let mut w = func_node.walk();
            for ch in func_node.children(&mut w) {
                if ch.kind() == "decorator" {
                    seen.push(ch);
                }
            }
            if let Some(parent) = func_node.parent() {
                if parent.kind() == "class_body" {
                    let mut pw = parent.walk();
                    for sib in parent.children(&mut pw) {
                        if sib.id() == func_node.id() {
                            break;
                        }
                        if sib.kind() == "decorator" {
                            seen.push(sib);
                        } else if sib.kind() != "decorator" && !seen.is_empty() {
                            // Only the contiguous run of decorators immediately
                            // before this method is relevant; reset if a non-
                            // decorator node intervenes.
                            if sib.end_byte() < func_node.start_byte() {
                                seen.clear();
                            }
                        }
                    }
                }
            }
            for dec in seen {
                let mut dw = dec.walk();
                let expr = dec.children(&mut dw).find(|c| c.kind() != "@");
                let Some(expr) = expr else { continue };
                if let Some(name) = leading_ident_text(expr, code) {
                    push(&name);
                }
                for arg in decorator_arg_names(expr, code) {
                    push(&arg);
                }
            }
        }
        "java" => {
            // method_declaration has a `modifiers` field listing annotations.
            let modifiers = func_node.child_by_field_name("modifiers").or_else(|| {
                let mut w = func_node.walk();
                func_node.children(&mut w).find(|c| c.kind() == "modifiers")
            });
            if let Some(modifiers) = modifiers {
                let mut w = modifiers.walk();
                for ch in modifiers.children(&mut w) {
                    match ch.kind() {
                        "marker_annotation" | "annotation" => {
                            if let Some(name_node) = ch.child_by_field_name("name") {
                                if let Some(t) = text_of(name_node, code) {
                                    push(&t);
                                }
                            } else if let Some(t) = leading_ident_text(ch, code) {
                                push(&t);
                            }
                            for arg in decorator_arg_names(ch, code) {
                                push(&arg);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        "rust" => {
            // In tree-sitter-rust, outer `#[..]` attributes may appear either
            // as children of `function_item` OR as preceding siblings inside
            // the parent container (grammar has varied by version).
            let mut harvest = |node: Node<'_>| {
                if node.kind() == "attribute_item" || node.kind() == "inner_attribute_item" {
                    let mut aw = node.walk();
                    for inner in node.children(&mut aw) {
                        if inner.kind() == "attribute" {
                            if let Some(name) = leading_ident_text(inner, code) {
                                push(&name);
                            }
                        }
                    }
                }
            };
            let mut w = func_node.walk();
            for ch in func_node.children(&mut w) {
                harvest(ch);
            }
            if let Some(parent) = func_node.parent() {
                let mut pw = parent.walk();
                let mut pending: Vec<Node<'_>> = Vec::new();
                for sib in parent.children(&mut pw) {
                    if sib.id() == func_node.id() {
                        for p in &pending {
                            harvest(*p);
                        }
                        break;
                    }
                    if sib.kind() == "attribute_item" || sib.kind() == "inner_attribute_item" {
                        pending.push(sib);
                    } else {
                        pending.clear();
                    }
                }
            }
        }
        "php" => {
            // `attribute_list` child of `method_declaration`.
            let mut w = func_node.walk();
            for ch in func_node.children(&mut w) {
                if ch.kind() == "attribute_list" {
                    let mut aw = ch.walk();
                    for attr_group in ch.children(&mut aw) {
                        let mut gw = attr_group.walk();
                        for attr in attr_group.children(&mut gw) {
                            if attr.kind() == "attribute" {
                                if let Some(name) = leading_ident_text(attr, code) {
                                    push(&name);
                                }
                                for arg in decorator_arg_names(attr, code) {
                                    push(&arg);
                                }
                            }
                        }
                    }
                }
            }
        }
        "cpp" => {
            // C++ attributes `[[auth]]` appear as preceding siblings
            // (`attribute_declaration`) or as children of the function declarator.
            let mut harvest = |node: Node<'_>| {
                let mut w = node.walk();
                for ch in node.children(&mut w) {
                    if ch.kind() == "attribute" {
                        if let Some(name) = leading_ident_text(ch, code) {
                            push(&name);
                        }
                    }
                }
            };
            let mut w = func_node.walk();
            for ch in func_node.children(&mut w) {
                if ch.kind() == "attribute_declaration" || ch.kind() == "attribute_specifier" {
                    harvest(ch);
                }
            }
            if let Some(parent) = func_node.parent() {
                let mut pw = parent.walk();
                let mut pending: Vec<Node<'_>> = Vec::new();
                for sib in parent.children(&mut pw) {
                    if sib.id() == func_node.id() {
                        for p in &pending {
                            harvest(*p);
                        }
                        break;
                    }
                    if sib.kind() == "attribute_declaration" {
                        pending.push(sib);
                    } else {
                        pending.clear();
                    }
                }
            }
        }
        "ruby" => {
            // Walk up to enclosing class/module body and collect
            // `before_action :name` filter calls. Apply `only:` / `except:`
            // hash args by comparing against the current method name.
            let method_name = func_node
                .child_by_field_name("name")
                .and_then(|n| text_of(n, code))
                .map(|s| normalize_decorator_name(&s))
                .unwrap_or_default();
            let mut cursor = func_node.parent();
            while let Some(node) = cursor {
                match node.kind() {
                    "class" | "module" => {
                        // Body is the direct sibling/child sequence.
                        let mut w = node.walk();
                        for ch in node.children(&mut w) {
                            match ch.kind() {
                                "body_statement" | "block_body" => {
                                    let mut bw = ch.walk();
                                    for stmt in ch.children(&mut bw) {
                                        collect_ruby_before_action(
                                            stmt,
                                            code,
                                            &method_name,
                                            &mut out,
                                        );
                                    }
                                }
                                "call" | "method_call" | "identifier" | "command" => {
                                    collect_ruby_before_action(ch, code, &method_name, &mut out);
                                }
                                _ => {}
                            }
                        }
                        break;
                    }
                    _ => {}
                }
                cursor = node.parent();
            }
        }
        _ => {}
    }
    out
}

/// If a Ruby statement is `before_action :name` (or `before_filter :name`),
/// push the normalized filter name into `out`, honoring any `only:` / `except:`
/// hash arguments against `method_name`.
///
/// Positional symbol args (`before_action :a, :b, only: [:x]`) all share the
/// single trailing scope. Conditional filters (`if:` / `unless:`) are not
/// honored here, those require predicate evaluation and are deferred.
fn collect_ruby_before_action(
    node: Node<'_>,
    code: &[u8],
    method_name: &str,
    out: &mut Vec<String>,
) {
    // The call may be wrapped in expression nodes; drill to a call-shaped node.
    let mut cur = node;
    loop {
        match cur.kind() {
            "call" | "method_call" | "command" => break,
            _ => {}
        }
        let mut w = cur.walk();
        let next = cur
            .children(&mut w)
            .find(|c| matches!(c.kind(), "call" | "method_call" | "command" | "identifier"));
        match next {
            Some(n) if n.id() != cur.id() => cur = n,
            _ => return,
        }
    }
    let head = cur
        .child_by_field_name("method")
        .or_else(|| cur.child_by_field_name("name"))
        .and_then(|n| text_of(n, code))
        .or_else(|| leading_ident_text(cur, code));
    let Some(head) = head else { return };
    let head_lc = head.to_ascii_lowercase();
    if !(head_lc == "before_action" || head_lc == "before_filter") {
        return;
    }
    let args = cur.child_by_field_name("arguments").or_else(|| {
        let mut w = cur.walk();
        cur.children(&mut w).find(|c| {
            matches!(
                c.kind(),
                "argument_list" | "arguments" | "command_argument_list"
            )
        })
    });
    let Some(args) = args else { return };

    let mut positional: Vec<String> = Vec::new();
    let mut only_list: Vec<String> = Vec::new();
    let mut except_list: Vec<String> = Vec::new();
    let mut only_present = false;
    let mut except_present = false;

    let mut w = args.walk();
    for arg in args.children(&mut w) {
        match arg.kind() {
            "simple_symbol" | "symbol" | "hash_key_symbol" | "identifier" => {
                if let Some(t) = text_of(arg, code) {
                    let norm = normalize_decorator_name(&t);
                    if !norm.is_empty() {
                        positional.push(norm);
                    }
                }
            }
            "pair" => {
                collect_ruby_filter_pair(
                    arg,
                    code,
                    &mut only_list,
                    &mut except_list,
                    &mut only_present,
                    &mut except_present,
                );
            }
            "hash" => {
                let mut hw = arg.walk();
                for pair_node in arg.children(&mut hw) {
                    if pair_node.kind() == "pair" {
                        collect_ruby_filter_pair(
                            pair_node,
                            code,
                            &mut only_list,
                            &mut except_list,
                            &mut only_present,
                            &mut except_present,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    // Scope check: apply filter to this method only when the scope matches.
    if except_present
        && except_list
            .iter()
            .any(|n| n.eq_ignore_ascii_case(method_name))
    {
        return;
    }
    if only_present
        && !only_list
            .iter()
            .any(|n| n.eq_ignore_ascii_case(method_name))
    {
        return;
    }

    for filter in positional {
        if !out.contains(&filter) {
            out.push(filter);
        }
    }
}

/// Parse a single `only:` / `except:` hash pair and append the symbol list into
/// the corresponding out-vec. Sets the `*_present` flag when the key is seen,
/// regardless of whether the value parses into any symbols, treating
/// `only: []` as "no actions match" is safer than ignoring the scope.
fn collect_ruby_filter_pair(
    pair_node: Node<'_>,
    code: &[u8],
    only_list: &mut Vec<String>,
    except_list: &mut Vec<String>,
    only_present: &mut bool,
    except_present: &mut bool,
) {
    let key_node = pair_node.child_by_field_name("key");
    let Some(key_node) = key_node else { return };
    let Some(key_text) = text_of(key_node, code) else {
        return;
    };
    let key_norm = normalize_decorator_name(&key_text);
    let value_node = pair_node.child_by_field_name("value");
    match key_norm.as_str() {
        "only" => {
            *only_present = true;
            if let Some(v) = value_node {
                collect_ruby_symbol_list(v, code, only_list);
            }
        }
        "except" => {
            *except_present = true;
            if let Some(v) = value_node {
                collect_ruby_symbol_list(v, code, except_list);
            }
        }
        _ => {}
    }
}

/// Recursively collect symbol / identifier names from a `:x` or `[:x, :y]`
/// value into `out`, using the tree-sitter AST (no text parsing).
fn collect_ruby_symbol_list(node: Node<'_>, code: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "simple_symbol" | "symbol" | "hash_key_symbol" | "identifier" | "string" => {
            if let Some(t) = text_of(node, code) {
                let norm = normalize_decorator_name(&t);
                if !norm.is_empty() {
                    out.push(norm);
                }
            }
        }
        "array" => {
            let mut w = node.walk();
            for ch in node.children(&mut w) {
                collect_ruby_symbol_list(ch, code, out);
            }
        }
        _ => {}
    }
}

/// Extract route-path capture variable names from framework routing decorators
/// on a function AST node.
///
/// Supported languages:
/// * Python: walks Flask-style `@app.route("/users/<name>")`,
///   blueprint-prefixed `@bp.get("/u/<int:id>")`, and verb-shaped
///   `@router.post("/<path:slug>")` decorators. Returns inner names from
///   `<name>` / `<conv:name>` brace-segments.
/// * Ruby: walks Sinatra `get "/u/:name" do |name| ... end`. The
///   `func_node` is the `do_block`; its parent `call` carries the verb
///   in the `method` field and the path pattern in the first positional
///   string argument. Returns inner names from `:name` colon-segments.
///
/// Functions without a recognised routing pattern return an empty `Vec`.
/// Strict additive: downstream consumers gate the result via
/// `param.contains(name)` so empty captures preserve today's behaviour.
pub(super) fn extract_route_path_captures<'a>(
    func_node: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match lang {
        "python" => extract_python_route_captures(func_node, code, &mut out),
        "ruby" => extract_ruby_route_captures(func_node, code, &mut out),
        _ => {}
    }
    out
}

fn extract_python_route_captures<'a>(
    func_node: Node<'a>,
    code: &'a [u8],
    out: &mut Vec<String>,
) {
    let Some(parent) = func_node.parent() else {
        return;
    };
    if parent.kind() != "decorated_definition" {
        return;
    }
    let mut w = parent.walk();
    for ch in parent.children(&mut w) {
        if ch.kind() != "decorator" {
            continue;
        }
        let mut dw = ch.walk();
        let Some(expr) = ch.children(&mut dw).find(|c| c.kind() != "@") else {
            continue;
        };
        if expr.kind() != "call" {
            continue;
        }
        let Some(target) = expr.child_by_field_name("function") else {
            continue;
        };
        if target.kind() != "attribute" {
            continue;
        }
        let Some(attr) = target.child_by_field_name("attribute") else {
            continue;
        };
        let Some(attr_text) = text_of(attr, code) else {
            continue;
        };
        let attr_lower = attr_text.to_ascii_lowercase();
        let is_route_verb = matches!(
            attr_lower.as_str(),
            "route" | "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
        );
        if !is_route_verb {
            continue;
        }
        let Some(args) = expr.child_by_field_name("arguments") else {
            continue;
        };
        let Some(pattern) = first_positional_string_arg(args, code) else {
            continue;
        };
        collect_flask_path_captures(&pattern, out);
        collect_fastapi_path_captures(&pattern, out);
    }
}

/// Walk up from a Ruby `do_block` / `block` to the enclosing `call`.
/// If the call's method is a Sinatra-style HTTP verb and its first
/// positional argument is a static string literal, parse Sinatra
/// `:name` path captures into `out`.
fn extract_ruby_route_captures<'a>(
    func_node: Node<'a>,
    code: &'a [u8],
    out: &mut Vec<String>,
) {
    let Some(parent) = func_node.parent() else {
        return;
    };
    if parent.kind() != "call" {
        return;
    }
    let Some(method_node) = parent.child_by_field_name("method") else {
        return;
    };
    let Some(verb) = text_of(method_node, code) else {
        return;
    };
    let verb_lc = verb.to_ascii_lowercase();
    let is_sinatra_verb = matches!(
        verb_lc.as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "link" | "unlink"
    );
    if !is_sinatra_verb {
        return;
    }
    let Some(args) = parent.child_by_field_name("arguments") else {
        return;
    };
    let Some(pattern) = first_positional_string_arg_ruby(args, code) else {
        return;
    };
    collect_sinatra_path_captures(&pattern, out);
}

/// Return the literal text of the first positional string argument inside a
/// Python `argument_list`. Skips keyword args and non-string positionals.
fn first_positional_string_arg(args: Node<'_>, code: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        match arg.kind() {
            "(" | ")" | "," => continue,
            "keyword_argument" => continue,
            "string" => {
                return python_string_text(arg, code);
            }
            _ => return None,
        }
    }
    None
}

/// Strip Python string-literal quoting from a `string` AST node. Rejects
/// f-strings (interpolation children present) because the captured pattern
/// is not statically known.
fn python_string_text(node: Node<'_>, code: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for ch in node.children(&mut cursor) {
        if ch.kind() == "interpolation" {
            return None;
        }
    }
    let raw = text_of(node, code)?;
    let trimmed = raw.trim();
    let trimmed = trimmed
        .trim_start_matches(['r', 'R', 'b', 'B', 'u', 'U', 'f', 'F']);
    let stripped = trimmed
        .strip_prefix("\"\"\"")
        .and_then(|s| s.strip_suffix("\"\"\""))
        .or_else(|| trimmed.strip_prefix("'''").and_then(|s| s.strip_suffix("'''")))
        .or_else(|| trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .or_else(|| trimmed.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))?;
    Some(stripped.to_string())
}

/// Return the literal text of the first positional string argument inside a
/// Ruby `argument_list`. Hash literals (`pair`), block arguments,
/// hash-splat arguments, and non-string positionals all return `None`.
fn first_positional_string_arg_ruby(args: Node<'_>, code: &[u8]) -> Option<String> {
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        match arg.kind() {
            "(" | ")" | "," => continue,
            "pair" | "hash" | "block_argument" | "hash_splat_argument" => return None,
            "string" => return ruby_string_text(arg, code),
            _ => return None,
        }
    }
    None
}

/// Strip Ruby string-literal quoting from a `string` AST node. Rejects
/// strings with `#{...}` interpolation (the captured pattern is not
/// statically known). Returns the concatenation of `string_content`
/// children.
fn ruby_string_text(node: Node<'_>, code: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let mut content = String::new();
    let mut had_content = false;
    for ch in node.children(&mut cursor) {
        match ch.kind() {
            "interpolation" => return None,
            "string_content" => {
                if let Some(t) = text_of(ch, code) {
                    content.push_str(&t);
                    had_content = true;
                }
            }
            _ => continue,
        }
    }
    if had_content { Some(content) } else { None }
}

/// Parse Sinatra-style `:name` capture segments out of a route pattern.
/// A capture is a `:` followed by an identifier-ish run of bytes
/// (`[A-Za-z0-9_]+`). Only fires when `:` is at pattern start or
/// immediately follows `/`, so `Foo::Bar` style names embedded in a
/// non-routing string are not mis-parsed as captures.
fn collect_sinatra_path_captures(pattern: &str, out: &mut Vec<String>) {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let at_segment_boundary = i == 0 || bytes[i - 1] == b'/';
        if bytes[i] == b':' && at_segment_boundary {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > i + 1 {
                let name = &pattern[i + 1..j];
                let lower = name.to_ascii_lowercase();
                if !out.iter().any(|existing| existing == &lower) {
                    out.push(lower);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
}

/// Parse FastAPI / Starlette-style `{name}` / `{name:converter}` capture
/// segments out of a route pattern. Pushes the inner name (lowercased)
/// into `out`. FastAPI puts the name FIRST (`{item_id:int}`), unlike
/// Flask which puts the converter first (`<int:item_id>`). Skips
/// malformed segments (no closing `}`, empty name) and rejects names
/// with non-identifier characters.
fn collect_fastapi_path_captures(pattern: &str, out: &mut Vec<String>) {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            let inner = &pattern[i + 1..j];
            let name = inner.split(':').next().unwrap_or(inner).trim();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                let lower = name.to_ascii_lowercase();
                if !out.iter().any(|existing| existing == &lower) {
                    out.push(lower);
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
}

/// Parse Flask-style `<conv:name>` / `<name>` capture segments out of a
/// route pattern. Pushes the inner name (lowercased) into `out`. Skips
/// malformed segments (no closing `>`, empty name).
fn collect_flask_path_captures(pattern: &str, out: &mut Vec<String>) {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'>' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            let inner = &pattern[i + 1..j];
            let name = match inner.rsplit_once(':') {
                Some((_, n)) => n,
                None => inner,
            };
            let name = name.trim();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                let lower = name.to_ascii_lowercase();
                if !out.iter().any(|existing| existing == &lower) {
                    out.push(lower);
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod path_capture_tests {
    use super::*;

    fn collect_for(pat: &str) -> Vec<String> {
        let mut out = Vec::new();
        collect_flask_path_captures(pat, &mut out);
        out
    }

    #[test]
    fn extracts_bare_capture() {
        assert_eq!(collect_for("/users/<name>"), vec!["name".to_string()]);
    }

    #[test]
    fn extracts_converter_capture() {
        assert_eq!(
            collect_for("/items/<int:item_id>"),
            vec!["item_id".to_string()]
        );
    }

    #[test]
    fn extracts_path_converter() {
        assert_eq!(collect_for("/x/<path:slug>"), vec!["slug".to_string()]);
    }

    #[test]
    fn extracts_multiple_captures() {
        assert_eq!(
            collect_for("/u/<uid>/post/<int:pid>"),
            vec!["uid".to_string(), "pid".to_string()]
        );
    }

    #[test]
    fn dedupes_repeated_names() {
        let mut out = Vec::new();
        collect_flask_path_captures("/<a>/<a>", &mut out);
        assert_eq!(out, vec!["a".to_string()]);
    }

    #[test]
    fn rejects_unclosed_brace() {
        assert_eq!(collect_for("/<oops"), Vec::<String>::new());
    }

    #[test]
    fn rejects_non_ident_chars() {
        assert_eq!(collect_for("/<bad name>"), Vec::<String>::new());
        assert_eq!(collect_for("/<name!>"), Vec::<String>::new());
    }

    #[test]
    fn empty_when_no_captures() {
        assert_eq!(collect_for("/static/path"), Vec::<String>::new());
    }

    fn collect_sinatra_for(pat: &str) -> Vec<String> {
        let mut out = Vec::new();
        collect_sinatra_path_captures(pat, &mut out);
        out
    }

    #[test]
    fn sinatra_extracts_bare_capture() {
        assert_eq!(
            collect_sinatra_for("/users/:name"),
            vec!["name".to_string()]
        );
    }

    #[test]
    fn sinatra_extracts_multiple_captures() {
        assert_eq!(
            collect_sinatra_for("/u/:uid/post/:pid"),
            vec!["uid".to_string(), "pid".to_string()]
        );
    }

    #[test]
    fn sinatra_extracts_leading_capture() {
        assert_eq!(collect_sinatra_for(":root"), vec!["root".to_string()]);
    }

    #[test]
    fn sinatra_dedupes_repeated_names() {
        let mut out = Vec::new();
        collect_sinatra_path_captures("/:a/:a", &mut out);
        assert_eq!(out, vec!["a".to_string()]);
    }

    #[test]
    fn sinatra_ignores_double_colon() {
        assert_eq!(collect_sinatra_for("/Foo::Bar"), Vec::<String>::new());
    }

    #[test]
    fn sinatra_ignores_lone_colon() {
        assert_eq!(collect_sinatra_for("/users/:"), Vec::<String>::new());
    }

    #[test]
    fn sinatra_empty_when_no_captures() {
        assert_eq!(collect_sinatra_for("/static/path"), Vec::<String>::new());
    }

    fn collect_fastapi_for(pat: &str) -> Vec<String> {
        let mut out = Vec::new();
        collect_fastapi_path_captures(pat, &mut out);
        out
    }

    #[test]
    fn fastapi_extracts_bare_capture() {
        assert_eq!(
            collect_fastapi_for("/items/{item_id}"),
            vec!["item_id".to_string()]
        );
    }

    #[test]
    fn fastapi_extracts_converter_capture() {
        assert_eq!(
            collect_fastapi_for("/items/{item_id:int}"),
            vec!["item_id".to_string()]
        );
    }

    #[test]
    fn fastapi_extracts_path_converter() {
        assert_eq!(
            collect_fastapi_for("/files/{file_path:path}"),
            vec!["file_path".to_string()]
        );
    }

    #[test]
    fn fastapi_extracts_multiple_captures() {
        assert_eq!(
            collect_fastapi_for("/u/{uid}/post/{pid:int}"),
            vec!["uid".to_string(), "pid".to_string()]
        );
    }

    #[test]
    fn fastapi_dedupes_repeated_names() {
        let mut out = Vec::new();
        collect_fastapi_path_captures("/{a}/{a}", &mut out);
        assert_eq!(out, vec!["a".to_string()]);
    }

    #[test]
    fn fastapi_rejects_unclosed_brace() {
        assert_eq!(collect_fastapi_for("/{oops"), Vec::<String>::new());
    }

    #[test]
    fn fastapi_rejects_non_ident_chars() {
        assert_eq!(collect_fastapi_for("/{bad name}"), Vec::<String>::new());
        assert_eq!(collect_fastapi_for("/{name!}"), Vec::<String>::new());
    }

    #[test]
    fn fastapi_empty_when_no_captures() {
        assert_eq!(collect_fastapi_for("/static/path"), Vec::<String>::new());
    }
}
