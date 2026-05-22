//! Shared PHP-route adapter helpers (Phase 16 — Track L.14).
//!
//! The Laravel / Symfony / CodeIgniter adapters all need the same
//! handful of tree-sitter helpers: locate a `function_definition` or
//! `method_declaration` by name, enumerate formal parameter names,
//! walk a method-level or class-level `attribute_list`
//! (`#[Route(...)]`), parse `Route::get('/x', ...)` static calls and
//! `$routes->get('users/(:num)', 'Controller::method')` member
//! calls, and bind formals to request slots.  Centralising the
//! helpers here keeps the three adapters terse and lets every
//! framework share the same placeholder-binding semantics.

use crate::dynamic::framework::{
    HttpMethod, MiddlewareShape, ParamBinding, ParamSource, auth_markers,
};
use crate::symbol::Lang;
use tree_sitter::Node;

/// True when `bytes` carries any of the well-known Laravel import
/// stanzas (the `Route::` facade, `Illuminate\…` namespace, the
/// `Illuminate\Routing\Router` class, the convention-based
/// `app/Http/Controllers` base class, or a `# nyx-shape: laravel`
/// annotation).
pub fn source_imports_laravel(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"Illuminate\\Routing",
            b"Illuminate\\Http",
            b"Illuminate\\Support\\Facades\\Route",
            b"use Illuminate\\",
            b"Route::get(",
            b"Route::post(",
            b"Route::put(",
            b"Route::patch(",
            b"Route::delete(",
            b"Route::any(",
            b"Route::match(",
            b"App\\Http\\Controllers",
            b"// nyx-shape: laravel",
        ],
    )
}

/// True when `bytes` carries any of the well-known Symfony import
/// stanzas (the `Symfony\…` namespace, the `#[Route]` attribute, the
/// `AbstractController` base class).
pub fn source_imports_symfony(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"Symfony\\Component\\Routing",
            b"Symfony\\Component\\HttpFoundation",
            b"Symfony\\Bundle\\FrameworkBundle",
            b"use Symfony\\",
            b"Symfony\\Component\\Routing\\Annotation\\Route",
            b"Symfony\\Component\\Routing\\Attribute\\Route",
            b"AbstractController",
            b"// nyx-shape: symfony",
        ],
    )
}

/// True when `bytes` carries any of the well-known CodeIgniter
/// import stanzas (the `CodeIgniter\…` namespace, the `$routes`
/// service used inside `app/Config/Routes.php`, the convention-based
/// `extends BaseController`, or a `# nyx-shape: codeigniter`
/// annotation).
pub fn source_imports_codeigniter(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"CodeIgniter\\Router",
            b"CodeIgniter\\HTTP",
            b"CodeIgniter\\Controller",
            b"use CodeIgniter\\",
            b"$routes->get(",
            b"$routes->post(",
            b"$routes->put(",
            b"$routes->patch(",
            b"$routes->delete(",
            b"$routes->add(",
            b"extends BaseController",
            b"// nyx-shape: codeigniter",
        ],
    )
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| haystack.windows(n.len()).any(|w| w == *n))
}

/// Find a top-level `function_definition` or a `method_declaration`
/// whose `name` field equals `target`.  Returns
/// `(node, enclosing_class_decl)` — the class is `Some` when the
/// match is a method.
pub fn find_php_function<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
) -> Option<(Node<'a>, Option<Node<'a>>)> {
    let mut hit: Option<(Node<'a>, Option<Node<'a>>)> = None;
    walk(root, bytes, target, None, &mut hit);
    hit
}

fn walk<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    enclosing_class: Option<Node<'a>>,
    out: &mut Option<(Node<'a>, Option<Node<'a>>)>,
) {
    if out.is_some() {
        return;
    }
    let here_class = if node.kind() == "class_declaration" {
        Some(node)
    } else {
        enclosing_class
    };
    if matches!(node.kind(), "function_definition" | "method_declaration")
        && let Some(name) = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(bytes).ok())
        && name == target
    {
        let klass = if node.kind() == "method_declaration" {
            here_class
        } else {
            None
        };
        *out = Some((node, klass));
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk(child, bytes, target, here_class, out);
    }
}

/// Enumerate formal parameter names from a `function_definition` /
/// `method_declaration` node.  Strips the leading `$` sigil from each
/// `variable_name` so `$id` → `id`.
pub fn php_formal_names(func: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(parameters) = func.child_by_field_name("parameters") else {
        return out;
    };
    let mut cur = parameters.walk();
    for fp in parameters.named_children(&mut cur) {
        if fp.kind() != "simple_parameter" && fp.kind() != "variadic_parameter" {
            continue;
        }
        let Some(name) = fp.child_by_field_name("name") else {
            continue;
        };
        let Ok(text) = name.utf8_text(bytes) else {
            continue;
        };
        let trimmed = text.trim_start_matches('$').to_owned();
        if !trimmed.is_empty() {
            out.push(trimmed);
        }
    }
    out
}

/// Read the simple class name from a `class_declaration` node — its
/// `name` field, which is a `name` leaf node.
pub fn php_class_name<'a>(class: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    class
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(bytes).ok())
}

/// Walk the `attribute_list` attached to a `class_declaration`,
/// `method_declaration`, or `function_definition` and invoke `visit`
/// for each contained `attribute`.  The visitor receives the
/// `attribute` node + the attribute's leaf name (the last segment of
/// the qualified name — `Symfony\…\Route` → `"Route"`).
pub fn iter_php_attributes<'a, F>(node: Node<'a>, bytes: &'a [u8], mut visit: F)
where
    F: FnMut(Node<'a>, &str),
{
    let Some(attrs) = node.child_by_field_name("attributes") else {
        return;
    };
    let mut gc = attrs.walk();
    for group in attrs.named_children(&mut gc) {
        if group.kind() != "attribute_group" {
            continue;
        }
        let mut ac = group.walk();
        for ann in group.named_children(&mut ac) {
            if ann.kind() != "attribute" {
                continue;
            }
            if let Some(leaf) = attribute_leaf_name(ann, bytes) {
                visit(ann, leaf);
            }
        }
    }
}

fn attribute_leaf_name<'a>(ann: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    let mut cur = ann.walk();
    for child in ann.named_children(&mut cur) {
        if matches!(child.kind(), "name" | "qualified_name" | "relative_name") {
            let text = child.utf8_text(bytes).ok()?;
            return Some(text.rsplit('\\').next().unwrap_or(text));
        }
    }
    None
}

/// First positional string-argument from an `attribute` /
/// `function_call_expression` / `member_call_expression` /
/// `scoped_call_expression` arguments node.
pub fn first_php_string_arg(arguments: Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cur = arguments.walk();
    for arg in arguments.named_children(&mut cur) {
        if arg.kind() != "argument" {
            continue;
        }
        if arg.child_by_field_name("name").is_some() {
            continue;
        }
        if let Some(value) = arg.named_child(0)
            && let Some(s) = string_content(value, bytes)
        {
            return Some(s);
        }
    }
    None
}

/// Read a named-argument's string value (e.g. `path: "/x"` →
/// `Some("/x")`).
pub fn named_string_arg(arguments: Node<'_>, bytes: &[u8], key: &str) -> Option<String> {
    let mut cur = arguments.walk();
    for arg in arguments.named_children(&mut cur) {
        if arg.kind() != "argument" {
            continue;
        }
        let Some(name_node) = arg.child_by_field_name("name") else {
            continue;
        };
        if name_node.utf8_text(bytes).ok() != Some(key) {
            continue;
        }
        if let Some(value) = named_arg_value(arg, name_node)
            && let Some(s) = string_content(value, bytes)
        {
            return Some(s);
        }
    }
    None
}

/// Parse a Symfony-style `methods: ['POST', 'PUT']` named argument
/// from an `arguments` node and return the first method, or `None`
/// when the kwarg is missing.
pub fn methods_named_arg(arguments: Node<'_>, bytes: &[u8]) -> Option<HttpMethod> {
    let mut cur = arguments.walk();
    for arg in arguments.named_children(&mut cur) {
        if arg.kind() != "argument" {
            continue;
        }
        let Some(name_node) = arg.child_by_field_name("name") else {
            continue;
        };
        if name_node.utf8_text(bytes).ok() != Some("methods") {
            continue;
        }
        let Some(value) = named_arg_value(arg, name_node) else {
            continue;
        };
        let raw = value.utf8_text(bytes).ok()?;
        for verb in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            if raw.contains(verb) {
                return HttpMethod::from_ident(verb);
            }
        }
    }
    None
}

/// Inside a named `argument` node (one with a `name` field), pick the
/// value child — the first named child whose byte range does not
/// coincide with the `name` field's range.  Tree-sitter PHP exposes
/// both the field-name leaf and the value as named children, so
/// `arg.named_child(0)` would otherwise return the leaf.
fn named_arg_value<'a>(arg: Node<'a>, name_node: Node<'a>) -> Option<Node<'a>> {
    let name_range = name_node.byte_range();
    let mut cur = arg.walk();
    arg.named_children(&mut cur)
        .find(|c| c.byte_range() != name_range)
}

/// Read the raw string content of a `string` / `encapsed_string` /
/// `name` value node, stripping the surrounding quotes (single,
/// double, or backtick).
pub fn string_content(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let raw = node.utf8_text(bytes).ok()?;
    let trimmed = raw.trim();
    let stripped = trimmed
        .trim_matches('\'')
        .trim_matches('"')
        .trim_matches('`');
    if stripped == trimmed {
        return None;
    }
    Some(stripped.to_owned())
}

/// Parse a Laravel/Symfony brace placeholder syntax (`/users/{id}` →
/// `id`; `/u/{id?}` → `id`) and a CodeIgniter parenthesised
/// placeholder syntax (`users/(:num)`, `users/(:any)`,
/// `users/(:segment)`).  Brace placeholders win when both are
/// present.
pub fn extract_php_path_placeholders(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if !name.is_empty() && !out.iter().any(|n| n == &name) {
            out.push(name);
        }
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}') {
                    let inner = &path[i + 1..i + 1 + end];
                    let stripped = inner.trim_end_matches('?');
                    let name = stripped.split(':').next().unwrap_or(stripped).trim();
                    push(name.to_owned());
                    i += end + 2;
                    continue;
                }
            }
            b'(' => {
                if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b')') {
                    let inner = &path[i + 1..i + 1 + end];
                    if let Some(name) = inner.strip_prefix(':') {
                        push(name.trim().to_owned());
                    }
                    i += end + 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Bind formals to request slots given a route path template.
///
/// A formal whose name matches a placeholder becomes a
/// [`ParamSource::PathSegment`].  `request` / `req` / `response` /
/// `res` go to [`ParamSource::Implicit`] (the Laravel
/// `IlluminateRequest`, Symfony `Request`, CodeIgniter
/// `IncomingRequest`).  Every other formal falls back to a
/// [`ParamSource::QueryParam`] of the same name.
pub fn bind_php_path_params(formals: &[String], path: &str) -> Vec<ParamBinding> {
    let placeholders = extract_php_path_placeholders(path);
    formals
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let source = if is_implicit_formal(name) {
                ParamSource::Implicit
            } else if placeholders.iter().any(|p| p == name) {
                ParamSource::PathSegment(name.clone())
            } else {
                ParamSource::QueryParam(name.clone())
            };
            ParamBinding {
                index: idx,
                name: name.clone(),
                source,
            }
        })
        .collect()
}

fn is_implicit_formal(name: &str) -> bool {
    matches!(name, "request" | "req" | "response" | "res")
}

/// Walk every `scoped_call_expression` in the file looking for a
/// `Route::get('/path', ...)` / `Route::post(...)` mapping that
/// references `target` either as a string callable (`'Controller@method'`,
/// `'Controller::method'`, `[Controller::class, 'method']`) or as a
/// closure declared inline (matched by callable arg-position only —
/// the adapter then accepts the binding because the surrounding
/// adapter has already matched the function's name to a Laravel route
/// shape).  Returns `(method, path)` on first match.
pub fn find_laravel_static_route<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    controller: Option<&str>,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    visit_laravel_routes(root, bytes, target, controller, &mut hit);
    hit
}

fn visit_laravel_routes<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    controller: Option<&str>,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "scoped_call_expression"
        && let Some(found) = try_laravel_route(node, bytes, target, controller)
    {
        *out = Some(found);
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        visit_laravel_routes(child, bytes, target, controller, out);
    }
}

fn try_laravel_route<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    controller: Option<&str>,
) -> Option<(HttpMethod, String)> {
    let scope = call.child_by_field_name("scope")?.utf8_text(bytes).ok()?;
    let scope_leaf = scope.rsplit('\\').next().unwrap_or(scope);
    if scope_leaf != "Route" {
        return None;
    }
    let verb_node = call.child_by_field_name("name")?.utf8_text(bytes).ok()?;
    let method = verb_method(verb_node)?;
    let args = call.child_by_field_name("arguments")?;
    let path = first_php_string_arg(args, bytes)?;
    if !laravel_callable_matches(args, bytes, target, controller) {
        return None;
    }
    Some((method, path))
}

/// Check the second positional arg of a `Route::verb('/x', ...)` call
/// against `target` (the action method name).  Accepts:
///   - Closures (treated as a wildcard — surrounding adapter has
///     already matched the function name)
///   - `'Controller@method'` / `'Controller::method'` strings
///   - `[ Controller::class, 'method' ]` arrays
fn laravel_callable_matches(
    arguments: Node<'_>,
    bytes: &[u8],
    target: &str,
    controller: Option<&str>,
) -> bool {
    let mut cur = arguments.walk();
    let mut positional: Vec<Node<'_>> = Vec::new();
    for arg in arguments.named_children(&mut cur) {
        if arg.kind() != "argument" {
            continue;
        }
        if arg.child_by_field_name("name").is_some() {
            continue;
        }
        positional.push(arg);
    }
    let Some(callable_arg) = positional.get(1) else {
        return false;
    };
    let Some(value) = callable_arg.named_child(0) else {
        return false;
    };
    match value.kind() {
        "anonymous_function" | "anonymous_function_creation_expression" | "arrow_function" => true,
        "string" | "encapsed_string" => {
            let Some(literal) = string_content(value, bytes) else {
                return false;
            };
            let (ctrl, act) = split_laravel_callable(&literal);
            if act != target {
                return false;
            }
            match controller {
                Some(c) => ctrl.as_deref() == Some(c),
                None => true,
            }
        }
        "array_creation_expression" => {
            let Some((ctrl, action)) = parse_array_callable(value, bytes) else {
                return false;
            };
            if action != target {
                return false;
            }
            match controller {
                Some(c) => ctrl.as_deref() == Some(c),
                None => true,
            }
        }
        _ => false,
    }
}

fn parse_array_callable<'a>(array: Node<'a>, bytes: &'a [u8]) -> Option<(Option<String>, String)> {
    let mut cur = array.walk();
    let elements: Vec<Node<'a>> = array
        .named_children(&mut cur)
        .filter(|c| c.kind() == "array_element_initializer")
        .collect();
    if elements.len() < 2 {
        return None;
    }
    let action_value = elements[1].named_child(0)?;
    let action = string_content(action_value, bytes)?;
    let ctrl_text = elements[0].utf8_text(bytes).ok()?.trim();
    let ctrl = ctrl_text
        .strip_suffix("::class")
        .map(|s| leaf(s).to_owned());
    Some((ctrl, action))
}

fn split_laravel_callable(literal: &str) -> (Option<String>, String) {
    if let Some((ctrl, act)) = literal.split_once('@') {
        return (Some(leaf(ctrl).to_owned()), act.to_owned());
    }
    if let Some((ctrl, act)) = literal.rsplit_once("::") {
        return (Some(leaf(ctrl).to_owned()), act.to_owned());
    }
    (None, literal.to_owned())
}

fn leaf(qualified: &str) -> &str {
    let last_backslash = qualified.rsplit('\\').next().unwrap_or(qualified);
    last_backslash.rsplit("::").next().unwrap_or(last_backslash)
}

fn verb_method(verb: &str) -> Option<HttpMethod> {
    match verb {
        "get" => Some(HttpMethod::GET),
        "post" => Some(HttpMethod::POST),
        "put" => Some(HttpMethod::PUT),
        "patch" => Some(HttpMethod::PATCH),
        "delete" => Some(HttpMethod::DELETE),
        "options" => Some(HttpMethod::OPTIONS),
        "head" => Some(HttpMethod::HEAD),
        "any" | "match" => Some(HttpMethod::GET),
        _ => None,
    }
}

/// Walk every `member_call_expression` in the file looking for a
/// CodeIgniter `$routes->get('users/(:num)', 'Controller::method')`
/// mapping that references `target` as the callable argument.
/// Returns `(method, path)` on first match.
pub fn find_codeigniter_route<'a>(
    root: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    controller: Option<&str>,
) -> Option<(HttpMethod, String)> {
    let mut hit: Option<(HttpMethod, String)> = None;
    visit_codeigniter_routes(root, bytes, target, controller, &mut hit);
    hit
}

fn visit_codeigniter_routes<'a>(
    node: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    controller: Option<&str>,
    out: &mut Option<(HttpMethod, String)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "member_call_expression"
        && let Some(found) = try_codeigniter_route(node, bytes, target, controller)
    {
        *out = Some(found);
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        visit_codeigniter_routes(child, bytes, target, controller, out);
    }
}

fn try_codeigniter_route<'a>(
    call: Node<'a>,
    bytes: &'a [u8],
    target: &str,
    controller: Option<&str>,
) -> Option<(HttpMethod, String)> {
    let object = call.child_by_field_name("object")?.utf8_text(bytes).ok()?;
    if object.trim_start_matches('$').trim() != "routes" {
        return None;
    }
    let verb = call.child_by_field_name("name")?.utf8_text(bytes).ok()?;
    let method = verb_method(verb)?;
    let args = call.child_by_field_name("arguments")?;
    let path = first_php_string_arg(args, bytes)?;
    if !codeigniter_callable_matches(args, bytes, target, controller) {
        return None;
    }
    Some((method, path))
}

fn codeigniter_callable_matches(
    arguments: Node<'_>,
    bytes: &[u8],
    target: &str,
    controller: Option<&str>,
) -> bool {
    let mut cur = arguments.walk();
    let mut positional: Vec<Node<'_>> = Vec::new();
    for arg in arguments.named_children(&mut cur) {
        if arg.kind() != "argument" {
            continue;
        }
        if arg.child_by_field_name("name").is_some() {
            continue;
        }
        positional.push(arg);
    }
    let Some(callable_arg) = positional.get(1) else {
        return false;
    };
    let Some(value) = callable_arg.named_child(0) else {
        return false;
    };
    match value.kind() {
        "anonymous_function" | "anonymous_function_creation_expression" | "arrow_function" => true,
        "string" | "encapsed_string" => {
            let Some(literal) = string_content(value, bytes) else {
                return false;
            };
            let (ctrl, act) = literal
                .rsplit_once("::")
                .map(|(c, a)| (Some(leaf(c).to_owned()), a.to_owned()))
                .unwrap_or((None, literal));
            if act != target {
                return false;
            }
            match controller {
                Some(c) => ctrl.as_deref() == Some(c),
                None => true,
            }
        }
        _ => false,
    }
}

/// Walk every PHP attach-site in `root` and collect arguments whose
/// names match a known PHP middleware marker (see
/// [`crate::dynamic::framework::auth_markers::is_protective`]).
///
/// Three attach idioms are recognised:
///
///   - **Chained `->middleware(...)` member calls** (Laravel):
///     `Route::get('/x', '...')->middleware('auth:sanctum')`,
///     `$this->middleware(['auth', 'verified'])` declared in a
///     controller constructor.
///   - **Static `Route::middleware(...)` scoped calls** (Laravel):
///     `Route::middleware(['auth'])->group(...)`.
///   - **Symfony PHP attributes** on `class_declaration` /
///     `method_declaration` / `function_definition`: `#[IsGranted]`,
///     `#[Security]`.  Attribute leaf names are wrapped with the
///     `#[...]` brackets so they classify against the PHP marker
///     table (`#[IsGranted]`, `#[Security]`).
///
/// Argument rendering (for `->middleware(...)` / `Route::middleware(...)`):
///   - string literal → string content (e.g. `'auth:sanctum'`)
///   - array literal  → each element string content, in order
///   - non-string args dropped silently
///
/// De-duplicates within a single file; preserves declaration order.
/// Names the registry does not recognise are dropped silently —
/// callers can re-walk with a wider predicate if broader inclusion is
/// needed.  CodeIgniter `['filter' => 'auth-jwt']` array-key idiom is
/// out of scope for v1; revisit when a real-world CodeIgniter fixture
/// surfaces the gap.
pub fn collect_php_middleware(root: Node<'_>, bytes: &[u8]) -> Vec<MiddlewareShape> {
    let mut raw: Vec<String> = Vec::new();
    walk_php_middleware(root, bytes, &mut raw);
    let mut out: Vec<MiddlewareShape> = Vec::new();
    for name in raw {
        if auth_markers::is_protective(Lang::Php, &name) && !out.iter().any(|m| m.name == name) {
            out.push(MiddlewareShape { name });
        }
    }
    out
}

fn walk_php_middleware(node: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "member_call_expression" | "scoped_call_expression" => {
            collect_middleware_call(node, bytes, out);
        }
        "class_declaration" | "method_declaration" | "function_definition" => {
            iter_php_attributes(node, bytes, |_ann, leaf| {
                out.push(format!("#[{leaf}]"));
            });
        }
        _ => {}
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_php_middleware(child, bytes, out);
    }
}

fn collect_middleware_call(call: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    let Some(name_node) = call.child_by_field_name("name") else {
        return;
    };
    let Ok(name) = name_node.utf8_text(bytes) else {
        return;
    };
    if name != "middleware" {
        return;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    let mut ac = args.walk();
    for arg in args.named_children(&mut ac) {
        if arg.kind() != "argument" {
            continue;
        }
        if arg.child_by_field_name("name").is_some() {
            continue;
        }
        let Some(value) = arg.named_child(0) else {
            continue;
        };
        push_middleware_value(value, bytes, out);
    }
}

fn push_middleware_value(node: Node<'_>, bytes: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "string" | "encapsed_string" => {
            if let Some(s) = string_content(node, bytes) {
                out.push(s);
            }
        }
        "array_creation_expression" => {
            let mut ac = node.walk();
            for elem in node.named_children(&mut ac) {
                if elem.kind() != "array_element_initializer" {
                    continue;
                }
                if let Some(value) = elem.named_child(0) {
                    push_middleware_value(value, bytes, out);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn finds_top_level_function() {
        let src: &[u8] = b"<?php\nfunction target($a) { return $a; }\n";
        let tree = parse(src);
        let (node, klass) = find_php_function(tree.root_node(), src, "target").unwrap();
        assert_eq!(node.kind(), "function_definition");
        assert!(klass.is_none());
    }

    #[test]
    fn finds_method_with_enclosing_class() {
        let src: &[u8] =
            b"<?php\nclass UserController {\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let (node, klass) = find_php_function(tree.root_node(), src, "show").unwrap();
        assert_eq!(node.kind(), "method_declaration");
        assert_eq!(klass.unwrap().kind(), "class_declaration");
    }

    #[test]
    fn formal_names_strip_dollar_sigil() {
        let src: &[u8] = b"<?php\nfunction f($id, $extra) { return $id; }\n";
        let tree = parse(src);
        let (func, _) = find_php_function(tree.root_node(), src, "f").unwrap();
        assert_eq!(php_formal_names(func, src), vec!["id", "extra"]);
    }

    #[test]
    fn extracts_brace_placeholders() {
        assert_eq!(extract_php_path_placeholders("/users/{id}"), vec!["id"]);
        assert_eq!(
            extract_php_path_placeholders("/u/{id}/p/{slug?}"),
            vec!["id", "slug"]
        );
        assert_eq!(extract_php_path_placeholders("/u/{id:[0-9]+}"), vec!["id"]);
    }

    #[test]
    fn extracts_codeigniter_placeholders() {
        assert_eq!(extract_php_path_placeholders("users/(:num)"), vec!["num"]);
        assert_eq!(
            extract_php_path_placeholders("p/(:any)/c/(:segment)"),
            vec!["any", "segment"]
        );
    }

    #[test]
    fn binds_known_placeholder_as_path_segment() {
        let formals = vec!["id".to_string(), "extra".to_string()];
        let bindings = bind_php_path_params(&formals, "/users/{id}");
        assert!(matches!(bindings[0].source, ParamSource::PathSegment(_)));
        assert!(matches!(bindings[1].source, ParamSource::QueryParam(_)));
    }

    #[test]
    fn binds_request_as_implicit() {
        let formals = vec!["request".to_string(), "id".to_string()];
        let bindings = bind_php_path_params(&formals, "/users/{id}");
        assert!(matches!(bindings[0].source, ParamSource::Implicit));
        assert!(matches!(bindings[1].source, ParamSource::PathSegment(_)));
    }

    #[test]
    fn iter_attributes_visits_each_attribute() {
        let src: &[u8] = b"<?php\nuse Symfony\\Component\\Routing\\Annotation\\Route;\nclass C {\n  #[Route('/x', methods: ['GET'])]\n  public function show($id) {}\n}\n";
        let tree = parse(src);
        let (method, _) = find_php_function(tree.root_node(), src, "show").unwrap();
        let mut hit_name: Option<String> = None;
        let mut hit_path: Option<String> = None;
        iter_php_attributes(method, src, |ann, name| {
            hit_name = Some(name.to_owned());
            let args = ann.child_by_field_name("parameters").unwrap();
            hit_path = first_php_string_arg(args, src);
        });
        assert_eq!(hit_name.as_deref(), Some("Route"));
        assert_eq!(hit_path.as_deref(), Some("/x"));
    }

    #[test]
    fn iter_attributes_reads_named_methods_kwarg() {
        let src: &[u8] = b"<?php\nclass C {\n  #[Route('/x', methods: ['POST'])]\n  public function save() {}\n}\n";
        let tree = parse(src);
        let (method, _) = find_php_function(tree.root_node(), src, "save").unwrap();
        let mut verb: Option<HttpMethod> = None;
        iter_php_attributes(method, src, |ann, _| {
            let args = ann.child_by_field_name("parameters").unwrap();
            verb = methods_named_arg(args, src);
        });
        assert_eq!(verb, Some(HttpMethod::POST));
    }

    #[test]
    fn finds_laravel_static_route_with_string_callable() {
        let src: &[u8] = b"<?php\nRoute::get('/users/{id}', 'UserController@show');\nclass UserController {\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let hit = find_laravel_static_route(tree.root_node(), src, "show", Some("UserController"))
            .unwrap();
        assert_eq!(hit.0, HttpMethod::GET);
        assert_eq!(hit.1, "/users/{id}");
    }

    #[test]
    fn finds_laravel_static_route_with_closure() {
        let src: &[u8] =
            b"<?php\nRoute::post('/users', function ($payload) { return $payload; });\n";
        let tree = parse(src);
        let hit = find_laravel_static_route(tree.root_node(), src, "anything", None).unwrap();
        assert_eq!(hit.0, HttpMethod::POST);
        assert_eq!(hit.1, "/users");
    }

    #[test]
    fn finds_codeigniter_member_route() {
        let src: &[u8] = b"<?php\n$routes->get('users/(:num)', 'UserController::show');\n";
        let tree = parse(src);
        let hit =
            find_codeigniter_route(tree.root_node(), src, "show", Some("UserController")).unwrap();
        assert_eq!(hit.0, HttpMethod::GET);
        assert_eq!(hit.1, "users/(:num)");
    }

    #[test]
    fn collects_chained_middleware_string_arg() {
        let src: &[u8] =
            b"<?php\nRoute::get('/users', 'UserController@index')->middleware('auth');\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.iter().any(|m| m.name == "auth"), "got {mw:?}");
    }

    #[test]
    fn collects_chained_middleware_with_sanctum_guard() {
        let src: &[u8] = b"<?php\nRoute::get('/x', 'C@x')->middleware('auth:sanctum');\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.iter().any(|m| m.name == "auth:sanctum"), "got {mw:?}");
    }

    #[test]
    fn collects_array_middleware_arg() {
        let src: &[u8] = b"<?php\nRoute::get('/x', 'C@x')->middleware(['auth', 'verified']);\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.iter().any(|m| m.name == "auth"), "got {mw:?}");
        assert!(mw.iter().any(|m| m.name == "verified"), "got {mw:?}");
    }

    #[test]
    fn collects_static_route_middleware_chain() {
        let src: &[u8] = b"<?php\nRoute::middleware(['auth'])->group(function () {});\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.iter().any(|m| m.name == "auth"), "got {mw:?}");
    }

    #[test]
    fn collects_controller_constructor_middleware() {
        let src: &[u8] = b"<?php\nclass C {\n  public function __construct() {\n    $this->middleware('auth');\n  }\n}\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.iter().any(|m| m.name == "auth"), "got {mw:?}");
    }

    #[test]
    fn collects_symfony_is_granted_attribute() {
        let src: &[u8] = b"<?php\nclass C {\n  #[IsGranted('ROLE_USER')]\n  public function show($id) { return $id; }\n}\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.iter().any(|m| m.name == "#[IsGranted]"), "got {mw:?}");
    }

    #[test]
    fn collects_symfony_security_attribute_at_class_level() {
        let src: &[u8] = b"<?php\n#[Security(\"is_granted('ROLE_ADMIN')\")]\nclass C {\n  public function show() { return 1; }\n}\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.iter().any(|m| m.name == "#[Security]"), "got {mw:?}");
    }

    #[test]
    fn drops_unknown_php_middleware_names() {
        let src: &[u8] =
            b"<?php\nRoute::get('/x', 'C@x')->middleware('custom-thing-not-in-table');\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        assert!(mw.is_empty(), "got {mw:?}");
    }

    #[test]
    fn dedupes_repeated_php_middleware() {
        let src: &[u8] = b"<?php\nRoute::get('/a', 'C@a')->middleware('auth');\nRoute::get('/b', 'C@b')->middleware('auth');\n";
        let tree = parse(src);
        let mw = collect_php_middleware(tree.root_node(), src);
        let auth_count = mw.iter().filter(|m| m.name == "auth").count();
        assert_eq!(auth_count, 1, "got {mw:?}");
    }
}
