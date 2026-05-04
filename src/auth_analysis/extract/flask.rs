use super::AuthExtractor;
use super::common::{
    attach_route_handler, auth_check_from_call_site, call_site_from_node, named_children,
    push_route_registration, string_literal_value, text, visit_named_nodes,
};
use crate::auth_analysis::config::{AuthAnalysisRules, matches_name};
use crate::auth_analysis::extract::common::decorated_definition_child;
use crate::auth_analysis::model::{AuthorizationModel, CallSite, Framework, HttpMethod};
use crate::labels::bare_method_name;
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct FlaskExtractor;

impl AuthExtractor for FlaskExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "python"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Flask))
    }

    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        path: &Path,
        rules: &AuthAnalysisRules,
        model: &mut AuthorizationModel,
    ) {
        let root = tree.root_node();
        visit_named_nodes(root, &mut |node| {
            if node.kind() == "decorated_definition" {
                maybe_collect_flask_route(root, node, bytes, path, rules, model);
            }
        });
    }
}

#[derive(Clone)]
struct FlaskRouteSpec {
    method: HttpMethod,
    path: String,
}

fn maybe_collect_flask_route(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(definition) = decorated_definition_child(node) else {
        return;
    };
    if definition.kind() != "function_definition" {
        return;
    }

    let mut route_specs = Vec::new();
    let mut middleware_calls = Vec::new();
    for decorator in decorator_expressions(node) {
        if let Some(mut specs) = parse_flask_route_decorator(decorator, bytes) {
            route_specs.append(&mut specs);
            // FastAPI puts route-level dependencies (auth checks +
            // logging hooks) inside the route decorator's
            // `dependencies=[Depends(...)]` keyword argument, instead
            // of as separate `@decorator` lines like Flask.  Walk the
            // route decorator's keyword args for that shape and lift
            // each `Depends(call(...))` element into the
            // middleware_calls list, so the same `inject_middleware_auth`
            // path that Flask uses also picks up FastAPI auth deps.
            middleware_calls.extend(extract_fastapi_dependencies(decorator, bytes));
        } else {
            middleware_calls.extend(expand_decorator_calls(decorator, bytes));
        }
    }

    if route_specs.is_empty() {
        return;
    }

    for spec in route_specs {
        let Some(handler) = attach_route_handler(
            root,
            node,
            format!("{:?} {}", spec.method, spec.path),
            bytes,
            rules,
            model,
        ) else {
            continue;
        };
        inject_middleware_auth(
            model,
            handler.unit_idx,
            handler.line,
            &middleware_calls,
            rules,
        );

        push_route_registration(
            model,
            Framework::Flask,
            spec.method,
            spec.path,
            path,
            handler,
            middleware_calls.clone(),
        );
    }
}

fn parse_flask_route_decorator(
    decorator_expr: Node<'_>,
    bytes: &[u8],
) -> Option<Vec<FlaskRouteSpec>> {
    let function = if decorator_expr.kind() == "call" {
        decorator_expr.child_by_field_name("function")?
    } else {
        return None;
    };

    let callee = text(function, bytes);
    if callee_is_test_decorator(&callee) {
        return None;
    }
    let method_name = bare_method_name(&callee);
    let arguments = decorator_expr.child_by_field_name("arguments")?;
    let args = named_children(arguments);

    let route_path = args
        .iter()
        .find_map(|arg| string_literal_value(*arg, bytes))
        .or_else(|| keyword_argument_string(arguments, bytes, "rule"))?;

    let methods = match method_name.to_ascii_lowercase().as_str() {
        "get" => vec![HttpMethod::Get],
        "post" => vec![HttpMethod::Post],
        "put" => vec![HttpMethod::Put],
        "delete" => vec![HttpMethod::Delete],
        "patch" => vec![HttpMethod::Patch],
        "route" => parse_methods_keyword(arguments, bytes).unwrap_or_else(|| vec![HttpMethod::Get]),
        _ => return None,
    };

    Some(
        methods
            .into_iter()
            .map(|method| FlaskRouteSpec {
                method,
                path: route_path.clone(),
            })
            .collect(),
    )
}

fn parse_methods_keyword(arguments: Node<'_>, bytes: &[u8]) -> Option<Vec<HttpMethod>> {
    let value = keyword_argument_value(arguments, bytes, "methods")?;
    let mut methods = Vec::new();
    for child in named_children(value) {
        if let Some(method) = string_literal_value(child, bytes).and_then(|text| http_method(&text))
        {
            methods.push(method);
        }
    }
    if methods.is_empty() {
        None
    } else {
        Some(methods)
    }
}

/// True iff the callee text matches a known Python test-framework
/// decorator that incidentally collides with the Flask `<app>.<verb>`
/// shape.  `unittest.mock.patch` is the dominant collision: it takes a
/// string literal as its first positional arg (the import path of the
/// thing being patched), and `bare_method_name("mock.patch")` is
/// `patch`, which `parse_flask_route_decorator` previously matched as
/// HTTP PATCH.  Every test method decorated with `@mock.patch("...")`
/// was therefore being attached as a Flask route handler, which
/// flipped its `unit.kind` to `RouteHandler` and made it pass
/// `unit_has_user_input_evidence` unconditionally — flooding the
/// pytest test suites with `missing_ownership_check` findings.
///
/// The denylist mirrors common mock / monkeypatch / parametrize forms.
/// Conservative: matches only the canonical receiver chains; an
/// imported alias `from unittest.mock import patch` then bare
/// `@patch("x")` would still match `patch` as PATCH, but the
/// decorator must also carry a string-literal first arg AND the
/// route-attached unit must come back through the auth analysis to
/// fire — handlers with a string-arg decorator are rare outside Flask
/// itself, and the wider precondition path now covers most of those.
fn callee_is_test_decorator(callee: &str) -> bool {
    matches!(
        callee,
        "mock.patch"
            | "mock.patch.object"
            | "mock.patch.dict"
            | "mock.patch.multiple"
            | "unittest.mock.patch"
            | "unittest.mock.patch.object"
            | "unittest.mock.patch.dict"
            | "unittest.mock.patch.multiple"
            | "monkeypatch.setattr"
            | "monkeypatch.setenv"
            | "monkeypatch.delattr"
            | "monkeypatch.delenv"
            | "pytest.mark.parametrize"
    )
}

fn keyword_argument_string(arguments: Node<'_>, bytes: &[u8], name: &str) -> Option<String> {
    let value = keyword_argument_value(arguments, bytes, name)?;
    string_literal_value(value, bytes)
}

fn keyword_argument_value<'tree>(
    arguments: Node<'tree>,
    bytes: &[u8],
    name: &str,
) -> Option<Node<'tree>> {
    for arg in named_children(arguments) {
        if arg.kind() != "keyword_argument" {
            continue;
        }
        let key = arg.child_by_field_name("name")?;
        if text(key, bytes) == name {
            return arg.child_by_field_name("value");
        }
    }
    None
}

fn http_method(value: &str) -> Option<HttpMethod> {
    match value.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        _ => None,
    }
}

fn decorator_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| named_children(decorator).into_iter().next())
        .collect()
}

fn expand_decorator_calls(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    if node.kind() == "call" {
        let call = call_site_from_node(node, bytes);
        if matches_name(&call.name, "method_decorator")
            && let Some(arguments) = node.child_by_field_name("arguments")
            && let Some(first) = named_children(arguments).first().copied()
        {
            return vec![call_site_from_node(first, bytes)];
        }
        return vec![call];
    }

    vec![call_site_from_node(node, bytes)]
}

/// Walk the route-decorator call's keyword args looking for the FastAPI
/// `dependencies=[Depends(call(...)), Depends(call), ...]` shape.  For
/// each `Depends(...)` list element, extract the inner callable as a
/// `CallSite` so it can flow through `inject_middleware_auth` and be
/// matched against the per-language authorization-check / login-guard
/// name lists.  Refuses non-call elements and `Depends(...)` without a
/// recognised inner call shape.
///
/// The function is decoupled from Flask semantics (Flask routes never
/// use `dependencies=`); the lookup is purely structural and matches
/// FastAPI's documented dependency-injection convention.  Lives in the
/// flask module because Flask's route-decorator parser already targets
/// the `@<router>.<method>(<path>, ...)` shape that FastAPI shares.
fn extract_fastapi_dependencies(decorator_expr: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    if decorator_expr.kind() != "call" {
        return Vec::new();
    }
    let Some(arguments) = decorator_expr.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let Some(value) = keyword_argument_value(arguments, bytes, "dependencies") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for element in named_children(value) {
        if let Some(call) = unwrap_depends_call(element, bytes) {
            out.push(call);
        }
    }
    out
}

/// Unwrap one `Depends(...)` list element from a FastAPI `dependencies`
/// list and return the inner callable as a `CallSite`.  Three shapes
/// are accepted:
///   * `Depends(callee(arg1, arg2))`, most common, the inner call is
///     the callable factory invocation; record `callee` as the auth
///     check.
///   * `Depends(callee)`, bare reference; record `callee` itself.
///   * `Depends()` / non-`Depends` items, skipped.
fn unwrap_depends_call(node: Node<'_>, bytes: &[u8]) -> Option<CallSite> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let function_text = text(function, bytes);
    if !is_depends_callee(&function_text) {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let first = named_children(arguments).into_iter().next()?;
    match first.kind() {
        "call" => Some(call_site_from_node(first, bytes)),
        "identifier" | "attribute" | "scoped_identifier" => Some(call_site_from_node(first, bytes)),
        _ => None,
    }
}

/// True for the FastAPI `Depends` marker, including the
/// fully-qualified `fastapi.Depends` form.  Conservative: only literal
/// matches, no canonicalisation.
fn is_depends_callee(callee: &str) -> bool {
    let trimmed = callee.trim();
    matches!(
        trimmed,
        "Depends" | "fastapi.Depends" | "fastapi.params.Depends"
    )
}

fn inject_middleware_auth(
    model: &mut AuthorizationModel,
    unit_idx: usize,
    line: usize,
    middleware_calls: &[CallSite],
    rules: &AuthAnalysisRules,
) {
    let Some(unit) = model.units.get_mut(unit_idx) else {
        return;
    };
    for call in middleware_calls {
        if let Some(mut check) = auth_check_from_call_site(call, line, rules) {
            // Mark as route-level: the check is declared at the route
            // boundary (Flask `@requires_role(...)` decorator, FastAPI
            // `dependencies=[Depends(...)]`, or any custom-router
            // equivalent) and semantically authorizes every value the
            // handler receives, path param, body, query, downstream
            // row fetches, the lot.  `auth_check_covers_subject` reads
            // `is_route_level` and short-circuits `true` for any
            // non-login-guard match, which is the correct shape for a
            // decorator-level guard whose inner call carries no
            // per-arg subject ref pointing back into the handler body.
            // LoginGuard / TokenExpiry / TokenRecipient kinds are
            // already excluded by `has_prior_subject_auth`'s filter
            // before they reach `auth_check_covers_subject`, so the
            // flag is safe to set unconditionally here, it has no
            // effect on those kinds.
            check.is_route_level = true;
            unit.auth_checks.push(check);
        }
    }
}

#[cfg(test)]
mod test_decorator_tests {
    use super::callee_is_test_decorator;

    /// Test-framework decorators that share their bare method name with
    /// a Flask HTTP verb (`patch`, `delete`, ...) must be excluded
    /// from `parse_flask_route_decorator`.  Without the denylist,
    /// every `@mock.patch("module")` in pytest test files attaches
    /// the test method as a Flask PATCH route handler — flooding the
    /// auth-analysis with FPs.
    #[test]
    fn callee_is_test_decorator_recognises_canonical_forms() {
        // unittest.mock variants.
        assert!(callee_is_test_decorator("mock.patch"));
        assert!(callee_is_test_decorator("mock.patch.object"));
        assert!(callee_is_test_decorator("mock.patch.dict"));
        assert!(callee_is_test_decorator("mock.patch.multiple"));
        assert!(callee_is_test_decorator("unittest.mock.patch"));
        assert!(callee_is_test_decorator("unittest.mock.patch.object"));
        // pytest fixtures.
        assert!(callee_is_test_decorator("monkeypatch.setattr"));
        assert!(callee_is_test_decorator("monkeypatch.setenv"));
        assert!(callee_is_test_decorator("pytest.mark.parametrize"));
        // Negatives — real Flask decorators must still match.
        assert!(!callee_is_test_decorator("app.route"));
        assert!(!callee_is_test_decorator("app.get"));
        assert!(!callee_is_test_decorator("app.post"));
        assert!(!callee_is_test_decorator("app.patch"));
        assert!(!callee_is_test_decorator("bp.delete"));
        assert!(!callee_is_test_decorator("blueprint.put"));
        assert!(!callee_is_test_decorator("router.get"));
        assert!(!callee_is_test_decorator(""));
    }
}

#[cfg(test)]
mod fastapi_dependencies_tests {
    use super::is_depends_callee;

    /// `is_depends_callee` only matches the FastAPI `Depends` marker.
    /// Any other wrapper call inside `dependencies=[...]` is ignored ,
    /// extracting an inner callee from the wrong wrapper would
    /// misclassify logging hooks or filter callables as auth checks.
    #[test]
    fn is_depends_callee_recognises_canonical_forms() {
        assert!(is_depends_callee("Depends"));
        assert!(is_depends_callee("fastapi.Depends"));
        assert!(is_depends_callee("fastapi.params.Depends"));
        // Whitespace tolerance.
        assert!(is_depends_callee(" Depends "));
        // Negatives.
        assert!(!is_depends_callee("Annotated"));
        assert!(!is_depends_callee("Body"));
        assert!(!is_depends_callee("Depends.something"));
        assert!(!is_depends_callee("RequiresAuth"));
        assert!(!is_depends_callee(""));
    }
}
