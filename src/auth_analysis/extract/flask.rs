use super::AuthExtractor;
use super::common::{
    attach_route_handler, auth_check_from_call_site, call_site_from_node, named_children,
    push_route_registration, string_literal_value, text, visit_named_nodes,
};
use crate::auth_analysis::config::{AuthAnalysisRules, matches_name};
use crate::auth_analysis::extract::common::decorated_definition_child;
use crate::auth_analysis::model::{
    AuthCheck, AuthCheckKind, AuthorizationModel, CallSite, Framework, HttpMethod,
};
use crate::labels::bare_method_name;
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct FlaskExtractor;

/// Map from a module-level router/app variable name to the
/// `dependencies=[...]` deps declared on its constructor call.  FastAPI
/// propagates these to every route attached via
/// `@<router>.<verb>(...)`, so the route extractor must merge them in
/// before running ownership / membership checks.  Each entry follows
/// the same shape as `extract_fastapi_dependencies` produces:
/// `(CallSite, is_scoped_security)`.  See `collect_router_level_dependencies`.
type RouterLevelDepMap = HashMap<String, Vec<(CallSite, bool)>>;

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
        // Pass 1: pre-walk for module-level router/app assignments
        // (`ti_id_router = VersionedAPIRouter(dependencies=[Security(...)])`).
        // FastAPI applies router-level deps to every attached route, so
        // every per-route `@<router>.<verb>(...)` decorator must merge
        // the router's deps before the ownership check fires.  Without
        // this, airflow's execution-API routes that re-use a single
        // `ti_id_router` declared once at module scope inherit no auth
        // and flag `missing_ownership_check` despite being authorized.
        let mut router_deps = collect_router_level_dependencies(root, bytes);
        // Merge in cross-file router-deps lifted via
        // `<parent>.include_router(<this_file>.<router>, ...)` calls in
        // other project files — pre-resolved by the orchestrator at
        // pass 2 entry from `GlobalSummaries.router_facts_by_module`.
        // Cross-file deps are PREPENDED to mirror FastAPI's runtime
        // ordering (parent router deps run before any in-file router
        // deps and before per-route deps).  Empty when global summaries
        // are unavailable (single-file scan / unit-test paths).
        if !model.cross_file_router_deps.is_empty() {
            for (router_var, cross_deps) in &model.cross_file_router_deps {
                if cross_deps.is_empty() {
                    continue;
                }
                let entry = router_deps.entry(router_var.clone()).or_default();
                let mut merged: Vec<(CallSite, bool)> = cross_deps.clone();
                // Dedup so an inline `dependencies=[Security(...)]` and a
                // cross-file lift of the same `Security(callee)` don't
                // double-fire downstream auth checks.
                for dep in entry.iter() {
                    let already = merged
                        .iter()
                        .any(|(call, scoped)| call.name == dep.0.name && *scoped == dep.1);
                    if !already {
                        merged.push(dep.clone());
                    }
                }
                *entry = merged;
            }
        }
        visit_named_nodes(root, &mut |node| {
            if node.kind() == "decorated_definition" {
                maybe_collect_flask_route(root, node, bytes, path, rules, model, &router_deps);
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
    router_deps: &RouterLevelDepMap,
) {
    let Some(definition) = decorated_definition_child(node) else {
        return;
    };
    if definition.kind() != "function_definition" {
        return;
    }

    let mut route_specs = Vec::new();
    let mut middleware_calls: Vec<(CallSite, bool)> = Vec::new();
    for decorator in decorator_expressions(node) {
        if let Some(mut specs) = parse_flask_route_decorator(decorator, bytes) {
            route_specs.append(&mut specs);
            // FastAPI propagates router-level `dependencies=[...]` from
            // `<router> = APIRouter(...)` to every attached
            // `@<router>.<verb>(...)` route.  Look up the decorator's
            // router prefix in the pre-built map and merge its deps
            // BEFORE the route-level deps so the ordering matches
            // FastAPI runtime semantics (router deps run before route
            // deps).  Without this, airflow execution-API routes that
            // declare auth once at the router level fire spurious
            // `missing_ownership_check` / `token_override` findings.
            if let Some(prefix) = router_prefix_from_decorator(decorator, bytes)
                && let Some(deps) = router_deps.get(&prefix)
            {
                middleware_calls.extend(deps.iter().cloned());
            }
            // FastAPI puts route-level dependencies (auth checks +
            // logging hooks) inside the route decorator's
            // `dependencies=[Depends(...)]` keyword argument, instead
            // of as separate `@decorator` lines like Flask.  Walk the
            // route decorator's keyword args for that shape and lift
            // each `Depends(call(...))` / `Security(call, scopes=[...])`
            // element into the middleware_calls list, so the same
            // `inject_middleware_auth` path that Flask uses also
            // picks up FastAPI auth deps.  The boolean tracks whether
            // the wrapper was a scoped `Security(...)` — those are
            // OAuth2-scope-checked authorization (not just login),
            // so the AuthCheckKind is promoted in
            // `inject_middleware_auth`.
            middleware_calls.extend(extract_fastapi_dependencies(decorator, bytes));
        } else {
            middleware_calls.extend(
                expand_decorator_calls(decorator, bytes)
                    .into_iter()
                    .map(|c| (c, false)),
            );
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

        let registration_calls: Vec<CallSite> = middleware_calls
            .iter()
            .map(|(call, _)| call.clone())
            .collect();
        push_route_registration(
            model,
            Framework::Flask,
            spec.method,
            spec.path,
            path,
            handler,
            registration_calls,
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
/// `dependencies=[Depends(call(...)), Security(call, scopes=[...]), ...]`
/// shape.  For each `Depends(...)` / `Security(...)` list element,
/// extract the inner callable as a `CallSite` so it can flow through
/// `inject_middleware_auth` and be matched against the per-language
/// authorization-check / login-guard name lists.  Refuses non-call
/// elements and markers without a recognised inner call shape.
///
/// Returns `(CallSite, is_scoped_security)` pairs.  The boolean is
/// `true` when the wrapper was `Security(...)` carrying a non-empty
/// `scopes=[...]` kwarg — those are OAuth2-scope-checked authorization
/// (FastAPI semantics), not bare login dependency, so
/// `inject_middleware_auth` promotes the `AuthCheckKind`.
///
/// The function is decoupled from Flask semantics (Flask routes never
/// use `dependencies=`); the lookup is purely structural and matches
/// FastAPI's documented dependency-injection convention.  Lives in the
/// flask module because Flask's route-decorator parser already targets
/// the `@<router>.<method>(<path>, ...)` shape that FastAPI shares.
fn extract_fastapi_dependencies(decorator_expr: Node<'_>, bytes: &[u8]) -> Vec<(CallSite, bool)> {
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
        if let Some(unwrapped) = unwrap_depends_call(element, bytes) {
            out.push(unwrapped);
        }
    }
    out
}

/// Walk the module root for top-level assignments of the form
/// `<router> = <RouterCtor>(..., dependencies=[Depends(...), Security(...)])`
/// and build a map from the router variable name to its router-level
/// dependency CallSites.  FastAPI applies these to every attached
/// `@<router>.<verb>(...)` route at runtime — the per-route extractor
/// merges them in before running ownership / membership checks.
///
/// Recognised router/app constructors (callee-tail-name match, so
/// `fastapi.APIRouter(...)` and `routing.APIRouter(...)` both work):
///   * `APIRouter` (FastAPI canonical)
///   * `FastAPI` (FastAPI app object — `dependencies=[...]` on the app
///     applies to every route under it)
///   * `VersionedAPIRouter` (airflow-specific subclass)
///   * Any callee whose tail name ends with `Router` — covers
///     project-specific `APIRouter` subclasses without the airflow-
///     specific allowlist needing to grow per-codebase.  Conservative:
///     the lookup only ever fires when the route decorator's prefix
///     matches a captured variable, so over-matching the constructor
///     doesn't produce false auth attribution unless the same name is
///     also used as a route decorator's receiver — extremely rare.
///
/// The walk is restricted to module-root expression statements / typed
/// assignments — nested function-local routers aren't supported (and
/// don't appear in real-world FastAPI codebases — the router pattern is
/// always module-scoped so it can be imported into the app at startup).
fn collect_router_level_dependencies(root: Node<'_>, bytes: &[u8]) -> RouterLevelDepMap {
    let mut out: RouterLevelDepMap = HashMap::new();
    for child in named_children(root) {
        // Top-level shape: `expression_statement` wrapping an
        // `assignment` (Python tree-sitter convention).  Also accept
        // bare `assignment` in case the grammar changes.
        let assign = match child.kind() {
            "expression_statement" => named_children(child).into_iter().next(),
            "assignment" => Some(child),
            _ => None,
        };
        let Some(assign) = assign else { continue };
        if assign.kind() != "assignment" {
            continue;
        }
        let Some(left) = assign.child_by_field_name("left") else {
            continue;
        };
        if left.kind() != "identifier" {
            continue;
        }
        let Some(right) = assign.child_by_field_name("right") else {
            continue;
        };
        if right.kind() != "call" {
            continue;
        }
        let Some(function) = right.child_by_field_name("function") else {
            continue;
        };
        let function_text = text(function, bytes);
        if !is_router_like_constructor(&function_text) {
            continue;
        }
        let Some(arguments) = right.child_by_field_name("arguments") else {
            continue;
        };
        let Some(deps_value) = keyword_argument_value(arguments, bytes, "dependencies") else {
            continue;
        };
        let mut deps = Vec::new();
        for element in named_children(deps_value) {
            if let Some(unwrapped) = unwrap_depends_call(element, bytes) {
                deps.push(unwrapped);
            }
        }
        if deps.is_empty() {
            continue;
        }
        let var_name = text(left, bytes).trim().to_string();
        if var_name.is_empty() {
            continue;
        }
        // First declaration wins.  A `<router> = …` re-assignment
        // would be unusual at module scope; if it happens, the first
        // dependency declaration is conservatively the one that
        // applies to most routes attached after it.
        out.entry(var_name).or_insert(deps);
    }
    out
}

/// True for callee text that looks like a FastAPI router or app
/// constructor.  Tail-name match (after the last `.`) so
/// `fastapi.APIRouter` / `routing.APIRouter` / bare `APIRouter` all
/// hit, plus airflow's `VersionedAPIRouter` subclass and any project-
/// specific `*Router` callable.  See `collect_router_level_dependencies`
/// for the wider rationale.
fn is_router_like_constructor(callee: &str) -> bool {
    let trimmed = callee.trim();
    let tail = trimmed.rsplit('.').next().unwrap_or(trimmed);
    if tail == "APIRouter" || tail == "FastAPI" || tail == "VersionedAPIRouter" {
        return true;
    }
    // `*Router` suffix — covers project-specific subclasses without an
    // exhaustive allowlist.  Reject empty / single-char / lowercase
    // tails to avoid catching arbitrary identifiers.
    if tail.len() > "Router".len()
        && tail.ends_with("Router")
        && tail.chars().next().is_some_and(|c| c.is_ascii_uppercase())
    {
        return true;
    }
    false
}

/// Extract the router-receiver identifier from a route-decorator call
/// node.  Decorator shape: `@<router>.<verb>(<path>, ...)` — the
/// callee is `<router>.<verb>`, so the prefix is everything before the
/// last `.`.  Returns `None` for decorators that don't match the
/// expected `attribute`-style shape (e.g. bare `@requires_auth` or
/// `@blueprint.route("/x")` where the attribute is the verb itself).
fn router_prefix_from_decorator(decorator_expr: Node<'_>, bytes: &[u8]) -> Option<String> {
    if decorator_expr.kind() != "call" {
        return None;
    }
    let function = decorator_expr.child_by_field_name("function")?;
    if function.kind() != "attribute" {
        return None;
    }
    let object = function.child_by_field_name("object")?;
    if !matches!(object.kind(), "identifier" | "attribute") {
        return None;
    }
    let prefix = text(object, bytes).trim().to_string();
    if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    }
}

/// Unwrap one `Depends(...)` / `Security(...)` list element from a
/// FastAPI `dependencies` list and return the inner callable as a
/// `CallSite`.  Four shapes are accepted:
///   * `Depends(callee(arg1, arg2))`, most common, the inner call is
///     the callable factory invocation; record `callee` as the auth
///     check.
///   * `Depends(callee)`, bare reference; record `callee` itself.
///   * `Security(callee, scopes=[...])`, FastAPI's OAuth2-scope
///     variant of `Depends`; the first positional arg is the auth
///     callable, the `scopes=` kwarg is ignored.  Real-world airflow
///     execution-API routes use this form
///     (`task_instances.py:104`).
///   * `Depends()` / non-marker items, skipped.
///
/// Skips `keyword_argument` children when locating the first
/// positional, so kwargs ordering (`Security(scopes=..., callee)`)
/// does not hide the dependency.
fn unwrap_depends_call(node: Node<'_>, bytes: &[u8]) -> Option<(CallSite, bool)> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let function_text = text(function, bytes);
    if !is_dep_marker_callee(&function_text) {
        return None;
    }
    let is_security = is_security_marker(&function_text);
    let arguments = node.child_by_field_name("arguments")?;
    let children = named_children(arguments);
    let first = children
        .iter()
        .copied()
        .find(|child| child.kind() != "keyword_argument")?;
    let scoped_security = is_security
        && keyword_argument_value(arguments, bytes, "scopes")
            .map(|value| {
                named_children(value)
                    .iter()
                    .any(|item| item.kind() != "comment")
            })
            .unwrap_or(false);
    match first.kind() {
        "call" => Some((call_site_from_node(first, bytes), scoped_security)),
        "identifier" | "attribute" | "scoped_identifier" => {
            Some((call_site_from_node(first, bytes), scoped_security))
        }
        _ => None,
    }
}

/// Subset of `is_dep_marker_callee` that matches only the `Security`
/// variant (and its fully-qualified forms).  `Security(callable,
/// scopes=[...])` is FastAPI's OAuth2-scope-checked dependency: the
/// inner callable is invoked with the merged `SecurityScopes` from
/// every parent `Security(...)` declaration, and the route is
/// rejected unless the bearer token carries one of the requested
/// scopes.  Treating a scoped Security wrapper as authorization
/// (not just login) is the deeper semantic encoded by
/// `inject_middleware_auth`.
fn is_security_marker(callee: &str) -> bool {
    let trimmed = callee.trim();
    matches!(
        trimmed,
        "Security" | "fastapi.Security" | "fastapi.params.Security"
    )
}

/// True for the FastAPI dependency markers `Depends` and `Security`,
/// including their fully-qualified forms.  `Security(callable,
/// scopes=[...])` is the OAuth2-scope variant of `Depends(callable)`;
/// FastAPI treats the inner callable identically for dep-injection
/// purposes.  Conservative: only literal matches, no canonicalisation.
fn is_dep_marker_callee(callee: &str) -> bool {
    let trimmed = callee.trim();
    matches!(
        trimmed,
        "Depends"
            | "fastapi.Depends"
            | "fastapi.params.Depends"
            | "Security"
            | "fastapi.Security"
            | "fastapi.params.Security"
    )
}

fn inject_middleware_auth(
    model: &mut AuthorizationModel,
    unit_idx: usize,
    line: usize,
    middleware_calls: &[(CallSite, bool)],
    rules: &AuthAnalysisRules,
) {
    let Some(unit) = model.units.get_mut(unit_idx) else {
        return;
    };
    for (call, scoped_security) in middleware_calls {
        let mut check = match auth_check_from_call_site(call, line, rules) {
            Some(check) => check,
            None if *scoped_security => {
                // FastAPI `Security(callable, scopes=[...])` always
                // enforces authorization at the route boundary even
                // when `callable` doesn't appear in any per-language
                // login-guard / authorization-check name list.  Synthesise
                // an `Other`-kind check so the route is recognised as
                // guarded; without this, every `Security(custom_dep,
                // scopes=[...])` route fires `missing_ownership_check`
                // FPs.
                AuthCheck {
                    kind: AuthCheckKind::Other,
                    callee: call.name.clone(),
                    subjects: Vec::new(),
                    span: call.span,
                    line,
                    args: call.args.clone(),
                    condition_text: None,
                    is_route_level: false,
                }
            }
            None => continue,
        };
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
        // FastAPI `Security(callable, scopes=[...])` is OAuth2-scope-
        // checked authorization (the JWT must carry one of the listed
        // scopes); a `LoginGuard` classification would be wrong because
        // `has_prior_subject_auth` filters LoginGuard out.  Promote to
        // `Other` so the route counts as authorized for ownership /
        // membership / token-override checks.
        if *scoped_security
            && matches!(
                check.kind,
                AuthCheckKind::LoginGuard
                    | AuthCheckKind::TokenExpiry
                    | AuthCheckKind::TokenRecipient
            )
        {
            check.kind = AuthCheckKind::Other;
        }
        let push_token_synth = *scoped_security;
        unit.auth_checks.push(check);
        if push_token_synth {
            // FastAPI `Security(callable, scopes=[...])` validates the
            // bearer JWT in two ways: signature verification (which
            // includes expiry — a JWT past its `exp` claim fails the
            // signature path) and scope checking (the requested scopes
            // identify what the bearer is authorized to act on, which
            // semantically encodes recipient binding for the route).
            // Synthesise the matching `TokenExpiry` + `TokenRecipient`
            // checks so the `token_override_without_validation` rule
            // recognises the JWT-validated route.  Without this,
            // every FastAPI route declaring scoped Security at the
            // route or router boundary fires token-override FPs on
            // its `session.add` / `Model.save()` calls — the
            // missing_ownership_check sibling of the same finding is
            // already cleared by the kind-promotion above.  Empty- or
            // missing-scopes Security wrappers fall through this gate
            // (scoped_security is false) and remain bare login deps.
            unit.auth_checks.push(AuthCheck {
                kind: AuthCheckKind::TokenExpiry,
                callee: call.name.clone(),
                subjects: Vec::new(),
                span: call.span,
                line,
                args: call.args.clone(),
                condition_text: None,
                is_route_level: true,
            });
            unit.auth_checks.push(AuthCheck {
                kind: AuthCheckKind::TokenRecipient,
                callee: call.name.clone(),
                subjects: Vec::new(),
                span: call.span,
                line,
                args: call.args.clone(),
                condition_text: None,
                is_route_level: true,
            });
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
    use super::{is_dep_marker_callee, is_security_marker, unwrap_depends_call};
    use tree_sitter::Parser;

    fn parse_python(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .expect("python language");
        parser.parse(source, None).expect("parse")
    }

    /// Walk the parsed tree to find the first `call` node whose
    /// callee name matches `marker`.  Helper for the `unwrap_depends_call`
    /// regression tests below — the production extractor traverses the
    /// route-decorator's `dependencies=[...]` list and feeds each
    /// element into `unwrap_depends_call`, so the test mirrors that
    /// element shape directly without the surrounding boilerplate.
    fn find_first_marker_call<'a>(
        node: tree_sitter::Node<'a>,
        bytes: &[u8],
        marker: &str,
    ) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == "call"
            && let Some(function) = node.child_by_field_name("function")
            && function.utf8_text(bytes).unwrap_or("") == marker
        {
            return Some(node);
        }
        for idx in 0..node.named_child_count() {
            if let Some(child) = node.named_child(idx as u32)
                && let Some(found) = find_first_marker_call(child, bytes, marker)
            {
                return Some(found);
            }
        }
        None
    }

    /// `is_dep_marker_callee` matches only FastAPI's `Depends` /
    /// `Security` markers.  Any other wrapper call inside
    /// `dependencies=[...]` is ignored, extracting an inner callee
    /// from the wrong wrapper would misclassify logging hooks or
    /// filter callables as auth checks.
    #[test]
    fn is_dep_marker_callee_recognises_canonical_forms() {
        assert!(is_dep_marker_callee("Depends"));
        assert!(is_dep_marker_callee("fastapi.Depends"));
        assert!(is_dep_marker_callee("fastapi.params.Depends"));
        // Security variant — OAuth2-scope-bearing equivalent.
        assert!(is_dep_marker_callee("Security"));
        assert!(is_dep_marker_callee("fastapi.Security"));
        assert!(is_dep_marker_callee("fastapi.params.Security"));
        // Whitespace tolerance.
        assert!(is_dep_marker_callee(" Depends "));
        assert!(is_dep_marker_callee(" Security "));
        // Negatives.
        assert!(!is_dep_marker_callee("Annotated"));
        assert!(!is_dep_marker_callee("Body"));
        assert!(!is_dep_marker_callee("Depends.something"));
        assert!(!is_dep_marker_callee("Security.something"));
        assert!(!is_dep_marker_callee("RequiresAuth"));
        assert!(!is_dep_marker_callee(""));
    }

    /// `is_security_marker` is the strictly-Security subset.  Used to
    /// promote the wrapper's `is_scoped_security` flag without a
    /// second string-match pass.
    #[test]
    fn is_security_marker_recognises_security_only() {
        assert!(is_security_marker("Security"));
        assert!(is_security_marker("fastapi.Security"));
        assert!(is_security_marker("fastapi.params.Security"));
        assert!(is_security_marker(" Security "));
        // Depends is NOT a Security marker.
        assert!(!is_security_marker("Depends"));
        assert!(!is_security_marker("fastapi.Depends"));
        assert!(!is_security_marker("Annotated"));
        assert!(!is_security_marker(""));
    }

    /// `Security(callable, scopes=[...])` — the canonical airflow
    /// execution-API auth-dep shape (`task_instances.py:104`).  Must
    /// extract `callable` as the inner CallSite AND flag the wrapper as
    /// scoped-security so `inject_middleware_auth` promotes the
    /// AuthCheckKind from LoginGuard to Other (OAuth2 scopes are
    /// authorization, not just login).  Without the promotion, the
    /// route still fires `missing_ownership_check` despite carrying a
    /// declared route-level dependency.
    #[test]
    fn unwrap_depends_call_security_with_scopes_flags_scoped() {
        let src = "x = Security(require_auth, scopes=[\"token:execution\"])\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let call = find_first_marker_call(tree.root_node(), bytes, "Security")
            .expect("Security call node");
        let (site, scoped) = unwrap_depends_call(call, bytes).expect("Security recognised");
        assert_eq!(site.name, "require_auth");
        assert!(
            scoped,
            "non-empty scopes=[...] must mark the wrapper scoped"
        );
    }

    /// `Depends(callable())` — pre-existing FastAPI shape.  Inner call
    /// extracts to the factory's outer name; wrapper is NOT
    /// scoped-security.  Regression guard: the Security extension must
    /// not flip Depends's scoped flag on.
    #[test]
    fn unwrap_depends_call_depends_factory_not_scoped() {
        let src = "x = Depends(requires_access_dag(method=\"GET\"))\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let call =
            find_first_marker_call(tree.root_node(), bytes, "Depends").expect("Depends call node");
        let (site, scoped) = unwrap_depends_call(call, bytes).expect("Depends recognised");
        assert_eq!(site.name, "requires_access_dag");
        assert!(!scoped, "Depends wrapper never scoped-security");
    }

    /// `Security(callable)` without scopes (rare but legal) is NOT
    /// scoped — the OAuth2-scope semantic only fires when scopes is
    /// non-empty, so the wrapper falls back to the regular login-guard
    /// classification.  Conservative: don't over-promote.
    #[test]
    fn unwrap_depends_call_security_without_scopes_not_scoped() {
        let src = "x = Security(require_auth)\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let call = find_first_marker_call(tree.root_node(), bytes, "Security")
            .expect("Security call node");
        let (site, scoped) = unwrap_depends_call(call, bytes).expect("Security recognised");
        assert_eq!(site.name, "require_auth");
        assert!(
            !scoped,
            "missing scopes=[...] kwarg means not scoped-security"
        );
    }

    /// `Security(callable, scopes=[])` with an empty scope list is NOT
    /// scoped-security: an empty `scopes=[]` declaration accumulates
    /// no required scopes onto the JWT check, so the route is
    /// effectively a bare login dependency.  Conservative — keeps the
    /// promotion gate tight.
    #[test]
    fn unwrap_depends_call_security_empty_scopes_not_scoped() {
        let src = "x = Security(require_auth, scopes=[])\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let call = find_first_marker_call(tree.root_node(), bytes, "Security")
            .expect("Security call node");
        let (site, scoped) = unwrap_depends_call(call, bytes).expect("Security recognised");
        assert_eq!(site.name, "require_auth");
        assert!(!scoped, "scopes=[] is not scoped-security");
    }
}

#[cfg(test)]
mod router_level_dependencies_tests {
    use super::{
        collect_router_level_dependencies, is_router_like_constructor, router_prefix_from_decorator,
    };
    use tree_sitter::Parser;

    fn parse_python(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .expect("python language");
        parser.parse(source, None).expect("parse")
    }

    /// Tail-name match: `fastapi.APIRouter`, `routing.APIRouter`, bare
    /// `APIRouter`, plus airflow's `VersionedAPIRouter` subclass.  Suffix
    /// rule covers project-specific `*Router` subclasses without an
    /// exhaustive allowlist.  Negatives must reject arbitrary lowercase
    /// or non-router identifiers.
    #[test]
    fn is_router_like_constructor_matches_canonical_names() {
        // Canonical FastAPI.
        assert!(is_router_like_constructor("APIRouter"));
        assert!(is_router_like_constructor("FastAPI"));
        assert!(is_router_like_constructor("fastapi.APIRouter"));
        assert!(is_router_like_constructor("fastapi.routing.APIRouter"));
        assert!(is_router_like_constructor("fastapi.FastAPI"));
        // Airflow.
        assert!(is_router_like_constructor("VersionedAPIRouter"));
        // Project-specific *Router subclasses.
        assert!(is_router_like_constructor("CustomRouter"));
        assert!(is_router_like_constructor("api.v1.MyRouter"));
        // Negatives.
        assert!(!is_router_like_constructor("router"));
        assert!(!is_router_like_constructor("Annotated"));
        assert!(!is_router_like_constructor("Depends"));
        assert!(!is_router_like_constructor("Security"));
        assert!(!is_router_like_constructor(""));
        // `Router` alone is too short / generic to match the suffix
        // rule (would over-fire on any callable named exactly
        // `Router`); we accept it explicitly nowhere.
        assert!(!is_router_like_constructor("Router"));
        // `flat_router` ends with `Router` but starts lowercase —
        // suffix rule requires uppercase first char to avoid catching
        // generic verbs.
        assert!(!is_router_like_constructor("flat_router"));
    }

    /// Airflow's `ti_id_router = VersionedAPIRouter(route_class=...,
    /// dependencies=[Security(require_auth, scopes=["ti:self"])])` is
    /// the canonical real-repo shape.  The collector must capture the
    /// `Security(require_auth, scopes=...)` dep keyed by
    /// `ti_id_router`, and the wrapper must be flagged scoped-security
    /// so `inject_middleware_auth` promotes the AuthCheckKind to Other.
    #[test]
    fn collect_router_level_dependencies_picks_up_versioned_apirouter_security() {
        let src = "ti_id_router = VersionedAPIRouter(\n    route_class=ExecutionAPIRoute,\n    dependencies=[\n        Security(require_auth, scopes=[\"ti:self\"]),\n    ],\n)\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let map = collect_router_level_dependencies(tree.root_node(), bytes);
        let deps = map
            .get("ti_id_router")
            .expect("ti_id_router router-level deps captured");
        assert_eq!(deps.len(), 1);
        let (site, scoped) = &deps[0];
        assert_eq!(site.name, "require_auth");
        assert!(*scoped, "scopes=[\"ti:self\"] must mark scoped-security");
    }

    /// Bare `Depends(...)` router-level dep (no scopes) — captured but
    /// NOT scoped-security.  Mirrors the per-route Depends test in the
    /// sibling fastapi_dependencies_tests module.
    #[test]
    fn collect_router_level_dependencies_picks_up_apirouter_depends_not_scoped() {
        let src = "v1 = APIRouter(\n    prefix=\"/v1\",\n    dependencies=[Depends(get_current_user)],\n)\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let map = collect_router_level_dependencies(tree.root_node(), bytes);
        let deps = map.get("v1").expect("v1 router-level deps captured");
        assert_eq!(deps.len(), 1);
        let (site, scoped) = &deps[0];
        assert_eq!(site.name, "get_current_user");
        assert!(!*scoped, "Depends never scoped-security");
    }

    /// Constructor without `dependencies=` kwarg → no entry in the
    /// map.  Routers without router-level deps must not produce a
    /// fake key — the per-route extractor would then merge an empty
    /// list and silently no-op, but absence is the cleaner signal.
    #[test]
    fn collect_router_level_dependencies_skips_routers_without_deps() {
        let src = "router = APIRouter(prefix=\"/x\")\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let map = collect_router_level_dependencies(tree.root_node(), bytes);
        assert!(map.get("router").is_none());
    }

    /// Non-router constructor (`MyService(...)`) with a coincidental
    /// `dependencies=` kwarg must NOT enter the router-dep map.
    /// `MyService` doesn't end with `Router` and isn't on the explicit
    /// allowlist, so the gate rejects it.
    #[test]
    fn collect_router_level_dependencies_skips_non_router_constructors() {
        let src = "svc = MyService(dependencies=[Depends(get_db)])\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let map = collect_router_level_dependencies(tree.root_node(), bytes);
        assert!(map.get("svc").is_none());
    }

    /// Helper: parse a single decorated function and pull out the
    /// decorator call so `router_prefix_from_decorator` can be tested
    /// in isolation.  Mirrors the `find_first_marker_call` helper in
    /// the sibling test module.
    fn find_first_decorator<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == "decorator"
            && let Some(child) = node.named_child(0)
        {
            return Some(child);
        }
        for idx in 0..node.named_child_count() {
            if let Some(child) = node.named_child(idx as u32)
                && let Some(found) = find_first_decorator(child)
            {
                return Some(found);
            }
        }
        None
    }

    /// `@ti_id_router.patch("/x")` → prefix `"ti_id_router"`.  This is
    /// the lookup key the per-route extractor uses to pull
    /// router-level deps out of the map.
    #[test]
    fn router_prefix_from_decorator_extracts_simple_identifier() {
        let src = "@ti_id_router.patch(\"/x\")\ndef f():\n    pass\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let decorator = find_first_decorator(tree.root_node()).expect("decorator call node");
        let prefix = router_prefix_from_decorator(decorator, bytes).expect("prefix extracted");
        assert_eq!(prefix, "ti_id_router");
    }

    /// Bare-identifier decorators (`@requires_auth\ndef f(): ...`) and
    /// non-attribute callees return None — there's no router prefix
    /// to look up.
    #[test]
    fn router_prefix_from_decorator_returns_none_for_bare_decorator() {
        let src = "@requires_auth\ndef f():\n    pass\n";
        let tree = parse_python(src);
        let bytes = src.as_bytes();
        let decorator = find_first_decorator(tree.root_node()).expect("decorator node");
        // `@requires_auth` produces an `identifier` child, not a
        // `call`, so router_prefix should None out at the call gate.
        assert!(router_prefix_from_decorator(decorator, bytes).is_none());
    }
}
