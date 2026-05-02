use super::AuthExtractor;
use super::common::{
    attach_route_handler, call_name, call_site_from_node, call_sites_from_value,
    collect_top_level_units, function_definition_node, named_children, resolve_handler_node,
    string_literal_value, text,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{
    AuthCheck, AuthCheckKind, AuthorizationModel, CallSite, Framework, HttpMethod,
    RouteRegistration, ValueRef, ValueSourceKind,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct AxumExtractor;

impl AuthExtractor for AxumExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "rust"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Axum))
    }

    fn extract(
        &self,
        tree: &Tree,
        bytes: &[u8],
        path: &Path,
        rules: &AuthAnalysisRules,
    ) -> AuthorizationModel {
        let root = tree.root_node();
        let mut model = AuthorizationModel::default();

        collect_top_level_units(root, bytes, rules, &mut model);
        collect_routes(root, root, bytes, path, rules, &mut model);
        apply_typed_extractor_guards_to_units(root, bytes, rules, &mut model, GuardFramework::Axum);

        model
    }
}

fn collect_routes(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    if node.kind() == "call_expression" {
        maybe_collect_route(root, node, bytes, path, rules, model);
    }

    for child in named_children(node) {
        collect_routes(root, child, bytes, path, rules, model);
    }
}

fn maybe_collect_route(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    if call_name(node, bytes).rsplit('.').next() != Some("route") {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = named_children(arguments);
    let Some(path_node) = args.first().copied() else {
        return;
    };
    let Some(route_path) = string_literal_value(path_node, bytes) else {
        return;
    };
    let Some(route_spec) = args.get(1).copied() else {
        return;
    };
    let Some(spec) = parse_method_router(route_spec, bytes) else {
        return;
    };
    let Some(handler_node) = resolve_handler_node(root, spec.handler_expr, bytes) else {
        return;
    };
    let Some(handler) = attach_route_handler(
        root,
        spec.handler_expr,
        format!("{:?} {}", spec.method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let mut middleware_calls = inherited_layer_calls(node, bytes);
    middleware_calls.extend(spec.middleware_calls.clone());
    let guard_calls =
        guard_calls_for_handler(handler_node, &route_path, bytes, GuardFramework::Axum);
    middleware_calls.extend(guard_calls.clone());
    dedup_call_sites(&mut middleware_calls);

    if let Some(unit) = model.units.get_mut(handler.unit_idx) {
        let aliases = rust_param_aliases(handler_node, &route_path, bytes, GuardFramework::Axum);
        apply_aliases(unit, &aliases);
        inject_guard_checks(unit, &guard_calls, rules);
    }

    model.routes.push(RouteRegistration {
        framework: Framework::Axum,
        method: spec.method,
        path: route_path,
        middleware: middleware_calls
            .iter()
            .map(|call| call.name.clone())
            .collect(),
        handler_span: handler.span,
        handler_params: handler.params,
        file: path.to_path_buf(),
        line: handler.line,
        unit_idx: handler.unit_idx,
        middleware_calls,
    });
}

struct MethodRouterSpec<'tree> {
    method: HttpMethod,
    handler_expr: Node<'tree>,
    middleware_calls: Vec<CallSite>,
}

fn parse_method_router<'tree>(node: Node<'tree>, bytes: &[u8]) -> Option<MethodRouterSpec<'tree>> {
    let last = call_name(node, bytes).rsplit('.').next()?.to_string();
    if let Some(method) = axum_http_method(&last) {
        let args = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
        let handler_expr = *args.last()?;
        return Some(MethodRouterSpec {
            method,
            handler_expr,
            middleware_calls: Vec::new(),
        });
    }

    if node.kind() != "call_expression" {
        return None;
    }

    let function = node.child_by_field_name("function")?;
    let receiver = function
        .child_by_field_name("object")
        .or_else(|| function.child_by_field_name("argument"))?;
    let mut spec = parse_method_router(receiver, bytes)?;
    match last.as_str() {
        "layer" | "route_layer" => {
            if let Some(arguments) = node.child_by_field_name("arguments") {
                for arg in named_children(arguments) {
                    spec.middleware_calls
                        .extend(expanded_guard_call_sites(arg, bytes));
                }
            }
            Some(spec)
        }
        _ => None,
    }
}

fn axum_http_method(name: &str) -> Option<HttpMethod> {
    match name {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        "any" => Some(HttpMethod::All),
        _ => None,
    }
}

fn inherited_layer_calls(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let Some(function) = node.child_by_field_name("function") else {
        return Vec::new();
    };
    let Some(receiver) = function
        .child_by_field_name("object")
        .or_else(|| function.child_by_field_name("argument"))
    else {
        return Vec::new();
    };
    collect_layer_calls(receiver, bytes)
}

fn collect_layer_calls(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    if node.kind() != "call_expression" {
        return Vec::new();
    }

    let mut calls = Vec::new();
    let name = call_name(node, bytes);
    if matches!(name.rsplit('.').next(), Some("layer" | "route_layer"))
        && let Some(arguments) = node.child_by_field_name("arguments")
    {
        for arg in named_children(arguments) {
            calls.extend(expanded_guard_call_sites(arg, bytes));
        }
    }

    if let Some(function) = node.child_by_field_name("function")
        && let Some(receiver) = function
            .child_by_field_name("object")
            .or_else(|| function.child_by_field_name("argument"))
    {
        calls.extend(collect_layer_calls(receiver, bytes));
    }

    calls
}

#[derive(Clone, Copy)]
pub(crate) enum GuardFramework {
    Axum,
    ActixWeb,
    Rocket,
}

pub(crate) fn rust_param_aliases(
    handler_node: Node<'_>,
    route_path: &str,
    bytes: &[u8],
    framework: GuardFramework,
) -> HashMap<String, ValueSourceKind> {
    let mut aliases = HashMap::new();
    let Some(parameters) = function_definition_node(handler_node).child_by_field_name("parameters")
    else {
        return aliases;
    };

    let path_names = route_placeholder_names(route_path);
    let query_names = route_query_placeholder_names(route_path);

    for param in named_children(parameters) {
        let param_text = text(param, bytes);
        if param.kind() == "self_parameter" || param_text.trim().is_empty() {
            continue;
        }
        let binding = rust_binding_name(&param_text);
        let type_text = rust_param_type_text(param, bytes, &param_text);
        if binding.is_empty() || type_text.is_empty() {
            continue;
        }

        let kind = match framework {
            GuardFramework::Axum => classify_axum_param(&binding, &type_text),
            GuardFramework::ActixWeb => classify_actix_param(&binding, &type_text),
            GuardFramework::Rocket => {
                classify_rocket_param(&binding, &type_text, &path_names, &query_names)
            }
        };
        if let Some(kind) = kind {
            aliases.insert(binding, kind);
        }
    }

    aliases
}

pub(crate) fn guard_calls_for_handler(
    handler_node: Node<'_>,
    route_path: &str,
    bytes: &[u8],
    framework: GuardFramework,
) -> Vec<CallSite> {
    let mut calls = Vec::new();
    let Some(parameters) = function_definition_node(handler_node).child_by_field_name("parameters")
    else {
        return calls;
    };
    let span = (handler_node.start_byte(), handler_node.end_byte());
    let path_names = route_placeholder_names(route_path);
    let query_names = route_query_placeholder_names(route_path);

    for param in named_children(parameters) {
        let param_text = text(param, bytes);
        if param.kind() == "self_parameter" || param_text.trim().is_empty() {
            continue;
        }
        let type_text = rust_param_type_text(param, bytes, &param_text);
        let Some(kind) = (match framework {
            GuardFramework::Axum => classify_guard_type(&type_text),
            GuardFramework::ActixWeb => classify_guard_type(&type_text),
            GuardFramework::Rocket => classify_rocket_guard_type(
                &type_text,
                &rust_binding_name(&param_text),
                &path_names,
                &query_names,
            ),
        }) else {
            continue;
        };

        let name = type_last_segment(&type_text);
        if !name.is_empty() {
            calls.push(CallSite {
                name,
                args: Vec::new(),
                span,
                args_value_refs: Vec::new(),
            });
            if matches!(kind, AuthCheckKind::AdminGuard) {
                calls.push(CallSite {
                    name: "require_admin".to_string(),
                    args: Vec::new(),
                    span,
                    args_value_refs: Vec::new(),
                });
            }
        }
    }

    dedup_call_sites(&mut calls);
    calls
}

fn classify_axum_param(binding: &str, type_text: &str) -> Option<ValueSourceKind> {
    if wrapper_type_matches(type_text, &["Path"]) {
        Some(ValueSourceKind::RequestParam)
    } else if wrapper_type_matches(type_text, &["Query"]) {
        Some(ValueSourceKind::RequestQuery)
    } else if wrapper_type_matches(type_text, &["Json", "Form"]) {
        Some(ValueSourceKind::RequestBody)
    } else if wrapper_type_matches(type_text, &["State", "Extension"]) || binding == "session" {
        Some(ValueSourceKind::Session)
    } else {
        None
    }
}

fn classify_actix_param(binding: &str, type_text: &str) -> Option<ValueSourceKind> {
    if wrapper_type_matches(type_text, &["Path"]) {
        Some(ValueSourceKind::RequestParam)
    } else if wrapper_type_matches(type_text, &["Query"]) {
        Some(ValueSourceKind::RequestQuery)
    } else if wrapper_type_matches(type_text, &["Json", "Form"]) {
        Some(ValueSourceKind::RequestBody)
    } else if wrapper_type_matches(type_text, &["Session", "Identity", "ReqData"])
        || binding == "session"
    {
        Some(ValueSourceKind::Session)
    } else {
        None
    }
}

fn classify_rocket_param(
    binding: &str,
    type_text: &str,
    path_names: &[String],
    query_names: &[String],
) -> Option<ValueSourceKind> {
    if wrapper_type_matches(type_text, &["Json", "Form"]) {
        Some(ValueSourceKind::RequestBody)
    } else if wrapper_type_matches(type_text, &["State", "Session"]) || binding == "session" {
        Some(ValueSourceKind::Session)
    } else if query_names.iter().any(|name| name == binding) {
        Some(ValueSourceKind::RequestQuery)
    } else if path_names.iter().any(|name| name == binding) {
        Some(ValueSourceKind::RequestParam)
    } else {
        None
    }
}

/// Classify a route-handler parameter type as a route-level auth
/// guard.  Used to tag the route as gated by a login or admin check
/// when one of its parameters is a typed auth extractor.
///
/// **Looser than [`super::common::is_self_actor_type_text`] by
/// design.**  This recogniser runs only on the type of a route-bound
/// parameter, appearing in a route handler signature is itself a
/// strong signal, and a false positive here just over-credits the
/// route with a login guard, which is conservative w.r.t. flagging.
/// `is_self_actor_type_text` runs on every parameter, including in
/// non-route functions, and a false positive there suppresses
/// downstream `V.id` flagging entirely; that path uses a structural
/// recogniser keyed on the `<PREFIX>User<SUFFIX>?` shape.
///
/// Recognition is **outer-wrapper based**: classify by the outermost
/// type name only, not by substring-anywhere on the whole text.  This
/// avoids both directions of leakage:
/// * A bare data-only extractor like `web::Path<u64>` early-returns
///   `None` regardless of inner type tokens (preserves existing
///   behaviour).
/// * A policy-bearing wrapper like
///   `GuardedData<ActionPolicy<X>, Data<AuthController>>` is
///   classified by the outer `GuardedData`, not by whether the inner
///   `Data<AuthController>` happens to lowercase-contain "auth".  The
///   wrapper proves capability enforcement → `AuthCheckKind::Other`
///   (the route-level short-circuit in `auth_check_covers_subject`
///   suppresses missing-ownership-check for non-LoginGuard kinds).
fn classify_guard_type(type_text: &str) -> Option<AuthCheckKind> {
    let outer = outermost_type_name(type_text);
    let outer_lower = outer.to_ascii_lowercase();

    // Bare data-only extractors are *not* auth-bearing regardless of
    // their inner generic args.  Outer-name match (case-insensitive
    // exact) — `Path<u64>` / `web::Path<...>` / `Query<X>` /
    // `Json<X>` / `Form<X>` / `State<X>` / `Extension<X>` /
    // `Data<X>`.
    if is_data_only_extractor_outer(&outer_lower) {
        return None;
    }

    // Policy/guard-bearing outer wrapper.  Names containing
    // `guarded` (e.g. `GuardedData`, `GuardedRoute`) signal the
    // wrapper enforced a capability/permission check at request
    // construction.  Distinct from `LoginGuard` because Policy
    // enforcement is more than authentication, it's authorization.
    if outer_lower.contains("guarded") || outer_lower.contains("guard") {
        if outer_lower.contains("admin") {
            return Some(AuthCheckKind::AdminGuard);
        }
        return Some(AuthCheckKind::Other);
    }

    if outer_lower.contains("admin") {
        return Some(AuthCheckKind::AdminGuard);
    }
    if outer_lower.contains("user")
        || outer_lower.contains("auth")
        || outer_lower.contains("session")
        || outer_lower.contains("identity")
        || outer_lower.contains("principal")
    {
        return Some(AuthCheckKind::LoginGuard);
    }

    // Backwards-compat fallback: legacy whole-text substring check
    // for unusual shapes whose outer wrapper is generic but whose
    // qualified path still mentions an auth token.  Preserves
    // pre-2026-05-02 behaviour for non-Guarded wrappers.
    let lower = type_text.to_ascii_lowercase();
    if is_extractor_wrapper(&lower) {
        return None;
    }
    if lower.contains("admin") {
        Some(AuthCheckKind::AdminGuard)
    } else if lower.contains("user")
        || lower.contains("auth")
        || lower.contains("session")
        || lower.contains("identity")
    {
        Some(AuthCheckKind::LoginGuard)
    } else {
        None
    }
}

/// Outermost type name: text before the first `<`, with reference
/// markers (`&`, `&mut`, `&'a`, etc.) and module-path prefix
/// (`std::collections::`) stripped.  Returns the empty string for
/// inputs that don't parse as a type.
fn outermost_type_name(type_text: &str) -> &str {
    let trimmed = type_text.trim();
    let mut after_refs = trimmed;
    loop {
        let next = after_refs
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .trim_start();
        // Strip any single lifetime token like `'a ` after the `&`.
        let next = if let Some(rest) = next.strip_prefix('\'') {
            rest.split_once(' ')
                .map(|(_, after)| after.trim_start())
                .unwrap_or(rest)
        } else {
            next
        };
        if next == after_refs {
            break;
        }
        after_refs = next;
    }
    let prefix = after_refs.split('<').next().unwrap_or(after_refs).trim();
    prefix.rsplit("::").next().unwrap_or(prefix).trim()
}

/// Outer wrapper name (lowercase, exact-match) that the engine treats
/// as a bare data-only extractor: yielding the inner type to the
/// handler without any auth side-effect.  Matched on the outer name
/// only so policy-bearing wrappers carrying a data extractor as one
/// of their generic args (e.g.
/// `GuardedData<Policy, web::Path<u64>>`) are not mis-suppressed by
/// the inner `Path<...>`.
fn is_data_only_extractor_outer(outer_lower: &str) -> bool {
    matches!(
        outer_lower,
        "path" | "query" | "json" | "form" | "extension" | "state" | "data" | "reqdata"
    )
}

fn classify_rocket_guard_type(
    type_text: &str,
    binding: &str,
    path_names: &[String],
    query_names: &[String],
) -> Option<AuthCheckKind> {
    if path_names.iter().any(|name| name == binding)
        || query_names.iter().any(|name| name == binding)
    {
        return None;
    }
    classify_guard_type(type_text)
}

fn is_extractor_wrapper(lower: &str) -> bool {
    lower.contains("path<")
        || lower.contains("query<")
        || lower.contains("json<")
        || lower.contains("form<")
        || lower.contains("state<")
        || lower.contains("extension<")
        || lower.contains("web::")
}

fn wrapper_type_matches(type_text: &str, wrappers: &[&str]) -> bool {
    let normalized = type_text.replace(' ', "");
    wrappers.iter().any(|wrapper| {
        normalized.contains(&format!("{wrapper}<")) || normalized.contains(&format!("::{wrapper}<"))
    })
}

fn rust_binding_name(param_text: &str) -> String {
    let before_colon = param_text.split(':').next().unwrap_or(param_text).trim();
    let tokens: Vec<&str> = before_colon
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty() && *token != "mut")
        .collect();
    tokens.last().copied().unwrap_or_default().to_string()
}

fn rust_param_type_text(param: Node<'_>, bytes: &[u8], param_text: &str) -> String {
    param
        .child_by_field_name("type")
        .map(|node| text(node, bytes))
        .or_else(|| {
            param_text
                .split_once(':')
                .map(|(_, ty)| ty.trim().to_string())
        })
        .unwrap_or_default()
}

fn route_placeholder_names(route_path: &str) -> Vec<String> {
    route_path
        .split(['/', '<', '>', ':', '{', '}'])
        .filter(|segment| !segment.is_empty())
        .filter(|segment| !segment.contains('?'))
        .filter(|segment| {
            route_path.contains(&format!("<{segment}>"))
                || route_path.contains(&format!(":{segment}"))
                || route_path.contains(&format!("{{{segment}}}"))
        })
        .map(|segment| segment.to_string())
        .collect()
}

fn route_query_placeholder_names(route_path: &str) -> Vec<String> {
    let Some((_, query)) = route_path.split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|segment| {
            if let Some(name) = segment.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
                Some(name.to_string())
            } else {
                segment
                    .split('=')
                    .next()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(|name| name.to_string())
            }
        })
        .collect()
}

fn type_last_segment(type_text: &str) -> String {
    type_text
        .trim_start_matches('&')
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'))
        .find(|segment| !segment.is_empty())
        .and_then(|segment| segment.rsplit("::").next())
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn expanded_guard_call_sites(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let mut calls = call_sites_from_value(node, bytes);
    if node.kind() == "call_expression" {
        let name = call_name(node, bytes);
        if matches!(
            name.rsplit('.').next(),
            Some("from_fn" | "from_fn_with_state" | "wrap_fn" | "fn_guard")
        ) && let Some(arguments) = node.child_by_field_name("arguments")
        {
            for arg in named_children(arguments) {
                let inner = call_site_from_node(arg, bytes);
                if !inner.name.is_empty() {
                    calls.push(inner);
                }
            }
        }
    }
    dedup_call_sites(&mut calls);
    calls
}

pub(crate) fn dedup_call_sites(calls: &mut Vec<CallSite>) {
    let mut deduped = Vec::new();
    for call in calls.drain(..) {
        if !deduped.iter().any(|existing: &CallSite| {
            existing.name == call.name && existing.span == call.span && existing.args == call.args
        }) {
            deduped.push(call);
        }
    }
    *calls = deduped;
}

pub(crate) fn apply_aliases(
    unit: &mut crate::auth_analysis::model::AnalysisUnit,
    aliases: &HashMap<String, ValueSourceKind>,
) {
    for value in &mut unit.value_refs {
        apply_alias_to_value(value, aliases);
    }
    for check in &mut unit.auth_checks {
        for subject in &mut check.subjects {
            apply_alias_to_value(subject, aliases);
        }
    }
    for op in &mut unit.operations {
        for subject in &mut op.subjects {
            apply_alias_to_value(subject, aliases);
        }
    }
    unit.context_inputs = unit
        .value_refs
        .iter()
        .filter(|value| {
            matches!(
                value.source_kind,
                ValueSourceKind::RequestParam
                    | ValueSourceKind::RequestBody
                    | ValueSourceKind::RequestQuery
                    | ValueSourceKind::Session
            )
        })
        .cloned()
        .collect();
}

fn apply_alias_to_value(value: &mut ValueRef, aliases: &HashMap<String, ValueSourceKind>) {
    let root = value
        .base
        .as_deref()
        .and_then(first_identifier)
        .or_else(|| first_identifier(&value.name));
    let Some(root) = root else {
        return;
    };
    let Some(kind) = aliases.get(root) else {
        return;
    };

    if value.source_kind == ValueSourceKind::ArrayIndex && *kind != ValueSourceKind::Session {
        return;
    }

    value.source_kind = *kind;
}

fn first_identifier(input: &str) -> Option<&str> {
    let mut end = input.len();
    for (idx, ch) in input.char_indices() {
        if !(ch.is_ascii_alphanumeric() || ch == '_') {
            end = idx;
            break;
        }
    }
    if end == 0 { None } else { Some(&input[..end]) }
}

pub(crate) fn inject_guard_checks(
    unit: &mut crate::auth_analysis::model::AnalysisUnit,
    guard_calls: &[CallSite],
    rules: &AuthAnalysisRules,
) {
    let line = unit.line;
    for call in guard_calls {
        let kind = if rules.is_admin_guard(&call.name, &call.args) {
            AuthCheckKind::AdminGuard
        } else if rules.is_policy_guard(&call.name) {
            // Policy/capability-bearing typed extractor (e.g.
            // meilisearch's `GuardedData<ActionPolicy<X>, _>`).
            // Recorded as `Other` so the route-level short-circuit in
            // `auth_check_covers_subject` covers any sink in the
            // handler — the wrapper proves authorization, not just
            // authentication.
            AuthCheckKind::Other
        } else if rules.is_login_guard(&call.name) {
            AuthCheckKind::LoginGuard
        } else {
            continue;
        };
        unit.auth_checks.push(AuthCheck {
            kind,
            callee: call.name.clone(),
            subjects: Vec::new(),
            span: call.span,
            line,
            args: call.args.clone(),
            condition_text: None,
            // Route-level guard injected from a tower / axum layer
            // (`RequireAuthorizationLayer`, `axum_login::login_required!`,
            // …).  Tells `auth_check_covers_subject` to short-circuit
            // for any non-login-guard match.
            is_route_level: true,
        });
    }
}

/// Walk every `Function`-kind unit in `model` and inject route-level
/// guard checks for any parameter whose type is recognised as a
/// typed auth/policy extractor (e.g. meilisearch's `GuardedData<P, D>`,
/// `axum::extract::State<AuthCtx>`).  Complements the route-walk path
/// in `collect_routes`: handlers registered by attribute macros
/// (`#[routes::path(...)]`, `#[get("/path")]`) or by external
/// service-config builders are never matched as route registrations
/// here, so their typed-extractor guards would otherwise never be
/// injected and `missing_ownership_check` would fire on every
/// id-shaped sink they contain.
///
/// `RouteHandler`-kind units already had their guards injected during
/// the route walk and are skipped to avoid duplicate `AuthCheck`
/// entries.
pub(crate) fn apply_typed_extractor_guards_to_units(
    root: Node<'_>,
    bytes: &[u8],
    rules: &AuthAnalysisRules,
    model: &mut crate::auth_analysis::model::AuthorizationModel,
    framework: GuardFramework,
) {
    use crate::auth_analysis::model::AnalysisUnitKind;
    let function_nodes = collect_function_definition_nodes(root);
    for unit_idx in 0..model.units.len() {
        let span = {
            let unit = &model.units[unit_idx];
            if unit.kind == AnalysisUnitKind::RouteHandler {
                continue;
            }
            unit.span
        };
        let Some(handler_node) = function_nodes
            .iter()
            .find(|node| node.start_byte() == span.0 && node.end_byte() == span.1)
            .copied()
        else {
            continue;
        };
        let guard_calls = guard_calls_for_handler(handler_node, "", bytes, framework);
        if guard_calls.is_empty() {
            continue;
        }
        let unit = &mut model.units[unit_idx];
        inject_guard_checks(unit, &guard_calls, rules);
    }
}

fn collect_function_definition_nodes<'tree>(root: Node<'tree>) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    walk_function_definitions(root, &mut out);
    out
}

fn walk_function_definitions<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    match node.kind() {
        // Free / impl / trait fn definitions in tree-sitter-rust.
        "function_item" => out.push(node),
        _ => {}
    }
    for child in named_children(node) {
        walk_function_definitions(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outermost_type_name_strips_refs_and_module_prefix() {
        assert_eq!(outermost_type_name("GuardedData<P, D>"), "GuardedData");
        assert_eq!(outermost_type_name("&GuardedData<P, D>"), "GuardedData");
        assert_eq!(
            outermost_type_name("&'a mut GuardedData<P, D>"),
            "GuardedData"
        );
        assert_eq!(outermost_type_name("web::Path<u64>"), "Path");
        assert_eq!(outermost_type_name("std::sync::Arc<Mutex<T>>"), "Arc");
        assert_eq!(outermost_type_name(""), "");
        assert_eq!(outermost_type_name("Bare"), "Bare");
    }

    #[test]
    fn classify_guard_type_recognises_guarded_data_outer_wrapper() {
        // Real meilisearch shape with both an admin-token-bearing inner
        // type and a Data inner extractor — must classify as `Other`
        // (route-level policy), not LoginGuard (filtered out by
        // `has_prior_subject_auth`) and not None (over-suppression
        // would happen if the inner `Data<>` early-return fired).
        let kind = classify_guard_type(
            "GuardedData<ActionPolicy<{ actions::KEYS_GET }>, Data<AuthController>>",
        );
        assert_eq!(kind, Some(AuthCheckKind::Other));
    }

    #[test]
    fn classify_guard_type_data_only_extractor_outer_returns_none() {
        // Outer `Data<>` is a bare actix data extractor — not auth.
        // Even though the inner type lower-cases to contain "auth",
        // the outer-wrapper recognition correctly returns None.
        assert_eq!(
            classify_guard_type("Data<AuthController>"),
            None,
            "outer Data<> is a bare data extractor, not auth-bearing"
        );
        assert_eq!(classify_guard_type("web::Path<UserId>"), None);
        assert_eq!(classify_guard_type("Json<CreateUser>"), None);
        assert_eq!(classify_guard_type("Form<LoginForm>"), None);
    }

    #[test]
    fn classify_guard_type_preserves_existing_login_guard_recognition() {
        assert_eq!(
            classify_guard_type("LocalUserView"),
            Some(AuthCheckKind::LoginGuard)
        );
        assert_eq!(
            classify_guard_type("Authenticated"),
            Some(AuthCheckKind::LoginGuard)
        );
        assert_eq!(
            classify_guard_type("AdminUser"),
            Some(AuthCheckKind::AdminGuard)
        );
        assert_eq!(
            classify_guard_type("CurrentUser"),
            Some(AuthCheckKind::LoginGuard)
        );
    }

    #[test]
    fn classify_guard_type_admin_guarded_takes_admin_priority() {
        // `AdminGuard` outer wrapper has both "admin" and "guard" tokens
        // — admin-priority rule wins inside the Guarded branch.
        assert_eq!(
            classify_guard_type("AdminGuard<P, D>"),
            Some(AuthCheckKind::AdminGuard)
        );
        assert_eq!(
            classify_guard_type("GuardedAdmin<X>"),
            Some(AuthCheckKind::AdminGuard)
        );
    }

    #[test]
    fn classify_guard_type_unknown_outer_returns_none() {
        assert_eq!(classify_guard_type("MyCustomWrapper<T>"), None);
        assert_eq!(classify_guard_type(""), None);
    }
}
