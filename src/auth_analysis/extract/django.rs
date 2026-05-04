use super::AuthExtractor;
use super::common::{
    auth_check_from_call_site, build_function_unit, call_site_from_node,
    decorated_definition_child, member_chain, named_children, push_route_registration, span,
    string_literal_value, text, visit_named_nodes,
};
use crate::auth_analysis::config::{AuthAnalysisRules, matches_name};
use crate::auth_analysis::extract::common::attach_route_handler;
use crate::auth_analysis::model::{
    AnalysisUnitKind, AuthorizationModel, CallSite, Framework, HttpMethod,
};
use crate::labels::bare_method_name;
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct DjangoExtractor;

impl AuthExtractor for DjangoExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "python"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Django))
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
            if node.kind() == "call" {
                maybe_collect_django_path(root, node, bytes, path, rules, model);
            }
        });
    }
}

fn maybe_collect_django_path(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let callee = text(function, bytes);
    let target = bare_method_name(&callee);
    if !matches!(target, "path" | "re_path") {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = named_children(arguments);
    let Some(route_path) = args
        .first()
        .and_then(|arg| string_literal_value(*arg, bytes))
    else {
        return;
    };
    let Some(handler_expr) = args.get(1).copied() else {
        return;
    };

    if let Some(class_name) = as_view_class_name(handler_expr, bytes) {
        collect_class_based_routes(root, &class_name, &route_path, bytes, path, rules, model);
        return;
    }

    let Some(handler) = attach_route_handler(
        root,
        handler_expr,
        format!("All {}", route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let middleware_calls = function_view_middleware(root, handler_expr, bytes);
    inject_middleware_auth(
        model,
        handler.unit_idx,
        handler.line,
        &middleware_calls,
        rules,
    );
    for method in function_view_methods(root, handler_expr, bytes) {
        push_route_registration(
            model,
            Framework::Django,
            method,
            route_path.clone(),
            path,
            super::common::ResolvedHandler {
                unit_idx: handler.unit_idx,
                span: handler.span,
                params: handler.params.clone(),
                line: handler.line,
            },
            middleware_calls.clone(),
        );
    }
}

fn function_view_middleware(root: Node<'_>, handler_expr: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let Some(handler_node) = resolve_function_node(root, handler_expr, bytes) else {
        return Vec::new();
    };
    if handler_node.kind() != "decorated_definition" {
        return Vec::new();
    }

    decorator_expressions(handler_node)
        .into_iter()
        .filter(|decorator| http_methods_from_decorator(*decorator, bytes).is_none())
        .flat_map(|decorator| expand_decorator_calls(decorator, bytes))
        .collect()
}

fn function_view_methods(root: Node<'_>, handler_expr: Node<'_>, bytes: &[u8]) -> Vec<HttpMethod> {
    let Some(handler_node) = resolve_function_node(root, handler_expr, bytes) else {
        return vec![HttpMethod::All];
    };
    if handler_node.kind() != "decorated_definition" {
        return vec![HttpMethod::All];
    }

    let mut methods = Vec::new();
    for decorator in decorator_expressions(handler_node) {
        if let Some(found) = http_methods_from_decorator(decorator, bytes) {
            methods.extend(found);
        }
    }

    if methods.is_empty() {
        vec![HttpMethod::All]
    } else {
        methods
    }
}

fn collect_class_based_routes(
    root: Node<'_>,
    class_name: &str,
    route_path: &str,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(class_node) = find_top_level_class_node(root, class_name, bytes) else {
        return;
    };
    let Some(class_definition) = class_definition_node(class_node) else {
        return;
    };
    let class_middleware = class_middleware_calls(class_node, class_definition, bytes);
    let Some(body) = class_definition.child_by_field_name("body") else {
        return;
    };

    for child in named_children(body) {
        let method_node =
            if child.kind() == "function_definition" || child.kind() == "decorated_definition" {
                Some(child)
            } else {
                None
            };
        let Some(method_node) = method_node else {
            continue;
        };
        let method_name = function_name(method_node, bytes).unwrap_or_default();
        let Some(http_method) = method_name_to_http_method(&method_name) else {
            continue;
        };

        let route_name = format!("{class_name}.{method_name}");
        let unit_idx = model.units.len();
        let mut unit = build_function_unit(
            method_node,
            AnalysisUnitKind::RouteHandler,
            Some(route_name.clone()),
            bytes,
            rules,
        );

        let mut middleware_calls = class_middleware.clone();
        if method_node.kind() == "decorated_definition" {
            for decorator in decorator_expressions(method_node) {
                if http_methods_from_decorator(decorator, bytes).is_none() {
                    middleware_calls.extend(expand_decorator_calls(decorator, bytes));
                }
            }
        }
        let line = method_node.start_position().row + 1;
        for call in &middleware_calls {
            if let Some(mut check) = auth_check_from_call_site(call, line, rules) {
                // Django class-based-view decorators (`@method_decorator(login_required)`,
                // `@permission_required(...)`) and DRF `permission_classes`
                // are declared at the route boundary; mark route-level
                // so coverage applies to the action body's operations.
                check.is_route_level = true;
                unit.auth_checks.push(check);
            }
        }
        let handler_span = span(method_node);
        let handler_params = unit.params.clone();
        model.units.push(unit);

        push_route_registration(
            model,
            Framework::Django,
            http_method,
            route_path.to_string(),
            path,
            super::common::ResolvedHandler {
                unit_idx,
                span: handler_span,
                params: handler_params,
                line,
            },
            middleware_calls,
        );
    }
}

fn class_middleware_calls(
    class_node: Node<'_>,
    class_definition: Node<'_>,
    bytes: &[u8],
) -> Vec<CallSite> {
    let mut calls = Vec::new();
    if class_node.kind() == "decorated_definition" {
        for decorator in decorator_expressions(class_node) {
            calls.extend(expand_decorator_calls(decorator, bytes));
        }
    }
    if let Some(superclasses) = class_definition.child_by_field_name("superclasses") {
        for superclass in named_children(superclasses) {
            calls.push(call_site_from_node(superclass, bytes));
        }
    }
    calls
}

fn resolve_function_node<'tree>(
    root: Node<'tree>,
    handler_expr: Node<'tree>,
    bytes: &[u8],
) -> Option<Node<'tree>> {
    if matches!(handler_expr.kind(), "identifier" | "attribute") {
        let candidate = text(handler_expr, bytes);
        let name = candidate.rsplit('.').next().unwrap_or(&candidate);
        find_top_level_function_node(root, name, bytes)
    } else if handler_expr.kind() == "decorated_definition"
        || handler_expr.kind() == "function_definition"
    {
        Some(handler_expr)
    } else {
        None
    }
}

fn find_top_level_function_node<'tree>(
    root: Node<'tree>,
    name: &str,
    bytes: &[u8],
) -> Option<Node<'tree>> {
    for child in named_children(root) {
        match child.kind() {
            "function_definition" if function_name(child, bytes).as_deref() == Some(name) => {
                return Some(child);
            }
            "decorated_definition" => {
                if let Some(definition) = decorated_definition_child(child)
                    && definition.kind() == "function_definition"
                    && function_name(child, bytes).as_deref() == Some(name)
                {
                    return Some(child);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_top_level_class_node<'tree>(
    root: Node<'tree>,
    name: &str,
    bytes: &[u8],
) -> Option<Node<'tree>> {
    for child in named_children(root) {
        match child.kind() {
            "class_definition" if class_name(child, bytes).as_deref() == Some(name) => {
                return Some(child);
            }
            "decorated_definition" => {
                if let Some(definition) = decorated_definition_child(child)
                    && definition.kind() == "class_definition"
                    && class_name(child, bytes).as_deref() == Some(name)
                {
                    return Some(child);
                }
            }
            _ => {}
        }
    }
    None
}

fn class_definition_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "class_definition" {
        Some(node)
    } else {
        decorated_definition_child(node).filter(|child| child.kind() == "class_definition")
    }
}

fn class_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    class_definition_node(node)?
        .child_by_field_name("name")
        .map(|name| text(name, bytes))
}

fn function_name(node: Node<'_>, bytes: &[u8]) -> Option<String> {
    let definition = if node.kind() == "decorated_definition" {
        decorated_definition_child(node)?
    } else {
        node
    };
    definition
        .child_by_field_name("name")
        .map(|name| text(name, bytes))
}

fn as_view_class_name(handler_expr: Node<'_>, bytes: &[u8]) -> Option<String> {
    if handler_expr.kind() != "call" {
        return None;
    }
    let function = handler_expr.child_by_field_name("function")?;
    let chain = member_chain(function, bytes);
    if chain.len() >= 2 && chain.last().is_some_and(|segment| segment == "as_view") {
        return Some(chain[chain.len() - 2].clone());
    }
    None
}

fn method_name_to_http_method(name: &str) -> Option<HttpMethod> {
    match name.to_ascii_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        "dispatch" => Some(HttpMethod::All),
        _ => None,
    }
}

fn http_methods_from_decorator(node: Node<'_>, bytes: &[u8]) -> Option<Vec<HttpMethod>> {
    if node.kind() == "call" {
        let name = text(node.child_by_field_name("function")?, bytes);
        if matches_name(&name, "require_http_methods") {
            let arguments = node.child_by_field_name("arguments")?;
            let first = named_children(arguments).first().copied()?;
            let mut methods = Vec::new();
            for child in named_children(first) {
                if let Some(method) = string_literal_value(child, bytes)
                    .as_deref()
                    .and_then(http_method)
                {
                    methods.push(method);
                }
            }
            return Some(methods);
        }
    }

    let call = call_site_from_node(node, bytes);
    match call.name.rsplit('.').next().unwrap_or(&call.name) {
        "require_GET" => Some(vec![HttpMethod::Get]),
        "require_POST" => Some(vec![HttpMethod::Post]),
        "require_PUT" => Some(vec![HttpMethod::Put]),
        "require_DELETE" => Some(vec![HttpMethod::Delete]),
        "require_PATCH" => Some(vec![HttpMethod::Patch]),
        _ => None,
    }
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
            // Django decorators (`@login_required`, `@permission_required`,
            // `@user_passes_test`, etc.) and DRF `permission_classes` are
            // declared at the route boundary; mark route-level so
            // `auth_check_covers_subject` short-circuits `true` for any
            // non-login-guard match.  See flask.rs / model.rs for the
            // full rationale.
            check.is_route_level = true;
            unit.auth_checks.push(check);
        }
    }
}
