use super::AuthExtractor;
use super::axum::{
    GuardFramework, apply_aliases, apply_typed_extractor_guards_to_units, dedup_call_sites,
    expanded_guard_call_sites, guard_calls_for_handler, inject_guard_checks, rust_param_aliases,
};
use super::common::{
    attach_route_handler, call_name, named_children, resolve_handler_node, string_literal_value,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{
    AuthorizationModel, CallSite, Framework, HttpMethod, RouteRegistration,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct ActixWebExtractor;

impl AuthExtractor for ActixWebExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "rust"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::ActixWeb))
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
        collect_routes(root, root, bytes, path, rules, model);
        apply_typed_extractor_guards_to_units(root, bytes, rules, model, GuardFramework::ActixWeb);
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

    let receiver = node.child_by_field_name("function").and_then(|function| {
        function
            .child_by_field_name("object")
            .or_else(|| function.child_by_field_name("argument"))
    });
    let receiver_spec = receiver
        .map(|r| parse_service_receiver(r, bytes))
        .unwrap_or_default();

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = named_children(arguments);
    let (route_suffix, builder_node) = if args.len() >= 2 {
        let Some(route_path) = args
            .first()
            .and_then(|arg| string_literal_value(*arg, bytes))
        else {
            return;
        };
        let Some(builder_node) = args.get(1).copied() else {
            return;
        };
        (route_path, builder_node)
    } else if args.len() == 1 && !receiver_spec.resource_path.is_empty() {
        (String::new(), args[0])
    } else {
        return;
    };
    let Some(spec) = parse_route_builder(builder_node, bytes) else {
        return;
    };
    let Some(handler_node) = resolve_handler_node(root, spec.handler_expr, bytes) else {
        return;
    };
    let Some(handler) = attach_route_handler(
        root,
        spec.handler_expr,
        format!(
            "{:?} {}",
            spec.method,
            join_paths(
                &join_paths(&receiver_spec.scope_prefix, &receiver_spec.resource_path),
                &route_suffix
            )
        ),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let mut middleware_calls = receiver_spec.middleware_calls;
    middleware_calls.extend(spec.middleware_calls);
    let guard_calls =
        guard_calls_for_handler(handler_node, &route_suffix, bytes, GuardFramework::ActixWeb);
    middleware_calls.extend(guard_calls.clone());
    dedup_call_sites(&mut middleware_calls);

    if let Some(unit) = model.units.get_mut(handler.unit_idx) {
        let aliases =
            rust_param_aliases(handler_node, &route_suffix, bytes, GuardFramework::ActixWeb);
        apply_aliases(unit, &aliases);
        inject_guard_checks(unit, &guard_calls, rules);
    }

    model.routes.push(RouteRegistration {
        framework: Framework::ActixWeb,
        method: spec.method,
        path: join_paths(
            &join_paths(&receiver_spec.scope_prefix, &receiver_spec.resource_path),
            &route_suffix,
        ),
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

#[derive(Default)]
struct ReceiverSpec {
    scope_prefix: String,
    resource_path: String,
    middleware_calls: Vec<CallSite>,
}

fn parse_service_receiver(node: Node<'_>, bytes: &[u8]) -> ReceiverSpec {
    if node.kind() != "call_expression" {
        return ReceiverSpec::default();
    }

    let name = call_name(node, bytes);
    let method = name.rsplit('.').next().unwrap_or_default();
    let receiver = node.child_by_field_name("function").and_then(|function| {
        function
            .child_by_field_name("object")
            .or_else(|| function.child_by_field_name("argument"))
    });
    let mut spec = receiver
        .map(|receiver| parse_service_receiver(receiver, bytes))
        .unwrap_or_default();

    match method {
        "scope" => {
            if let Some(arguments) = node.child_by_field_name("arguments")
                && let Some(prefix) = named_children(arguments)
                    .first()
                    .and_then(|arg| string_literal_value(*arg, bytes))
            {
                spec.scope_prefix = join_paths(&spec.scope_prefix, &prefix);
            }
        }
        "resource" => {
            if let Some(arguments) = node.child_by_field_name("arguments")
                && let Some(path) = named_children(arguments)
                    .first()
                    .and_then(|arg| string_literal_value(*arg, bytes))
            {
                spec.resource_path = path;
            }
        }
        "wrap" | "guard" => {
            if let Some(arguments) = node.child_by_field_name("arguments") {
                for arg in named_children(arguments) {
                    spec.middleware_calls
                        .extend(expanded_guard_call_sites(arg, bytes));
                }
            }
        }
        _ => {}
    }

    spec
}

struct BuilderSpec<'tree> {
    method: HttpMethod,
    handler_expr: Node<'tree>,
    middleware_calls: Vec<CallSite>,
}

fn parse_route_builder<'tree>(node: Node<'tree>, bytes: &[u8]) -> Option<BuilderSpec<'tree>> {
    let name = call_name(node, bytes);
    let method = name.rsplit('.').next().unwrap_or_default();
    if matches!(method, "to" | "guard") {
        let receiver = node.child_by_field_name("function").and_then(|function| {
            function
                .child_by_field_name("object")
                .or_else(|| function.child_by_field_name("argument"))
        })?;
        let mut spec = parse_route_builder(receiver, bytes)?;
        if method == "to" {
            let args = node
                .child_by_field_name("arguments")
                .map(named_children)
                .unwrap_or_default();
            spec.handler_expr = *args.last()?;
        } else if let Some(arguments) = node.child_by_field_name("arguments") {
            for arg in named_children(arguments) {
                spec.middleware_calls
                    .extend(expanded_guard_call_sites(arg, bytes));
            }
        }
        return Some(spec);
    }

    let method = actix_http_method(method)?;
    Some(BuilderSpec {
        method,
        handler_expr: node,
        middleware_calls: Vec::new(),
    })
}

fn actix_http_method(name: &str) -> Option<HttpMethod> {
    match name {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "delete" => Some(HttpMethod::Delete),
        "patch" => Some(HttpMethod::Patch),
        _ => None,
    }
}

fn join_paths(prefix: &str, route: &str) -> String {
    match (prefix.trim_end_matches('/'), route.trim_start_matches('/')) {
        ("", "") => "/".to_string(),
        ("", route) => format!("/{route}"),
        (prefix, "") => prefix.to_string(),
        (prefix, route) => format!("{prefix}/{route}"),
    }
}
