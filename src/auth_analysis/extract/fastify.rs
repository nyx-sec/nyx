use super::AuthExtractor;
use super::common::{
    attach_route_handler, call_sites_from_value, http_method_from_name, is_handler_reference,
    member_target, named_children, object_property_value, push_route_registration,
    string_literal_value, visit_named_nodes,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{AuthorizationModel, CallSite, Framework};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct FastifyExtractor;

impl AuthExtractor for FastifyExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        matches!(lang, "javascript" | "typescript")
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Fastify))
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
            if node.kind() == "call_expression" {
                maybe_collect_shorthand_route(root, node, bytes, path, rules, model);
                maybe_collect_route_object(root, node, bytes, path, rules, model);
            }
        });
    }
}

fn maybe_collect_shorthand_route(
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
    let Some((object_name, method_name)) = member_target(function, bytes) else {
        return;
    };
    let Some(method) = http_method_from_name(&method_name) else {
        return;
    };
    if !matches!(object_name.as_str(), "fastify" | "app" | "server") {
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

    let options = args.get(1).copied().filter(|node| node.kind() == "object");
    let handler_expr = args
        .last()
        .copied()
        .filter(|node| is_handler_reference(*node))
        .or_else(|| options.and_then(|opts| object_property_value(opts, bytes, &["handler"])));
    let Some(handler_expr) = handler_expr else {
        return;
    };

    let Some(handler) = attach_route_handler(
        root,
        handler_expr,
        format!("{:?} {}", method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let middleware_calls = options
        .map(|opts| collect_fastify_hooks(opts, bytes))
        .unwrap_or_default();

    push_route_registration(
        model,
        Framework::Fastify,
        method,
        route_path,
        path,
        handler,
        middleware_calls,
    );
}

fn maybe_collect_route_object(
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
    if !is_fastify_route_call(function, bytes) {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let Some(route_object) = named_children(arguments).first().copied() else {
        return;
    };
    if route_object.kind() != "object" {
        return;
    }

    let Some(method_text) = object_property_value(route_object, bytes, &["method"])
        .and_then(|value| string_literal_value(value, bytes))
    else {
        return;
    };
    let Some(method) = http_method_from_name(&method_text) else {
        return;
    };
    let Some(route_path) = object_property_value(route_object, bytes, &["url", "path"])
        .and_then(|value| string_literal_value(value, bytes))
    else {
        return;
    };
    let Some(handler_expr) = object_property_value(route_object, bytes, &["handler"]) else {
        return;
    };
    let Some(handler) = attach_route_handler(
        root,
        handler_expr,
        format!("{:?} {}", method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let middleware_calls = collect_fastify_hooks(route_object, bytes);

    push_route_registration(
        model,
        Framework::Fastify,
        method,
        route_path,
        path,
        handler,
        middleware_calls,
    );
}

fn collect_fastify_hooks(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let mut hooks = Vec::new();
    for field in ["preHandler", "preValidation", "onRequest"] {
        if let Some(value) = object_property_value(node, bytes, &[field]) {
            hooks.extend(call_sites_from_value(value, bytes));
        }
    }
    hooks
}

fn is_fastify_route_call(node: Node<'_>, bytes: &[u8]) -> bool {
    member_target(node, bytes).is_some_and(|(object_name, property)| {
        matches!(object_name.as_str(), "fastify" | "app" | "server") && property == "route"
    })
}
