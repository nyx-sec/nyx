use super::AuthExtractor;
use super::common::{
    attach_route_handler, call_site_from_node, http_method_from_name, is_handler_reference,
    member_target, named_children, push_route_registration, string_literal_value,
    visit_named_nodes,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{AuthorizationModel, Framework};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct ExpressExtractor;

impl AuthExtractor for ExpressExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        matches!(lang, "javascript" | "typescript")
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Express))
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
                maybe_collect_route(root, node, bytes, path, rules, model);
            }
        });
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
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let Some((object_name, method_name)) = member_target(function, bytes) else {
        return;
    };
    let Some(method) = http_method_from_name(&method_name) else {
        return;
    };
    if !matches!(object_name.as_str(), "router" | "app") {
        return;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    let named_args = named_children(arguments);
    let Some(path_node) = named_args.first().copied() else {
        return;
    };
    let Some(route_path) = string_literal_value(path_node, bytes) else {
        return;
    };

    let Some((handler_idx, handler_expr)) = named_args
        .iter()
        .enumerate()
        .rev()
        .find(|(_, arg)| is_handler_reference(**arg))
    else {
        return;
    };

    let Some(handler) = attach_route_handler(
        root,
        *handler_expr,
        format!("{:?} {}", method, route_path),
        bytes,
        rules,
        model,
    ) else {
        return;
    };

    let middleware_calls = named_args[1..handler_idx]
        .iter()
        .map(|middleware| call_site_from_node(*middleware, bytes))
        .collect();

    push_route_registration(
        model,
        Framework::Express,
        method,
        route_path,
        path,
        handler,
        middleware_calls,
    );
}
