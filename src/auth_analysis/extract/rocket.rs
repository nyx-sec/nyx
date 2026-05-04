use super::AuthExtractor;
use super::axum::{
    GuardFramework, apply_aliases, dedup_call_sites, guard_calls_for_handler, inject_guard_checks,
    rust_param_aliases,
};
use super::common::{
    attach_route_handler, function_definition_node, function_name, named_children, text,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{AuthorizationModel, Framework, HttpMethod, RouteRegistration};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct RocketExtractor;

impl AuthExtractor for RocketExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "rust"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Rocket))
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
        collect_handlers(root, root, bytes, path, rules, model);
    }
}

fn collect_handlers(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    if node.kind() == "function_item" {
        maybe_collect_route(root, node, bytes, path, rules, model);
    }

    for child in named_children(node) {
        collect_handlers(root, child, bytes, path, rules, model);
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
    let route_attrs = route_attributes(node, bytes);
    if route_attrs.is_empty() {
        return;
    }

    for (method, route_path) in route_attrs {
        let Some(handler) = attach_route_handler(
            root,
            node,
            format!(
                "{:?} {}",
                method,
                function_name(function_definition_node(node), bytes)
                    .unwrap_or_else(|| "rocket_handler".to_string())
            ),
            bytes,
            rules,
            model,
        ) else {
            continue;
        };

        let mut middleware_calls =
            guard_calls_for_handler(node, &route_path, bytes, GuardFramework::Rocket);
        dedup_call_sites(&mut middleware_calls);

        if let Some(unit) = model.units.get_mut(handler.unit_idx) {
            let aliases = rust_param_aliases(node, &route_path, bytes, GuardFramework::Rocket);
            apply_aliases(unit, &aliases);
            inject_guard_checks(unit, &middleware_calls, rules);
        }

        model.routes.push(RouteRegistration {
            framework: Framework::Rocket,
            method,
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
}

fn route_attributes(node: Node<'_>, bytes: &[u8]) -> Vec<(HttpMethod, String)> {
    text(node, bytes)
        .lines()
        .map(str::trim)
        .take_while(|line| line.starts_with("#["))
        .filter_map(parse_route_attribute)
        .collect()
}

fn parse_route_attribute(line: &str) -> Option<(HttpMethod, String)> {
    let method = if line.starts_with("#[get") {
        HttpMethod::Get
    } else if line.starts_with("#[post") {
        HttpMethod::Post
    } else if line.starts_with("#[put") {
        HttpMethod::Put
    } else if line.starts_with("#[delete") {
        HttpMethod::Delete
    } else if line.starts_with("#[patch") {
        HttpMethod::Patch
    } else {
        return None;
    };

    let start = line.find('"')?;
    let rest = &line[start + 1..];
    let end = rest.find('"')?;
    Some((method, rest[..end].to_string()))
}
