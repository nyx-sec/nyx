use super::AuthExtractor;
use super::common::{
    auth_check_from_call_site, build_function_unit, call_name, call_site_from_node, named_children,
    span, string_literal_value,
};
use crate::auth_analysis::config::{AuthAnalysisRules, matches_name};
use crate::auth_analysis::model::{
    AnalysisUnitKind, AuthorizationModel, CallSite, Framework, HttpMethod, RouteRegistration,
};
use crate::labels::bare_method_name;
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct SinatraExtractor;

impl AuthExtractor for SinatraExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "ruby"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Sinatra))
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
        let before_filters = collect_before_filters(root, bytes);
        collect_routes(root, bytes, path, rules, &before_filters, model);
    }
}

fn collect_before_filters(root: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let mut filters = Vec::new();
    for child in named_children(root) {
        if child.kind() != "call" {
            continue;
        }
        let callee = call_name(child, bytes);
        let target = bare_method_name(&callee);
        if !matches_name(target, "before") {
            continue;
        }
        if let Some(block) = child_block(child) {
            filters.extend(call_sites_in_block(block, bytes));
        }
    }
    filters
}

fn collect_routes(
    root: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    before_filters: &[CallSite],
    model: &mut AuthorizationModel,
) {
    for child in named_children(root) {
        if child.kind() != "call" {
            continue;
        }
        maybe_collect_route(child, bytes, path, rules, before_filters, model);
    }
}

fn maybe_collect_route(
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    before_filters: &[CallSite],
    model: &mut AuthorizationModel,
) {
    let callee = call_name(node, bytes);
    let route_name = bare_method_name(&callee);
    let method = match route_name.to_ascii_lowercase().as_str() {
        "get" => HttpMethod::Get,
        "post" => HttpMethod::Post,
        "put" => HttpMethod::Put,
        "delete" => HttpMethod::Delete,
        "patch" => HttpMethod::Patch,
        _ => return,
    };

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
    let Some(block) = child_block(node) else {
        return;
    };

    let unit_idx = model.units.len();
    let mut unit = build_function_unit(
        block,
        AnalysisUnitKind::RouteHandler,
        Some(format!("{:?} {}", method, route_path)),
        bytes,
        rules,
    );
    let line = block.start_position().row + 1;
    for call in before_filters {
        if let Some(mut check) = auth_check_from_call_site(call, line, rules) {
            // Sinatra `before` filters run before the route handler
            // body and authorize the request as a whole, same shape
            // as Rails `before_action`.  Route-level so coverage
            // applies to the handler's row fetches and downstream
            // sinks.
            check.is_route_level = true;
            unit.auth_checks.push(check);
        }
    }
    let handler_span = span(block);
    let handler_params = unit.params.clone();
    model.units.push(unit);

    model.routes.push(RouteRegistration {
        framework: Framework::Sinatra,
        method,
        path: route_path,
        middleware: before_filters
            .iter()
            .map(|call| call.name.clone())
            .collect(),
        handler_span,
        handler_params,
        file: path.to_path_buf(),
        line,
        unit_idx,
        middleware_calls: before_filters.to_vec(),
    });
}

fn child_block(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| matches!(child.kind(), "block" | "do_block"))
}

fn call_sites_in_block(block: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    let Some(body) = block.child_by_field_name("body") else {
        return Vec::new();
    };
    named_children(body)
        .into_iter()
        .filter(|child| child.kind() == "call")
        .map(|child| call_site_from_node(child, bytes))
        .filter(|call| !call.name.is_empty())
        .collect()
}
