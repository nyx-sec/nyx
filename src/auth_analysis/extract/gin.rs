use super::AuthExtractor;
use super::common::{
    attach_route_handler, call_site_from_node, http_method_from_name, is_handler_reference,
    join_route_paths, member_target, named_children, push_route_registration, string_literal_value,
    text, visit_named_nodes,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{AuthorizationModel, CallSite, Framework};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct GinExtractor;

impl AuthExtractor for GinExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "go"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Gin))
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
        let mut groups = HashMap::new();

        visit_named_nodes(root, &mut |node| match node.kind() {
            "short_var_declaration" | "assignment_statement" => {
                maybe_collect_group_binding(node, bytes, &mut groups)
            }
            "call_expression" => {
                maybe_collect_group_use(node, bytes, &mut groups);
                maybe_collect_route(root, node, bytes, path, rules, &groups, model);
            }
            _ => {}
        });
    }
}

#[derive(Clone, Default)]
struct GroupSpec {
    path_prefix: String,
    middleware_calls: Vec<CallSite>,
}

fn maybe_collect_group_binding(
    node: Node<'_>,
    bytes: &[u8],
    groups: &mut HashMap<String, GroupSpec>,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let Some(group_call) = named_children(right)
        .into_iter()
        .find(|child| child.kind() == "call_expression" && is_group_call(*child, bytes))
    else {
        return;
    };

    let Some(group_name) = named_children(left)
        .into_iter()
        .find(|child| child.kind() == "identifier")
        .map(|child| text(child, bytes))
    else {
        return;
    };
    let Some((base_name, path_prefix, middleware_calls)) = parse_group_call(group_call, bytes)
    else {
        return;
    };
    let base = groups.get(&base_name).cloned().unwrap_or_default();
    let mut combined = base.middleware_calls;
    combined.extend(middleware_calls);
    groups.insert(
        group_name,
        GroupSpec {
            path_prefix: join_route_paths(&base.path_prefix, &path_prefix),
            middleware_calls: combined,
        },
    );
}

fn maybe_collect_group_use(node: Node<'_>, bytes: &[u8], groups: &mut HashMap<String, GroupSpec>) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let Some((object_name, method_name)) = member_target(function, bytes) else {
        return;
    };
    if method_name != "Use" {
        return;
    }
    let Some(group) = groups.get_mut(&object_name) else {
        return;
    };
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return;
    };
    for arg in named_children(arguments) {
        group.middleware_calls.push(call_site_from_node(arg, bytes));
    }
}

fn maybe_collect_route(
    root: Node<'_>,
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    groups: &HashMap<String, GroupSpec>,
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
    let Some((handler_idx, handler_expr)) = args
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

    let mut middleware_calls = groups
        .get(&object_name)
        .map(|group| group.middleware_calls.clone())
        .unwrap_or_default();
    for middleware in &args[1..handler_idx] {
        middleware_calls.push(call_site_from_node(*middleware, bytes));
    }
    let path_prefix = groups
        .get(&object_name)
        .map(|group| group.path_prefix.as_str())
        .unwrap_or("");

    push_route_registration(
        model,
        Framework::Gin,
        method,
        join_route_paths(path_prefix, &route_path),
        path,
        handler,
        middleware_calls,
    );
}

fn is_group_call(node: Node<'_>, bytes: &[u8]) -> bool {
    node.child_by_field_name("function")
        .and_then(|function| member_target(function, bytes))
        .is_some_and(|(_, method_name)| method_name == "Group")
}

fn parse_group_call(node: Node<'_>, bytes: &[u8]) -> Option<(String, String, Vec<CallSite>)> {
    let function = node.child_by_field_name("function")?;
    let (base_name, method_name) = member_target(function, bytes)?;
    if method_name != "Group" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let args = named_children(arguments);
    let path = args
        .first()
        .and_then(|arg| string_literal_value(*arg, bytes))
        .unwrap_or_default();
    let middleware_calls = args[1..]
        .iter()
        .map(|arg| call_site_from_node(*arg, bytes))
        .collect();
    Some((base_name, path, middleware_calls))
}
