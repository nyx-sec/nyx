use super::AuthExtractor;
use super::common::{
    auth_check_from_call_site, build_function_unit, call_name, call_site_from_node, function_name,
    named_children, ruby_callback_target_names, ruby_method_is_callback_or_private,
    ruby_method_visibility, span, text,
};
use crate::auth_analysis::config::{AuthAnalysisRules, matches_name, strip_quotes};
use crate::auth_analysis::model::{
    AnalysisUnitKind, AuthorizationModel, CallSite, Framework, HttpMethod, RouteRegistration,
};
use crate::labels::bare_method_name;
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct RailsExtractor;

impl AuthExtractor for RailsExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "ruby"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Rails))
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
        collect_nodes(root, &[], bytes, path, rules, &mut model);
        model
    }
}

#[derive(Clone)]
struct FilterDirective {
    call: CallSite,
    only: Vec<String>,
    except: Vec<String>,
    skip: bool,
}

fn collect_nodes(
    node: Node<'_>,
    namespace: &[String],
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    match node.kind() {
        "module" => {
            let mut next_namespace = namespace.to_vec();
            if let Some(name) = ruby_constant_segments(node.child_by_field_name("name"), bytes) {
                next_namespace.extend(name);
            }
            if let Some(body) = node.child_by_field_name("body") {
                collect_nodes(body, &next_namespace, bytes, path, rules, model);
            }
        }
        "class" => {
            maybe_collect_controller(node, namespace, bytes, path, rules, model);
        }
        _ => {
            for child in named_children(node) {
                collect_nodes(child, namespace, bytes, path, rules, model);
            }
        }
    }
}

fn maybe_collect_controller(
    class_node: Node<'_>,
    namespace: &[String],
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let Some(name_segments) = ruby_constant_segments(class_node.child_by_field_name("name"), bytes)
    else {
        return;
    };
    let Some(class_name) = name_segments.last() else {
        return;
    };
    if !class_name.ends_with("Controller") {
        return;
    }
    let Some(body) = class_node.child_by_field_name("body") else {
        return;
    };

    let mut controller_namespace = namespace.to_vec();
    controller_namespace.extend(
        name_segments[..name_segments.len().saturating_sub(1)]
            .iter()
            .cloned(),
    );
    let controller_segment = underscore_segment(class_name.trim_end_matches("Controller"));
    let filter_directives = class_filter_directives(body, bytes);
    // Rails routes only dispatch to public instance methods that are
    // not registered as filter callbacks.  Private / protected helpers
    // and methods named in `before_action :foo` / `after_action :bar`
    // run as part of an action's request cycle but are never
    // independently routable, so emitting them as RouteHandler units
    // produces FPs (e.g. `set_account` in
    // `mastodon/app/controllers/admin/accounts_controller.rb` does
    // `Account.find(params[:id])` inside a `private` block, with the
    // actual `authorize @account` check living in the public action
    // that triggers the callback).  Skip them here; the action units
    // remain under analysis with their own auth context.
    let visibility = ruby_method_visibility(body, bytes);
    let callback_targets = ruby_callback_target_names(body, bytes);
    let controller_name = format!(
        "{}{}",
        if controller_namespace.is_empty() {
            String::new()
        } else {
            format!("{}::", controller_namespace.join("::"))
        },
        class_name
    );

    for child in named_children(body) {
        if child.kind() != "method" {
            continue;
        }
        let Some(action_name) = function_name(child, bytes) else {
            continue;
        };
        if action_name.is_empty() || action_name.ends_with('=') {
            continue;
        }
        if ruby_method_is_callback_or_private(&action_name, &visibility, &callback_targets) {
            continue;
        }

        let unit_idx = model.units.len();
        let route_name = format!("{controller_name}#{action_name}");
        let mut unit = build_function_unit(
            child,
            AnalysisUnitKind::RouteHandler,
            Some(route_name.clone()),
            bytes,
            rules,
        );
        let handler_span = span(child);
        let handler_params = unit.params.clone();
        let line = child.start_position().row + 1;
        let middleware_calls = applicable_filters(&filter_directives, &action_name);
        for call in &middleware_calls {
            if let Some(mut check) = auth_check_from_call_site(call, line, rules) {
                // Rails `before_action :authorize_user`-style filter
                // callbacks run before the action and authorize the
                // entire request, same shape as FastAPI / Flask
                // `dependencies=[Depends(...)]`.  Mark route-level so
                // `auth_check_covers_subject` covers the row-fetches
                // and downstream sinks the action body performs.
                check.is_route_level = true;
                unit.auth_checks.push(check);
            }
        }
        model.units.push(unit);

        let mut route_segments = controller_namespace
            .iter()
            .map(|segment| underscore_segment(segment))
            .collect::<Vec<_>>();
        route_segments.push(controller_segment.clone());
        route_segments.push(underscore_segment(&action_name));
        let route_path = format!("/{}", route_segments.join("/"));

        model.routes.push(RouteRegistration {
            framework: Framework::Rails,
            method: infer_action_method(&action_name),
            path: route_path,
            middleware: middleware_calls
                .iter()
                .map(|call| call.name.clone())
                .collect(),
            handler_span,
            handler_params,
            file: path.to_path_buf(),
            line,
            unit_idx,
            middleware_calls,
        });
    }
}

fn class_filter_directives(body: Node<'_>, bytes: &[u8]) -> Vec<FilterDirective> {
    let mut filters = Vec::new();
    for child in named_children(body) {
        if child.kind() != "call" {
            continue;
        }
        let callee = call_name(child, bytes);
        let directive_name = bare_method_name(&callee);
        if !matches_name(directive_name, "before_action")
            && !matches_name(directive_name, "prepend_before_action")
            && !matches_name(directive_name, "skip_before_action")
        {
            continue;
        }
        filters.extend(parse_filter_directive(
            child,
            bytes,
            matches_name(directive_name, "skip_before_action"),
        ));
    }
    filters
}

fn parse_filter_directive(node: Node<'_>, bytes: &[u8], skip: bool) -> Vec<FilterDirective> {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let args = named_children(arguments);
    if args.is_empty() {
        return Vec::new();
    }

    let mut filters = Vec::new();
    let mut only = Vec::new();
    let mut except = Vec::new();
    for arg in &args {
        if arg.kind() == "pair" {
            let key = text(arg.child_by_field_name("key").unwrap_or(*arg), bytes);
            let normalized = strip_quotes(&key).trim_start_matches(':').to_string();
            let value = arg.child_by_field_name("value").unwrap_or(*arg);
            if normalized == "only" {
                only = symbol_list(value, bytes);
            } else if normalized == "except" {
                except = symbol_list(value, bytes);
            }
            continue;
        }
        filters.extend(filter_calls_from_arg(*arg, bytes));
    }

    filters
        .into_iter()
        .map(|call| FilterDirective {
            call,
            only: only.clone(),
            except: except.clone(),
            skip,
        })
        .collect()
}

fn filter_calls_from_arg(node: Node<'_>, bytes: &[u8]) -> Vec<CallSite> {
    match node.kind() {
        "simple_symbol" | "hash_key_symbol" | "identifier" => vec![CallSite {
            name: strip_quotes(&text(node, bytes))
                .trim_start_matches(':')
                .to_string(),
            args: Vec::new(),
            span: span(node),
            args_value_refs: Vec::new(),
        }],
        "array" => named_children(node)
            .into_iter()
            .flat_map(|child| filter_calls_from_arg(child, bytes))
            .collect(),
        _ => {
            let call = call_site_from_node(node, bytes);
            if call.name.is_empty() {
                Vec::new()
            } else {
                vec![call]
            }
        }
    }
}

fn applicable_filters(filters: &[FilterDirective], action: &str) -> Vec<CallSite> {
    let mut middleware = Vec::new();
    for filter in filters {
        if !filter_applies(filter, action) {
            continue;
        }
        if filter.skip {
            middleware.retain(|existing: &CallSite| existing.name != filter.call.name);
        } else if !middleware
            .iter()
            .any(|existing: &CallSite| existing.name == filter.call.name)
        {
            middleware.push(filter.call.clone());
        }
    }
    middleware
}

fn filter_applies(filter: &FilterDirective, action: &str) -> bool {
    (filter.only.is_empty() || filter.only.iter().any(|name| name == action))
        && !filter.except.iter().any(|name| name == action)
}

fn symbol_list(node: Node<'_>, bytes: &[u8]) -> Vec<String> {
    match node.kind() {
        "simple_symbol" | "hash_key_symbol" | "identifier" | "string" => vec![
            strip_quotes(&text(node, bytes))
                .trim_start_matches(':')
                .to_string(),
        ],
        "array" => named_children(node)
            .into_iter()
            .flat_map(|child| symbol_list(child, bytes))
            .collect(),
        _ => Vec::new(),
    }
}

fn ruby_constant_segments(node: Option<Node<'_>>, bytes: &[u8]) -> Option<Vec<String>> {
    let node = node?;
    let value = text(node, bytes);
    if value.is_empty() {
        return None;
    }
    Some(
        value
            .split("::")
            .map(|segment| segment.trim().to_string())
            .filter(|segment| !segment.is_empty())
            .collect(),
    )
}

fn infer_action_method(action: &str) -> HttpMethod {
    match action {
        "index" | "show" | "new" | "edit" => HttpMethod::Get,
        "create" => HttpMethod::Post,
        "update" => HttpMethod::Patch,
        "destroy" => HttpMethod::Delete,
        _ => HttpMethod::All,
    }
}

fn underscore_segment(value: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}
