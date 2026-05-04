use super::AuthExtractor;
use super::common::{
    auth_check_from_call_site, build_function_unit, function_name, join_route_paths,
    named_children, push_route_registration, span, text,
};
use crate::auth_analysis::config::AuthAnalysisRules;
use crate::auth_analysis::model::{
    AnalysisUnitKind, AuthorizationModel, CallSite, Framework, HttpMethod,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use std::path::Path;
use tree_sitter::{Node, Tree};

pub struct SpringExtractor;

impl AuthExtractor for SpringExtractor {
    fn supports(&self, lang: &str, framework_ctx: Option<&FrameworkContext>) -> bool {
        lang == "java"
            && framework_ctx
                .is_none_or(|ctx| ctx.frameworks.is_empty() || ctx.has(DetectedFramework::Spring))
    }

    fn requires_top_level_units(&self) -> bool {
        // Spring synthesises its own units inside `maybe_collect_controller`
        // (only `@Controller` / `@RestController`-annotated classes
        // produce units; non-controller Java files contribute nothing).
        // The orchestrator's shared `collect_top_level_units` pass would
        // emit a `Function` unit per top-level method on every Java file
        // including non-controller helpers, doubling work and broadening
        // the analysis surface beyond what Spring needs.
        false
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
        collect_classes(root, bytes, path, rules, model);
    }
}

#[derive(Clone)]
struct SpringRouteSpec {
    method: HttpMethod,
    path: String,
}

fn collect_classes(
    node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    if node.kind() == "class_declaration" {
        maybe_collect_controller(node, bytes, path, rules, model);
    }

    for child in named_children(node) {
        collect_classes(child, bytes, path, rules, model);
    }
}

fn maybe_collect_controller(
    class_node: Node<'_>,
    bytes: &[u8],
    path: &Path,
    rules: &AuthAnalysisRules,
    model: &mut AuthorizationModel,
) {
    let class_annotations = annotation_lines(class_node, bytes);
    if !class_annotations.iter().any(|annotation| {
        annotation.starts_with("@Controller") || annotation.starts_with("@RestController")
    }) {
        return;
    }

    let class_name = class_node
        .child_by_field_name("name")
        .map(|name| text(name, bytes))
        .unwrap_or_else(|| "SpringController".to_string());
    let class_path = class_request_path(&class_annotations);
    let class_security = parse_security_annotations(&class_annotations, span(class_node));
    let Some(body) = class_node.child_by_field_name("body") else {
        return;
    };

    for child in named_children(body) {
        if child.kind() != "method_declaration" {
            continue;
        }

        let method_annotations = annotation_lines(child, bytes);
        let route_specs = parse_route_annotations(&method_annotations);
        if route_specs.is_empty() {
            continue;
        }

        let mut middleware_calls = class_security.clone();
        middleware_calls.extend(parse_security_annotations(&method_annotations, span(child)));
        let route_name = format!(
            "{class_name}.{}",
            function_name(child, bytes).unwrap_or_else(|| "handler".to_string())
        );
        let line = child.start_position().row + 1;

        for spec in route_specs {
            let unit_idx = model.units.len();
            let mut unit = build_function_unit(
                child,
                AnalysisUnitKind::RouteHandler,
                Some(route_name.clone()),
                bytes,
                rules,
            );
            for call in &middleware_calls {
                if let Some(mut check) = auth_check_from_call_site(call, line, rules) {
                    // Spring `@PreAuthorize` / `@Secured` /
                    // `@RolesAllowed` annotations are declared at the
                    // method or class boundary and authorize the entire
                    // request, same shape as FastAPI / Flask
                    // `dependencies=[Depends(...)]`.  Mark route-level
                    // so `auth_check_covers_subject` covers row fetches
                    // and downstream sinks in the handler body.
                    check.is_route_level = true;
                    unit.auth_checks.push(check);
                }
            }
            let handler_span = span(child);
            let handler_params = unit.params.clone();
            model.units.push(unit);

            push_route_registration(
                model,
                Framework::Spring,
                spec.method,
                join_route_paths(&class_path, &spec.path),
                path,
                super::common::ResolvedHandler {
                    unit_idx,
                    span: handler_span,
                    params: handler_params,
                    line,
                },
                middleware_calls.clone(),
            );
        }
    }
}

fn annotation_lines(node: Node<'_>, bytes: &[u8]) -> Vec<String> {
    text(node, bytes)
        .lines()
        .map(str::trim)
        .take_while(|line| line.starts_with('@'))
        .map(|line| line.to_string())
        .collect()
}

fn class_request_path(annotations: &[String]) -> String {
    annotations
        .iter()
        .find(|annotation| annotation.starts_with("@RequestMapping"))
        .and_then(|annotation| annotation_path(annotation))
        .unwrap_or_default()
}

fn parse_route_annotations(annotations: &[String]) -> Vec<SpringRouteSpec> {
    let mut specs = Vec::new();

    for annotation in annotations {
        let annotation = annotation.as_str();
        let method = if annotation.starts_with("@GetMapping") {
            Some(vec![HttpMethod::Get])
        } else if annotation.starts_with("@PostMapping") {
            Some(vec![HttpMethod::Post])
        } else if annotation.starts_with("@PutMapping") {
            Some(vec![HttpMethod::Put])
        } else if annotation.starts_with("@DeleteMapping") {
            Some(vec![HttpMethod::Delete])
        } else if annotation.starts_with("@PatchMapping") {
            Some(vec![HttpMethod::Patch])
        } else if annotation.starts_with("@RequestMapping") {
            Some(request_mapping_methods(annotation))
        } else {
            None
        };
        let Some(methods) = method else {
            continue;
        };
        let path = annotation_path(annotation).unwrap_or_default();
        specs.extend(methods.into_iter().map(|method| SpringRouteSpec {
            method,
            path: path.clone(),
        }));
    }

    specs
}

fn request_mapping_methods(annotation: &str) -> Vec<HttpMethod> {
    let mut methods = Vec::new();
    for (needle, method) in [
        ("RequestMethod.GET", HttpMethod::Get),
        ("RequestMethod.POST", HttpMethod::Post),
        ("RequestMethod.PUT", HttpMethod::Put),
        ("RequestMethod.DELETE", HttpMethod::Delete),
        ("RequestMethod.PATCH", HttpMethod::Patch),
    ] {
        if annotation.contains(needle) {
            methods.push(method);
        }
    }
    if methods.is_empty() {
        methods.push(HttpMethod::All);
    }
    methods
}

fn annotation_path(annotation: &str) -> Option<String> {
    quoted_strings(annotation).into_iter().next()
}

fn parse_security_annotations(annotations: &[String], span: (usize, usize)) -> Vec<CallSite> {
    let mut calls = Vec::new();

    for annotation in annotations {
        if annotation.starts_with("@RolesAllowed") {
            calls.push(CallSite {
                name: "RolesAllowed".to_string(),
                args: quoted_strings(annotation),
                span,
                args_value_refs: Vec::new(),
            });
        } else if annotation.starts_with("@Secured") {
            calls.push(CallSite {
                name: "Secured".to_string(),
                args: quoted_strings(annotation),
                span,
                args_value_refs: Vec::new(),
            });
        } else if annotation.starts_with("@PreAuthorize")
            || annotation.starts_with("@PostAuthorize")
        {
            let Some(expression) = quoted_strings(annotation).into_iter().next() else {
                continue;
            };
            if expression.contains("isAuthenticated") {
                calls.push(CallSite {
                    name: "isAuthenticated".to_string(),
                    args: vec![expression.clone()],
                    span,
                    args_value_refs: Vec::new(),
                });
            }
            if let Some((name, args)) = parse_expression_call(&expression) {
                calls.push(CallSite {
                    name,
                    args,
                    span,
                    args_value_refs: Vec::new(),
                });
            }
        }
    }

    calls
}

fn parse_expression_call(expression: &str) -> Option<(String, Vec<String>)> {
    for candidate in ["hasRole", "hasAuthority"] {
        if let Some(args) = named_call_args(expression, candidate) {
            return Some((candidate.to_string(), args));
        }
    }

    let open_idx = expression.find('(')?;
    let close_idx = expression.rfind(')')?;
    if close_idx <= open_idx {
        return None;
    }

    let prefix = expression[..open_idx].trim();
    let name = prefix
        .trim_start_matches('@')
        .rsplit('.')
        .next()
        .unwrap_or(prefix)
        .trim();
    if name.is_empty() {
        return None;
    }
    let args = expression[open_idx + 1..close_idx]
        .split(',')
        .map(str::trim)
        .filter(|arg| !arg.is_empty())
        .map(|arg| arg.to_string())
        .collect::<Vec<_>>();
    Some((name.to_string(), args))
}

fn named_call_args(expression: &str, name: &str) -> Option<Vec<String>> {
    let needle = format!("{name}(");
    let start = expression.find(&needle)?;
    let args = &expression[start + needle.len()..];
    let end = args.find(')')?;
    let values = args[..end]
        .split(',')
        .map(|arg| arg.trim().trim_matches('\'').trim_matches('"'))
        .filter(|arg| !arg.is_empty())
        .map(|arg| arg.to_string())
        .collect::<Vec<_>>();
    Some(values)
}

fn quoted_strings(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for ch in input.chars() {
        match quote {
            Some(active) if ch == active => {
                out.push(current.clone());
                current.clear();
                quote = None;
            }
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
            }
            None => {}
        }
    }

    out
}
