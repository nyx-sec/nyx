use super::AuthExtractor;
use super::common::{
    auth_check_from_call_site, build_function_unit, function_name, guarantee_level,
    join_route_paths, named_children, push_route_registration, span, text,
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
            && framework_ctx.is_none_or(|ctx| ctx.allows(lang, DetectedFramework::Spring))
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
    let class_annotations = annotation_texts(class_node, bytes);
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
    let class_security = parse_security_annotations(&class_annotations, span(class_node), rules);
    let Some(body) = class_node.child_by_field_name("body") else {
        return;
    };

    for child in named_children(body) {
        if child.kind() != "method_declaration" {
            continue;
        }

        let method_annotations = annotation_texts(child, bytes);
        let route_specs = parse_route_annotations(&method_annotations);
        if route_specs.is_empty() {
            continue;
        }

        let mut middleware_calls = class_security.clone();
        middleware_calls.extend(parse_security_annotations(
            &method_annotations,
            span(child),
            rules,
        ));
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

/// The annotations on a class or method, one string each with runs of
/// whitespace collapsed, so `@PreAuthorize(\n  "..."\n)` reads as one line.
/// They come from the `modifiers` node, which keeps annotations that wrap
/// over several lines and ignores comments between them.
fn annotation_texts(node: Node<'_>, bytes: &[u8]) -> Vec<String> {
    let Some(modifiers) = named_children(node)
        .into_iter()
        .find(|child| child.kind() == "modifiers")
    else {
        return Vec::new();
    };
    named_children(modifiers)
        .into_iter()
        .filter(|child| matches!(child.kind(), "annotation" | "marker_annotation"))
        .map(|annotation| {
            text(annotation, bytes)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
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

fn parse_security_annotations(
    annotations: &[String],
    span: (usize, usize),
    rules: &AuthAnalysisRules,
) -> Vec<CallSite> {
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
            // A SpEL expression can be split over several string literals
            // (`"a and " + "b"`), so the pieces are joined before parsing.
            let expression = quoted_strings(annotation).concat();
            if expression.is_empty() {
                continue;
            }
            calls.extend(spel_expression_checks(&expression, span, rules));
        }
    }

    calls
}

/// The checks a SpEL expression guarantees once it lets a request through.
///
/// Each operand of `a and b` holds, so each is its own check.  A disjunction
/// guarantees only what its weakest disjunct does: `hasRole('ADMIN') or
/// hasRole('USER')` admits every user, and `hasRole('ADMIN') or
/// @sec.isOwner(#id, authentication)` authorizes the row without making the
/// caller an admin.  So the checks of the weakest disjunct are the ones kept
/// (see [`guarantee_level`]).  A negated operand (`!hasRole('X')`, `not ..`)
/// grants nothing.
fn spel_expression_checks(
    expression: &str,
    span: (usize, usize),
    rules: &AuthAnalysisRules,
) -> Vec<CallSite> {
    split_spel(expression, Connective::Or)
        .into_iter()
        .map(|disjunct| {
            split_spel(disjunct, Connective::And)
                .into_iter()
                .filter(|operand| !is_negated_operand(operand))
                .flat_map(|operand| spel_operand_calls(operand, span))
                .collect::<Vec<_>>()
        })
        .min_by_key(|calls| guarantee_level(calls, rules))
        .unwrap_or_default()
}

/// The calls one SpEL operand makes: `hasRole('A')`, `isAuthenticated()`,
/// `@docSecurity.isOwner(#id, authentication)`.
fn spel_operand_calls(operand: &str, span: (usize, usize)) -> Vec<CallSite> {
    let mut calls = Vec::new();
    let parsed = parse_expression_call(operand);
    if operand.contains("isAuthenticated")
        && parsed
            .as_ref()
            .is_none_or(|(name, _)| name != "isAuthenticated")
    {
        calls.push(CallSite {
            name: "isAuthenticated".to_string(),
            args: vec![operand.to_string()],
            span,
            args_value_refs: Vec::new(),
        });
    }
    if let Some((name, args)) = parsed {
        calls.push(CallSite {
            name,
            args,
            span,
            args_value_refs: Vec::new(),
        });
    }
    calls
}

#[derive(Clone, Copy)]
enum Connective {
    And,
    Or,
}

impl Connective {
    fn symbol(self) -> &'static [u8] {
        match self {
            Connective::And => b"&&",
            Connective::Or => b"||",
        }
    }

    fn word(self) -> &'static [u8] {
        match self {
            Connective::And => b"and",
            Connective::Or => b"or",
        }
    }
}

/// Split a SpEL expression at the `connective` that sit outside parentheses
/// and quotes, and drop the parentheses that wrap a whole part.
fn split_spel(expression: &str, connective: Connective) -> Vec<&str> {
    let bytes = expression.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut start = 0;
    let mut idx = 0;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
            idx += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0
            && let Some(len) = connective_len_at(bytes, idx, connective)
        {
            // Connectives are ASCII, so both ends of the part are char
            // boundaries.
            parts.push(&expression[start..idx]);
            idx += len;
            start = idx;
            continue;
        }
        idx += 1;
    }
    parts.push(&expression[start..]);
    parts
        .into_iter()
        .map(strip_wrapping_parens)
        .filter(|part| !part.is_empty())
        .collect()
}

/// Length of the connective that starts at `idx`: its symbol, or its word
/// with a space or a parenthesis on either side (`a and b`, `(a)or(b)`).
fn connective_len_at(bytes: &[u8], idx: usize, connective: Connective) -> Option<usize> {
    let rest = &bytes[idx..];
    if rest.starts_with(connective.symbol()) {
        return Some(connective.symbol().len());
    }
    let word = connective.word();
    let before = idx
        .checked_sub(1)
        .map(|prev| bytes[prev])
        .is_some_and(|b| b.is_ascii_whitespace() || b == b')');
    let matches_word = rest
        .get(..word.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(word));
    let after = rest
        .get(word.len())
        .is_some_and(|b| b.is_ascii_whitespace() || *b == b'(');
    (before && matches_word && after).then_some(word.len())
}

/// `!hasRole('X')`, `not hasRole('X')`, `not(hasRole('X'))`.
fn is_negated_operand(operand: &str) -> bool {
    let bytes = operand.as_bytes();
    bytes.first() == Some(&b'!')
        || (bytes.len() > 3
            && bytes[..3].eq_ignore_ascii_case(b"not")
            && (bytes[3].is_ascii_whitespace() || bytes[3] == b'('))
}

/// `(hasRole('A'))` -> `hasRole('A')`.  Parentheses that belong to a call are
/// kept: `hasRole('A')` stays as it is.
fn strip_wrapping_parens(operand: &str) -> &str {
    let mut operand = operand.trim();
    while operand.starts_with('(') && operand.ends_with(')') {
        let mut depth = 0usize;
        let mut wraps = true;
        for (idx, byte) in operand.bytes().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 && idx + 1 < operand.len() {
                        wraps = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !wraps {
            break;
        }
        operand = operand[1..operand.len() - 1].trim();
    }
    operand
}

fn parse_expression_call(expression: &str) -> Option<(String, Vec<String>)> {
    for candidate in ["hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority"] {
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

#[cfg(test)]
mod tests {
    use super::{
        Connective, guarantee_level, is_negated_operand, parse_expression_call,
        spel_expression_checks, split_spel, strip_wrapping_parens,
    };
    use crate::auth_analysis::config::build_auth_rules;
    use crate::utils::config::Config;

    fn check_names(expression: &str) -> Vec<String> {
        let rules = build_auth_rules(&Config::default(), "java");
        spel_expression_checks(expression, (0, 0), &rules)
            .into_iter()
            .map(|call| call.name)
            .collect()
    }

    #[test]
    fn parts_split_at_top_level_connectives_only() {
        assert_eq!(
            split_spel(
                "hasRole('ADMIN') and @sec.isOwner(#id, authentication)",
                Connective::And
            ),
            vec!["hasRole('ADMIN')", "@sec.isOwner(#id, authentication)"]
        );
        // `and` binds tighter than `or`, so the `or` split comes first.
        assert_eq!(
            split_spel(
                "hasRole('A') or hasRole('B') && isAuthenticated()",
                Connective::Or
            ),
            vec!["hasRole('A')", "hasRole('B') && isAuthenticated()"]
        );
        // Connectives inside parentheses or quotes stay where they are.
        assert_eq!(
            split_spel("@sec.check(#a and #b)", Connective::And),
            vec!["@sec.check(#a and #b)"]
        );
        assert_eq!(
            split_spel("hasAuthority('read or write')", Connective::Or),
            vec!["hasAuthority('read or write')"]
        );
        // A word that merely starts with `or` or contains `and` is not a
        // connective.
        assert_eq!(
            split_spel("order.isOpen() and brand.ok()", Connective::Or),
            vec!["order.isOpen() and brand.ok()"]
        );
        assert_eq!(
            split_spel("(hasRole('A'))or(hasRole('B'))", Connective::Or),
            vec!["hasRole('A')", "hasRole('B')"]
        );
    }

    #[test]
    fn negated_operands_are_recognised() {
        assert!(is_negated_operand("!hasRole('BLOCKED')"));
        assert!(is_negated_operand("not hasRole('BLOCKED')"));
        assert!(is_negated_operand("NOT(hasRole('BLOCKED'))"));
        assert!(!is_negated_operand("nothing()"));
        assert!(!is_negated_operand("hasRole('ADMIN')"));
    }

    #[test]
    fn every_conjunct_is_a_check() {
        assert_eq!(
            check_names("hasRole('ADMIN') and @sec.isOwner(#id, authentication)"),
            vec!["hasRole", "isOwner"]
        );
        // A negated conjunct grants nothing; the rest still holds.
        assert_eq!(
            check_names("!hasRole('BLOCKED') and isAuthenticated()"),
            vec!["isAuthenticated"]
        );
    }

    #[test]
    fn a_disjunction_keeps_only_its_weakest_disjunct() {
        let rules = build_auth_rules(&Config::default(), "java");
        let admin = |expression: &str| {
            spel_expression_checks(expression, (0, 0), &rules)
                .iter()
                .any(|call| rules.is_admin_guard(&call.name, &call.args))
        };
        // Any user passes `hasRole('USER')`, so the admin role proves nothing.
        assert!(!admin("hasRole('ADMIN') or hasRole('USER')"));
        assert_eq!(
            check_names("hasRole('ADMIN') or hasRole('USER')"),
            vec!["hasRole"]
        );
        // Admin or owner: the row is authorized either way, but the caller
        // need not be an admin.
        assert_eq!(
            check_names("hasRole('ADMIN') or @sec.isOwner(#id, authentication)"),
            vec!["isOwner"]
        );
        assert!(!admin(
            "hasRole('ADMIN') or @sec.isOwner(#id, authentication)"
        ));
        // Both disjuncts are admin roles.
        assert!(admin("hasRole('ADMIN') or hasAuthority('ROLE_SUPERUSER')"));
        // A negated or unknown disjunct lets anyone through.
        let level = |expression: &str| {
            guarantee_level(&spel_expression_checks(expression, (0, 0), &rules), &rules)
        };
        assert_eq!(level("not hasRole('BLOCKED') or hasRole('ADMIN')"), 0);
        assert_eq!(level("permitAll() or hasRole('ADMIN')"), 0);
        assert_eq!(level("isAuthenticated() or hasRole('ADMIN')"), 1);
    }

    #[test]
    fn wrapping_parentheses_are_stripped_but_call_parentheses_are_not() {
        assert_eq!(strip_wrapping_parens("(hasRole('A'))"), "hasRole('A')");
        assert_eq!(strip_wrapping_parens("((a))"), "a");
        assert_eq!(strip_wrapping_parens("hasRole('A')"), "hasRole('A')");
        assert_eq!(
            strip_wrapping_parens("(a) and (b)"),
            "(a) and (b)",
            "the outer parentheses do not match each other"
        );
    }

    #[test]
    fn role_lists_keep_every_argument() {
        let (name, args) = parse_expression_call("hasAnyRole('ADMIN', 'MANAGER')").unwrap();
        assert_eq!(name, "hasAnyRole");
        assert_eq!(args, vec!["ADMIN", "MANAGER"]);
        let (name, args) = parse_expression_call("hasAnyAuthority('ROLE_ADMIN')").unwrap();
        assert_eq!(name, "hasAnyAuthority");
        assert_eq!(args, vec!["ROLE_ADMIN"]);
    }
}
