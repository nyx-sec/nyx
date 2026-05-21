//! Shared Java-route adapter helpers (Phase 14 — Track L.12).
//!
//! The Spring / Quarkus / Micronaut / Servlet adapters all share the
//! same handful of tree-sitter helpers: locate a `class_declaration`
//! containing a `method_declaration` whose name matches the target,
//! walk the class- and method-level annotation lists, pull a string
//! argument from an annotation, classify the path placeholders, and
//! bind formals to request slots.  Centralising the helpers keeps the
//! four adapters terse and makes the placeholder-binding semantics
//! identical across frameworks.

use crate::dynamic::framework::{HttpMethod, ParamBinding, ParamSource};
use tree_sitter::Node;

/// True when `bytes` carries any of the well-known Spring import
/// stanzas or the bare `@RestController` / `@RequestMapping` /
/// `@GetMapping` / `@PostMapping` annotations (the synthetic-import
/// fixture path used by the Phase 14 corpus).
pub fn source_imports_spring(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"org.springframework",
            b"@RestController",
            b"@Controller(",
            b"@Controller\n",
            b"@Controller\r",
            b"@RequestMapping",
            b"@GetMapping",
            b"@PostMapping",
            b"@PutMapping",
            b"@PatchMapping",
            b"@DeleteMapping",
        ],
    )
}

/// True when `bytes` carries a Quarkus or JAX-RS / Jakarta REST
/// stanza.  Distinct from `source_imports_spring` so the Spring
/// adapter does not collide on a Quarkus file that happens to use
/// the bare `@Path` annotation.
pub fn source_imports_quarkus(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"io.quarkus",
            b"jakarta.ws.rs",
            b"javax.ws.rs",
            b"@QuarkusTest",
            b"@Path(",
        ],
    )
}

/// True when `bytes` carries a Micronaut import stanza.  Micronaut
/// reuses `@Controller` as a class-level marker but pairs it with
/// `@Get` / `@Post` / `@Put` / `@Delete` (mixed-case, distinct from
/// the all-caps JAX-RS verb annotations Quarkus picks up).
pub fn source_imports_micronaut(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"io.micronaut",
            b"@MicronautTest",
            b"micronaut.http.annotation",
        ],
    )
}

/// True when `bytes` carries any of the well-known Java Servlet API
/// import stanzas or a class extending `HttpServlet`.  The bare
/// `HttpServletRequest` / `HttpServletResponse` stub-class names also
/// fire so the Phase 14 default-package fixture path lights up the
/// adapter without a Jakarta servlet jar.
pub fn source_imports_servlet(bytes: &[u8]) -> bool {
    contains_any(
        bytes,
        &[
            b"javax.servlet",
            b"jakarta.servlet",
            b"HttpServletRequest",
            b"HttpServletResponse",
            b"extends HttpServlet",
        ],
    )
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| haystack.windows(n.len()).any(|w| w == *n))
}

/// Locate the (class_decl, method_decl) pair whose method's name
/// equals `target`.  Returns the outermost matching class so the
/// caller can read class-level annotations (route prefix, auth
/// markers) without re-walking.
pub fn find_class_with_method<'a>(
    root: Node<'a>,
    bytes: &[u8],
    target: &str,
) -> Option<(Node<'a>, Node<'a>)> {
    let mut hit: Option<(Node<'a>, Node<'a>)> = None;
    walk(root, bytes, target, &mut hit);
    hit
}

fn walk<'a>(
    node: Node<'a>,
    bytes: &[u8],
    target: &str,
    out: &mut Option<(Node<'a>, Node<'a>)>,
) {
    if out.is_some() {
        return;
    }
    if node.kind() == "class_declaration"
        && let Some(body) = node
            .child_by_field_name("body")
            .or_else(|| named_child_of_kind(node, "class_body"))
        {
            let mut cur = body.walk();
            for member in body.children(&mut cur) {
                if member.kind() != "method_declaration" {
                    continue;
                }
                if let Some(name) = member
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    && name == target {
                        *out = Some((node, member));
                        return;
                    }
            }
        }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk(child, bytes, target, out);
    }
}

fn named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cur = node.walk();
    node.named_children(&mut cur).find(|c| c.kind() == kind)
}

/// True when `node` is a `marker_annotation` (`@GET`) or `annotation`
/// (`@Path("/x")`).
pub fn is_annotation(node: Node<'_>) -> bool {
    matches!(node.kind(), "annotation" | "marker_annotation")
}

/// Read the leaf annotation name (`@a.b.GetMapping` → `"GetMapping"`).
pub fn annotation_leaf<'a>(ann: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    let name = ann.child_by_field_name("name")?.utf8_text(bytes).ok()?;
    Some(name.rsplit('.').next().unwrap_or(name))
}

/// Extract the first quoted string argument from an annotation node,
/// supporting both positional (`@Path("/x")`) and `value="…"` /
/// `path="…"` keyword forms.
pub fn annotation_string_arg(ann: Node<'_>, bytes: &[u8]) -> Option<String> {
    let args = ann.child_by_field_name("arguments")?;
    let raw = args.utf8_text(bytes).ok()?;
    // Try `value = "…"` / `path = "…"` first so the keyword form is
    // not accidentally captured by the bare-string scan.
    for key in ["value", "path"] {
        if let Some(start) = raw.find(&format!("{key} = ")).or_else(|| raw.find(&format!("{key}="))) {
            let after = &raw[start..];
            if let Some(open) = after.find('"') {
                let rest = &after[open + 1..];
                if let Some(close) = rest.find('"') {
                    return Some(rest[..close].to_owned());
                }
            }
        }
    }
    let open = raw.find('"')? + 1;
    let close = raw[open..].find('"')? + open;
    Some(raw[open..close].to_owned())
}

/// Iterate annotations attached to a `class_declaration` or
/// `method_declaration` node via its `modifiers` child.
pub fn iter_annotations<'a, F>(node: Node<'a>, bytes: &'a [u8], mut visit: F)
where
    F: FnMut(Node<'a>, &str),
{
    let Some(modifiers) = named_child_of_kind(node, "modifiers") else {
        return;
    };
    let mut cur = modifiers.walk();
    for ann in modifiers.children(&mut cur) {
        if !is_annotation(ann) {
            continue;
        }
        if let Some(name) = annotation_leaf(ann, bytes) {
            visit(ann, name);
        }
    }
}

/// True when the class declaration extends a class whose simple name
/// matches `target`.  The match strips package qualifiers so
/// `jakarta.servlet.http.HttpServlet` and bare `HttpServlet` both
/// trip the predicate.
pub fn class_extends(class: Node<'_>, bytes: &[u8], target: &str) -> bool {
    let Some(superclass) = class.child_by_field_name("superclass") else {
        return false;
    };
    let Ok(text) = superclass.utf8_text(bytes) else {
        return false;
    };
    let cleaned = text.trim().trim_start_matches("extends ").trim();
    let leaf = cleaned.rsplit('.').next().unwrap_or(cleaned);
    leaf.split_whitespace()
        .next()
        .unwrap_or(leaf)
        .trim_end_matches('<')
        == target
}

/// Parse `method = RequestMethod.<VERB>` (or array form) from a
/// `@RequestMapping(...)` annotation's raw arguments text.
pub fn request_method_from_args(ann: Node<'_>, bytes: &[u8]) -> Option<HttpMethod> {
    let args = ann.child_by_field_name("arguments")?;
    let raw = args.utf8_text(bytes).ok()?;
    for verb in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        if raw.contains(&format!("RequestMethod.{verb}")) {
            return HttpMethod::from_ident(verb);
        }
    }
    None
}

/// Extract `(type_simple_name, formal_name)` pairs from a
/// `method_declaration` node.  The simple type lets adapters
/// recognise framework-implicit slots (`HttpServletRequest` /
/// `HttpServletResponse`) and route the remaining formals to query /
/// body params.
pub fn method_formal_types(method: Node<'_>, bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(params) = method.child_by_field_name("parameters") else {
        return out;
    };
    let mut cur = params.walk();
    for fp in params.named_children(&mut cur) {
        if fp.kind() != "formal_parameter" && fp.kind() != "spread_parameter" {
            continue;
        }
        let ty = fp
            .child_by_field_name("type")
            .and_then(|t| t.utf8_text(bytes).ok())
            .unwrap_or("")
            .trim();
        let name = fp
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(bytes).ok())
            .unwrap_or("")
            .trim();
        if name.is_empty() {
            continue;
        }
        let ty_leaf = ty.rsplit('.').next().unwrap_or(ty);
        let ty_simple = ty_leaf
            .split('<')
            .next()
            .unwrap_or(ty_leaf)
            .trim()
            .to_owned();
        out.push((ty_simple, name.to_owned()));
    }
    out
}

/// Extract placeholder names from a route path template.
///
/// Supports two placeholder syntaxes:
///   - JAX-RS / Spring / Micronaut: `/users/{id}` → `id`,
///     `/users/{id:[0-9]+}` → `id`.
///   - Servlet-mapping `*` wildcards: ignored (no name to bind).
pub fn extract_path_placeholders(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}') {
                let inner = &path[i + 1..i + 1 + end];
                let name = inner.split(':').next().unwrap_or(inner).trim();
                if !name.is_empty() && !out.iter().any(|n| n == name) {
                    out.push(name.to_owned());
                }
                i += end + 2;
                continue;
            }
        i += 1;
    }
    out
}

/// Bind formals to request slots given a route path template.
///
/// `HttpServletRequest` / `HttpServletResponse` / `ServletRequest` /
/// `ServletResponse` / `HttpRequest` / `HttpResponse` go to
/// [`ParamSource::Implicit`].  A formal whose name matches a
/// placeholder becomes a [`ParamSource::PathSegment`]; everything
/// else falls back to [`ParamSource::QueryParam`].
pub fn bind_java_params(formals: &[(String, String)], path: &str) -> Vec<ParamBinding> {
    let placeholders = extract_path_placeholders(path);
    formals
        .iter()
        .enumerate()
        .map(|(idx, (ty, name))| {
            let source = if is_implicit_type(ty) {
                ParamSource::Implicit
            } else if placeholders.iter().any(|p| p == name) {
                ParamSource::PathSegment(name.clone())
            } else {
                ParamSource::QueryParam(name.clone())
            };
            ParamBinding {
                index: idx,
                name: name.clone(),
                source,
            }
        })
        .collect()
}

fn is_implicit_type(ty: &str) -> bool {
    matches!(
        ty,
        "HttpServletRequest"
            | "HttpServletResponse"
            | "ServletRequest"
            | "ServletResponse"
            | "HttpRequest"
            | "HttpResponse"
            | "MultiValueMap"
            | "Model"
    )
}

/// Concatenate a class-level path prefix and a method-level path
/// suffix.  Strips a trailing slash from the prefix and a leading
/// slash from the suffix to avoid `/api//x`-style joins.
pub fn join_route_path(class_path: &str, method_path: &str) -> String {
    if class_path.is_empty() {
        return method_path.to_owned();
    }
    if method_path.is_empty() {
        return class_path.to_owned();
    }
    format!(
        "{}/{}",
        class_path.trim_end_matches('/'),
        method_path.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter::Language::from(tree_sitter_java::LANGUAGE);
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn finds_class_and_method() {
        let src: &[u8] = b"public class V { public String run(String x) { return x; } }\n";
        let tree = parse(src);
        let (class, method) = find_class_with_method(tree.root_node(), src, "run").unwrap();
        assert_eq!(class.kind(), "class_declaration");
        assert_eq!(method.kind(), "method_declaration");
    }

    #[test]
    fn extracts_brace_placeholders() {
        assert_eq!(extract_path_placeholders("/users/{id}"), vec!["id"]);
        assert_eq!(
            extract_path_placeholders("/u/{id}/posts/{slug}"),
            vec!["id", "slug"]
        );
        assert_eq!(extract_path_placeholders("/u/{id:[0-9]+}"), vec!["id"]);
    }

    #[test]
    fn join_drops_double_slash() {
        assert_eq!(join_route_path("/api", "/x"), "/api/x");
        assert_eq!(join_route_path("/api/", "/x"), "/api/x");
        assert_eq!(join_route_path("", "/x"), "/x");
        assert_eq!(join_route_path("/api", ""), "/api");
    }

    #[test]
    fn bind_servlet_request_as_implicit() {
        let formals = vec![
            ("HttpServletRequest".to_owned(), "req".to_owned()),
            ("HttpServletResponse".to_owned(), "resp".to_owned()),
        ];
        let bound = bind_java_params(&formals, "/x");
        assert!(matches!(bound[0].source, ParamSource::Implicit));
        assert!(matches!(bound[1].source, ParamSource::Implicit));
    }

    #[test]
    fn class_extends_detects_servlet() {
        let src: &[u8] =
            b"public class V extends HttpServlet { public void doGet() {} }\n";
        let tree = parse(src);
        let (class, _) = find_class_with_method(tree.root_node(), src, "doGet").unwrap();
        assert!(class_extends(class, src, "HttpServlet"));
        assert!(!class_extends(class, src, "Object"));
    }

    #[test]
    fn annotation_string_arg_pulls_first_literal() {
        let src: &[u8] =
            b"public class V { @GetMapping(\"/users/{id}\") public String run(String id) { return id; } }\n";
        let tree = parse(src);
        let (_, method) = find_class_with_method(tree.root_node(), src, "run").unwrap();
        let mut path: Option<String> = None;
        iter_annotations(method, src, |ann, name| {
            if name == "GetMapping" {
                path = annotation_string_arg(ann, src);
            }
        });
        assert_eq!(path.as_deref(), Some("/users/{id}"));
    }

    #[test]
    fn method_formal_types_strips_qualifiers() {
        let src: &[u8] =
            b"public class V { public String run(java.lang.String x, int y) { return x; } }\n";
        let tree = parse(src);
        let (_, method) = find_class_with_method(tree.root_node(), src, "run").unwrap();
        let formals = method_formal_types(method, src);
        assert_eq!(
            formals,
            vec![
                ("String".to_owned(), "x".to_owned()),
                ("int".to_owned(), "y".to_owned()),
            ]
        );
    }
}
