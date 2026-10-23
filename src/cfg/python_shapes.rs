//! Python call shapes whose flat sink label does not apply at a given call
//! site.
//!
//! `make_response`, `HttpResponse` and `yaml.load` are static sinks, but
//! their idiomatic safe spellings are common enough to drown the real
//! findings: an autoescaped template or a JSON body in the response, and
//! `yaml.load(f, Loader=yaml.SafeLoader)`. Likewise `request.args.get(k,
//! type=int)` is a request accessor that returns a number. The label table
//! cannot see an argument, so the shape is recognised here from the call's AST
//! and the node gets a same-node `Sanitizer` for the sink's own cap (all caps,
//! for the accessor). That clears the taint finding and, because a node
//! dominates itself, the structural `cfg-unguarded-sink` one too, while the
//! unsafe spellings keep their label.

use super::{extract_const_keyword_arg, text_of};
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, classify_all};
use tree_sitter::Node;

/// Positional arguments of a Python call: every named child of the argument
/// list except keyword arguments and comments. `None` when a `*args` or
/// `**kwargs` splat is present, since positions are no longer reliable.
fn positional_args(call: Node) -> Option<Vec<Node>> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut out = Vec::new();
    for child in args.named_children(&mut cursor) {
        match child.kind() {
            "comment" | "keyword_argument" => {}
            "list_splat" | "dictionary_splat" => return None,
            _ => out.push(child),
        }
    }
    Some(out)
}

/// Value node of the keyword argument `name`.
fn keyword_arg_value<'a>(call: Node<'a>, name: &str, code: &[u8]) -> Option<Node<'a>> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.kind() != "keyword_argument" {
            continue;
        }
        let key = child
            .child_by_field_name("name")
            .and_then(|n| text_of(n, code))?;
        if key == name {
            return child.child_by_field_name("value");
        }
    }
    None
}

/// True when `call` is `yaml.load(stream, Loader=<safe loader>)`, with the
/// loader given by keyword or as the second positional argument. Only the
/// loaders that never construct arbitrary Python objects count: `FullLoader`,
/// `Loader`, `UnsafeLoader`, a missing loader and any computed loader are all
/// treated as unsafe.
pub(crate) fn yaml_loader_is_safe(call: Node, code: &[u8]) -> bool {
    let loader = keyword_arg_value(call, "Loader", code)
        .or_else(|| positional_args(call).and_then(|a| a.get(1).copied()));
    let Some(loader) = loader else {
        return false;
    };
    if !matches!(loader.kind(), "identifier" | "attribute") {
        return false;
    }
    let Some(text) = text_of(loader, code) else {
        return false;
    };
    matches!(
        text.rsplit('.').next().unwrap_or(""),
        "SafeLoader" | "CSafeLoader" | "BaseLoader" | "CBaseLoader"
    )
}

/// True when the source text of a string literal (`"application/json"`,
/// `b'text/plain; charset=utf-8'`) names a media type a browser does not
/// render as HTML.
pub(crate) fn response_content_type_is_non_html(raw: &str) -> bool {
    let body = raw.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let Some(value) = ["\"\"\"", "'''", "\"", "'"]
        .iter()
        .find_map(|q| body.strip_prefix(q)?.strip_suffix(q))
    else {
        return false;
    };
    let media = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        media.as_str(),
        "application/json" | "text/plain" | "text/csv" | "application/octet-stream"
    ) || (media.starts_with("application/")
        && media.ends_with("+json")
        && !media.contains(['{', '}']))
}

/// True when the body argument of a `make_response` / `HttpResponse` call
/// cannot carry markup: it is a `jsonify(..)` result or the output of an
/// HTML-escaping call (`render_template`, `render_to_string`,
/// `html.escape`), or the response declares a non-HTML content type.
fn response_body_is_safe(
    leaf: &str,
    call: Node,
    code: &[u8],
    extra: Option<&[RuntimeLabelRule]>,
) -> bool {
    if let Some(body) = positional_args(call).and_then(|a| a.first().copied()) {
        let mut body = body;
        while body.kind() == "parenthesized_expression"
            && let Some(inner) = body.named_child(0)
        {
            body = inner;
        }
        if body.kind() == "call"
            && let Some(callee) = body
                .child_by_field_name("function")
                .and_then(|f| text_of(f, code))
        {
            let callee: String = callee.chars().filter(|c| !c.is_whitespace()).collect();
            if callee.rsplit('.').next() == Some("jsonify") {
                return true;
            }
            if classify_all("python", &callee, extra)
                .iter()
                .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::HTML_ESCAPE)))
            {
                return true;
            }
        }
    }
    let content_type = ["content_type", "mimetype"]
        .iter()
        .find_map(|kw| extract_const_keyword_arg(call, kw, code))
        .or_else(|| {
            // Django's `HttpResponse(content, content_type)`.
            if leaf != "HttpResponse" {
                return None;
            }
            let second = positional_args(call)?.get(1).copied()?;
            (second.kind() == "string")
                .then(|| text_of(second, code))
                .flatten()
        });
    content_type.is_some_and(|ct| response_content_type_is_non_html(&ct))
}

/// The same-node sanitizer a Python call node should carry because its call
/// shape neutralises the sink it matched, or `None` to leave the labels as
/// they are.
///
/// `text` is the callee text the node was classified under and `call` the
/// call node it was read from; `labels` are the labels classification gave
/// the node.
pub(super) fn safe_shape_sanitizer(
    text: &str,
    call: Node,
    code: &[u8],
    extra: Option<&[RuntimeLabelRule]>,
    labels: &[DataLabel],
) -> Option<DataLabel> {
    let has_sink = |cap: Cap| {
        labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(cap)))
    };
    let has_sanitizer = |cap: Cap| {
        labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(cap)))
    };
    let html = has_sink(Cap::HTML_ESCAPE) && !has_sanitizer(Cap::HTML_ESCAPE);
    let deser = has_sink(Cap::DESERIALIZE) && !has_sanitizer(Cap::DESERIALIZE);
    let source = labels.iter().any(|l| matches!(l, DataLabel::Source(_)))
        && !labels.iter().any(|l| matches!(l, DataLabel::Sanitizer(_)));
    if !html && !deser && !source {
        return None;
    }
    // `text` can name an inner call the node was rebound to; the shape below
    // is only read off the call that `text` is the callee of.
    let written_leaf = text.rsplit('.').next().unwrap_or(text);
    let call_callee = call
        .child_by_field_name("function")
        .and_then(|f| text_of(f, code))?;
    let call_callee: String = call_callee.chars().filter(|c| !c.is_whitespace()).collect();
    if call_callee.rsplit('.').next() != Some(written_leaf) {
        return None;
    }
    if source && source_value_is_coerced(call, code) {
        return Some(DataLabel::Sanitizer(Cap::all()));
    }
    let qualified = crate::labels::python_import_qualified(text);
    let callee = qualified.as_deref().unwrap_or(text);
    let leaf = callee.rsplit('.').next().unwrap_or(callee);
    if html
        && matches!(leaf, "make_response" | "HttpResponse")
        && response_body_is_safe(leaf, call, code, extra)
    {
        return Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE));
    }
    if deser
        && (callee == "yaml.load" || callee.ends_with(".yaml.load"))
        && yaml_loader_is_safe(call, code)
    {
        return Some(DataLabel::Sanitizer(Cap::DESERIALIZE));
    }
    None
}

/// True for a request accessor that converts what it returns with a numeric
/// `type=`, as werkzeug's `MultiDict.get(key, default, type=int)` does
/// (`request.args.get("page", 1, type=int)`). The value is a number or the
/// literal default, the same as the result of `int(..)`.
fn source_value_is_coerced(call: Node, code: &[u8]) -> bool {
    keyword_arg_value(call, "type", code)
        .filter(|v| v.kind() == "identifier")
        .and_then(|v| text_of(v, code))
        .is_some_and(|t| matches!(t.as_str(), "int" | "float" | "bool"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    fn parse(src: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    /// The first `call` node in the source.
    fn first_call(tree: &Tree) -> Node<'_> {
        let mut stack = vec![tree.root_node()];
        while let Some(n) = stack.pop() {
            if n.kind() == "call" {
                return n;
            }
            let mut c = n.walk();
            let mut kids: Vec<_> = n.named_children(&mut c).collect();
            kids.reverse();
            stack.extend(kids);
        }
        panic!("no call in source");
    }

    fn yaml_safe(src: &str) -> bool {
        let tree = parse(src);
        yaml_loader_is_safe(first_call(&tree), src.as_bytes())
    }

    #[test]
    fn yaml_safe_loaders_by_keyword_and_position() {
        assert!(yaml_safe("yaml.load(f, Loader=yaml.SafeLoader)"));
        assert!(yaml_safe("yaml.load(f, Loader=SafeLoader)"));
        assert!(yaml_safe("yaml.load(f, Loader=yaml.CSafeLoader)"));
        assert!(yaml_safe("yaml.load(f, yaml.SafeLoader)"));
        assert!(yaml_safe("yaml.load(stream=f, Loader=yaml.BaseLoader)"));
    }

    #[test]
    fn yaml_unsafe_or_unknown_loaders_are_not_safe() {
        assert!(!yaml_safe("yaml.load(f)"));
        assert!(!yaml_safe("yaml.load(f, Loader=yaml.Loader)"));
        assert!(!yaml_safe("yaml.load(f, Loader=yaml.FullLoader)"));
        assert!(!yaml_safe("yaml.load(f, Loader=yaml.UnsafeLoader)"));
        assert!(!yaml_safe("yaml.load(f, Loader=getattr(yaml, name))"));
        assert!(!yaml_safe("yaml.load(f, Loader=loader_cls)"));
        assert!(!yaml_safe("yaml.load(*args)"));
    }

    #[test]
    fn non_html_content_types() {
        assert!(response_content_type_is_non_html("\"application/json\""));
        assert!(response_content_type_is_non_html(
            "'text/plain; charset=utf-8'"
        ));
        assert!(response_content_type_is_non_html("b\"text/csv\""));
        assert!(response_content_type_is_non_html(
            "\"application/vnd.api+json\""
        ));
        assert!(!response_content_type_is_non_html("\"text/html\""));
        assert!(!response_content_type_is_non_html(
            "\"text/html; charset=utf-8\""
        ));
        assert!(!response_content_type_is_non_html("\"image/svg+xml\""));
        assert!(!response_content_type_is_non_html(
            "\"application/xhtml+xml\""
        ));
        assert!(!response_content_type_is_non_html("content_type_var"));
        assert!(!response_content_type_is_non_html("\"\""));
    }

    fn body_safe(src: &str, leaf: &str) -> bool {
        let tree = parse(src);
        response_body_is_safe(leaf, first_call(&tree), src.as_bytes(), None)
    }

    #[test]
    fn response_body_shapes() {
        assert!(body_safe(
            "make_response(render_template('x.html', q=q))",
            "make_response"
        ));
        assert!(body_safe(
            "make_response(jsonify({'q': q}), 200)",
            "make_response"
        ));
        assert!(body_safe(
            "HttpResponse(render_to_string('x.html', {'q': q}))",
            "HttpResponse"
        ));
        assert!(body_safe(
            "HttpResponse(html.escape(q), status=200)",
            "HttpResponse"
        ));
        assert!(body_safe(
            "HttpResponse(json.dumps({'q': q}), content_type='application/json')",
            "HttpResponse"
        ));
        assert!(body_safe("HttpResponse(q, 'text/plain')", "HttpResponse"));
        // Not safe: default text/html, an explicit HTML type, a computed
        // type, a concatenation around an escape call, a plain value.
        assert!(!body_safe(
            "HttpResponse(json.dumps({'q': q}))",
            "HttpResponse"
        ));
        assert!(!body_safe(
            "HttpResponse(q, content_type='text/html')",
            "HttpResponse"
        ));
        assert!(!body_safe(
            "HttpResponse(q, content_type=ct)",
            "HttpResponse"
        ));
        assert!(!body_safe(
            "make_response('<p>' + html.escape(q) + tail)",
            "make_response"
        ));
        assert!(!body_safe("make_response(q)", "make_response"));
        assert!(!body_safe(
            "make_response(render_template_string(q))",
            "make_response"
        ));
        // Flask's `make_response` has no positional content type.
        assert!(!body_safe(
            "make_response(q, 'text/plain')",
            "make_response"
        ));
    }
}

#[cfg(test)]
mod cfg_tests {
    use crate::labels::{Cap, DataLabel};

    /// Labels of every CFG node whose callee ends in `leaf`, one entry per node.
    fn labels_of(src: &str, leaf: &str) -> Vec<Vec<DataLabel>> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        let mut out = Vec::new();
        for body in &file.bodies {
            for idx in body.graph.node_indices() {
                let node = &body.graph[idx];
                if node
                    .call
                    .callee
                    .as_deref()
                    .is_some_and(|c| c.rsplit('.').next() == Some(leaf))
                {
                    out.push(node.taint.labels.to_vec());
                }
            }
        }
        assert!(!out.is_empty(), "no `{leaf}` node in:\n{src}");
        out
    }

    fn sanitizes(labels: &[DataLabel], cap: Cap) -> bool {
        labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(cap)))
    }

    fn all_sanitize(src: &str, leaf: &str, cap: Cap) -> bool {
        labels_of(src, leaf).iter().all(|l| sanitizes(l, cap))
    }

    fn none_sanitize(src: &str, leaf: &str, cap: Cap) -> bool {
        labels_of(src, leaf).iter().all(|l| !sanitizes(l, cap))
    }

    #[test]
    fn response_sinks_with_safe_bodies_carry_a_sanitizer() {
        for src in [
            "def f(q):\n    return make_response(render_template('x.html', q=q))\n",
            "def f(q):\n    return make_response(jsonify({'q': q}), 200)\n",
            "def f(q):\n    return HttpResponse(json.dumps({'q': q}), content_type='application/json')\n",
            "def f(q):\n    return HttpResponse(render_to_string('x.html', {'q': q}))\n",
            "def f(q):\n    return HttpResponse(q, content_type='text/plain; charset=utf-8')\n",
            "def f(q):\n    return HttpResponse(html.escape(q), status=200)\n",
        ] {
            let leaf = if src.contains("make_response") {
                "make_response"
            } else {
                "HttpResponse"
            };
            assert!(all_sanitize(src, leaf, Cap::HTML_ESCAPE), "{src}");
        }
    }

    #[test]
    fn response_sinks_with_unsafe_bodies_keep_their_sink_alone() {
        for src in [
            "def f(q):\n    return HttpResponse(json.dumps({'q': q}))\n",
            "def f(q):\n    return HttpResponse(q, content_type='text/html')\n",
            "def f(q):\n    return HttpResponse(q, content_type=ct)\n",
            "def f(q):\n    return HttpResponse('<p>' + html.escape(q) + tail)\n",
        ] {
            assert!(
                none_sanitize(src, "HttpResponse", Cap::HTML_ESCAPE),
                "{src}"
            );
        }
        for src in [
            "def f(q):\n    return make_response('<h1>' + q + '</h1>')\n",
            "def f(q):\n    return make_response(render_template_string(q))\n",
        ] {
            assert!(
                none_sanitize(src, "make_response", Cap::HTML_ESCAPE),
                "{src}"
            );
        }
    }

    #[test]
    fn yaml_load_with_safe_loader_carries_a_sanitizer() {
        for src in [
            "def f(b):\n    return yaml.load(b, Loader=yaml.SafeLoader)\n",
            "def f(b):\n    return yaml.load(b, yaml.CSafeLoader)\n",
            "from yaml import load\ndef f(b):\n    return load(b, Loader=SafeLoader)\n",
        ] {
            assert!(all_sanitize(src, "load", Cap::DESERIALIZE), "{src}");
        }
        for src in [
            "def f(b):\n    return yaml.load(b)\n",
            "def f(b):\n    return yaml.load(b, Loader=yaml.Loader)\n",
            "def f(b):\n    return yaml.load(b, Loader=yaml.FullLoader)\n",
        ] {
            assert!(none_sanitize(src, "load", Cap::DESERIALIZE), "{src}");
        }
    }

    #[test]
    fn numeric_type_coerced_request_accessor_is_neutralised() {
        for src in [
            "def f():\n    page = request.args.get('page', 1, type=int)\n    return page\n",
            "def f():\n    p = request.args.get('p', type=float)\n    return p\n",
        ] {
            assert!(all_sanitize(src, "get", Cap::all()), "{src}");
        }
        for src in [
            "def f():\n    p = request.args.get('p', type=str)\n    return p\n",
            "def f():\n    p = request.args.get('p')\n    return p\n",
            "def f():\n    p = request.args.get('p', type=parse_page)\n    return p\n",
        ] {
            assert!(none_sanitize(src, "get", Cap::all()), "{src}");
        }
    }

    #[test]
    fn from_imported_callees_carry_the_qualified_labels() {
        let src = "from subprocess import check_output\nfrom html import escape\n\
                   def f(d):\n    safe = escape(d)\n    return check_output(safe, shell=True)\n";
        assert!(
            labels_of(src, "check_output")
                .iter()
                .all(|l| l.contains(&DataLabel::Sink(Cap::SHELL_ESCAPE)))
        );
        assert!(all_sanitize(src, "escape", Cap::HTML_ESCAPE));
        // The same name without an import binding classifies as nothing.
        let unbound = "def f(d):\n    return check_output(d, shell=True)\n";
        assert!(
            labels_of(unbound, "check_output")
                .iter()
                .all(|l| !l.contains(&DataLabel::Sink(Cap::SHELL_ESCAPE)))
        );
    }

    #[test]
    fn chained_sql_execute_is_rebound_to_the_execute_call() {
        let src = "def f(conn, uid):\n    rows = conn.execute('SELECT * FROM t WHERE id = ?', (uid,)).fetchall()\n    return rows\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        let node = file.bodies[1]
            .graph
            .node_indices()
            .map(|i| &file.bodies[1].graph[i])
            .find(|n| n.call.callee.as_deref() == Some("conn.execute"))
            .expect("the sink node is named after the execute call, not the whole chain");
        assert_eq!(node.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
        assert!(node.parameterized_query);
        assert!(node.call.outer_callee.is_some());
    }

    #[test]
    fn inline_source_beside_a_keyword_argument_binds_to_its_position() {
        let src = "def f():\n    return check_output('ls ' + request.args.get('d'), shell=True)\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        let body = &file.bodies[1];
        let has_synth_source = body.graph.node_indices().any(|i| {
            let n = &body.graph[i];
            n.taint
                .defines
                .as_deref()
                .is_some_and(|d| d.starts_with("__nyx_src_"))
                && n.taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, DataLabel::Source(_)))
        });
        assert!(has_synth_source);
    }
}
