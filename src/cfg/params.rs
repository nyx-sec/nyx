use super::{
    AstMeta, Cfg, DTO_CLASSES, EdgeKind, NodeInfo, PYTHON_NORETURN_IMPORTS, StmtKind, TaintMeta,
    collect_idents, connect_all, is_anon_fn_name, node_str, text_of,
};
use crate::cfg::fast_kind::FastKind;
use crate::labels::{DataLabel, LangAnalysisRules, classify, param_config};
use crate::ssa::type_facts::TypeKind;
use petgraph::graph::NodeIndex;
use smallvec::{SmallVec, smallvec};
use tree_sitter::Node;

/// resolve a syntactic class / struct / interface / model
/// name against the per-file [`DTO_CLASSES`] map populated at the top
/// of `build_cfg`.  Returns the [`TypeKind::Dto`] carrying the
/// per-field type map when the class is declared in the same file;
/// returns `None` otherwise so callers can fall through to the
/// generic Object / Unknown classification.
fn lookup_dto_class(class_name: &str) -> Option<TypeKind> {
    DTO_CLASSES.with(|cell| cell.borrow().get(class_name).cloned().map(TypeKind::Dto))
}

/// Descend a C / C++ `function_definition` declarator chain to the
/// `function_declarator` that owns the parameter list and the name.  Pointer
/// returns (`char *f(char *x)`, `FILE *f(...)`), parenthesized and attributed
/// declarators wrap it in extra layers.  Returns `None` for other shapes.
pub(super) fn c_function_declarator(func_node: Node<'_>) -> Option<Node<'_>> {
    let mut d = func_node.child_by_field_name("declarator")?;
    for _ in 0..16 {
        match d.fkind() {
            // The declarator that names the function holds its parameters.  A
            // function returning a function pointer
            // (`void *(*pick(int sel))(void)`) nests another one inside a
            // parenthesized declarator; the inner one is the definition's own.
            "function_declarator" => match d.child_by_field_name("declarator") {
                Some(inner) if inner.fkind() == "parenthesized_declarator" => d = inner,
                _ => return Some(d),
            },
            "pointer_declarator"
            | "reference_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator"
            | "array_declarator" => {
                d = d.child_by_field_name("declarator").or_else(|| {
                    let mut c = d.walk();
                    d.named_children(&mut c)
                        .find(|n| n.fkind().ends_with("declarator"))
                })?;
            }
            _ => return None,
        }
    }
    None
}

/// Extract parameter names + per-position [`TypeKind`] from a function
/// AST node.  Each entry's second slot is `Some(TypeKind)` when the
/// parameter's decorator, attribute, or static type annotation maps to
/// a known kind, and `None` otherwise.  The third slot lists
/// destructured field names bound by the same parameter slot — empty
/// for non-destructured params and for the primary name itself.  E.g.
/// for the JS/TS object-pattern formal `({ a, b, c })`, the entry is
/// `("a", None, ["b", "c"])`.  Strictly additive: when the param is
/// not a destructured pattern (or the language has no destructure
/// concept), behaviour is identical to the names-only path.
///
/// Closes the residual gap behind CVE-2026-25544 (PayloadCMS Drizzle
/// SQL injection): a per-parameter taint probe that seeds only the
/// primary name `column` cannot see flow through sibling destructured
/// bindings (`value` etc.) inside the body, so summary extraction
/// misses `validated_params_to_return` when a validator helper is
/// applied to one of the siblings.
pub(super) fn extract_param_meta<'a>(
    func_node: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Vec<(String, Option<TypeKind>, Vec<String>)> {
    let cfg = param_config(lang);
    let mut out: Vec<(String, Option<TypeKind>, Vec<String>)> = Vec::new();
    // A FastAPI route binds its plain annotated formals from the request, so
    // the Python classifier needs to know whether it is looking at one.
    let in_fastapi_route = matches!(lang, "python" | "py")
        && func_node.fkind() == "function_definition"
        && crate::entry_points::python_is_fastapi_route(func_node, code);
    let classify = |param: Node<'a>| {
        if matches!(lang, "python" | "py") {
            classify_param_type_python(param, code, in_fastapi_route)
        } else {
            classify_param_type(param, lang, code)
        }
    };
    // Try the params_field directly on the function node first.
    // For C/C++ the parameter list lives inside the declarator chain
    // (function_definition > declarator: [pointer_declarator >]* function_declarator
    // > parameters), so descend it with the shared helper.
    let params = func_node.child_by_field_name(cfg.params_field).or_else(|| {
        c_function_declarator(func_node).and_then(|d| d.child_by_field_name(cfg.params_field))
    });
    let Some(params) = params else {
        // Single-param arrow shorthand (`uri => ...` in JS/TS): tree-sitter
        // exposes the lone identifier under the singular `parameter` field
        // rather than wrapping it in `formal_parameters`. Without this
        // fallback the function appears parameterless to the SSA pipeline,
        // breaking cross-function param_to_sink resolution for any
        // single-arg arrow helper. Motivated by CVE-2025-64430.
        if func_node.fkind() == "arrow_function" {
            if let Some(p) = func_node.child_by_field_name("parameter") {
                if p.fkind() == "identifier" {
                    if let Some(name) = text_of(p, code) {
                        out.push((name, None, Vec::new()));
                    }
                }
            }
        }
        return out;
    };
    // Java lambda shorthand: tree-sitter-java exposes the `parameters` field
    // on `lambda_expression` as either a single bare identifier (`cmd -> …`)
    // or an `inferred_parameters` wrapper around identifiers (`(a, b) -> …`).
    // Neither shape matches the formal_parameter / spread_parameter kinds in
    // PARAM_CONFIG, so the per-child loop below would otherwise see no
    // params and the lambda would appear parameterless.  Without this, the
    // SSA pipeline treats the lambda binding as a free / closure-captured
    // variable, defeating the JS/TS / Java auto-seed distinction between
    // real handler-param formals and bubbled-up captures.  Mirrors the JS/TS
    // arrow shorthand handled above.
    if func_node.fkind() == "lambda_expression" {
        if params.fkind() == "identifier" {
            if let Some(name) = text_of(params, code) {
                out.push((name, None, Vec::new()));
                return out;
            }
        } else if params.fkind() == "inferred_parameters" {
            let mut cursor = params.walk();
            for child in params.named_children(&mut cursor) {
                if child.fkind() == "identifier" {
                    if let Some(name) = text_of(child, code) {
                        out.push((name, None, Vec::new()));
                    }
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        // Self/this parameter (e.g. Rust's `self_parameter`)
        if cfg.self_param_kinds.contains(&child.fkind()) {
            out.push(("self".into(), None, Vec::new()));
            continue;
        }

        // Regular parameter
        if cfg.param_node_kinds.contains(&child.fkind()) {
            // Try each ident field in order
            let mut found = false;
            for &field in cfg.ident_fields {
                if let Some(node) = child.child_by_field_name(field) {
                    let mut tmp = Vec::new();
                    collect_idents(node, code, &mut tmp);
                    let primary = if lang == "rust" {
                        // Rust: last ident is the binding name (e.g.
                        // `Path(project_id): Path<i64>` → `project_id`).
                        tmp.pop()
                    } else if tmp.is_empty() {
                        None
                    } else {
                        Some(tmp.remove(0))
                    };
                    if let Some(name) = primary {
                        let ty = classify(child);
                        // Surface destructured siblings only when the
                        // pattern node is a destructure container.  For
                        // ordinary (non-destructured) params, `tmp` is
                        // already empty after `pop()` / `remove(0)`.
                        // Object-pattern children of the same slot
                        // (`{ a, b, c }`) leave the remaining names in
                        // `tmp`, which become the slot's siblings.
                        let siblings = sibling_names_for_destructure(node, &tmp, lang);
                        out.push((name, ty, siblings));
                        found = true;
                        break;
                    }
                }
            }
            // Fallback: if the param node itself is an identifier (e.g. JS/Python)
            if !found
                && child.fkind() == "identifier"
                && let Some(txt) = text_of(child, code)
            {
                out.push((txt, None, Vec::new()));
                found = true;
            }
            // Fallback for C/C++: look for nested declarator → identifier
            if !found && child.fkind() == "parameter_declaration" {
                let mut tmp = Vec::new();
                collect_idents(child, code, &mut tmp);
                if let Some(last) = tmp.pop() {
                    let ty = classify(child);
                    out.push((last, ty, Vec::new()));
                    found = true;
                }
            }
            // Generic fallback for typed/default parameter wrappers (e.g.
            // Python `typed_parameter`, `default_parameter`,
            // `typed_default_parameter`): the wrapper node has no `name`
            // field but contains the identifier as a child.  Pick the
            // *first* identifier, that is the parameter name; subsequent
            // identifiers are part of the type annotation or default
            // expression.
            //
            // Destructure-container case (JS arrow `({ a, b }) => …`):
            // when the child node IS a destructure pattern itself (no
            // `required_parameter` / `assignment_pattern` wrapper), the
            // remaining idents after the primary are destructured
            // bindings sharing this slot — surface them as siblings so
            // per-parameter summary probing seeds every binding the
            // slot produces.
            if !found {
                let mut tmp = Vec::new();
                collect_idents(child, code, &mut tmp);
                if !tmp.is_empty() {
                    let first = tmp.remove(0);
                    let ty = classify(child);
                    let siblings = sibling_names_for_destructure(child, &tmp, lang);
                    out.push((first, ty, siblings));
                }
            }
            continue;
        }

        // Bare identifier children, e.g. Rust untyped closure params `|cmd|`
        // where the child is an `identifier` node, not a `parameter` wrapper.
        if child.fkind() == "identifier" {
            if let Some(txt) = text_of(child, code) {
                out.push((txt, None, Vec::new()));
            }
        }
    }
    out
}

/// Return destructured field-name siblings for a parameter's pattern
/// node, but only when the pattern is a recognised destructure
/// container (object / record pattern).  For ordinary patterns the
/// `remaining` slice is already empty so this is a noop.  Restricting
/// the return to destructure containers prevents typed-parameter
/// idioms (`Path<i64>`, `@PathVariable Long userId`, Rust extractor
/// wrappers) from accidentally surfacing the type identifier as a
/// destructured sibling.
fn sibling_names_for_destructure(
    pattern: Node<'_>,
    remaining: &[String],
    lang: &str,
) -> Vec<String> {
    if remaining.is_empty() {
        return Vec::new();
    }
    if !is_destructure_container_kind(pattern.fkind(), lang) {
        return Vec::new();
    }
    remaining.to_vec()
}

/// Recognise tree-sitter pattern node kinds that destructure a
/// single argument into multiple bindings — JS/TS object patterns
/// today, plus Python's `pattern_list` / `tuple_pattern` for kwargs
/// destructure if those ever come through this path.  Conservative:
/// only kinds we have explicit per-language reasoning for return
/// `true`; everything else returns `false` so the existing single-
/// name fallback path is preserved untouched.
fn is_destructure_container_kind(kind: &str, lang: &str) -> bool {
    match (lang, kind) {
        ("javascript" | "typescript", "object_pattern") => true,
        // Future languages: array pattern (`[a, b]`) is intentionally
        // omitted — the index-based unpacking is positional, and the
        // names don't map cleanly to "all share slot 0".
        _ => false,
    }
}

/// Walk up from a function definition node and build a container path.
///
/// Records the names of enclosing classes / impls / modules / namespaces /
/// structs, and, for anonymous / nested functions, the name of an enclosing
/// named function, joined with `::`.  Also returns a `FuncKind` guess
/// reflecting the structural role.
///
/// Returns `(container, kind)`.
pub(super) fn compute_container_and_kind(
    func_node: Node<'_>,
    ast_kind: &str,
    fn_name: &str,
    code: &[u8],
) -> (String, crate::symbol::FuncKind) {
    use crate::symbol::FuncKind;

    // Lambda / arrow / anonymous function ⇒ Closure regardless of context.
    let mut kind = if ast_kind == "lambda_expression"
        || ast_kind == "arrow_function"
        || ast_kind == "function_expression"
        || ast_kind == "anonymous_function"
        || ast_kind == "closure_expression"
        || is_anon_fn_name(fn_name)
    {
        FuncKind::Closure
    } else {
        FuncKind::Function
    };

    let mut segments: Vec<String> = Vec::new();
    let mut inside_class = false;
    let mut cursor = func_node.parent();

    while let Some(parent) = cursor {
        let pk = parent.fkind();

        // Class / struct / impl / interface / namespace / module containers.
        let container_name_field: Option<&str> = match pk {
            // JS / TS / Python / Ruby / PHP / Java / Kotlin / C++ classes
            "class_declaration"
            | "class_definition"
            | "class_specifier"
            | "class"
            | "interface_declaration"
            | "interface_body"
            | "enum_declaration"
            | "trait_item"
            | "trait_declaration"
            | "enum_item"
            | "struct_specifier"
            | "struct_item" => Some("name"),
            // Rust impl blocks, pick the type name, not the trait name.
            "impl_item" => Some("type"),
            // Go / C++ / PHP namespaces and modules.
            "namespace_definition" | "namespace_declaration" | "module_declaration" | "module" => {
                Some("name")
            }
            _ => None,
        };

        if let Some(field) = container_name_field {
            if let Some(name_node) = parent.child_by_field_name(field) {
                if let Some(text) = text_of(name_node, code) {
                    segments.push(text);
                    inside_class |= matches!(
                        pk,
                        "class_declaration"
                            | "class_definition"
                            | "class_specifier"
                            | "class"
                            | "interface_declaration"
                            | "interface_body"
                            | "trait_item"
                            | "trait_declaration"
                            | "impl_item"
                            | "struct_item"
                            | "struct_specifier"
                    );
                }
            }
        } else if pk == "function_declaration"
            || pk == "function_definition"
            || pk == "method_declaration"
            || pk == "method_definition"
            || pk == "function_item"
            || pk == "arrow_function"
            || pk == "lambda_expression"
            || pk == "function_expression"
        {
            // Nested definition, record the outer function's name and
            // classify self as Closure even if we got a real name.
            if let Some(name_node) = parent.child_by_field_name("name") {
                if let Some(text) = text_of(name_node, code) {
                    segments.push(text);
                }
            }
            if !matches!(kind, FuncKind::Closure) {
                kind = FuncKind::Closure;
            }
        }

        cursor = parent.parent();
    }

    // Upgrade to Method/Constructor when inside a class-like container.
    if inside_class && matches!(kind, FuncKind::Function) {
        kind = if fn_name == "__init__"
            || fn_name == "constructor"
            || fn_name == "initialize"
            || fn_name == "new"
        {
            FuncKind::Constructor
        } else {
            FuncKind::Method
        };
    }

    segments.reverse();
    let container = segments.join("::");
    (container, kind)
}

pub(super) fn rust_param_binding_name(param_text: &str) -> Option<String> {
    let before_colon = param_text.split(':').next().unwrap_or(param_text).trim();
    let tokens: Vec<&str> = before_colon
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty() && !matches!(*token, "mut" | "ref"))
        .collect();
    tokens.last().map(|token| (*token).to_string())
}

pub(super) fn rust_param_type_text(param: Node<'_>, code: &[u8]) -> Option<String> {
    param
        .child_by_field_name("type")
        .and_then(|node| text_of(node, code))
        .or_else(|| {
            text_of(param, code).and_then(|text| {
                text.split_once(':')
                    .map(|(_, ty)| ty.trim().to_string())
                    .filter(|ty| !ty.is_empty())
            })
        })
}

pub(super) fn rust_route_attribute_bindings(func_node: Node<'_>, code: &[u8]) -> Vec<String> {
    let Some(text) = text_of(func_node, code) else {
        return Vec::new();
    };
    let mut bindings = Vec::new();

    for line in text
        .lines()
        .map(str::trim)
        .take_while(|line| line.starts_with("#["))
    {
        if !(line.starts_with("#[get")
            || line.starts_with("#[post")
            || line.starts_with("#[put")
            || line.starts_with("#[delete")
            || line.starts_with("#[patch"))
        {
            continue;
        }

        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '<' {
                let mut token = String::new();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next == '>' {
                        break;
                    }
                    token.push(next);
                }
                let token = token.trim();
                if !token.is_empty() {
                    bindings.push(token.to_string());
                }
            }
        }
    }

    bindings
}

pub(super) fn rust_framework_param_sources<'a>(
    func_node: Node<'a>,
    code: &'a [u8],
    analysis_rules: Option<&crate::labels::LangAnalysisRules>,
) -> Vec<(String, crate::labels::Cap, (usize, usize))> {
    let Some(analysis_rules) = analysis_rules else {
        return Vec::new();
    };
    let extra = analysis_rules.extra_labels.as_slice();
    if extra.is_empty() {
        return Vec::new();
    }

    let cfg = param_config("rust");
    let params = func_node.child_by_field_name(cfg.params_field);
    let Some(params) = params else {
        return Vec::new();
    };

    let rocket_route_bindings = if analysis_rules
        .frameworks
        .contains(&crate::utils::project::DetectedFramework::Rocket)
    {
        rust_route_attribute_bindings(func_node, code)
    } else {
        Vec::new()
    };

    let mut sources = Vec::new();
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if cfg.self_param_kinds.contains(&child.fkind()) || child.fkind() != "parameter" {
            continue;
        }

        let Some(param_text) = text_of(child, code) else {
            continue;
        };
        let Some(binding) = rust_param_binding_name(&param_text) else {
            continue;
        };
        let span = (child.start_byte(), child.end_byte());

        let type_caps = rust_param_type_text(child, code).and_then(|type_text| {
            match classify("rust", &type_text, Some(extra)) {
                Some(DataLabel::Source(caps)) => Some(caps),
                _ => None,
            }
        });
        let route_caps = rocket_route_bindings
            .iter()
            .any(|name| name == &binding)
            .then_some(crate::labels::Cap::all());

        let Some(caps) = type_caps.or(route_caps) else {
            continue;
        };
        if !sources
            .iter()
            .any(|(name, _, existing_span)| name == &binding && existing_span == &span)
        {
            sources.push((binding, caps, span));
        }
    }

    sources
}

pub(super) fn inject_framework_param_sources(
    func_node: Node<'_>,
    code: &[u8],
    analysis_rules: Option<&crate::labels::LangAnalysisRules>,
    graph: &mut Cfg,
    entry: NodeIndex,
    enclosing_func: Option<&str>,
) -> Vec<NodeIndex> {
    let sources = rust_framework_param_sources(func_node, code, analysis_rules);
    if sources.is_empty() {
        return vec![entry];
    }

    let mut preds = vec![entry];
    for (binding, caps, span) in sources {
        let idx = graph.add_node(NodeInfo {
            kind: StmtKind::Seq,
            taint: TaintMeta {
                labels: smallvec![DataLabel::Source(caps)],
                defines: Some(binding),
                ..Default::default()
            },
            ast: AstMeta {
                span,
                enclosing_func: enclosing_func.map(|s| s.to_string()),
            },
            ..Default::default()
        });
        connect_all(graph, &preds, idx, EdgeKind::Seq);
        preds = vec![idx];
    }

    preds
}

/// Classify a parameter AST node to a [`TypeKind`] using per-language
/// decorator / attribute / annotation matchers.  Strictly additive: when
/// no recognised pattern matches, returns `None` and the engine
/// behaves exactly as before.
///
/// Recognised patterns:
/// * Java (Spring), `@PathVariable`/`@RequestParam Long X` →
///   [`TypeKind::Int`]; `@RequestBody T` → object (no kind today).
/// * TypeScript (NestJS), `@Param('id') id: number` →
///   [`TypeKind::Int`]; `@Body() dto: T` / `@Query('q') q: string`.
/// * Rust (Axum / Rocket / Actix), `Path<i64>` / `Path<u32>` /
///   `web::Path<i64>` → [`TypeKind::Int`]; `Path<String>` →
///   [`TypeKind::String`].
/// * Python (FastAPI), `def h(x: int)` under a route decorator →
///   [`TypeKind::Int`]; `Annotated[int, Path()]` → [`TypeKind::Int`].  The same
///   annotation on an undecorated function classifies as nothing.
pub(super) fn classify_param_type<'a>(
    param: Node<'a>,
    lang: &str,
    code: &'a [u8],
) -> Option<TypeKind> {
    match lang {
        "java" => classify_param_type_java(param, code),
        "typescript" | "ts" => classify_param_type_ts(param, code),
        "javascript" | "js" => classify_param_type_ts(param, code),
        "rust" | "rs" => classify_param_type_rust(param, code),
        "python" | "py" => classify_param_type_python(param, code, false),
        "go" => classify_param_type_go(param, code),
        _ => None,
    }
}

/// Go: recognise a **generic (non-response) writer** parameter from its
/// declared static type and tag it [`TypeKind::FileHandle`].
///
/// The single motivating consumer is the Go `fmt.Fprintf` XSS gate in
/// `taint::ssa_transfer` (via
/// [`crate::ssa::type_facts::GoInterfaceTable::definitely_not`]).
/// `fmt.Fprintf(w, fmt, args...)` is modelled as an `HTML_ESCAPE` (reflected
/// XSS) sink because `w` is *often* an `http.ResponseWriter`.  When `w` is
/// instead declared as a generic byte writer (`io.Writer`, `io.WriteCloser`,
/// a `*bytes.Buffer`, a `*strings.Builder`, an `*os.File`, a `bufio.Writer`,
/// ...), the formatted bytes never reach an HTTP client, so the finding is a
/// false positive.  Tagging the parameter `FileHandle` — which
/// `GoInterfaceTable::definitely_not(FileHandle, "http.ResponseWriter")`
/// already reports as provably-not-a-ResponseWriter — makes the existing gate
/// strip `HTML_ESCAPE` at the sink.
///
/// A *real* reflected-XSS handler declares its writer explicitly as
/// `http.ResponseWriter`.  That formal is typed [`TypeKind::HttpResponse`],
/// which `go_writer_is_non_response` reports as a possible response, so the
/// `fmt.Fprint*` gate keeps firing, and which lets type-qualified resolution
/// turn `w.Write(b)` into the `HttpResponse.Write` sink.  A `*http.Client`
/// formal is typed [`TypeKind::HttpClient`] so `c.Get(u)` resolves to the
/// `HttpClient.Get` SSRF gate.  See [`go_decl_type_to_kind`].
///
/// Precision/recall note: an `io.Writer` parameter *could* dynamically be
/// bound to an `http.ResponseWriter` at some call site (an interprocedural
/// XSS via a generic write-helper).  We accept that residual recall loss:
/// idiomatic Go response handlers take `http.ResponseWriter` directly, and
/// the FP volume from buffer / pipe / file / doc-gen writers dominates.
/// `FileHandle` is not in the `Int | Bool` set consulted by
/// `is_type_safe_for_sink`, and Go has no `FileHandle.*` type-qualified
/// method rules, so the tag has no effect outside the ResponseWriter gate.
///
/// Motivated by prometheus `util/documentcli/documentcli.go`
/// (`func GenerateMarkdown(model, writer io.Writer)` → `fmt.Fprintf(writer,
/// ...)`) and the gitea `*bytes.Buffer` / `*os.File` write helpers.
fn classify_param_type_go<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    if param.fkind() != "parameter_declaration" && param.fkind() != "variadic_parameter_declaration"
    {
        return None;
    }
    let type_node = param.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;
    go_decl_type_to_kind(&type_text)
}

/// Receiver-alias frame for a Go function / method / func literal: every
/// formal name paired with the canonical receiver prefix of its declared
/// type, or `None` for any other type so the formal shadows a same-named
/// binding of an enclosing function.  Request types use their request prefix
/// (`req *http.Request` → `("req", Some("Request"))`); the types
/// [`go_decl_type_to_kind`] knows use the [`TypeKind::label_prefix`] the SSA
/// type-qualified rules are keyed on (`w http.ResponseWriter` →
/// `HttpResponse`, `c *http.Client` → `HttpClient`, `out io.Writer` →
/// `FileHandle`).  Pushed via [`crate::labels::push_receiver_aliases`] while
/// the body is built.  `a, b *http.Request` binds both names.
pub(super) fn go_receiver_alias_frame(
    func_node: Node<'_>,
    code: &[u8],
) -> crate::labels::ReceiverAliasFrame {
    let mut frame = Vec::new();
    // A method's receiver is a formal too (`func (c *Ctx) h() { c.Req.URL }`).
    let receiver = func_node.child_by_field_name("receiver");
    let params = func_node.child_by_field_name("parameters");
    for list in receiver.into_iter().chain(params) {
        let mut cursor = list.walk();
        for param in list.named_children(&mut cursor) {
            if param.fkind() != "parameter_declaration"
                && param.fkind() != "variadic_parameter_declaration"
            {
                continue;
            }
            let type_text = if param.fkind() == "parameter_declaration" {
                param
                    .child_by_field_name("type")
                    .and_then(|t| text_of(t, code))
            } else {
                None
            };
            let prefix = type_text.as_deref().and_then(|t| {
                crate::labels::go_request_receiver_prefix(t)
                    .or_else(|| go_decl_type_to_kind(t).and_then(|k| k.label_prefix()))
            });
            let mut name_cursor = param.walk();
            for name in param.children_by_field_name("name", &mut name_cursor) {
                let Some(n) = text_of(name, code) else {
                    continue;
                };
                // A formal whose type is a struct declared in this file also
                // brings the struct's request-typed fields (`ctx.Req`).
                if let Some(t) = type_text.as_deref() {
                    go_struct_typed_fields(func_node, code, t, |field, field_prefix| {
                        frame.push((format!("{n}.{field}"), Some(field_prefix)));
                    });
                }
                frame.push((n, prefix));
            }
        }
    }
    frame
}

type GoStructTypedFields = std::collections::HashMap<String, Vec<(String, &'static str)>>;

thread_local! {
    /// Fields of the file's struct types whose declared type has a receiver
    /// prefix, by struct name.  Built on the first Go function of a file and
    /// cleared with the receiver-alias frames at the start and end of each
    /// file's CFG build.
    static GO_STRUCT_TYPED_FIELDS: std::cell::RefCell<Option<GoStructTypedFields>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn clear_go_struct_typed_fields() {
    GO_STRUCT_TYPED_FIELDS.with(|c| *c.borrow_mut() = None);
}

/// The fields of the struct type named by the formal type text `type_text`
/// (`*Context`, `Context`) whose own types have a receiver prefix, as
/// `(field name, prefix)`.  Only a struct declared in the same file is known;
/// a type from another package, an embedded field and a field of a field are
/// not followed.
fn go_struct_typed_fields(
    func_node: Node<'_>,
    code: &[u8],
    type_text: &str,
    mut each: impl FnMut(&str, &'static str),
) {
    let name = type_text.trim().trim_start_matches('*').trim();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return;
    }
    GO_STRUCT_TYPED_FIELDS.with(|cell| {
        let mut cell = cell.borrow_mut();
        let index = cell.get_or_insert_with(|| {
            let mut root = func_node;
            while let Some(parent) = root.parent() {
                root = parent;
            }
            go_index_struct_typed_fields(root, code)
        });
        if let Some(fields) = index.get(name) {
            for (field, prefix) in fields {
                each(field, prefix);
            }
        }
    })
}

fn go_index_struct_typed_fields(
    root: Node<'_>,
    code: &[u8],
) -> std::collections::HashMap<String, Vec<(String, &'static str)>> {
    let mut index = std::collections::HashMap::new();
    let mut top = root.walk();
    for decl in root.named_children(&mut top) {
        if decl.fkind() != "type_declaration" {
            continue;
        }
        let mut specs = decl.walk();
        for spec in decl.named_children(&mut specs) {
            if spec.fkind() != "type_spec" {
                continue;
            }
            let (Some(name), Some(ty)) = (
                spec.child_by_field_name("name")
                    .and_then(|n| text_of(n, code)),
                spec.child_by_field_name("type"),
            ) else {
                continue;
            };
            if ty.fkind() != "struct_type" {
                continue;
            }
            let mut fields = Vec::new();
            let mut walk = ty.walk();
            for list in ty.named_children(&mut walk) {
                if list.fkind() != "field_declaration_list" {
                    continue;
                }
                let mut lw = list.walk();
                for field in list.named_children(&mut lw) {
                    if field.fkind() != "field_declaration" {
                        continue;
                    }
                    let Some(prefix) = field
                        .child_by_field_name("type")
                        .and_then(|t| text_of(t, code))
                        .and_then(|t| {
                            crate::labels::go_request_receiver_prefix(&t)
                                .or_else(|| go_decl_type_to_kind(&t).and_then(|k| k.label_prefix()))
                        })
                    else {
                        continue;
                    };
                    let mut nw = field.walk();
                    for fname in field.children_by_field_name("name", &mut nw) {
                        if let Some(f) = text_of(fname, code) {
                            fields.push((f, prefix));
                        }
                    }
                }
            }
            if !fields.is_empty() {
                index.insert(name, fields);
            }
        }
    }
    index
}

/// Map a declared Go type (a formal's type, a `var x T` declaration, or the
/// `T` of a `&T{...}` / `new(T)` constructor) to the [`TypeKind`] the
/// analysis tracks: byte writers that are not a response
/// ([`go_writer_type_to_kind`]), `http.ResponseWriter` as
/// [`TypeKind::HttpResponse`], and `http.Client` (by value or pointer) as
/// [`TypeKind::HttpClient`].  Every other type returns `None`.
pub(super) fn go_decl_type_to_kind(t: &str) -> Option<TypeKind> {
    if let Some(kind) = go_writer_type_to_kind(t) {
        return Some(kind);
    }
    match t.trim().trim_start_matches('*').trim() {
        "http.ResponseWriter" => Some(TypeKind::HttpResponse),
        "http.Client" => Some(TypeKind::HttpClient),
        _ => None,
    }
}

/// Map a Go parameter / local type-text to [`TypeKind::FileHandle`] when the
/// head names a generic byte writer that is provably not an
/// `http.ResponseWriter`.  Strips a leading pointer marker (`*`) and
/// surrounding whitespace, then matches the qualified type name.  Returns
/// `None` for `http.ResponseWriter` and every unrecognised type so the sink
/// gate stays conservative.
fn go_writer_type_to_kind(t: &str) -> Option<TypeKind> {
    let head = t.trim().trim_start_matches('*').trim();
    match head {
        // Generic writer interfaces — a bare `io.Writer` is written to be
        // destination-agnostic; a reflected-XSS handler would name
        // `http.ResponseWriter` explicitly.
        "io.Writer"
        | "io.WriteCloser"
        | "io.ReadWriteCloser"
        | "io.ReadWriter"
        // Concrete in-memory / local byte sinks — never an HTTP response.
        | "bytes.Buffer"
        | "strings.Builder"
        | "os.File"
        | "bufio.Writer"
        | "bufio.ReadWriter"
        | "tabwriter.Writer"
        | "gzip.Writer"
        | "zlib.Writer" => Some(TypeKind::FileHandle),
        _ => None,
    }
}

/// Java (Spring), recognise typed-extractor parameters via the
/// surrounding annotation.  Per Hard Rule 3, plain `Long X` without a
/// known framework annotation is **not** treated as a typed extractor ,
/// the parameter could be a regular function argument that the
/// framework never validates.  Recognised annotations:
/// `@PathVariable`, `@RequestParam`, `@RequestBody`, `@RequestHeader`,
/// `@CookieValue`, `@MatrixVariable`.  When an annotation matches, the
/// parameter's static type is consulted via [`java_type_to_kind`].
fn classify_param_type_java<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    if param.fkind() != "formal_parameter" && param.fkind() != "spread_parameter" {
        return None;
    }
    if !has_java_framework_annotation(param, code) {
        return None;
    }
    let type_node = param.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;
    if let Some(k) = java_type_to_kind(&type_text) {
        return Some(k);
    }
    // when the static type is a class name we don't classify
    // as a primitive (e.g. `@RequestBody CreateUser dto`), look up the
    // class in the same-file DTO map.  Strip any generics for the
    // leading type so `Foo<Bar>` still resolves on `Foo`.
    let bare = type_text.split('<').next().unwrap_or(&type_text).trim();
    let last = bare.rsplit('.').next().unwrap_or(bare);
    lookup_dto_class(last)
}

/// Check whether the parameter carries a Spring web binding annotation
/// whose value has a typed shape worth recording in `param_types`.
fn has_java_framework_annotation(param: Node<'_>, code: &[u8]) -> bool {
    const KNOWN: &[&str] = &[
        "PathVariable",
        "RequestParam",
        "RequestBody",
        "RequestHeader",
        "CookieValue",
        "MatrixVariable",
        "ModelAttribute",
    ];
    java_annotation_leaves(param, code)
        .iter()
        .any(|a| KNOWN.contains(a))
}

/// Leaf names of the annotations on a Java formal (`@RequestParam` and
/// `@org.springframework.web.bind.annotation.RequestParam` both give
/// `RequestParam`).  tree-sitter-java puts the annotations inside the
/// formal's `modifiers` child; direct annotation children are read too.
fn java_annotation_leaves<'a>(param: Node<'_>, code: &'a [u8]) -> SmallVec<[&'a str; 4]> {
    fn push_leaf<'a>(ann: Node<'_>, code: &'a [u8], out: &mut SmallVec<[&'a str; 4]>) {
        if matches!(ann.fkind(), "marker_annotation" | "annotation")
            && let Some(name) = ann
                .child_by_field_name("name")
                .and_then(|n| node_str(n, code))
        {
            out.push(name.rsplit('.').next().unwrap_or(name).trim());
        }
    }
    let mut out = SmallVec::new();
    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        if child.fkind() == "modifiers" {
            let mut inner = child.walk();
            for ann in child.children(&mut inner) {
                push_leaf(ann, code, &mut out);
            }
        } else {
            push_leaf(child, code, &mut out);
        }
    }
    out
}

/// Spring MVC and JAX-RS annotations that bind a handler formal from the
/// request (query, path, form, header, cookie, body, multipart part).
const JAVA_REQUEST_BINDING_ANNOTATIONS: &[&str] = &[
    "RequestParam",
    "PathVariable",
    "RequestBody",
    "RequestHeader",
    "CookieValue",
    "MatrixVariable",
    "ModelAttribute",
    "RequestPart",
    "QueryParam",
    "PathParam",
    "FormParam",
    "HeaderParam",
    "CookieParam",
    "MatrixParam",
    "BeanParam",
];

/// Annotations that inject server-side state into a handler formal: the
/// authenticated principal, request or session attributes the server set,
/// configuration values, beans, and the JAX-RS async response handle.
const JAVA_SERVER_INJECTED_ANNOTATIONS: &[&str] = &[
    "AuthenticationPrincipal",
    "CurrentSecurityContext",
    "RequestAttribute",
    "SessionAttribute",
    "Value",
    "Autowired",
    "Suspended",
];

/// Handler formal types the framework fills with infrastructure objects
/// rather than request data.  The servlet request is here too: its
/// accessors (`getParameter`, `getHeader`, ...) are sources by label, the
/// same policy a plain servlet `doGet` gets, so painting the whole object
/// only adds flows that start at the bare receiver.  JAX-RS `UriInfo` and
/// `HttpHeaders` are left out because no label covers their accessors yet.
const JAVA_INFRA_FORMAL_TYPES: &[&str] = &[
    "HttpServletRequest",
    "ServletRequest",
    "HttpServletResponse",
    "ServletResponse",
    "ServerHttpResponse",
    "HttpSession",
    "WebRequest",
    "NativeWebRequest",
    "Model",
    "ModelMap",
    "ModelAndView",
    "RedirectAttributes",
    "BindingResult",
    "Errors",
    "SessionStatus",
    "UriComponentsBuilder",
    "ServletUriComponentsBuilder",
    "Principal",
    "Authentication",
    "Locale",
    "TimeZone",
    "ZoneId",
    "OutputStream",
    "ServletOutputStream",
    "Writer",
    "PrintWriter",
    "SecurityContext",
    "AsyncResponse",
    "Sse",
    "SseEventSink",
    "ServletContext",
    "ServletConfig",
    "Providers",
    "ResourceContext",
    "PushBuilder",
    "HttpMethod",
];

/// Whether a Spring / JAX-RS handler formal is bound from the request, and
/// so is adversary input.  A request-binding annotation decides yes and a
/// server-injection annotation decides no.  Otherwise the declared type
/// decides: infrastructure types ([`JAVA_INFRA_FORMAL_TYPES`]) are not
/// request data, and every other type is (Spring binds an unannotated
/// `String q` or DTO from the request, JAX-RS binds an unannotated formal
/// from the entity body).
pub(super) fn java_formal_is_request_bound(param: Node<'_>, code: &[u8]) -> bool {
    let annotations = java_annotation_leaves(param, code);
    if annotations
        .iter()
        .any(|a| JAVA_REQUEST_BINDING_ANNOTATIONS.contains(a))
    {
        return true;
    }
    if annotations
        .iter()
        .any(|a| JAVA_SERVER_INJECTED_ANNOTATIONS.contains(a))
    {
        return false;
    }
    let Some(type_text) = param
        .child_by_field_name("type")
        .and_then(|t| node_str(t, code))
    else {
        return true;
    };
    let head = type_text.split('<').next().unwrap_or(type_text);
    let head = head.trim_end_matches(|c: char| c == '[' || c == ']' || c.is_whitespace());
    let leaf = head.rsplit('.').next().unwrap_or(head).trim();
    !JAVA_INFRA_FORMAL_TYPES.contains(&leaf)
}

/// Per-formal [`java_formal_is_request_bound`] flags for a Java method, in
/// the order [`extract_param_meta`] lists the formals.  When the walk does
/// not line up with the `expected` formal count, every formal is reported
/// bound, which is the behaviour without this gate.
pub(super) fn java_request_bound_flags(
    func_node: Node<'_>,
    code: &[u8],
    expected: usize,
) -> Vec<bool> {
    let cfg = param_config("java");
    let mut flags = Vec::with_capacity(expected);
    if let Some(params) = func_node.child_by_field_name(cfg.params_field) {
        let mut cursor = params.walk();
        for child in params.children(&mut cursor) {
            if cfg.param_node_kinds.contains(&child.fkind()) {
                flags.push(java_formal_is_request_bound(child, code));
            }
        }
    }
    if flags.len() == expected {
        flags
    } else {
        vec![true; expected]
    }
}

/// Map a Java type-text fragment to a [`TypeKind`].  Public to the
/// `cfg` module so the DTO DTO collector can reuse the same
/// classifier for class fields.
pub(super) fn java_type_to_kind(t: &str) -> Option<TypeKind> {
    let bare = t.trim().trim_start_matches('@').trim();
    // Drop generic args for the leading type.
    let bare = bare.split('<').next().unwrap_or(bare).trim();
    let last = bare.rsplit('.').next().unwrap_or(bare);
    match last {
        "int" | "long" | "short" | "byte" | "Integer" | "Long" | "Short" | "Byte"
        | "BigInteger" => Some(TypeKind::Int),
        "boolean" | "Boolean" => Some(TypeKind::Bool),
        "double" | "float" | "Double" | "Float" | "BigDecimal" => Some(TypeKind::Int),
        "String" | "CharSequence" => Some(TypeKind::String),
        _ => None,
    }
}

/// Map a TypeScript type-text fragment (already stripped of leading
/// `:` / whitespace) to a primitive [`TypeKind`].  Used by both the
/// per-parameter classifier and the DTO DTO collector.
pub(super) fn ts_type_to_kind(t: &str) -> Option<TypeKind> {
    let head = t.split('<').next().unwrap_or(t).trim();
    match head {
        "number" | "bigint" => Some(TypeKind::Int),
        "boolean" => Some(TypeKind::Bool),
        "string" => Some(TypeKind::String),
        _ => None,
    }
}

/// TypeScript (NestJS), recognise typed-extractor parameters via a
/// known NestJS decorator (`@Param`, `@Body`, `@Query`, `@Headers`,
/// `@Req`, `@Res`).  Per Hard Rule 3, a bare `function h(id: number)`
/// is not a framework extractor, without a NestJS decorator no
/// runtime gate is implied.  Pipe coercions (`ParseIntPipe` /
/// `ParseBoolPipe`) override the static type.
///
/// Exception: parameters annotated as a known JS built-in collection
/// type (`Map<...>`, `Set<...>`, `WeakMap<...>`, `WeakSet<...>`,
/// `Array<...>` / `T[]` / `ReadonlyArray<...>`) resolve to
/// [`TypeKind::LocalCollection`] regardless of decorator presence.
/// `LocalCollection` is a *receiver-shape* claim, not a
/// framework-validated-input claim, it tells the auth analyser that
/// `param.get(k)` / `param.set(k, v)` / `param.find(p)` is a
/// container operation rather than a data-layer read/mutation.  This
/// closes the Excalidraw FP cluster (`elementsMap: ElementsMap`,
/// `groupIdMapForOperation: Map<string, string>`) without affecting
/// any input-validation reasoning.
fn classify_param_type_ts<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    let type_text = param
        .child_by_field_name("type")
        .and_then(|n| inner_ts_type_text(n, code));

    if let Some(t) = type_text.as_deref()
        && let Some(k) = ts_type_to_local_collection(t.trim().trim_start_matches(':').trim())
    {
        return Some(k);
    }

    if !has_ts_decorator_argument(
        param,
        code,
        &[
            "@Param",
            "@Body",
            "@Query",
            "@Headers",
            "@Header",
            "@Cookie",
            "@UploadedFile",
        ],
    ) {
        return None;
    }
    // Decorator-based pipe coercion overrides the static type.
    if has_ts_decorator_argument(param, code, &["ParseIntPipe"]) {
        return Some(TypeKind::Int);
    }
    if has_ts_decorator_argument(param, code, &["ParseBoolPipe"]) {
        return Some(TypeKind::Bool);
    }
    let t = type_text?;
    let stripped = t.trim().trim_start_matches(':').trim();
    if let Some(k) = ts_type_to_kind(stripped) {
        return Some(k);
    }
    // NestJS `@Body() dto: CreateUser`, when the static
    // type is a class / interface name declared in the same file,
    // resolve via the DTO map.  Generic args dropped for the leading
    // type so `Foo<Bar>` matches on `Foo`.
    let head = stripped.split('<').next().unwrap_or(stripped).trim();
    lookup_dto_class(head)
}

/// Map a TypeScript / JavaScript type-text fragment to
/// [`TypeKind::LocalCollection`] when the head is a JS built-in
/// container type.  Recognises:
///
/// * `Map<K, V>`, `Set<T>`, `WeakMap<K, V>`, `WeakSet<T>`, the four
///   built-in keyed/unkeyed collection types.
/// * `Array<T>`, `ReadonlyArray<T>`, the named array generics.
/// * `T[]`, `readonly T[]`, the array shorthand syntax.
/// * Same-file `type X = Map<...>` aliases (resolved via the
///   per-file `TYPE_ALIAS_LC` map populated at the top of
///   [`build_cfg`]).
///
/// Same-file user types named `Map` / `Set` / etc. (which would
/// shadow the built-ins) are vanishingly rare in TS codebases that
/// also define the methods (`get`, `set`, `has`, `find`); the
/// classifier accepts the head match.
pub(super) fn ts_type_to_local_collection(t: &str) -> Option<TypeKind> {
    let head_text = t.trim().trim_start_matches("readonly ").trim();
    // Array shorthand: `T[]` or `readonly T[]`.
    if head_text.ends_with("[]") {
        return Some(TypeKind::LocalCollection);
    }
    let head = head_text.split('<').next().unwrap_or(head_text).trim();
    match head {
        "Map" | "Set" | "WeakMap" | "WeakSet" | "Array" | "ReadonlyArray" => {
            Some(TypeKind::LocalCollection)
        }
        _ => super::TYPE_ALIAS_LC
            .with(|cell| cell.borrow().contains(head))
            .then_some(TypeKind::LocalCollection),
    }
}

fn inner_ts_type_text<'a>(type_anno: Node<'a>, code: &'a [u8]) -> Option<String> {
    // type_annotation node text is `: T`, unwrap to T.
    if let Some(child) = type_anno.named_child(0) {
        return text_of(child, code);
    }
    text_of(type_anno, code)
}

/// Walk through a TypeScript / NestJS parameter's decorators looking
/// for an identifier matching `wanted` anywhere in the decorator
/// argument list (e.g. `@Query('id', ParseIntPipe)`).  Conservative
/// substring match; all decorator nodes precede the parameter.
fn has_ts_decorator_argument(param: Node<'_>, code: &[u8], wanted: &[&str]) -> bool {
    let mut cur = param.prev_sibling();
    while let Some(node) = cur {
        if node.fkind() == "decorator" {
            if let Some(text) = text_of(node, code) {
                for w in wanted {
                    if text.contains(w) {
                        return true;
                    }
                }
            }
        }
        // Some grammars attach decorators as children of the param.
        cur = node.prev_sibling();
    }
    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        if child.fkind() == "decorator" {
            if let Some(text) = text_of(child, code) {
                for w in wanted {
                    if text.contains(w) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Rust (Axum / Rocket / Actix), read the parameter's type text and
/// look for `Path<i64>` / `Json<T>` / `Form<T>` / `Query<T>` shapes.
/// Per Hard Rule 3, bare primitives (`fn h(id: i64)` without an
/// extractor wrapper) are **not** treated as typed extractors, only
/// framework-wrapped types qualify.
fn classify_param_type_rust<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    if param.fkind() != "parameter" {
        return None;
    }
    let type_node = param.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;

    // LocalCollection is a *receiver-shape* claim, not a
    // framework-validated-input claim, Hard Rule 3's "bare primitives
    // don't count" gate doesn't apply (mirrors `classify_param_type_ts`
    // for the same reason).  Captures `unsharded: RoaringBitmap`,
    // `docids: &mut RoaringBitmap`, `params: HashMap<String, String>`,
    // `new_shard_docids: &'a mut hashbrown::HashMap<...>` shapes from
    // meilisearch/index-scheduler's bitmap bookkeeping where the
    // verb-name dispatch (`is_mutation: insert/remove`) would otherwise
    // classify these as DB writes.
    if let Some(k) = rust_type_to_local_collection(&type_text) {
        return Some(k);
    }

    if let Some(k) = rust_db_connection_type(&type_text) {
        return Some(k);
    }

    rust_type_to_kind(&type_text)
}

/// The receiver type a Rust formal brings to its body: a `File` is a
/// [`TypeKind::FileHandle`], so `file.read_to_end(&mut buf)` resolves to the
/// type-qualified read source; a `rusqlite` connection is a
/// [`TypeKind::DatabaseConnection`] ([`rust_db_connection_type`]).
fn rust_receiver_type(t: &str) -> Option<TypeKind> {
    if matches!(
        strip_rust_ref_markers(t),
        "File" | "std::fs::File" | "fs::File"
    ) {
        return Some(TypeKind::FileHandle);
    }
    rust_db_connection_type(t)
}

/// A `rusqlite` connection formal (`conn: &Connection`, `&mut rusqlite::Connection`)
/// is a [`TypeKind::DatabaseConnection`], the same type `Connection::open(..)`
/// produces for a local, so `conn.execute(sql, params)` resolves to the
/// type-qualified SQL gate whichever way the handle arrived.  Only the exact
/// type name qualifies: pools and unrelated `*Connection` types stay untyped.
/// A connection behind `Arc<Mutex<..>>` is not the receiver of its methods
/// (the lock guard is), so it is typed through the declaration instead
/// ([`super::rust_receivers`]).
fn rust_db_connection_type(t: &str) -> Option<TypeKind> {
    matches!(
        strip_rust_ref_markers(t),
        "Connection" | "rusqlite::Connection"
    )
    .then_some(TypeKind::DatabaseConnection)
}

/// Receiver-alias frame for a Rust function: every `rusqlite` connection formal
/// (`conn: &Connection`) paired with the `DatabaseConnection` receiver prefix,
/// every other formal with `None` so it shadows a same-named binding of an
/// enclosing function.  Unscoped SSA lowering emits no `Param` op for a formal
/// that is only ever a method receiver, so the type cannot reach the SSA type
/// facts; classifying the callee text under the prefix while the body is built
/// (the Go formals use the same channel) makes `conn.execute(sql, params)` hit
/// the type-qualified SQL gate whether the handle is a local or a parameter.
pub(super) fn rust_receiver_alias_frame(
    func_node: Node<'_>,
    code: &[u8],
) -> crate::labels::ReceiverAliasFrame {
    let Some(params) = func_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut frame = Vec::new();
    let mut cursor = params.walk();
    for param in params.named_children(&mut cursor) {
        if param.fkind() != "parameter" {
            continue;
        }
        let Some(pattern) = param.child_by_field_name("pattern") else {
            continue;
        };
        if pattern.fkind() != "identifier" {
            continue;
        }
        let Some(name) = text_of(pattern, code) else {
            continue;
        };
        let prefix = rust_param_type_text(param, code)
            .and_then(|t| rust_receiver_type(&t))
            .and_then(|k| k.label_prefix());
        frame.push((name, prefix));
    }
    frame
}

/// A Rust type with its reference markers and smart-pointer / lock wrappers
/// (`Arc`, `Rc`, `Mutex`, `RwLock`, `RefCell`, `Box`, `Option`) peeled:
/// `&Arc<Mutex<Connection>>` is `Connection`.  Any other generic type is
/// returned as is.
pub(super) fn rust_peel_wrappers(t: &str) -> &str {
    let mut s = strip_rust_ref_markers(t);
    loop {
        let Some(lt) = s.find('<') else {
            return s;
        };
        if !s.ends_with('>') {
            return s;
        }
        let head = s[..lt].trim();
        let leaf = head.rsplit("::").next().unwrap_or(head);
        if !matches!(
            leaf,
            "Arc" | "Rc" | "Mutex" | "RwLock" | "RefCell" | "Box" | "Option"
        ) {
            return s;
        }
        s = strip_rust_ref_markers(&s[lt + 1..s.len() - 1]);
    }
}

/// Strip Rust reference markers, lifetimes, and `mut` from the head of
/// a type-text fragment so the underlying type name is exposed for
/// matching.  Handles `&T`, `&mut T`, `&'a T`, `&'a mut T`, and
/// repeated `&` prefixes (e.g. `&&mut T`).
fn strip_rust_ref_markers(t: &str) -> &str {
    let mut s = t.trim();
    loop {
        if let Some(rest) = s.strip_prefix('&') {
            let rest = rest.trim_start();
            // Optional lifetime label: `'a`, `'static`, `'_`.
            let rest = if let Some(after) = rest.strip_prefix('\'') {
                let end = after
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(after.len());
                after[end..].trim_start()
            } else {
                rest
            };
            // Optional `mut` keyword.
            let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
            s = rest;
            continue;
        }
        if let Some(rest) = s.strip_prefix("mut ") {
            s = rest.trim_start();
            continue;
        }
        break;
    }
    s
}

/// Map a Rust parameter / variable type-text to
/// [`TypeKind::LocalCollection`] when the head names a known
/// in-memory container.  Strips reference / lifetime / `mut` markers,
/// drops module-path prefixes (`std::collections::`, `hashbrown::`,
/// `roaring::`), then matches the head against std and ecosystem
/// collection types.
///
/// Recognises:
///   * Std: `Vec`, `HashMap`, `HashSet`, `BTreeMap`, `BTreeSet`,
///     `VecDeque`, `BinaryHeap`, `LinkedList`.
///   * Ecosystem: `IndexMap`, `IndexSet` (indexmap), `SmallVec`
///     (smallvec), `DashMap`, `DashSet` (dashmap), `FxHashMap`,
///     `FxHashSet` (rustc-hash / fxhash), `RoaringBitmap`,
///     `RoaringTreemap` (roaring).
///   * Array / slice shorthand: `[T; N]`, `[T]` (covered by the
///     leading-`[` check after ref-stripping).
///
/// Returns `None` for `Database<...>` (heed/sled, persistent KV
/// store, NOT a local collection, keeping this `None` preserves
/// real IDOR detection on persistent-store calls), `Mutex<...>` /
/// `RwLock<...>` (synchronisation wrappers, not sink-shape claims),
/// and bare primitives.
pub(super) fn rust_type_to_local_collection(t: &str) -> Option<TypeKind> {
    let stripped = strip_rust_ref_markers(t);

    // Array / slice shorthand: `[T; N]` or `[T]` (the `&` was
    // already stripped).
    if stripped.starts_with('[') {
        return Some(TypeKind::LocalCollection);
    }

    // Drop module-path prefix: keep only the last segment before `<`
    // or end (`std::collections::HashMap<K, V>` → `HashMap`).
    let head_with_generics = stripped.rsplit("::").next().unwrap_or(stripped);
    let head = head_with_generics
        .split('<')
        .next()
        .unwrap_or(head_with_generics)
        .trim();

    const TYPES: &[&str] = &[
        "Vec",
        "VecDeque",
        "BinaryHeap",
        "LinkedList",
        "HashMap",
        "HashSet",
        "BTreeMap",
        "BTreeSet",
        "IndexMap",
        "IndexSet",
        "SmallVec",
        "DashMap",
        "DashSet",
        "FxHashMap",
        "FxHashSet",
        "RoaringBitmap",
        "RoaringTreemap",
    ];
    if TYPES.contains(&head) {
        Some(TypeKind::LocalCollection)
    } else {
        None
    }
}

fn rust_type_to_kind(t: &str) -> Option<TypeKind> {
    let stripped = t.trim();
    // Reject reference / mutability noise so `&Path<i64>` still matches
    // the wrapper detection below.
    let stripped = stripped
        .trim_start_matches('&')
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    // Only framework wrapper extractors qualify, bare primitives like
    // `i64` could be regular function parameters with no framework
    // validation gate.
    for wrap in [
        "Path",
        "Json",
        "Form",
        "Query",
        "web::Path",
        "web::Json",
        "web::Form",
        "web::Query",
        "rocket::http::uri::Origin",
    ] {
        let prefix = format!("{wrap}<");
        if let Some(rest) = stripped.strip_prefix(&prefix) {
            if let Some(inner) = rest.strip_suffix('>') {
                let inner = inner.trim();
                // Tuple extractor `Path<(i64, String)>`, first element wins.
                if inner.starts_with('(') {
                    let inside = inner.trim_start_matches('(').trim_end_matches(')');
                    let first = inside.split(',').next().unwrap_or("").trim();
                    if let Some(k) = rust_primitive_to_kind(first) {
                        return Some(k);
                    }
                }
                // Bare path generic `Path<i64>`.
                if let Some(k) = rust_primitive_to_kind(inner) {
                    return Some(k);
                }
                // `Json<T>` / `Form<T>` / `Query<T>` /
                // `Path<T>` with a same-file struct type, resolve via
                // the DTO map.  Strip nested generics so `Json<Foo<i64>>`
                // matches on `Foo`.
                let head = inner.split('<').next().unwrap_or(inner).trim();
                if let Some(k) = lookup_dto_class(head) {
                    return Some(k);
                }
                // Custom struct outside the same file, leave None
                // (cross-file resolution is a follow-up).
                return None;
            }
        }
    }
    None
}

/// Map a Rust primitive / `String` / `&str` to a [`TypeKind`].  Public
/// to the `cfg` module so the DTO DTO collector can reuse it for
/// `struct` field types.
pub(super) fn rust_primitive_to_kind(t: &str) -> Option<TypeKind> {
    let t = t.trim();
    match t {
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" => Some(TypeKind::Int),
        "f32" | "f64" => Some(TypeKind::Int),
        "bool" => Some(TypeKind::Bool),
        "String" | "&str" | "str" => Some(TypeKind::String),
        _ => None,
    }
}

/// Python (FastAPI), recognise request-bound formals.  Per Hard Rule 3, a
/// bare `def h(id: int)` is **not** a framework extractor on its own: the
/// function may be a plain Python function and the annotation provides no
/// runtime gate.  A formal counts as request-bound when:
///
/// * its annotation is `Annotated[T, Path()/Query()/Body()/...]`, or
/// * its default is a `Query(..)` / `Body(..)` / `Header(..)` / `Cookie(..)` /
///   `Form(..)` / `File(..)` / `Path(..)` marker call, or
/// * the function carries a FastAPI route decorator (`in_route`) and the
///   annotation is a plain scalar, a container of scalars, or a same-file
///   Pydantic model, which FastAPI binds from the query string or the body.
///
/// A `Depends(..)` / `Security(..)` default is never request-bound, and
/// neither are formals whose annotation is not one of the above
/// (`Request`, `Session`, an `Annotated` dependency alias such as
/// `SessionDep`): those stay unseeded.
fn classify_param_type_python<'a>(
    param: Node<'a>,
    code: &'a [u8],
    in_route: bool,
) -> Option<TypeKind> {
    let default_marker = param
        .child_by_field_name("value")
        .and_then(|v| python_default_marker(v, code));
    if matches!(default_marker.as_deref(), Some("Depends" | "Security")) {
        return None;
    }
    let type_text = param
        .child_by_field_name("type")
        .and_then(|t| text_of(t, code));
    if let Some(kind) = type_text.as_deref().and_then(python_type_to_kind) {
        return Some(kind);
    }
    // pathlib's `Path("..")` default is not FastAPI's `Path(..)` marker.
    let marker = default_marker.filter(|m| {
        m != "Path"
            || !type_text.as_deref().is_some_and(|t| {
                matches!(
                    t.trim().rsplit('.').next(),
                    Some("Path" | "PurePath" | "PosixPath" | "WindowsPath")
                )
            })
    });
    let marker = marker.filter(|m| {
        matches!(
            m.as_str(),
            "Query" | "Body" | "Form" | "Header" | "Cookie" | "File" | "Path"
        )
    });
    if let Some(kind) = type_text.as_deref().and_then(python_request_value_kind) {
        // A bare annotation on a route is a request value, but a plain
        // number is validated by the framework and cannot carry a payload,
        // so it is only painted when a marker says so.
        if marker.is_some() || (in_route && !python_annotation_is_numeric(type_text.as_deref())) {
            return Some(kind);
        }
    }
    // An explicit marker with an annotation we cannot read still says the
    // value comes from the request.
    match marker.as_deref() {
        Some("Body" | "File") => Some(TypeKind::Object),
        Some(_) => Some(TypeKind::String),
        None => None,
    }
}

/// Last dotted segment of the callee when `default` is a call
/// (`Query(None)` and `fastapi.Query(None)` both give `Query`).
fn python_default_marker(default: Node<'_>, code: &[u8]) -> Option<String> {
    if default.fkind() != "call" {
        return None;
    }
    let callee = text_of(default.child_by_field_name("function")?, code)?;
    callee.rsplit('.').next().map(|s| s.trim().to_string())
}

/// `X` for `Optional[X]`, `Union[X, None]` and `X | None`; `None` when `t`
/// is not one of those or has more than one non-`None` member.
fn strip_optional(t: &str) -> Option<&str> {
    let t = t.trim();
    let members: Vec<&str> = if let Some(inner) = t
        .strip_prefix("Optional[")
        .or_else(|| t.strip_prefix("typing.Optional["))
        .or_else(|| t.strip_prefix("Union["))
        .or_else(|| t.strip_prefix("typing.Union["))
    {
        split_top_level(inner.strip_suffix(']')?, ',')
    } else {
        split_top_level(t, '|')
    };
    let mut rest = members.iter().map(|m| m.trim()).filter(|m| *m != "None");
    let only = rest.next()?;
    (rest.next().is_none() && (members.len() > 1 || only != t)).then_some(only)
}

/// True for an annotation that names only numbers: `int`, `float`, `bool`,
/// their `Optional` / `| None` forms and lists of them.
fn python_annotation_is_numeric(t: Option<&str>) -> bool {
    let Some(mut t) = t.map(str::trim) else {
        return false;
    };
    if let Some(inner) = t
        .strip_prefix("Annotated[")
        .or_else(|| t.strip_prefix("typing.Annotated["))
        && let Some(inside) = inner.strip_suffix(']')
    {
        return python_annotation_is_numeric(Some(split_top_level(inside, ',')[0]));
    }
    while let Some(inner) = strip_optional(t) {
        t = inner;
    }
    let numeric = |h: &str| matches!(h.trim(), "int" | "float" | "bool");
    if numeric(t) {
        return true;
    }
    // `list[int]`, `List[float]`, `set[int]`.
    let Some((head, elem)) = t.split_once('[') else {
        return false;
    };
    matches!(
        head.trim(),
        "list" | "List" | "set" | "Set" | "frozenset" | "FrozenSet" | "Sequence"
    ) && elem.strip_suffix(']').is_some_and(numeric)
}

/// Kind of a request-bound FastAPI formal from its annotation text:
/// `str`, `int`, `Optional[str]`, `str | None`, `list[str]` or a same-file
/// Pydantic model.  `None` for annotations that name types we cannot tell
/// from an injected dependency, and for `Literal[..]` and validated value
/// types (`UUID`, `date`), whose values are constrained by the framework.
fn python_request_value_kind(t: &str) -> Option<TypeKind> {
    let mut t = t.trim();
    // `Annotated[X, Field(..)]` is `X`, unless a metadata entry makes it a
    // dependency (`Annotated[Session, Depends(get_db)]`).
    if let Some(inner) = t
        .strip_prefix("Annotated[")
        .or_else(|| t.strip_prefix("typing.Annotated["))
    {
        let parts = split_top_level(inner.strip_suffix(']')?, ',');
        if parts
            .iter()
            .skip(1)
            .any(|p| p.contains("Depends(") || p.contains("Security("))
        {
            return None;
        }
        return python_request_value_kind(parts[0]);
    }
    // `Optional[X]`, `Union[X, None]` and `X | None` reduce to `X`.
    while let Some(inner) = strip_optional(t) {
        t = inner;
    }
    if t == "None" {
        return None;
    }
    let head = t.split('[').next().unwrap_or(t).trim();
    match head.rsplit('.').next().unwrap_or(head) {
        "list" | "List" | "set" | "Set" | "frozenset" | "FrozenSet" | "tuple" | "Tuple"
        | "Sequence" => Some(TypeKind::Array),
        "bytes" => Some(TypeKind::String),
        "dict" | "Dict" | "Mapping" | "MutableMapping" => Some(TypeKind::Object),
        "Literal" | "UUID" | "date" | "datetime" | "time" | "timedelta" | "Decimal" => None,
        _ => python_primitive_to_kind(head).or_else(|| lookup_dto_class(head)),
    }
}

/// Split `s` at `sep` outside any bracket nesting.
fn split_top_level(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            c if c == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn python_type_to_kind(t: &str) -> Option<TypeKind> {
    let stripped = t.trim();
    // `Annotated[int, Path()]`, only matches when one of the generic
    // args names a recognised FastAPI binding marker.  Otherwise no
    // framework gate is implied.
    if let Some(inner) = stripped
        .strip_prefix("Annotated[")
        .or_else(|| stripped.strip_prefix("typing.Annotated["))
    {
        let inside = inner.trim_end_matches(']');
        if !contains_fastapi_marker(inside) {
            return None;
        }
        // `Annotated[CreateUser, Body()]` resolves a same-file Pydantic
        // model through the DTO map; `Annotated[Optional[int], Query()]`
        // unwraps to its scalar.
        let first = split_top_level(inside, ',')[0];
        return python_request_value_kind(first);
    }
    None
}

fn contains_fastapi_marker(s: &str) -> bool {
    const MARKERS: &[&str] = &[
        "Path(", "Query(", "Body(", "Header(", "Cookie(", "Form(", "File(",
    ];
    MARKERS.iter().any(|m| s.contains(m))
}

/// Map a Python type expression to a primitive [`TypeKind`].  Used by
/// both the per-parameter classifier and the DTO Pydantic-model
/// field collector.
pub(super) fn python_primitive_to_kind(t: &str) -> Option<TypeKind> {
    let head = t.trim().split('[').next().unwrap_or(t).trim();
    match head {
        "int" => Some(TypeKind::Int),
        "bool" => Some(TypeKind::Bool),
        "float" => Some(TypeKind::Int),
        "str" => Some(TypeKind::String),
        _ => None,
    }
}

/// Language built-ins that never return.  A call to one of these ends the
/// block: control reaches nothing after it, so the CFG builder must not
/// draw a fall-through edge out of it.
///
/// This matters far beyond dead-code accounting, because it decides whether
/// a validation guard is *dominating*.  In
///
/// ```php
/// if (!in_array($cmd, $allowed)) { die('denied'); }
/// system($cmd);
/// ```
///
/// the sink is reachable only along the edge on which `in_array` held.  If
/// `die` keeps a fall-through edge, the rejected value merges back in at the
/// join and every "validate, else abort" guard in the language silently stops
/// suppressing — the shape reads as unvalidated no matter how the guard is
/// written.  The same argument covers `exit(1)` in C, `panic!()` in Rust and
/// `sys.exit()` in Python.
///
/// Until now `LangAnalysisRules::terminators` was populated *only* from user
/// config (`labels::build_lang_rules`), so out of the box no language had any
/// terminator at all.  The knowledge did exist, but in
/// `cfg_analysis::error_handling::call_never_returns`, which is reachable only
/// from the `cfg-error-fallthrough` rule and never consulted while the graph
/// is being built.  These are the built-in defaults the CFG builder needs;
/// user config still unions on top.
///
/// Deliberately conservative.  Marking a call a terminator makes everything
/// after it unreachable, which turns a false positive into a false *negative*
/// if the callee can in fact return.  So this list only holds names that
/// cannot return in the surface language, and only in their unambiguous
/// namespace-qualified or reserved-word forms:
///
///  * PHP `die` / `exit` are reserved constructs and cannot be redefined.
///  * Rust's diverging macros are `!`-typed by definition.  `assert!` and
///    friends are excluded — they are conditional.
///  * Bare `Exit` / `exit` on an arbitrary receiver (`session.exit()`) is
///    *not* matched; only the qualified std forms are.
///  * Framework request-abort helpers are included when they cannot return
///    by contract and the name is specific to the framework: WordPress
///    `wp_die` / `wp_send_json*`, the Laravel `abort` helper (not the
///    conditional `abort_if` / `abort_unless`), Koa `ctx.throw`, Sinatra
///    `halt`, and the module-qualified Flask / Werkzeug / Bottle `abort`.
///    A bare Python `abort` is a terminator only when the file imports it
///    from one of those modules; see [`is_terminator_call`].
fn is_builtin_terminator(lang: &str, callee: &str) -> bool {
    // Receiver-qualified std terminators are matched on the full callee text,
    // never on the trailing segment, so a user-defined `server.Exit()` or
    // `session.exit()` is not mistaken for `os.Exit` / `sys.exit`.
    match lang {
        // A leading `\` is the global-namespace qualifier (`\abort(403)`
        // inside a namespaced Laravel controller).
        "php" => matches!(
            callee.strip_prefix('\\').unwrap_or(callee),
            "die"
                | "exit"
                | "wp_die"
                | "wp_send_json"
                | "wp_send_json_success"
                | "wp_send_json_error"
                | "abort"
        ),
        // `_Exit` / `quick_exit` are C11; `err`/`errx` are BSD and exit(3)
        // internally.  `abort` raises SIGABRT and never returns.
        "c" | "cpp" => matches!(
            callee,
            "exit" | "_exit" | "_Exit" | "abort" | "quick_exit" | "err" | "errx"
        ),
        // Macro callees are recorded without the trailing `!`
        // (see `is_rust_format_style_macro`).
        "rust" => matches!(
            callee,
            "panic"
                | "unreachable"
                | "todo"
                | "unimplemented"
                | "process::exit"
                | "process::abort"
                | "std::process::exit"
                | "std::process::abort"
        ),
        "python" => matches!(
            callee,
            "sys.exit"
                | "os._exit"
                | "os.abort"
                | "flask.abort"
                | "werkzeug.exceptions.abort"
                | "bottle.abort"
        ),
        "go" => matches!(
            callee,
            "panic"
                | "os.Exit"
                | "syscall.Exit"
                | "runtime.Goexit"
                | "log.Fatal"
                | "log.Fatalf"
                | "log.Fatalln"
                | "log.Panic"
                | "log.Panicf"
                | "log.Panicln"
        ),
        "java" => matches!(callee, "System.exit"),
        // Koa / Egg `ctx.throw` always throws an HttpError.  Matched on the
        // conventional context parameter name only, like the `ctx.query`
        // source rules.
        "javascript" | "typescript" | "tsx" => matches!(callee, "process.exit" | "ctx.throw"),
        // Ruby `exit`/`exit!`/`abort` raise SystemExit / terminate, and
        // Sinatra / Roda `halt` throws `:halt`.  `raise` is deliberately
        // absent: it is modelled as `Kind::Throw`, which the CFG already
        // routes to handlers rather than to a dead end.
        "ruby" => matches!(callee, "exit" | "exit!" | "abort" | "Kernel.exit" | "halt"),
        _ => false,
    }
}

/// Check if a callee name is a terminator: either a language built-in
/// ([`is_builtin_terminator`]) or a user-configured one.
///
/// Config matching stays case-insensitive, as it always was.  Built-in
/// matching is case-*sensitive* because the names it carries are qualified
/// std identifiers where case is meaningful (`os.Exit` is Go's, `os.exit` is
/// nobody's) and a case-insensitive compare would let a user-defined
/// `System.Exit` or `PANIC` slip in.
pub(super) fn is_terminator_call(
    lang: &str,
    callee: &str,
    analysis_rules: Option<&LangAnalysisRules>,
) -> bool {
    if is_builtin_terminator(lang, callee) {
        return true;
    }
    // Bare `abort(400)` is Flask's / Werkzeug's only when the file imported
    // it from there.  A local `def abort(...)` keeps its fall-through edge.
    if lang == "python" && PYTHON_NORETURN_IMPORTS.with(|s| s.borrow().contains(callee)) {
        return true;
    }
    if let Some(rules) = analysis_rules {
        let callee_lower = callee.to_ascii_lowercase();
        rules
            .terminators
            .iter()
            .any(|t| callee_lower == t.to_ascii_lowercase())
    } else {
        false
    }
}

#[cfg(test)]
mod terminator_tests {
    use super::is_builtin_terminator;

    #[test]
    fn framework_abort_helpers_are_terminators() {
        for (lang, callee) in [
            ("php", "wp_die"),
            ("php", "\\wp_die"),
            ("php", "abort"),
            ("php", "\\abort"),
            ("php", "wp_send_json_error"),
            ("javascript", "ctx.throw"),
            ("typescript", "ctx.throw"),
            ("ruby", "halt"),
            ("python", "flask.abort"),
            ("python", "werkzeug.exceptions.abort"),
        ] {
            assert!(is_builtin_terminator(lang, callee), "{lang} {callee}");
        }
    }

    #[test]
    fn conditional_or_receiver_abort_forms_are_not_terminators() {
        for (lang, callee) in [
            // conditional Laravel helpers
            ("php", "abort_if"),
            ("php", "abort_unless"),
            // method on an arbitrary receiver
            ("php", "$this->abort"),
            // redirects return
            ("php", "wp_safe_redirect"),
            ("javascript", "res.throw"),
            ("javascript", "throw"),
            // bare Python `abort` needs the flask/werkzeug import binding
            ("python", "abort"),
            ("python", "self.abort"),
            ("ruby", "r.halt"),
        ] {
            assert!(!is_builtin_terminator(lang, callee), "{lang} {callee}");
        }
    }
}

#[cfg(test)]
mod typed_extractor_tests {
    use super::{
        contains_fastapi_marker, java_type_to_kind, python_primitive_to_kind, python_type_to_kind,
        rust_primitive_to_kind, rust_type_to_kind, rust_type_to_local_collection,
        ts_type_to_local_collection,
    };
    use crate::ssa::type_facts::TypeKind;

    // ── TypeScript / JavaScript local-collection types ───────────────────

    #[test]
    fn ts_built_in_collections_map_to_local_collection() {
        // The four keyed/unkeyed built-in container generics.
        assert_eq!(
            ts_type_to_local_collection("Map<string, number>"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            ts_type_to_local_collection("Set<string>"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            ts_type_to_local_collection("WeakMap<object, string>"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            ts_type_to_local_collection("WeakSet<object>"),
            Some(TypeKind::LocalCollection)
        );
        // Array forms.
        assert_eq!(
            ts_type_to_local_collection("Array<string>"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            ts_type_to_local_collection("ReadonlyArray<string>"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            ts_type_to_local_collection("string[]"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            ts_type_to_local_collection("readonly string[]"),
            Some(TypeKind::LocalCollection)
        );
        // Excalidraw-style keyed map with index-type generic args.
        assert_eq!(
            ts_type_to_local_collection("Map<ExcalidrawElement[\"id\"], ExcalidrawElement>"),
            Some(TypeKind::LocalCollection)
        );
    }

    #[test]
    fn ts_non_collection_types_return_none() {
        // Plain primitives.
        assert_eq!(ts_type_to_local_collection("string"), None);
        assert_eq!(ts_type_to_local_collection("number"), None);
        assert_eq!(ts_type_to_local_collection("boolean"), None);
        // Promise / Iterator / etc. are not LocalCollections.
        assert_eq!(ts_type_to_local_collection("Promise<string>"), None);
        assert_eq!(ts_type_to_local_collection("Iterator<number>"), None);
        // User types.
        assert_eq!(ts_type_to_local_collection("CreateUserDto"), None);
        assert_eq!(ts_type_to_local_collection("ElementsMap"), None);
    }

    // ── Java (Spring) ────────────────────────────────────────────────────

    #[test]
    fn java_long_path_variable_maps_to_int() {
        assert_eq!(java_type_to_kind("Long"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("long"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("Integer"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("int"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("Short"), Some(TypeKind::Int));
        assert_eq!(java_type_to_kind("BigInteger"), Some(TypeKind::Int));
        assert_eq!(
            java_type_to_kind("java.lang.Long"),
            Some(TypeKind::Int),
            "fully-qualified Long must still map to Int"
        );
    }

    #[test]
    fn java_string_request_param_maps_to_string() {
        assert_eq!(java_type_to_kind("String"), Some(TypeKind::String));
        assert_eq!(java_type_to_kind("CharSequence"), Some(TypeKind::String));
    }

    #[test]
    fn java_boolean_maps_to_bool() {
        assert_eq!(java_type_to_kind("Boolean"), Some(TypeKind::Bool));
        assert_eq!(java_type_to_kind("boolean"), Some(TypeKind::Bool));
    }

    #[test]
    fn java_request_body_dto_returns_none_until_phase_six() {
        // @RequestBody CreateUserDto dto, no kind today; future passes will
        // return DtoObject(name) once cross-file class resolution lands.
        assert_eq!(java_type_to_kind("CreateUserDto"), None);
        assert_eq!(java_type_to_kind("List<String>"), None);
    }

    // ── Rust (Axum / Rocket / Actix) ─────────────────────────────────────

    #[test]
    fn rust_connection_formal_is_a_database_connection() {
        for t in [
            "Connection",
            "&Connection",
            "&mut rusqlite::Connection",
            "&'a Connection",
        ] {
            assert_eq!(
                super::rust_db_connection_type(t),
                Some(TypeKind::DatabaseConnection),
                "{t}"
            );
        }
        for t in [
            "Arc<Mutex<Connection>>",
            "PgConnection",
            "Pool",
            "MyConnection",
        ] {
            assert_eq!(super::rust_db_connection_type(t), None, "{t}");
        }
    }

    #[test]
    fn rust_path_int_extractor_maps_to_int() {
        assert_eq!(rust_type_to_kind("Path<i64>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("Path<u32>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("Path<usize>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("Path<i32>"), Some(TypeKind::Int));
        assert_eq!(rust_type_to_kind("web::Path<i64>"), Some(TypeKind::Int));
    }

    #[test]
    fn rust_path_tuple_first_element_wins() {
        // Path<(i64, String)>, first slot is the int extractor that
        // matters for sink suppression.
        assert_eq!(
            rust_type_to_kind("Path<(i64, String)>"),
            Some(TypeKind::Int)
        );
    }

    #[test]
    fn rust_path_string_maps_to_string() {
        assert_eq!(rust_type_to_kind("Path<String>"), Some(TypeKind::String));
        assert_eq!(rust_type_to_kind("Path<&str>"), Some(TypeKind::String));
    }

    #[test]
    fn rust_json_dto_returns_none_until_phase_six() {
        // Json<T> / Form<T> / Query<T> with a custom struct type, no
        // primitive resolution available; future passes will lift to DTO.
        assert_eq!(rust_type_to_kind("Json<CreateUserDto>"), None);
        assert_eq!(rust_type_to_kind("Form<CreateUserDto>"), None);
        assert_eq!(rust_type_to_kind("Query<Filters>"), None);
    }

    /// Per Hard Rule 3, bare primitives (`fn h(id: i64)`) are NOT
    /// framework extractors, only wrapper types (`Path<i64>` etc.)
    /// imply a framework runtime gate.  Bare i64 must return None.
    #[test]
    fn rust_bare_primitives_are_not_framework_extractors() {
        assert_eq!(rust_type_to_kind("i64"), None);
        assert_eq!(rust_type_to_kind("u32"), None);
        assert_eq!(rust_type_to_kind("bool"), None);
        assert_eq!(rust_type_to_kind("String"), None);
        // `rust_primitive_to_kind` (used for tuple inner / wrapper inner)
        // remains a separate primitive-only mapping.
        assert_eq!(rust_primitive_to_kind("i64"), Some(TypeKind::Int));
        assert_eq!(rust_primitive_to_kind("bool"), Some(TypeKind::Bool));
    }

    // ── Python (FastAPI) ─────────────────────────────────────────────────

    #[test]
    fn python_bare_primitives_are_not_framework_extractors() {
        // Per Hard Rule 3: bare `def h(id: int)` is NOT a typed
        // extractor, without an `Annotated[..., Path()/Query()/Body()]`
        // wrapper, no FastAPI gate is implied.
        assert_eq!(python_type_to_kind("int"), None);
        assert_eq!(python_type_to_kind("float"), None);
        assert_eq!(python_type_to_kind("bool"), None);
        assert_eq!(python_type_to_kind("str"), None);
        // The inner primitive resolver is unchanged.
        assert_eq!(python_primitive_to_kind("int"), Some(TypeKind::Int));
    }

    #[test]
    fn python_annotated_with_fastapi_marker_qualifies() {
        assert_eq!(
            python_type_to_kind("Annotated[int, Path()]"),
            Some(TypeKind::Int)
        );
        assert_eq!(
            python_type_to_kind("typing.Annotated[int, Path()]"),
            Some(TypeKind::Int)
        );
        assert_eq!(
            python_type_to_kind("Annotated[str, Query(max_length=50)]"),
            Some(TypeKind::String)
        );
        assert_eq!(
            python_type_to_kind("Annotated[bool, Body()]"),
            Some(TypeKind::Bool)
        );
    }

    #[test]
    fn python_annotated_without_marker_returns_none() {
        // Annotated without a FastAPI binding marker is a generic
        // type-system tag, not a framework extractor.
        assert_eq!(python_type_to_kind("Annotated[int, str]"), None);
        assert_eq!(python_type_to_kind("Annotated[int, MyMeta]"), None);
    }

    #[test]
    fn python_pydantic_model_returns_none_until_phase_six() {
        assert_eq!(python_type_to_kind("CreateUser"), None);
        assert_eq!(python_type_to_kind("BaseModel"), None);
    }

    #[test]
    fn fastapi_marker_detection() {
        assert!(contains_fastapi_marker("int, Path()"));
        assert!(contains_fastapi_marker("str, Query(max_length=5)"));
        assert!(contains_fastapi_marker("bytes, File()"));
        assert!(!contains_fastapi_marker("int, str"));
    }

    // ── Rust local-collection types ──────────────────────────────────────

    #[test]
    fn rust_std_collections_map_to_local_collection() {
        for ty in [
            "Vec<u32>",
            "HashMap<String, u32>",
            "HashSet<u64>",
            "BTreeMap<u32, String>",
            "BTreeSet<u32>",
            "VecDeque<u8>",
            "BinaryHeap<u32>",
            "LinkedList<i32>",
        ] {
            assert_eq!(
                rust_type_to_local_collection(ty),
                Some(TypeKind::LocalCollection),
                "{ty} should map to LocalCollection"
            );
        }
    }

    #[test]
    fn rust_ecosystem_collections_map_to_local_collection() {
        for ty in [
            "IndexMap<String, u32>",
            "IndexSet<u64>",
            "SmallVec<[u32; 4]>",
            "DashMap<String, u32>",
            "DashSet<u64>",
            "FxHashMap<String, u32>",
            "FxHashSet<u64>",
            "RoaringBitmap",
            "RoaringTreemap",
        ] {
            assert_eq!(
                rust_type_to_local_collection(ty),
                Some(TypeKind::LocalCollection),
                "{ty} should map to LocalCollection"
            );
        }
    }

    #[test]
    fn rust_module_qualified_collections_map_to_local_collection() {
        // Module-path prefixes: keep only the last segment for matching.
        assert_eq!(
            rust_type_to_local_collection("std::collections::HashMap<K, V>"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            rust_type_to_local_collection("hashbrown::HashMap<String, RoaringBitmap>"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            rust_type_to_local_collection("roaring::RoaringBitmap"),
            Some(TypeKind::LocalCollection)
        );
    }

    #[test]
    fn rust_reference_and_lifetime_markers_stripped() {
        // `&T`, `&mut T`, `&'a T`, `&'a mut T`, `&'static T`,
        // repeated `&` prefixes, all reach the underlying type head.
        for ty in [
            "&RoaringBitmap",
            "&mut RoaringBitmap",
            "&'a RoaringBitmap",
            "&'a mut RoaringBitmap",
            "&'static RoaringBitmap",
            "&&mut RoaringBitmap",
            "&'a mut hashbrown::HashMap<String, RoaringBitmap>",
        ] {
            assert_eq!(
                rust_type_to_local_collection(ty),
                Some(TypeKind::LocalCollection),
                "{ty} should map to LocalCollection after ref stripping"
            );
        }
    }

    #[test]
    fn rust_array_and_slice_shorthand_map_to_local_collection() {
        // `[T; N]` arrays and `[T]` slices are local containers.
        assert_eq!(
            rust_type_to_local_collection("[u32; 4]"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            rust_type_to_local_collection("[u8]"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            rust_type_to_local_collection("&[u32]"),
            Some(TypeKind::LocalCollection)
        );
        assert_eq!(
            rust_type_to_local_collection("&mut [u32]"),
            Some(TypeKind::LocalCollection)
        );
    }

    #[test]
    fn rust_persistent_db_and_sync_wrappers_return_none() {
        // heed / sled / rocksdb persistent-store handles are NOT local
        // collections, preserves IDOR detection on real DB calls.
        assert_eq!(
            rust_type_to_local_collection("Database<BEU32, SerdeJson<Task>>"),
            None
        );
        assert_eq!(rust_type_to_local_collection("heed::Database<K, V>"), None);
        assert_eq!(rust_type_to_local_collection("sled::Db"), None);
        // Sync wrappers don't claim a sink shape.
        assert_eq!(rust_type_to_local_collection("Mutex<HashMap<K, V>>"), None);
        assert_eq!(rust_type_to_local_collection("RwLock<Vec<u32>>"), None);
        // Bare primitives.
        assert_eq!(rust_type_to_local_collection("u32"), None);
        assert_eq!(rust_type_to_local_collection("&str"), None);
        assert_eq!(rust_type_to_local_collection("String"), None);
        // Unrelated user types.
        assert_eq!(rust_type_to_local_collection("MyDao<User>"), None);
        assert_eq!(rust_type_to_local_collection("Connection"), None);
    }

    // ── FastAPI request-bound formals ────────────────────────────────────

    use super::{python_request_value_kind, split_top_level};

    /// `(name, kind)` of every formal of the first function named `name`.
    fn formal_kinds(src: &str, name: &str) -> Vec<(String, Option<TypeKind>)> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        let body = file
            .bodies
            .iter()
            .find(|b| b.meta.name.as_deref() == Some(name))
            .expect("function body");
        body.meta
            .params
            .iter()
            .cloned()
            .zip(body.meta.param_types.iter().cloned())
            .collect()
    }

    fn kind_of(formals: &[(String, Option<TypeKind>)], param: &str) -> Option<TypeKind> {
        formals
            .iter()
            .find(|(n, _)| n == param)
            .and_then(|(_, k)| k.clone())
    }

    #[test]
    fn python_request_value_kinds() {
        let kind = python_request_value_kind;
        assert_eq!(kind("str"), Some(TypeKind::String));
        assert_eq!(kind("int"), Some(TypeKind::Int));
        assert_eq!(kind("bool"), Some(TypeKind::Bool));
        assert_eq!(kind("bytes"), Some(TypeKind::String));
        assert_eq!(kind("Optional[str]"), Some(TypeKind::String));
        assert_eq!(kind("typing.Optional[int]"), Some(TypeKind::Int));
        assert_eq!(kind("Union[str, None]"), Some(TypeKind::String));
        assert_eq!(kind("str | None"), Some(TypeKind::String));
        assert_eq!(kind("None | str"), Some(TypeKind::String));
        assert_eq!(kind("list[str]"), Some(TypeKind::Array));
        assert_eq!(kind("List[str] | None"), Some(TypeKind::Array));
        assert_eq!(kind("Optional[List[str]]"), Some(TypeKind::Array));
        assert_eq!(kind("dict[str, Any]"), Some(TypeKind::Object));
        assert_eq!(
            kind("Annotated[str, Field(max_length=5)]"),
            Some(TypeKind::String)
        );
        // Values the framework constrains, ambiguous unions, dependencies and
        // names we cannot tell from an injected handle.
        assert_eq!(kind("Literal['a', 'b']"), None);
        assert_eq!(kind("UUID"), None);
        assert_eq!(kind("Union[int, str]"), None);
        assert_eq!(kind("Annotated[Session, Depends(get_db)]"), None);
        assert_eq!(kind("Session"), None);
        assert_eq!(kind("Request"), None);
        assert_eq!(kind("SessionDep"), None);
        assert_eq!(kind("None"), None);
    }

    #[test]
    fn split_top_level_ignores_brackets() {
        assert_eq!(
            split_top_level("a, b[c, d], e", ','),
            ["a", " b[c, d]", " e"]
        );
        assert_eq!(
            split_top_level("list[int | str] | None", '|'),
            ["list[int | str] ", " None"]
        );
    }

    #[test]
    fn fastapi_route_formals_are_request_bound() {
        let src = "\
from fastapi import FastAPI, Query, Depends
from pydantic import BaseModel
app = FastAPI()
class Item(BaseModel):
    name: str
@app.get('/a')
def a(q: str, n: int, nums: list[int], page: Optional[int] = None, limit: int = Query(5), tags: list[str] = None, opt: Optional[str] = None, m: str = Query(None)):
    pass
@app.post('/b')
def b(item: Item, payload: dict, request: Request, db: Session = Depends(get_db), user: CurrentUser = None):
    pass
@app.get('/c')
def c(x: str = Depends(get_x), session: SessionDep = None):
    pass
";
        let a = formal_kinds(src, "a");
        assert_eq!(kind_of(&a, "q"), Some(TypeKind::String));
        // A bare number is validated by the framework and is not painted.
        assert_eq!(kind_of(&a, "n"), None);
        assert_eq!(kind_of(&a, "nums"), None);
        assert_eq!(kind_of(&a, "page"), None);
        assert_eq!(kind_of(&a, "limit"), Some(TypeKind::Int));
        assert_eq!(kind_of(&a, "tags"), Some(TypeKind::Array));
        assert_eq!(kind_of(&a, "opt"), Some(TypeKind::String));
        assert_eq!(kind_of(&a, "m"), Some(TypeKind::String));
        let b = formal_kinds(src, "b");
        assert!(matches!(kind_of(&b, "item"), Some(TypeKind::Dto(_))));
        assert_eq!(kind_of(&b, "payload"), Some(TypeKind::Object));
        // Injected handles stay unseeded.
        assert_eq!(kind_of(&b, "request"), None);
        assert_eq!(kind_of(&b, "db"), None);
        assert_eq!(kind_of(&b, "user"), None);
        let c = formal_kinds(src, "c");
        assert_eq!(kind_of(&c, "x"), None);
        assert_eq!(kind_of(&c, "session"), None);
    }

    #[test]
    fn plain_python_functions_keep_bare_annotations_unclassified() {
        // Hard Rule 3: an annotation alone is no framework gate.
        let src = "\
def helper(q: str, n: int):
    pass
@app.route('/x/<id>')
def flask_view(id: int, q: str):
    pass
";
        for name in ["helper", "flask_view"] {
            let f = formal_kinds(src, name);
            assert!(f.iter().all(|(_, k)| k.is_none()), "{name}: {f:?}");
        }
    }

    #[test]
    fn default_marker_calls_bind_outside_a_route() {
        let src = "\
def read(item_id: int = Path(..., gt=0), tok: str = Header(None), body = Body(...), p: Path = Path('/tmp'), d: str = Depends(dep)):
    pass
";
        let f = formal_kinds(src, "read");
        assert_eq!(kind_of(&f, "item_id"), Some(TypeKind::Int));
        assert_eq!(kind_of(&f, "tok"), Some(TypeKind::String));
        assert_eq!(kind_of(&f, "body"), Some(TypeKind::Object));
        // pathlib's `Path("..")` default is not FastAPI's marker.
        assert_eq!(kind_of(&f, "p"), None);
        assert_eq!(kind_of(&f, "d"), None);
    }
}

#[cfg(test)]
mod java_request_bound_tests {
    use super::{extract_param_meta, java_formal_is_request_bound, java_request_bound_flags};
    use tree_sitter::{Language, Node, Parser};

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&Language::from(tree_sitter_java::LANGUAGE))
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    fn first_method(node: Node<'_>) -> Option<Node<'_>> {
        if node.kind() == "method_declaration" {
            return Some(node);
        }
        let mut cursor = node.walk();
        node.children(&mut cursor).find_map(first_method)
    }

    /// Request-bound verdict of the single formal in `formal`.
    fn bound(formal: &str) -> bool {
        let src = format!("class C {{ void m({formal}) {{}} }}");
        let tree = parse(&src);
        let method = first_method(tree.root_node()).expect("method");
        let params = method.child_by_field_name("parameters").unwrap();
        let mut cursor = params.walk();
        let param = params
            .named_children(&mut cursor)
            .find(|c| matches!(c.kind(), "formal_parameter" | "spread_parameter"))
            .expect("formal");
        java_formal_is_request_bound(param, src.as_bytes())
    }

    #[test]
    fn binding_annotations_and_plain_values_are_request_bound() {
        for formal in [
            "@RequestParam String a",
            "@org.springframework.web.bind.annotation.PathVariable Long id",
            "@Valid @RequestBody CreateUser dto",
            "@RequestHeader(\"X-A\") String h",
            "@RequestPart MultipartFile f",
            "String q",
            "MultipartFile f",
            "InputStream body",
            "Pageable page",
            "@Context UriInfo ui",
            "@Context HttpHeaders h",
            "@QueryParam(\"q\") String q",
            "@BeanParam Filter filter",
            "String payload",
            "String... tags",
            "@RequestParam HttpServletRequest odd",
        ] {
            assert!(bound(formal), "{formal} should be request-bound");
        }
    }

    #[test]
    fn injected_infrastructure_formals_are_not_request_bound() {
        for formal in [
            "HttpServletResponse r",
            "javax.servlet.http.HttpServletRequest r",
            "HttpSession s",
            "Model m",
            "Principal p",
            "@AuthenticationPrincipal UserDetails u",
            "@Context SecurityContext sc",
            "@Context HttpServletResponse r",
            "@Suspended AsyncResponse ar",
            "Locale l",
            "OutputStream os",
            "BindingResult br",
            "@Value(\"${app.dir}\") String dir",
            "@RequestAttribute(\"user\") String user",
        ] {
            assert!(!bound(formal), "{formal} should not be request-bound");
        }
    }

    #[test]
    fn flags_follow_formal_order() {
        let src = "class C { void m(HttpServletResponse resp, @RequestParam String name, \
                   Principal p, String... rest) {} }";
        let tree = parse(src);
        let method = first_method(tree.root_node()).unwrap();
        assert_eq!(extract_param_meta(method, "java", src.as_bytes()).len(), 4);
        assert_eq!(
            java_request_bound_flags(method, src.as_bytes(), 4),
            vec![false, true, false, true]
        );
        // A count that does not line up falls back to seeding every formal.
        assert_eq!(
            java_request_bound_flags(method, src.as_bytes(), 3),
            vec![true; 3]
        );
    }
}
