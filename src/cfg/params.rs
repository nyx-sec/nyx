use super::{
    AstMeta, Cfg, DTO_CLASSES, EdgeKind, NodeInfo, StmtKind, TaintMeta, collect_idents,
    connect_all, is_anon_fn_name, text_of,
};
use crate::labels::{DataLabel, LangAnalysisRules, classify, param_config};
use crate::ssa::type_facts::TypeKind;
use petgraph::graph::NodeIndex;
use smallvec::smallvec;
use tree_sitter::Node;

/// resolve a syntactic class / struct / interface / model
/// name against the per-file [`DTO_CLASSES`] map populated at the top
/// of `build_cfg`.  Returns the [`TypeKind::Dto`] carrying the
/// per-field type map when the class is declared in the same file;
/// returns `None` otherwise so callers can fall through to the
/// pre-Phase-6 behaviour (Object / Unknown).
fn lookup_dto_class(class_name: &str) -> Option<TypeKind> {
    DTO_CLASSES.with(|cell| cell.borrow().get(class_name).cloned().map(TypeKind::Dto))
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
/// concept), behaviour is identical to the pre-Phase-5 names-only path.
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
    // Try the params_field directly on the function node first.
    // For C/C++, the parameter list is nested inside the declarator
    // (function_definition > declarator:function_declarator > parameters:parameter_list),
    // so fall back to looking one level deeper via the "declarator" field.
    let params = func_node.child_by_field_name(cfg.params_field).or_else(|| {
        func_node
            .child_by_field_name("declarator")
            .and_then(|d| d.child_by_field_name(cfg.params_field))
    });
    let Some(params) = params else {
        // Single-param arrow shorthand (`uri => ...` in JS/TS): tree-sitter
        // exposes the lone identifier under the singular `parameter` field
        // rather than wrapping it in `formal_parameters`. Without this
        // fallback the function appears parameterless to the SSA pipeline,
        // breaking cross-function param_to_sink resolution for any
        // single-arg arrow helper. Motivated by CVE-2025-64430.
        if func_node.kind() == "arrow_function" {
            if let Some(p) = func_node.child_by_field_name("parameter") {
                if p.kind() == "identifier" {
                    if let Some(name) = text_of(p, code) {
                        out.push((name, None, Vec::new()));
                    }
                }
            }
        }
        return out;
    };
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        // Self/this parameter (e.g. Rust's `self_parameter`)
        if cfg.self_param_kinds.contains(&child.kind()) {
            out.push(("self".into(), None, Vec::new()));
            continue;
        }

        // Regular parameter
        if cfg.param_node_kinds.contains(&child.kind()) {
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
                    } else {
                        if tmp.is_empty() {
                            None
                        } else {
                            Some(tmp.remove(0))
                        }
                    };
                    if let Some(name) = primary {
                        let ty = classify_param_type(child, lang, code);
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
                && child.kind() == "identifier"
                && let Some(txt) = text_of(child, code)
            {
                out.push((txt, None, Vec::new()));
                found = true;
            }
            // Fallback for C/C++: look for nested declarator → identifier
            if !found && child.kind() == "parameter_declaration" {
                let mut tmp = Vec::new();
                collect_idents(child, code, &mut tmp);
                if let Some(last) = tmp.pop() {
                    let ty = classify_param_type(child, lang, code);
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
                    let ty = classify_param_type(child, lang, code);
                    let siblings = sibling_names_for_destructure(child, &tmp, lang);
                    out.push((first, ty, siblings));
                }
            }
            continue;
        }

        // Bare identifier children, e.g. Rust untyped closure params `|cmd|`
        // where the child is an `identifier` node, not a `parameter` wrapper.
        if child.kind() == "identifier" {
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
fn sibling_names_for_destructure(pattern: Node<'_>, remaining: &[String], lang: &str) -> Vec<String> {
    if remaining.is_empty() {
        return Vec::new();
    }
    if !is_destructure_container_kind(pattern.kind(), lang) {
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
        let pk = parent.kind();

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
        if cfg.self_param_kinds.contains(&child.kind()) || child.kind() != "parameter" {
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
/// * Python (FastAPI), `def h(x: int)` → [`TypeKind::Int`];
///   `Annotated[int, Path()]` → [`TypeKind::Int`].
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
        "python" | "py" => classify_param_type_python(param, code),
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
    if param.kind() != "formal_parameter" && param.kind() != "spread_parameter" {
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

/// Walk the parameter's modifiers (annotations) and check if any of
/// them are a recognised Spring web binding annotation.  Spring's
/// annotation grammar exposes annotations as `marker_annotation` /
/// `annotation` siblings inside the formal_parameter's `modifiers`
/// child.
fn has_java_framework_annotation(param: Node<'_>, code: &[u8]) -> bool {
    const KNOWN: &[&str] = &[
        "@PathVariable",
        "@RequestParam",
        "@RequestBody",
        "@RequestHeader",
        "@CookieValue",
        "@MatrixVariable",
        "@ModelAttribute",
    ];
    // Inspect modifiers child first.
    if let Some(modifiers) = param.child_by_field_name("modifiers") {
        if let Some(text) = text_of(modifiers, code) {
            for k in KNOWN {
                if text.contains(k) {
                    return true;
                }
            }
        }
    }
    // Fall back to scanning all named children: tree-sitter-java emits
    // annotations as direct children of formal_parameter in some grammar
    // versions.
    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        let kind = child.kind();
        if matches!(kind, "marker_annotation" | "annotation" | "modifiers")
            && let Some(text) = text_of(child, code)
        {
            for k in KNOWN {
                if text.contains(k) {
                    return true;
                }
            }
        }
    }
    false
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
        if node.kind() == "decorator" {
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
        if child.kind() == "decorator" {
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
    if param.kind() != "parameter" {
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

    rust_type_to_kind(&type_text)
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

/// Python (FastAPI), recognise typed-extractor parameters via the
/// `Annotated[X, Path()/Query()/Body()/Header()/Cookie()]` shape.  Per
/// Hard Rule 3, a bare `def h(id: int)` is **not** a framework
/// extractor, the function may be a plain Python function and the
/// type annotation provides no runtime gate.
fn classify_param_type_python<'a>(param: Node<'a>, code: &'a [u8]) -> Option<TypeKind> {
    let type_node = param.child_by_field_name("type")?;
    let type_text = text_of(type_node, code)?;
    python_type_to_kind(&type_text)
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
        let first = inside.split(',').next().unwrap_or("").trim();
        if let Some(k) = python_primitive_to_kind(first) {
            return Some(k);
        }
        // `Annotated[CreateUser, Body()]` with a same-file
        // Pydantic model, resolve via the DTO map.  Generic args are
        // dropped via the same head-split as `python_primitive_to_kind`.
        let head = first.split('[').next().unwrap_or(first).trim();
        return lookup_dto_class(head);
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

/// Check if a callee name matches any configured terminator.
pub(super) fn is_configured_terminator(
    callee: &str,
    analysis_rules: Option<&LangAnalysisRules>,
) -> bool {
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
}
